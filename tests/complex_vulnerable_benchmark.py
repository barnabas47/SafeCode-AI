"""
Complex Benchmark Codebase for SafeCode-AI Stress Testing.
Contains:
- Legacy SDK integrations (mocked external dependencies)
- Async event loops & thread pool dispatchers
- Implicit state mutation & tuple return schemas
- Multiple security risks (Unsafe deserialization, SSRF, SQL string concatenation)
- Strict functional contracts that MUST NOT break.
"""

import os
import json
import sqlite3
import hashlib
import asyncio
from typing import Dict, Any, Tuple, List, Optional, Callable

# =====================================================================
# 1. External Mock Legacy SDKs (Imaginary Third-Party Dependencies)
# =====================================================================

class LegacyVaultSDK:
    """Mock external third-party vault SDK with strict signature expectations."""
    def __init__(self, vault_url: str, token: str):
        self.vault_url = vault_url
        self.token = token

    def fetch_secret_token(self, key_id: str) -> Dict[str, str]:
        # Imagine this calls an internal vault API
        if not key_id:
            raise ValueError("Key ID cannot be empty")
        return {
            "key_id": key_id,
            "raw_secret": hashlib.sha256(key_id.encode()).hexdigest(),
            "status": "VALIDATED"
        }

class AsyncQueueBridge:
    """Mock messaging middleware requiring exact message payload schemas."""
    def __init__(self, queue_name: str):
        self.queue_name = queue_name
        self.messages: List[Dict[str, Any]] = []

    async def publish(self, payload: Dict[str, Any]) -> bool:
        if "event_id" not in payload or "data" not in payload:
            raise KeyError("Payload missing required schema keys: event_id, data")
        self.messages.append(payload)
        await asyncio.sleep(0.01)  # Simulate network latency
        return True

# =====================================================================
# 2. Complex Core Business Logic & Enterprise Data Pipeline
# =====================================================================

class EnterpriseDataPipeline:
    def __init__(self, db_path: str = ":memory:"):
        self.db = sqlite3.connect(db_path)
        self.vault = LegacyVaultSDK("https://vault.internal.corp:8200", "s.legacy-token-12345")
        self.queue = AsyncQueueBridge("enterprise_events")
        self.state_cache: Dict[str, Any] = {}
        self._init_db()

    def _init_db(self):
        cursor = self.db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                role TEXT,
                email TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                performed_by TEXT,
                payload_json TEXT
            )
        """)
        self.db.commit()

    # -----------------------------------------------------------------
    # VULNERABILITY 1: SQL Injection via Dynamic String Formatting
    # -----------------------------------------------------------------
    def query_user_records(self, search_term: str, role_filter: str) -> List[Tuple[int, str, str, str]]:
        """
        TRICKY: Returns a List of 4-tuples (id, username, role, email).
        Downstream code relies on index positions [0], [1], [2], [3]!
        VULNERABILITY: Raw string interpolation in SQL query.
        """
        cursor = self.db.cursor()
        # VULNERABLE: Direct string formatting allows SQL Injection
        raw_sql = f"SELECT id, username, role, email FROM users WHERE username LIKE '%{search_term}%' AND role = '{role_filter}'"
        cursor.execute(raw_sql)
        return cursor.fetchall()

    # -----------------------------------------------------------------
    # VULNERABILITY 2: SSRF & Weak Key Validation
    # -----------------------------------------------------------------
    def fetch_remote_user_profile(self, user_provided_url: str) -> Dict[str, Any]:
        """
        TRICKY: External fetch simulator.
        VULNERABILITY: Unvalidated URL permits SSRF (Server-Side Request Forgery)
        to internal subnets like 169.254.169.254 or localhost.
        """
        import urllib.request
        
        # Naive validation easily bypassed by AI or attacker
        if "file://" in user_provided_url:
            raise ValueError("File protocol forbidden")

        # Dangerous: Allows HTTP requests to internal IP addresses
        # In a real environment, urllib.request.urlopen(user_provided_url) would execute
        return {
            "target_url": user_provided_url,
            "status_code": 200,
            "simulated_body": "{\"user\": \"admin\", \"privileges\": [\"ALL\"]}"
        }

    # -----------------------------------------------------------------
    # COMPLEX WORKFLOW: Multi-step Async Pipeline with Vault Integration
    # -----------------------------------------------------------------
    async def process_enterprise_batch(self, user_requests: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Executes batch queries, fetches secret tokens from LegacyVaultSDK,
        updates state_cache, and dispatches events to AsyncQueueBridge.
        
        CONTRACT REQUIREMENT:
        Must return dict with keys: 'total_processed', 'vault_keys_synced', 'errors'
        """
        processed_count = 0
        vault_keys_synced = 0
        errors = []

        for req in user_requests:
            u_name = req.get("username", "")
            r_filter = req.get("role", "USER")

            try:
                # Query DB using vulnerable method
                records = self.query_user_records(u_name, r_filter)
                
                # Fetch secret token from vault
                secret_info = self.vault.fetch_secret_token(f"key_for_{u_name}")
                vault_keys_synced += 1

                # Update internal state cache (Downstream caller expects state_cache mutation)
                self.state_cache[u_name] = {
                    "records_count": len(records),
                    "vault_status": secret_info["status"]
                }

                # Publish event to async queue
                event_payload = {
                    "event_id": f"EVT-{hashlib.md5(u_name.encode()).hexdigest()[:8]}",
                    "data": {
                        "username": u_name,
                        "records_found": len(records)
                    }
                }
                await self.queue.publish(event_payload)
                processed_count += 1

            except Exception as e:
                errors.append(f"Failed processing {u_name}: {str(e)}")

        return {
            "total_processed": processed_count,
            "vault_keys_synced": vault_keys_synced,
            "errors": errors
        }
