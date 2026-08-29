import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.safecode_agent import SafeCodeAgent

ULTRA_VULNERABLE_ENTERPRISE_CODE = '''import os
import sqlite3
import pickle
import requests
import hashlib
import time
from typing import List, Tuple

class UltraVulnerableEnterpriseService:
    # 1. Hardcoded Credentials (CWE-798)
    AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY"

    def __init__(self, db_conn):
        self.db = db_conn

    def search_users(self, search_user: str, status_filter: str) -> List[Tuple]:
        # 2. SQL Injection (CWE-89)
        cursor = self.db.cursor()
        raw_sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_user}%' AND status = '{status_filter}'"
        cursor.execute(raw_sql)
        return cursor.fetchall()

    def run_diagnostics(self, domain_or_ip: str):
        # 3. OS Command Injection (CWE-78)
        os.system(f"ping -c 1 {domain_or_ip}")

    def trigger_webhook(self, webhook_url: str):
        # 4. Server-Side Request Forgery - SSRF (CWE-918)
        resp = requests.get(webhook_url, timeout=5)
        return resp.text

    def restore_session(self, raw_session_data: bytes):
        # 5. Unsafe Deserialization RCE (CWE-502)
        session_obj = pickle.loads(raw_session_data)
        return session_obj

    def get_user_avatar(self, file_name: str):
        # 6. Path Traversal File Leak (CWE-22)
        avatar_path = "/var/app/avatars/" + file_name
        with open(avatar_path, "rb") as f:
            return f.read()

    def authenticate_user(self, password: str, expected_hash: str) -> bool:
        # 7. Weak Cryptographic Hash MD5 (CWE-327)
        user_hash = hashlib.md5(password.encode()).hexdigest()
        return user_hash == expected_hash

    def evaluate_discount_rule(self, user_expression: str, context: dict):
        # 8. Arbitrary Code Execution via Eval (CWE-94)
        return eval(user_expression, context)
'''

def test_ultra_vulnerable_benchmark():
    agent = SafeCodeAgent()
    result = agent.audit_and_patch(
        ULTRA_VULNERABLE_ENTERPRISE_CODE,
        "Ultra Multi-Vulnerability Audit: SQLi, OS Command Injection, SSRF, Pickle RCE, Path Traversal, MD5 Crypto, Eval RCE, Hardcoded Secrets."
    )
    assert result["status"] == "SUCCESS"
    assert result["patch_guardrail"]["is_safe"] is True
    assert "executive_report" in result
