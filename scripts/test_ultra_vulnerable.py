import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.safecode_agent import SafeCodeAgent

ULTRA_VULNERABLE_CODE = '''import os
import sqlite3
import pickle
import requests
import hashlib
import time

class EnterprisePortalService:
    AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY"  # HARDCODED SECRET (CWE-798)

    def __init__(self, db_conn):
        self.db = db_conn

    def search_users(self, search_user: str, status_filter: str):
        # 1. SQL Injection (CWE-89)
        cursor = self.db.cursor()
        raw_sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_user}%' AND status = '{status_filter}'"
        cursor.execute(raw_sql)
        return cursor.fetchall()

    def run_diagnostics(self, domain_or_ip: str):
        # 2. OS Command Injection (CWE-78)
        os.system(f"ping -c 1 {domain_or_ip}")

    def trigger_webhook(self, webhook_url: str):
        # 3. Server-Side Request Forgery - SSRF (CWE-918)
        resp = requests.get(webhook_url, timeout=5)
        return resp.text

    def restore_session(self, raw_session_data: bytes):
        # 4. Unsafe Deserialization RCE (CWE-502)
        session_obj = pickle.loads(raw_session_data)
        return session_obj

    def get_user_avatar(self, file_name: str):
        # 5. Path Traversal (CWE-22)
        avatar_path = "/var/app/avatars/" + file_name
        with open(avatar_path, "rb") as f:
            return f.read()

    def authenticate_user(self, password: str, expected_hash: str):
        # 6. Weak Cryptographic Hash MD5 (CWE-327)
        user_hash = hashlib.md5(password.encode()).hexdigest()
        return user_hash == expected_hash

    def evaluate_discount_rule(self, user_expression: str, context: dict):
        # 7. Unsafe Code Execution via Eval (CWE-94)
        return eval(user_expression, context)

    def withdraw_funds(self, user_id: str, amount: float):
        # 8. TOCTOU Double Spend Race Condition (CWE-362)
        cursor = self.db.cursor()
        cursor.execute("SELECT balance FROM accounts WHERE user_id = ?", (user_id,))
        balance = cursor.fetchone()[0]
        if balance >= amount:
            time.sleep(0.1)  # Simulated race window
            cursor.execute("UPDATE accounts SET balance = balance - ? WHERE user_id = ?", (amount, user_id))
            self.db.commit()
            return True
        return False
'''

if __name__ == "__main__":
    agent = SafeCodeAgent()
    print("Executing 4-Stage Multi-Agent Audit on Ultra-Vulnerable Codebase...")
    result = agent.audit_and_patch(
        ULTRA_VULNERABLE_CODE,
        "Multi-Vulnerability Audit: SQLi, OS Command Injection, SSRF, Pickle RCE, Path Traversal, MD5 Crypto, Eval RCE, and TOCTOU Race Condition."
    )
    print("\n================== AUDIT RESULTS ==================")
    print("Taxonomy:", result["taxonomy_classification"])
    print("Architect Analysis:\n", result["architect_analysis"])
    print("\nPatch Guardrail Safe:", result["patch_guardrail"]["is_safe"])
    print("\nExecutive Report HTML generated:", result["executive_report"]["filename"])
