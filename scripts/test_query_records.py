import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.safecode_agent import SafeCodeAgent

code = '''def query_user_records(self, search_term: str, role_filter: str) -> List[Tuple[int, str, str, str]]:
    cursor = self.db.cursor()
    # VULNERABLE: Direct string formatting allows SQL Injection
    raw_sql = f"SELECT id, username, role, email FROM users WHERE username LIKE '%{search_term}%' AND role = '{role_filter}'"
    cursor.execute(raw_sql)
    return cursor.fetchall()'''

agent = SafeCodeAgent()
res = agent.audit_and_patch(code, 'SQL Injection via unsafe string interpolation in query_user_records')

print("=== REFACTORED PATCH CODE ===")
print(res['patch_code'])
