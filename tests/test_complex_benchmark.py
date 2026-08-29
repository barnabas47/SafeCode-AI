import pytest
import asyncio
from tests.complex_vulnerable_benchmark import EnterpriseDataPipeline
from src.agents.safecode_agent import SafeCodeAgent

def test_enterprise_pipeline_baseline():
    """Verifies that the complex enterprise pipeline baseline functions correctly."""
    pipeline = EnterpriseDataPipeline()
    
    # Populate initial data
    cursor = pipeline.db.cursor()
    cursor.execute("INSERT INTO users (username, role, email) VALUES ('alice', 'ADMIN', 'alice@corp.com')")
    cursor.execute("INSERT INTO users (username, role, email) VALUES ('bob', 'USER', 'bob@corp.com')")
    pipeline.db.commit()

    # 1. Verify tuple schema contract (id, username, role, email)
    records = pipeline.query_user_records("alice", "ADMIN")
    assert len(records) == 1
    assert records[0][1] == "alice"
    assert records[0][2] == "ADMIN"
    assert records[0][3] == "alice@corp.com"

    # 2. Verify async batch processing and state mutation
    requests = [{"username": "alice", "role": "ADMIN"}, {"username": "bob", "role": "USER"}]
    res = asyncio.run(pipeline.process_enterprise_batch(requests))
    
    assert res["total_processed"] == 2
    assert res["vault_keys_synced"] == 2
    assert len(res["errors"]) == 0
    assert "alice" in pipeline.state_cache
    assert pipeline.state_cache["alice"]["vault_status"] == "VALIDATED"

def test_safecode_agent_on_complex_benchmark():
    """
    Stress-tests SafeCodeAgent against the multi-vulnerability complex codebase.
    Verifies that all 4 stages (Architect, Patch Engineer, Sandbox Verifier, Red-Team Critic)
    are executed cleanly without crashing.
    """
    agent = SafeCodeAgent()
    
    complex_code_snippet = """
    def query_user_records(self, search_term: str, role_filter: str) -> List[Tuple[int, str, str, str]]:
        cursor = self.db.cursor()
        raw_sql = f"SELECT id, username, role, email FROM users WHERE username LIKE '%{search_term}%' AND role = '{role_filter}'"
        cursor.execute(raw_sql)
        return cursor.fetchall()
    """
    vulnerability_desc = "SQL Injection via unsafe string interpolation in query_user_records"

    result = agent.audit_and_patch(complex_code_snippet, vulnerability_desc)

    assert result["status"] == "SUCCESS"
    assert "architect_analysis" in result
    assert "patch_code" in result
    assert "sandbox_verification" in result
    assert "red_team_attestation" in result
