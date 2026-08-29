import pytest
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_frontend_dashboard_renders():
    """Verify that the main HTML Frontend Dashboard loads correctly (200 OK)."""
    response = client.get("/")
    assert response.status_code == 200
    assert "SafeCode-AI" in response.text
    assert "Nebius Token Factory" in response.text
    assert "NVIDIA OpenShell" in response.text

def test_scenario_1_sqli_remediation():
    """E2E Test Scenario 1: SQL Injection Remediation (SafeCode-AI)."""
    payload = {
        "code_snippet": "def query_user(u): return db.execute(f'SELECT * FROM users WHERE name=\"{u}\"')",
        "vulnerability": "SQL Injection vulnerability via unsanitized string formatting"
    }
    response = client.post("/api/code/patch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "ROOT CAUSE ANALYSIS" in data["architect_analysis"]
    assert "REFACTORED" in data["patch_code"]
    assert "SANDBOX VERIFICATION LOGS" in data["sandbox_verification"]
    assert "RED-TEAM ATTESTATION" in data["red_team_attestation"]

def test_scenario_2_ssrf_remediation():
    """E2E Test Scenario 2: SSRF (Server-Side Request Forgery) Remediation (SafeCode-AI)."""
    payload = {
        "code_snippet": "def fetch_url(url): return requests.get(url).text",
        "vulnerability": "SSRF vulnerability allowing internal subnet access (169.254.169.254)"
    }
    response = client.post("/api/code/patch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["security_layer"] == "NVIDIA OpenShell Egress Proxy & Kernel Sandbox"

def test_scenario_3_command_injection_remediation():
    """E2E Test Scenario 3: Unsafe Subprocess / Command Injection Remediation."""
    payload = {
        "code_snippet": "def ping_host(host): os.system('ping ' + host)",
        "vulnerability": "Command Injection vulnerability via unsafe os.system call"
    }
    response = client.post("/api/code/patch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"

def test_scenario_4_omniclaim_fraud_detection():
    """E2E Test Scenario 4: OmniClaim-AI Insurance Claim Processing."""
    payload = {
        "claim_id": "CLM-TEST-88",
        "policy_holder": "John Doe",
        "amount": 15000.00,
        "description": "Suspicious high-value claim for damaged electronics"
    }
    response = client.post("/api/claim/process", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["claim_id"] == "CLM-TEST-88"
    assert data["fast_parse_model"] == "nvidia/nemotron-4-8b-instruct"
    assert data["deep_reasoning_model"] == "nvidia/nemotron-4-340b-instruct"

def test_scenario_5_serverless_batch_jobs():
    """E2E Test Scenario 5: Nebius Serverless Jobs Batch Processing."""
    claims_batch = [
        {"claim_id": "BATCH-1", "policy_holder": "User A", "amount": 100.0, "description": "Minor claim"},
        {"claim_id": "BATCH-2", "policy_holder": "User B", "amount": 250.0, "description": "Routine claim"},
        {"claim_id": "BATCH-3", "policy_holder": "User C", "amount": 5000.0, "description": "High value claim"}
    ]
    response = client.post("/api/serverless/job", json=claims_batch)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert data["processed_items_count"] == 3
    assert len(data["results"]) == 3
