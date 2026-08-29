import pytest
from src.rules.threat_intel_syncer import ThreatIntelSyncer
from src.rules.zero_day_discovery import ZeroDayDiscoveryEngine
from src.agents.safecode_agent import SafeCodeAgent

def test_threat_intel_syncer():
    syncer = ThreatIntelSyncer()
    res = syncer.sync_external_feeds()
    assert res["status"] == "SYNCED"
    assert "feed_sources" in res

def test_zero_day_discovery_and_auto_ingestion():
    engine = ZeroDayDiscoveryEngine()
    code = "def custom_flaw(data): eval(data)"
    analysis = "This is an unclassified novel business logic execution vulnerability."
    
    res = engine.analyze_and_ingest_novel_flaw(code, analysis, "INJECTION")
    assert res["is_novel_discovered"] is True
    assert "novel_cwe_id" in res
    assert "category_key" in res

def test_safecode_agent_with_threat_intel_and_zero_day():
    agent = SafeCodeAgent()
    code = "def run_unclassified_logic(payload): return eval(payload)"
    vuln = "Unknown novel execution flaw"
    
    res = agent.audit_and_patch(code, vuln)
    assert res["status"] == "SUCCESS"
    assert "threat_intel_sync" in res
    assert "zero_day_discovery" in res
