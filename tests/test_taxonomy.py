import pytest
from src.rules.vulnerability_taxonomy import VulnerabilityTaxonomyManager

def test_taxonomy_classification_sqli():
    taxonomy = VulnerabilityTaxonomyManager()
    code = "def query(u): return db.execute('SELECT * FROM users WHERE name=' + u)"
    res = taxonomy.classify(code, "SQL Injection vulnerability")
    assert res["category_key"] == "INJECTION"
    assert "CWE-89" in res["cwe_list"]

def test_taxonomy_classification_ssrf():
    taxonomy = VulnerabilityTaxonomyManager()
    code = "def fetch(url): return requests.get(url)"
    res = taxonomy.classify(code, "SSRF vulnerability accessing 169.254.169.254")
    assert res["category_key"] == "NETWORK_ACCESS"
    assert "CWE-918" in res["cwe_list"]

def test_taxonomy_classification_crypto():
    taxonomy = VulnerabilityTaxonomyManager()
    code = "def hash_password(pwd): return hashlib.md5(pwd.encode()).hexdigest()"
    res = taxonomy.classify(code, "Weak cryptography using MD5 with hardcoded secret")
    assert res["category_key"] == "CRYPTOGRAPHY_CREDENTIALS"
    assert "CWE-327" in res["cwe_list"] or "CWE-798" in res["cwe_list"]
