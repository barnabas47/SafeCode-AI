import os
import sys
import json
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.safecode_agent import SafeCodeAgent

logging.basicConfig(level=logging.INFO)

def run_detailed_benchmark():
    new_tests_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "new_tests.txt")
    with open(new_tests_path, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    agent = SafeCodeAgent()

    print("\n==========================================================================")
    print("  SAFECODE-AI BENCHMARK EVALUATION ON tests/new_tests.txt")
    print("==========================================================================\n")

    results = []

    for item in test_cases:
        t_id = item.get("test_id")
        title = item.get("title", "")
        lang = item.get("language", "")
        hint = item.get("vulnerability_hint", "")
        code = item.get("code_snippet", "")

        print(f"\n[{t_id}] Running Audit on {lang} Code ({title})...")
        print(f"    Expected Vulnerability: {hint}")

        audit_res = agent.audit_and_patch(code, hint)
        
        status = audit_res.get("status")
        tax = audit_res.get("taxonomy_classification", {})
        cat_name = tax.get("category_name")
        cwes = tax.get("cwe_list", [])
        guardrail = audit_res.get("patch_guardrail", {})

        print(f"    -> Status: {status}")
        print(f"    -> Taxonomy Detected: {cat_name} (CWEs: {', '.join(cwes)})")
        print(f"    -> Guardrail Evaluation: Safe={guardrail.get('is_safe')} (Risk Score: {guardrail.get('risk_score')})")

        results.append({
            "test_id": t_id,
            "expected_hint": hint,
            "status": status,
            "detected_category": cat_name,
            "cwes": cwes,
            "guardrail_safe": guardrail.get("is_safe")
        })

    print("\n==========================================================================")
    print("  BENCHMARK EVALUATION SUMMARY TABLE")
    print("==========================================================================")
    for r in results:
        print(f"{r['test_id']} | Status: {r['status']} | Detected: {r['detected_category']} ({', '.join(r['cwes'])})")

if __name__ == "__main__":
    run_detailed_benchmark()
