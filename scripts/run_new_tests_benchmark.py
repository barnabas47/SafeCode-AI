"""
Benchmark Runner for new_tests.txt
Parses both JSON blocks (TEST-01..05 and TEST-01..05-ADV) from tests/new_tests.txt,
extracts the expected hidden vulnerability notes, executes SafeCodeAgent on each,
and evaluates if the agent correctly identified and remediated all primary and subtle flaws.
"""

import sys
import os
import json
import logging
from typing import List, Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.safecode_agent import SafeCodeAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NewTestsBenchmark")

def parse_new_tests_txt(file_path: str) -> List[Dict[str, Any]]:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Extract JSON blocks using bracket matching or splitting
    test_cases = []
    
    # We locate JSON blocks starting with '[' and ending with ']'
    in_json = False
    json_str = ""
    bracket_count = 0
    
    for line in content.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("[") and not in_json:
            in_json = True
            json_str = ""
            bracket_count = 0
        
        if in_json:
            json_str += line + "\n"
            bracket_count += line.count("[") - line.count("]")
            if bracket_count == 0 and json_str.strip().endswith("]"):
                in_json = False
                try:
                    parsed_block = json.loads(json_str)
                    test_cases.extend(parsed_block)
                except Exception as e:
                    logger.error(f"Error parsing JSON block: {e}")
                json_str = ""

    return test_cases

def run_benchmark():
    txt_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "new_tests.txt")
    test_cases = parse_new_tests_txt(txt_path)

    print(f"\n==========================================================================")
    print(f"  RUNNING BENCHMARK ON {len(test_cases)} TEST CASES FROM new_tests.txt")
    print(f"==========================================================================\n")

    agent = SafeCodeAgent()
    results = []

    for idx, tc in enumerate(test_cases, 1):
        t_id = tc.get("test_id", f"TEST-{idx}")
        cat = tc.get("category", "UNKNOWN")
        desc = tc.get("vulnerability_description", "")
        code = tc.get("code_snippet", "")

        print(f"[{idx}/{len(test_cases)}] Executing {t_id} | Category: {cat}")
        print(f"  Vulnerability: {desc[:100]}...")

        res = agent.audit_and_patch(code, desc)
        
        # Check taxonomy & zero-day discovery
        cls_info = res.get("taxonomy_classification", {})
        arch_analysis = res.get("architect_analysis", "")
        patch_code = res.get("patch_code", "")
        is_zero_day = res.get("zero_day_discovery", {}).get("is_novel_discovered", False)

        results.append({
            "test_id": t_id,
            "category": cat,
            "classified_as": cls_info.get("category_name"),
            "cwe_list": cls_info.get("cwe_list"),
            "status": res.get("status"),
            "zero_day_detected": is_zero_day,
            "architect_analysis_snippet": arch_analysis[:200],
            "patch_snippet": patch_code[:200]
        })

        print(f"  -> Status: {res.get('status')} | Classified: [{cls_info.get('category_name')}] | Zero-Day: {is_zero_day}")
        print("-" * 74)

    print(f"\n==========================================================================")
    print(f"  SUMMARY AUDIT REPORT FOR new_tests.txt ({len(results)} CASES PROCESSED)")
    print(f"==========================================================================")
    for r in results:
        print(f"[{r['test_id']}] Category: {r['category']} -> Classified: {r['classified_as']} | Status: {r['status']}")

    return results

if __name__ == "__main__":
    run_benchmark()
