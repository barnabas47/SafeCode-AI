"""
SafeCode-AI - Command Line Interface (CLI) Scanner
Enables batch security scanning of files and directories directly from the terminal.
"""

import sys
import os
import json
import argparse
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.safecode_agent import SafeCodeAgent
from src.reports.report_generator import SecurityReportGenerator

# ANSI Terminal Color Codes
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    print(f"{CYAN}{BOLD}")
    print("      ____        SafeCode-AI Enterprise CLI Scanner v2.0")
    print("     / __/___ _____ _____ ____  ____  ____  ___ ")
    print("    _\\ \\/ __ `/ __ `/ ___/ __ \\/ __ \\/ __ \\/ _ \\")
    print("   /___/\\__,_/\\__,_/____/\\____/\\____/\\____/\\___/")
    print(f"   Autonomous Multi-Agent Security Audit Engine{RESET}\n")

def scan_file(file_path: str, agent: SafeCodeAgent) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        print(f"{RED}[-] Error: File '{file_path}' does not exist.{RESET}")
        return {}

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        code_content = f.read()

    print(f"{CYAN}[*] Auditing file:{RESET} {BOLD}{file_path}{RESET} ({len(code_content)} bytes)")
    result = agent.audit_and_patch(code_content, f"CLI Batch Security Scan of {os.path.basename(file_path)}")
    
    status = result.get("status", "UNKNOWN")
    tax = result.get("taxonomy_classification", {})
    cat_name = tax.get("category_name", "N/A")
    cwes = ", ".join(tax.get("cwe_list", []))
    guardrail = result.get("patch_guardrail", {})

    status_color = GREEN if status == "SUCCESS" else RED
    print(f"    -> Status: {status_color}{BOLD}{status}{RESET}")
    print(f"    -> Taxonomy: {YELLOW}{cat_name}{RESET} (CWEs: {cwes})")
    print(f"    -> Guardrail Evaluation: Safe={guardrail.get('is_safe')} (Risk Score: {guardrail.get('risk_score')})")

    report_info = result.get("executive_report", {})
    if report_info and "filename" in report_info:
        print(f"    -> Report Generated: {GREEN}{report_info['filename']}{RESET}")

    return result

def scan_directory(dir_path: str, agent: SafeCodeAgent, extensions: List[str] = [".py", ".js", ".go", ".ts"]) -> List[Dict[str, Any]]:
    print(f"{CYAN}[*] Scanning directory recursively:{RESET} {BOLD}{dir_path}{RESET}")
    results = []
    
    for root, _, files in os.walk(dir_path):
        for f in files:
            if any(f.endswith(ext) for ext in extensions):
                full_path = os.path.join(root, f)
                res = scan_file(full_path, agent)
                if res:
                    results.append({"path": full_path, "result": res})
    return results

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="SafeCode-AI CLI Security Auditor & Refactoring Scanner")
    parser.add_argument("target", help="File or directory path to scan")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    args = parser.parse_args()

    agent = SafeCodeAgent()

    if os.path.isfile(args.target):
        res = scan_file(args.target, agent)
        if args.json:
            print("\n" + json.dumps(res, indent=2))
    elif os.path.isdir(args.target):
        results = scan_directory(args.target, agent)
        print(f"\n{GREEN}{BOLD}[+] Batch scan complete. Total files processed: {len(results)}{RESET}")
    else:
        print(f"{RED}[-] Target '{args.target}' is neither a file nor a directory.{RESET}")

if __name__ == "__main__":
    main()
