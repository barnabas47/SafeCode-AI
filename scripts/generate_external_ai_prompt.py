"""
External AI Test Case Generation Prompt Generator.
Outputs a copy-pasteable master prompt for ChatGPT / Claude / Gemini / DeepSeek
to generate diverse, complex Python code snippets for benchmarking SafeCode-AI.
"""

PROMPT_TEMPLATE = """
Act as a Senior Cyber Security Benchmark Engineer and Software Architect.

I am testing an autonomous AI Code Audit & Refactoring Agent (SafeCode-AI) that detects vulnerabilities, refactors code safely, and preserves business logic contracts (Zero-Regression).

Please generate a JSON array of 5 diverse, realistic Python code test cases. Each item must represent a real-world coding scenario with subtle or complex flaws.

### Output JSON Format Required:
```json
[
  {
    "test_id": "TEST-01",
    "category": "INJECTION | NETWORK_ACCESS | DESERIALIZATION_DATA | CRYPTOGRAPHY_CREDENTIALS | LOGIC_FLAW",
    "vulnerability_description": "Short description of the vulnerability/flaw",
    "code_snippet": "Full Python source code snippet containing the flaw"
  }
]
```

### Requirements for the Test Cases:
1. Include a mix of OWASP/CWE flaws (e.g., SQL Injection, SSRF, Command Injection, Unsafe Pickle/Yaml, Weak Hash, Hardcoded Keys, Logic Flaw).
2. Make the code realistic (include type hints, return contracts, helper calls, or async code).
3. Ensure the return signatures (tuples, dicts, lists) are clear so we can verify zero-regression.

Return ONLY the raw JSON array.
"""

def main():
    print("=================================================================")
    print("MASTER PROMPT FOR OTHER AIs (ChatGPT / Claude / Gemini / DeepSeek)")
    print("=================================================================\n")
    print(PROMPT_TEMPLATE)

if __name__ == "__main__":
    main()
