"""
SafeCode-AI - Universal AI Security Test Case Generator Prompt
Provides ready-to-use prompts for ChatGPT / Claude / Gemini / DeepSeek to generate realistic,
testable code snippets with subtle security flaws across Python, JavaScript, and Go.
"""

import sys
import argparse

MASTER_PROMPT_TEMPLATE = """Act as a Senior Cybersecurity Benchmark Engineer and Polyglot Software Architect.

I am benchmarking an autonomous AI Security Auditor & Refactorer (SafeCode-AI). I need realistic, self-contained source code samples containing subtle security flaws and design bugs to evaluate the auditor.

Please generate {count} realistic, production-style code samples in {language} focusing on {domain}.

### REQUIRED OUTPUT FORMAT (JSON Array):
[
  {{
    "test_id": "TEST-01",
    "title": "Short descriptive title of the component",
    "language": "{language}",
    "vulnerability_hint": "Brief description of the intended vulnerability (e.g. Second-Order SQLi, SSRF via Metadata, Prototype Pollution, Pickle RCE, TOCTOU Race Condition)",
    "code_snippet": "Full source code string (must be valid syntactically, with imports, functions, and return types)"
  }}
]

### REQUIREMENTS FOR THE CODE SAMPLES:
1. **Realistic & Modular**: The code should look like production code from a web service, API handler, or microservice. Include classes, type annotations, and realistic variable names.
2. **Subtle & Second-Order Flaws**: Do not make the flaws overly obvious. Include complex patterns like parameter tampering, unvalidated HTTP redirects, unsafe deserialization, hardcoded secrets, weak cryptographic hashes (MD5/SHA1), or command injection.
3. **Clean Syntax**: Ensure the code compiles/parses cleanly in {language} without syntax errors.
4. **Preserve Return Types**: Functions should have clear return values (dicts, lists, tuples, or responses) so refactoring can preserve business logic contracts (Zero-Regression).

Return ONLY the valid JSON array without any markdown conversational wrapper around it.
"""

def generate_prompt(language: str = "Python 3.12", domain: str = "Backend APIs & Microservices", count: int = 5):
    return MASTER_PROMPT_TEMPLATE.format(language=language, domain=domain, count=count)

def main():
    parser = argparse.ArgumentParser(description="Generate AI Security Test Case Prompts for ChatGPT / Claude / Gemini")
    parser.add_argument("--lang", default="Python", help="Programming language (Python, JavaScript/Node.js, Go)")
    parser.add_argument("--domain", default="Web APIs & Cloud Microservices", help="Domain category")
    parser.add_argument("--count", type=int, default=5, help="Number of test cases to request")
    args = parser.parse_args()

    print("==========================================================================")
    print(f"  MASTER PROMPT FOR OTHER AIs ({args.lang} - {args.domain})")
    print("==========================================================================\n")
    print(generate_prompt(args.lang, args.domain, args.count))
    print("==========================================================================")
    print("Másold ki a fenti szöveget, küldd el bármelyik AI-nak (ChatGPT / Claude / Gemini),")
    print("és a kapott JSON kimenetet közvetlenül tesztelheted a SafeCode-AI felületén!")

if __name__ == "__main__":
    main()
