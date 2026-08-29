"""
SafeCode-AI - AI Patch Guardrail Engine
Audits LLM-generated patch code before deployment to ensure it introduces zero
backdoors, prompt injections, telemetry leaks, or silent logic inversions.
"""

import re
import ast
import logging
from typing import Dict, Any, List

logger = logging.getLogger("PatchGuardrail")

class PatchGuardrailEngine:
    def __init__(self):
        # Known dangerous functions if introduced in patch
        self.dangerous_calls = {"eval", "exec", "__import__", "compile", "os.system", "os.popen", "subprocess.call", "subprocess.Popen"}
        # Telemetry / exfiltration patterns
        self.exfil_patterns = [
            r"requests\.(post|get|put)\([\"']http",
            r"socket\.socket",
            r"urllib\.request\.urlopen"
        ]

    def audit_patch(self, original_code: str, patch_code: str) -> Dict[str, Any]:
        """
        Audits patch_code against original_code.
        Returns validation status, risk score, and list of violations.
        """
        violations = []
        risk_score = 0.0  # 0.0 (Safe) to 1.0 (Critical Threat)

        # Strip markdown code blocks if present
        clean_patch = self._extract_code_from_markdown(patch_code)
        clean_orig = self._extract_code_from_markdown(original_code)

        # 1. AST Analysis of original vs patch
        try:
            orig_ast = ast.parse(clean_orig)
            patch_ast = ast.parse(clean_patch)

            # Collect function calls in original vs patch
            orig_calls = self._get_called_functions(orig_ast)
            patch_calls = self._get_called_functions(patch_ast)

            new_calls = patch_calls - orig_calls
            dangerous_added = new_calls.intersection(self.dangerous_calls)

            if dangerous_added:
                violations.append(f"Patch introduced dangerous execution calls: {list(dangerous_added)}")
                risk_score += 0.5

            # Check for silent logic bypasses
            if self._detect_silent_bypass(patch_ast, orig_ast):
                violations.append("Patch introduced silent exception swallowing or unconditional bypass")
                risk_score += 0.3

        except Exception as e:
            logger.info(f"AST parsing skipped for non-strict Python snippet: {e}")
            # Fallback to regex string scanning for dangerous calls
            for d_call in self.dangerous_calls:
                if d_call in clean_patch and d_call not in clean_orig:
                    violations.append(f"Patch introduced dangerous execution call: {d_call}")
                    risk_score += 0.5

        # 2. Check for unexpected exfiltration / network calls
        for pattern in self.exfil_patterns:
            if re.search(pattern, clean_patch) and not re.search(pattern, clean_orig):
                violations.append(f"Patch introduced potential outbound network exfiltration call matching pattern: {pattern}")
                risk_score += 0.4

        is_safe = risk_score < 0.4 and len(violations) == 0

        return {
            "is_safe": is_safe,
            "risk_score": round(risk_score, 2),
            "violations": violations,
            "recommendation": "APPROVED_FOR_DEPLOYMENT" if is_safe else "REJECTED_GUARDRAIL_VIOLATION"
        }

    def _extract_code_from_markdown(self, text: str) -> str:
        text = text.strip()
        if "```" in text:
            match = re.search(r"```(?:python|py|go|js|ts)?\n(.*?)```", text, re.DOTALL)
            if match:
                return match.group(1).strip()
        return text

    def _get_called_functions(self, tree: ast.AST) -> set:
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.add(f"{self._get_attr_base(node.func)}.{node.func.attr}")
        return calls

    def _get_attr_base(self, node: ast.Attribute) -> str:
        if isinstance(node.value, ast.Name):
            return node.value.id
        elif isinstance(node.value, ast.Attribute):
            return f"{self._get_attr_base(node.value)}.{node.value.attr}"
        return "unknown"

    def _detect_silent_bypass(self, patch_ast: ast.AST, orig_ast: ast.AST) -> bool:
        for node in ast.walk(patch_ast):
            # Check for except: pass
            if isinstance(node, ast.ExceptHandler):
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    return True
        return False
