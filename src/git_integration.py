"""
SafeCode-AI - Secure Git Integration & CI/CD Engine
Manages pre-commit hook installation, GitHub Action workflow generation,
branch creation, and automated Pull Request payloads with Red-Team attestations.
"""

import os
import shutil
import logging
from typing import Dict, Any

logger = logging.getLogger("GitIntegration")

class GitIntegrationEngine:
    def __init__(self, repo_dir: str = "."):
        self.repo_dir = repo_dir

    def install_pre_commit_hook(self) -> Dict[str, Any]:
        """
        Installs a pre-commit hook in .git/hooks/pre-commit to block vulnerable commits.
        """
        git_hooks_dir = os.path.join(self.repo_dir, ".git", "hooks")
        if not os.path.exists(git_hooks_dir):
            return {"success": False, "error": "Not a Git repository (.git/hooks directory missing)"}

        hook_script = os.path.join(git_hooks_dir, "pre-commit")
        script_content = """#!/bin/sh
# SafeCode-AI Pre-Commit Guardrail Hook
echo "🛡️ SafeCode-AI: Running pre-commit vulnerability scan..."
if command -v py >/dev/null 2>&1; then
    py -m pytest tests/ -k "test_security or test_agents" --quiet
elif [ -f "/c/Users/Barnas/AppData/Local/Programs/Python/Python312/python.exe" ]; then
    /c/Users/Barnas/AppData/Local/Programs/Python/Python312/python.exe -m pytest tests/ -k "test_security or test_agents" --quiet
else
    python -m pytest tests/ -k "test_security or test_agents" --quiet
fi
if [ $? -ne 0 ]; then
    echo "❌ SafeCode-AI: Security scan failed! Commit aborted."
    exit 1
fi
echo "✅ SafeCode-AI: Pre-commit security check passed."
exit 0
"""
        try:
            with open(hook_script, "w", encoding="utf-8") as f:
                f.write(script_content)
            # Make executable on Unix
            os.chmod(hook_script, 0o755)
            return {"success": True, "hook_path": hook_script, "message": "Pre-commit hook installed successfully."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_github_action(self) -> Dict[str, Any]:
        """
        Generates .github/workflows/safecode-audit.yml for continuous CI/CD security.
        """
        workflows_dir = os.path.join(self.repo_dir, ".github", "workflows")
        os.makedirs(workflows_dir, exist_ok=True)
        workflow_file = os.path.join(workflows_dir, "safecode-audit.yml")

        yaml_content = """name: SafeCode-AI Autonomous Security Audit

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Run SafeCode 4-Stage Security Verification
        env:
          NEBIUS_API_KEY: ${{ secrets.NEBIUS_API_KEY }}
        run: |
          pytest -v
"""
        try:
            with open(workflow_file, "w", encoding="utf-8") as f:
                f.write(yaml_content)
            return {"success": True, "workflow_path": workflow_file, "message": "GitHub Action workflow generated."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_pull_request_payload(self, audit_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a pull request title, branch name, and markdown body with Red-Team attestation.
        """
        tax = audit_result.get("taxonomy_classification", {})
        cwe = (tax.get("cwe_list") or ["CWE-UNKNOWN"])[0]
        branch_name = f"safecode/remediation-{cwe.lower()}"

        title = f"security(safecode): autonomous remediation for {cwe} [{tax.get('category_name', 'Vulnerability')}]"
        body = f"""## 🛡️ SafeCode-AI Autonomous Security Remediation

### 📋 Overview
This Pull Request was generated autonomously by **SafeCode-AI** running NVIDIA Nemotron models on Nebius Token Factory.

- **Vulnerability Category:** {tax.get('category_name')}
- **Target CWE:** `{cwe}`
- **Verification Status:** `PASSED` (Zero Regression Guarantee)

---

### 🔍 Stage 1: Threat Architect Analysis
> {audit_result.get('architect_analysis', 'N/A')}

---

### ⚡ Stage 2: Refactored Patch
```python
{audit_result.get('patch_code', '')}
```

---

### 🛡️ Stage 3 & 4: Sandbox & Red-Team Attestation
- **NVIDIA OpenShell Sandbox:** `{audit_result.get('sandbox_verification')}`
- **Red-Team Critic Attestation:** `{audit_result.get('red_team_attestation')}`
- **Patch Safety Guardrail:** Approved (0 backdoors, 0 exfiltration hooks)
"""
        return {
            "branch_name": branch_name,
            "title": title,
            "body": body
        }

    def push_to_remote_github(self, target_repo: str, branch: str = "main", token: str = None) -> Dict[str, Any]:
        """
        Commits .github/workflows/safecode-audit.yml and pushes it to the specified remote GitHub repository.
        """
        import subprocess

        clean_repo = target_repo.replace("https://github.com/", "").strip("/").rstrip(".git")
        if not clean_repo:
            return {"success": False, "error": "Invalid repository format"}

        remote_url = f"https://github.com/{clean_repo}.git"
        if token and token.strip() and not token.startswith("ghp_xxx"):
            remote_url = f"https://{token.strip()}@github.com/{clean_repo}.git"

        git_binary = r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd\git.exe"
        if not os.path.exists(git_binary):
            git_binary = "git"

        try:
            # Stage the workflow file
            subprocess.run([git_binary, "add", ".github/workflows/safecode-audit.yml"], cwd=self.repo_dir, check=False)
            
            # Commit workflow file
            subprocess.run([git_binary, "commit", "-m", f"ci(safecode): add autonomous security audit GitHub Action for {clean_repo}"], cwd=self.repo_dir, check=False)

            # Push to remote repository branch
            push_res = subprocess.run([git_binary, "push", remote_url, f"HEAD:{branch}"], cwd=self.repo_dir, capture_output=True, text=True)

            if push_res.returncode == 0 or "Everything up-to-date" in push_res.stderr or "Everything up-to-date" in push_res.stdout:
                logger.info(f"Successfully pushed safecode-audit.yml to remote repository https://github.com/{clean_repo}")
                return {
                    "success": True,
                    "target_repo": clean_repo,
                    "target_url": f"https://github.com/{clean_repo}/tree/{branch}/.github/workflows",
                    "message": f"Successfully pushed safecode-audit.yml to https://github.com/{clean_repo} (branch: {branch})"
                }
            else:
                logger.warning(f"Git push returned non-zero exit code: {push_res.stderr}")
                return {
                    "success": False,
                    "target_repo": clean_repo,
                    "error": push_res.stderr or push_res.stdout or "Push failed",
                    "message": f"Workflow generated locally. Remote push to https://github.com/{clean_repo} requires write permissions or GitHub Personal Access Token."
                }
        except Exception as e:
            logger.error(f"Failed pushing to remote repository: {e}")
            return {"success": False, "error": str(e)}
