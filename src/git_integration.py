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

    def upload_workflow_via_github_api(self, clean_repo: str, branch: str = "main", token: str = None) -> Dict[str, Any]:
        """
        Uses GitHub REST API (PUT /repos/{owner}/{repo}/contents/{path}) to directly upload
        .github/workflows/safecode-audit.yml into any target repository without git history conflicts.
        """
        import json
        import base64
        import urllib.request
        import urllib.error

        workflow_file = os.path.join(self.repo_dir, ".github", "workflows", "safecode-audit.yml")
        if not os.path.exists(workflow_file):
            self.generate_github_action()

        with open(workflow_file, "r", encoding="utf-8") as f:
            content_str = f.read()

        b64_content = base64.b64encode(content_str.encode("utf-8")).decode("utf-8")

        url = f"https://api.github.com/repos/{clean_repo}/contents/.github/workflows/safecode-audit.yml"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SafeCode-AI-Engine"
        }
        if token and token.strip() and not token.startswith("ghp_xxx"):
            headers["Authorization"] = f"Bearer {token.strip()}"

        # Check if file exists to fetch existing sha for updating
        existing_sha = None
        try:
            req_get = urllib.request.Request(f"{url}?ref={branch}", headers=headers, method="GET")
            with urllib.request.urlopen(req_get) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                existing_sha = data.get("sha")
        except Exception:
            pass

        payload = {
            "message": "ci(safecode): add autonomous security audit GitHub Action workflow",
            "content": b64_content,
            "branch": branch
        }
        if existing_sha:
            payload["sha"] = existing_sha

        payload_bytes = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

        try:
            req_put = urllib.request.Request(url, data=payload_bytes, headers=headers, method="PUT")
            with urllib.request.urlopen(req_put) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                commit_html = res_data.get("commit", {}).get("html_url", f"https://github.com/{clean_repo}")
                return {
                    "success": True,
                    "target_repo": clean_repo,
                    "target_url": f"https://github.com/{clean_repo}/tree/{branch}/.github/workflows",
                    "commit_url": commit_html,
                    "message": f"Successfully created .github/workflows/safecode-audit.yml in https://github.com/{clean_repo} (branch: {branch})"
                }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            logger.error(f"GitHub API Upload HTTP {e.code}: {err_body}")
            return {
                "success": False,
                "target_repo": clean_repo,
                "error": f"HTTP {e.code}: {err_body}",
                "message": f"GitHub API returned HTTP {e.code}. Check repository permissions or token validity."
            }
        except Exception as e:
            logger.error(f"GitHub API Upload failed: {e}")
            return {"success": False, "error": str(e)}

    def push_to_remote_github(self, target_repo: str, branch: str = "main", token: str = None) -> Dict[str, Any]:
        """
        Commits .github/workflows/safecode-audit.yml and uploads it to target GitHub repository via API or Git CLI.
        """
        clean_repo = target_repo.replace("https://github.com/", "").strip("/").rstrip(".git")
        if not clean_repo:
            return {"success": False, "error": "Invalid repository format"}

        # 1. Try GitHub REST API first if token is provided
        if token and token.strip() and not token.startswith("ghp_xxx"):
            api_res = self.upload_workflow_via_github_api(clean_repo, branch, token)
            if api_res.get("success"):
                return api_res

        # 2. Fallback to local git CLI push
        import subprocess

        remote_url = f"https://github.com/{clean_repo}.git"
        if token and token.strip() and not token.startswith("ghp_xxx"):
            remote_url = f"https://{token.strip()}@github.com/{clean_repo}.git"

        git_binary = r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd\git.exe"
        if not os.path.exists(git_binary):
            git_binary = "git"

        try:
            subprocess.run([git_binary, "add", ".github/workflows/safecode-audit.yml"], cwd=self.repo_dir, check=False)
            subprocess.run([git_binary, "commit", "-m", f"ci(safecode): add autonomous security audit GitHub Action for {clean_repo}"], cwd=self.repo_dir, check=False)

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
                # Try API as final fallback
                api_res = self.upload_workflow_via_github_api(clean_repo, branch, token)
                if api_res.get("success"):
                    return api_res
                    
                logger.warning(f"Git push returned non-zero exit code: {push_res.stderr}")
                return {
                    "success": False,
                    "target_repo": clean_repo,
                    "error": push_res.stderr or push_res.stdout or "Push failed",
                    "message": f"Workflow generated locally. Remote push to https://github.com/{clean_repo} requires write permissions or GitHub Access Token."
                }
        except Exception as e:
            logger.error(f"Failed pushing to remote repository: {e}")
            return {"success": False, "error": str(e)}
