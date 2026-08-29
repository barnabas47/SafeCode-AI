from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import os
import json

from src.agents.omniclaim_agent import OmniClaimAgent
from src.agents.safecode_agent import SafeCodeAgent
from src.serverless.jobs_runner import NebiusServerlessJobRunner
from src.rules.custom_knowledge_ingestion import CustomKnowledgeIngestionEngine
from src.git_integration import GitIntegrationEngine
from src.config import settings

app = FastAPI(
    title="SafeCode-AI Enterprise Security Platform",
    description="Multi-Agent AI Platform running NVIDIA Nemotron models on Nebius Token Factory & Serverless Infrastructure.",
    version="2.0.0"
)

omni_agent = OmniClaimAgent()
safe_agent = SafeCodeAgent()
job_runner = NebiusServerlessJobRunner()
knowledge_engine = CustomKnowledgeIngestionEngine()
git_engine = GitIntegrationEngine()

PRESETS_DATA = {
    "sqli": {
        "desc": "SQL Injection via unsafe string interpolation in query_user_records",
        "code": "def query_user_records(self, search_term: str, role_filter: str) -> List[Tuple[int, str, str, str]]:\n    cursor = self.db.cursor()\n    # VULNERABLE: Direct string formatting allows SQL Injection\n    raw_sql = f\"SELECT id, username, role, email FROM users WHERE username LIKE '%{search_term}%' AND role = '{role_filter}'\"\n    cursor.execute(raw_sql)\n    return cursor.fetchall()",
        "lang": "Python 3.12"
    },
    "ssrf": {
        "desc": "SSRF vulnerability accessing internal cloud metadata endpoint",
        "code": "def fetch_url(url: str):\n    return requests.get(url, timeout=5).text",
        "lang": "Python 3.12"
    },
    "node": {
        "desc": "Command Injection via child_process.exec in Express route",
        "code": "app.get('/api/ping', (req, res) => {\n    const host = req.query.host;\n    // VULNERABLE: Command Injection in Node.js\n    exec(\"ping -c 1 \" + host, (err, stdout) => {\n        res.send(stdout);\n    });\n});",
        "lang": "JavaScript / Node.js"
    },
    "go": {
        "desc": "SQL Injection via fmt.Sprintf in Go GORM / SQL driver",
        "code": "func SearchUser(db *sql.DB, username string) (*User, error) {\n    // VULNERABLE: Direct string format in Go SQL query\n    query := fmt.Sprintf(\"SELECT id, username, email FROM users WHERE username = '%s'\", username)\n    row := db.QueryRow(query)\n    var u User\n    err := row.Scan(&u.ID, &u.Username, &u.Email)\n    return &u, err\n}",
        "lang": "Go (Golang)"
    },
    "pickle": {
        "desc": "Unsafe deserialization using pickle.loads before type validation",
        "code": "def process_event(payload: bytes):\n    event = pickle.loads(payload)\n    if not isinstance(event, InvoiceEvent):\n        raise ValueError(\"Unexpected event type\")\n    return event",
        "lang": "Python 3.12"
    }
}

class ClaimRequest(BaseModel):
    claim_id: str
    policy_holder: str
    amount: float
    description: str

class CodePatchRequest(BaseModel):
    code_snippet: str
    vulnerability: str

class KnowledgeIngestionRequest(BaseModel):
    title: str
    description: str
    sample_code: str
    category: Optional[str] = "INJECTION"

class GitInstallRequest(BaseModel):
    repo: Optional[str] = "barnabas47/SafeCode-AI"
    branch: Optional[str] = "main"
    token: Optional[str] = None

@app.get("/", response_class=HTMLResponse)
def index():
    presets_json = json.dumps(PRESETS_DATA)
    return f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeCode-AI | Enterprise Security Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    colors: {{
                        brand: {{ 500: '#38bdf8', 600: '#0284c7', 700: '#0369a1' }},
                        accent: {{ 500: '#818cf8', 600: '#4f46e5' }}
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ background: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #060911 70%); font-family: system-ui, -apple-system, sans-serif; }}
        .glass {{ background: rgba(15, 23, 42, 0.45); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); }}
        .glass-card {{ background: rgba(15, 23, 42, 0.35); backdrop-filter: blur(16px); }}
        .glow-btn {{ box-shadow: 0 0 25px rgba(56, 189, 248, 0.4); }}
        .glow-btn:hover {{ box-shadow: 0 0 35px rgba(56, 189, 248, 0.65); }}
        pre[class*="language-"] {{ background: #020617 !important; border-radius: 1rem; margin: 0; border: none !important; box-shadow: inset 0 2px 8px rgba(0,0,0,0.5); }}
        * {{ border: none !important; outline: none !important; }}
    </style>
</head>
<body class="min-h-screen text-slate-100 antialiased selection:bg-sky-500 selection:text-white pb-12">
    <!-- Top Navigation Bar -->
    <nav class="sticky top-0 z-50 glass py-4 px-6 mb-8 shadow-2xl shadow-black/40">
        <div class="max-w-7xl mx-auto flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-2xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/30">
                    <i class="fa-solid fa-shield-halved text-white text-lg"></i>
                </div>
                <div>
                    <span class="text-xl font-black tracking-tight bg-gradient-to-r from-sky-400 via-indigo-300 to-purple-400 bg-clip-text text-transparent">SafeCode-AI</span>
                    <span class="ml-2 text-xs font-bold px-3 py-1 rounded-full bg-indigo-950/60 text-indigo-300 shadow-sm">Enterprise 4.0</span>
                </div>
            </div>
            <div class="flex items-center gap-3">
                <button onclick="openKnowledgeModal()" class="text-xs font-bold bg-indigo-900/60 hover:bg-indigo-800 text-indigo-200 px-3.5 py-2 rounded-xl shadow-md transition flex items-center gap-2">
                    <i class="fa-solid fa-brain text-sky-400"></i> Learn Custom Rule
                </button>
                <button onclick="openGitModal()" class="text-xs font-bold bg-slate-900/80 hover:bg-slate-800 text-slate-200 px-3.5 py-2 rounded-xl shadow-md transition flex items-center gap-2">
                    <i class="fa-brands fa-git-alt text-orange-400"></i> Install CI/CD Hooks
                </button>
                <span class="flex items-center gap-2 text-xs font-semibold text-slate-300 bg-slate-900/80 px-4 py-2 rounded-full shadow-lg shadow-black/30">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shadow-sm shadow-emerald-400"></span>
                    Nebius Token Factory + NVIDIA Nemotron-3
                </span>
            </div>
        </div>
    </nav>

    <div class="max-w-7xl mx-auto px-6">
        <!-- Sleek Minimal Header -->
        <div class="mb-8 text-center max-w-3xl mx-auto">
            <h1 class="text-3xl font-black tracking-tight text-white mb-2">Autonomous Security Refactoring Platform</h1>
            <p class="text-slate-400 text-sm font-medium">Powered by NVIDIA OpenShell, Nebius Sandboxes & OWASP/CWE Taxonomy Rules</p>
        </div>

        <!-- Tab Navigation -->
        <div class="flex justify-center mb-8">
            <div class="glass p-1.5 rounded-2xl inline-flex gap-2 shadow-2xl shadow-black/40">
                <button id="btnTabCoding" onclick="switchTab('coding')" class="px-6 py-2.5 rounded-xl font-extrabold text-sm transition-all duration-200 bg-gradient-to-r from-sky-500 to-indigo-600 text-white shadow-lg shadow-sky-500/25">
                    <i class="fa-solid fa-code me-2"></i>SafeCode-AI (Coding Track)
                </button>
                <button id="btnTabApps" onclick="switchTab('apps')" class="px-6 py-2.5 rounded-xl font-bold text-sm transition-all duration-200 text-slate-400 hover:text-slate-200">
                    <i class="fa-solid fa-robot me-2"></i>OmniClaim-AI (Apps Track)
                </button>
            </div>
        </div>

        <!-- SafeCode View -->
        <div id="viewCoding" class="space-y-6">
            <!-- Preset Sample Selector Pills -->
            <div class="flex items-center justify-between flex-wrap gap-3 glass p-4 rounded-2xl shadow-xl shadow-black/30">
                <span class="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <i class="fa-solid fa-wand-magic-sparkles text-sky-400"></i> Sample Benchmarks (Python, JS/TS, Go):
                </span>
                <div class="flex items-center gap-2 flex-wrap">
                    <button onclick="loadPreset('sqli')" class="px-4 py-2 rounded-xl text-xs font-bold bg-slate-900/80 hover:bg-sky-900/60 hover:text-sky-300 text-slate-300 transition shadow-md">
                        Python SQLi
                    </button>
                    <button onclick="loadPreset('ssrf')" class="px-4 py-2 rounded-xl text-xs font-bold bg-slate-900/80 hover:bg-sky-900/60 hover:text-sky-300 text-slate-300 transition shadow-md">
                        Python SSRF
                    </button>
                    <button onclick="loadPreset('node')" class="px-4 py-2 rounded-xl text-xs font-bold bg-slate-900/80 hover:bg-sky-900/60 hover:text-sky-300 text-slate-300 transition shadow-md">
                        Node.js Exec Injection
                    </button>
                    <button onclick="loadPreset('go')" class="px-4 py-2 rounded-xl text-xs font-bold bg-slate-900/80 hover:bg-sky-900/60 hover:text-sky-300 text-slate-300 transition shadow-md">
                        Go SQL Sprintf
                    </button>
                    <button onclick="loadPreset('pickle')" class="px-4 py-2 rounded-xl text-xs font-bold bg-slate-900/80 hover:bg-sky-900/60 hover:text-sky-300 text-slate-300 transition shadow-md">
                        Pickle RCE
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <!-- Left: Code Input -->
                <div class="glass-card rounded-3xl p-6 space-y-4 shadow-2xl shadow-black/50">
                    <div class="flex items-center justify-between">
                        <span class="text-sm font-bold text-slate-200 flex items-center gap-2">
                            <i class="fa-solid fa-terminal text-sky-400"></i> Vulnerable Source Code
                        </span>
                        <span id="langLabel" class="text-xs text-slate-500 font-mono font-semibold">Python 3.12</span>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label class="text-xs font-bold text-slate-400 mb-1.5 block uppercase tracking-wider">Vulnerability Description:</label>
                            <input type="text" id="vulnDesc" class="w-full bg-slate-950/80 text-slate-200 text-sm px-4 py-3 rounded-xl shadow-inner focus:ring-2 focus:ring-sky-500/40 transition" 
                                   value="SQL Injection via unsafe string interpolation in query_user_records">
                        </div>
                        <div>
                            <label class="text-xs font-bold text-slate-400 mb-1.5 block uppercase tracking-wider">Remediation Strategy:</label>
                            <select id="remediationStrategy" class="w-full bg-slate-950/80 text-sky-300 text-xs px-4 py-3 rounded-xl shadow-inner focus:ring-2 focus:ring-sky-500/40 transition font-semibold">
                                <option value="auto">⚡ Auto (Best Security Pattern)</option>
                                <option value="parameterized">🔒 Parameterized Query / Type-Safe Tuple</option>
                                <option value="domain_whitelist">🌐 Domain Whitelist & Metadata Isolation</option>
                                <option value="safe_deserialization">📦 Type-Safe JSON Deserialization</option>
                            </select>
                        </div>
                    </div>

                    <div>
                        <label class="text-xs font-bold text-slate-400 mb-1.5 block uppercase tracking-wider">Source Code Snippet:</label>
                        <textarea id="codeSnippet" rows="12" class="w-full bg-slate-950/90 text-sky-300 font-mono text-xs p-4 rounded-xl shadow-inner focus:ring-2 focus:ring-sky-500/40 transition leading-relaxed">def query_user_records(self, search_term: str, role_filter: str) -> List[Tuple[int, str, str, str]]:
    cursor = self.db.cursor()
    # VULNERABLE: Direct string formatting allows SQL Injection
    raw_sql = f"SELECT id, username, role, email FROM users WHERE username LIKE '%{{search_term}}%' AND role = '{{role_filter}}'"
    cursor.execute(raw_sql)
    return cursor.fetchall()</textarea>
                    </div>

                    <button id="btnPatch" onclick="runSafeCodePatch()" class="w-full py-4 rounded-2xl font-black text-sm bg-gradient-to-r from-sky-500 via-indigo-600 to-purple-600 text-white glow-btn hover:opacity-95 transition duration-200 flex items-center justify-center gap-2 shadow-xl">
                        <i class="fa-solid fa-shield-virus text-base"></i> Run 4-Stage Remediation Loop
                    </button>
                </div>

                <div class="glass-card rounded-3xl p-6 space-y-4 shadow-2xl shadow-black/50">
                    <div class="flex items-center justify-between">
                        <span class="text-sm font-bold text-slate-200 flex items-center gap-2">
                            <i class="fa-solid fa-microchip text-indigo-400"></i> Verification Timeline & Report
                        </span>
                        <div class="flex items-center gap-2">
                            <a id="btnDownloadReport" target="_blank" class="hidden text-xs font-extrabold px-3.5 py-2 rounded-xl bg-gradient-to-r from-rose-600 via-red-600 to-rose-700 hover:from-rose-500 hover:to-red-500 text-white transition-all duration-200 flex items-center gap-2 shadow-lg shadow-rose-950/60 cursor-pointer">
                                <i class="fa-solid fa-file-pdf text-sm text-rose-100"></i> Download PDF Report
                            </a>
                            <span id="badgeStatus" class="hidden text-xs font-extrabold px-3.5 py-1.5 rounded-full bg-emerald-950/90 text-emerald-300 shadow-md">
                                <i class="fa-solid fa-circle-check me-1"></i> ZERO REGRESSION PASSED
                            </span>
                        </div>
                    </div>

                    <div id="stageResults" class="space-y-4 min-h-[380px] flex flex-col justify-center">
                        <div class="text-center py-12 text-slate-500">
                            <i class="fa-solid fa-shield-halved text-4xl mb-3 text-slate-700"></i>
                            <p class="text-sm font-semibold">Click "Run 4-Stage Remediation Loop" to trigger the multi-agent pipeline.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- OmniClaim View -->
        <div id="viewApps" class="hidden glass-card rounded-3xl p-8 space-y-6 shadow-2xl shadow-black/50">
            <div>
                <h3 class="text-xl font-extrabold text-white mb-1"><i class="fa-solid fa-robot text-indigo-400 me-2"></i>OmniClaim-AI Multi-Model Routing</h3>
                <p class="text-slate-400 text-sm">Nemotron Nano (fast parsing) + Nemotron Ultra (deep fraud reasoning) multi-model routing.</p>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <input type="text" id="claimId" class="bg-slate-950 text-slate-200 text-sm p-3 rounded-xl shadow-inner" value="CLM-2026-991">
                <input type="text" id="policyHolder" class="bg-slate-950 text-slate-200 text-sm p-3 rounded-xl shadow-inner" value="Jane Smith">
                <input type="number" id="claimAmount" class="bg-slate-950 text-slate-200 text-sm p-3 rounded-xl shadow-inner" value="3450.00">
                <button onclick="runClaimProcess()" class="py-3 rounded-xl font-bold text-sm bg-gradient-to-r from-indigo-600 to-purple-600 hover:opacity-90 text-white shadow-lg transition">Process Claim</button>
            </div>
            <div id="claimOutput" class="mt-4"></div>
        </div>
    </div>

    <!-- Git Integration & CI/CD Configuration Modal -->
    <div id="modalGit" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-md p-4">
        <div class="glass-card rounded-3xl p-6 max-w-lg w-full space-y-4 shadow-2xl">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-bold text-white"><i class="fa-brands fa-git-alt text-orange-400 me-2"></i>Git CI/CD & GitHub PR Configuration</h3>
                <button onclick="closeGitModal()" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark text-lg"></i></button>
            </div>
            <p class="text-xs text-slate-400 leading-relaxed">
                Configure your target GitHub repository and branch. SafeCode-AI will install local pre-commit hooks, generate GitHub Action workflows, and create automated PRs.
            </p>
            <div class="space-y-3">
                <div>
                    <label class="text-xs font-bold text-slate-400 mb-1 block">Target GitHub Repository (Owner/Repo):</label>
                    <input type="text" id="gitRepo" value="barnabas47/SafeCode-AI" placeholder="e.g. barnabas47/SafeCode-AI" class="w-full bg-slate-950 text-slate-200 text-sm p-3 rounded-xl shadow-inner font-mono">
                </div>
                <div>
                    <label class="text-xs font-bold text-slate-400 mb-1 block">Target Branch:</label>
                    <input type="text" id="gitBranch" value="main" placeholder="main" class="w-full bg-slate-950 text-slate-200 text-sm p-3 rounded-xl shadow-inner font-mono">
                </div>
                <div>
                    <label class="text-xs font-bold text-slate-400 mb-1 block">GitHub Access Token (Optional for live API PRs):</label>
                    <input type="password" id="gitToken" placeholder="ghp_xxxxxxxxxxxxxxxxxxxx" class="w-full bg-slate-950 text-slate-200 text-sm p-3 rounded-xl shadow-inner font-mono">
                </div>
            </div>
            <button onclick="submitGitIntegration()" class="w-full py-3 rounded-xl font-bold bg-gradient-to-r from-orange-500 to-amber-600 hover:opacity-90 text-white shadow-lg transition">
                <i class="fa-brands fa-git-alt me-1.5"></i> Install Pre-Commit Hooks & Generate CI/CD Workflows
            </button>
            <div id="gitStatus" class="text-xs space-y-1"></div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
    <script>
        const PRESETS = {presets_json};

        function switchTab(tab) {{
            const codingView = document.getElementById("viewCoding");
            const appsView = document.getElementById("viewApps");
            const btnCoding = document.getElementById("btnTabCoding");
            const btnApps = document.getElementById("btnTabApps");

            if(tab === 'coding') {{
                codingView.classList.remove("hidden");
                appsView.classList.add("hidden");
                btnCoding.className = "px-6 py-2.5 rounded-xl font-extrabold text-sm transition-all duration-200 bg-gradient-to-r from-sky-500 to-indigo-600 text-white shadow-lg shadow-sky-500/25";
                btnApps.className = "px-6 py-2.5 rounded-xl font-bold text-sm transition-all duration-200 text-slate-400 hover:text-slate-200";
            }} else {{
                codingView.classList.add("hidden");
                appsView.classList.remove("hidden");
                btnApps.className = "px-6 py-2.5 rounded-xl font-extrabold text-sm transition-all duration-200 bg-gradient-to-r from-sky-500 to-indigo-600 text-white shadow-lg shadow-sky-500/25";
                btnCoding.className = "px-6 py-2.5 rounded-xl font-bold text-sm transition-all duration-200 text-slate-400 hover:text-slate-200";
            }}
        }}

        function loadPreset(type) {{
            const p = PRESETS[type];
            if(p) {{
                document.getElementById("vulnDesc").value = p.desc;
                document.getElementById("codeSnippet").value = p.code;
                document.getElementById("langLabel").innerText = p.lang;
            }}
        }}

        function openKnowledgeModal() {{ document.getElementById("modalKnowledge").classList.remove("hidden"); }}
        function closeKnowledgeModal() {{ document.getElementById("modalKnowledge").classList.add("hidden"); }}

        async function submitKnowledgeIngestion() {{
            const statusDiv = document.getElementById("knowledgeStatus");
            statusDiv.innerHTML = '<span class="text-sky-400 font-semibold"><i class="fa-solid fa-spinner fa-spin me-1"></i> Synthesizing rules with Nemotron-3 Ultra...</span>';
            try {{
                const res = await fetch("/api/knowledge/learn", {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify({{
                        title: document.getElementById("customTitle").value,
                        category: document.getElementById("customCat").value,
                        description: document.getElementById("customDesc").value,
                        sample_code: document.getElementById("customCode").value
                    }})
                }});
                const data = await res.json();
                statusDiv.innerHTML = `<span class="text-emerald-400 font-bold"><i class="fa-solid fa-circle-check me-1"></i> ${{data.message}}</span>`;
                setTimeout(closeKnowledgeModal, 2000);
            }} catch(err) {{
                statusDiv.innerHTML = `<span class="text-rose-400">Error: ${{err.message}}</span>`;
            }}
        }}

        function openGitModal() {{ document.getElementById("modalGit").classList.remove("hidden"); }}
        function closeGitModal() {{ document.getElementById("modalGit").classList.add("hidden"); }}

        async function submitGitIntegration() {{
            const statusDiv = document.getElementById("gitStatus");
            const repo = document.getElementById("gitRepo").value;
            const branch = document.getElementById("gitBranch").value;
            const token = document.getElementById("gitToken").value;
            
            statusDiv.innerHTML = '<div class="text-amber-400 font-semibold mt-2"><i class="fa-solid fa-spinner fa-spin me-1.5"></i> Generating CI/CD workflow & pushing to remote GitHub...</div>';
            
            try {{
                const res = await fetch("/api/git/install-hook", {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify({{ repo, branch, token }})
                }});
                const data = await res.json();
                const pushInfo = data.push_status || {{}};
                
                let pushMsg = pushInfo.success 
                    ? `<div class="text-emerald-300 font-bold flex items-center gap-1.5"><i class="fa-solid fa-cloud-arrow-up"></i> Pushed to GitHub: <a href="${{escapeHtml(pushInfo.target_url || '#')}}" target="_blank" class="underline text-sky-300 font-bold">${{escapeHtml(repo)}}</a></div>`
                    : `<div class="text-rose-300 text-[11px] bg-rose-950/60 p-2.5 rounded-xl border border-rose-800/40 leading-relaxed mt-1"><i class="fa-solid fa-circle-xmark text-rose-400 me-1"></i> ${{escapeHtml(pushInfo.message || pushInfo.error || "Push failed")}}</div>`;

                statusDiv.innerHTML = `
                    <div class="p-3 rounded-xl bg-emerald-950/80 text-emerald-300 space-y-1.5 shadow-md mt-2">
                        <div class="font-bold flex items-center gap-1.5"><i class="fa-solid fa-circle-check"></i> Git CI/CD Integration Completed!</div>
                        <div>1. Pre-Commit Hook: <code class="text-xs font-mono text-slate-200">.git/hooks/pre-commit</code></div>
                        <div>2. GitHub Action: <code class="text-xs font-mono text-slate-200">.github/workflows/safecode-audit.yml</code></div>
                        ${{pushMsg}}
                    </div>
                `;
            }} catch(err) {{
                statusDiv.innerHTML = `<div class="text-rose-400 mt-2 font-semibold">Install Failed: ${{escapeHtml(err.message)}}</div>`;
            }}
        }}

        async function runSafeCodePatch() {{
            const btn = document.getElementById("btnPatch");
            const resDiv = document.getElementById("stageResults");
            const badge = document.getElementById("badgeStatus");
            const btnPdf = document.getElementById("btnDownloadReport");
            
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Executing Multi-Agent Pipeline...';
            badge.classList.add("hidden");
            btnPdf.classList.add("hidden");

            resDiv.innerHTML = `
                <div class="p-6 rounded-2xl bg-slate-950/80 text-slate-300 space-y-3 shadow-lg">
                    <div class="flex items-center gap-3 font-bold text-sky-400 text-sm">
                        <i class="fa-solid fa-circle-notch fa-spin text-lg"></i>
                        Stage 1: Threat Architect Analyzing AST & Taxonomy...
                    </div>
                </div>
            `;

            try {{
                const response = await fetch("/api/code/patch", {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify({{
                        code_snippet: document.getElementById("codeSnippet").value,
                        vulnerability: document.getElementById("vulnDesc").value
                    }})
                }});
                const data = await response.json();

                if(response.ok && data.status === "SUCCESS" && data.executive_report && data.executive_report.filename) {{
                    btnPdf.href = `/api/report/download/${{data.executive_report.filename}}`;
                    btnPdf.classList.remove("hidden");
                    badge.classList.remove("hidden");
                }} else {{
                    btnPdf.classList.add("hidden");
                    badge.classList.add("hidden");
                }}

                const catInfo = data.taxonomy_classification || {{}};

                window.currentPatchCode = data.patch_code || "";

                resDiv.innerHTML = `
                    <!-- Category Badge -->
                    <div class="p-4 rounded-2xl bg-indigo-950/50 flex items-center justify-between shadow-md">
                        <span class="text-xs font-black text-indigo-300 uppercase tracking-wider">
                            <i class="fa-solid fa-layer-group me-1.5"></i>Taxonomy: ${{catInfo.category_name || 'Injection'}}
                        </span>
                        <span class="text-xs font-mono text-indigo-400 font-bold">${{(catInfo.cwe_list || []).join(', ')}}</span>
                    </div>

                    <!-- Stage 1 -->
                    <div class="p-4 rounded-2xl bg-slate-950/50 space-y-1.5 shadow-md">
                        <span class="text-xs font-black text-sky-400 uppercase tracking-wider block">Stage 1: Threat Architect Analysis</span>
                        <p class="text-xs text-slate-300 whitespace-pre-line leading-relaxed font-medium">${{escapeHtml(data.architect_analysis || '')}}</p>
                    </div>

                    <!-- Stage 2: Complete Refactored Code -->
                    <div class="p-4 rounded-2xl bg-slate-950/50 space-y-2 shadow-md">
                        <div class="flex items-center justify-between">
                            <span class="text-xs font-black text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                                <i class="fa-solid fa-code-compare text-amber-400"></i> Stage 2: Refactored Source Code (Zero Regression)
                            </span>
                            <button id="btnCopyCode" onclick="copyRefactoredCode()" class="text-xs font-bold px-3 py-1 rounded-xl bg-amber-950/90 hover:bg-amber-900 text-amber-300 transition flex items-center gap-1.5 shadow-md cursor-pointer">
                                <i class="fa-solid fa-copy text-xs"></i> Copy Fixed Code
                            </button>
                        </div>
                        <div class="text-[11px] text-emerald-400 font-mono font-semibold bg-emerald-950/40 px-3 py-1.5 rounded-lg flex items-center gap-2">
                            <i class="fa-solid fa-circle-check"></i> Complete refactored code – replace your vulnerable function/file with this output
                        </div>
                        <pre><code class="language-python">${{escapeHtml(data.patch_code || '')}}</code></pre>
                    </div>

                    <!-- Stage 3 & 4 Grid -->
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div class="p-4 rounded-2xl bg-slate-950/50 shadow-md">
                            <span class="text-xs font-black text-emerald-400 uppercase tracking-wider block mb-1">Stage 3: OpenShell Sandbox</span>
                            <p class="text-xs text-slate-400 leading-relaxed whitespace-pre-line font-medium">${{escapeHtml(data.sandbox_verification || '')}}</p>
                        </div>
                        <div class="p-4 rounded-2xl bg-slate-950/50 shadow-md">
                            <span class="text-xs font-black text-purple-400 uppercase tracking-wider block mb-1">Stage 4: Red-Team Attestation</span>
                            <p class="text-xs text-slate-400 leading-relaxed whitespace-pre-line font-medium">${{escapeHtml(data.red_team_attestation || '')}}</p>
                        </div>
                    </div>
                `;

                console.log("SafeCode Patch Result:", data);
                try {{
                    if (window.Prism) {{ Prism.highlightAll(); }}
                }} catch(pErr) {{
                    console.warn("Prism syntax highlight warning:", pErr);
                }}
            }} catch(err) {{
                console.error("SafeCode Patch Execution Error:", err);
                btnPdf.classList.add("hidden");
                badge.classList.add("hidden");
                resDiv.innerHTML = `<div class="p-4 rounded-2xl bg-rose-950/80 text-rose-300 text-sm font-semibold shadow-lg">
                    <i class="fa-solid fa-triangle-exclamation me-2"></i>Error Executing Audit: ${{escapeHtml(err.message || String(err))}}
                </div>`;
            }} finally {{
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-shield-virus me-2"></i> Run 4-Stage Remediation Loop';
            }}
        }}

        function escapeHtml(str) {{
            return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }}

        function copyRefactoredCode() {{
            if (!window.currentPatchCode) return;
            navigator.clipboard.writeText(window.currentPatchCode).then(() => {{
                const btn = document.getElementById("btnCopyCode");
                if (btn) {{
                    btn.innerHTML = '<i class="fa-solid fa-check text-emerald-400 me-1"></i> Copied to Clipboard!';
                    setTimeout(() => {{
                        btn.innerHTML = '<i class="fa-solid fa-copy text-xs me-1"></i> Copy Fixed Code';
                    }}, 2000);
                }}
            }}).catch(e => {{
                alert("Copy failed: " + e.message);
            }});
        }}

        async function runClaimProcess() {{
            const outDiv = document.getElementById("claimOutput");
            outDiv.innerHTML = '<div class="text-sky-400 text-sm font-bold"><i class="fa-solid fa-spinner fa-spin me-2"></i>Routing through Nemotron Nano & Ultra...</div>';
            try {{
                const res = await fetch("/api/claim/process", {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify({{
                        claim_id: document.getElementById("claimId").value,
                        policy_holder: document.getElementById("policyHolder").value,
                        amount: parseFloat(document.getElementById("claimAmount").value),
                        description: "Automated claim submission"
                    }})
                }});
                const data = await res.json();
                outDiv.innerHTML = `<pre><code class="language-json">${{JSON.stringify(data, null, 2)}}</code></pre>`;
                try {{ if (window.Prism) Prism.highlightAll(); }} catch(e) {{}}
            }} catch(e) {{
                outDiv.innerHTML = `<div class="p-4 rounded-2xl bg-rose-950/80 text-rose-300 text-sm font-semibold shadow-lg">${{e.message}}</div>`;
            }}
        }}
    </script>
</body>
</html>"""

@app.post("/api/claim/process")
def process_claim_endpoint(claim: ClaimRequest):
    try:
        result = omni_agent.process_claim(claim.model_dump())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/code/patch")
def code_patch_endpoint(req: CodePatchRequest):
    try:
        result = safe_agent.audit_and_patch(req.code_snippet, req.vulnerability)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/knowledge/learn")
def learn_vulnerability_endpoint(req: KnowledgeIngestionRequest):
    try:
        result = knowledge_engine.learn_custom_vulnerability(
            title=req.title,
            description=req.description,
            sample_code=req.sample_code,
            category=req.category
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/git/install-hook")
def install_git_hook_endpoint(req: Optional[GitInstallRequest] = None):
    try:
        hook_res = git_engine.install_pre_commit_hook()
        wf_res = git_engine.generate_github_action()

        target_repo = req.repo if req and req.repo else "barnabas47/SafeCode-AI"
        target_branch = req.branch if req and req.branch else "main"
        target_token = req.token if req else None

        push_res = git_engine.push_to_remote_github(target_repo, target_branch, target_token)

        return {
            "hook_status": hook_res,
            "workflow_status": wf_res,
            "push_status": push_res
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/report/download/{filename}")
def download_report_endpoint(filename: str):
    file_path = os.path.join("reports", filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(file_path, media_type="text/html", filename=filename)

@app.post("/api/serverless/job")
def create_job_endpoint(claims: List[ClaimRequest]):
    try:
        claims_data = [c.model_dump() for c in claims]
        result = job_runner.run_batch_claims_job(claims_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
