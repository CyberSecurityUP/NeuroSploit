# NeuroSploit v3

![NeuroSploit](https://img.shields.io/badge/NeuroSploit-AI--Powered%20Pentesting-blueviolet)
![Version](https://img.shields.io/badge/Version-3.0.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)
![React](https://img.shields.io/badge/React-18-61dafb)
![Vuln Types](https://img.shields.io/badge/Vuln%20Types-100-red)
![Docker](https://img.shields.io/badge/Docker-Kali%20Sandbox-informational)

**AI-Powered Autonomous Penetration Testing Platform**

NeuroSploit v3 is an advanced security assessment platform that combines AI-driven autonomous agents with 100 vulnerability types, per-scan isolated Kali Linux containers, false-positive hardening, exploit chaining, and a modern React web interface with real-time monitoring.

---

## Highlights

- **100 Vulnerability Types** across 10 categories with AI-driven testing prompts
- **Autonomous Agent** - 3-stream parallel pentest (recon + junior tester + tool runner)
- **Per-Scan Kali Containers** - Each scan runs in its own isolated Docker container
- **Anti-Hallucination Pipeline** - Negative controls, proof-of-execution, confidence scoring
- **Exploit Chain Engine** - Automatically chains findings (SSRF->internal, SQLi->DB-specific, etc.)
- **WAF Detection & Bypass** - 16 WAF signatures, 12 bypass techniques
- **Smart Strategy Adaptation** - Dead endpoint detection, diminishing returns, priority recomputation
- **Multi-Provider LLM** - Claude, GPT, Gemini, Ollama, LMStudio, OpenRouter
- **Real-Time Dashboard** - WebSocket-powered live scan progress, findings, and reports
- **Sandbox Dashboard** - Monitor running Kali containers, tools, health checks in real-time

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Autonomous Agent](#autonomous-agent)
- [100 Vulnerability Types](#100-vulnerability-types)
- [Kali Sandbox System](#kali-sandbox-system)
- [Anti-Hallucination & Validation](#anti-hallucination--validation)
- [Web GUI](#web-gui)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Development](#development)
- [Security Notice](#security-notice)

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/your-org/NeuroSploitv2.git
cd NeuroSploitv2

# Copy environment file and add your API keys
cp .env.example .env
nano .env  # Add ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY

# Build the Kali sandbox image (first time only, ~5 min)
./scripts/build-kali.sh

# Start backend
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Option 2: Manual Setup

```bash
# Backend
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

### Build Kali Sandbox Image

```bash
# Normal build (uses Docker cache)
./scripts/build-kali.sh

# Full rebuild (no cache)
./scripts/build-kali.sh --fresh

# Build + run health check
./scripts/build-kali.sh --test

# Or via docker-compose
docker compose -f docker/docker-compose.kali.yml build
```

Access the web interface at **http://localhost:8000** (production build) or **http://localhost:5173** (dev mode).

---

## Architecture

```
NeuroSploitv3/
├── backend/                         # FastAPI Backend
│   ├── api/v1/                      # REST API (13 routers)
│   │   ├── scans.py                 # Scan CRUD + pause/resume/stop
│   │   ├── agent.py                 # AI Agent control
│   │   ├── agent_tasks.py           # Scan task tracking
│   │   ├── dashboard.py             # Stats + activity feed
│   │   ├── reports.py               # Report generation (HTML/PDF/JSON)
│   │   ├── scheduler.py             # Cron/interval scheduling
│   │   ├── vuln_lab.py              # Per-type vulnerability lab
│   │   ├── terminal.py              # Terminal agent (10 endpoints)
│   │   ├── sandbox.py               # Sandbox container monitoring
│   │   ├── targets.py               # Target validation
│   │   ├── prompts.py               # Preset prompts
│   │   ├── vulnerabilities.py       # Vulnerability management
│   │   └── settings.py              # Runtime settings
│   ├── core/
│   │   ├── autonomous_agent.py      # Main AI agent (~7000 lines)
│   │   ├── vuln_engine/             # 100-type vulnerability engine
│   │   │   ├── registry.py          # 100 VULNERABILITY_INFO entries
│   │   │   ├── payload_generator.py # 526 payloads across 95 libraries
│   │   │   ├── ai_prompts.py        # Per-vuln AI decision prompts
│   │   │   ├── system_prompts.py    # 12 anti-hallucination prompts
│   │   │   └── testers/             # 10 category tester modules
│   │   ├── validation/              # False-positive hardening
│   │   │   ├── negative_control.py  # Benign request control engine
│   │   │   ├── proof_of_execution.py # Per-type proof checks (25+ methods)
│   │   │   ├── confidence_scorer.py # Numeric 0-100 scoring
│   │   │   └── validation_judge.py  # Sole authority for finding approval
│   │   ├── request_engine.py        # Retry, rate limit, circuit breaker
│   │   ├── waf_detector.py          # 16 WAF signatures + bypass
│   │   ├── strategy_adapter.py      # Mid-scan strategy adaptation
│   │   ├── chain_engine.py          # 10 exploit chain rules
│   │   ├── auth_manager.py          # Multi-user auth management
│   │   ├── xss_context_analyzer.py  # 8-context XSS analysis
│   │   ├── poc_generator.py         # 20+ per-type PoC generators
│   │   ├── execution_history.py     # Cross-scan learning
│   │   ├── access_control_learner.py # Adaptive BOLA/BFLA/IDOR learning
│   │   ├── response_verifier.py     # 4-signal response verification
│   │   ├── agent_memory.py          # Bounded dedup agent memory
│   │   └── report_engine/           # OHVR report generator
│   ├── models/                      # SQLAlchemy ORM models
│   ├── db/                          # Database layer
│   ├── config.py                    # Pydantic settings
│   └── main.py                      # FastAPI app entry
│
├── core/                            # Shared core modules
│   ├── llm_manager.py               # Multi-provider LLM routing
│   ├── sandbox_manager.py           # BaseSandbox ABC + legacy shared sandbox
│   ├── kali_sandbox.py              # Per-scan Kali container manager
│   ├── container_pool.py            # Global container pool coordinator
│   ├── tool_registry.py             # 56 tool install recipes for Kali
│   ├── mcp_server.py                # MCP server (12 tools, stdio)
│   ├── scheduler.py                 # APScheduler scan scheduling
│   └── browser_validator.py         # Playwright browser validation
│
├── frontend/                        # React + TypeScript Frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── HomePage.tsx             # Dashboard with stats
│   │   │   ├── AutoPentestPage.tsx      # 3-stream auto pentest
│   │   │   ├── VulnLabPage.tsx          # Per-type vulnerability lab
│   │   │   ├── TerminalAgentPage.tsx    # AI terminal chat
│   │   │   ├── SandboxDashboardPage.tsx # Container monitoring
│   │   │   ├── ScanDetailsPage.tsx      # Findings + validation
│   │   │   ├── SchedulerPage.tsx        # Cron/interval scheduling
│   │   │   ├── SettingsPage.tsx         # Configuration
│   │   │   └── ReportsPage.tsx          # Report management
│   │   ├── components/              # Reusable UI components
│   │   ├── services/api.ts          # API client layer
│   │   └── types/index.ts           # TypeScript interfaces
│   └── package.json
│
├── docker/
│   ├── Dockerfile.kali              # Multi-stage Kali sandbox (11 Go tools)
│   ├── Dockerfile.sandbox           # Legacy Debian sandbox
│   ├── Dockerfile.backend           # Backend container
│   ├── Dockerfile.frontend          # Frontend container
│   ├── docker-compose.kali.yml      # Kali sandbox build
│   └── docker-compose.sandbox.yml   # Legacy sandbox
│
├── config/config.json               # Profiles, tools, sandbox, MCP
├── data/
│   ├── vuln_knowledge_base.json     # 100 vuln type definitions
│   ├── execution_history.json       # Cross-scan learning data
│   └── access_control_learning.json # BOLA/BFLA adaptive data
│
├── scripts/
│   └── build-kali.sh               # Build/rebuild Kali image
├── tools/
│   └── benchmark_runner.py          # 104 CTF challenges
├── agents/base_agent.py             # BaseAgent class
├── neurosploit.py                   # CLI entry point
└── requirements.txt
```

---

## Autonomous Agent

The AI agent (`autonomous_agent.py`) orchestrates the entire penetration test autonomously.

### 3-Stream Parallel Architecture

```
                    ┌─────────────────────┐
                    │   Auto Pentest      │
                    │   Target URL(s)     │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
   │  Stream 1    │ │  Stream 2    │ │  Stream 3    │
   │  Recon       │ │  Junior Test │ │  Tool Runner │
   │  ─────────── │ │  ─────────── │ │  ─────────── │
   │  Crawl pages │ │  Test target │ │  Nuclei scan │
   │  Find params │ │  AI-priority │ │  Naabu ports │
   │  Tech detect │ │  3 payloads  │ │  AI decides  │
   │  WAF detect  │ │  per endpoint│ │  extra tools │
   └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
          │                │                │
          └────────────────┼────────────────┘
                           ▼
              ┌─────────────────────┐
              │  Deep Analysis      │
              │  100 vuln types     │
              │  Full payload sets  │
              │  Chain exploitation │
              └─────────┬───────────┘
                        ▼
              ┌─────────────────────┐
              │  Report Generation  │
              │  AI executive brief │
              │  PoC code per find  │
              └─────────────────────┘
```

### Agent Autonomy Modules

| Module | Description |
|--------|-------------|
| **Request Engine** | Retry with backoff, per-host rate limiting, circuit breaker, adaptive timeouts |
| **WAF Detector** | 16 WAF signatures (Cloudflare, AWS, Akamai, Imperva, etc.), 12 bypass techniques |
| **Strategy Adapter** | Dead endpoint detection, diminishing returns, 403 bypass, priority recomputation |
| **Chain Engine** | 10 chain rules (SSRF->internal, SQLi->DB-specific, LFI->config, IDOR pattern transfer) |
| **Auth Manager** | Multi-user contexts (user_a, user_b, admin), login form detection, session management |

### Scan Features

- **Pause / Resume / Stop** with checkpoints
- **Manual Validation** - Confirm or reject AI findings
- **Screenshot Capture** on confirmed findings (Playwright)
- **Cross-Scan Learning** - Historical success rates influence future priorities
- **CVE Testing** - Regex detection + AI-generated payloads

---

## 100 Vulnerability Types

### Categories

| Category | Types | Examples |
|----------|-------|---------|
| **Injection** | 38 | XSS (reflected/stored/DOM), SQLi, NoSQLi, Command Injection, SSTI, LDAP, XPath, CRLF, Header Injection, Log Injection, GraphQL Injection |
| **Inspection** | 21 | Security Headers, CORS, Clickjacking, Info Disclosure, Debug Endpoints, Error Disclosure, Source Code Exposure |
| **AI-Driven** | 41 | BOLA, BFLA, IDOR, Race Condition, Business Logic, JWT Manipulation, OAuth Flaws, Prototype Pollution, WebSocket Hijacking, Cache Poisoning, HTTP Request Smuggling |
| **Authentication** | 8 | Auth Bypass, Session Fixation, Credential Stuffing, Password Reset Flaws, MFA Bypass, Default Credentials |
| **Authorization** | 6 | BOLA, BFLA, IDOR, Privilege Escalation, Forced Browsing, Function-Level Access Control |
| **File Access** | 5 | LFI, RFI, Path Traversal, File Upload, XXE |
| **Request Forgery** | 4 | SSRF, CSRF, Cloud Metadata, DNS Rebinding |
| **Client-Side** | 8 | CORS, Clickjacking, Open Redirect, DOM Clobbering, Prototype Pollution, PostMessage, CSS Injection |
| **Infrastructure** | 6 | SSL/TLS, HTTP Methods, Subdomain Takeover, Host Header, CNAME Hijacking |
| **Cloud/Supply** | 4 | Cloud Metadata, S3 Bucket Misconfiguration, Dependency Confusion, Third-Party Script |

### Payload Engine

- **526 payloads** across 95 libraries
- **73 XSS stored payloads** + 5 context-specific sets
- Per-type AI decision prompts with anti-hallucination directives
- WAF-adaptive payload transformation (12 techniques)

---

## Kali Sandbox System

Each scan runs in its own **isolated Kali Linux Docker container**, providing:

- **Complete Isolation** - No interference between concurrent scans
- **On-Demand Tools** - 56 tools installed only when needed
- **Auto Cleanup** - Containers destroyed when scan completes
- **Resource Limits** - Per-container memory (2GB) and CPU (2 cores) limits

### Pre-Installed Tools (28)

| Category | Tools |
|----------|-------|
| **Scanners** | nuclei, naabu, httpx, nmap, nikto, masscan, whatweb |
| **Discovery** | subfinder, katana, dnsx, uncover, ffuf, gobuster, waybackurls |
| **Exploitation** | dalfox, sqlmap |
| **System** | curl, wget, git, python3, pip3, go, jq, dig, whois, openssl, netcat, bash |

### On-Demand Tools (28 more)

Installed automatically inside the container when first requested:

- **APT**: wpscan, dirb, hydra, john, hashcat, testssl, sslscan, enum4linux, dnsrecon, amass, medusa, crackmapexec, etc.
- **Go**: gau, gitleaks, anew, httprobe
- **Pip**: dirsearch, wfuzz, arjun, wafw00f, sslyze, commix, trufflehog, retire

### Container Pool

```
ContainerPool (global coordinator, max 5 concurrent)
  ├── KaliSandbox(scan_id="abc") → docker: neurosploit-abc
  ├── KaliSandbox(scan_id="def") → docker: neurosploit-def
  └── KaliSandbox(scan_id="ghi") → docker: neurosploit-ghi
```

- **TTL enforcement** - Containers auto-destroyed after 60 min
- **Orphan cleanup** - Stale containers removed on server startup
- **Graceful fallback** - Falls back to shared container if Docker unavailable

---

## Anti-Hallucination & Validation

NeuroSploit uses a multi-layered validation pipeline to eliminate false positives:

### Validation Pipeline

```
Finding Candidate
    │
    ▼
┌─────────────────────┐
│ Negative Controls    │  Send benign/empty requests as controls
│ Same behavior = FP   │  -60 confidence if same response
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Proof of Execution   │  25+ per-vuln-type proof methods
│ XSS: context check   │  SSRF: metadata markers
│ SQLi: DB errors       │  BOLA: data comparison
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ AI Interpretation    │  LLM with anti-hallucination prompts
│ Per-type system msgs │  12 composable prompt templates
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Confidence Scorer    │  0-100 numeric score
│ ≥90 = confirmed      │  +proof, +impact, +controls
│ ≥60 = likely          │  -baseline_only, -same_behavior
│ <60 = rejected        │  Breakdown visible in UI
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Validation Judge     │  Final verdict authority
│ approve / reject     │  Records for adaptive learning
└─────────────────────┘
```

### Anti-Hallucination System Prompts

12 composable prompts applied across 7 task contexts:
- `anti_hallucination` - Core truthfulness directives
- `proof_of_execution` - Require concrete evidence
- `negative_controls` - Compare with benign requests
- `anti_severity_inflation` - Accurate severity ratings
- `access_control_intelligence` - BOLA/BFLA data comparison methodology

### Access Control Adaptive Learning

- Records TP/FP outcomes per domain for BOLA/BFLA/IDOR
- 9 default response patterns, 6 known FP patterns (WSO2, Keycloak, etc.)
- Historical FP rate influences future confidence scoring

---

## Web GUI

### Pages

| Page | Route | Description |
|------|-------|-------------|
| **Dashboard** | `/` | Stats overview, severity distribution, recent activity feed |
| **Auto Pentest** | `/auto` | One-click autonomous pentest with 3-stream live display |
| **Vuln Lab** | `/vuln-lab` | Per-type vulnerability testing (100 types, 11 categories) |
| **Terminal Agent** | `/terminal` | AI-powered interactive security chat + tool execution |
| **Sandboxes** | `/sandboxes` | Real-time Docker container monitoring + management |
| **AI Agent** | `/scan/new` | Manual scan creation with prompt selection |
| **Scan Details** | `/scan/:id` | Findings with confidence badges, pause/resume/stop |
| **Scheduler** | `/scheduler` | Cron/interval automated scan scheduling |
| **Reports** | `/reports` | HTML/PDF/JSON report generation and viewing |
| **Settings** | `/settings` | LLM providers, model routing, feature toggles |

### Sandbox Dashboard

Real-time monitoring of per-scan Kali containers:
- **Pool stats** - Active/max containers, Docker status, TTL
- **Capacity bar** - Visual utilization indicator
- **Per-container cards** - Name, scan link, uptime, installed tools, status
- **Actions** - Health check, destroy (with confirmation), cleanup expired/orphans
- **5-second auto-polling** for real-time updates

---

## API Reference

### Base URL

```
http://localhost:8000/api/v1
```

### Endpoints

#### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scans` | Create new scan |
| `GET` | `/scans` | List all scans |
| `GET` | `/scans/{id}` | Get scan details |
| `POST` | `/scans/{id}/start` | Start scan |
| `POST` | `/scans/{id}/stop` | Stop scan |
| `POST` | `/scans/{id}/pause` | Pause scan |
| `POST` | `/scans/{id}/resume` | Resume scan |
| `DELETE` | `/scans/{id}` | Delete scan |

#### AI Agent

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/agent/run` | Launch autonomous agent |
| `GET` | `/agent/status/{id}` | Get agent status + findings |
| `GET` | `/agent/by-scan/{scan_id}` | Get agent by scan ID |
| `POST` | `/agent/stop/{id}` | Stop agent |
| `POST` | `/agent/pause/{id}` | Pause agent |
| `POST` | `/agent/resume/{id}` | Resume agent |
| `GET` | `/agent/findings/{id}` | Get findings with details |
| `GET` | `/agent/logs/{id}` | Get agent logs |

#### Sandbox

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/sandbox` | List containers + pool status |
| `GET` | `/sandbox/{scan_id}` | Health check container |
| `DELETE` | `/sandbox/{scan_id}` | Destroy container |
| `POST` | `/sandbox/cleanup` | Remove expired containers |
| `POST` | `/sandbox/cleanup-orphans` | Remove orphan containers |

#### Scheduler

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/scheduler` | List scheduled jobs |
| `POST` | `/scheduler` | Create scheduled job |
| `DELETE` | `/scheduler/{id}` | Delete job |
| `POST` | `/scheduler/{id}/pause` | Pause job |
| `POST` | `/scheduler/{id}/resume` | Resume job |

#### Vulnerability Lab

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/vuln-lab/types` | List 100 vuln types by category |
| `POST` | `/vuln-lab/run` | Run per-type vulnerability test |
| `GET` | `/vuln-lab/challenges` | List challenge runs |
| `GET` | `/vuln-lab/stats` | Detection rate stats |

#### Reports & Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/reports` | Generate report |
| `POST` | `/reports/ai-generate` | AI-powered report |
| `GET` | `/reports/{id}/view` | View HTML report |
| `GET` | `/dashboard/stats` | Dashboard statistics |
| `GET` | `/dashboard/activity-feed` | Recent activity |

### WebSocket

```
ws://localhost:8000/ws/scan/{scan_id}
```

Events: `scan_started`, `progress_update`, `finding_discovered`, `scan_completed`, `scan_error`

### API Docs

Interactive docs available at:
- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`

---

## Configuration

### Environment Variables

```bash
# LLM API Keys (at least one required)
ANTHROPIC_API_KEY=your-key
OPENAI_API_KEY=your-key
GEMINI_API_KEY=your-key

# Local LLM (optional)
OLLAMA_BASE_URL=http://localhost:11434
LMSTUDIO_BASE_URL=http://localhost:1234
OPENROUTER_API_KEY=your-key

# Database
DATABASE_URL=sqlite+aiosqlite:///./data/neurosploit.db

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false
```

### config/config.json

```json
{
  "llm": {
    "default_profile": "gemini_pro_default",
    "profiles": { ... }
  },
  "agent_roles": {
    "pentest_generalist": { "vuln_coverage": 100 },
    "bug_bounty_hunter": { "vuln_coverage": 100 }
  },
  "sandbox": {
    "mode": "per_scan",
    "kali": {
      "enabled": true,
      "image": "neurosploit-kali:latest",
      "max_concurrent": 5,
      "container_ttl_minutes": 60
    }
  },
  "mcp_servers": {
    "neurosploit_tools": {
      "transport": "stdio",
      "command": "python3",
      "args": ["-m", "core.mcp_server"]
    }
  }
}
```

---

## Development

### Backend

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# API docs: http://localhost:8000/api/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev        # Dev server at http://localhost:5173
npm run build      # Production build
```

### Build Kali Sandbox

```bash
./scripts/build-kali.sh --test    # Build + health check
```

### MCP Server

```bash
python3 -m core.mcp_server        # Starts stdio MCP server (12 tools)
```

---

## Security Notice

**This tool is for authorized security testing only.**

- Only test systems you own or have explicit written permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations
- Unauthorized access to computer systems is illegal

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | Python, FastAPI, SQLAlchemy, Pydantic, aiohttp |
| **Frontend** | React 18, TypeScript, TailwindCSS, Vite |
| **AI/LLM** | Anthropic Claude, OpenAI GPT, Google Gemini, Ollama, LMStudio, OpenRouter |
| **Sandbox** | Docker, Kali Linux, ProjectDiscovery suite, Nmap, SQLMap, Nikto |
| **Tools** | Nuclei, Naabu, httpx, Subfinder, Katana, FFuf, Gobuster, Dalfox |
| **Infra** | Docker Compose, MCP Protocol, Playwright, APScheduler |

---

**NeuroSploit v3** - *AI-Powered Autonomous Penetration Testing Platform*
