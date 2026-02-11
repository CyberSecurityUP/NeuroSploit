# NeuroSploit v3 - Quick Start Guide

Get NeuroSploit running in under 5 minutes.

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Python** | 3.10+ | 3.12 |
| **Node.js** | 18+ | 20 LTS |
| **Docker** | 24+ | Latest (for Kali sandbox) |
| **RAM** | 4 GB | 8 GB+ |
| **Disk** | 2 GB | 5 GB (with Kali image) |
| **LLM API Key** | 1 provider | Claude recommended |

---

## Step 1: Clone & Configure

```bash
git clone https://github.com/your-org/NeuroSploitv2.git
cd NeuroSploitv2

# Create your environment file
cp .env.example .env
```

Edit `.env` and add at least one API key:

```bash
# Pick one (or more):
ANTHROPIC_API_KEY=sk-ant-...        # Claude (recommended)
OPENAI_API_KEY=sk-...               # GPT-4
GEMINI_API_KEY=AI...                 # Gemini Pro
OPENROUTER_API_KEY=sk-or-...        # OpenRouter (any model)
```

> **No API key?** Use a local LLM (Ollama or LM Studio) -- see [Local LLM Setup](#local-llm-setup) below.

---

## Step 2: Install Dependencies

### Backend

```bash
pip install -r backend/requirements.txt
```

### Frontend

```bash
cd frontend
npm install
cd ..
```

---

## Step 3: Build Kali Sandbox Image (Optional but Recommended)

The Kali sandbox enables isolated tool execution (Nuclei, Nmap, SQLMap, etc.) in Docker containers.

```bash
# Requires Docker Desktop running
./scripts/build-kali.sh --test
```

This builds a Kali Linux image with 28 pre-installed security tools. Takes ~5 min on first build.

> **No Docker?** NeuroSploit works without it -- the agent uses HTTP-only testing. Docker adds tool-based scanning (Nuclei, Nmap, etc.).

---

## Step 4: Start NeuroSploit

### Option A: Development Mode (hot reload)

Terminal 1 -- Backend:
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Terminal 2 -- Frontend:
```bash
cd frontend
npm run dev
```

Open: **http://localhost:5173**

### Option B: Production Mode

```bash
# Build frontend
cd frontend && npm run build && cd ..

# Start backend (serves frontend too)
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Open: **http://localhost:8000**

### Option C: Quick Start Script

```bash
./start.sh
```

---

## Step 5: Verify Setup

### Check API Health

```bash
curl http://localhost:8000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "app": "NeuroSploit",
  "version": "3.0.0",
  "llm": {
    "status": "configured",
    "provider": "claude",
    "message": "AI agent ready"
  }
}
```

### Check Swagger Docs

Open **http://localhost:8000/api/docs** for interactive API documentation.

---

## Your First Scan

### Option 1: Auto Pentest (Recommended)

1. Open the web interface
2. Click **Auto Pentest** in the sidebar
3. Enter a target URL (e.g., `http://testphp.vulnweb.com`)
4. Click **Start Auto Pentest**
5. Watch the 3-stream parallel scan in real-time

### Option 2: Via API

```bash
curl -X POST http://localhost:8000/api/v1/agent/run \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://testphp.vulnweb.com",
    "mode": "auto_pentest"
  }'
```

### Option 3: Vuln Lab (Single Type)

1. Click **Vuln Lab** in the sidebar
2. Pick a vulnerability type (e.g., `xss_reflected`)
3. Enter target URL
4. Click **Run Test**

---

## Pages Overview

| Page | What it does |
|------|-------------|
| **Dashboard** (`/`) | Stats, severity charts, recent activity |
| **Auto Pentest** (`/auto`) | One-click full autonomous pentest |
| **Vuln Lab** (`/vuln-lab`) | Test specific vuln types (100 available) |
| **Terminal Agent** (`/terminal`) | AI chat + command execution |
| **Sandboxes** (`/sandboxes`) | Monitor Kali containers in real-time |
| **Scheduler** (`/scheduler`) | Schedule recurring scans |
| **Reports** (`/reports`) | View/download generated reports |
| **Settings** (`/settings`) | Configure LLM providers, features |

---

## Local LLM Setup

### Ollama (Easiest)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3.1

# Add to .env
echo "OLLAMA_BASE_URL=http://localhost:11434" >> .env
```

### LM Studio

1. Download from [lmstudio.ai](https://lmstudio.ai)
2. Load any model (e.g., Mistral, Llama)
3. Start the server on port 1234
4. Add to `.env`:
   ```
   LMSTUDIO_BASE_URL=http://localhost:1234
   ```

---

## Kali Sandbox Commands

```bash
# Build image
./scripts/build-kali.sh

# Rebuild from scratch
./scripts/build-kali.sh --fresh

# Build + verify tools work
./scripts/build-kali.sh --test

# Check running containers (via API)
curl http://localhost:8000/api/v1/sandbox/

# Monitor via web UI
# Open http://localhost:8000/sandboxes
```

### Pre-installed tools (28)

nuclei, naabu, httpx, subfinder, katana, dnsx, uncover, ffuf, gobuster, dalfox, waybackurls, nmap, nikto, sqlmap, masscan, whatweb, curl, wget, git, python3, pip3, go, jq, dig, whois, openssl, netcat, bash

### On-demand tools (28 more)

Installed inside the container automatically when first needed:

wpscan, dirb, hydra, john, hashcat, testssl, sslscan, enum4linux, dnsrecon, amass, medusa, crackmapexec, gau, gitleaks, anew, httprobe, dirsearch, wfuzz, arjun, wafw00f, sslyze, commix, trufflehog, retire, fierce, nbtscan, responder

---

## Troubleshooting

### "AI agent not configured"

Check your `.env` has at least one valid API key:
```bash
curl http://localhost:8000/api/health | python3 -m json.tool
```

### "Kali sandbox image not found"

Build the Docker image:
```bash
./scripts/build-kali.sh
```

### "Docker daemon not running"

Start Docker Desktop, then retry.

### "Port 8000 already in use"

```bash
lsof -i :8000
kill <PID>
```

### Frontend not loading

Dev mode: ensure frontend is running (`npm run dev` in `/frontend`).
Production: ensure `frontend/dist/` exists (`cd frontend && npm run build`).

---

## What's Next

- Read the full [README.md](README.md) for architecture details
- Explore the **100 vulnerability types** in Vuln Lab
- Set up **scheduled scans** for continuous monitoring
- Try the **Terminal Agent** for interactive AI-guided testing
- Check the **Sandbox Dashboard** to monitor container health

---

**NeuroSploit v3** - *AI-Powered Autonomous Penetration Testing Platform*
