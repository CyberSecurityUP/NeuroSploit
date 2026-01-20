# NeuroSploit v3

![NeuroSploit](https://img.shields.io/badge/NeuroSploit-AI--Powered%20Pentesting-blueviolet)
![Version](https://img.shields.io/badge/Version-3.0.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)
![React](https://img.shields.io/badge/React-18-61dafb)

**AI-Powered Penetration Testing Platform with Web GUI**

NeuroSploit v3 is an advanced security assessment platform that combines AI-driven vulnerability testing with a modern web interface. It uses prompt-driven testing to dynamically determine what vulnerabilities to test based on natural language instructions.

---

## What's New in v3

- **Web GUI** - Modern React interface for scan management, real-time monitoring, and reports
- **Dynamic Vulnerability Engine** - Tests 50+ vulnerability types based on prompt analysis
- **Prompt-Driven Testing** - AI extracts vulnerability types from natural language prompts
- **Real-time Dashboard** - WebSocket-powered live updates during scans
- **Multiple Input Modes** - Single URL, comma-separated URLs, or file upload
- **Preset Prompts** - Ready-to-use security testing profiles
- **Export Reports** - HTML, PDF, and JSON export formats
- **Docker Deployment** - One-command deployment with Docker Compose

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Architecture](#architecture)
- [Web GUI](#web-gui)
- [API Reference](#api-reference)
- [Vulnerability Engine](#vulnerability-engine)
- [Configuration](#configuration)
- [Development](#development)
- [Security Notice](#security-notice)

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/CyberSecurityUP/NeuroSploit.git
cd NeuroSploit

# Copy environment file and add your API keys
cp .env.example .env
nano .env  # Add ANTHROPIC_API_KEY or OPENAI_API_KEY

# Start with Docker Compose
./start.sh
# or
docker-compose up -d
```

Access the web interface at **http://localhost:3000**

### Option 2: Manual Setup

```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

---

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Dynamic Testing** | 50+ vulnerability types across 10 categories |
| **Prompt-Driven** | AI extracts test types from natural language |
| **Web Interface** | Modern React dashboard with real-time updates |
| **Multiple Inputs** | Single URL, bulk URLs, or file upload |
| **Preset Prompts** | Bug Bounty, OWASP Top 10, API Security, and more |
| **Export Reports** | HTML, PDF, JSON with professional styling |
| **WebSocket Updates** | Real-time scan progress and findings |
| **Docker Ready** | One-command deployment |

### Vulnerability Categories

| Category | Vulnerability Types |
|----------|---------------------|
| **Injection** | XSS (Reflected/Stored/DOM), SQLi, NoSQLi, Command Injection, SSTI, LDAP, XPath |
| **File Access** | LFI, RFI, Path Traversal, File Upload, XXE |
| **Request Forgery** | SSRF, CSRF, Cloud Metadata Access |
| **Authentication** | Auth Bypass, JWT Manipulation, Session Fixation, OAuth Flaws |
| **Authorization** | IDOR, BOLA, BFLA, Privilege Escalation |
| **API Security** | Rate Limiting, Mass Assignment, GraphQL Injection |
| **Logic Flaws** | Race Conditions, Business Logic, Workflow Bypass |
| **Client-Side** | CORS Misconfiguration, Clickjacking, Open Redirect, WebSocket |
| **Info Disclosure** | Error Disclosure, Source Code Exposure, Debug Endpoints |
| **Infrastructure** | Security Headers, SSL/TLS Issues, HTTP Methods |

---

## Architecture

```
NeuroSploitv3/
├── backend/                    # FastAPI Backend
│   ├── api/v1/                 # REST API endpoints
│   │   ├── scans.py            # Scan CRUD operations
│   │   ├── targets.py          # Target validation
│   │   ├── prompts.py          # Preset prompts
│   │   ├── reports.py          # Report generation
│   │   ├── dashboard.py        # Dashboard stats
│   │   └── vulnerabilities.py  # Vulnerability management
│   ├── core/
│   │   ├── vuln_engine/        # Dynamic vulnerability testing
│   │   │   ├── engine.py       # Main testing engine
│   │   │   ├── registry.py     # Vulnerability registry
│   │   │   ├── payload_generator.py
│   │   │   └── testers/        # Category-specific testers
│   │   ├── prompt_engine/      # Prompt parsing
│   │   │   └── parser.py       # Extract vuln types from prompts
│   │   └── report_engine/      # Report generation
│   │       └── generator.py    # HTML/PDF/JSON export
│   ├── models/                 # SQLAlchemy ORM models
│   ├── schemas/                # Pydantic validation schemas
│   ├── services/               # Business logic
│   └── main.py                 # FastAPI app entry
│
├── frontend/                   # React Frontend
│   ├── src/
│   │   ├── pages/              # Page components
│   │   │   ├── HomePage.tsx    # Dashboard
│   │   │   ├── NewScanPage.tsx # Create scan
│   │   │   ├── ScanDetailsPage.tsx
│   │   │   ├── ReportsPage.tsx
│   │   │   └── ReportViewPage.tsx
│   │   ├── components/         # Reusable components
│   │   ├── services/           # API client
│   │   └── store/              # Zustand state
│   └── package.json
│
├── docker/                     # Docker configuration
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── nginx.conf
│
├── docker-compose.yml
├── start.sh
└── .env.example
```

---

## Web GUI

### Dashboard (Home Page)

- **Stats Overview** - Total scans, vulnerabilities by severity, success rate
- **Severity Distribution** - Visual chart of critical/high/medium/low findings
- **Recent Scans** - Quick access to latest scan results
- **Recent Findings** - Latest discovered vulnerabilities

### New Scan Page

**Target Input Modes:**
- **Single URL** - Enter one target URL
- **Multiple URLs** - Comma-separated list
- **File Upload** - Upload .txt file with URLs (one per line)

**Prompt Options:**
- **Preset Prompts** - Select from ready-to-use profiles:
  - Full Penetration Test
  - OWASP Top 10
  - API Security Assessment
  - Bug Bounty Hunter
  - Quick Security Scan
  - Authentication Testing
- **Custom Prompt** - Write your own testing instructions
- **No Prompt** - Run all available tests

### Scan Details Page

- **Progress Bar** - Real-time scan progress
- **Discovered Endpoints** - List of found paths and URLs
- **Vulnerabilities** - Real-time findings with severity badges
- **Activity Log** - Live scan events via WebSocket

### Reports Page

- **Report List** - All generated reports with metadata
- **View Report** - In-browser HTML viewer
- **Export Options** - Download as HTML, PDF, or JSON
- **Delete Reports** - Remove old reports

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
| `POST` | `/scans/{id}/start` | Start scan execution |
| `POST` | `/scans/{id}/stop` | Stop running scan |
| `DELETE` | `/scans/{id}` | Delete scan |
| `GET` | `/scans/{id}/endpoints` | Get discovered endpoints |
| `GET` | `/scans/{id}/vulnerabilities` | Get found vulnerabilities |

#### Targets

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/targets/validate` | Validate URL(s) |
| `POST` | `/targets/upload` | Upload URL file |

#### Prompts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/prompts/presets` | List preset prompts |
| `GET` | `/prompts/presets/{id}` | Get preset details |
| `POST` | `/prompts/parse` | Parse custom prompt |

#### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/reports` | List all reports |
| `GET` | `/reports/{id}` | Get report details |
| `GET` | `/reports/{id}/download` | Download report |
| `DELETE` | `/reports/{id}` | Delete report |

#### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/stats` | Get dashboard statistics |
| `GET` | `/dashboard/recent-scans` | Get recent scans |
| `GET` | `/dashboard/recent-findings` | Get recent vulnerabilities |

### WebSocket

```
ws://localhost:8000/ws/{scan_id}
```

**Events:**
- `scan_started` - Scan has begun
- `scan_progress` - Progress update (percentage)
- `endpoint_found` - New endpoint discovered
- `vulnerability_found` - New vulnerability found
- `scan_completed` - Scan finished
- `scan_error` - Error occurred

---

## Vulnerability Engine

### How It Works

1. **Prompt Parsing** - User prompt analyzed for vulnerability keywords
2. **Type Extraction** - Relevant vulnerability types identified
3. **Tester Selection** - Appropriate testers loaded from registry
4. **Payload Generation** - Context-aware payloads generated
5. **Testing Execution** - Tests run against target endpoints
6. **Finding Reporting** - Results sent via WebSocket in real-time

### Prompt Examples

```
"Test for SQL injection and XSS vulnerabilities"
→ Extracts: sql_injection, xss_reflected, xss_stored

"Check for OWASP Top 10 issues"
→ Extracts: All major vulnerability types

"Look for authentication bypass and IDOR"
→ Extracts: auth_bypass, idor, bola

"Find server-side request forgery and file inclusion"
→ Extracts: ssrf, lfi, rfi, path_traversal
```

### Adding Custom Testers

Create a new tester in `backend/core/vuln_engine/testers/`:

```python
from .base_tester import BaseTester, TestResult

class MyCustomTester(BaseTester):
    """Custom vulnerability tester"""

    async def test(self, url: str, endpoint: str, params: dict) -> list[TestResult]:
        results = []
        # Your testing logic here
        return results
```

Register in `backend/core/vuln_engine/registry.py`:

```python
VULNERABILITY_REGISTRY["my_custom_vuln"] = {
    "name": "My Custom Vulnerability",
    "category": "custom",
    "severity": "high",
    "tester": "MyCustomTester",
    # ...
}
```

---

## Configuration

### Environment Variables

```bash
# .env file

# LLM API Keys (at least one required for AI-powered testing)
ANTHROPIC_API_KEY=your-anthropic-api-key
OPENAI_API_KEY=your-openai-api-key

# Database (default is SQLite)
DATABASE_URL=sqlite+aiosqlite:///./data/neurosploit.db

# Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=false
```

### Preset Prompts

Available presets in `/api/v1/prompts/presets`:

| ID | Name | Description |
|----|------|-------------|
| `full_pentest` | Full Penetration Test | Comprehensive testing across all categories |
| `owasp_top10` | OWASP Top 10 | Focus on OWASP Top 10 vulnerabilities |
| `api_security` | API Security | API-specific security testing |
| `bug_bounty` | Bug Bounty Hunter | High-impact findings for bounty programs |
| `quick_scan` | Quick Security Scan | Fast essential security checks |
| `auth_testing` | Authentication Testing | Auth and session security |

---

## Development

### Backend Development

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run with hot reload
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# API docs available at http://localhost:8000/docs
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev

# Build for production
npm run build
```

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

---

## Upgrading from v2

v3 is a complete rewrite with a new architecture. Key differences:

| Feature | v2 | v3 |
|---------|----|----|
| Interface | CLI only | Web GUI + API |
| Vulnerability Testing | Hardcoded (XSS, SQLi, LFI) | Dynamic 50+ types |
| Test Selection | Manual | Prompt-driven |
| Progress Updates | Terminal output | WebSocket real-time |
| Reports | HTML file | Web viewer + export |
| Deployment | Python script | Docker Compose |

**Migration:** v3 is a separate installation. Your v2 configurations and results are not compatible.

---

## Security Notice

**This tool is for authorized security testing only.**

- Only test systems you own or have written permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations
- Unauthorized access to computer systems is illegal

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## Acknowledgements

### Technologies
- FastAPI, SQLAlchemy, Pydantic
- React, TypeScript, TailwindCSS, Zustand
- Docker, Nginx

### LLM Providers
- Anthropic Claude
- OpenAI GPT

---

**NeuroSploit v3** - *AI-Powered Penetration Testing Platform*
