# NeuroSploit v2

![NeuroSploitv2](https://img.shields.io/badge/NeuroSploitv2-AI--Powered%20Pentesting-blueviolet)
![Version](https://img.shields.io/badge/Version-2.0.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.8+-yellow)

**AI-Powered Penetration Testing Framework with Adaptive Intelligence**

NeuroSploit v2 is an advanced security assessment framework that combines reconnaissance tools with adaptive AI analysis. It intelligently collects data, analyzes attack surfaces, and performs targeted security testing using LLM-powered decision making.

---

## What's New in v2

- **Adaptive AI Mode** - AI automatically determines if context is sufficient; runs tools only when needed
- **3 Execution Modes** - CLI, Interactive, and guided Experience/Wizard mode
- **Consolidated Recon** - All reconnaissance outputs merged into a single context file
- **Context-Based Analysis** - Analyze pre-collected recon data without re-running tools
- **Professional Reports** - Auto-generated HTML reports with charts and findings

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [3 Execution Modes](#3-execution-modes)
- [Workflow](#workflow)
- [Adaptive AI Mode](#adaptive-ai-mode)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Agent Roles](#agent-roles)
- [Built-in Tools](#built-in-tools)
- [Output Files](#output-files)
- [Examples](#examples)
- [Architecture](#architecture)
- [Security Notice](#security-notice)

---

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Adaptive AI** | Automatically runs tools when context is insufficient |
| **Multi-Mode** | CLI, Interactive, and Wizard execution modes |
| **Consolidated Recon** | All tool outputs merged into single context file |
| **Multi-LLM Support** | Claude, OpenAI, Gemini, Ollama, LM Studio |
| **Professional Reports** | HTML reports with charts and findings |
| **Extensible** | Custom agents, tools, and prompts |

### Security Testing

| Category | Tests |
|----------|-------|
| **Injection** | SQL Injection, XSS, Command Injection, Template Injection |
| **File Attacks** | LFI, Path Traversal, File Upload, XXE |
| **Server-Side** | SSRF, RCE, Deserialization |
| **Authentication** | Auth Bypass, IDOR, Session Issues, JWT |
| **Reconnaissance** | Subdomain Enum, Port Scan, Tech Detection, URL Collection |

### Reconnaissance Tools

| Tool | Purpose |
|------|---------|
| subfinder, amass, assetfinder | Subdomain enumeration |
| httpx, httprobe | HTTP probing |
| gau, waybackurls, waymore | URL collection |
| katana, gospider | Web crawling |
| naabu, nmap | Port scanning |
| nuclei | Vulnerability scanning |

---

## Installation

### Prerequisites

```bash
# Python 3.8+
python3 --version

# Install dependencies
pip3 install -r requirements.txt
```

### Setup

```bash
# Clone repository
git clone https://github.com/your-org/NeuroSploitv2.git
cd NeuroSploitv2

# Create config from example
cp config/config-example.json config/config.json

# Edit with your LLM API keys
nano config/config.json

# Create required directories
mkdir -p results reports logs

# Install security tools (recommended)
python3 neurosploit.py --install-tools
```

### Environment Variables

```bash
# Set in .bashrc, .zshrc, or .env
export ANTHROPIC_API_KEY="your_key"
export OPENAI_API_KEY="your_key"
export GEMINI_API_KEY="your_key"
```

---

## Quick Start

### Option 1: Wizard Mode (Recommended for beginners)

```bash
python3 neurosploit.py -e
```

Follow the guided prompts to configure your scan.

### Option 2: Two-Step Workflow

```bash
# Step 1: Run reconnaissance
python3 neurosploit.py --recon example.com

# Step 2: AI analysis
python3 neurosploit.py --input "Find XSS and SQLi vulnerabilities" \
  -cf results/context_*.json \
  --llm-profile claude_opus_default
```

### Option 3: Interactive Mode

```bash
python3 neurosploit.py -i
```

---

## 3 Execution Modes

### 1. CLI Mode

Direct command-line execution with all parameters:

```bash
# Reconnaissance
python3 neurosploit.py --recon example.com

# AI Analysis with context
python3 neurosploit.py --input "Analyze for XSS and SQLi" \
  -cf results/context_X.json \
  --llm-profile claude_opus_default

# Full pentest scan
python3 neurosploit.py --scan https://example.com

# Quick scan
python3 neurosploit.py --quick-scan https://example.com
```

### 2. Interactive Mode (`-i`)

REPL interface with tab completion:

```bash
python3 neurosploit.py -i
```

```
        ╔═══════════════════════════════════════════════════════════╗
        ║         NeuroSploitv2 - AI Offensive Security             ║
        ║                  Interactive Mode                         ║
        ╚═══════════════════════════════════════════════════════════╝

NeuroSploit> help
NeuroSploit> recon example.com
NeuroSploit> analyze results/context_X.json
NeuroSploit> scan https://example.com
NeuroSploit> experience
NeuroSploit> exit
```

**Available Commands:**

| Command | Description |
|---------|-------------|
| `recon <target>` | Run full reconnaissance |
| `analyze <file.json>` | LLM analysis of context file |
| `scan <target>` | Full pentest with tools |
| `quick_scan <target>` | Fast essential checks |
| `experience` / `wizard` | Start guided setup |
| `set_agent <name>` | Set default agent role |
| `set_profile <name>` | Set LLM profile |
| `list_roles` | Show available agents |
| `list_profiles` | Show LLM profiles |
| `check_tools` | Check installed tools |
| `install_tools` | Install required tools |
| `discover_ollama` | Find local Ollama models |

### 3. Experience/Wizard Mode (`-e`)

Guided step-by-step configuration:

```bash
python3 neurosploit.py -e
```

```
        ╔═══════════════════════════════════════════════════════════╗
        ║       NEUROSPLOIT - EXPERIENCE MODE (WIZARD)              ║
        ║           Step-by-step Configuration                      ║
        ╚═══════════════════════════════════════════════════════════╝

[STEP 1/6] Choose Operation Mode
--------------------------------------------------
  1. AI Analysis   - Analyze recon context with LLM (no tools)
  2. Full Scan     - Run real pentest tools + AI analysis
  3. Quick Scan    - Fast essential checks + AI analysis
  4. Recon Only    - Run reconnaissance tools, save context

[STEP 2/6] Set Target
[STEP 3/6] Context File
[STEP 4/6] LLM Profile
[STEP 5/6] Agent Role
[STEP 6/6] Custom Prompt

============================================================
  CONFIGURATION SUMMARY
============================================================
  Mode:         analysis
  Target:       example.com
  Context File: results/context_20240115.json
  LLM Profile:  claude_opus_default
  Agent Role:   bug_bounty_hunter
  Prompt:       Find XSS and SQLi vulnerabilities...
============================================================

  Execute with this configuration? [Y/n]:
```

---

## Workflow

### Recommended Workflow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   STEP 1        │     │   STEP 2        │     │   STEP 3        │
│   RECON         │────▶│   AI ANALYSIS   │────▶│   REPORT        │
│                 │     │                 │     │                 │
│ - Subdomains    │     │ - Adaptive AI   │     │ - HTML Report   │
│ - URLs          │     │ - Auto-test     │     │ - JSON Results  │
│ - Ports         │     │ - if needed     │     │ - Findings      │
│ - Technologies  │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Step 1: Reconnaissance

```bash
python3 neurosploit.py --recon example.com
```

Runs all discovery tools and consolidates output:

- **Subdomain Enumeration**: subfinder, amass, assetfinder
- **HTTP Probing**: httpx, httprobe
- **URL Collection**: gau, waybackurls, waymore
- **Web Crawling**: katana, gospider
- **Port Scanning**: naabu, nmap
- **Vulnerability Scanning**: nuclei

**Output:** `results/context_YYYYMMDD_HHMMSS.json`

### Step 2: AI Analysis

```bash
python3 neurosploit.py --input "Test for SQL injection and XSS" \
  -cf results/context_X.json \
  --llm-profile claude_opus_default
```

The Adaptive AI:
1. Analyzes your request
2. Checks if context has sufficient data
3. Runs additional tests if needed
4. Provides comprehensive analysis

---

## Adaptive AI Mode

The AI automatically determines if context data is sufficient:

```
======================================================================
  NEUROSPLOIT ADAPTIVE AI - BUG_BOUNTY_HUNTER
======================================================================
  Mode: Adaptive (LLM + Tools when needed)
  Target: testphp.vulnweb.com
  Context loaded with:
    - Subdomains: 1
    - URLs: 12085
    - URLs with params: 10989
======================================================================

[PHASE 1] Analyzing Context Sufficiency
--------------------------------------------------
  [*] User wants: xss, sqli
  [*] Data sufficient: No
  [*] Missing: XSS test results, SQL injection evidence

[PHASE 2] Collecting Missing Data
--------------------------------------------------
  [!] Context insufficient for: XSS test results
  [*] Running tools to collect data...

  [XSS] Running XSS tests...
  [>] curl: -s -k "http://target.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
  [!] FOUND: XSS

  [SQLi] Running SQL Injection tests...
  [>] curl: -s -k "http://target.com/product?id=1'"
  [!] FOUND: SQL Injection

  [+] Ran 15 tool commands to fill context gaps

[PHASE 3] AI Analysis
--------------------------------------------------
  [*] Generating final analysis with collected evidence...
  [+] Analysis complete
```

### How It Works

| Scenario | AI Action |
|----------|-----------|
| Context has XSS evidence | LLM-only analysis (no tools) |
| Context missing XSS evidence | Run XSS tests, then analyze |
| User asks for port scan | Check context, run nmap if missing |
| General analysis request | Use available context data |

### Supported Auto-Tests

When context is insufficient, AI can automatically run:

| Test | Trigger Keywords |
|------|------------------|
| XSS | xss, cross-site, reflected, stored |
| SQLi | sqli, sql, injection, database |
| LFI | lfi, file, inclusion, traversal |
| SSRF | ssrf, server-side, request |
| RCE | rce, command, execution, shell |
| Crawl | crawl, discover, spider, urls |
| Port Scan | port, scan, nmap, service |

---

## Configuration

### config/config.json

```json
{
  "llm": {
    "default_profile": "claude_opus_default",
    "profiles": {
      "claude_opus_default": {
        "provider": "claude",
        "model": "claude-sonnet-4-20250514",
        "api_key": "${ANTHROPIC_API_KEY}",
        "temperature": 0.7,
        "max_tokens": 8192,
        "guardrails_enabled": true,
        "hallucination_mitigation_strategy": "grounding"
      },
      "ollama_local": {
        "provider": "ollama",
        "model": "llama3:8b",
        "api_key": "",
        "temperature": 0.7
      },
      "gpt_4o": {
        "provider": "gpt",
        "model": "gpt-4o",
        "api_key": "${OPENAI_API_KEY}",
        "temperature": 0.7
      }
    }
  },
  "agent_roles": {
    "bug_bounty_hunter": {
      "enabled": true,
      "description": "Aggressive bug bounty hunting",
      "llm_profile": "claude_opus_default",
      "tools_allowed": ["subfinder", "nuclei", "sqlmap"]
    },
    "red_team_agent": {
      "enabled": true,
      "description": "Red team operations specialist"
    }
  },
  "tools": {
    "nmap": "/usr/bin/nmap",
    "sqlmap": "/usr/bin/sqlmap",
    "nuclei": "/usr/local/bin/nuclei"
  }
}
```

### LLM Providers

| Provider | Config Value | Notes |
|----------|--------------|-------|
| Claude (Anthropic) | `"provider": "claude"` | Best for security analysis |
| OpenAI | `"provider": "gpt"` | GPT-4, GPT-4o |
| Google | `"provider": "gemini"` | Gemini Pro |
| Ollama | `"provider": "ollama"` | Local models |
| LM Studio | `"provider": "lmstudio"` | Local with OpenAI API |

---

## CLI Reference

```
usage: neurosploit.py [-h] [--recon TARGET] [--context-file FILE]
                      [--target TARGET] [--scan TARGET] [--quick-scan TARGET]
                      [--install-tools] [--check-tools] [-r AGENT_ROLE] [-i]
                      [-e] [--input INPUT] [--llm-profile LLM_PROFILE]

NeuroSploitv2 - AI-Powered Penetration Testing Framework

Arguments:
  --recon TARGET        Run FULL RECON on target
  --context-file, -cf   Load recon context from JSON file
  --target, -t          Specify target URL/domain
  --scan TARGET         Run FULL pentest scan with tools
  --quick-scan TARGET   Run QUICK pentest scan
  --install-tools       Install required security tools
  --check-tools         Check status of installed tools
  -r, --agent-role      Agent role to execute (optional)
  -i, --interactive     Start interactive mode
  -e, --experience      Start wizard mode (guided setup)
  --input               Input prompt for the AI agent
  --llm-profile         LLM profile to use
  --list-agents         List available agent roles
  --list-profiles       List LLM profiles
  -v, --verbose         Enable verbose output
```

---

## Agent Roles

Predefined agents in `config.json` with prompts in `prompts/`:

| Agent | Description |
|-------|-------------|
| `bug_bounty_hunter` | Web app vulnerabilities, high-impact findings |
| `red_team_agent` | Simulated attack campaigns |
| `blue_team_agent` | Threat detection and response |
| `exploit_expert` | Exploitation strategies and payloads |
| `pentest_generalist` | Broad penetration testing |
| `owasp_expert` | OWASP Top 10 assessment |
| `malware_analyst` | Malware examination and IOCs |

### Custom Agents

1. Create prompt file: `prompts/my_agent.md`
2. Add to config:

```json
"agent_roles": {
  "my_agent": {
    "enabled": true,
    "description": "My custom agent",
    "llm_profile": "claude_opus_default"
  }
}
```

---

## Built-in Tools

### Reconnaissance

| Tool | File | Features |
|------|------|----------|
| OSINT Collector | `tools/recon/osint_collector.py` | IP resolution, tech detection, email patterns |
| Subdomain Finder | `tools/recon/subdomain_finder.py` | CT logs, DNS brute-force |
| DNS Enumerator | `tools/recon/dns_enumerator.py` | A, AAAA, MX, NS, TXT, CNAME |
| Full Recon Runner | `tools/recon/recon_tools.py` | Orchestrates all recon tools |

### Post-Exploitation

| Tool | File | Features |
|------|------|----------|
| SMB Lateral | `tools/lateral_movement/smb_lateral.py` | Share enum, pass-the-hash |
| SSH Lateral | `tools/lateral_movement/ssh_lateral.py` | SSH tunnels, key enum |
| Cron Persistence | `tools/persistence/cron_persistence.py` | Linux persistence |
| Registry Persistence | `tools/persistence/registry_persistence.py` | Windows persistence |

---

## Output Files

| File | Location | Description |
|------|----------|-------------|
| Context JSON | `results/context_*.json` | Consolidated recon data |
| Context TXT | `results/context_*.txt` | Human-readable context |
| Campaign JSON | `results/campaign_*.json` | Full execution results |
| HTML Report | `reports/report_*.html` | Professional report with charts |

### HTML Report Features

- Executive summary
- Severity statistics with charts
- Risk score calculation
- Vulnerability details with PoCs
- Remediation recommendations
- Modern dark theme UI

---

## Examples

### Basic Recon

```bash
# Domain recon
python3 neurosploit.py --recon example.com

# URL recon
python3 neurosploit.py --recon https://example.com
```

### AI Analysis

```bash
# Specific vulnerability analysis
python3 neurosploit.py --input "Find SQL injection and XSS vulnerabilities. Provide PoC with CVSS scores." \
  -cf results/context_20240115.json \
  --llm-profile claude_opus_default

# Comprehensive assessment
python3 neurosploit.py --input "Perform comprehensive security assessment. Analyze attack surface, test for OWASP Top 10, prioritize critical findings." \
  -cf results/context_X.json
```

### Pentest Scan

```bash
# Full scan with context
python3 neurosploit.py --scan https://example.com -cf results/context_X.json

# Quick scan
python3 neurosploit.py --quick-scan https://example.com -r bug_bounty_hunter
```

### Wizard Mode

```bash
python3 neurosploit.py -e
# Follow interactive prompts...
```

---

## Architecture

```
NeuroSploitv2/
├── neurosploit.py              # Main entry point
├── config/
│   ├── config.json             # Configuration
│   └── config-example.json     # Example config
├── agents/
│   └── base_agent.py           # Adaptive AI agent
├── core/
│   ├── llm_manager.py          # LLM provider abstraction
│   ├── context_builder.py      # Recon consolidation
│   ├── pentest_executor.py     # Tool execution
│   ├── report_generator.py     # Report generation
│   └── tool_installer.py       # Tool installation
├── tools/
│   ├── recon/
│   │   ├── recon_tools.py      # Advanced recon
│   │   ├── osint_collector.py  # OSINT gathering
│   │   ├── subdomain_finder.py # Subdomain enum
│   │   └── dns_enumerator.py   # DNS enumeration
│   ├── lateral_movement/
│   │   ├── smb_lateral.py      # SMB techniques
│   │   └── ssh_lateral.py      # SSH techniques
│   └── persistence/
│       ├── cron_persistence.py # Linux persistence
│       └── registry_persistence.py # Windows persistence
├── prompts/
│   ├── library.json            # Prompt library
│   └── *.md                    # Agent prompts
├── results/                    # Output directory
├── reports/                    # Generated reports
└── logs/                       # Log files
```

---

## Security Features

- **Secure Tool Execution**: `shlex` parsing, no shell injection
- **Input Validation**: Tool paths and arguments validated
- **Timeout Protection**: 60-second default timeout
- **Permission System**: Agent-based tool access control
- **Error Handling**: Comprehensive logging

---

## Troubleshooting

### LLM Connection Issues

```bash
# Check API key
echo $ANTHROPIC_API_KEY

# Test with local Ollama
python3 neurosploit.py -i
NeuroSploit> discover_ollama
```

### Missing Tools

```bash
# Check status
python3 neurosploit.py --check-tools

# Install
python3 neurosploit.py --install-tools
```

### Permission Issues

```bash
mkdir -p results reports logs
chmod 755 results reports logs
```

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

### LLM Providers
- Anthropic Claude
- OpenAI GPT
- Google Gemini
- Ollama
- LM Studio

### Security Tools
- Nmap, Nuclei, SQLMap
- Subfinder, Amass, httpx
- Katana, Gospider, gau

---

**NeuroSploit v2** - *Intelligent Adaptive Security Testing*
