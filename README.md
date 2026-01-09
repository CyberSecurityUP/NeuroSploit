# NeuroSploitv2 - AI-Powered Penetration Testing Framework

![NeuroSploitv2 Logo](https://img.shields.io/badge/NeuroSploitv2-AI--Powered%20Pentesting-blueviolet)
![Version](https://img.shields.io/badge/Version-2.0.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)

NeuroSploitv2 is an advanced, AI-powered penetration testing framework designed to automate and augment various aspects of offensive security operations. Leveraging the capabilities of large language models (LLMs), NeuroSploitv2 provides specialized agent roles that can analyze targets, identify vulnerabilities, plan exploitation strategies, and assist in defensive measures, all while prioritizing ethical considerations and operational security.

YouTube Demonstration Video: https://youtu.be/SQq1TVwlrxQ

## ✨ Features

*   **Modular Agent Roles:** Execute specialized AI agents tailored for specific security tasks (e.g., Red Team, Blue Team, Bug Bounty Hunter, Malware Analyst).
*   **Flexible LLM Integration:** Supports multiple LLM providers including Gemini, Claude, GPT (OpenAI), Ollama, and LM Studio, configurable via profiles.
*   **LM Studio Support:** Full integration with LM Studio for local model execution with OpenAI-compatible API.
*   **Granular LLM Profiles:** Define distinct LLM configurations for each agent role, controlling parameters like model, temperature, token limits, caching, and context.
*   **Markdown-based Prompts:** Agents utilize dynamic Markdown prompt templates, allowing for context-aware and highly specific instructions.
*   **Hallucination Mitigation:** Implements strategies like grounding, self-reflection, and consistency checks to reduce LLM hallucinations and ensure focused output.
*   **Guardrails:** Basic guardrails (e.g., keyword filtering, length checks) are in place to enhance safety and ethical adherence of LLM-generated content.
*   **Extensible Tooling:** Integrate and manage external security tools (Nmap, Metasploit, Subfinder, Nuclei, etc.) directly through configuration.
*   **Tool Chaining:** Execute multiple tools in sequence for complex reconnaissance and attack workflows.
*   **Built-in Reconnaissance Tools:**
    *   **OSINT Collector:** Gather intelligence from public sources (IP resolution, technology detection, email patterns, social media)
    *   **Subdomain Finder:** Discover subdomains using Certificate Transparency logs and DNS brute-forcing
    *   **DNS Enumerator:** Enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME)
*   **Lateral Movement Modules:** SMB and SSH-based lateral movement techniques
*   **Persistence Mechanisms:** Cron-based (Linux) and Registry-based (Windows) persistence modules
*   **Enhanced Security:** Secure subprocess execution with input validation, timeout protection, and no shell injection vulnerabilities
*   **Structured Reporting:** Generates detailed JSON campaign results and user-friendly HTML reports.
*   **Interactive Mode:** An intuitive command-line interface for direct interaction and control over agent execution.

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/CyberSecurityUP/NeuroSploitv2.git
    cd NeuroSploitv2
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: `requirements.txt` should contain `anthropic`, `openai`, `google-generativeai`, `requests` as used in `llm_manager.py`)*

4.  **Configure API Keys:**
    NeuroSploitv2 uses environment variables for LLM API keys. Set them in your environment or a `.env` file (and load it, if you set up dotenv).
    *   `ANTHROPIC_API_KEY` for Claude
    *   `OPENAI_API_KEY` for GPT models
    *   `GEMINI_API_KEY` for Gemini models

    Example (`.bashrc` or `.zshrc`):
    ```bash
    export ANTHROPIC_API_KEY="your_anthropic_api_key"
    export OPENAI_API_KEY="your_openai_api_key"
    export GEMINI_API_KEY="your_gemini_api_key"
    ```

5.  **Configure Local LLM Servers (Optional):**
    *   **Ollama:** Ensure your local Ollama server is running on `http://localhost:11434`
    *   **LM Studio:** Start LM Studio server on `http://localhost:1234` with your preferred model loaded

## ⚙️ Configuration

The `config/config.json` file is the central place for configuring NeuroSploitv2. A default `config.json` will be created if one doesn't exist.

### `llm` Section

This section defines your LLM profiles.

```json
"llm": {
    "default_profile": "gemini_pro_default",
    "profiles": {
        "ollama_llama3_default": {
            "provider": "ollama",
            "model": "llama3:8b",
            "api_key": "",
            "temperature": 0.7,
            "max_tokens": 4096,
            "input_token_limit": 8000,
            "output_token_limit": 4000,
            "cache_enabled": true,
            "search_context_level": "medium",
            "pdf_support_enabled": false,
            "guardrails_enabled": true,
            "hallucination_mitigation_strategy": "grounding"
        },
        "gemini_pro_default": {
            "provider": "gemini",
            "model": "gemini-pro",
            "api_key": "${GEMINI_API_KEY}",
            "temperature": 0.7,
            "max_tokens": 4096,
            "input_token_limit": 30720,
            "output_token_limit": 2048,
            "cache_enabled": true,
            "search_context_level": "medium",
            "pdf_support_enabled": true,
            "guardrails_enabled": true,
            "hallucination_mitigation_strategy": "consistency_check"
        },
        // ... other profiles like claude_opus_default, gpt_4o_default
    }
}
```

*   `default_profile`: The name of the LLM profile to use by default.
*   `profiles`: A dictionary where each key is a profile name and its value is an object containing:
    *   `provider`: `ollama`, `claude`, `gpt`, `gemini`, `gemini-cli`, `lmstudio`.
    *   `model`: Specific model identifier (e.g., `llama3:8b`, `gemini-pro`, `claude-3-opus-20240229`, `gpt-4o`).
    *   `api_key`: API key or environment variable placeholder (e.g., `${GEMINI_API_KEY}`).
    *   `temperature`: Controls randomness in output (0.0-1.0).
    *   `max_tokens`: Maximum tokens in the LLM's response.
    *   `input_token_limit`: Maximum tokens allowed in the input prompt.
    *   `output_token_limit`: Maximum tokens allowed in the output response.
    *   `cache_enabled`: Whether to cache LLM responses for this profile.
    *   `search_context_level`: (`low`, `medium`, `high`) How much external context to inject into prompts.
    *   `pdf_support_enabled`: Whether the model/provider can directly process PDFs.
    *   `guardrails_enabled`: Enables content safety and ethical checks.
    *   `hallucination_mitigation_strategy`: `grounding`, `self_reflection`, `consistency_check`.

### `agent_roles` Section

This section defines the various AI agent personas.

```json
"agent_roles": {
    "bug_bounty_hunter": {
        "enabled": true,
        "llm_profile": "gemini_pro_default",
        "tools_allowed": ["subfinder", "nuclei", "burpsuite", "sqlmap"],
        "description": "Focuses on web application vulnerabilities, leveraging recon and exploitation tools."
    },
    // ... other agent roles
}
```

*   Each key is an agent role name (e.g., `red_team_agent`, `malware_analyst`).
*   `enabled`: `true` to enable the agent, `false` to disable.
*   `llm_profile`: The name of the LLM profile from the `llm.profiles` section to use for this agent.
*   `tools_allowed`: A list of tools (from the `tools` section) that this agent is permitted to use.
*   `description`: A brief description of the agent's purpose.

### `tools` Section

Defines the paths to external security tools.

```json
"tools": {
    "nmap": "/usr/bin/nmap",
    "metasploit": "/usr/bin/msfconsole",
    "burpsuite": "/usr/bin/burpsuite",
    "sqlmap": "/usr/bin/sqlmap",
    "hydra": "/usr/bin/hydra",
    "subfinder": "/usr/local/bin/subfinder",
    "nuclei": "/usr/local/bin/nuclei"
}
```

Ensure these paths are correct for your system.

## 🚀 Usage

NeuroSploitv2 can be run in two modes: command-line execution or interactive mode.

### Command-line Execution

To execute a specific agent role with a given input:

```bash
python neurosploit.py --agent-role <agent_role_name> --input "<your_task_or_target>"
# Example:
python neurosploit.py --agent-role red_team_agent --input "Conduct a phishing simulation against example.com's HR department."
python neurosploit.py --agent-role bug_bounty_hunter --input "Analyze example.com for common web vulnerabilities (OWASP Top 10)."
```

*   `--agent-role`: Specify the name of the agent role to use (e.g., `red_team_agent`, `malware_analyst`).
*   `--input`: Provide the task or target information for the agent to process.
*   `-c`/`--config`: (Optional) Path to a custom configuration file.
*   `-v`/`--verbose`: (Optional) Enable verbose logging output.

### Interactive Mode

Start the framework in interactive mode for a conversational experience:

```bash
python neurosploit.py -i
```

Once in interactive mode, you can use the following commands:

*   `run_agent <agent_role_name> "<user_input>"`: Execute a specific agent with your task.
    *   Example: `run_agent pentest_generalist "Perform an external network penetration test on 192.168.1.0/24."`
*   `list_roles`: Display all configured agent roles, their status, LLM profile, allowed tools, and descriptions.
*   `config`: Show the current loaded configuration.
*   `help`: Display available commands.
*   `exit` / `quit`: Exit interactive mode.

## 👤 Agent Roles

NeuroSploitv2 comes with several predefined agent roles, each with a unique persona and focus:

*   **`bug_bounty_hunter`**: Identifies web application vulnerabilities, focusing on high-impact findings.
*   **`blue_team_agent`**: Detects and responds to threats by analyzing security logs and telemetry.
*   **`exploit_expert`**: Crafts exploitation strategies and payloads for discovered vulnerabilities.
*   **`red_team_agent`**: Plans and executes simulated attack campaigns against target environments.
*   **`replay_attack_specialist`**: Focuses on identifying and leveraging replay attack vectors.
*   **`pentest_generalist`**: Performs broad penetration tests across various domains.
*   **`owasp_expert`**: Assesses web applications against the OWASP Top 10.
*   **`cwe_expert`**: Analyzes code and reports for weaknesses based on MITRE CWE Top 25.
*   **`malware_analyst`**: Examines malware samples to understand functionality and identify IOCs.

## 📚 Prompt System

Agent roles are powered by `.md` (Markdown) prompt files located in `prompts/md_library/`. Each `.md` file defines a `User Prompt` and a `System Prompt` that guide the LLM's behavior and context for that specific agent role. This allows for highly customized and effective AI-driven interactions.

## 📊 Output and Reporting

Results from agent executions are saved in the `results/` directory as JSON files (e.g., `campaign_YYYYMMDD_HHMMSS.json`). Additionally, an HTML report (`report_YYYYMMDD_HHMMSS.html`) is generated in the `reports/` directory, providing a human-readable summary of the agent's activities and findings.

## 🧩 Extensibility

*   **Custom Agent Roles:** Easily define new agent roles by creating a new `.md` file in `prompts/md_library/` and adding its configuration to the `agent_roles` section in `config.json`.
*   **Custom Tools:** Add new tools to the `tools` section in `config.json` and grant specific agent roles permission to use them.

## 🤝 Contributing

Contributions are welcome! Please feel free to fork the repository, open issues, and submit pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔧 Built-in Tools

NeuroSploitv2 includes several built-in reconnaissance and post-exploitation tools:

### Reconnaissance Tools
*   **OSINT Collector** (`tools/recon/osint_collector.py`):
    *   IP address resolution
    *   Technology stack detection
    *   Email pattern generation
    *   Social media account discovery
    *   Web framework identification

*   **Subdomain Finder** (`tools/recon/subdomain_finder.py`):
    *   Certificate Transparency log queries
    *   Common subdomain brute-forcing
    *   DNS resolution validation

*   **DNS Enumerator** (`tools/recon/dns_enumerator.py`):
    *   A, AAAA, MX, NS, TXT, CNAME record enumeration
    *   IPv4 and IPv6 resolution
    *   Mail server discovery

### Lateral Movement
*   **SMB Lateral** (`tools/lateral_movement/smb_lateral.py`):
    *   Share enumeration framework
    *   Pass-the-hash preparation
    *   Remote command execution templates

*   **SSH Lateral** (`tools/lateral_movement/ssh_lateral.py`):
    *   SSH accessibility checks
    *   Key enumeration paths
    *   SSH tunnel creation helpers

### Persistence Modules
*   **Cron Persistence** (`tools/persistence/cron_persistence.py`):
    *   Cron entry generation
    *   Persistence location suggestions
    *   Reverse shell payload templates

*   **Registry Persistence** (`tools/persistence/registry_persistence.py`):
    *   Windows registry key enumeration
    *   Registry command generation
    *   Startup persistence mechanisms

## 🛡️ Security Features

*   **Secure Tool Execution:** All external tools are executed with `shlex` argument parsing and no shell injection vulnerabilities
*   **Input Validation:** Tool paths and arguments are validated before execution
*   **Timeout Protection:** 60-second timeout on all tool executions to prevent hanging
*   **Permission System:** Agent-based tool access control
*   **Error Handling:** Comprehensive error handling with detailed logging

## 🔗 Tool Chaining

NeuroSploitv2 supports executing multiple tools in sequence for complex workflows:

```python
# LLM can request multiple tools
[TOOL] nmap: -sV -sC target.com
[TOOL] subfinder: -d target.com
[TOOL] nuclei: -l subdomains.txt
```

The framework will execute each tool in order and provide results to the LLM for analysis.

## 🙏 Acknowledgements

NeuroSploitv2 leverages the power of various Large Language Models and open-source security tools to deliver its capabilities.

### LLM Providers
*   Google Gemini
*   Anthropic Claude
*   OpenAI GPT
*   Ollama
*   LM Studio

### Security Tools
*   Nmap
*   Metasploit
*   Burp Suite
*   SQLMap
*   Hydra
*   Subfinder
*   Nuclei
