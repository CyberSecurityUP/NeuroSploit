# NeuroSploitv2 - Quick Start Guide

## 🚀 Fast Track Setup (5 minutes)

YouTube Video: https://youtu.be/SQq1TVwlrxQ

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set Up API Keys (Choose One)

#### Option A: Using Gemini (Free Tier Available)
```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
```
Get your key at: https://makersuite.google.com/app/apikey

#### Option B: Using LM Studio (Fully Local, No API Key)
```bash
# Download and install LM Studio from: https://lmstudio.ai/
# Start LM Studio and load a model
# Start the local server on port 1234

# Update config/config.json:
{
  "llm": {
    "default_profile": "lmstudio_default"
  }
}
```

#### Option C: Using Ollama (Fully Local, No API Key)
```bash
# Install Ollama: https://ollama.ai/
ollama pull llama3:8b
ollama serve

# Update config/config.json:
{
  "llm": {
    "default_profile": "ollama_llama3_default"
  }
}
```

### 3. Test Installation
```bash
# List available agents
python neurosploit.py --list-agents

# List available LLM profiles
python neurosploit.py --list-profiles
```

---

## 📝 Basic Usage Examples

### Example 1: OSINT Reconnaissance
```bash
python neurosploit.py \
  --agent-role bug_bounty_hunter \
  --input "Perform OSINT reconnaissance on example.com"
```

**What it does:**
- Uses OSINT Collector to gather public information
- Resolves IP addresses
- Detects web technologies
- Generates email patterns
- Identifies potential social media accounts

### Example 2: Subdomain Enumeration
```bash
python neurosploit.py \
  --agent-role pentest_generalist \
  --input "Find all subdomains for example.com"
```

**What it does:**
- Queries Certificate Transparency logs
- Brute-forces common subdomain names
- Validates discovered subdomains via DNS

### Example 3: DNS Enumeration
```bash
python neurosploit.py \
  --agent-role pentest_generalist \
  --input "Enumerate all DNS records for example.com"
```

**What it does:**
- Discovers A records (IPv4)
- Discovers AAAA records (IPv6)
- Finds MX records (mail servers)
- Identifies NS records (name servers)
- Extracts TXT records

### Example 4: Interactive Mode
```bash
python neurosploit.py -i
```

**Commands available:**
```
> list_roles
> run_agent pentest_generalist "scan example.com"
> config
> exit
```

---

## 🧪 Testing the New Features

### Test 1: OSINT Collector
```python
python3 << 'EOF'
from tools.recon.osint_collector import OSINTCollector

collector = OSINTCollector({})
results = collector.collect("google.com")

print("IP Addresses:", results['ip_addresses'])
print("Technologies:", results['technologies'])
print("Email Patterns:", results['email_patterns'][:3])
print("Social Media:", results['social_media'])
EOF
```

**Expected Output:**
```
IP Addresses: ['142.250.xxx.xxx', ...]
Technologies: {'server': 'gws', 'status_code': 200, ...}
Email Patterns: ['info@google.com', 'contact@google.com', ...]
Social Media: {'twitter': 'https://twitter.com/google', ...}
```

### Test 2: Subdomain Finder
```python
python3 << 'EOF'
from tools.recon.subdomain_finder import SubdomainFinder

finder = SubdomainFinder({})
subdomains = finder.find("github.com")

print(f"Found {len(subdomains)} subdomains")
print("First 5:", subdomains[:5])
EOF
```

**Expected Output:**
```
Found 15+ subdomains
First 5: ['api.github.com', 'www.github.com', 'gist.github.com', ...]
```

### Test 3: DNS Enumerator
```python
python3 << 'EOF'
from tools.recon.dns_enumerator import DNSEnumerator

enumerator = DNSEnumerator({})
records = enumerator.enumerate("github.com")

print("A Records:", records['records']['A'])
print("MX Records:", records['records']['MX'])
print("NS Records:", records['records']['NS'])
EOF
```

### Test 4: LM Studio Integration
```bash
# 1. Start LM Studio server
# 2. Load a model (e.g., Llama 3, Mistral, Phi-3)
# 3. Start the server

# 4. Test connection
curl http://localhost:1234/v1/models

# 5. Run NeuroSploit with LM Studio
python neurosploit.py \
  --llm-profile lmstudio_default \
  --agent-role pentest_generalist \
  --input "Explain the OWASP Top 10"
```

---

## 🔧 Testing Tool Chaining

Create a test script to see tool chaining in action:

```bash
python neurosploit.py -i
```

Then enter:
```
run_agent pentest_generalist "Perform complete reconnaissance: DNS enumeration, subdomain discovery, and OSINT collection for example.com"
```

The AI will automatically chain multiple tools:
1. DNS Enumerator → finds DNS records
2. Subdomain Finder → discovers subdomains
3. OSINT Collector → gathers intelligence

All results are combined and analyzed by the AI.

---

## 📊 View Results

### JSON Results
```bash
ls -lt results/
cat results/campaign_*.json | jq '.'
```

### HTML Reports
```bash
ls -lt reports/
open reports/report_*.html  # macOS
xdg-open reports/report_*.html  # Linux
```

---

## 🛠️ Troubleshooting

### Issue: "No module named 'anthropic'"
```bash
pip install anthropic openai google-generativeai requests
```

### Issue: LM Studio Connection Error
```bash
# Verify LM Studio server is running
curl http://localhost:1234/v1/models

# Check logs in LM Studio console
# Ensure model is loaded and server is started
```

### Issue: "Tool not found"
Edit `config/config.json` and update tool paths:
```json
{
  "tools": {
    "nmap": "/usr/bin/nmap",
    "metasploit": "/usr/bin/msfconsole"
  }
}
```

### Issue: DNS Enumeration Shows Limited Results
```bash
# Install nslookup
# macOS: Already included
# Linux: sudo apt-get install dnsutils
```

---

## 🎯 Advanced Examples

### Custom Agent Workflow
```bash
# 1. Web Application Pentest
python neurosploit.py \
  --agent-role owasp_expert \
  --input "Analyze https://testphp.vulnweb.com for OWASP Top 10 vulnerabilities"

# 2. Network Reconnaissance
python neurosploit.py \
  --agent-role red_team_agent \
  --input "Plan a network penetration test for 192.168.1.0/24"

# 3. Malware Analysis
python neurosploit.py \
  --agent-role malware_analyst \
  --input "Analyze this malware sample: /path/to/sample.exe"
```

### Using Different LLM Profiles
```bash
# High-quality reasoning with Claude
python neurosploit.py \
  --llm-profile claude_opus_default \
  --agent-role exploit_expert \
  --input "Generate an exploitation strategy for CVE-2024-XXXX"

# Fast local processing with Ollama
python neurosploit.py \
  --llm-profile ollama_llama3_default \
  --agent-role bug_bounty_hunter \
  --input "Quick scan of example.com"
```

---

## 📚 Next Steps

1. **Read the Full Documentation:** Check `README.md`
2. **Explore Agent Prompts:** Look at `prompts/md_library/`
3. **Review Improvements:** Read `IMPROVEMENTS.md`
4. **Customize Config:** Edit `config/config.json`
5. **Create Custom Agents:** Use `custom_agents/example_agent.py` as template

---

## 🔐 Important Security Notes

1. **Always get authorization** before testing systems
2. **Use in isolated environments** for learning
3. **Never test production systems** without permission
4. **Review all AI-generated commands** before execution
5. **Keep API keys secure** (use environment variables)

---

## 💡 Pro Tips

1. **Interactive Mode is Fastest:** Use `-i` for quick iterations
2. **Tool Chaining Saves Time:** Let AI orchestrate multiple tools
3. **Local LLMs are Free:** Use LM Studio or Ollama for unlimited usage
4. **Results are Logged:** Check `results/` and `reports/` directories
5. **Custom Prompts:** Modify `prompts/md_library/` for specialized behavior

---

**Happy Pentesting! 🎯**

For more help: `python neurosploit.py --help`
