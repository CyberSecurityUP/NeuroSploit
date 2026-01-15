# Authenticated Vulnerability Testing with NeuroSploitv2 and OWASP ZAP

## Table of Contents
1. [Introduction](#introduction)
2. [Overview of NeuroSploitv2](#overview-of-neurosploitv2)
3. [Understanding Authenticated Testing](#understanding-authenticated-testing)
4. [OWASP ZAP Integration](#owasp-zap-integration)
5. [Obtaining Session Cookies](#obtaining-session-cookies)
6. [Complete Setup Guide](#complete-setup-guide)
7. [Step-by-Step Workflow](#step-by-step-workflow)
8. [Configuration Examples](#configuration-examples)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)
11. [Advanced Techniques](#advanced-techniques)

---

## Introduction

This document provides a comprehensive guide on how to leverage **NeuroSploitv2** for authenticated web application vulnerability testing using **OWASP ZAP** and session cookies. Authenticated testing is crucial for discovering vulnerabilities that only exist in protected areas of applications, such as:

- Insecure Direct Object References (IDOR)
- Broken Access Control
- Privilege Escalation
- Session Management Issues
- Authenticated API Vulnerabilities

---

## Overview of NeuroSploitv2

### What is NeuroSploitv2?

NeuroSploitv2 is an AI-powered penetration testing framework that:

- **Orchestrates Security Tools**: Uses AI agents to intelligently select and execute security tools
- **Automates Workflows**: Chains multiple tools together based on findings
- **Generates Reports**: Creates detailed HTML and JSON reports of vulnerabilities
- **Supports Multiple LLMs**: Works with Claude, GPT, Gemini, Ollama, and LM Studio
- **Agent-Based Architecture**: Specialized agents for different testing scenarios

### Key Components

1. **BaseAgent**: Core agent class that orchestrates LLM interactions and tool execution
2. **LLMManager**: Manages multiple LLM providers and prompt templates
3. **Tool Execution System**: Safely executes external security tools
4. **Reporting System**: Generates comprehensive vulnerability reports

### How AI Helps in Testing

The AI agent:
- **Decides which tools to use** based on the testing objective
- **Interprets tool outputs** and identifies vulnerabilities
- **Adapts strategy** based on findings
- **Correlates multiple findings** to identify complex vulnerabilities
- **Generates actionable reports** with remediation steps

---

## Understanding Authenticated Testing

### Why Authenticated Testing Matters

Most web applications have two security layers:

1. **Unauthenticated Areas**: Public-facing pages (homepage, login, public APIs)
2. **Authenticated Areas**: Protected areas requiring login (dashboards, user profiles, admin panels)

**Critical vulnerabilities often exist only in authenticated areas:**

- **IDOR (Insecure Direct Object Reference)**: Accessing other users' data by manipulating IDs
- **Broken Access Control**: Accessing admin functions as regular user
- **Privilege Escalation**: Gaining higher privileges than intended
- **Session Fixation**: Manipulating session tokens
- **CSRF in Authenticated Context**: Cross-site request forgery in protected areas

### What You Need for Authenticated Testing

1. **Valid Credentials**: Username and password (or API keys)
2. **Session Cookie**: Authentication token/session identifier
3. **Target Endpoints**: URLs of protected areas to test
4. **Testing Tools**: ZAP, SQLMap, or other authenticated scanners

---

## OWASP ZAP Integration

### Why OWASP ZAP?

**OWASP ZAP (Zed Attack Proxy)** is the perfect tool for authenticated testing because:

✅ **100% Free and Open Source**  
✅ **Excellent CLI Support** - Works seamlessly with NeuroSploitv2  
✅ **Strong Authentication Features** - Supports multiple auth methods  
✅ **Comprehensive Scanning** - Active and passive vulnerability scanning  
✅ **Session Management** - Handles cookies and tokens automatically  
✅ **API Access** - Full REST API for automation  

### ZAP Authentication Methods

ZAP supports several authentication methods:

1. **Session Cookie Authentication** (Our focus)
   - Uses existing session cookies
   - Simple and effective
   - Works with most web applications

2. **Form-Based Authentication**
   - Automatically logs in via forms
   - Handles CSRF tokens
   - Manages session lifecycle

3. **HTTP Basic/Digest Authentication**
   - For API endpoints
   - Header-based authentication

4. **Script-Based Authentication**
   - Custom authentication scripts
   - For complex authentication flows

---

## Obtaining Session Cookies

### Method 1: Browser Developer Tools (Easiest)

This is the most straightforward method for obtaining session cookies:

#### Step-by-Step Process:

1. **Open Your Web Application**
   ```
   Navigate to: https://your-webapp.com
   ```

2. **Open Developer Tools**
   - **Chrome/Edge**: Press `F12` or `Ctrl+Shift+I` (Windows) / `Cmd+Option+I` (Mac)
   - **Firefox**: Press `F12` or `Ctrl+Shift+I` (Windows) / `Cmd+Option+I` (Mac)
   - **Safari**: Enable Developer menu first, then `Cmd+Option+I`

3. **Navigate to Application/Storage Tab**
   - **Chrome/Edge**: Click "Application" tab → "Cookies" → Select your domain
   - **Firefox**: Click "Storage" tab → "Cookies" → Select your domain
   - **Safari**: Click "Storage" tab → "Cookies"

4. **Log In to the Application**
   - Enter your credentials
   - Complete the login process

5. **Find the Session Cookie**
   - Look for cookies with names like:
     - `PHPSESSID` (PHP applications)
     - `JSESSIONID` (Java applications)
     - `sessionid` (Django applications)
     - `ASP.NET_SessionId` (ASP.NET applications)
     - `connect.sid` (Express.js applications)
     - Custom session cookies (varies by application)

6. **Copy the Cookie Value**
   - Right-click on the cookie → Copy value
   - Or manually copy the "Value" column

#### Example Cookie Extraction:

```
Cookie Name: PHPSESSID
Cookie Value: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
Domain: .your-webapp.com
Path: /
```

**Full Cookie String for ZAP:**
```
PHPSESSID=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

### Method 2: Browser Network Tab

1. **Open Developer Tools** → **Network Tab**
2. **Log In** to the application
3. **Find the Login Request** in the network log
4. **Click on the Request** → **Headers Tab**
5. **Look for "Set-Cookie"** in Response Headers
6. **Copy the cookie value** from the response

### Method 3: Using curl/HTTPie

If you have login credentials, you can obtain cookies programmatically:

```bash
# Using curl
curl -c cookies.txt -X POST https://your-webapp.com/login \
  -d "username=testuser&password=testpass" \
  -H "Content-Type: application/x-www-form-urlencoded"

# View cookies
cat cookies.txt

# Extract session cookie
grep PHPSESSID cookies.txt
```

### Method 4: Using Python requests

```python
import requests

# Create session
session = requests.Session()

# Login
login_url = "https://your-webapp.com/login"
credentials = {
    "username": "testuser",
    "password": "testpass"
}

response = session.post(login_url, data=credentials)

# Extract session cookie
session_cookie = session.cookies.get('PHPSESSID')
print(f"Session Cookie: {session_cookie}")

# Or get all cookies as string
cookie_string = "; ".join([f"{name}={value}" for name, value in session.cookies.items()])
print(f"Cookie String: {cookie_string}")
```

### Method 5: Browser Extensions

Use browser extensions to export cookies:

- **Chrome**: "EditThisCookie" or "Cookie-Editor"
- **Firefox**: "Cookie Quick Manager"

### Method 6: Burp Suite / OWASP ZAP Proxy

1. **Configure Browser Proxy** to use ZAP (localhost:8080)
2. **Browse and Log In** through the proxy
3. **View Requests in ZAP** → Find login request
4. **Extract Cookie** from response headers

---

## Complete Setup Guide

### Prerequisites

1. **Python 3.8+** installed
2. **NeuroSploitv2** framework installed
3. **OWASP ZAP** installed
4. **zap-cli** (optional but recommended)

### Step 1: Install OWASP ZAP

#### Option A: Download Standalone (Recommended)

```bash
# Download from official website
# https://www.zaproxy.org/download/

# Extract and note the installation path
# Example: /opt/zaproxy/ or ~/zaproxy/
```

#### Option B: Install via Package Manager

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install zaproxy

# macOS (via Homebrew)
brew install --cask owasp-zap

# Verify installation
zap.sh --version
```

### Step 2: Install zap-cli (Python Wrapper)

```bash
# Install zap-cli for easier command-line usage
pip install zapcli

# Verify installation
zap-cli --version
```

### Step 3: Configure NeuroSploitv2

Edit `config/config.json`:

```json
{
  "tools": {
    "nmap": "/usr/bin/nmap",
    "sqlmap": "/usr/bin/sqlmap",
    "subfinder": "/usr/local/bin/subfinder",
    "nuclei": "/usr/local/bin/nuclei",
    "zap": "/usr/bin/zap-cli",
    "zap_baseline": "/opt/zaproxy/zap-baseline.py"
  },
  "agent_roles": {
    "bug_bounty_hunter": {
      "enabled": true,
      "tools_allowed": [
        "subfinder",
        "nuclei",
        "zap",
        "sqlmap"
      ],
      "description": "Web application testing with authenticated ZAP scanning"
    },
    "owasp_expert": {
      "enabled": true,
      "tools_allowed": [
        "zap",
        "sqlmap"
      ],
      "description": "OWASP Top 10 assessment with authenticated ZAP"
    },
    "pentest_generalist": {
      "enabled": true,
      "tools_allowed": [
        "nmap",
        "subfinder",
        "nuclei",
        "zap",
        "sqlmap"
      ],
      "description": "Comprehensive testing with authenticated ZAP"
    }
  }
}
```

**Note**: Update the paths according to your installation:
- `zap-cli` is usually at `/usr/local/bin/zap-cli` or `~/.local/bin/zap-cli`
- `zap-baseline.py` is in your ZAP installation directory

### Step 4: Verify ZAP Installation

```bash
# Start ZAP daemon (required for zap-cli)
zap-cli start

# Test ZAP connection
zap-cli status

# Run a quick test scan
zap-cli quick-scan --start-options '-config api.disablekey=true' https://example.com
```

---

## Step-by-Step Workflow

### Workflow Overview

```
1. Obtain Session Cookie
   ↓
2. Start ZAP Daemon
   ↓
3. Configure NeuroSploitv2
   ↓
4. Run Authenticated Scan
   ↓
5. Analyze Results
   ↓
6. Generate Report
```

### Detailed Steps

#### Step 1: Obtain Session Cookie

Use one of the methods described in [Obtaining Session Cookies](#obtaining-session-cookies) section.

**Example Cookie:**
```
PHPSESSID=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6; csrf_token=xyz789abc
```

#### Step 2: Start ZAP Daemon

```bash
# Start ZAP in daemon mode (runs in background)
zap-cli start

# Verify ZAP is running
zap-cli status
```

**Expected Output:**
```
ZAP is running
```

#### Step 3: Prepare Your Test Command

You'll provide the session cookie and target information to NeuroSploitv2.

#### Step 4: Run Authenticated Scan

##### Option A: Interactive Mode (Recommended)

```bash
# Start NeuroSploitv2 in interactive mode
python neurosploit.py -i

# Run authenticated scan
> run_agent bug_bounty_hunter "Perform authenticated vulnerability scan on https://myapp.com. Session cookie: PHPSESSID=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6. Test authenticated endpoints: /api/users, /admin/dashboard, /profile/settings. Focus on IDOR, privilege escalation, and broken access control vulnerabilities."
```

##### Option B: Command Line

```bash
python neurosploit.py \
  --agent-role bug_bounty_hunter \
  --input "Authenticated vulnerability scan on https://myapp.com. Session cookie: PHPSESSID=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6. Test endpoints: /api/*, /admin/*, /user/profile"
```

#### Step 5: AI Agent Orchestration

The AI agent will:

1. **Parse your request** and extract:
   - Target URL
   - Session cookie
   - Endpoints to test

2. **Generate ZAP commands**:
   ```bash
   [TOOL] zap: quick-scan --cookie "PHPSESSID=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" https://myapp.com
   ```

3. **Execute the scan** and capture output

4. **Analyze results** and identify vulnerabilities

5. **Generate comprehensive report**

#### Step 6: Review Results

```bash
# View JSON results
cat results/campaign_*.json

# View HTML report
open reports/report_*.html  # macOS
xdg-open reports/report_*.html  # Linux
```

---

## Configuration Examples

### Example 1: Basic Authenticated Scan

**Scenario**: Test a web application with a simple session cookie

**Cookie**: `PHPSESSID=abc123xyz789`

**Command**:
```bash
python neurosploit.py \
  --agent-role bug_bounty_hunter \
  --input "Authenticated scan on https://myapp.com with session cookie PHPSESSID=abc123xyz789"
```

**What Happens**:
- AI starts ZAP daemon (if not running)
- Configures ZAP with session cookie
- Runs spider scan to discover authenticated endpoints
- Performs active vulnerability scanning
- Analyzes results and generates report

### Example 2: Multiple Cookies

**Scenario**: Application uses multiple cookies (session + CSRF token)

**Cookies**: 
```
PHPSESSID=abc123xyz789; csrf_token=def456uvw012; user_pref=theme=dark
```

**Command**:
```bash
python neurosploit.py \
  --agent-role owasp_expert \
  --input "OWASP Top 10 scan on https://myapp.com. Cookies: PHPSESSID=abc123xyz789; csrf_token=def456uvw012. Test authenticated areas for injection, broken auth, and sensitive data exposure."
```

### Example 3: Specific Endpoint Testing

**Scenario**: Test specific authenticated endpoints

**Command**:
```bash
python neurosploit.py -i

> run_agent bug_bounty_hunter "Test authenticated API endpoints on https://api.myapp.com. Session cookie: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. Test endpoints: /api/v1/users, /api/v1/admin/settings, /api/v1/profile. Look for IDOR, broken access control, and API authentication bypass."
```

### Example 4: Complete Authenticated Assessment

**Scenario**: Comprehensive authenticated penetration test

**Command**:
```bash
python neurosploit.py \
  --agent-role pentest_generalist \
  --input "Comprehensive authenticated penetration test on https://myapp.com. Authentication: Session cookie PHPSESSID=abc123xyz789. Scope: All authenticated endpoints. Focus areas: 1) IDOR vulnerabilities in user profiles and API endpoints, 2) Privilege escalation in admin functions, 3) Broken access control in /admin/* paths, 4) Session management issues, 5) CSRF in authenticated forms. Use ZAP for automated scanning and provide detailed exploitation steps for each finding."
```

### Example 5: Form-Based Authentication (Alternative)

If you prefer form-based authentication instead of cookies:

**Command**:
```bash
python neurosploit.py \
  --agent-role bug_bounty_hunter \
  --input "Authenticated scan on https://myapp.com using form authentication. Login URL: https://myapp.com/login, Username: testuser, Password: testpass123. Test authenticated endpoints for vulnerabilities."
```

**Note**: The AI will need to configure ZAP context for form-based auth, which requires additional setup.

---

## Best Practices

### 1. Cookie Management

✅ **Do**:
- Use fresh session cookies (obtain right before testing)
- Include all relevant cookies (session, CSRF, etc.)
- Verify cookie validity before scanning
- Document cookie expiration time

❌ **Don't**:
- Use expired cookies
- Share cookies between different test sessions
- Use cookies from production in test environments

### 2. Scope Definition

✅ **Clearly define**:
- Target URLs and endpoints
- Authentication requirements
- Testing boundaries
- Sensitive areas to avoid

**Example**:
```
"Test https://myapp.com with cookie PHPSESSID=abc123. 
Scope: /api/*, /user/*, /dashboard/*. 
Exclude: /admin/delete, /admin/export (destructive operations)"
```

### 3. Session Validity

- **Check cookie expiration**: Some cookies expire quickly
- **Refresh if needed**: Re-authenticate if scan takes long
- **Monitor session**: Watch for session timeout during scanning

### 4. Rate Limiting

- **Respect rate limits**: Don't overwhelm the application
- **Use delays**: Configure ZAP to add delays between requests
- **Monitor responses**: Watch for 429 (Too Many Requests) errors

### 5. Security Considerations

⚠️ **Important**:
- Only test applications you own or have permission to test
- Use test/staging environments when possible
- Don't perform destructive testing without authorization
- Follow responsible disclosure for vulnerabilities

### 6. Tool Configuration

**ZAP Configuration Tips**:

```bash
# Start ZAP with custom options
zap-cli start --start-options '-config api.disablekey=true -config scanner.attackOnStart=true'

# Configure scan policy
zap-cli policy set-strength High
zap-cli policy set-threshold Medium
```

### 7. Report Analysis

- **Review AI-generated findings** carefully
- **Verify false positives** manually
- **Prioritize vulnerabilities** by severity
- **Document exploitation steps** for critical findings

---

## Troubleshooting

### Issue 1: ZAP Not Starting

**Symptoms**:
```
Error: Cannot connect to ZAP
```

**Solutions**:
```bash
# Check if ZAP is running
zap-cli status

# Start ZAP manually
zap-cli start

# Check ZAP port (default: 8080)
netstat -an | grep 8080

# Kill existing ZAP processes
pkill -f zap
zap-cli start
```

### Issue 2: Invalid Session Cookie

**Symptoms**:
```
401 Unauthorized
403 Forbidden
Redirected to login page
```

**Solutions**:
- **Re-obtain cookie**: Get a fresh session cookie
- **Check cookie format**: Ensure proper format (name=value)
- **Verify cookie validity**: Test cookie in browser first
- **Include all cookies**: Some apps need multiple cookies

### Issue 3: Cookie Expired During Scan

**Symptoms**:
```
Scan starts successfully but fails mid-way
```

**Solutions**:
- **Use longer-lived sessions**: Configure app for longer session timeout
- **Refresh cookie**: Re-authenticate and update cookie
- **Use form-based auth**: Let ZAP handle authentication automatically

### Issue 4: ZAP Timeout

**Symptoms**:
```
[ERROR] Tool execution timeout after 60 seconds
```

**Solutions**:
- **Increase timeout**: Modify `base_agent.py` timeout (default: 60s)
- **Use baseline scan**: Faster than full active scan
- **Scan smaller scope**: Test fewer endpoints at once

### Issue 5: AI Not Using ZAP

**Symptoms**:
```
AI doesn't generate [TOOL] zap commands
```

**Solutions**:
- **Check tools_allowed**: Ensure "zap" is in agent's tools_allowed list
- **Be explicit**: Mention "Use ZAP" in your input
- **Check tool path**: Verify ZAP path in config.json is correct

### Issue 6: Cookie Not Working in ZAP

**Symptoms**:
```
ZAP scan runs but finds no authenticated endpoints
```

**Solutions**:
```bash
# Test cookie manually first
curl -H "Cookie: PHPSESSID=abc123" https://myapp.com/api/users

# Verify ZAP is using cookie
zap-cli context list
zap-cli context info <context-name>

# Check ZAP session
zap-cli session list
```

---

## Advanced Techniques

### Technique 1: Context-Based Authentication

Create a ZAP context for better authentication management:

```bash
# Create context file (auth_context.json)
cat > auth_context.json << EOF
{
  "context": {
    "name": "WebApp",
    "urls": ["https://myapp.com"],
    "authentication": {
      "method": "manual",
      "loggedInIndicator": "Logout"
    }
  }
}
EOF

# Import context
zap-cli context import auth_context.json

# Use context in scan
zap-cli quick-scan --context WebApp --cookie "PHPSESSID=abc123" https://myapp.com
```

### Technique 2: Multi-Step Authentication

For complex authentication flows:

```javascript
// Create auth script (auth_script.js)
var loginUrl = "https://myapp.com/login";
var step1Data = "username=testuser";
var step2Data = "password=testpass&otp=123456";

// Step 1: Submit username
var request1 = new org.parosproxy.paros.network.HttpMessage();
// ... configure request1 ...

// Step 2: Submit password + OTP
var request2 = new org.parosproxy.paros.network.HttpMessage();
// ... configure request2 ...

// Extract session cookie
var sessionCookie = response.getResponseHeader().getHeader("Set-Cookie");
```

### Technique 3: Automated Cookie Refresh

Create a script to refresh cookies during long scans:

```python
import requests
import time

def refresh_session_cookie(login_url, credentials):
    """Refresh session cookie"""
    session = requests.Session()
    response = session.post(login_url, data=credentials)
    return session.cookies.get('PHPSESSID')

# Use in long-running scans
while scan_running:
    cookie = refresh_session_cookie(login_url, credentials)
    # Update ZAP with new cookie
    time.sleep(3600)  # Refresh every hour
```

### Technique 4: Custom ZAP Scripts

Create custom ZAP scripts for specific testing:

```bash
# Load custom script
zap-cli script load custom_auth.js

# Use in scan
zap-cli quick-scan --script custom_auth.js https://myapp.com
```

### Technique 5: Integration with Other Tools

Combine ZAP with other tools for comprehensive testing:

```bash
# ZAP for authenticated scanning
zap-cli quick-scan --cookie "PHPSESSID=abc123" https://myapp.com

# SQLMap for authenticated SQL injection testing
sqlmap -u "https://myapp.com/api/users?id=1" --cookie="PHPSESSID=abc123" --batch

# Nuclei for authenticated template scanning
nuclei -u https://myapp.com -H "Cookie: PHPSESSID=abc123" -t ~/nuclei-templates/
```

---

## Example: Complete Authenticated Test Scenario

### Scenario: E-Commerce Application

**Application**: `https://shop.example.com`  
**Authentication**: Session cookie  
**Test Scope**: User dashboard, order history, profile settings

#### Step 1: Obtain Session Cookie

```bash
# Using browser:
# 1. Open https://shop.example.com
# 2. Login with test credentials
# 3. Open DevTools → Application → Cookies
# 4. Copy: session_id=abc123xyz789
```

#### Step 2: Configure NeuroSploitv2

```json
{
  "agent_roles": {
    "bug_bounty_hunter": {
      "tools_allowed": ["zap", "sqlmap", "nuclei"]
    }
  }
}
```

#### Step 3: Run Authenticated Scan

```bash
python neurosploit.py -i

> run_agent bug_bounty_hunter "Perform authenticated vulnerability assessment on https://shop.example.com. Session cookie: session_id=abc123xyz789. Test endpoints: /dashboard, /orders, /profile, /api/user/*. Focus on: 1) IDOR in order history (accessing other users' orders), 2) Broken access control in profile settings, 3) SQL injection in search functionality, 4) XSS in user comments, 5) CSRF in order cancellation. Provide detailed exploitation steps for each vulnerability found."
```

#### Step 4: AI Agent Execution

The AI will:
1. Start ZAP daemon
2. Configure ZAP with session cookie
3. Spider authenticated areas
4. Perform active vulnerability scanning
5. Test for IDOR, broken access control, etc.
6. Generate comprehensive report

#### Step 5: Review Findings

```bash
# View report
open reports/report_*.html

# Expected findings might include:
# - IDOR: /api/orders/{id} allows accessing other users' orders
# - Broken Access Control: Regular users can access admin endpoints
# - SQL Injection: Search parameter vulnerable to SQLi
# - XSS: User comments reflect user input without sanitization
```

---

## Summary

This guide has covered:

✅ **NeuroSploitv2 Overview**: Understanding the AI-powered framework  
✅ **Authenticated Testing**: Why it's crucial for security testing  
✅ **OWASP ZAP Integration**: How to use ZAP for authenticated scanning  
✅ **Session Cookie Extraction**: Multiple methods to obtain cookies  
✅ **Complete Setup**: Step-by-step installation and configuration  
✅ **Workflow**: Detailed process for authenticated testing  
✅ **Best Practices**: Security and testing guidelines  
✅ **Troubleshooting**: Common issues and solutions  
✅ **Advanced Techniques**: Power-user tips and tricks  

### Key Takeaways

1. **Session cookies are essential** for authenticated testing
2. **ZAP is a powerful free alternative** to Burp Suite Professional
3. **NeuroSploitv2 AI orchestrates** the entire testing process
4. **Multiple cookie extraction methods** are available
5. **Proper configuration** ensures successful scans

### Next Steps

1. Install and configure ZAP
2. Update NeuroSploitv2 configuration
3. Obtain a session cookie from your test application
4. Run your first authenticated scan
5. Review and analyze the results

---

## Additional Resources

- **OWASP ZAP Documentation**: https://www.zaproxy.org/docs/
- **ZAP CLI Documentation**: https://github.com/Grunny/zap-cli
- **NeuroSploitv2 GitHub**: [Repository URL]
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

---

## Appendix: Quick Reference

### Common ZAP Commands

```bash
# Start ZAP
zap-cli start

# Status check
zap-cli status

# Quick scan with cookie
zap-cli quick-scan --cookie "PHPSESSID=abc123" https://example.com

# Active scan with cookie
zap-cli active-scan --cookie "PHPSESSID=abc123" https://example.com

# Spider with cookie
zap-cli spider --cookie "PHPSESSID=abc123" https://example.com

# Generate report
zap-cli report -o report.html -f html

# Stop ZAP
zap-cli shutdown
```

### Cookie Format Examples

```
# Single cookie
PHPSESSID=abc123xyz789

# Multiple cookies
PHPSESSID=abc123xyz789; csrf_token=def456uvw012

# With path
session_id=abc123; Path=/; Domain=.example.com
```

### NeuroSploitv2 Command Templates

```bash
# Basic authenticated scan
python neurosploit.py --agent-role bug_bounty_hunter \
  --input "Authenticated scan on {URL} with cookie {COOKIE}"

# OWASP Top 10 focused
python neurosploit.py --agent-role owasp_expert \
  --input "OWASP Top 10 scan on {URL} with cookie {COOKIE}"

# Comprehensive test
python neurosploit.py --agent-role pentest_generalist \
  --input "Full authenticated penetration test on {URL} with cookie {COOKIE}"
```

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Author**: NeuroSploitv2 Documentation Team

