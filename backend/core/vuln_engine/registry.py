"""
NeuroSploit v3 - Vulnerability Registry

Registry of all vulnerability types and their testers.
Provides metadata, severity info, and tester classes.
"""
from typing import Dict, Optional, Tuple
from backend.core.vuln_engine.testers.base_tester import BaseTester
from backend.core.vuln_engine.testers.injection import (
    XSSReflectedTester, XSSStoredTester, XSSDomTester,
    SQLiErrorTester, SQLiUnionTester, SQLiBlindTester, SQLiTimeTester,
    CommandInjectionTester, SSTITester, NoSQLInjectionTester
)
from backend.core.vuln_engine.testers.file_access import (
    LFITester, RFITester, PathTraversalTester, XXETester, FileUploadTester
)
from backend.core.vuln_engine.testers.request_forgery import (
    SSRFTester, CSRFTester
)
from backend.core.vuln_engine.testers.auth import (
    AuthBypassTester, JWTManipulationTester, SessionFixationTester
)
from backend.core.vuln_engine.testers.authorization import (
    IDORTester, BOLATester, PrivilegeEscalationTester
)
from backend.core.vuln_engine.testers.client_side import (
    CORSTester, ClickjackingTester, OpenRedirectTester
)
from backend.core.vuln_engine.testers.infrastructure import (
    SecurityHeadersTester, SSLTester, HTTPMethodsTester
)


class VulnerabilityRegistry:
    """
    Central registry for all vulnerability types.

    Maps vulnerability types to:
    - Tester classes
    - Severity levels
    - CWE IDs
    - Descriptions
    - Remediation advice
    """

    # Vulnerability metadata
    VULNERABILITY_INFO = {
        # XSS
        "xss_reflected": {
            "title": "Reflected Cross-Site Scripting (XSS)",
            "severity": "medium",
            "cwe_id": "CWE-79",
            "description": "Reflected XSS occurs when user input is immediately returned by a web application in an error message, search result, or any other response that includes some or all of the input provided by the user as part of the request, without that data being made safe to render in the browser.",
            "impact": "An attacker can execute arbitrary JavaScript in the victim's browser, potentially stealing session cookies, capturing credentials, or performing actions on behalf of the user.",
            "remediation": "1. Encode all user input when rendering in HTML context\n2. Use Content-Security-Policy headers\n3. Set HttpOnly flag on sensitive cookies\n4. Use modern frameworks with auto-escaping"
        },
        "xss_stored": {
            "title": "Stored Cross-Site Scripting (XSS)",
            "severity": "high",
            "cwe_id": "CWE-79",
            "description": "Stored XSS occurs when malicious script is permanently stored on the target server, such as in a database, message forum, visitor log, or comment field.",
            "impact": "All users who view the affected page will execute the malicious script, leading to mass credential theft, session hijacking, or malware distribution.",
            "remediation": "1. Sanitize and validate all user input before storage\n2. Encode output when rendering\n3. Implement Content-Security-Policy\n4. Use HttpOnly and Secure flags on cookies"
        },
        "xss_dom": {
            "title": "DOM-based Cross-Site Scripting",
            "severity": "medium",
            "cwe_id": "CWE-79",
            "description": "DOM-based XSS occurs when client-side JavaScript processes user input and writes it to the DOM in an unsafe way.",
            "impact": "Attacker can execute JavaScript in the user's browser through malicious links or user interaction.",
            "remediation": "1. Avoid using dangerous DOM sinks (innerHTML, eval, document.write)\n2. Use textContent instead of innerHTML\n3. Sanitize user input on the client side\n4. Implement CSP with strict policies"
        },

        # SQL Injection
        "sqli_error": {
            "title": "Error-based SQL Injection",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "description": "SQL injection vulnerability that reveals database errors containing query information, allowing attackers to extract data through error messages.",
            "impact": "Complete database compromise including data theft, modification, or deletion. May lead to remote code execution on the database server.",
            "remediation": "1. Use parameterized queries/prepared statements\n2. Implement input validation with whitelist approach\n3. Apply least privilege principle for database accounts\n4. Disable detailed error messages in production"
        },
        "sqli_union": {
            "title": "Union-based SQL Injection",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "description": "SQL injection allowing UNION-based queries to extract data from other database tables.",
            "impact": "Full database extraction capability. Attacker can read all database tables, users, and potentially escalate to RCE.",
            "remediation": "1. Use parameterized queries exclusively\n2. Implement strict input validation\n3. Use stored procedures where appropriate\n4. Monitor for unusual query patterns"
        },
        "sqli_blind": {
            "title": "Blind SQL Injection (Boolean-based)",
            "severity": "high",
            "cwe_id": "CWE-89",
            "description": "SQL injection where results are inferred from application behavior changes rather than direct output.",
            "impact": "Slower but complete data extraction is possible. Can lead to full database compromise.",
            "remediation": "1. Use parameterized queries\n2. Implement WAF rules for SQL injection patterns\n3. Use connection pooling with timeout limits\n4. Implement query logging and monitoring"
        },
        "sqli_time": {
            "title": "Time-based Blind SQL Injection",
            "severity": "high",
            "cwe_id": "CWE-89",
            "description": "SQL injection where attacker can infer information based on time delays in responses.",
            "impact": "Complete data extraction possible, though slower. Can determine database structure and content.",
            "remediation": "1. Use parameterized queries\n2. Set strict query timeout limits\n3. Monitor for anomalously slow queries\n4. Implement rate limiting"
        },

        # Command Injection
        "command_injection": {
            "title": "OS Command Injection",
            "severity": "critical",
            "cwe_id": "CWE-78",
            "description": "Application passes unsafe user-supplied data to a system shell, allowing execution of arbitrary OS commands.",
            "impact": "Complete system compromise. Attacker can execute any command with the application's privileges, potentially gaining full server access.",
            "remediation": "1. Avoid shell commands; use native library functions\n2. If shell required, use strict whitelist validation\n3. Never pass user input directly to shell\n4. Run with minimal privileges, use containers"
        },

        # SSTI
        "ssti": {
            "title": "Server-Side Template Injection",
            "severity": "critical",
            "cwe_id": "CWE-94",
            "description": "User input is unsafely embedded into server-side templates, allowing template code execution.",
            "impact": "Often leads to remote code execution. Attacker can read files, execute commands, and compromise the server.",
            "remediation": "1. Never pass user input to template engines\n2. Use logic-less templates when possible\n3. Implement sandbox environments for templates\n4. Validate and sanitize all template inputs"
        },

        # NoSQL Injection
        "nosql_injection": {
            "title": "NoSQL Injection",
            "severity": "high",
            "cwe_id": "CWE-943",
            "description": "Injection attack targeting NoSQL databases like MongoDB through operator injection.",
            "impact": "Authentication bypass, data theft, and potential server compromise depending on database configuration.",
            "remediation": "1. Validate and sanitize all user input\n2. Use parameterized queries where available\n3. Disable server-side JavaScript execution\n4. Apply strict typing to query parameters"
        },

        # File Access
        "lfi": {
            "title": "Local File Inclusion",
            "severity": "high",
            "cwe_id": "CWE-98",
            "description": "Application includes local files based on user input, allowing access to sensitive files.",
            "impact": "Read sensitive configuration files, source code, and potentially achieve code execution via log poisoning.",
            "remediation": "1. Avoid dynamic file inclusion\n2. Use whitelist of allowed files\n3. Validate and sanitize file paths\n4. Implement proper access controls"
        },
        "rfi": {
            "title": "Remote File Inclusion",
            "severity": "critical",
            "cwe_id": "CWE-98",
            "description": "Application includes remote files, allowing execution of attacker-controlled code.",
            "impact": "Direct remote code execution. Complete server compromise.",
            "remediation": "1. Disable allow_url_include in PHP\n2. Use whitelists for file inclusion\n3. Never use user input in include paths\n4. Implement strict input validation"
        },
        "path_traversal": {
            "title": "Path Traversal",
            "severity": "high",
            "cwe_id": "CWE-22",
            "description": "Application allows navigation outside intended directory through ../ sequences.",
            "impact": "Access to sensitive files outside web root, including configuration files and source code.",
            "remediation": "1. Validate and sanitize file paths\n2. Use basename() to strip directory components\n3. Implement chroot or containerization\n4. Use whitelist of allowed directories"
        },
        "xxe": {
            "title": "XML External Entity Injection",
            "severity": "high",
            "cwe_id": "CWE-611",
            "description": "XML parser processes external entity references, allowing file access or SSRF.",
            "impact": "Read local files, perform SSRF attacks, and potentially achieve denial of service.",
            "remediation": "1. Disable external entity processing\n2. Use JSON instead of XML where possible\n3. Validate and sanitize XML input\n4. Use updated XML parsers with secure defaults"
        },
        "file_upload": {
            "title": "Arbitrary File Upload",
            "severity": "high",
            "cwe_id": "CWE-434",
            "description": "Application allows uploading of dangerous file types that can be executed.",
            "impact": "Upload of web shells leading to remote code execution and complete server compromise.",
            "remediation": "1. Validate file type using magic bytes\n2. Rename uploaded files\n3. Store outside web root\n4. Disable execution in upload directory"
        },

        # Request Forgery
        "ssrf": {
            "title": "Server-Side Request Forgery",
            "severity": "high",
            "cwe_id": "CWE-918",
            "description": "Application makes requests to attacker-specified URLs, accessing internal resources.",
            "impact": "Access to internal services, cloud metadata, and potential for pivoting to internal networks.",
            "remediation": "1. Implement URL whitelist\n2. Block requests to internal IPs\n3. Disable unnecessary URL schemes\n4. Use network segmentation"
        },
        "ssrf_cloud": {
            "title": "SSRF to Cloud Metadata",
            "severity": "critical",
            "cwe_id": "CWE-918",
            "description": "SSRF vulnerability allowing access to cloud provider metadata services.",
            "impact": "Credential theft, full cloud account compromise, lateral movement in cloud infrastructure.",
            "remediation": "1. Block requests to metadata IPs\n2. Use IMDSv2 (AWS) or equivalent\n3. Implement strict URL validation\n4. Use firewall rules for metadata endpoints"
        },
        "csrf": {
            "title": "Cross-Site Request Forgery",
            "severity": "medium",
            "cwe_id": "CWE-352",
            "description": "Application allows state-changing requests without proper origin validation.",
            "impact": "Attacker can perform actions as authenticated users, including transfers, password changes, or data modification.",
            "remediation": "1. Implement anti-CSRF tokens\n2. Verify Origin/Referer headers\n3. Use SameSite cookie attribute\n4. Require re-authentication for sensitive actions"
        },

        # Authentication
        "auth_bypass": {
            "title": "Authentication Bypass",
            "severity": "critical",
            "cwe_id": "CWE-287",
            "description": "Authentication mechanisms can be bypassed through various techniques.",
            "impact": "Complete unauthorized access to user accounts and protected resources.",
            "remediation": "1. Implement proper authentication checks on all routes\n2. Use proven authentication frameworks\n3. Implement account lockout\n4. Use MFA for sensitive accounts"
        },
        "jwt_manipulation": {
            "title": "JWT Token Manipulation",
            "severity": "high",
            "cwe_id": "CWE-347",
            "description": "JWT implementation vulnerabilities allowing token forgery or manipulation.",
            "impact": "Authentication bypass, privilege escalation, and identity impersonation.",
            "remediation": "1. Always verify JWT signatures\n2. Use strong signing algorithms (RS256)\n3. Validate all claims including exp and iss\n4. Implement token refresh mechanisms"
        },
        "session_fixation": {
            "title": "Session Fixation",
            "severity": "medium",
            "cwe_id": "CWE-384",
            "description": "Application accepts session tokens from URL parameters or doesn't regenerate after login.",
            "impact": "Attacker can hijack user sessions by fixing known session IDs.",
            "remediation": "1. Regenerate session ID after login\n2. Only accept session from cookies\n3. Implement secure session management\n4. Use short session timeouts"
        },

        # Authorization
        "idor": {
            "title": "Insecure Direct Object Reference",
            "severity": "high",
            "cwe_id": "CWE-639",
            "description": "Application exposes internal object IDs without proper authorization checks.",
            "impact": "Unauthorized access to other users' data, potentially exposing sensitive information.",
            "remediation": "1. Implement proper authorization checks\n2. Use indirect references or UUIDs\n3. Validate user ownership of resources\n4. Implement access control lists"
        },
        "bola": {
            "title": "Broken Object Level Authorization",
            "severity": "high",
            "cwe_id": "CWE-639",
            "description": "API endpoints don't properly validate object-level permissions.",
            "impact": "Access to any object by manipulating IDs, leading to mass data exposure.",
            "remediation": "1. Implement object-level authorization\n2. Validate permissions on every request\n3. Use authorization middleware\n4. Log and monitor access patterns"
        },
        "privilege_escalation": {
            "title": "Privilege Escalation",
            "severity": "critical",
            "cwe_id": "CWE-269",
            "description": "User can elevate privileges to access higher-level functionality.",
            "impact": "User can gain admin access, access to all data, and full system control.",
            "remediation": "1. Implement role-based access control\n2. Validate roles on every request\n3. Use principle of least privilege\n4. Monitor for privilege escalation attempts"
        },

        # Client-side
        "cors_misconfig": {
            "title": "CORS Misconfiguration",
            "severity": "medium",
            "cwe_id": "CWE-942",
            "description": "Overly permissive CORS policy allows cross-origin requests from untrusted domains.",
            "impact": "Cross-origin data theft and unauthorized API access from malicious websites.",
            "remediation": "1. Implement strict origin whitelist\n2. Avoid Access-Control-Allow-Origin: *\n3. Validate Origin header server-side\n4. Don't reflect Origin without validation"
        },
        "clickjacking": {
            "title": "Clickjacking",
            "severity": "medium",
            "cwe_id": "CWE-1021",
            "description": "Application can be framed by malicious pages, tricking users into clicking hidden elements.",
            "impact": "Users can be tricked into performing unintended actions like transfers or permission grants.",
            "remediation": "1. Set X-Frame-Options: DENY\n2. Implement frame-ancestors CSP directive\n3. Use JavaScript frame-busting as backup\n4. Require confirmation for sensitive actions"
        },
        "open_redirect": {
            "title": "Open Redirect",
            "severity": "low",
            "cwe_id": "CWE-601",
            "description": "Application redirects to user-specified URLs without validation.",
            "impact": "Phishing attacks using trusted domain, credential theft, and reputation damage.",
            "remediation": "1. Use whitelist for redirect destinations\n2. Validate redirect URLs server-side\n3. Don't use user input directly in redirects\n4. Warn users before redirecting externally"
        },

        # Infrastructure
        "security_headers": {
            "title": "Missing Security Headers",
            "severity": "low",
            "cwe_id": "CWE-693",
            "description": "Application doesn't set important security headers like CSP, HSTS, X-Frame-Options.",
            "impact": "Increased risk of XSS, clickjacking, and MITM attacks.",
            "remediation": "1. Implement Content-Security-Policy\n2. Enable Strict-Transport-Security\n3. Set X-Frame-Options and X-Content-Type-Options\n4. Configure Referrer-Policy"
        },
        "ssl_issues": {
            "title": "SSL/TLS Configuration Issues",
            "severity": "medium",
            "cwe_id": "CWE-326",
            "description": "Weak SSL/TLS configuration including outdated protocols or weak ciphers.",
            "impact": "Traffic interception, credential theft, and man-in-the-middle attacks.",
            "remediation": "1. Disable SSLv3, TLS 1.0, TLS 1.1\n2. Use strong cipher suites only\n3. Enable HSTS with preload\n4. Implement certificate pinning for mobile apps"
        },
        "http_methods": {
            "title": "Dangerous HTTP Methods Enabled",
            "severity": "low",
            "cwe_id": "CWE-749",
            "description": "Server allows potentially dangerous HTTP methods like TRACE, PUT, DELETE without proper restrictions.",
            "impact": "Potential for XST attacks, unauthorized file uploads, or resource manipulation.",
            "remediation": "1. Disable unnecessary HTTP methods\n2. Configure web server to reject TRACE/TRACK\n3. Implement proper authorization for PUT/DELETE\n4. Use web application firewall"
        },

        # Logic
        "race_condition": {
            "title": "Race Condition",
            "severity": "medium",
            "cwe_id": "CWE-362",
            "description": "Application has race conditions that can be exploited through concurrent requests.",
            "impact": "Double-spending, bypassing limits, or corrupting data through timing attacks.",
            "remediation": "1. Implement proper locking mechanisms\n2. Use atomic database operations\n3. Implement idempotency keys\n4. Add proper synchronization"
        },
        "business_logic": {
            "title": "Business Logic Vulnerability",
            "severity": "varies",
            "cwe_id": "CWE-840",
            "description": "Flaw in application's business logic allowing unintended behavior.",
            "impact": "Varies based on specific flaw - could range from minor to critical impact.",
            "remediation": "1. Review business logic flows\n2. Implement comprehensive validation\n3. Add server-side checks for all rules\n4. Test edge cases and negative scenarios"
        }
    }

    # Tester class mappings
    TESTER_CLASSES = {
        "xss_reflected": XSSReflectedTester,
        "xss_stored": XSSStoredTester,
        "xss_dom": XSSDomTester,
        "sqli_error": SQLiErrorTester,
        "sqli_union": SQLiUnionTester,
        "sqli_blind": SQLiBlindTester,
        "sqli_time": SQLiTimeTester,
        "command_injection": CommandInjectionTester,
        "ssti": SSTITester,
        "nosql_injection": NoSQLInjectionTester,
        "lfi": LFITester,
        "rfi": RFITester,
        "path_traversal": PathTraversalTester,
        "xxe": XXETester,
        "file_upload": FileUploadTester,
        "ssrf": SSRFTester,
        "ssrf_cloud": SSRFTester,  # Same tester, different payloads
        "csrf": CSRFTester,
        "auth_bypass": AuthBypassTester,
        "jwt_manipulation": JWTManipulationTester,
        "session_fixation": SessionFixationTester,
        "idor": IDORTester,
        "bola": BOLATester,
        "privilege_escalation": PrivilegeEscalationTester,
        "cors_misconfig": CORSTester,
        "clickjacking": ClickjackingTester,
        "open_redirect": OpenRedirectTester,
        "security_headers": SecurityHeadersTester,
        "ssl_issues": SSLTester,
        "http_methods": HTTPMethodsTester,
    }

    def __init__(self):
        self._tester_cache = {}

    def get_tester(self, vuln_type: str) -> BaseTester:
        """Get tester instance for a vulnerability type"""
        if vuln_type in self._tester_cache:
            return self._tester_cache[vuln_type]

        tester_class = self.TESTER_CLASSES.get(vuln_type, BaseTester)
        tester = tester_class()
        self._tester_cache[vuln_type] = tester
        return tester

    def get_severity(self, vuln_type: str) -> str:
        """Get severity for a vulnerability type"""
        info = self.VULNERABILITY_INFO.get(vuln_type, {})
        return info.get("severity", "medium")

    def get_cwe_id(self, vuln_type: str) -> str:
        """Get CWE ID for a vulnerability type"""
        info = self.VULNERABILITY_INFO.get(vuln_type, {})
        return info.get("cwe_id", "")

    def get_title(self, vuln_type: str) -> str:
        """Get title for a vulnerability type"""
        info = self.VULNERABILITY_INFO.get(vuln_type, {})
        return info.get("title", vuln_type.replace("_", " ").title())

    def get_description(self, vuln_type: str) -> str:
        """Get description for a vulnerability type"""
        info = self.VULNERABILITY_INFO.get(vuln_type, {})
        return info.get("description", "")

    def get_impact(self, vuln_type: str) -> str:
        """Get impact for a vulnerability type"""
        info = self.VULNERABILITY_INFO.get(vuln_type, {})
        return info.get("impact", "")

    def get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for a vulnerability type"""
        info = self.VULNERABILITY_INFO.get(vuln_type, {})
        return info.get("remediation", "")
