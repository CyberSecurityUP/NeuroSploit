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
from backend.core.vuln_engine.testers.advanced_injection import (
    LdapInjectionTester, XpathInjectionTester, GraphqlInjectionTester,
    CrlfInjectionTester, HeaderInjectionTester, EmailInjectionTester,
    ELInjectionTester, LogInjectionTester, HtmlInjectionTester,
    CsvInjectionTester, OrmInjectionTester
)
from backend.core.vuln_engine.testers.file_access import (
    LFITester, RFITester, PathTraversalTester, XXETester, FileUploadTester,
    ArbitraryFileReadTester, ArbitraryFileDeleteTester, ZipSlipTester
)
from backend.core.vuln_engine.testers.request_forgery import (
    SSRFTester, CSRFTester, GraphqlIntrospectionTester, GraphqlDosTester
)
from backend.core.vuln_engine.testers.auth import (
    AuthBypassTester, JWTManipulationTester, SessionFixationTester,
    WeakPasswordTester, DefaultCredentialsTester, TwoFactorBypassTester,
    OauthMisconfigTester
)
from backend.core.vuln_engine.testers.authorization import (
    IDORTester, BOLATester, PrivilegeEscalationTester,
    BflaTester, MassAssignmentTester, ForcedBrowsingTester
)
from backend.core.vuln_engine.testers.client_side import (
    CORSTester, ClickjackingTester, OpenRedirectTester,
    DomClobberingTester, PostMessageVulnTester, WebsocketHijackTester,
    PrototypePollutionTester, CssInjectionTester, TabnabbingTester
)
from backend.core.vuln_engine.testers.infrastructure import (
    SecurityHeadersTester, SSLTester, HTTPMethodsTester,
    DirectoryListingTester, DebugModeTester, ExposedAdminPanelTester,
    ExposedApiDocsTester, InsecureCookieFlagsTester
)
from backend.core.vuln_engine.testers.logic import (
    RaceConditionTester, BusinessLogicTester, RateLimitBypassTester,
    ParameterPollutionTester, TypeJugglingTester, TimingAttackTester,
    HostHeaderInjectionTester, HttpSmugglingTester, CachePoisoningTester
)
from backend.core.vuln_engine.testers.data_exposure import (
    SensitiveDataExposureTester, InformationDisclosureTester,
    ApiKeyExposureTester, SourceCodeDisclosureTester,
    BackupFileExposureTester, VersionDisclosureTester
)
from backend.core.vuln_engine.testers.cloud_supply import (
    S3BucketMisconfigTester, CloudMetadataExposureTester,
    SubdomainTakeoverTester, VulnerableDependencyTester,
    ContainerEscapeTester, ServerlessMisconfigTester
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
        },

        # ===== NEW TYPES (68 additional) =====

        # Advanced Injection
        "ldap_injection": {"title": "LDAP Injection", "severity": "high", "cwe_id": "CWE-90", "description": "User input injected into LDAP queries allowing directory enumeration or auth bypass.", "impact": "Directory enumeration, authentication bypass, data extraction from LDAP stores.", "remediation": "1. Escape LDAP special characters\n2. Use parameterized LDAP queries\n3. Validate input against whitelist\n4. Apply least privilege to LDAP accounts"},
        "xpath_injection": {"title": "XPath Injection", "severity": "high", "cwe_id": "CWE-643", "description": "User input injected into XPath queries manipulating XML data retrieval.", "impact": "Extraction of XML data, authentication bypass via XPath condition manipulation.", "remediation": "1. Use parameterized XPath queries\n2. Validate and sanitize input\n3. Avoid string concatenation in XPath\n4. Limit XPath query privileges"},
        "graphql_injection": {"title": "GraphQL Injection", "severity": "high", "cwe_id": "CWE-89", "description": "Injection attacks targeting GraphQL endpoints through malicious queries or variables.", "impact": "Schema exposure, unauthorized data access, denial of service via complex queries.", "remediation": "1. Disable introspection in production\n2. Implement query depth/complexity limits\n3. Use persisted queries\n4. Apply field-level authorization"},
        "crlf_injection": {"title": "CRLF Injection / HTTP Response Splitting", "severity": "medium", "cwe_id": "CWE-93", "description": "Injection of CRLF characters to manipulate HTTP response headers or split responses.", "impact": "HTTP header injection, session fixation via Set-Cookie, XSS via response splitting.", "remediation": "1. Strip \\r\\n from user input in headers\n2. Use framework header-setting functions\n3. Validate header values\n4. Implement WAF rules for CRLF patterns"},
        "header_injection": {"title": "HTTP Header Injection", "severity": "medium", "cwe_id": "CWE-113", "description": "User input reflected in HTTP headers enabling header manipulation.", "impact": "Password reset poisoning, cache poisoning, access control bypass via header manipulation.", "remediation": "1. Validate Host header against whitelist\n2. Don't use Host header for URL generation\n3. Strip CRLF from header values\n4. Use absolute URLs for sensitive operations"},
        "email_injection": {"title": "Email Header Injection", "severity": "medium", "cwe_id": "CWE-93", "description": "Injection of email headers through form fields that feed into mail functions.", "impact": "Spam relay, phishing via injected CC/BCC recipients, email content manipulation.", "remediation": "1. Validate email addresses strictly\n2. Strip CRLF from email inputs\n3. Use email library APIs not raw headers\n4. Implement rate limiting on email features"},
        "expression_language_injection": {"title": "Expression Language Injection", "severity": "critical", "cwe_id": "CWE-917", "description": "Injection of EL/SpEL/OGNL expressions evaluated server-side in Java applications.", "impact": "Remote code execution, server compromise, data exfiltration via expression evaluation.", "remediation": "1. Disable EL evaluation on user input\n2. Use strict sandboxing\n3. Update frameworks (Struts2 OGNL patches)\n4. Validate input before template rendering"},
        "log_injection": {"title": "Log Injection / Log4Shell", "severity": "high", "cwe_id": "CWE-117", "description": "Injection into application logs enabling log forging or JNDI-based RCE (Log4Shell).", "impact": "Log tampering, JNDI-based RCE (Log4Shell), log analysis tool exploitation.", "remediation": "1. Strip newlines from log input\n2. Update Log4j to 2.17+ (CVE-2021-44228)\n3. Disable JNDI lookups\n4. Use structured logging"},
        "html_injection": {"title": "HTML Injection", "severity": "medium", "cwe_id": "CWE-79", "description": "Injection of HTML markup into web pages without script execution.", "impact": "Content spoofing, phishing form injection, defacement, link manipulation.", "remediation": "1. HTML-encode all user output\n2. Use Content-Security-Policy\n3. Implement output encoding libraries\n4. Sanitize HTML with whitelist approach"},
        "csv_injection": {"title": "CSV/Formula Injection", "severity": "medium", "cwe_id": "CWE-1236", "description": "Injection of spreadsheet formulas into data exported as CSV/Excel.", "impact": "Code execution when CSV opened in Excel, DDE attacks, data exfiltration via formulas.", "remediation": "1. Prefix cells starting with =,+,-,@ with single quote\n2. Sanitize formula characters\n3. Use safe CSV export libraries\n4. Warn users about untrusted CSV files"},
        "orm_injection": {"title": "ORM Injection", "severity": "high", "cwe_id": "CWE-89", "description": "Injection through ORM query builders via operator injection or raw query manipulation.", "impact": "Data extraction, authentication bypass through ORM filter manipulation.", "remediation": "1. Use ORM built-in parameter binding\n2. Avoid raw queries with user input\n3. Validate filter operators\n4. Use field-level whitelists"},

        # XSS Advanced
        "blind_xss": {"title": "Blind Cross-Site Scripting", "severity": "high", "cwe_id": "CWE-79", "description": "XSS payload stored and executed in backend/admin context not visible to the attacker.", "impact": "Admin session hijacking, backend system compromise, persistent access to admin panels.", "remediation": "1. Sanitize all input regardless of display context\n2. Implement CSP on admin panels\n3. Use HttpOnly cookies\n4. Review admin panel input rendering"},
        "mutation_xss": {"title": "Mutation XSS (mXSS)", "severity": "high", "cwe_id": "CWE-79", "description": "XSS via browser HTML mutation where sanitized HTML changes to executable form after DOM processing.", "impact": "Bypasses HTML sanitizers, executes JavaScript through browser parsing quirks.", "remediation": "1. Update DOMPurify/sanitizers\n2. Use textContent not innerHTML\n3. Avoid innerHTML re-serialization\n4. Test with multiple browsers"},

        # File Access Advanced
        "arbitrary_file_read": {"title": "Arbitrary File Read", "severity": "high", "cwe_id": "CWE-22", "description": "Reading arbitrary files via API or download endpoints outside intended scope.", "impact": "Access to credentials, configuration, source code, private keys.", "remediation": "1. Validate file paths against whitelist\n2. Use chroot/jail\n3. Implement proper access controls\n4. Avoid user input in file paths"},
        "arbitrary_file_delete": {"title": "Arbitrary File Delete", "severity": "high", "cwe_id": "CWE-22", "description": "Deleting arbitrary files through path traversal in delete operations.", "impact": "Denial of service, security bypass by deleting .htaccess/config, data destruction.", "remediation": "1. Validate file paths strictly\n2. Use indirect references\n3. Implement soft-delete\n4. Restrict delete operations to specific directories"},
        "zip_slip": {"title": "Zip Slip (Archive Path Traversal)", "severity": "high", "cwe_id": "CWE-22", "description": "Path traversal via crafted archive filenames writing files outside extraction directory.", "impact": "Arbitrary file write, web shell deployment, configuration overwrite.", "remediation": "1. Validate archive entry names\n2. Resolve and check extraction paths\n3. Use secure archive extraction libraries\n4. Extract to isolated directories"},

        # Auth Advanced
        "weak_password": {"title": "Weak Password Policy", "severity": "medium", "cwe_id": "CWE-521", "description": "Application accepts weak passwords that can be easily guessed or brute-forced.", "impact": "Account compromise through password guessing, credential stuffing success.", "remediation": "1. Enforce minimum 8+ character passwords\n2. Check against breached password databases\n3. Implement password strength meter\n4. Follow NIST SP 800-63B guidelines"},
        "default_credentials": {"title": "Default Credentials", "severity": "critical", "cwe_id": "CWE-798", "description": "Application or service uses default factory credentials that haven't been changed.", "impact": "Complete unauthorized access to admin or management interfaces.", "remediation": "1. Force password change on first login\n2. Remove default accounts\n3. Implement strong default password generation\n4. Regular credential audits"},
        "brute_force": {"title": "Brute Force Vulnerability", "severity": "medium", "cwe_id": "CWE-307", "description": "Login endpoint lacks rate limiting or account lockout allowing unlimited password attempts.", "impact": "Account compromise through automated password guessing.", "remediation": "1. Implement account lockout after N failures\n2. Add rate limiting per IP and per account\n3. Implement CAPTCHA after failures\n4. Use progressive delays"},
        "two_factor_bypass": {"title": "Two-Factor Authentication Bypass", "severity": "high", "cwe_id": "CWE-287", "description": "Second authentication factor can be bypassed through implementation flaws.", "impact": "Account takeover even when 2FA is enabled, defeating the purpose of MFA.", "remediation": "1. Enforce 2FA check on all authenticated routes\n2. Use server-side session state for 2FA completion\n3. Rate limit code attempts\n4. Make codes single-use with short expiry"},
        "oauth_misconfiguration": {"title": "OAuth Misconfiguration", "severity": "high", "cwe_id": "CWE-601", "description": "OAuth implementation flaws allowing redirect URI manipulation, state bypass, or token theft.", "impact": "Account takeover via stolen OAuth tokens, cross-site request forgery.", "remediation": "1. Strictly validate redirect_uri\n2. Require and validate state parameter\n3. Use PKCE for public clients\n4. Validate all OAuth scopes"},

        # Authorization Advanced
        "bfla": {"title": "Broken Function Level Authorization", "severity": "high", "cwe_id": "CWE-285", "description": "Admin API functions accessible to regular users without proper role checks.", "impact": "Privilege escalation to admin functionality, system configuration changes.", "remediation": "1. Implement role-based access control on all endpoints\n2. Deny by default\n3. Centralize authorization logic\n4. Audit all admin endpoints"},
        "mass_assignment": {"title": "Mass Assignment", "severity": "high", "cwe_id": "CWE-915", "description": "Application binds user-supplied data to internal model fields without filtering.", "impact": "Privilege escalation, data manipulation, bypassing business rules.", "remediation": "1. Use explicit field whitelists\n2. Implement DTOs for input\n3. Validate all bound fields\n4. Use strong parameter filtering"},
        "forced_browsing": {"title": "Forced Browsing / Broken Access Control", "severity": "medium", "cwe_id": "CWE-425", "description": "Direct URL access to restricted resources that should require authorization.", "impact": "Access to admin panels, sensitive files, debug interfaces, and internal tools.", "remediation": "1. Implement authentication on all protected routes\n2. Return 404 instead of 403 for sensitive paths\n3. Remove unnecessary files\n4. Use web server access controls"},

        # Client-Side Advanced
        "dom_clobbering": {"title": "DOM Clobbering", "severity": "medium", "cwe_id": "CWE-79", "description": "HTML injection that overrides JavaScript DOM properties through named elements.", "impact": "JavaScript logic bypass, potential XSS through clobbered variables.", "remediation": "1. Use strict variable declarations (const/let)\n2. Avoid global variable references\n3. Use safe DOM APIs\n4. Sanitize HTML input"},
        "postmessage_vulnerability": {"title": "postMessage Vulnerability", "severity": "medium", "cwe_id": "CWE-346", "description": "postMessage handlers that don't validate message origin allowing cross-origin data injection.", "impact": "Cross-origin data injection, XSS via injected data, sensitive data exfiltration.", "remediation": "1. Always validate event.origin\n2. Validate message data structure\n3. Use specific target origins\n4. Minimize data sent via postMessage"},
        "websocket_hijacking": {"title": "Cross-Site WebSocket Hijacking", "severity": "high", "cwe_id": "CWE-1385", "description": "WebSocket endpoints accepting connections from arbitrary origins without validation.", "impact": "Real-time data theft, message injection, session hijacking via WebSocket.", "remediation": "1. Validate Origin header on WebSocket upgrade\n2. Require authentication per-message\n3. Implement CSRF protection for handshake\n4. Use WSS (encrypted)"},
        "prototype_pollution": {"title": "Prototype Pollution", "severity": "high", "cwe_id": "CWE-1321", "description": "Injection of properties into JavaScript Object.prototype through merge/extend operations.", "impact": "Authentication bypass, RCE via gadget chains, denial of service.", "remediation": "1. Freeze Object.prototype\n2. Sanitize __proto__ and constructor keys\n3. Use Map instead of plain objects\n4. Update vulnerable libraries"},
        "css_injection": {"title": "CSS Injection", "severity": "medium", "cwe_id": "CWE-79", "description": "Injection of CSS code through user input reflected in style contexts.", "impact": "Data exfiltration via CSS selectors, UI manipulation, phishing.", "remediation": "1. Sanitize CSS properties\n2. Use CSP style-src\n3. Avoid user input in style attributes\n4. Whitelist safe CSS properties"},
        "tabnabbing": {"title": "Reverse Tabnabbing", "severity": "low", "cwe_id": "CWE-1022", "description": "Links with target=_blank without rel=noopener allowing opener tab navigation.", "impact": "Phishing via original tab replacement with fake login page.", "remediation": "1. Add rel='noopener noreferrer' to target=_blank links\n2. Use frameworks that add it automatically\n3. Audit user-generated links"},

        # Infrastructure Advanced
        "directory_listing": {"title": "Directory Listing Enabled", "severity": "low", "cwe_id": "CWE-548", "description": "Web server auto-indexing enabled exposing directory file structure.", "impact": "Exposure of file structure, sensitive files, backup files, and configuration.", "remediation": "1. Disable directory listing (Options -Indexes)\n2. Add index files to all directories\n3. Review web server configuration\n4. Use custom error pages"},
        "debug_mode": {"title": "Debug Mode Enabled", "severity": "high", "cwe_id": "CWE-489", "description": "Application running in debug/development mode in production.", "impact": "Source code exposure, interactive console access, credential disclosure.", "remediation": "1. Disable debug mode in production\n2. Use environment-specific configuration\n3. Implement custom error pages\n4. Remove debug endpoints"},
        "exposed_admin_panel": {"title": "Exposed Administration Panel", "severity": "medium", "cwe_id": "CWE-200", "description": "Admin panel accessible from public internet without IP restrictions.", "impact": "Brute force target, credential theft, administration access if default creds.", "remediation": "1. Restrict admin access by IP/VPN\n2. Use strong authentication + 2FA\n3. Change default admin paths\n4. Implement rate limiting"},
        "exposed_api_docs": {"title": "Exposed API Documentation", "severity": "low", "cwe_id": "CWE-200", "description": "API documentation (Swagger/OpenAPI/GraphQL playground) publicly accessible.", "impact": "Complete API endpoint mapping, parameter discovery, potential unauthorized access.", "remediation": "1. Disable API docs in production\n2. Require authentication for docs\n3. Disable GraphQL introspection\n4. Use API gateway access controls"},
        "insecure_cookie_flags": {"title": "Insecure Cookie Configuration", "severity": "medium", "cwe_id": "CWE-614", "description": "Session cookies missing security flags (Secure, HttpOnly, SameSite).", "impact": "Cookie theft via XSS (no HttpOnly), MITM (no Secure), CSRF (no SameSite).", "remediation": "1. Set HttpOnly on session cookies\n2. Set Secure flag on HTTPS sites\n3. Set SameSite=Lax or Strict\n4. Review all cookie configurations"},
        "http_smuggling": {"title": "HTTP Request Smuggling", "severity": "high", "cwe_id": "CWE-444", "description": "Discrepancy between front-end and back-end HTTP parsing enabling request smuggling.", "impact": "Cache poisoning, request hijacking, authentication bypass, response queue poisoning.", "remediation": "1. Use HTTP/2 end-to-end\n2. Normalize Content-Length/Transfer-Encoding\n3. Reject ambiguous requests\n4. Update proxy/server software"},
        "cache_poisoning": {"title": "Web Cache Poisoning", "severity": "high", "cwe_id": "CWE-444", "description": "Manipulation of cached responses via unkeyed inputs to serve malicious content.", "impact": "Mass XSS via cached responses, redirect poisoning, denial of service.", "remediation": "1. Include all inputs in cache key\n2. Validate unkeyed headers\n3. Use Vary header correctly\n4. Implement cache key normalization"},

        # Logic & Data
        "rate_limit_bypass": {"title": "Rate Limit Bypass", "severity": "medium", "cwe_id": "CWE-770", "description": "Rate limiting can be bypassed through header manipulation or request variation.", "impact": "Enables brute force attacks, API abuse, and denial of service.", "remediation": "1. Rate limit by authenticated user, not just IP\n2. Don't trust X-Forwarded-For for rate limiting\n3. Implement at multiple layers\n4. Use sliding window algorithms"},
        "parameter_pollution": {"title": "HTTP Parameter Pollution", "severity": "medium", "cwe_id": "CWE-235", "description": "Duplicate parameters exploit parsing differences between front-end and back-end.", "impact": "WAF bypass, logic bypass, access control circumvention.", "remediation": "1. Normalize parameters server-side\n2. Reject duplicate parameters\n3. Use consistent parsing\n4. Test with duplicate params"},
        "type_juggling": {"title": "Type Juggling / Type Coercion", "severity": "high", "cwe_id": "CWE-843", "description": "Loose type comparison exploited to bypass authentication or security checks.", "impact": "Authentication bypass, security check circumvention via type confusion.", "remediation": "1. Use strict comparison (=== in PHP/JS)\n2. Validate input types\n3. Use strong typing\n4. Hash comparison with timing-safe functions"},
        "insecure_deserialization": {"title": "Insecure Deserialization", "severity": "critical", "cwe_id": "CWE-502", "description": "Untrusted data deserialized without validation enabling code execution.", "impact": "Remote code execution, denial of service, authentication bypass.", "remediation": "1. Don't deserialize untrusted data\n2. Use JSON instead of native serialization\n3. Implement integrity checks\n4. Restrict deserialization types"},
        "subdomain_takeover": {"title": "Subdomain Takeover", "severity": "high", "cwe_id": "CWE-284", "description": "Dangling DNS records pointing to unclaimed cloud resources.", "impact": "Domain impersonation, phishing, cookie theft, authentication bypass.", "remediation": "1. Audit DNS records regularly\n2. Remove dangling CNAME records\n3. Monitor cloud resource lifecycle\n4. Use DNS monitoring tools"},
        "host_header_injection": {"title": "Host Header Injection", "severity": "medium", "cwe_id": "CWE-644", "description": "Host header value used in URL generation enabling poisoning attacks.", "impact": "Password reset poisoning, cache poisoning, SSRF via Host header.", "remediation": "1. Validate Host against allowed values\n2. Use absolute URLs from configuration\n3. Don't use Host header for URL generation\n4. Implement ALLOWED_HOSTS"},
        "timing_attack": {"title": "Timing Attack", "severity": "medium", "cwe_id": "CWE-208", "description": "Response time variations leak information about valid usernames or secret values.", "impact": "Username enumeration, token/password character extraction.", "remediation": "1. Use constant-time comparison for secrets\n2. Normalize response times\n3. Add random delays\n4. Use same code path for valid/invalid input"},
        "improper_error_handling": {"title": "Improper Error Handling", "severity": "low", "cwe_id": "CWE-209", "description": "Verbose error messages disclosing internal information in production.", "impact": "Source path disclosure, database details, technology stack exposure aiding further attacks.", "remediation": "1. Use custom error pages in production\n2. Log errors server-side only\n3. Return generic error messages\n4. Disable debug/stack trace output"},
        "sensitive_data_exposure": {"title": "Sensitive Data Exposure", "severity": "high", "cwe_id": "CWE-200", "description": "Sensitive data (PII, credentials, tokens) exposed in responses, URLs, or storage.", "impact": "Identity theft, account compromise, regulatory violations (GDPR, HIPAA).", "remediation": "1. Minimize data in API responses\n2. Encrypt sensitive data at rest/transit\n3. Remove sensitive data from URLs\n4. Implement data classification"},
        "information_disclosure": {"title": "Information Disclosure", "severity": "low", "cwe_id": "CWE-200", "description": "Unintended exposure of internal details: versions, paths, technology stack.", "impact": "Aids further attacks with technology-specific exploits and internal knowledge.", "remediation": "1. Remove version headers\n2. Disable directory listing\n3. Remove HTML comments\n4. Secure .git and config files"},
        "api_key_exposure": {"title": "API Key Exposure", "severity": "high", "cwe_id": "CWE-798", "description": "API keys or secrets hardcoded in client-side code or public files.", "impact": "Unauthorized API access, financial impact, data breach via exposed keys.", "remediation": "1. Use environment variables for secrets\n2. Implement key rotation\n3. Use backend proxy for API calls\n4. Monitor key usage for anomalies"},
        "source_code_disclosure": {"title": "Source Code Disclosure", "severity": "high", "cwe_id": "CWE-540", "description": "Application source code accessible through misconfigured servers, backups, or VCS exposure.", "impact": "White-box attack surface, credential discovery, vulnerability identification.", "remediation": "1. Block .git, .svn access\n2. Remove source maps in production\n3. Delete backup files\n4. Configure web server to block sensitive extensions"},
        "backup_file_exposure": {"title": "Backup File Exposure", "severity": "high", "cwe_id": "CWE-530", "description": "Backup files, database dumps, or archives accessible from web server.", "impact": "Full source code access, database contents including credentials.", "remediation": "1. Store backups outside web root\n2. Remove old backup files\n3. Block backup extensions in web server\n4. Encrypt backup files"},
        "version_disclosure": {"title": "Software Version Disclosure", "severity": "low", "cwe_id": "CWE-200", "description": "Specific software versions exposed enabling targeted CVE exploitation.", "impact": "Targeted exploitation of known vulnerabilities for the specific version.", "remediation": "1. Remove version from headers\n2. Update software regularly\n3. Remove version-disclosing files\n4. Customize error pages"},

        # Crypto & Supply
        "weak_encryption": {"title": "Weak Encryption Algorithm", "severity": "medium", "cwe_id": "CWE-327", "description": "Use of weak/deprecated encryption algorithms (DES, RC4, ECB mode).", "impact": "Data decryption, MITM attacks, breaking confidentiality protections.", "remediation": "1. Use AES-256-GCM or ChaCha20\n2. Disable weak cipher suites\n3. Use TLS 1.2+ only\n4. Regular cryptographic review"},
        "weak_hashing": {"title": "Weak Hashing Algorithm", "severity": "medium", "cwe_id": "CWE-328", "description": "Use of weak hash algorithms (MD5, SHA1) for security-critical purposes.", "impact": "Password cracking, hash collision attacks, integrity bypass.", "remediation": "1. Use bcrypt/scrypt/argon2 for passwords\n2. Use SHA-256+ for integrity\n3. Always use salts\n4. Implement key stretching"},
        "weak_random": {"title": "Weak Random Number Generation", "severity": "medium", "cwe_id": "CWE-330", "description": "Predictable random numbers used for security tokens or session IDs.", "impact": "Token prediction, session hijacking, CSRF token bypass.", "remediation": "1. Use cryptographic PRNG (secrets module, SecureRandom)\n2. Avoid Math.random() for security\n3. Use sufficient entropy\n4. Regular token rotation"},
        "cleartext_transmission": {"title": "Cleartext Transmission of Sensitive Data", "severity": "medium", "cwe_id": "CWE-319", "description": "Sensitive data transmitted over unencrypted HTTP connections.", "impact": "Credential theft via MITM, session hijacking, data exposure.", "remediation": "1. Enforce HTTPS everywhere\n2. Implement HSTS with preload\n3. Redirect HTTP to HTTPS\n4. Set Secure flag on cookies"},
        "vulnerable_dependency": {"title": "Vulnerable Third-Party Dependency", "severity": "varies", "cwe_id": "CWE-1104", "description": "Third-party library with known CVEs in use.", "impact": "Depends on specific CVE - from XSS to RCE.", "remediation": "1. Regular dependency updates\n2. Use automated vulnerability scanning\n3. Monitor CVE advisories\n4. Implement SCA in CI/CD"},
        "outdated_component": {"title": "Outdated Software Component", "severity": "medium", "cwe_id": "CWE-1104", "description": "Significantly outdated CMS, framework, or server with multiple known CVEs.", "impact": "Multiple exploitable vulnerabilities, targeted attacks.", "remediation": "1. Update to latest stable version\n2. Enable automatic security updates\n3. Monitor end-of-life announcements\n4. Implement patch management"},
        "insecure_cdn": {"title": "Insecure CDN Resource Loading", "severity": "low", "cwe_id": "CWE-829", "description": "External scripts loaded without Subresource Integrity (SRI) hashes.", "impact": "Supply chain attack via CDN compromise, mass XSS.", "remediation": "1. Add integrity= attribute to script/link tags\n2. Use crossorigin attribute\n3. Self-host critical resources\n4. Implement CSP with hash sources"},
        "container_escape": {"title": "Container Escape / Misconfiguration", "severity": "critical", "cwe_id": "CWE-250", "description": "Container running with elevated privileges or exposed host resources.", "impact": "Host system compromise, lateral movement, data access across containers.", "remediation": "1. Don't use --privileged\n2. Drop unnecessary capabilities\n3. Don't mount Docker socket\n4. Use seccomp/AppArmor profiles"},

        # Cloud & API
        "s3_bucket_misconfiguration": {"title": "S3/Cloud Storage Misconfiguration", "severity": "high", "cwe_id": "CWE-284", "description": "Cloud storage bucket with public read/write access.", "impact": "Data exposure, data tampering, hosting malicious content.", "remediation": "1. Enable S3 Block Public Access\n2. Review bucket policies\n3. Use IAM policies for access\n4. Enable access logging"},
        "cloud_metadata_exposure": {"title": "Cloud Metadata Exposure", "severity": "critical", "cwe_id": "CWE-918", "description": "Cloud instance metadata service accessible exposing credentials.", "impact": "IAM credential theft, cloud account compromise, lateral movement.", "remediation": "1. Use IMDSv2 (token-required)\n2. Block metadata endpoint in firewall\n3. Implement SSRF protection\n4. Use minimal IAM roles"},
        "serverless_misconfiguration": {"title": "Serverless Misconfiguration", "severity": "medium", "cwe_id": "CWE-284", "description": "Serverless function with excessive permissions or missing auth.", "impact": "Unauthorized function execution, environment variable exposure, privilege escalation.", "remediation": "1. Apply least privilege IAM roles\n2. Require authentication\n3. Don't expose secrets in env vars\n4. Implement function authorization"},
        "graphql_introspection": {"title": "GraphQL Introspection Enabled", "severity": "low", "cwe_id": "CWE-200", "description": "GraphQL introspection enabled in production exposing full API schema.", "impact": "Complete API mapping, discovery of sensitive types and mutations.", "remediation": "1. Disable introspection in production\n2. Use persisted queries\n3. Implement field-level authorization\n4. Use query allowlisting"},
        "graphql_dos": {"title": "GraphQL Denial of Service", "severity": "medium", "cwe_id": "CWE-400", "description": "GraphQL endpoint vulnerable to resource-exhaustion via complex/nested queries.", "impact": "Service unavailability, resource exhaustion, increased infrastructure costs.", "remediation": "1. Implement query depth limits\n2. Add query complexity analysis\n3. Set timeout on queries\n4. Use persisted/allowlisted queries"},
        "rest_api_versioning": {"title": "Insecure API Version Exposure", "severity": "low", "cwe_id": "CWE-284", "description": "Older API versions with weaker security controls still accessible.", "impact": "Bypass newer security controls via old API versions.", "remediation": "1. Deprecate and remove old API versions\n2. Apply same security to all versions\n3. Monitor old version usage\n4. Set deprecation timelines"},
        "soap_injection": {"title": "SOAP/XML Web Service Injection", "severity": "high", "cwe_id": "CWE-91", "description": "Injection in SOAP/XML web service parameters manipulating queries.", "impact": "Data extraction, XXE via SOAP, SOAP action spoofing for unauthorized operations.", "remediation": "1. Validate SOAP input\n2. Disable XML external entities\n3. Validate SOAPAction header\n4. Use WS-Security"},
        "api_rate_limiting": {"title": "Missing API Rate Limiting", "severity": "medium", "cwe_id": "CWE-770", "description": "API endpoints lacking rate limiting allowing unlimited requests.", "impact": "Brute force, scraping, DoS, API abuse at scale.", "remediation": "1. Implement rate limiting per user/IP\n2. Return 429 with Retry-After\n3. Use API gateway throttling\n4. Implement sliding window algorithm"},
        "excessive_data_exposure": {"title": "Excessive Data Exposure", "severity": "medium", "cwe_id": "CWE-213", "description": "APIs returning more data than the client needs, including sensitive fields.", "impact": "Exposure of sensitive fields (password hashes, tokens, PII) to clients.", "remediation": "1. Use response DTOs/serializers\n2. Implement field-level filtering\n3. Apply least-data principle\n4. Separate admin and user endpoints"}
    }

    # Tester class mappings (100 types)
    TESTER_CLASSES = {
        # Injection (10 original + 11 advanced)
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
        "ldap_injection": LdapInjectionTester,
        "xpath_injection": XpathInjectionTester,
        "graphql_injection": GraphqlInjectionTester,
        "crlf_injection": CrlfInjectionTester,
        "header_injection": HeaderInjectionTester,
        "email_injection": EmailInjectionTester,
        "expression_language_injection": ELInjectionTester,
        "log_injection": LogInjectionTester,
        "html_injection": HtmlInjectionTester,
        "csv_injection": CsvInjectionTester,
        "orm_injection": OrmInjectionTester,

        # XSS Advanced
        "blind_xss": XSSStoredTester,  # Similar detection pattern
        "mutation_xss": XSSReflectedTester,  # Similar detection pattern

        # File Access (5 original + 3 new)
        "lfi": LFITester,
        "rfi": RFITester,
        "path_traversal": PathTraversalTester,
        "xxe": XXETester,
        "file_upload": FileUploadTester,
        "arbitrary_file_read": ArbitraryFileReadTester,
        "arbitrary_file_delete": ArbitraryFileDeleteTester,
        "zip_slip": ZipSlipTester,

        # Request Forgery (3 original + 2 new)
        "ssrf": SSRFTester,
        "ssrf_cloud": SSRFTester,
        "csrf": CSRFTester,
        "cors_misconfig": CORSTester,
        "graphql_introspection": GraphqlIntrospectionTester,
        "graphql_dos": GraphqlDosTester,

        # Auth (3 original + 5 new)
        "auth_bypass": AuthBypassTester,
        "jwt_manipulation": JWTManipulationTester,
        "session_fixation": SessionFixationTester,
        "weak_password": WeakPasswordTester,
        "default_credentials": DefaultCredentialsTester,
        "brute_force": AuthBypassTester,  # Similar pattern
        "two_factor_bypass": TwoFactorBypassTester,
        "oauth_misconfiguration": OauthMisconfigTester,

        # Authorization (3 original + 3 new)
        "idor": IDORTester,
        "bola": BOLATester,
        "privilege_escalation": PrivilegeEscalationTester,
        "bfla": BflaTester,
        "mass_assignment": MassAssignmentTester,
        "forced_browsing": ForcedBrowsingTester,

        # Client-Side (3 original + 6 new)
        "clickjacking": ClickjackingTester,
        "open_redirect": OpenRedirectTester,
        "dom_clobbering": DomClobberingTester,
        "postmessage_vulnerability": PostMessageVulnTester,
        "websocket_hijacking": WebsocketHijackTester,
        "prototype_pollution": PrototypePollutionTester,
        "css_injection": CssInjectionTester,
        "tabnabbing": TabnabbingTester,

        # Infrastructure (3 original + 7 new)
        "security_headers": SecurityHeadersTester,
        "ssl_issues": SSLTester,
        "http_methods": HTTPMethodsTester,
        "directory_listing": DirectoryListingTester,
        "debug_mode": DebugModeTester,
        "exposed_admin_panel": ExposedAdminPanelTester,
        "exposed_api_docs": ExposedApiDocsTester,
        "insecure_cookie_flags": InsecureCookieFlagsTester,
        "http_smuggling": HttpSmugglingTester,
        "cache_poisoning": CachePoisoningTester,

        # Logic (9 types)
        "race_condition": RaceConditionTester,
        "business_logic": BusinessLogicTester,
        "rate_limit_bypass": RateLimitBypassTester,
        "parameter_pollution": ParameterPollutionTester,
        "type_juggling": TypeJugglingTester,
        "timing_attack": TimingAttackTester,
        "host_header_injection": HostHeaderInjectionTester,
        "insecure_deserialization": BaseTester,  # AI-driven
        "subdomain_takeover": SubdomainTakeoverTester,
        "improper_error_handling": BaseTester,  # AI-driven

        # Data Exposure (6 types)
        "sensitive_data_exposure": SensitiveDataExposureTester,
        "information_disclosure": InformationDisclosureTester,
        "api_key_exposure": ApiKeyExposureTester,
        "source_code_disclosure": SourceCodeDisclosureTester,
        "backup_file_exposure": BackupFileExposureTester,
        "version_disclosure": VersionDisclosureTester,

        # Crypto & Supply (8 types - mostly inspection/AI-driven)
        "weak_encryption": BaseTester,
        "weak_hashing": BaseTester,
        "weak_random": BaseTester,
        "cleartext_transmission": BaseTester,
        "vulnerable_dependency": VulnerableDependencyTester,
        "outdated_component": VulnerableDependencyTester,
        "insecure_cdn": BaseTester,
        "container_escape": ContainerEscapeTester,

        # Cloud & API (7 types)
        "s3_bucket_misconfiguration": S3BucketMisconfigTester,
        "cloud_metadata_exposure": CloudMetadataExposureTester,
        "serverless_misconfiguration": ServerlessMisconfigTester,
        "rest_api_versioning": BaseTester,  # AI-driven
        "soap_injection": BaseTester,  # AI-driven
        "api_rate_limiting": RateLimitBypassTester,
        "excessive_data_exposure": SensitiveDataExposureTester,
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
