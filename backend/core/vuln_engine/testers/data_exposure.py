"""
NeuroSploit v3 - Data Exposure Vulnerability Testers

Testers for sensitive data exposure, information disclosure, API key exposure,
source code disclosure, backup file exposure, and version disclosure.
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class SensitiveDataExposureTester(BaseTester):
    """Tester for Sensitive Data Exposure (PII leakage)"""

    def __init__(self):
        super().__init__()
        self.name = "sensitive_data_exposure"
        self.pii_patterns = [
            # SSN (US)
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
            # Credit card numbers (Visa, MC, Amex, Discover)
            (r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "Visa card number"),
            (r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "MasterCard number"),
            (r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b", "Amex card number"),
            (r"\b6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "Discover card number"),
            # Email addresses in bulk (10+ suggests a data leak)
            (r"[\w.+-]+@[\w-]+\.[\w.-]+", "email address"),
            # Phone numbers (US format)
            (r"\b\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b", "phone number"),
            # Passport numbers
            (r"\b[A-Z]\d{8}\b", "passport number pattern"),
            # Private keys
            (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private key"),
            # Password hashes
            (r"\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}", "bcrypt hash"),
            (r"\b[a-f0-9]{32}\b", "MD5 hash"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for PII patterns in response"""
        if response_status >= 400:
            return False, 0.0, None

        findings = []

        for pattern, description in self.pii_patterns:
            matches = re.findall(pattern, response_body)
            if matches:
                # Private keys and password hashes are always significant
                if "private key" in description:
                    return True, 0.95, f"Sensitive data exposure: {description} found in response"
                if "bcrypt hash" in description:
                    return True, 0.9, f"Sensitive data exposure: {description} found in response"

                # For patterns like emails, phone numbers - check for bulk exposure
                if description in ["email address", "phone number"]:
                    if len(matches) >= 5:
                        findings.append(f"{len(matches)} {description}s")
                elif description == "MD5 hash":
                    if len(matches) >= 3:
                        findings.append(f"{len(matches)} {description}es")
                else:
                    findings.append(f"{description} ({matches[0][:20]}...)")

        if findings:
            confidence = min(0.9, 0.6 + 0.1 * len(findings))
            return True, confidence, f"Sensitive data exposure: {', '.join(findings[:3])}"

        return False, 0.0, None


class InformationDisclosureTester(BaseTester):
    """Tester for Information Disclosure vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "information_disclosure"
        self.disclosure_patterns = [
            # Server version headers
            (r"Server:\s*(.+)", "header", "Server version"),
            (r"X-Powered-By:\s*(.+)", "header", "Technology stack"),
            (r"X-AspNet-Version:\s*(.+)", "header", "ASP.NET version"),
            (r"X-AspNetMvc-Version:\s*(.+)", "header", "ASP.NET MVC version"),
        ]
        self.body_patterns = [
            # Path disclosure
            (r"(?:/var/www|/home/\w+|/srv/|/opt/\w+|C:\\inetpub|C:\\Users\\\w+)[/\\]\S+", "Internal path"),
            # Stack traces
            (r"Traceback \(most recent call last\)", "Python stack trace"),
            (r"at \w+\.\w+\([\w.]+:\d+\)", "Java stack trace"),
            (r"(?:Fatal error|Warning|Notice):\s+.*\sin\s+/\S+\s+on line \d+", "PHP error with path"),
            (r"Microsoft \.NET Framework Version:\d+", ".NET framework version"),
            # Database info
            (r"(?:MySQL|PostgreSQL|Oracle|MSSQL)\s+\d+\.\d+", "Database version"),
            # Debug info
            (r"(?:DEBUG|TRACE)\s*=\s*(?:true|True|1)", "Debug mode enabled"),
            (r"(?:SECRET_KEY|DB_PASSWORD|API_SECRET)\s*[=:]\s*\S+", "Secret in debug output"),
            # Internal IPs
            (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "Internal IP address"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for information disclosure in headers and body"""
        findings = []

        # Check headers
        headers_str = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
        for pattern, location, description in self.disclosure_patterns:
            match = re.search(pattern, headers_str, re.IGNORECASE)
            if match:
                findings.append(f"{description}: {match.group(1)[:50]}")

        # Check body
        for pattern, description in self.body_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                findings.append(f"{description}: {match.group(0)[:80]}")

        if findings:
            # Stack traces and secrets are higher severity
            high_severity = any("stack trace" in f.lower() or "secret" in f.lower() or "debug" in f.lower() for f in findings)
            confidence = 0.85 if high_severity else 0.7
            return True, confidence, f"Information disclosure: {'; '.join(findings[:3])}"

        return False, 0.0, None


class ApiKeyExposureTester(BaseTester):
    """Tester for API Key Exposure vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "api_key_exposure"
        self.key_patterns = [
            # AWS
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}", "AWS Secret Key"),
            # Google
            (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
            (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth Token"),
            # Stripe
            (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key"),
            (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Publishable Key"),
            (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key"),
            # GitHub
            (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token"),
            # Slack
            (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "Slack Token"),
            # Twilio
            (r"SK[0-9a-fA-F]{32}", "Twilio API Key"),
            # SendGrid
            (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API Key"),
            # Heroku
            (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "Heroku API Key / UUID"),
            # Generic patterns
            (r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", "Generic API Key"),
            (r"(?:access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-.]{20,})['\"]?", "Access Token"),
            # Bearer tokens in JS
            (r"['\"]Bearer\s+[A-Za-z0-9_\-\.]{20,}['\"]", "Hardcoded Bearer Token"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for API key patterns in response"""
        findings = []

        for pattern, description in self.key_patterns:
            matches = re.findall(pattern, response_body)
            if matches:
                # Skip UUIDs unless in specific context (too many false positives)
                if "UUID" in description:
                    continue
                # Redact the actual key in evidence
                sample = matches[0] if isinstance(matches[0], str) else matches[0]
                redacted = sample[:8] + "..." + sample[-4:] if len(sample) > 12 else sample[:4] + "..."
                findings.append(f"{description} ({redacted})")

        if findings:
            # AWS/Stripe secret keys are critical
            critical = any(k in f for f in findings for k in ["AWS Secret", "Stripe Secret", "Secret Key"])
            confidence = 0.95 if critical else 0.85
            return True, confidence, f"API key exposure: {', '.join(findings[:3])}"

        return False, 0.0, None


class SourceCodeDisclosureTester(BaseTester):
    """Tester for Source Code Disclosure vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "source_code_disclosure"
        self.source_indicators = [
            # Git
            (r"\[core\]\s*\n\s*repositoryformatversion", "Git config exposed"),
            (r"\[remote \"origin\"\]", "Git config with remote"),
            (r"ref: refs/heads/", "Git HEAD reference exposed"),
            # Source maps
            (r"\"version\"\s*:\s*3,\s*\"sources\"", "JavaScript source map"),
            (r"//[#@]\s*sourceMappingURL=", "Source map reference"),
            # PHP source
            (r"<\?php\s", "PHP source code"),
            (r"<\?=", "PHP short tag source"),
            # Python source
            (r"^(?:import |from \w+ import |def \w+\(|class \w+)", "Python source code"),
            # Java/JSP
            (r"<%@?\s*page\s+", "JSP source code"),
            (r"package\s+\w+\.\w+;", "Java package declaration"),
            # Environment files
            (r"(?:DB_PASSWORD|SECRET_KEY|DATABASE_URL)\s*=\s*\S+", "Environment file content"),
            # Composer/package files with private repos
            (r"\"require\".*\"private/", "Private package reference"),
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for source code indicators in response"""
        if response_status >= 400:
            return False, 0.0, None

        for pattern, description in self.source_indicators:
            match = re.search(pattern, response_body, re.MULTILINE)
            if match:
                # Git config is high confidence
                if "Git" in description:
                    return True, 0.95, f"Source code disclosure: {description}"
                # Environment file is critical
                if "Environment" in description:
                    return True, 0.95, f"Source code disclosure: {description}"
                # Source maps lower confidence (often intentional)
                if "source map" in description.lower():
                    return True, 0.6, f"Source code disclosure: {description}"
                return True, 0.8, f"Source code disclosure: {description}"

        # Check for common source file access patterns
        source_paths = [".git/config", ".env", ".htaccess", "web.config",
                        "wp-config.php", "config.php", "settings.py"]
        for path in source_paths:
            if path in payload and response_status == 200 and len(response_body) > 50:
                return True, 0.7, f"Source code disclosure: {path} accessible"

        return False, 0.0, None


class BackupFileExposureTester(BaseTester):
    """Tester for Backup File Exposure vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "backup_file_exposure"
        self.file_signatures = [
            # SQL dumps
            (r"-- MySQL dump \d+", "MySQL database dump"),
            (r"-- PostgreSQL database dump", "PostgreSQL database dump"),
            (r"CREATE TABLE\s+[`\"]\w+[`\"]", "SQL DDL statements"),
            (r"INSERT INTO\s+[`\"]\w+[`\"]", "SQL data dump"),
            # Archive signatures (in text responses)
            (r"PK\x03\x04", "ZIP archive"),
            # Tar
            (r"ustar\s", "TAR archive"),
            # Config backups
            (r"<\?xml.*<configuration>", "XML configuration backup"),
            (r"server\s*\{[^}]*listen\s+\d+", "Nginx config backup"),
            (r"<VirtualHost\s+", "Apache config backup"),
        ]
        self.backup_extensions = [
            ".bak", ".backup", ".old", ".orig", ".save",
            ".swp", ".swo", ".tmp", ".temp", ".copy",
            "~", ".sql", ".tar.gz", ".zip", ".dump",
        ]

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for backup file content in response"""
        if response_status >= 400:
            return False, 0.0, None

        # Check file signatures
        for pattern, description in self.file_signatures:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.9, f"Backup file exposure: {description} detected"

        # Check if backup extension in request returned content
        for ext in self.backup_extensions:
            if ext in payload and response_status == 200 and len(response_body) > 100:
                headers_lower = {k.lower(): v for k, v in response_headers.items()}
                content_type = headers_lower.get("content-type", "").lower()
                # Non-HTML responses to backup file requests are suspicious
                if "text/html" not in content_type:
                    return True, 0.75, f"Backup file exposure: {ext} file served ({content_type})"
                # HTML response but contains code-like content
                if re.search(r"(?:function |class |import |require\(|define\()", response_body):
                    return True, 0.7, f"Backup file exposure: {ext} file contains source code"

        return False, 0.0, None


class VersionDisclosureTester(BaseTester):
    """Tester for Version Disclosure mapping to known CVEs"""

    def __init__(self):
        super().__init__()
        self.name = "version_disclosure"
        # Software versions with known critical CVEs
        self.vulnerable_versions = {
            r"Apache/2\.4\.49\b": "CVE-2021-41773 (path traversal)",
            r"Apache/2\.4\.50\b": "CVE-2021-42013 (path traversal bypass)",
            r"nginx/1\.(?:[0-9]|1[0-7])\.\d+": "Potential nginx < 1.18 vulnerabilities",
            r"PHP/(?:5\.\d|7\.[0-3])\.\d+": "Outdated PHP version with known CVEs",
            r"OpenSSL/1\.0\.\d": "OpenSSL 1.0.x - multiple known CVEs",
            r"jQuery/(?:1\.\d|2\.\d|3\.[0-4])\.\d+": "jQuery < 3.5 - XSS via htmlPrefilter",
            r"WordPress/(?:[1-4]\.\d|5\.[0-7])": "Outdated WordPress version",
            r"Drupal/(?:[1-7]\.\d|8\.[0-5])": "Outdated Drupal version",
            r"Rails/(?:[1-4]\.\d|5\.[01])": "Outdated Rails version",
            r"Spring Framework/(?:[1-4]\.\d|5\.[0-2])": "Outdated Spring version",
            r"Express/(?:[1-3]\.\d|4\.(?:1[0-6]))": "Outdated Express.js version",
            r"Django/(?:1\.\d|2\.[01]|3\.0)": "Outdated Django version",
            r"Log4j.(?:2\.(?:0|1[0-4])\.\d)": "CVE-2021-44228 (Log4Shell)",
            r"Tomcat/(?:[1-8]\.\d|9\.[0-3]\d\.\d)": "Potentially outdated Tomcat",
            r"IIS/(?:[1-9]\.0|10\.0)": "IIS version disclosure",
        }

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for version strings mapping to known CVEs"""
        # Combine headers and body for scanning
        headers_str = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
        full_text = headers_str + "\n" + response_body

        findings = []

        for pattern, cve_info in self.vulnerable_versions.items():
            match = re.search(pattern, full_text, re.IGNORECASE)
            if match:
                version_str = match.group(0)
                findings.append(f"{version_str} - {cve_info}")

        if findings:
            # Known CVEs are high confidence
            has_cve = any("CVE-" in f for f in findings)
            confidence = 0.9 if has_cve else 0.7
            return True, confidence, f"Version disclosure: {'; '.join(findings[:3])}"

        # Generic version disclosure in Server header
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        server = headers_lower.get("server", "")
        if re.search(r"/\d+\.\d+", server):
            return True, 0.5, f"Version disclosure in Server header: {server}"

        return False, 0.0, None
