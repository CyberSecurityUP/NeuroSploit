"""
NeuroSploit v3 - File Access Vulnerability Testers

Testers for LFI, RFI, Path Traversal, XXE, File Upload
"""
import re
from typing import Tuple, Dict, Optional
from backend.core.vuln_engine.testers.base_tester import BaseTester


class LFITester(BaseTester):
    """Tester for Local File Inclusion"""

    def __init__(self):
        super().__init__()
        self.name = "lfi"
        self.file_signatures = {
            # Linux files
            r"root:.*:0:0:": "/etc/passwd",
            r"\[boot loader\]": "Windows boot.ini",
            r"\[operating systems\]": "Windows boot.ini",
            r"# /etc/hosts": "/etc/hosts",
            r"localhost": "/etc/hosts",
            r"\[global\]": "Samba config",
            r"include.*php": "PHP config",
            # Windows files
            r"\[extensions\]": "Windows win.ini",
            r"for 16-bit app support": "Windows system.ini",
        }

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for LFI indicators"""
        for pattern, file_name in self.file_signatures.items():
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.95, f"LFI confirmed: {file_name} content detected"

        # Check for path in error messages
        path_patterns = [
            r"failed to open stream.*No such file",
            r"include\(.*\): failed to open stream",
            r"Warning.*file_get_contents",
            r"fopen\(.*\): failed"
        ]
        for pattern in path_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.6, "LFI indicator: File operation error with path"

        return False, 0.0, None


class RFITester(BaseTester):
    """Tester for Remote File Inclusion"""

    def __init__(self):
        super().__init__()
        self.name = "rfi"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for RFI indicators"""
        # Check if our remote content was included
        if "neurosploit_rfi_test" in response_body:
            return True, 0.95, "RFI confirmed: Remote content executed"

        # Check for URL-related errors
        rfi_errors = [
            r"failed to open stream: HTTP request failed",
            r"allow_url_include",
            r"URL file-access is disabled"
        ]
        for pattern in rfi_errors:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.5, f"RFI indicator: {pattern}"

        return False, 0.0, None


class PathTraversalTester(BaseTester):
    """Tester for Path Traversal"""

    def __init__(self):
        super().__init__()
        self.name = "path_traversal"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for path traversal indicators"""
        # Same as LFI essentially
        file_contents = [
            r"root:.*:0:0:",
            r"\[boot loader\]",
            r"# /etc/",
            r"127\.0\.0\.1.*localhost"
        ]
        for pattern in file_contents:
            if re.search(pattern, response_body):
                return True, 0.9, f"Path traversal successful: File content detected"

        return False, 0.0, None


class XXETester(BaseTester):
    """Tester for XML External Entity Injection"""

    def __init__(self):
        super().__init__()
        self.name = "xxe"

    def build_request(self, endpoint, payload: str) -> Tuple[str, Dict, Dict, Optional[str]]:
        """Build XXE request with XML body"""
        headers = {
            "User-Agent": "NeuroSploit/3.0",
            "Content-Type": "application/xml"
        }
        return endpoint.url, {}, headers, payload

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for XXE indicators"""
        # File content indicators
        xxe_indicators = [
            r"root:.*:0:0:",
            r"\[boot loader\]",
            r"# /etc/hosts",
            r"<!ENTITY",
        ]
        for pattern in xxe_indicators:
            if re.search(pattern, response_body):
                return True, 0.9, f"XXE confirmed: External entity processed"

        # Error indicators
        xxe_errors = [
            r"XML parsing error",
            r"External entity",
            r"DOCTYPE.*ENTITY",
            r"libxml"
        ]
        for pattern in xxe_errors:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.6, f"XXE indicator: XML error with entity reference"

        return False, 0.0, None


class FileUploadTester(BaseTester):
    """Tester for Arbitrary File Upload"""

    def __init__(self):
        super().__init__()
        self.name = "file_upload"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for file upload vulnerability indicators"""
        # Check for successful upload indicators
        if response_status in [200, 201]:
            success_indicators = [
                "uploaded successfully",
                "file saved",
                "upload complete",
                '"success"\\s*:\\s*true',
                '"status"\\s*:\\s*"ok"'
            ]
            for pattern in success_indicators:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True, 0.7, "File uploaded successfully - verify execution"

        # Check for path disclosure in response
        if re.search(r'["\']?(?:path|url|file)["\']?\s*:\s*["\'][^"\']+\.(php|asp|jsp)', response_body, re.IGNORECASE):
            return True, 0.8, "Executable file path returned - possible RCE"

        return False, 0.0, None


class ArbitraryFileReadTester(BaseTester):
    """Tester for Arbitrary File Read vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "arbitrary_file_read"
        self.sensitive_file_patterns = {
            # /etc/passwd format
            r"root:.*:0:0:": "/etc/passwd",
            r"daemon:.*:\d+:\d+:": "/etc/passwd",
            r"nobody:.*:\d+:\d+:": "/etc/passwd",
            # .env file patterns
            r"(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|APP_SECRET)\s*=": ".env file",
            r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=": ".env file (AWS credentials)",
            # SSH key headers
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----": "SSH/TLS private key",
            r"-----BEGIN CERTIFICATE-----": "TLS certificate",
            # Shadow file
            r"root:\$[0-9a-z]+\$": "/etc/shadow",
            # Config files
            r"<\?php.*\$db": "PHP config with DB credentials",
        }

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for sensitive file contents in response"""
        for pattern, file_desc in self.sensitive_file_patterns.items():
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.95, f"Arbitrary file read confirmed: {file_desc} content detected"

        # Check for base64-encoded sensitive content
        base64_pattern = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', response_body)
        for b64_match in base64_pattern[:5]:  # Check first 5 matches
            try:
                import base64
                decoded = base64.b64decode(b64_match).decode('utf-8', errors='ignore')
                if re.search(r"root:.*:0:0:", decoded) or re.search(r"-----BEGIN.*PRIVATE KEY-----", decoded):
                    return True, 0.9, "Arbitrary file read: Base64-encoded sensitive file content"
            except Exception:
                pass

        return False, 0.0, None


class ArbitraryFileDeleteTester(BaseTester):
    """Tester for Arbitrary File Delete vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "arbitrary_file_delete"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for successful file deletion indicators"""
        body_lower = response_body.lower()

        # Check for explicit deletion success messages
        delete_success_patterns = [
            r"file\s+(?:has been\s+)?(?:deleted|removed)\s+successfully",
            r"(?:deleted|removed)\s+successfully",
            r'"success"\s*:\s*true.*(?:delet|remov)',
            r'"status"\s*:\s*"(?:deleted|removed)"',
            r'"message"\s*:\s*".*(?:deleted|removed).*"',
        ]
        for pattern in delete_success_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.85, "Arbitrary file delete: Deletion success confirmed in response"

        # Check for 200/204 on DELETE request with traversal path
        traversal_indicators = ["../", "..\\", "%2e%2e", "..%2f", "..%5c"]
        has_traversal = any(t in payload.lower() for t in traversal_indicators)

        if has_traversal:
            if response_status == 204:
                return True, 0.8, "Arbitrary file delete: 204 No Content after path traversal delete"
            if response_status == 200:
                return True, 0.7, "Arbitrary file delete: 200 OK after path traversal delete request"

        # Check for file-not-found on subsequent access (context-based)
        if context.get("follow_up_status") == 404:
            return True, 0.85, "Arbitrary file delete: File not found after deletion request"

        return False, 0.0, None


class ZipSlipTester(BaseTester):
    """Tester for Zip Slip (path traversal in archive extraction)"""

    def __init__(self):
        super().__init__()
        self.name = "zip_slip"

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_headers: Dict,
        response_body: str,
        context: Dict
    ) -> Tuple[bool, float, Optional[str]]:
        """Check for path traversal in archive extraction"""
        body_lower = response_body.lower()

        # Check for traversal path acceptance in response
        traversal_patterns = [
            r"\.\./\.\./\.\./",
            r"\.\.\\\.\.\\\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e/",
        ]
        for pattern in traversal_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                # Traversal path echoed in response
                if response_status in [200, 201]:
                    return True, 0.8, "Zip Slip: Path traversal sequence accepted in archive extraction"

        # Check for successful extraction with traversal payload
        if response_status in [200, 201]:
            extraction_success = [
                r"extract(?:ed|ion)\s+(?:successful|complete)",
                r"(?:file|archive)\s+(?:uploaded|processed)\s+successfully",
                r'"extracted"\s*:\s*true',
                r'"files"\s*:\s*\[.*\.\./.*\]',
            ]
            for pattern in extraction_success:
                if re.search(pattern, response_body, re.IGNORECASE):
                    if any(t in payload for t in ["../", "..\\", "%2e%2e"]):
                        return True, 0.85, "Zip Slip: Archive with traversal paths extracted successfully"

        # Check for file written outside expected directory
        overwrite_indicators = [
            r"(?:overwr(?:ote|itten)|replaced)\s+.*(?:/etc/|/var/|/tmp/|C:\\)",
            r"(?:created|wrote)\s+.*\.\./",
        ]
        for pattern in overwrite_indicators:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, 0.9, "Zip Slip: File written outside extraction directory"

        return False, 0.0, None
