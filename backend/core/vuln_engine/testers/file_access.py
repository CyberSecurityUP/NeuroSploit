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
