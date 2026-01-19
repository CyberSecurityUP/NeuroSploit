"""
NeuroSploit v3 - Vulnerabilities API Endpoints
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.database import get_db
from backend.models import Vulnerability
from backend.schemas.vulnerability import VulnerabilityResponse, VulnerabilityTypeInfo

router = APIRouter()

# Vulnerability type definitions
VULNERABILITY_TYPES = {
    "injection": {
        "xss_reflected": {
            "name": "Reflected XSS",
            "description": "Cross-site scripting via user input reflected in response",
            "severity_range": "medium-high",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-79"]
        },
        "xss_stored": {
            "name": "Stored XSS",
            "description": "Cross-site scripting stored in application database",
            "severity_range": "high-critical",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-79"]
        },
        "xss_dom": {
            "name": "DOM-based XSS",
            "description": "Cross-site scripting via DOM manipulation",
            "severity_range": "medium-high",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-79"]
        },
        "sqli_error": {
            "name": "Error-based SQL Injection",
            "description": "SQL injection detected via error messages",
            "severity_range": "high-critical",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-89"]
        },
        "sqli_union": {
            "name": "Union-based SQL Injection",
            "description": "SQL injection exploitable via UNION queries",
            "severity_range": "critical",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-89"]
        },
        "sqli_blind": {
            "name": "Blind SQL Injection",
            "description": "SQL injection without visible output",
            "severity_range": "high-critical",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-89"]
        },
        "sqli_time": {
            "name": "Time-based SQL Injection",
            "description": "SQL injection detected via response time",
            "severity_range": "high-critical",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-89"]
        },
        "command_injection": {
            "name": "Command Injection",
            "description": "OS command injection vulnerability",
            "severity_range": "critical",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-78"]
        },
        "ssti": {
            "name": "Server-Side Template Injection",
            "description": "Template injection allowing code execution",
            "severity_range": "high-critical",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-94"]
        },
        "ldap_injection": {
            "name": "LDAP Injection",
            "description": "LDAP query injection",
            "severity_range": "high",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-90"]
        },
        "xpath_injection": {
            "name": "XPath Injection",
            "description": "XPath query injection",
            "severity_range": "medium-high",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-643"]
        },
        "nosql_injection": {
            "name": "NoSQL Injection",
            "description": "NoSQL database injection",
            "severity_range": "high-critical",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-943"]
        },
        "header_injection": {
            "name": "HTTP Header Injection",
            "description": "Injection into HTTP headers",
            "severity_range": "medium-high",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-113"]
        },
        "crlf_injection": {
            "name": "CRLF Injection",
            "description": "Carriage return line feed injection",
            "severity_range": "medium",
            "owasp_category": "A03:2021",
            "cwe_ids": ["CWE-93"]
        }
    },
    "file_access": {
        "lfi": {
            "name": "Local File Inclusion",
            "description": "Include local files via path manipulation",
            "severity_range": "high-critical",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-98"]
        },
        "rfi": {
            "name": "Remote File Inclusion",
            "description": "Include remote files for code execution",
            "severity_range": "critical",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-98"]
        },
        "path_traversal": {
            "name": "Path Traversal",
            "description": "Access files outside web root",
            "severity_range": "high",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-22"]
        },
        "file_upload": {
            "name": "Arbitrary File Upload",
            "description": "Upload malicious files",
            "severity_range": "high-critical",
            "owasp_category": "A04:2021",
            "cwe_ids": ["CWE-434"]
        },
        "xxe": {
            "name": "XML External Entity",
            "description": "XXE injection vulnerability",
            "severity_range": "high-critical",
            "owasp_category": "A05:2021",
            "cwe_ids": ["CWE-611"]
        }
    },
    "request_forgery": {
        "ssrf": {
            "name": "Server-Side Request Forgery",
            "description": "Forge requests from the server",
            "severity_range": "high-critical",
            "owasp_category": "A10:2021",
            "cwe_ids": ["CWE-918"]
        },
        "ssrf_cloud": {
            "name": "SSRF to Cloud Metadata",
            "description": "SSRF accessing cloud provider metadata",
            "severity_range": "critical",
            "owasp_category": "A10:2021",
            "cwe_ids": ["CWE-918"]
        },
        "csrf": {
            "name": "Cross-Site Request Forgery",
            "description": "Forge requests as authenticated user",
            "severity_range": "medium-high",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-352"]
        }
    },
    "authentication": {
        "auth_bypass": {
            "name": "Authentication Bypass",
            "description": "Bypass authentication mechanisms",
            "severity_range": "critical",
            "owasp_category": "A07:2021",
            "cwe_ids": ["CWE-287"]
        },
        "session_fixation": {
            "name": "Session Fixation",
            "description": "Force known session ID on user",
            "severity_range": "high",
            "owasp_category": "A07:2021",
            "cwe_ids": ["CWE-384"]
        },
        "jwt_manipulation": {
            "name": "JWT Token Manipulation",
            "description": "Manipulate JWT tokens for auth bypass",
            "severity_range": "high-critical",
            "owasp_category": "A07:2021",
            "cwe_ids": ["CWE-347"]
        },
        "weak_password_policy": {
            "name": "Weak Password Policy",
            "description": "Application accepts weak passwords",
            "severity_range": "medium",
            "owasp_category": "A07:2021",
            "cwe_ids": ["CWE-521"]
        }
    },
    "authorization": {
        "idor": {
            "name": "Insecure Direct Object Reference",
            "description": "Access objects without proper authorization",
            "severity_range": "high",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-639"]
        },
        "bola": {
            "name": "Broken Object Level Authorization",
            "description": "API-level object authorization bypass",
            "severity_range": "high",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-639"]
        },
        "privilege_escalation": {
            "name": "Privilege Escalation",
            "description": "Escalate to higher privilege level",
            "severity_range": "critical",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-269"]
        }
    },
    "api_security": {
        "rate_limiting": {
            "name": "Missing Rate Limiting",
            "description": "No rate limiting on sensitive endpoints",
            "severity_range": "medium",
            "owasp_category": "A04:2021",
            "cwe_ids": ["CWE-770"]
        },
        "mass_assignment": {
            "name": "Mass Assignment",
            "description": "Modify unintended object properties",
            "severity_range": "high",
            "owasp_category": "A04:2021",
            "cwe_ids": ["CWE-915"]
        },
        "excessive_data": {
            "name": "Excessive Data Exposure",
            "description": "API returns more data than needed",
            "severity_range": "medium-high",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-200"]
        },
        "graphql_introspection": {
            "name": "GraphQL Introspection Enabled",
            "description": "GraphQL schema exposed via introspection",
            "severity_range": "low-medium",
            "owasp_category": "A05:2021",
            "cwe_ids": ["CWE-200"]
        }
    },
    "client_side": {
        "cors_misconfig": {
            "name": "CORS Misconfiguration",
            "description": "Permissive CORS policy",
            "severity_range": "medium-high",
            "owasp_category": "A05:2021",
            "cwe_ids": ["CWE-942"]
        },
        "clickjacking": {
            "name": "Clickjacking",
            "description": "Page can be framed for clickjacking",
            "severity_range": "medium",
            "owasp_category": "A05:2021",
            "cwe_ids": ["CWE-1021"]
        },
        "open_redirect": {
            "name": "Open Redirect",
            "description": "Redirect to arbitrary URLs",
            "severity_range": "low-medium",
            "owasp_category": "A01:2021",
            "cwe_ids": ["CWE-601"]
        }
    },
    "information_disclosure": {
        "error_disclosure": {
            "name": "Error Message Disclosure",
            "description": "Detailed error messages exposed",
            "severity_range": "low-medium",
            "owasp_category": "A05:2021",
            "cwe_ids": ["CWE-209"]
        },
        "sensitive_data": {
            "name": "Sensitive Data Exposure",
            "description": "Sensitive information exposed",
            "severity_range": "medium-high",
            "owasp_category": "A02:2021",
            "cwe_ids": ["CWE-200"]
        },
        "debug_endpoints": {
            "name": "Debug Endpoints Exposed",
            "description": "Debug/admin endpoints accessible",
            "severity_range": "high",
            "owasp_category": "A05:2021",
            "cwe_ids": ["CWE-489"]
        }
    },
    "infrastructure": {
        "security_headers": {
            "name": "Missing Security Headers",
            "description": "Important security headers not set",
            "severity_range": "low-medium",
            "owasp_category": "A05:2021",
            "cwe_ids": ["CWE-693"]
        },
        "ssl_issues": {
            "name": "SSL/TLS Issues",
            "description": "Weak SSL/TLS configuration",
            "severity_range": "medium",
            "owasp_category": "A02:2021",
            "cwe_ids": ["CWE-326"]
        },
        "http_methods": {
            "name": "Dangerous HTTP Methods",
            "description": "Dangerous HTTP methods enabled",
            "severity_range": "low-medium",
            "owasp_category": "A05:2021",
            "cwe_ids": ["CWE-749"]
        }
    },
    "logic_flaws": {
        "race_condition": {
            "name": "Race Condition",
            "description": "Exploitable race condition",
            "severity_range": "medium-high",
            "owasp_category": "A04:2021",
            "cwe_ids": ["CWE-362"]
        },
        "business_logic": {
            "name": "Business Logic Flaw",
            "description": "Exploitable business logic error",
            "severity_range": "varies",
            "owasp_category": "A04:2021",
            "cwe_ids": ["CWE-840"]
        }
    }
}


@router.get("/types")
async def get_vulnerability_types():
    """Get all vulnerability types organized by category"""
    return VULNERABILITY_TYPES


@router.get("/types/{category}")
async def get_vulnerability_types_by_category(category: str):
    """Get vulnerability types for a specific category"""
    if category not in VULNERABILITY_TYPES:
        raise HTTPException(status_code=404, detail=f"Category '{category}' not found")

    return VULNERABILITY_TYPES[category]


@router.get("/types/{category}/{vuln_type}", response_model=VulnerabilityTypeInfo)
async def get_vulnerability_type_info(category: str, vuln_type: str):
    """Get detailed info for a specific vulnerability type"""
    if category not in VULNERABILITY_TYPES:
        raise HTTPException(status_code=404, detail=f"Category '{category}' not found")

    if vuln_type not in VULNERABILITY_TYPES[category]:
        raise HTTPException(status_code=404, detail=f"Type '{vuln_type}' not found in category '{category}'")

    info = VULNERABILITY_TYPES[category][vuln_type]
    return VulnerabilityTypeInfo(
        type=vuln_type,
        category=category,
        **info
    )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific vulnerability by ID"""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return VulnerabilityResponse(**vuln.to_dict())
