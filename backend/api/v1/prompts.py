"""
NeuroSploit v3 - Prompts API Endpoints
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.database import get_db
from backend.models import Prompt
from backend.schemas.prompt import (
    PromptCreate, PromptUpdate, PromptResponse, PromptParse, PromptParseResult, PromptPreset
)
from backend.core.prompt_engine.parser import PromptParser

router = APIRouter()

# Preset prompts
PRESET_PROMPTS = [
    {
        "id": "full_pentest",
        "name": "Full Penetration Test",
        "description": "Comprehensive security assessment covering all vulnerability categories",
        "category": "pentest",
        "content": """Perform a comprehensive penetration test on the target application.

Test for ALL vulnerability categories:
- Injection vulnerabilities (XSS, SQL Injection, Command Injection, LDAP, XPath, Template Injection)
- Authentication flaws (Broken auth, session management, JWT issues, OAuth flaws)
- Authorization issues (IDOR, BOLA, privilege escalation, access control bypass)
- File handling vulnerabilities (LFI, RFI, path traversal, file upload, XXE)
- Request forgery (SSRF, CSRF)
- API security issues (rate limiting, mass assignment, excessive data exposure)
- Client-side vulnerabilities (CORS misconfig, clickjacking, open redirect)
- Information disclosure (error messages, stack traces, sensitive data exposure)
- Infrastructure issues (security headers, SSL/TLS, HTTP methods)
- Business logic flaws (race conditions, workflow bypass)

Use thorough testing with multiple payloads and bypass techniques.
Generate detailed PoC for each vulnerability found.
Provide remediation recommendations."""
    },
    {
        "id": "owasp_top10",
        "name": "OWASP Top 10",
        "description": "Test for OWASP Top 10 2021 vulnerabilities",
        "category": "compliance",
        "content": """Test for OWASP Top 10 2021 vulnerabilities:

A01:2021 - Broken Access Control
- IDOR, privilege escalation, access control bypass, CORS misconfig

A02:2021 - Cryptographic Failures
- Sensitive data exposure, weak encryption, cleartext transmission

A03:2021 - Injection
- SQL injection, XSS, command injection, LDAP injection

A04:2021 - Insecure Design
- Business logic flaws, missing security controls

A05:2021 - Security Misconfiguration
- Default configs, unnecessary features, missing headers

A06:2021 - Vulnerable Components
- Outdated libraries, known CVEs

A07:2021 - Identification and Authentication Failures
- Weak passwords, session fixation, credential stuffing

A08:2021 - Software and Data Integrity Failures
- Insecure deserialization, CI/CD vulnerabilities

A09:2021 - Security Logging and Monitoring Failures
- Missing audit logs, insufficient monitoring

A10:2021 - Server-Side Request Forgery (SSRF)
- Internal network access, cloud metadata exposure"""
    },
    {
        "id": "api_security",
        "name": "API Security Testing",
        "description": "Focused testing for REST and GraphQL APIs",
        "category": "api",
        "content": """Perform API security testing:

Authentication & Authorization:
- Test JWT implementation (algorithm confusion, signature bypass, claim manipulation)
- OAuth/OIDC flow testing
- API key exposure and validation
- Rate limiting bypass
- BOLA/IDOR on all endpoints

Input Validation:
- SQL injection on API parameters
- NoSQL injection
- Command injection
- Parameter pollution
- Mass assignment vulnerabilities

Data Exposure:
- Excessive data exposure in responses
- Sensitive data in error messages
- Information disclosure in headers
- Debug endpoints exposure

GraphQL Specific (if applicable):
- Introspection enabled
- Query depth attacks
- Batching attacks
- Field suggestion exploitation

API Abuse:
- Rate limiting effectiveness
- Resource exhaustion
- Denial of service vectors"""
    },
    {
        "id": "bug_bounty",
        "name": "Bug Bounty Hunter",
        "description": "Focus on high-impact, bounty-worthy vulnerabilities",
        "category": "bug_bounty",
        "content": """Hunt for high-impact vulnerabilities suitable for bug bounty:

Priority 1 - Critical Impact:
- Remote Code Execution (RCE)
- SQL Injection leading to data breach
- Authentication bypass
- SSRF to internal services/cloud metadata
- Privilege escalation to admin

Priority 2 - High Impact:
- Stored XSS
- IDOR on sensitive resources
- Account takeover vectors
- Payment/billing manipulation
- PII exposure

Priority 3 - Medium Impact:
- Reflected XSS
- CSRF on sensitive actions
- Information disclosure
- Rate limiting bypass
- Open redirects (if exploitable)

Look for:
- Unique attack chains
- Business logic flaws
- Edge cases and race conditions
- Bypass techniques for existing security controls

Document with clear PoC and impact assessment."""
    },
    {
        "id": "quick_scan",
        "name": "Quick Security Scan",
        "description": "Fast scan for common vulnerabilities",
        "category": "quick",
        "content": """Perform a quick security scan for common vulnerabilities:

- Reflected XSS on input parameters
- Basic SQL injection testing
- Directory traversal/LFI
- Security headers check
- SSL/TLS configuration
- Common misconfigurations
- Information disclosure

Use minimal payloads for speed.
Focus on quick wins and obvious issues."""
    },
    {
        "id": "auth_testing",
        "name": "Authentication Testing",
        "description": "Focus on authentication and session management",
        "category": "auth",
        "content": """Test authentication and session management:

Login Functionality:
- Username enumeration
- Password brute force protection
- Account lockout bypass
- Credential stuffing protection
- SQL injection in login

Session Management:
- Session token entropy
- Session fixation
- Session timeout
- Cookie security flags (HttpOnly, Secure, SameSite)
- Session invalidation on logout

Password Reset:
- Token predictability
- Token expiration
- Account enumeration
- Host header injection

Multi-Factor Authentication:
- MFA bypass techniques
- Backup codes weakness
- Rate limiting on OTP

OAuth/SSO:
- State parameter validation
- Redirect URI manipulation
- Token leakage"""
    }
]


@router.get("/presets", response_model=List[PromptPreset])
async def get_preset_prompts():
    """Get list of preset prompts"""
    return [
        PromptPreset(
            id=p["id"],
            name=p["name"],
            description=p["description"],
            category=p["category"],
            vulnerability_count=len(p["content"].split("\n"))
        )
        for p in PRESET_PROMPTS
    ]


@router.get("/presets/{preset_id}")
async def get_preset_prompt(preset_id: str):
    """Get a specific preset prompt by ID"""
    for preset in PRESET_PROMPTS:
        if preset["id"] == preset_id:
            return preset
    raise HTTPException(status_code=404, detail="Preset not found")


@router.post("/parse", response_model=PromptParseResult)
async def parse_prompt(prompt_data: PromptParse):
    """Parse a prompt to extract vulnerability types and testing scope"""
    parser = PromptParser()
    result = await parser.parse(prompt_data.content)
    return result


@router.get("", response_model=List[PromptResponse])
async def list_prompts(
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all custom prompts"""
    query = select(Prompt).where(Prompt.is_preset == False)
    if category:
        query = query.where(Prompt.category == category)
    query = query.order_by(Prompt.created_at.desc())

    result = await db.execute(query)
    prompts = result.scalars().all()

    return [PromptResponse(**p.to_dict()) for p in prompts]


@router.post("", response_model=PromptResponse)
async def create_prompt(prompt_data: PromptCreate, db: AsyncSession = Depends(get_db)):
    """Create a custom prompt"""
    # Parse vulnerabilities from content
    parser = PromptParser()
    parsed = await parser.parse(prompt_data.content)

    prompt = Prompt(
        name=prompt_data.name,
        description=prompt_data.description,
        content=prompt_data.content,
        category=prompt_data.category,
        is_preset=False,
        parsed_vulnerabilities=[v.dict() for v in parsed.vulnerabilities_to_test]
    )
    db.add(prompt)
    await db.commit()
    await db.refresh(prompt)

    return PromptResponse(**prompt.to_dict())


@router.get("/{prompt_id}", response_model=PromptResponse)
async def get_prompt(prompt_id: str, db: AsyncSession = Depends(get_db)):
    """Get a prompt by ID"""
    result = await db.execute(select(Prompt).where(Prompt.id == prompt_id))
    prompt = result.scalar_one_or_none()

    if not prompt:
        raise HTTPException(status_code=404, detail="Prompt not found")

    return PromptResponse(**prompt.to_dict())


@router.put("/{prompt_id}", response_model=PromptResponse)
async def update_prompt(
    prompt_id: str,
    prompt_data: PromptUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update a prompt"""
    result = await db.execute(select(Prompt).where(Prompt.id == prompt_id))
    prompt = result.scalar_one_or_none()

    if not prompt:
        raise HTTPException(status_code=404, detail="Prompt not found")

    if prompt.is_preset:
        raise HTTPException(status_code=400, detail="Cannot modify preset prompts")

    if prompt_data.name is not None:
        prompt.name = prompt_data.name
    if prompt_data.description is not None:
        prompt.description = prompt_data.description
    if prompt_data.content is not None:
        prompt.content = prompt_data.content
        # Re-parse vulnerabilities
        parser = PromptParser()
        parsed = await parser.parse(prompt_data.content)
        prompt.parsed_vulnerabilities = [v.dict() for v in parsed.vulnerabilities_to_test]
    if prompt_data.category is not None:
        prompt.category = prompt_data.category

    await db.commit()
    await db.refresh(prompt)

    return PromptResponse(**prompt.to_dict())


@router.delete("/{prompt_id}")
async def delete_prompt(prompt_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a prompt"""
    result = await db.execute(select(Prompt).where(Prompt.id == prompt_id))
    prompt = result.scalar_one_or_none()

    if not prompt:
        raise HTTPException(status_code=404, detail="Prompt not found")

    if prompt.is_preset:
        raise HTTPException(status_code=400, detail="Cannot delete preset prompts")

    await db.delete(prompt)
    await db.commit()

    return {"message": "Prompt deleted"}


@router.post("/upload")
async def upload_prompt(file: UploadFile = File(...)):
    """Upload a prompt file (.md or .txt)"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    ext = "." + file.filename.split(".")[-1].lower() if "." in file.filename else ""
    if ext not in {".md", ".txt"}:
        raise HTTPException(status_code=400, detail="Invalid file type. Use .md or .txt")

    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Unable to decode file")

    # Parse the prompt
    parser = PromptParser()
    parsed = await parser.parse(text)

    return {
        "filename": file.filename,
        "content": text,
        "parsed": parsed.dict()
    }
