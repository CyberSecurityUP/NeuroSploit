"""
NeuroSploit v3 - Settings API Endpoints
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, text
from pydantic import BaseModel

from backend.db.database import get_db, engine
from backend.models import Scan, Target, Endpoint, Vulnerability, VulnerabilityTest, Report

router = APIRouter()


class SettingsUpdate(BaseModel):
    """Settings update schema"""
    llm_provider: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    max_concurrent_scans: Optional[int] = None
    aggressive_mode: Optional[bool] = None
    default_scan_type: Optional[str] = None
    recon_enabled_by_default: Optional[bool] = None


class SettingsResponse(BaseModel):
    """Settings response schema"""
    llm_provider: str = "claude"
    has_anthropic_key: bool = False
    has_openai_key: bool = False
    max_concurrent_scans: int = 3
    aggressive_mode: bool = False
    default_scan_type: str = "full"
    recon_enabled_by_default: bool = True


# In-memory settings storage (in production, use database or config file)
_settings = {
    "llm_provider": "claude",
    "anthropic_api_key": "",
    "openai_api_key": "",
    "max_concurrent_scans": 3,
    "aggressive_mode": False,
    "default_scan_type": "full",
    "recon_enabled_by_default": True
}


@router.get("", response_model=SettingsResponse)
async def get_settings():
    """Get current settings"""
    return SettingsResponse(
        llm_provider=_settings["llm_provider"],
        has_anthropic_key=bool(_settings["anthropic_api_key"]),
        has_openai_key=bool(_settings["openai_api_key"]),
        max_concurrent_scans=_settings["max_concurrent_scans"],
        aggressive_mode=_settings["aggressive_mode"],
        default_scan_type=_settings["default_scan_type"],
        recon_enabled_by_default=_settings["recon_enabled_by_default"]
    )


@router.put("", response_model=SettingsResponse)
async def update_settings(settings_data: SettingsUpdate):
    """Update settings"""
    if settings_data.llm_provider is not None:
        _settings["llm_provider"] = settings_data.llm_provider

    if settings_data.anthropic_api_key is not None:
        _settings["anthropic_api_key"] = settings_data.anthropic_api_key
        # Also update environment variable for LLM calls
        import os
        if settings_data.anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = settings_data.anthropic_api_key

    if settings_data.openai_api_key is not None:
        _settings["openai_api_key"] = settings_data.openai_api_key
        import os
        if settings_data.openai_api_key:
            os.environ["OPENAI_API_KEY"] = settings_data.openai_api_key

    if settings_data.max_concurrent_scans is not None:
        _settings["max_concurrent_scans"] = settings_data.max_concurrent_scans

    if settings_data.aggressive_mode is not None:
        _settings["aggressive_mode"] = settings_data.aggressive_mode

    if settings_data.default_scan_type is not None:
        _settings["default_scan_type"] = settings_data.default_scan_type

    if settings_data.recon_enabled_by_default is not None:
        _settings["recon_enabled_by_default"] = settings_data.recon_enabled_by_default

    return await get_settings()


@router.post("/clear-database")
async def clear_database(db: AsyncSession = Depends(get_db)):
    """Clear all data from the database (reset to fresh state)"""
    try:
        # Delete in correct order to respect foreign key constraints
        await db.execute(delete(VulnerabilityTest))
        await db.execute(delete(Vulnerability))
        await db.execute(delete(Endpoint))
        await db.execute(delete(Report))
        await db.execute(delete(Target))
        await db.execute(delete(Scan))
        await db.commit()

        return {
            "message": "Database cleared successfully",
            "status": "success"
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to clear database: {str(e)}")


@router.get("/stats")
async def get_database_stats(db: AsyncSession = Depends(get_db)):
    """Get database statistics"""
    from sqlalchemy import func

    scans_count = (await db.execute(select(func.count()).select_from(Scan))).scalar() or 0
    vulns_count = (await db.execute(select(func.count()).select_from(Vulnerability))).scalar() or 0
    endpoints_count = (await db.execute(select(func.count()).select_from(Endpoint))).scalar() or 0
    reports_count = (await db.execute(select(func.count()).select_from(Report))).scalar() or 0

    return {
        "scans": scans_count,
        "vulnerabilities": vulns_count,
        "endpoints": endpoints_count,
        "reports": reports_count
    }


@router.get("/tools")
async def get_installed_tools():
    """Check which security tools are installed"""
    import asyncio
    import shutil

    # Complete list of 40+ tools
    tools = {
        "recon": [
            "subfinder", "amass", "assetfinder", "chaos", "uncover",
            "dnsx", "massdns", "puredns", "cero", "tlsx", "cdncheck"
        ],
        "web_discovery": [
            "httpx", "httprobe", "katana", "gospider", "hakrawler",
            "gau", "waybackurls", "cariddi", "getJS", "gowitness"
        ],
        "fuzzing": [
            "ffuf", "gobuster", "dirb", "dirsearch", "wfuzz", "arjun", "paramspider"
        ],
        "vulnerability_scanning": [
            "nuclei", "nikto", "sqlmap", "xsstrike", "dalfox", "crlfuzz"
        ],
        "port_scanning": [
            "nmap", "naabu", "rustscan"
        ],
        "utilities": [
            "gf", "qsreplace", "unfurl", "anew", "uro", "jq"
        ],
        "tech_detection": [
            "whatweb", "wafw00f"
        ],
        "exploitation": [
            "hydra", "medusa", "john", "hashcat"
        ],
        "network": [
            "curl", "wget", "dig", "whois"
        ]
    }

    results = {}
    total_installed = 0
    total_tools = 0

    for category, tool_list in tools.items():
        results[category] = {}
        for tool in tool_list:
            total_tools += 1
            # Check if tool exists in PATH
            is_installed = shutil.which(tool) is not None
            results[category][tool] = is_installed
            if is_installed:
                total_installed += 1

    return {
        "tools": results,
        "summary": {
            "total": total_tools,
            "installed": total_installed,
            "missing": total_tools - total_installed,
            "percentage": round((total_installed / total_tools) * 100, 1)
        }
    }
