"""
NeuroSploit v3 - Settings API Endpoints
"""
import os
import re
from pathlib import Path
from typing import Optional, Dict
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, text
from pydantic import BaseModel

from backend.db.database import get_db, engine
from backend.models import Scan, Target, Endpoint, Vulnerability, VulnerabilityTest, Report

router = APIRouter()

# Path to .env file (project root)
ENV_FILE_PATH = Path(__file__).parent.parent.parent.parent / ".env"


def _update_env_file(updates: Dict[str, str]) -> bool:
    """
    Update key=value pairs in the .env file without breaking formatting.
    - If the key exists (even commented out), update its value
    - If the key doesn't exist, append it
    - Preserves comments and blank lines
    """
    if not ENV_FILE_PATH.exists():
        return False

    try:
        lines = ENV_FILE_PATH.read_text().splitlines()
        updated_keys = set()

        new_lines = []
        for line in lines:
            stripped = line.strip()
            matched = False

            for key, value in updates.items():
                # Match: KEY=..., # KEY=..., #KEY=...
                pattern = rf'^#?\s*{re.escape(key)}\s*='
                if re.match(pattern, stripped):
                    # Replace with uncommented key=value
                    new_lines.append(f"{key}={value}")
                    updated_keys.add(key)
                    matched = True
                    break

            if not matched:
                new_lines.append(line)

        # Append any keys that weren't found in existing file
        for key, value in updates.items():
            if key not in updated_keys:
                new_lines.append(f"{key}={value}")

        # Write back with trailing newline
        ENV_FILE_PATH.write_text("\n".join(new_lines) + "\n")
        return True
    except Exception as e:
        print(f"Warning: Failed to update .env file: {e}")
        return False


class SettingsUpdate(BaseModel):
    """Settings update schema"""
    llm_provider: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    max_concurrent_scans: Optional[int] = None
    aggressive_mode: Optional[bool] = None
    default_scan_type: Optional[str] = None
    recon_enabled_by_default: Optional[bool] = None
    enable_model_routing: Optional[bool] = None
    enable_knowledge_augmentation: Optional[bool] = None
    enable_browser_validation: Optional[bool] = None
    max_output_tokens: Optional[int] = None


class SettingsResponse(BaseModel):
    """Settings response schema"""
    llm_provider: str = "claude"
    has_anthropic_key: bool = False
    has_openai_key: bool = False
    has_openrouter_key: bool = False
    max_concurrent_scans: int = 3
    aggressive_mode: bool = False
    default_scan_type: str = "full"
    recon_enabled_by_default: bool = True
    enable_model_routing: bool = False
    enable_knowledge_augmentation: bool = False
    enable_browser_validation: bool = False
    max_output_tokens: Optional[int] = None


def _load_settings_from_env() -> dict:
    """
    Load settings from environment variables / .env file on startup.
    This ensures settings persist across server restarts and browser sessions.
    """
    from dotenv import load_dotenv
    # Re-read .env file to pick up disk-persisted values
    if ENV_FILE_PATH.exists():
        load_dotenv(ENV_FILE_PATH, override=True)

    def _env_bool(key: str, default: bool = False) -> bool:
        val = os.getenv(key, "").strip().lower()
        if val in ("true", "1", "yes"):
            return True
        if val in ("false", "0", "no"):
            return False
        return default

    def _env_int(key: str, default=None):
        val = os.getenv(key, "").strip()
        if val:
            try:
                return int(val)
            except ValueError:
                pass
        return default

    # Detect provider from which keys are set
    provider = "claude"
    if os.getenv("ANTHROPIC_API_KEY"):
        provider = "claude"
    elif os.getenv("OPENAI_API_KEY"):
        provider = "openai"
    elif os.getenv("OPENROUTER_API_KEY"):
        provider = "openrouter"

    return {
        "llm_provider": provider,
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY", ""),
        "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
        "openrouter_api_key": os.getenv("OPENROUTER_API_KEY", ""),
        "max_concurrent_scans": _env_int("MAX_CONCURRENT_SCANS", 3),
        "aggressive_mode": _env_bool("AGGRESSIVE_MODE", False),
        "default_scan_type": os.getenv("DEFAULT_SCAN_TYPE", "full"),
        "recon_enabled_by_default": _env_bool("RECON_ENABLED_BY_DEFAULT", True),
        "enable_model_routing": _env_bool("ENABLE_MODEL_ROUTING", False),
        "enable_knowledge_augmentation": _env_bool("ENABLE_KNOWLEDGE_AUGMENTATION", False),
        "enable_browser_validation": _env_bool("ENABLE_BROWSER_VALIDATION", False),
        "max_output_tokens": _env_int("MAX_OUTPUT_TOKENS", None),
    }


# Load settings from .env on module import (server start)
_settings = _load_settings_from_env()


@router.get("", response_model=SettingsResponse)
async def get_settings():
    """Get current settings"""
    import os
    return SettingsResponse(
        llm_provider=_settings["llm_provider"],
        has_anthropic_key=bool(_settings["anthropic_api_key"] or os.getenv("ANTHROPIC_API_KEY")),
        has_openai_key=bool(_settings["openai_api_key"] or os.getenv("OPENAI_API_KEY")),
        has_openrouter_key=bool(_settings["openrouter_api_key"] or os.getenv("OPENROUTER_API_KEY")),
        max_concurrent_scans=_settings["max_concurrent_scans"],
        aggressive_mode=_settings["aggressive_mode"],
        default_scan_type=_settings["default_scan_type"],
        recon_enabled_by_default=_settings["recon_enabled_by_default"],
        enable_model_routing=_settings["enable_model_routing"],
        enable_knowledge_augmentation=_settings["enable_knowledge_augmentation"],
        enable_browser_validation=_settings["enable_browser_validation"],
        max_output_tokens=_settings["max_output_tokens"]
    )


@router.put("", response_model=SettingsResponse)
async def update_settings(settings_data: SettingsUpdate):
    """Update settings - persists to memory, env vars, AND .env file"""
    env_updates: Dict[str, str] = {}

    if settings_data.llm_provider is not None:
        _settings["llm_provider"] = settings_data.llm_provider

    if settings_data.anthropic_api_key is not None:
        _settings["anthropic_api_key"] = settings_data.anthropic_api_key
        if settings_data.anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = settings_data.anthropic_api_key
            env_updates["ANTHROPIC_API_KEY"] = settings_data.anthropic_api_key

    if settings_data.openai_api_key is not None:
        _settings["openai_api_key"] = settings_data.openai_api_key
        if settings_data.openai_api_key:
            os.environ["OPENAI_API_KEY"] = settings_data.openai_api_key
            env_updates["OPENAI_API_KEY"] = settings_data.openai_api_key

    if settings_data.openrouter_api_key is not None:
        _settings["openrouter_api_key"] = settings_data.openrouter_api_key
        if settings_data.openrouter_api_key:
            os.environ["OPENROUTER_API_KEY"] = settings_data.openrouter_api_key
            env_updates["OPENROUTER_API_KEY"] = settings_data.openrouter_api_key

    if settings_data.max_concurrent_scans is not None:
        _settings["max_concurrent_scans"] = settings_data.max_concurrent_scans

    if settings_data.aggressive_mode is not None:
        _settings["aggressive_mode"] = settings_data.aggressive_mode

    if settings_data.default_scan_type is not None:
        _settings["default_scan_type"] = settings_data.default_scan_type

    if settings_data.recon_enabled_by_default is not None:
        _settings["recon_enabled_by_default"] = settings_data.recon_enabled_by_default

    if settings_data.enable_model_routing is not None:
        _settings["enable_model_routing"] = settings_data.enable_model_routing
        val = str(settings_data.enable_model_routing).lower()
        os.environ["ENABLE_MODEL_ROUTING"] = val
        env_updates["ENABLE_MODEL_ROUTING"] = val

    if settings_data.enable_knowledge_augmentation is not None:
        _settings["enable_knowledge_augmentation"] = settings_data.enable_knowledge_augmentation
        val = str(settings_data.enable_knowledge_augmentation).lower()
        os.environ["ENABLE_KNOWLEDGE_AUGMENTATION"] = val
        env_updates["ENABLE_KNOWLEDGE_AUGMENTATION"] = val

    if settings_data.enable_browser_validation is not None:
        _settings["enable_browser_validation"] = settings_data.enable_browser_validation
        val = str(settings_data.enable_browser_validation).lower()
        os.environ["ENABLE_BROWSER_VALIDATION"] = val
        env_updates["ENABLE_BROWSER_VALIDATION"] = val

    if settings_data.max_output_tokens is not None:
        _settings["max_output_tokens"] = settings_data.max_output_tokens
        if settings_data.max_output_tokens:
            os.environ["MAX_OUTPUT_TOKENS"] = str(settings_data.max_output_tokens)
            env_updates["MAX_OUTPUT_TOKENS"] = str(settings_data.max_output_tokens)

    # Persist to .env file on disk
    if env_updates:
        _update_env_file(env_updates)

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
