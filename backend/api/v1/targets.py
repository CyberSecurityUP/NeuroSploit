"""
NeuroSploit v3 - Targets API Endpoints
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from urllib.parse import urlparse
import re

from backend.db.database import get_db
from backend.schemas.target import TargetCreate, TargetBulkCreate, TargetValidation, TargetResponse

router = APIRouter()


def validate_url(url: str) -> TargetValidation:
    """Validate and parse a URL"""
    url = url.strip()

    if not url:
        return TargetValidation(url=url, valid=False, error="URL is empty")

    # URL pattern
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    # Try with the URL as-is
    if url_pattern.match(url):
        normalized = url
    elif url_pattern.match(f"https://{url}"):
        normalized = f"https://{url}"
    else:
        return TargetValidation(url=url, valid=False, error="Invalid URL format")

    # Parse URL
    parsed = urlparse(normalized)

    return TargetValidation(
        url=url,
        valid=True,
        normalized_url=normalized,
        hostname=parsed.hostname,
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        protocol=parsed.scheme
    )


@router.post("/validate", response_model=TargetValidation)
async def validate_target(target: TargetCreate):
    """Validate a single target URL"""
    return validate_url(target.url)


@router.post("/validate/bulk", response_model=List[TargetValidation])
async def validate_targets_bulk(targets: TargetBulkCreate):
    """Validate multiple target URLs"""
    results = []
    for url in targets.urls:
        results.append(validate_url(url))
    return results


@router.post("/upload", response_model=List[TargetValidation])
async def upload_targets(file: UploadFile = File(...)):
    """Upload a file with URLs (one per line)"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Check file extension
    allowed_extensions = {".txt", ".csv", ".lst"}
    ext = "." + file.filename.split(".")[-1].lower() if "." in file.filename else ""
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
        )

    # Read file content
    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = content.decode("latin-1")
        except Exception:
            raise HTTPException(status_code=400, detail="Unable to decode file")

    # Parse URLs (one per line, or comma-separated)
    urls = []
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle comma-separated URLs
        if "," in line and "://" in line:
            for url in line.split(","):
                url = url.strip()
                if url:
                    urls.append(url)
        else:
            urls.append(line)

    if not urls:
        raise HTTPException(status_code=400, detail="No URLs found in file")

    # Validate all URLs
    results = []
    for url in urls:
        results.append(validate_url(url))

    return results


@router.post("/parse-input", response_model=List[TargetValidation])
async def parse_target_input(input_text: str):
    """Parse target input (comma-separated or newline-separated)"""
    urls = []

    # Split by newlines first
    for line in input_text.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Then split by commas
        for url in line.split(","):
            url = url.strip()
            if url:
                urls.append(url)

    if not urls:
        raise HTTPException(status_code=400, detail="No URLs provided")

    results = []
    for url in urls:
        results.append(validate_url(url))

    return results
