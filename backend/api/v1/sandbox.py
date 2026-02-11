"""
NeuroSploit v3 - Sandbox Container Management API

Real-time monitoring and management of per-scan Kali Linux containers.
"""

from datetime import datetime
from fastapi import APIRouter, HTTPException

router = APIRouter()


def _docker_available() -> bool:
    try:
        import docker
        docker.from_env().ping()
        return True
    except Exception:
        return False


@router.get("/")
async def list_sandboxes():
    """List all sandbox containers with pool status."""
    try:
        from core.container_pool import get_pool
        pool = get_pool()
    except Exception as e:
        return {
            "pool": {
                "active": 0,
                "max_concurrent": 0,
                "image": "neurosploit-kali:latest",
                "container_ttl_minutes": 60,
                "docker_available": _docker_available(),
            },
            "containers": [],
            "error": str(e),
        }

    sandboxes = pool.list_sandboxes()
    now = datetime.utcnow()

    containers = []
    for info in sandboxes.values():
        created = info.get("created_at")
        uptime = 0.0
        if created:
            try:
                dt = datetime.fromisoformat(created)
                uptime = (now - dt).total_seconds()
            except Exception:
                pass
        containers.append({
            **info,
            "uptime_seconds": uptime,
        })

    return {
        "pool": {
            "active": pool.active_count,
            "max_concurrent": pool.max_concurrent,
            "image": pool.image,
            "container_ttl_minutes": int(pool.container_ttl.total_seconds() / 60),
            "docker_available": _docker_available(),
        },
        "containers": containers,
    }


@router.get("/{scan_id}")
async def get_sandbox(scan_id: str):
    """Get health check for a specific sandbox container."""
    try:
        from core.container_pool import get_pool
        pool = get_pool()
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))

    sandboxes = pool.list_sandboxes()
    if scan_id not in sandboxes:
        raise HTTPException(status_code=404, detail=f"No sandbox for scan {scan_id}")

    sb = pool._sandboxes.get(scan_id)
    if not sb:
        raise HTTPException(status_code=404, detail=f"Sandbox instance not found")

    health = await sb.health_check()
    return health


@router.delete("/{scan_id}")
async def destroy_sandbox(scan_id: str):
    """Destroy a specific sandbox container."""
    try:
        from core.container_pool import get_pool
        pool = get_pool()
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))

    sandboxes = pool.list_sandboxes()
    if scan_id not in sandboxes:
        raise HTTPException(status_code=404, detail=f"No sandbox for scan {scan_id}")

    await pool.destroy(scan_id)
    return {"message": f"Sandbox for scan {scan_id} destroyed", "scan_id": scan_id}


@router.post("/cleanup")
async def cleanup_expired():
    """Remove containers that have exceeded their TTL."""
    try:
        from core.container_pool import get_pool
        pool = get_pool()
        await pool.cleanup_expired()
        return {"message": "Expired containers cleaned up"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/cleanup-orphans")
async def cleanup_orphans():
    """Remove orphan containers not tracked by the pool."""
    try:
        from core.container_pool import get_pool
        pool = get_pool()
        await pool.cleanup_orphans()
        return {"message": "Orphan containers cleaned up"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))
