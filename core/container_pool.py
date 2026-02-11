"""
NeuroSploit v3 - Container Pool

Global coordinator for per-scan Kali Linux containers.
Tracks all running sandbox containers, enforces max concurrent limits,
handles lifecycle management and orphan cleanup.
"""

import asyncio
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger(__name__)

try:
    import docker
    from docker.errors import NotFound
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

from core.kali_sandbox import KaliSandbox


class ContainerPool:
    """Global pool managing per-scan KaliSandbox instances.

    Thread-safe. One pool per process. Enforces resource limits.
    """

    def __init__(
        self,
        image: str = "neurosploit-kali:latest",
        max_concurrent: int = 5,
        memory_limit: str = "2g",
        cpu_limit: float = 2.0,
        container_ttl_minutes: int = 60,
    ):
        self.image = image
        self.max_concurrent = max_concurrent
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.container_ttl = timedelta(minutes=container_ttl_minutes)

        self._sandboxes: Dict[str, KaliSandbox] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def from_config(cls) -> "ContainerPool":
        """Create pool from config/config.json sandbox section."""
        try:
            with open("config/config.json") as f:
                cfg = json.load(f)
            sandbox_cfg = cfg.get("sandbox", {})
            kali_cfg = sandbox_cfg.get("kali", {})
            resources = sandbox_cfg.get("resources", {})

            return cls(
                image=kali_cfg.get("image", "neurosploit-kali:latest"),
                max_concurrent=kali_cfg.get("max_concurrent", 5),
                memory_limit=resources.get("memory_limit", "2g"),
                cpu_limit=resources.get("cpu_limit", 2.0),
                container_ttl_minutes=kali_cfg.get("container_ttl_minutes", 60),
            )
        except Exception as e:
            logger.warning(f"Could not load pool config, using defaults: {e}")
            return cls()

    async def get_or_create(self, scan_id: str) -> KaliSandbox:
        """Get existing sandbox for scan_id, or create a new one.

        Raises RuntimeError if max_concurrent limit reached.
        """
        async with self._lock:
            # Return existing
            if scan_id in self._sandboxes:
                sb = self._sandboxes[scan_id]
                if sb.is_available:
                    return sb
                else:
                    del self._sandboxes[scan_id]

            # Check limit
            active = sum(1 for sb in self._sandboxes.values() if sb.is_available)
            if active >= self.max_concurrent:
                raise RuntimeError(
                    f"Max concurrent containers ({self.max_concurrent}) reached. "
                    f"Active scans: {list(self._sandboxes.keys())}"
                )

            # Create new
            sb = KaliSandbox(
                scan_id=scan_id,
                image=self.image,
                memory_limit=self.memory_limit,
                cpu_limit=self.cpu_limit,
            )
            ok, msg = await sb.initialize()
            if not ok:
                raise RuntimeError(f"Failed to create Kali sandbox: {msg}")

            self._sandboxes[scan_id] = sb
            logger.info(
                f"Pool: created container for scan {scan_id} "
                f"({active + 1}/{self.max_concurrent} active)"
            )
            return sb

    async def destroy(self, scan_id: str):
        """Stop and remove the container for a specific scan."""
        async with self._lock:
            sb = self._sandboxes.pop(scan_id, None)
        if sb:
            await sb.stop()
            logger.info(f"Pool: destroyed container for scan {scan_id}")

    async def cleanup_all(self):
        """Destroy all managed containers (shutdown hook)."""
        async with self._lock:
            scan_ids = list(self._sandboxes.keys())
        for sid in scan_ids:
            await self.destroy(sid)
        logger.info("Pool: all containers destroyed")

    async def cleanup_orphans(self):
        """Find and remove neurosploit-* containers not tracked by this pool."""
        if not HAS_DOCKER:
            return

        try:
            client = docker.from_env()
            containers = client.containers.list(
                all=True,
                filters={"label": "neurosploit.type=kali-sandbox"},
            )
            async with self._lock:
                tracked = set(self._sandboxes.keys())

            removed = 0
            for c in containers:
                scan_id = c.labels.get("neurosploit.scan_id", "")
                if scan_id not in tracked:
                    try:
                        c.stop(timeout=5)
                    except Exception:
                        pass
                    try:
                        c.remove(force=True)
                        removed += 1
                        logger.info(f"Pool: removed orphan container {c.name}")
                    except Exception:
                        pass

            if removed:
                logger.info(f"Pool: cleaned up {removed} orphan containers")
        except Exception as e:
            logger.warning(f"Pool: orphan cleanup failed: {e}")

    async def cleanup_expired(self):
        """Remove containers that have exceeded their TTL."""
        now = datetime.utcnow()
        async with self._lock:
            expired = [
                sid for sid, sb in self._sandboxes.items()
                if sb._created_at and (now - sb._created_at) > self.container_ttl
            ]
        for sid in expired:
            logger.warning(f"Pool: container for scan {sid} exceeded TTL, destroying")
            await self.destroy(sid)

    def list_sandboxes(self) -> Dict[str, Dict]:
        """List all tracked sandboxes with status."""
        result = {}
        for sid, sb in self._sandboxes.items():
            result[sid] = {
                "scan_id": sid,
                "container_name": sb.container_name,
                "available": sb.is_available,
                "installed_tools": sorted(sb._installed_tools),
                "created_at": sb._created_at.isoformat() if sb._created_at else None,
            }
        return result

    @property
    def active_count(self) -> int:
        return sum(1 for sb in self._sandboxes.values() if sb.is_available)


# ---------------------------------------------------------------------------
# Global singleton pool
# ---------------------------------------------------------------------------
_pool: Optional[ContainerPool] = None
_pool_lock = threading.Lock()


def get_pool() -> ContainerPool:
    """Get or create the global container pool."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ContainerPool.from_config()
    return _pool
