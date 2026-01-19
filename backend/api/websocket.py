"""
NeuroSploit v3 - WebSocket Manager
"""
from typing import Dict, List, Optional
from fastapi import WebSocket
import json
import asyncio


class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""

    def __init__(self):
        # scan_id -> list of websocket connections
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept a WebSocket connection and register it for a scan"""
        await websocket.accept()
        async with self._lock:
            if scan_id not in self.active_connections:
                self.active_connections[scan_id] = []
            self.active_connections[scan_id].append(websocket)
        print(f"WebSocket connected for scan: {scan_id}")

    def disconnect(self, websocket: WebSocket, scan_id: str):
        """Remove a WebSocket connection"""
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        print(f"WebSocket disconnected for scan: {scan_id}")

    async def send_to_scan(self, scan_id: str, message: dict):
        """Send a message to all connections watching a specific scan"""
        if scan_id not in self.active_connections:
            return

        dead_connections = []
        for connection in self.active_connections[scan_id]:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead_connections.append(connection)

        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(conn, scan_id)

    async def broadcast_scan_started(self, scan_id: str):
        """Notify that a scan has started"""
        await self.send_to_scan(scan_id, {
            "type": "scan_started",
            "scan_id": scan_id
        })

    async def broadcast_phase_change(self, scan_id: str, phase: str):
        """Notify phase change (recon, testing, reporting)"""
        await self.send_to_scan(scan_id, {
            "type": "phase_change",
            "scan_id": scan_id,
            "phase": phase
        })

    async def broadcast_progress(self, scan_id: str, progress: int, message: Optional[str] = None):
        """Send progress update"""
        await self.send_to_scan(scan_id, {
            "type": "progress_update",
            "scan_id": scan_id,
            "progress": progress,
            "message": message
        })

    async def broadcast_endpoint_found(self, scan_id: str, endpoint: dict):
        """Notify a new endpoint was discovered"""
        await self.send_to_scan(scan_id, {
            "type": "endpoint_found",
            "scan_id": scan_id,
            "endpoint": endpoint
        })

    async def broadcast_path_crawled(self, scan_id: str, path: str, status: int):
        """Notify a path was crawled"""
        await self.send_to_scan(scan_id, {
            "type": "path_crawled",
            "scan_id": scan_id,
            "path": path,
            "status": status
        })

    async def broadcast_url_discovered(self, scan_id: str, url: str):
        """Notify a URL was discovered"""
        await self.send_to_scan(scan_id, {
            "type": "url_discovered",
            "scan_id": scan_id,
            "url": url
        })

    async def broadcast_test_started(self, scan_id: str, vuln_type: str, endpoint: str):
        """Notify a vulnerability test has started"""
        await self.send_to_scan(scan_id, {
            "type": "test_started",
            "scan_id": scan_id,
            "vulnerability_type": vuln_type,
            "endpoint": endpoint
        })

    async def broadcast_test_completed(self, scan_id: str, vuln_type: str, endpoint: str, is_vulnerable: bool):
        """Notify a vulnerability test has completed"""
        await self.send_to_scan(scan_id, {
            "type": "test_completed",
            "scan_id": scan_id,
            "vulnerability_type": vuln_type,
            "endpoint": endpoint,
            "is_vulnerable": is_vulnerable
        })

    async def broadcast_vulnerability_found(self, scan_id: str, vulnerability: dict):
        """Notify a vulnerability was found"""
        await self.send_to_scan(scan_id, {
            "type": "vuln_found",
            "scan_id": scan_id,
            "vulnerability": vulnerability
        })

    async def broadcast_log(self, scan_id: str, level: str, message: str):
        """Send a log message"""
        await self.send_to_scan(scan_id, {
            "type": "log_message",
            "scan_id": scan_id,
            "level": level,
            "message": message
        })

    async def broadcast_scan_completed(self, scan_id: str, summary: dict):
        """Notify that a scan has completed"""
        await self.send_to_scan(scan_id, {
            "type": "scan_completed",
            "scan_id": scan_id,
            "summary": summary
        })

    async def broadcast_error(self, scan_id: str, error: str):
        """Notify an error occurred"""
        await self.send_to_scan(scan_id, {
            "type": "error",
            "scan_id": scan_id,
            "error": error
        })


# Global instance
manager = ConnectionManager()
