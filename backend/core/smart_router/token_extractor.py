"""
NeuroSploit v3 - CLI Token Extractor

READ-ONLY extraction of OAuth/API tokens from 8 CLI tools.
Never modifies any CLI tool's files or state.
"""

import json
import logging
import os
import platform
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ExtractedToken:
    provider_id: str
    credential_type: str  # "oauth" | "api_key"
    token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[float] = None
    label: str = ""


class TokenExtractor:
    """Extracts tokens from CLI tools installed on the system."""

    EXTRACTORS = [
        "claude_code", "codex_cli", "cursor",
        "copilot", "iflow", "qwen_code", "kiro",
    ]

    def detect(self, provider_id: str) -> Optional[ExtractedToken]:
        """Detect a token for a specific provider."""
        method = getattr(self, f"_extract_{provider_id}", None)
        if not method:
            return None
        try:
            return method()
        except Exception as e:
            logger.debug(f"TokenExtractor: Failed to extract {provider_id}: {e}")
            return None

    def detect_all(self) -> List[ExtractedToken]:
        """Scan all known CLI tools and return found tokens."""
        tokens = []
        for pid in self.EXTRACTORS:
            result = self.detect(pid)
            if result:
                tokens.append(result)
                logger.info(f"TokenExtractor: Found {pid} token")
        return tokens

    # ── Individual Extractors ────────────────────────────────

    def _extract_claude_code(self) -> Optional[ExtractedToken]:
        """Claude Code: macOS Keychain or ~/.claude/.credentials.json"""
        is_mac = platform.system() == "Darwin"

        if is_mac:
            token = self._read_macos_keychain("Claude Code-credentials")
            if token:
                # Parse the JSON credential blob
                try:
                    cred = json.loads(token)
                    access_token = cred.get("claudeAiOauth", {}).get("accessToken")
                    refresh = cred.get("claudeAiOauth", {}).get("refreshToken")
                    expires = cred.get("claudeAiOauth", {}).get("expiresAt")
                    if access_token:
                        return ExtractedToken(
                            provider_id="claude_code",
                            credential_type="oauth",
                            token=access_token,
                            refresh_token=refresh,
                            expires_at=expires / 1000.0 if expires else None,
                            label="Claude Code (Keychain)",
                        )
                except (json.JSONDecodeError, AttributeError):
                    pass

        # Linux fallback: ~/.claude/.credentials.json
        creds_path = Path.home() / ".claude" / ".credentials.json"
        if creds_path.exists():
            try:
                data = json.loads(creds_path.read_text())
                access_token = data.get("claudeAiOauth", {}).get("accessToken")
                refresh = data.get("claudeAiOauth", {}).get("refreshToken")
                expires = data.get("claudeAiOauth", {}).get("expiresAt")
                if access_token:
                    return ExtractedToken(
                        provider_id="claude_code",
                        credential_type="oauth",
                        token=access_token,
                        refresh_token=refresh,
                        expires_at=expires / 1000.0 if expires else None,
                        label="Claude Code (credentials file)",
                    )
            except Exception:
                pass
        return None

    def _extract_codex_cli(self) -> Optional[ExtractedToken]:
        """OpenAI Codex CLI: ~/.codex/auth.json"""
        auth_path = Path.home() / ".codex" / "auth.json"
        if not auth_path.exists():
            return None
        try:
            data = json.loads(auth_path.read_text())
            # Codex uses OAuth2 PKCE
            access_token = data.get("access_token") or data.get("token")
            refresh = data.get("refresh_token")
            expires = data.get("expires_at")
            if access_token:
                return ExtractedToken(
                    provider_id="codex_cli",
                    credential_type="oauth",
                    token=access_token,
                    refresh_token=refresh,
                    expires_at=expires,
                    label="Codex CLI",
                )
        except Exception:
            pass
        return None

    def _extract_cursor(self) -> Optional[ExtractedToken]:
        """Cursor: SQLite state.vscdb database"""
        is_mac = platform.system() == "Darwin"
        if is_mac:
            base = Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage"
        else:
            base = Path.home() / ".config" / "Cursor" / "User" / "globalStorage"

        db_path = base / "state.vscdb"
        if not db_path.exists():
            return None

        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path), timeout=1)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM ItemTable WHERE key = ?",
                ("cursorAuth/accessToken",)
            )
            row = cursor.fetchone()
            conn.close()
            if row and row[0]:
                return ExtractedToken(
                    provider_id="cursor",
                    credential_type="oauth",
                    token=row[0],
                    label="Cursor IDE",
                )
        except Exception:
            pass
        return None

    def _extract_copilot(self) -> Optional[ExtractedToken]:
        """GitHub Copilot: ~/.config/gh/hosts.yml"""
        hosts_path = Path.home() / ".config" / "gh" / "hosts.yml"
        if not hosts_path.exists():
            return None
        try:
            content = hosts_path.read_text()
            # Simple YAML parsing for oauth_token
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("oauth_token:"):
                    token = line.split(":", 1)[1].strip()
                    if token:
                        return ExtractedToken(
                            provider_id="copilot",
                            credential_type="oauth",
                            token=token,
                            label="GitHub Copilot (gh CLI)",
                        )
        except Exception:
            pass
        return None

    def _extract_iflow(self) -> Optional[ExtractedToken]:
        """iFlow AI: ~/.iflow/settings.json"""
        settings_path = Path.home() / ".iflow" / "settings.json"
        if not settings_path.exists():
            return None
        try:
            data = json.loads(settings_path.read_text())
            api_key = data.get("apiKey") or data.get("api_key")
            if api_key:
                return ExtractedToken(
                    provider_id="iflow",
                    credential_type="api_key",
                    token=api_key,
                    label="iFlow AI",
                )
        except Exception:
            pass
        return None

    def _extract_qwen_code(self) -> Optional[ExtractedToken]:
        """Qwen Code: ~/.qwen/oauth_creds.json"""
        creds_path = Path.home() / ".qwen" / "oauth_creds.json"
        if not creds_path.exists():
            return None
        try:
            data = json.loads(creds_path.read_text())
            access_token = data.get("access_token")
            refresh = data.get("refresh_token")
            expires = data.get("expires_at")
            if access_token:
                return ExtractedToken(
                    provider_id="qwen_code",
                    credential_type="oauth",
                    token=access_token,
                    refresh_token=refresh,
                    expires_at=expires,
                    label="Qwen Code",
                )
        except Exception:
            pass
        return None

    def _extract_kiro(self) -> Optional[ExtractedToken]:
        """Kiro AI: SQLite data.sqlite3"""
        is_mac = platform.system() == "Darwin"
        if is_mac:
            db_path = Path.home() / "Library" / "Application Support" / "kiro-cli" / "data.sqlite3"
        else:
            db_path = Path.home() / ".local" / "share" / "kiro-cli" / "data.sqlite3"

        if not db_path.exists():
            return None

        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path), timeout=1)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM auth_kv WHERE key = ?",
                ("access_token",)
            )
            row = cursor.fetchone()

            refresh_row = None
            try:
                cursor.execute(
                    "SELECT value FROM auth_kv WHERE key = ?",
                    ("refresh_token",)
                )
                refresh_row = cursor.fetchone()
            except Exception:
                pass

            conn.close()
            if row and row[0]:
                return ExtractedToken(
                    provider_id="kiro",
                    credential_type="oauth",
                    token=row[0],
                    refresh_token=refresh_row[0] if refresh_row else None,
                    label="Kiro AI",
                )
        except Exception:
            pass
        return None

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _read_macos_keychain(service: str) -> Optional[str]:
        """Read a credential from macOS Keychain."""
        if platform.system() != "Darwin":
            return None
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-s", service, "-w"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        return None
