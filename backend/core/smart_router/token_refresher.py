"""
NeuroSploit v3 - Token Refresher

Background asyncio task that refreshes OAuth tokens before they expire.
Checks every 5 minutes, refreshes tokens expiring within 10 minutes.
"""

import asyncio
import logging
import os
import time
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .provider_registry import ProviderRegistry

logger = logging.getLogger(__name__)

REFRESH_INTERVAL = 300  # 5 minutes
REFRESH_THRESHOLD = 600  # Refresh if expiring within 10 minutes

# Known OAuth endpoints for token refresh
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
ANTHROPIC_TOKEN_URL = "https://auth.anthropic.com/oauth/token"
OPENAI_TOKEN_URL = "https://auth0.openai.com/oauth/token"


class TokenRefresher:
    """Background task that auto-refreshes expiring OAuth tokens."""

    def __init__(self, registry: "ProviderRegistry"):
        self._registry = registry
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the background refresh loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._refresh_loop())
        logger.info("TokenRefresher: Started background refresh loop")

    async def stop(self):
        """Stop the background refresh loop."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("TokenRefresher: Stopped")

    async def _refresh_loop(self):
        """Main loop: check and refresh tokens periodically."""
        while self._running:
            try:
                await self._check_and_refresh()
            except Exception as e:
                logger.error(f"TokenRefresher: Error in refresh loop: {e}")
            await asyncio.sleep(REFRESH_INTERVAL)

    async def _check_and_refresh(self):
        """Check all accounts and refresh tokens nearing expiry."""
        now = time.time()
        for provider in self._registry.get_all_providers():
            for acct in provider.accounts.values():
                if not acct.is_active or acct.credential_type != "oauth":
                    continue
                if acct.expires_at is None:
                    continue
                if acct.expires_at - now > REFRESH_THRESHOLD:
                    continue  # Not expiring soon

                refresh_token = self._registry.get_refresh_token(acct.id)
                if not refresh_token:
                    logger.debug(
                        f"TokenRefresher: {acct.label} expiring but no refresh token"
                    )
                    continue

                logger.info(
                    f"TokenRefresher: Refreshing {acct.label} "
                    f"(expires in {int(acct.expires_at - now)}s)"
                )

                success = await self._refresh_token(
                    provider_id=provider.id,
                    account_id=acct.id,
                    refresh_token=refresh_token,
                )
                if not success:
                    logger.warning(
                        f"TokenRefresher: Failed to refresh {acct.label}"
                    )

    async def _refresh_token(
        self, provider_id: str, account_id: str, refresh_token: str
    ) -> bool:
        """Attempt to refresh a token based on provider type."""
        try:
            if provider_id in ("claude_code", "kiro"):
                return await self._refresh_anthropic(account_id, refresh_token)
            elif provider_id == "codex_cli":
                return await self._refresh_openai(account_id, refresh_token)
            else:
                logger.debug(
                    f"TokenRefresher: No refresh method for {provider_id}"
                )
                return False
        except Exception as e:
            logger.error(f"TokenRefresher: Refresh failed for {provider_id}: {e}")
            return False

    async def _refresh_anthropic(self, account_id: str, refresh_token: str) -> bool:
        """Refresh an Anthropic/Claude OAuth token."""
        try:
            import aiohttp

            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(ANTHROPIC_TOKEN_URL, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        new_token = data.get("access_token")
                        expires_in = data.get("expires_in", 3600)
                        new_refresh = data.get("refresh_token")
                        if new_token:
                            self._registry.update_credential(
                                account_id,
                                new_token,
                                time.time() + expires_in,
                            )
                            # Update refresh token if rotated
                            if new_refresh:
                                self._registry._refresh_tokens[account_id] = new_refresh
                            logger.info(f"TokenRefresher: Anthropic token refreshed")
                            return True
                    else:
                        body = await resp.text()
                        logger.warning(f"TokenRefresher: Anthropic refresh failed: {resp.status} {body[:200]}")
        except ImportError:
            logger.warning("TokenRefresher: aiohttp not available for token refresh")
        except Exception as e:
            logger.error(f"TokenRefresher: Anthropic refresh error: {e}")
        return False

    async def _refresh_openai(self, account_id: str, refresh_token: str) -> bool:
        """Refresh an OpenAI/Codex OAuth token."""
        try:
            import aiohttp

            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(OPENAI_TOKEN_URL, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        new_token = data.get("access_token")
                        expires_in = data.get("expires_in", 3600)
                        if new_token:
                            self._registry.update_credential(
                                account_id,
                                new_token,
                                time.time() + expires_in,
                            )
                            logger.info(f"TokenRefresher: OpenAI token refreshed")
                            return True
                    else:
                        body = await resp.text()
                        logger.warning(f"TokenRefresher: OpenAI refresh failed: {resp.status} {body[:200]}")
        except ImportError:
            logger.warning("TokenRefresher: aiohttp not available for token refresh")
        except Exception as e:
            logger.error(f"TokenRefresher: OpenAI refresh error: {e}")
        return False
