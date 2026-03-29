"""
NeuroSploit v3 - Smart Router

Core routing engine with 4 API format translators, tier-based failover,
round-robin load balancing, and quota tracking.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from .provider_registry import Account, Provider, ProviderRegistry

logger = logging.getLogger(__name__)


class QuotaTracker:
    """Tracks per-account quota exhaustion with automatic recovery."""

    def __init__(self):
        self._exhausted: Dict[str, float] = {}  # acct_id -> retry_after_timestamp
        self._round_robin: Dict[str, int] = {}  # provider_id -> last_index

    def record_exhausted(self, account_id: str, retry_after: int = 300):
        """Mark an account as quota-exhausted."""
        self._exhausted[account_id] = time.time() + retry_after
        logger.warning(f"QuotaTracker: {account_id} exhausted, retry after {retry_after}s")

    def is_available(self, account_id: str) -> bool:
        """Check if an account is available (not exhausted or recovered)."""
        if account_id not in self._exhausted:
            return True
        if time.time() > self._exhausted[account_id]:
            del self._exhausted[account_id]
            return True
        return False

    def next_account(self, provider_id: str, accounts: List[Account]) -> Optional[Account]:
        """Round-robin selection from available accounts."""
        available = [a for a in accounts if self.is_available(a.id)]
        if not available:
            return None
        idx = self._round_robin.get(provider_id, -1) + 1
        idx = idx % len(available)
        self._round_robin[provider_id] = idx
        return available[idx]


class SmartRouter:
    """Smart LLM router with format translation, failover, and load balancing.

    Routing priority:
    1. Preferred provider (if specified)
    2. Tier 1 providers (subscription + paid API keys)
    3. Tier 2 providers (cheap API keys)
    4. Tier 3 providers (free/local)
    """

    def __init__(self, registry: ProviderRegistry):
        self.registry = registry
        self.quota = QuotaTracker()
        self._total_requests = 0
        self._total_tokens = 0
        self._failover_count = 0
        self._last_provider: Optional[str] = None  # Last provider used
        self._last_model: Optional[str] = None  # Last model used
        self._last_account_label: Optional[str] = None  # Last account label
        self._gemini_project_id: Optional[str] = None  # Cached Gemini CLI project ID

    async def generate(
        self,
        prompt: str,
        system: str = "",
        max_tokens: int = 4096,
        preferred_provider: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
    ) -> str:
        """Route a generation request through available providers.

        Tries providers in tier order, fails over on errors.
        Returns generated text or raises if all providers fail.
        """
        candidates = self._build_candidate_list(preferred_provider)
        if not candidates:
            raise RuntimeError(
                f"SmartRouter: No providers available "
                f"(preferred={preferred_provider}, model={model})"
            )

        logger.info(
            f"SmartRouter: {len(candidates)} candidates "
            f"[{', '.join(f'{p.id}/{a.label}' for p, a in candidates)}]"
        )

        last_error = None
        for provider, account in candidates:
            try:
                use_model = model or account.model_override or provider.default_model
                logger.info(f"SmartRouter: Trying {provider.name} ({use_model}) via {account.label}")

                text, tokens_used = await self._call_provider(
                    provider=provider,
                    account=account,
                    prompt=prompt,
                    system=system,
                    max_tokens=max_tokens,
                    model=use_model,
                    temperature=temperature,
                )

                # Record success + track which provider/model served the request
                self._total_requests += 1
                self._total_tokens += tokens_used
                self._last_provider = provider.id
                self._last_model = use_model
                self._last_account_label = account.label
                self.registry.record_usage(account.id, tokens_used)
                logger.info(f"SmartRouter: OK — served by {provider.name} ({use_model})")
                return text

            except QuotaExhaustedError as e:
                retry_after = getattr(e, "retry_after", 300)
                self.quota.record_exhausted(account.id, retry_after)
                self._failover_count += 1
                last_error = e
                logger.info(f"SmartRouter: {provider.name}/{account.label} quota exhausted, trying next")

            except AuthenticationError as e:
                # For CLI/OAuth accounts, try re-extracting token and RETRY immediately
                if account.source == "cli_detect":
                    refreshed = await self._try_reextract_cli_token(provider.id, account.id)
                    if refreshed:
                        logger.info(f"SmartRouter: {provider.name}/{account.label} token re-extracted, retrying NOW")
                        try:
                            text, tokens_used = await self._call_provider(
                                provider=provider,
                                account=account,
                                prompt=prompt,
                                system=system,
                                max_tokens=max_tokens,
                                model=use_model,
                                temperature=temperature,
                            )
                            self._total_requests += 1
                            self._total_tokens += tokens_used
                            self._last_provider = provider.id
                            self._last_model = use_model
                            self._last_account_label = account.label
                            self.registry.record_usage(account.id, tokens_used)
                            logger.info(f"SmartRouter: OK — served by {provider.name} ({use_model}) after token re-extract")
                            return text
                        except Exception as retry_err:
                            logger.warning(f"SmartRouter: {provider.name} retry after re-extract also failed: {retry_err}")
                            last_error = retry_err

                self.registry.deactivate_account(account.id)
                self._failover_count += 1
                if last_error is None:
                    last_error = e
                logger.warning(f"SmartRouter: {provider.name}/{account.label} auth failed, deactivated")

            except Exception as e:
                self._failover_count += 1
                last_error = e
                logger.warning(f"SmartRouter: {provider.name}/{account.label} error: {e}")

        raise RuntimeError(f"SmartRouter: All providers failed. Last error: {last_error}")

    def _build_candidate_list(
        self, preferred: Optional[str] = None
    ) -> List[Tuple[Provider, Account]]:
        """Build ordered list of (provider, account) candidates.

        If preferred is set, that provider is tried FIRST, then falls back
        to other providers of the same tier if all accounts fail.
        If preferred is not set, all providers are tried by tier.
        """
        candidates = []
        seen_account_ids = set()

        if preferred:
            # Preferred provider goes first in candidate list
            provider = self.registry.get_provider(preferred)
            if provider:
                accounts = self.registry.get_active_accounts(preferred)
                for acct in accounts:
                    if self.quota.is_available(acct.id):
                        candidates.append((provider, acct))
                        seen_account_ids.add(acct.id)
                if not candidates:
                    logger.warning(
                        f"SmartRouter: Preferred provider '{preferred}' has no active accounts! "
                        f"Falling back to all providers."
                    )

        # Add remaining providers as fallback (by tier)
        for tier in (1, 2, 3):
            providers = self.registry.get_providers_by_tier(tier)
            for provider in providers:
                if not getattr(provider, "enabled", True):
                    continue
                acct = self.quota.next_account(
                    provider.id,
                    self.registry.get_active_accounts(provider.id),
                )
                if acct and acct.id not in seen_account_ids:
                    candidates.append((provider, acct))
                    seen_account_ids.add(acct.id)

        return candidates

    async def _call_provider(
        self,
        provider: Provider,
        account: Account,
        prompt: str,
        system: str,
        max_tokens: int,
        model: str,
        temperature: float,
    ) -> Tuple[str, int]:
        """Make an API call to a provider. Returns (text, tokens_used)."""
        credential = self.registry.get_credential(account.id)
        if not credential:
            raise AuthenticationError(f"No credential for {account.id}")

        format_map = {
            "anthropic": (self._build_anthropic_request, self._parse_anthropic_response),
            "openai_compat": (self._build_openai_request, self._parse_openai_response),
            "gemini": (self._build_gemini_request, self._parse_gemini_response),
            "gemini_code_assist": (self._build_gemini_code_assist_request, self._parse_gemini_code_assist_response),
            "ollama": (self._build_ollama_request, self._parse_ollama_response),
        }

        builder, parser = format_map.get(provider.api_format, (None, None))
        if not builder:
            raise ValueError(f"Unknown API format: {provider.api_format}")

        url, headers, payload = builder(
            base_url=provider.base_url,
            credential=credential,
            credential_type=account.credential_type,
            prompt=prompt,
            system=system,
            max_tokens=max_tokens,
            model=model,
            temperature=temperature,
        )

        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                if resp.status == 429:
                    retry_after = int(resp.headers.get("Retry-After", "300"))
                    raise QuotaExhaustedError(
                        f"Rate limited by {provider.name}",
                        retry_after=retry_after,
                    )
                if resp.status in (401, 403):
                    raise AuthenticationError(
                        f"Authentication failed for {provider.name}: {resp.status}"
                    )
                if resp.status >= 400:
                    body = await resp.text()
                    raise RuntimeError(
                        f"{provider.name} returned {resp.status}: {body[:300]}"
                    )

                data = await resp.json()
                return parser(data)

    # ── Format Builders ──────────────────────────────────────

    def _build_anthropic_request(
        self, base_url: str, credential: str, credential_type: str,
        prompt: str, system: str, max_tokens: int, model: str, temperature: float,
    ) -> Tuple[str, Dict, Dict]:
        url = f"{base_url}/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if credential_type == "oauth":
            headers["Authorization"] = f"Bearer {credential}"
        else:
            headers["x-api-key"] = credential

        messages = [{"role": "user", "content": prompt}]
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system

        return url, headers, payload

    def _build_openai_request(
        self, base_url: str, credential: str, credential_type: str,
        prompt: str, system: str, max_tokens: int, model: str, temperature: float,
    ) -> Tuple[str, Dict, Dict]:
        url = f"{base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {credential}",
        }

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        return url, headers, payload

    def _build_gemini_request(
        self, base_url: str, credential: str, credential_type: str,
        prompt: str, system: str, max_tokens: int, model: str, temperature: float,
    ) -> Tuple[str, Dict, Dict]:
        if credential_type == "oauth":
            url = f"{base_url}/models/{model}:generateContent"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {credential}",
            }
        else:
            url = f"{base_url}/models/{model}:generateContent?key={credential}"
            headers = {"Content-Type": "application/json"}

        contents = [{"parts": [{"text": prompt}]}]
        payload = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        return url, headers, payload

    def _build_gemini_code_assist_request(
        self, base_url: str, credential: str, credential_type: str,
        prompt: str, system: str, max_tokens: int, model: str, temperature: float,
    ) -> Tuple[str, Dict, Dict]:
        """Build request for Google Cloud Code Assist API (Gemini CLI endpoint)."""
        url = f"{base_url}/v1internal:generateContent"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {credential}",
            "User-Agent": "google-cloud-sdk vscode_cloudshelleditor/0.1",
            "X-Goog-Api-Client": "gl-node/22.17.0",
        }

        inner_request: Dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system:
            inner_request["systemInstruction"] = {"parts": [{"text": system}]}

        payload: Dict[str, Any] = {
            "model": model,
            "request": inner_request,
        }
        # Include project ID if discovered
        if self._gemini_project_id:
            payload["project"] = self._gemini_project_id

        return url, headers, payload

    def _build_ollama_request(
        self, base_url: str, credential: str, credential_type: str,
        prompt: str, system: str, max_tokens: int, model: str, temperature: float,
    ) -> Tuple[str, Dict, Dict]:
        url = f"{base_url}/api/generate"
        headers = {"Content-Type": "application/json"}

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }
        if system:
            payload["system"] = system

        return url, headers, payload

    # ── Response Parsers ─────────────────────────────────────

    def _parse_anthropic_response(self, data: Dict) -> Tuple[str, int]:
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
        usage = data.get("usage", {})
        tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        return text, tokens

    def _parse_openai_response(self, data: Dict) -> Tuple[str, int]:
        choices = data.get("choices", [])
        text = choices[0]["message"]["content"] if choices else ""
        usage = data.get("usage", {})
        tokens = usage.get("total_tokens", 0)
        return text, tokens

    def _parse_gemini_response(self, data: Dict) -> Tuple[str, int]:
        candidates = data.get("candidates", [])
        text = ""
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
        usage = data.get("usageMetadata", {})
        tokens = usage.get("totalTokenCount", 0)
        return text, tokens

    def _parse_gemini_code_assist_response(self, data: Dict) -> Tuple[str, int]:
        """Parse Cloud Code Assist API response (wraps standard Gemini in 'response' field)."""
        response = data.get("response", data)
        candidates = response.get("candidates", [])
        text = ""
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
        usage = response.get("usageMetadata", {})
        tokens = usage.get("totalTokenCount", 0)
        return text, tokens

    def _parse_ollama_response(self, data: Dict) -> Tuple[str, int]:
        text = data.get("response", "")
        # Ollama doesn't always return token counts
        tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
        return text, tokens

    # ── Gemini CLI Project Discovery ────────────────────────────

    async def discover_gemini_project(self) -> Optional[str]:
        """Discover Gemini CLI project ID via loadCodeAssist API call."""
        if self._gemini_project_id:
            return self._gemini_project_id

        provider = self.registry.get_provider("gemini_cli")
        if not provider or not provider.accounts:
            return None

        account = next(iter(provider.accounts.values()), None)
        if not account or not account.is_active:
            return None

        credential = self.registry.get_credential(account.id)
        if not credential:
            return None

        try:
            import aiohttp

            url = f"{provider.base_url}/v1internal:loadCodeAssist"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {credential}",
                "User-Agent": "google-cloud-sdk vscode_cloudshelleditor/0.1",
            }
            payload = {
                "metadata": {
                    "ideType": "IDE_UNSPECIFIED",
                    "platform": "PLATFORM_UNSPECIFIED",
                    "pluginType": "GEMINI",
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, headers=headers, json=payload,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        project_data = data.get("cloudaicompanionProject", {})
                        project_id = (
                            project_data.get("id", "")
                            if isinstance(project_data, dict)
                            else str(project_data)
                        )
                        if project_id:
                            self._gemini_project_id = project_id
                            logger.info(f"SmartRouter: Gemini CLI project: {project_id}")
                            return project_id
        except Exception as e:
            logger.debug(f"SmartRouter: Gemini project discovery failed: {e}")

        return None

    # ── CLI Token Recovery ─────────────────────────────────────

    async def _try_reextract_cli_token(self, provider_id: str, account_id: str) -> bool:
        """Try to re-extract/refresh a CLI token when auth fails.

        Strategy:
        1. Re-extract from CLI credential files (may have been refreshed externally)
        2. If refresh_token is available, try OAuth refresh
        """
        # Strategy 1: Re-extract from disk
        try:
            from .token_extractor import TokenExtractor
            extractor = TokenExtractor()
            token = extractor.detect(provider_id)
            if token and token.token:
                self.registry.update_credential(account_id, token.token, token.expires_at)
                if token.refresh_token:
                    self.registry._refresh_tokens[account_id] = token.refresh_token
                self.registry.reactivate_account(account_id)
                logger.info(f"SmartRouter: Re-extracted CLI token for {provider_id}")
                return True
        except Exception as e:
            logger.debug(f"SmartRouter: CLI re-extraction failed for {provider_id}: {e}")

        # Strategy 2: OAuth refresh if we have a refresh_token
        refresh_token = self.registry.get_refresh_token(account_id)
        if refresh_token:
            try:
                from .token_refresher import TokenRefresher
                refresher = TokenRefresher(self.registry)
                success = await refresher._refresh_token(provider_id, account_id, refresh_token)
                if success:
                    self.registry.reactivate_account(account_id)
                    logger.info(f"SmartRouter: OAuth-refreshed token for {provider_id}")
                    return True
            except Exception as e:
                logger.debug(f"SmartRouter: OAuth refresh failed for {provider_id}: {e}")

        return False

    # ── Testing & Status ─────────────────────────────────────

    async def test_account(
        self, provider_id: str, account_id: str
    ) -> Tuple[bool, str]:
        """Test connectivity for a specific account. Returns (success, message)."""
        provider = self.registry.get_provider(provider_id)
        if not provider:
            return False, f"Unknown provider: {provider_id}"

        account = provider.accounts.get(account_id)
        if not account:
            return False, f"Unknown account: {account_id}"

        try:
            text, tokens = await self._call_provider(
                provider=provider,
                account=account,
                prompt="Say 'OK' and nothing else.",
                system="",
                max_tokens=10,
                model=account.model_override or provider.default_model,
                temperature=0,
            )
            return True, f"Connected. Response: {text[:50]}"
        except Exception as e:
            return False, str(e)

    def get_status(self) -> Dict:
        """Get router statistics."""
        return {
            "total_requests": self._total_requests,
            "total_tokens": self._total_tokens,
            "failover_count": self._failover_count,
            "last_provider": self._last_provider,
            "last_model": self._last_model,
            "last_account": self._last_account_label,
            "providers": self.registry.get_all_status(),
        }


# ── Custom Exceptions ────────────────────────────────────────

class QuotaExhaustedError(Exception):
    def __init__(self, message: str, retry_after: int = 300):
        super().__init__(message)
        self.retry_after = retry_after


class AuthenticationError(Exception):
    pass
