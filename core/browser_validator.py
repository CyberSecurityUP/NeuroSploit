#!/usr/bin/env python3
"""
Browser Validator - Playwright-based security finding validation.

Provides browser-based validation for security findings:
- Navigate to target URLs with payloads
- Detect security triggers (XSS dialogs, error patterns, etc.)
- Capture screenshots at each validation step
- Store evidence in structured per-finding directories

Screenshots are stored at: reports/screenshots/{finding_id}/
"""

import asyncio
import base64
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.debug("Playwright not installed. Browser validation disabled.")


# Known security trigger patterns in page content
SECURITY_TRIGGERS = {
    'xss': ['<script>alert(', 'onerror=', 'onload=', 'javascript:'],
    'sqli': ['SQL syntax', 'mysql_fetch', 'pg_query', 'ORA-', 'sqlite3.OperationalError',
             'SQLSTATE', 'syntax error at or near', 'unclosed quotation mark'],
    'lfi': ['root:x:0', '/etc/passwd', '[boot loader]', 'Windows\\system.ini'],
    'rce': ['uid=', 'gid=', 'groups=', 'total ', 'drwx'],
    'error_disclosure': ['Stack Trace', 'Traceback (most recent call last)',
                          'Exception in thread', 'Fatal error', 'Parse error'],
}


class BrowserValidator:
    """Playwright-based browser validation for security findings."""

    def __init__(self, screenshots_dir: str = "reports/screenshots"):
        self.screenshots_dir = Path(screenshots_dir)
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.browser: Optional['Browser'] = None
        self._playwright = None

    async def start(self, headless: bool = True):
        """Launch browser instance."""
        if not HAS_PLAYWRIGHT:
            raise RuntimeError(
                "Playwright not installed. Install with: pip install playwright && python -m playwright install chromium"
            )
        self._playwright = await async_playwright().start()
        self.browser = await self._playwright.chromium.launch(headless=headless)
        logger.info(f"Browser started (headless={headless})")

    async def stop(self):
        """Close browser and clean up."""
        if self.browser:
            await self.browser.close()
            self.browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
        logger.info("Browser stopped")

    async def validate_finding(self, finding_id: str, url: str,
                                payload: Optional[str] = None,
                                method: str = "GET",
                                interaction_steps: Optional[List[Dict]] = None,
                                timeout: int = 30000) -> Dict:
        """Validate a security finding in a real browser.

        Args:
            finding_id: Unique identifier for the finding
            url: Target URL (may include payload in query params)
            payload: Optional payload description for logging
            method: HTTP method (currently GET-based navigation)
            interaction_steps: Optional list of browser interaction steps
            timeout: Navigation timeout in milliseconds

        Returns:
            Dict with validation result, screenshots, evidence
        """
        if not self.browser:
            return {"error": "Browser not started. Call start() first."}

        finding_dir = self.screenshots_dir / finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)

        validation = {
            "finding_id": finding_id,
            "url": url,
            "payload": payload,
            "timestamp": datetime.now().isoformat(),
            "validated": False,
            "screenshots": [],
            "console_logs": [],
            "dialog_detected": False,
            "dialog_messages": [],
            "triggers_found": [],
            "evidence": "",
            "page_title": "",
            "status_code": None,
            "error": None
        }

        context = await self.browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = await context.new_page()

        # Capture console messages
        console_msgs = []
        page.on("console", lambda msg: console_msgs.append({
            "type": msg.type, "text": msg.text
        }))

        # Capture JavaScript dialogs (XSS alert/prompt/confirm detection)
        dialog_messages = []

        async def handle_dialog(dialog):
            dialog_messages.append({
                "type": dialog.type,
                "message": dialog.message
            })
            await dialog.dismiss()

        page.on("dialog", handle_dialog)

        # Track response status
        response_status = [None]

        def on_response(response):
            if response.url == url or response.url.rstrip('/') == url.rstrip('/'):
                response_status[0] = response.status

        page.on("response", on_response)

        try:
            # Navigate to the URL
            response = await page.goto(url, wait_until="networkidle", timeout=timeout)
            if response:
                validation["status_code"] = response.status

            validation["page_title"] = await page.title()

            # Take initial screenshot
            ss_path = finding_dir / "01_initial.png"
            await page.screenshot(path=str(ss_path), full_page=True)
            validation["screenshots"].append(str(ss_path))

            # Execute interaction steps if provided
            if interaction_steps:
                for i, step in enumerate(interaction_steps):
                    step_name = step.get('name', f'step_{i+2}')
                    try:
                        await self._execute_step(page, step)
                        await page.wait_for_timeout(500)  # Brief pause
                        ss_path = finding_dir / f"{i+2:02d}_{step_name}.png"
                        await page.screenshot(path=str(ss_path))
                        validation["screenshots"].append(str(ss_path))
                    except Exception as e:
                        logger.warning(f"Interaction step '{step_name}' failed: {e}")

            # Check for dialog detection (XSS)
            if dialog_messages:
                validation["validated"] = True
                validation["dialog_detected"] = True
                validation["dialog_messages"] = dialog_messages
                validation["evidence"] = f"JavaScript dialog triggered: {dialog_messages[0]['message']}"

                ss_path = finding_dir / "xss_dialog_detected.png"
                await page.screenshot(path=str(ss_path))
                validation["screenshots"].append(str(ss_path))

            # Check for security triggers in page content
            content = await page.content()
            for trigger_type, patterns in SECURITY_TRIGGERS.items():
                for pattern in patterns:
                    if pattern.lower() in content.lower():
                        validation["triggers_found"].append({
                            "type": trigger_type,
                            "pattern": pattern
                        })

            if validation["triggers_found"] and not validation["validated"]:
                validation["validated"] = True
                first_trigger = validation["triggers_found"][0]
                validation["evidence"] = (
                    f"Security trigger detected: {first_trigger['type']} "
                    f"(pattern: {first_trigger['pattern']})"
                )

                ss_path = finding_dir / "trigger_detected.png"
                await page.screenshot(path=str(ss_path))
                validation["screenshots"].append(str(ss_path))

            # Check console for errors that might indicate vulnerabilities
            error_msgs = [m for m in console_msgs if m["type"] in ("error", "warning")]
            if error_msgs:
                validation["console_logs"] = console_msgs

        except Exception as e:
            validation["error"] = str(e)
            logger.error(f"Browser validation error for {finding_id}: {e}")

            try:
                ss_path = finding_dir / "error.png"
                await page.screenshot(path=str(ss_path))
                validation["screenshots"].append(str(ss_path))
            except Exception:
                pass

        finally:
            await context.close()

        return validation

    async def verify_stored_xss(
        self,
        finding_id: str,
        form_url: str,
        form_data: Dict[str, str],
        display_url: str,
        submit_selector: str = "button[type=submit], input[type=submit], button:not([type])",
        timeout: int = 30000,
    ) -> Dict:
        """Two-phase stored XSS verification using browser.

        Phase 1: Navigate to form page, fill fields with payload, submit.
        Phase 2: Navigate to display page, check for dialog (alert/confirm/prompt).

        Args:
            finding_id: Unique ID for this verification attempt
            form_url: URL containing the form to submit
            form_data: Dict mapping CSS selectors to values (payload in relevant fields)
            display_url: URL where stored content is displayed
            submit_selector: CSS selector(s) for submit button (comma-separated)
            timeout: Navigation timeout in ms

        Returns:
            Dict with verification results, dialog detection, screenshots
        """
        if not self.browser:
            return {"error": "Browser not started. Call start() first."}

        finding_dir = self.screenshots_dir / finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)

        result = {
            "finding_id": finding_id,
            "form_url": form_url,
            "display_url": display_url,
            "timestamp": datetime.now().isoformat(),
            "phase1_success": False,
            "phase2_success": False,
            "xss_confirmed": False,
            "dialog_detected": False,
            "dialog_messages": [],
            "screenshots": [],
            "evidence": "",
            "error": None,
        }

        context = await self.browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = await context.new_page()

        dialog_messages = []

        async def handle_dialog(dialog):
            dialog_messages.append({
                "type": dialog.type,
                "message": dialog.message,
                "phase": "phase2" if result["phase1_success"] else "phase1"
            })
            await dialog.dismiss()

        page.on("dialog", handle_dialog)

        try:
            # === PHASE 1: Navigate to form and submit payload ===
            await page.goto(form_url, wait_until="networkidle", timeout=timeout)

            ss_path = finding_dir / "01_form_page.png"
            await page.screenshot(path=str(ss_path), full_page=True)
            result["screenshots"].append(str(ss_path))

            # Fill form fields
            for selector, value in form_data.items():
                try:
                    await page.fill(selector, value)
                except Exception:
                    try:
                        await page.type(selector, value)
                    except Exception as fill_err:
                        logger.warning(f"Could not fill {selector}: {fill_err}")

            ss_path = finding_dir / "02_form_filled.png"
            await page.screenshot(path=str(ss_path))
            result["screenshots"].append(str(ss_path))

            # Submit
            submitted = False
            for sel in submit_selector.split(","):
                sel = sel.strip()
                try:
                    btn = await page.query_selector(sel)
                    if btn:
                        await btn.click()
                        submitted = True
                        break
                except Exception:
                    continue

            if not submitted and form_data:
                # Fallback: press Enter on last filled field
                last_sel = list(form_data.keys())[-1]
                try:
                    await page.press(last_sel, "Enter")
                except Exception:
                    pass

            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                await page.wait_for_timeout(3000)

            ss_path = finding_dir / "03_after_submit.png"
            await page.screenshot(path=str(ss_path), full_page=True)
            result["screenshots"].append(str(ss_path))
            result["phase1_success"] = True

            # === PHASE 2: Navigate to display page ===
            await page.goto(display_url, wait_until="networkidle", timeout=timeout)
            await page.wait_for_timeout(1000)

            ss_path = finding_dir / "04_display_page.png"
            await page.screenshot(path=str(ss_path), full_page=True)
            result["screenshots"].append(str(ss_path))

            # Check for dialogs triggered on display page
            if dialog_messages:
                phase2_dialogs = [d for d in dialog_messages if d.get("phase") == "phase2"]
                if phase2_dialogs:
                    result["xss_confirmed"] = True
                    result["dialog_detected"] = True
                    result["dialog_messages"] = dialog_messages
                    result["evidence"] = (
                        f"Stored XSS CONFIRMED: JavaScript dialog triggered on display page. "
                        f"Dialog: {phase2_dialogs[0]['type']}('{phase2_dialogs[0]['message']}')"
                    )
                    result["phase2_success"] = True

                    ss_path = finding_dir / "05_xss_confirmed.png"
                    await page.screenshot(path=str(ss_path))
                    result["screenshots"].append(str(ss_path))
                else:
                    result["evidence"] = (
                        "Dialog triggered during form submission (phase1), not on display page."
                    )

            # Content-based fallback if no dialog
            if not result["xss_confirmed"]:
                content = await page.content()
                for _, payload_val in form_data.items():
                    if payload_val in content:
                        payload_lower = payload_val.lower()
                        for tag in ["<script", "onerror=", "onload=", "<svg", "<img",
                                    "onfocus=", "onclick=", "ontoggle"]:
                            if tag in payload_lower:
                                result["phase2_success"] = True
                                result["evidence"] = (
                                    f"Stored payload with '{tag}' found unescaped on display page. "
                                    f"Dialog may be blocked by CSP."
                                )
                                break
                        break

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Stored XSS verification error: {e}")
            try:
                ss_path = finding_dir / "error.png"
                await page.screenshot(path=str(ss_path))
                result["screenshots"].append(str(ss_path))
            except Exception:
                pass
        finally:
            await context.close()

        return result

    async def _execute_step(self, page: 'Page', step: Dict):
        """Execute a single browser interaction step."""
        action = step.get("action", "")

        if action == "click":
            await page.click(step["selector"])
        elif action == "fill":
            await page.fill(step["selector"], step["value"])
        elif action == "type":
            await page.type(step["selector"], step["value"])
        elif action == "submit":
            selector = step.get("selector", "button[type=submit]")
            await page.click(selector)
        elif action == "wait":
            await page.wait_for_timeout(step.get("ms", 2000))
        elif action == "navigate":
            await page.goto(step["url"], wait_until="networkidle")
        elif action == "select":
            await page.select_option(step["selector"], step["value"])
        elif action == "check":
            await page.check(step["selector"])
        elif action == "press":
            await page.press(step.get("selector", "body"), step["key"])
        else:
            logger.warning(f"Unknown interaction action: {action}")

    async def batch_validate(self, findings: List[Dict],
                              headless: bool = True) -> List[Dict]:
        """Validate multiple findings in sequence.

        Args:
            findings: List of dicts with 'finding_id', 'url', and optional 'payload'
            headless: Run browser in headless mode

        Returns:
            List of validation results
        """
        results = []
        await self.start(headless=headless)
        try:
            for finding in findings:
                result = await self.validate_finding(
                    finding_id=finding['finding_id'],
                    url=finding['url'],
                    payload=finding.get('payload'),
                    interaction_steps=finding.get('interaction_steps')
                )
                results.append(result)
        finally:
            await self.stop()
        return results


def validate_finding_sync(finding_id: str, url: str,
                           payload: str = None,
                           screenshots_dir: str = "reports/screenshots",
                           headless: bool = True) -> Dict:
    """Synchronous wrapper for browser validation.

    For use in synchronous code paths (e.g., BaseAgent).
    """
    if not HAS_PLAYWRIGHT:
        return {
            "finding_id": finding_id,
            "skipped": True,
            "reason": "Playwright not installed"
        }

    async def _run():
        validator = BrowserValidator(screenshots_dir=screenshots_dir)
        await validator.start(headless=headless)
        try:
            return await validator.validate_finding(finding_id, url, payload)
        finally:
            await validator.stop()

    try:
        return asyncio.run(_run())
    except RuntimeError:
        # Already in an async context - use nest_asyncio or skip
        logger.warning("Cannot run sync validation inside async context")
        return {
            "finding_id": finding_id,
            "skipped": True,
            "reason": "Async context conflict"
        }


def embed_screenshot(filepath: str) -> str:
    """Convert a screenshot file to a base64 data URI for HTML embedding."""
    path = Path(filepath)
    if not path.exists():
        return ""
    with open(path, 'rb') as f:
        data = base64.b64encode(f.read()).decode('ascii')
    return f"data:image/png;base64,{data}"
