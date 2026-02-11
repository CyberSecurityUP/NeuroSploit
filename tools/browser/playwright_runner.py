#!/usr/bin/env python3
"""
Playwright Runner - Low-level browser automation helpers for security testing.

Provides convenience functions for common browser-based security validation tasks.
"""

import asyncio
import logging
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


async def check_xss_reflection(url: str, payload: str, headless: bool = True) -> Dict:
    """Check if a payload is reflected in page content or triggers a dialog.

    Args:
        url: Target URL (payload should be in query params)
        payload: The XSS payload being tested
        headless: Run in headless mode

    Returns:
        Dict with reflection status, dialog detection, and page content snippet
    """
    if not HAS_PLAYWRIGHT:
        return {"error": "Playwright not installed"}

    result = {
        "url": url,
        "payload": payload,
        "reflected": False,
        "dialog_triggered": False,
        "dialog_message": None,
        "content_snippet": ""
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        dialogs = []

        async def on_dialog(dialog):
            dialogs.append(dialog.message)
            await dialog.dismiss()

        page.on("dialog", on_dialog)

        try:
            await page.goto(url, wait_until="networkidle", timeout=15000)
            content = await page.content()

            if payload in content:
                result["reflected"] = True
                idx = content.find(payload)
                start = max(0, idx - 100)
                end = min(len(content), idx + len(payload) + 100)
                result["content_snippet"] = content[start:end]

            if dialogs:
                result["dialog_triggered"] = True
                result["dialog_message"] = dialogs[0]

        except Exception as e:
            result["error"] = str(e)
        finally:
            await browser.close()

    return result


async def capture_page_state(url: str, screenshot_path: str,
                              headless: bool = True) -> Dict:
    """Capture the full state of a page: screenshot, title, headers, cookies.

    Args:
        url: Page URL to capture
        screenshot_path: Path to save the screenshot
        headless: Run in headless mode

    Returns:
        Dict with page title, cookies, response headers, console messages
    """
    if not HAS_PLAYWRIGHT:
        return {"error": "Playwright not installed"}

    result = {
        "url": url,
        "title": "",
        "screenshot": screenshot_path,
        "cookies": [],
        "console_messages": [],
        "response_headers": {},
        "status_code": None
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        console_msgs = []
        page.on("console", lambda msg: console_msgs.append({
            "type": msg.type, "text": msg.text
        }))

        try:
            response = await page.goto(url, wait_until="networkidle", timeout=20000)

            result["title"] = await page.title()
            result["status_code"] = response.status if response else None
            result["response_headers"] = dict(response.headers) if response else {}

            Path(screenshot_path).parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=screenshot_path, full_page=True)

            cookies = await context.cookies()
            result["cookies"] = [
                {"name": c["name"], "domain": c["domain"],
                 "secure": c["secure"], "httpOnly": c["httpOnly"],
                 "sameSite": c.get("sameSite", "None")}
                for c in cookies
            ]

            result["console_messages"] = console_msgs

        except Exception as e:
            result["error"] = str(e)
        finally:
            await browser.close()

    return result


async def test_form_submission(url: str, form_data: Dict[str, str],
                                submit_selector: str = "button[type=submit]",
                                screenshot_dir: str = "/tmp/form_test",
                                headless: bool = True) -> Dict:
    """Submit a form and capture before/after state.

    Args:
        url: URL containing the form
        form_data: Dict of selector -> value to fill
        submit_selector: CSS selector for the submit button
        screenshot_dir: Directory to store screenshots
        headless: Run in headless mode

    Returns:
        Dict with before/after screenshots, response info, and any triggered dialogs
    """
    if not HAS_PLAYWRIGHT:
        return {"error": "Playwright not installed"}

    ss_dir = Path(screenshot_dir)
    ss_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "url": url,
        "before_screenshot": str(ss_dir / "before.png"),
        "after_screenshot": str(ss_dir / "after.png"),
        "dialogs": [],
        "response_url": "",
        "status": "unknown"
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        dialogs = []

        async def on_dialog(dialog):
            dialogs.append({"type": dialog.type, "message": dialog.message})
            await dialog.dismiss()

        page.on("dialog", on_dialog)

        try:
            await page.goto(url, wait_until="networkidle", timeout=15000)
            await page.screenshot(path=result["before_screenshot"])

            # Fill form fields
            for selector, value in form_data.items():
                await page.fill(selector, value)

            # Submit
            await page.click(submit_selector)
            await page.wait_for_load_state("networkidle")

            await page.screenshot(path=result["after_screenshot"], full_page=True)
            result["response_url"] = page.url
            result["dialogs"] = dialogs
            result["status"] = "completed"

        except Exception as e:
            result["error"] = str(e)
            result["status"] = "error"
        finally:
            await browser.close()

    return result
