from playwright.sync_api import sync_playwright
from typing import Optional
from ..config import settings
from urllib.parse import urlparse

class Browser:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self._pw = None
        self._browser = None
        self._context = None
        self.page = None

        # safety: enforce allowlist
        host = urlparse(self.base_url).hostname or ""
        if host not in settings.allowlist_hosts:
            raise RuntimeError(f"Target host '{host}' not in allowlist: {settings.allowlist_hosts}")

    def __enter__(self):
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=settings.headless)
        self._context = self._browser.new_context(ignore_https_errors=True)
        self.page = self._context.new_page()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._context: self._context.close()
            if self._browser: self._browser.close()
        finally:
            if self._pw: self._pw.stop()

    # helpers
    def goto(self, path: str):
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        self.page.goto(url, wait_until="domcontentloaded")

    def fill(self, selector: str, value: str):
        self.page.fill(selector, value)

    def click(self, selector: str):
        self.page.click(selector)

    def content(self) -> str:
        return self.page.content()

    def text(self) -> str:
        return self.page.inner_text("body")

    def screenshot(self, path: str):
        self.page.screenshot(path=path, full_page=True)
