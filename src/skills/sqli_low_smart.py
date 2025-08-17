from pathlib import Path
from urllib.parse import urlencode
from ..tools.browser import Browser
from ..detectors.sql_errors import has_sql_error
from ..fuzz.engine import generate_candidates, try_candidates
from ..fuzz.seeds import SQLI_SEEDS

def run(base_url: str, budget: int = 8) -> dict:
    with Browser(base_url) as b:
        # login
        b.goto("/login.php")
        b.page.wait_for_selector('input[name="username"]', timeout=15000)
        b.fill('input[name="username"]', "admin")
        b.fill('input[name="password"]', "password")
        b.click('input[type="submit"]')
        b.page.wait_for_load_state("domcontentloaded")

        # best effort low
        try:
            b.goto("/security.php")
            b.page.wait_for_selector('select[name="security"]', timeout=5000)
            b.page.select_option('select[name="security"]', 'low')
            b.click('input[type="submit"]')
            b.page.wait_for_load_state("domcontentloaded")
        except Exception:
            pass

        # baseline
        b.goto("/vulnerabilities/sqli/?id=1&Submit=Submit")
        b.page.wait_for_load_state("domcontentloaded")
        base_html = b.content()
        base_len = len(base_html)

        def success_metrics(html: str):
            if has_sql_error(html): return True, "SQL error pattern"
            if ("First name" in html and "Surname" in html): return True, "User table markers"
            if ("User ID" in html and "exists in the database" in html): return True, "Exists message"
            if len(html) > base_len + 150: return True, "Delta size grew"
            return False, ""

        # gerar candidatos com LLM (contexto simples da página)
        page_ctx = {"markers":["id input","Submit button"], "base_len": base_len}
        candidates = generate_candidates("SQLiLow", page_ctx, SQLI_SEEDS, budget)

        def try_one(p: str):
            qs = urlencode({"id": p, "Submit": "Submit"})
            b.goto(f"/vulnerabilities/sqli/?{qs}")
            b.page.wait_for_load_state("domcontentloaded")
            html = b.content()
            ok, reason = success_metrics(html)

            # screenshot
            screens = Path(__file__).resolve().parents[2].parent / "screens"
            screens.mkdir(parents=True, exist_ok=True)
            shot = screens / "sqli_low_smart.png"
            b.page.screenshot(path=str(shot), full_page=True)

            return {
                "ok": ok,
                "vector": "SQLi (Low) SMART",
                "payload": p,
                "reason": reason,
                "evidence_excerpt": html[:1200],
                "screenshot": str(shot),
                "url": b.page.url,
            }

        return try_candidates(try_one, candidates)
