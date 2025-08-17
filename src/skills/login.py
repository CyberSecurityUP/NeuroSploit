from ..tools.browser import Browser

def run(base_url: str, username: str="admin", password: str="password") -> dict:
    """Login on DVWA (default creds)."""
    with Browser(base_url) as b:
        b.goto("/login.php")
        b.fill('input[name="username"]', username)
        b.fill('input[name="password"]', password)
        b.click('input[type="submit"]')
        body = b.text()
        ok = "DVWA Security" in body or "Welcome" in body or "logout" in body.lower()
        return {"ok": ok, "page": "home", "evidence": "contains DVWA after login" if ok else body[:500]}
