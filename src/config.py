from pydantic import BaseModel
import os

class Settings(BaseModel):
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-5")
    allowlist_hosts: list[str] = [h.strip() for h in os.getenv("ALLOWLIST_HOSTS", "localhost,127.0.0.1,dvwa").split(",")]
    dvwa_url_env: str = os.getenv("DVWA_URL", "").strip()
    headless: bool = os.getenv("HEADLESS", "true").lower() == "true"

settings = Settings()
