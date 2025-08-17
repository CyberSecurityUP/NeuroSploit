from pydantic import BaseModel
import os

class Settings(BaseModel):
    # Provider: "openai", "ollama", "llamacpp"
    model_provider: str = os.getenv("MODEL_PROVIDER", "openai").lower()

    # OpenAI
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-5")

    # Ollama (LLaMA)
    llama_base_url: str = os.getenv("LLAMA_BASE_URL", "http://localhost:11434")
    llama_model: str = os.getenv("LLAMA_MODEL", "llama3.1")  # ex: llama3.1, llama3.2:latest

    # llama.cpp (local python)
    llamacpp_model_path: str = os.getenv("LLAMACPP_MODEL_PATH", "")
    llamacpp_n_threads: int = int(os.getenv("LLAMACPP_N_THREADS", "4"))

    # Safety / target
    allowlist_hosts: list[str] = [h.strip() for h in os.getenv("ALLOWLIST_HOSTS", "localhost,127.0.0.1,dvwa").split(",")]
    dvwa_url_env: str = os.getenv("DVWA_URL", "").strip()
    headless: bool = os.getenv("HEADLESS", "true").lower() == "true"

settings = Settings()
