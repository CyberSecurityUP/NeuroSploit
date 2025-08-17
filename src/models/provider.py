from typing import Dict, Any, List
from ..config import settings

# OpenAI (novo SDK 1.x)
def _openai_client():
    from openai import OpenAI
    return OpenAI(api_key=settings.openai_api_key)

class BaseProvider:
    def name(self) -> str: ...
    def complete_json(self, system: str, user: str) -> Dict[str, Any]:
        """Return parsed JSON (tool choice / payload proposals)."""
        raise NotImplementedError

class OpenAIProvider(BaseProvider):
    def name(self): 
        return "openai"

    def complete_json(self, system: str, user: str) -> Dict[str, Any]:
        """
        Tenta primeiro via Chat Completions com response_format JSON.
        Se a versão do SDK/modelo não suportar, cai para texto puro + parse.
        Por fim, tenta a Responses API sem response_format.
        """
        import json, re
        client = _openai_client()

        # 1) Chat Completions com JSON (preferido)
        try:
            chat = client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user + "\nReturn STRICT JSON only."},
                ],
                temperature=0.2,
                top_p=0.9,
                # algumas versões do SDK suportam isso; se não, cai no except
                response_format={"type": "json_object"},
            )
            txt = chat.choices[0].message.content or "{}"
            return json.loads(txt)
        except Exception:
            pass

        # 2) Chat Completions sem response_format (parse heurístico)
        try:
            chat = client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user + "\nReturn STRICT JSON only."},
                ],
                temperature=0.2,
                top_p=0.9,
            )
            txt = chat.choices[0].message.content or "{}"
            try:
                return json.loads(txt)
            except Exception:
                m = re.search(r"\{.*\}", txt, re.S)
                return json.loads(m.group(0)) if m else {}
        except Exception:
            pass

        # 3) Responses API (fallback), SEM response_format
        try:
            resp = client.responses.create(
                model=settings.openai_model,
                input=[
                    {"role":"system","content":system},
                    {"role":"user","content":user + "\nReturn STRICT JSON only."},
                ],
                temperature=0.2,
                top_p=0.9,
                max_output_tokens=600,
            )
            # diferentes versões expõem campos distintos:
            try:
                txt = resp.output_text
            except Exception:
                # tente extrair do conteúdo estruturado
                try:
                    blocks = resp.output
                    # concatena textos
                    txt = "".join([b.text if hasattr(b, "text") else "" for b in (blocks or [])]) or "{}"
                except Exception:
                    txt = "{}"
            try:
                return json.loads(txt)
            except Exception:
                m = re.search(r"\{.*\}", txt, re.S)
                return json.loads(m.group(0)) if m else {}
        except Exception:
            # último fallback: dict vazio (engine usa seeds)
            return {}

class OllamaProvider(BaseProvider):
    def name(self): return "ollama"
    def complete_json(self, system: str, user: str) -> Dict[str, Any]:
        import requests, json
        url = settings.llama_base_url.rstrip("/") + "/api/generate"
        prompt = f"[SYSTEM]{system}\n[USER]{user}\nReturn STRICT JSON only."
        r = requests.post(url, json={
            "model": settings.llama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature":0.2}
        }, timeout=120)
        r.raise_for_status()
        txt = r.json().get("response","{}")
        try:
            return json.loads(txt)
        except Exception:
            # tentativa robusta: extrair bloco {...}
            import re
            m = re.search(r"\{.*\}", txt, re.S)
            return json.loads(m.group(0)) if m else {}

class LlamaCppProvider(BaseProvider):
    def name(self): return "llamacpp"
    def complete_json(self, system: str, user: str) -> Dict[str, Any]:
        # requer: pip install llama-cpp-python
        from llama_cpp import Llama
        import json, re, os
        llm = Llama(model_path=settings.llamacpp_model_path, n_threads=settings.llamacpp_n_threads, verbose=False)
        prompt = f"[SYSTEM]{system}\n[USER]{user}\nReturn STRICT JSON only."
        out = llm(prompt=prompt, max_tokens=600, temperature=0.2)
        txt = out["choices"][0]["text"]
        try:
            return json.loads(txt)
        except Exception:
            m = re.search(r"\{.*\}", txt, re.S)
            return json.loads(m.group(0)) if m else {}

def get_provider() -> BaseProvider:
    prov = settings.model_provider
    if prov == "openai":
        return OpenAIProvider()
    if prov == "ollama":
        return OllamaProvider()
    if prov == "llamacpp":
        return LlamaCppProvider()
    return OpenAIProvider()
