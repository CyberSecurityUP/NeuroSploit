from typing import Dict, Any, List
from ..models import get_provider

_provider = get_provider()

def decide(context: dict) -> dict:
    """Mantém compat com o antigo: planejar uma ação simples."""
    system = "You are a safe web security agent. Return STRICT JSON."
    user = (
        "Given this context, propose one next action as JSON:\n"
        "{'tool':'navigate|fill_form|click|noop','target':'url|selector','data':null|{...},'why':'short'}\n\n"
        f"Context:\n{context}"
    )
    res = _provider.complete_json(system, user)
    if not isinstance(res, dict):
        res = {"tool":"noop","target":"","data":None,"why":"fallback"}
    return res

def propose_fuzz_payloads(category: str, page_context: dict, seeds: List[str], budget: int=8) -> List[str]:
    """Pede ao modelo variações de payload com base nos seeds e contexto da página."""
    system = "You are an offensive security payload generator. Return STRICT JSON: {'payloads': [..]}."
    user = (
        f"Category: {category}\n"
        f"Seeds: {seeds}\n"
        f"Page context (inputs, hints, server msgs): {page_context}\n"
        f"Generate up to {budget} diverse payloads. Focus on low-noise, high-signal candidates for DVWA Low.\n"
        "Only return JSON: {'payloads': ['...','...']}."
    )
    res = _provider.complete_json(system, user)
    pls = res.get("payloads", []) if isinstance(res, dict) else []
    # sanity filter
    uniq = []
    for p in pls:
        if not isinstance(p, str): continue
        p = p.strip()
        if p and p not in uniq and len(p) < 256:
            uniq.append(p)
    # fallback: se nada vier, retorne seeds
    return uniq or seeds[:budget]
