from typing import List, Dict, Any, Callable
from ..agent.planner import propose_fuzz_payloads

def generate_candidates(category: str, page_ctx: dict, seeds: List[str], budget: int=8) -> List[str]:
    """Combina seeds + LLM proposals."""
    props = propose_fuzz_payloads(category, page_ctx, seeds, budget)
    pool = list(dict.fromkeys(seeds + props))  # dedup preservando ordem
    return pool[: max(budget, len(seeds))]

def try_candidates(try_func: Callable[[str], Dict[str, Any]], candidates: List[str]) -> Dict[str, Any]:
    """Executa candidatos até achar sucesso, retornando o melhor resultado."""
    best = {"ok": False}
    for p in candidates:
        res = try_func(p)
        if res.get("ok"):
            return res
        # guarda “quase bom” se tiver um reason/signal
        if not best.get("ok") and len(res.get("evidence_excerpt","")) > len(best.get("evidence_excerpt","")):
            best = res
    return best
