"""Minimal orchestrator that can call planner (GPT-5) to pick actions.
For MVP we call hardcoded skills; planner integration is available for future loops.
"""
from typing import Dict, Any, Callable
from . import planner
from ..skills import login, xss_reflected_low, sqli_low, xss_stored_low, xss_dom_low, xss_reflected_low_smart, sqli_low_smart

SKILLS: Dict[str, Callable[[str], Dict[str, Any]]] = {
    "login": lambda base: login.run(base),
    "xss_stored_low": lambda base: xss_stored_low.run(base), 
    "xss_reflected_low": lambda base: xss_reflected_low.run(base),
    "xss_dom_low": lambda base: xss_dom_low.run(base),
    "sqli_low": lambda base: sqli_low.run(base),
    "sqli_low_smart": lambda base: sqli_low_smart.run(base),  
    "xss_reflected_low_smart": lambda base: xss_reflected_low_smart.run(base),
}

def run_skill(base_url: str, skill: str) -> Dict[str, Any]:
    if skill not in SKILLS:
        raise KeyError(f"Unknown skill: {skill}")
    return SKILLS[skill](base_url)
