from typing import Any, Dict
from openai import OpenAI
from .config import settings

client = OpenAI(api_key=settings.openai_api_key)

def plan_next_action(context: Dict[str, Any]) -> Dict[str, Any]:
    """Ask GPT-5 for the next action using structured JSON output (no chain-of-thought)."""
    system = (
        "You are a safe web security agent. "
        "Only operate on the allowlisted lab host and return STRICT JSON with the next action."
    )
    user = (
        "Given this context, propose one next action as a JSON object with keys: "
        "{'tool': 'navigate|fill_form|click|type_and_submit|wait|noop', "
        "'target': 'url or selector', 'data': 'payload or null', 'rationale': 'short'}."
        "\nContext:\n" + str(context)
    )
    resp = client.responses.create(
        model=settings.openai_model,
        input=[
            {"role":"system","content":system},
            {"role":"user","content":user},
        ],
        temperature=0.2,
        top_p=0.9,
        max_output_tokens=400,
        response_format={ "type": "json_object" },
    )
    # For SDKs returning parsed JSON via output_parsed
    try:
        txt = resp.output_parsed
    except Exception:
        txt = None
    if not txt:
        try:
            txt = resp.output_text
        except Exception:
            txt = "{}"
    if isinstance(txt, dict):
        return txt
    import json
    try:
        return json.loads(txt)
    except Exception:
        return {"tool":"noop","target":"","data":None,"rationale":"fallback"}
