from ..openai_client import plan_next_action

def decide(context: dict) -> dict:
    return plan_next_action(context)
