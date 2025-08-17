import json, argparse
from .agent.orchestrator import run_skill

SUITE = [
    ("xss_reflected_low", {}),
    ("xss_stored_low", {}),
    ("sqli_low", {}),
    # depois: ("command_injection_low", {}), ("csrf_low", {}), ("upload_low", {})
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    args = ap.parse_args()
    results = []
    ok_count = 0
    for skill, kwargs in SUITE:
        res = run_skill(args.target, skill)
        results.append((skill, res))
        ok_count += 1 if res.get("ok") else 0
        print(f"[{skill}] -> {'OK' if res.get('ok') else 'FAIL'}")
    print(f"\nScore: {ok_count}/{len(SUITE)}")
    print(json.dumps({k: v for k, v in results}, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
