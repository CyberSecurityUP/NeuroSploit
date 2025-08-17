import argparse, json, os
from .config import settings
from .agent.orchestrator import run_skill

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=False, default=settings.dvwa_url_env or "http://localhost:8080")
    ap.add_argument('--skill', required=True, choices=['login','xss_reflected_low','sqli_low', 'xss_stored_low', 'xss_dom_low'])
    args = ap.parse_args()

    result = run_skill(args.target, args.skill)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
