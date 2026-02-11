"""
NeuroSploit v3 - Execution History

Tracks attack success/failure patterns across scans to learn what works.
Records technology-to-vulnerability-type mappings with success rates.
Used by the AI to prioritize tests based on historical data.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ExecutionHistory:
    """Tracks which attacks work against which technologies across scans."""

    MAX_ATTACKS = 500  # Keep last N attack records

    def __init__(self, history_file: str = "data/execution_history.json"):
        self.history_file = Path(history_file)
        self._attacks: List[Dict] = []
        # tech_lower -> vuln_type -> {"success": int, "fail": int}
        self._tech_success: Dict[str, Dict[str, Dict[str, int]]] = {}
        self._dirty = False
        self._load()

    def _load(self):
        """Load execution history from disk."""
        if not self.history_file.exists():
            return
        try:
            data = json.loads(self.history_file.read_text())
            self._attacks = data.get("attacks", [])
            for tech, vulns in data.get("tech_success", {}).items():
                self._tech_success[tech] = {}
                for vuln, counts in vulns.items():
                    self._tech_success[tech][vuln] = {
                        "success": counts.get("success", 0),
                        "fail": counts.get("fail", 0),
                    }
            logger.info(f"Loaded execution history: {len(self._attacks)} attacks, "
                        f"{len(self._tech_success)} technologies tracked")
        except Exception as e:
            logger.warning(f"Failed to load execution history: {e}")

    def _save(self):
        """Persist execution history to disk."""
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            self.history_file.write_text(json.dumps({
                "attacks": self._attacks[-self.MAX_ATTACKS:],
                "tech_success": self._tech_success,
                "saved_at": datetime.utcnow().isoformat(),
            }, indent=2, default=str))
            self._dirty = False
        except Exception as e:
            logger.warning(f"Failed to save execution history: {e}")

    def record(self, tech_stack: List[str], vuln_type: str,
               target: str, success: bool, evidence: str = ""):
        """Record an attack attempt result."""
        if not vuln_type:
            return

        # Record the individual attack
        try:
            domain = urlparse(target).netloc if target else ""
        except Exception:
            domain = ""

        self._attacks.append({
            "tech": [t[:50] for t in tech_stack[:5]],
            "vuln_type": vuln_type,
            "target_domain": domain,
            "success": success,
            "evidence_preview": (evidence or "")[:100],
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Update aggregated tech_success counters
        key = "success" if success else "fail"
        for tech in tech_stack[:5]:
            tech_lower = tech.lower().strip()
            if not tech_lower:
                continue
            if tech_lower not in self._tech_success:
                self._tech_success[tech_lower] = {}
            if vuln_type not in self._tech_success[tech_lower]:
                self._tech_success[tech_lower][vuln_type] = {"success": 0, "fail": 0}
            self._tech_success[tech_lower][vuln_type][key] += 1

        # Auto-save periodically (every 20 records)
        self._dirty = True
        if len(self._attacks) % 20 == 0:
            self._save()

    def flush(self):
        """Force save if there are unsaved changes."""
        if self._dirty:
            self._save()

    def get_priority_types(self, tech_stack: List[str], top_n: int = 15) -> List[str]:
        """Get vuln types most likely to succeed based on tech stack history."""
        scores: Dict[str, float] = defaultdict(float)

        for tech in tech_stack:
            tech_lower = tech.lower().strip()
            if tech_lower not in self._tech_success:
                continue
            for vuln_type, counts in self._tech_success[tech_lower].items():
                total = counts.get("success", 0) + counts.get("fail", 0)
                if total < 2:
                    continue  # Need at least 2 data points
                rate = counts.get("success", 0) / total
                # Weight by both success rate and volume
                scores[vuln_type] += rate * total

        sorted_types = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return [t[0] for t in sorted_types[:top_n]]

    def get_stats_for_prompt(self, tech_stack: List[str]) -> str:
        """Format execution history as context for AI prompts."""
        lines = []
        for tech in tech_stack[:5]:
            tech_lower = tech.lower().strip()
            if tech_lower not in self._tech_success:
                continue
            vulns = self._tech_success[tech_lower]
            top = sorted(
                vulns.items(),
                key=lambda x: x[1].get("success", 0),
                reverse=True
            )[:5]
            if top:
                entries = []
                for v, c in top:
                    s = c.get("success", 0)
                    total = s + c.get("fail", 0)
                    entries.append(f"{v}({s}/{total})")
                lines.append(f"  {tech}: {', '.join(entries)}")

        return "\n".join(lines) if lines else "  No historical data yet"

    def get_total_attacks(self) -> int:
        """Get total number of recorded attacks."""
        return len(self._attacks)

    def get_success_rate(self) -> float:
        """Get overall success rate."""
        if not self._attacks:
            return 0.0
        successes = sum(1 for a in self._attacks if a.get("success"))
        return successes / len(self._attacks)
