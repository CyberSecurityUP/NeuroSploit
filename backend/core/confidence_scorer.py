"""
NeuroSploit v3 - Confidence Scoring Engine

Numeric 0-100 confidence scoring for vulnerability findings.
Combines proof of execution, negative control results, and signal analysis
into a single score with transparent breakdown.

Score Thresholds:
    >= 90 → "confirmed" (AI Verified, high confidence)
    >= 60 → "likely" (needs manual review)
    <  60 → "rejected" (auto-reject, false positive)
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ConfidenceResult:
    """Result of confidence scoring."""
    score: int                       # 0-100
    verdict: str                     # "confirmed" | "likely" | "rejected"
    breakdown: Dict[str, int] = field(default_factory=dict)  # Component scores
    detail: str = ""                 # Human-readable explanation


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class ConfidenceScorer:
    """Calculates numeric confidence score 0-100 for vulnerability findings.

    Weights:
        +0-60  Proof of execution (per vuln type — the most important signal)
        +0-30  Proof of impact (severity-aware)
        +0-20  Negative controls passed (response differs from benign)
        -40    Only baseline diff signal (no actual proof of exploitation)
        -60    Same behavior on negative controls (critical false positive indicator)
        -40    AI interpretation says payload was ineffective
    """

    # Threshold constants
    THRESHOLD_CONFIRMED = 90
    THRESHOLD_LIKELY = 60

    # Weight caps
    MAX_PROOF_SCORE = 60
    MAX_IMPACT_SCORE = 30
    MAX_CONTROLS_BONUS = 20
    PENALTY_ONLY_DIFF = -40
    PENALTY_SAME_BEHAVIOR = -60
    PENALTY_AI_INEFFECTIVE = -40

    # Keywords in AI interpretation that indicate payload was ineffective
    INEFFECTIVE_KEYWORDS = [
        "ignored", "not processed", "blocked", "filtered",
        "sanitized", "rejected", "not executed", "was not",
        "does not", "did not", "no effect", "no impact",
        "benign", "safe", "harmless",
    ]

    def calculate(
        self,
        signals: List[str],
        proof_result,       # ProofResult from proof_of_execution
        control_result,     # NegativeControlResult from negative_control
        ai_interpretation: Optional[str] = None,
    ) -> ConfidenceResult:
        """Calculate confidence score from all verification components.

        Args:
            signals: List of signal names from multi_signal_verify
                     (e.g., ["baseline_diff", "payload_effect"])
            proof_result: ProofResult from ProofOfExecution.check()
            control_result: NegativeControlResult from NegativeControlEngine
            ai_interpretation: Optional AI response interpretation text

        Returns:
            ConfidenceResult with score, verdict, breakdown, and detail
        """
        breakdown: Dict[str, int] = {}
        score = 0

        # ── Component 1: Proof of Execution (0-60) ────────────────────
        proof_score = min(proof_result.score, self.MAX_PROOF_SCORE) if proof_result else 0
        score += proof_score
        breakdown["proof_of_execution"] = proof_score

        # ── Component 2: Proof of Impact (0-30) ───────────────────────
        impact_score = 0
        if proof_result and proof_result.proven:
            if proof_result.impact_demonstrated:
                impact_score = self.MAX_IMPACT_SCORE  # Full impact shown
            else:
                impact_score = 15  # Proven but no impact demonstration
        score += impact_score
        breakdown["proof_of_impact"] = impact_score

        # ── Component 3: Negative Controls (bonus/penalty) ─────────────
        controls_score = 0
        if control_result:
            if control_result.same_behavior:
                controls_score = self.PENALTY_SAME_BEHAVIOR  # -60
            else:
                controls_score = min(
                    self.MAX_CONTROLS_BONUS,
                    control_result.confidence_adjustment
                )  # +20
        score += controls_score
        breakdown["negative_controls"] = controls_score

        # ── Penalty: Only baseline diff signal ─────────────────────────
        diff_penalty = 0
        if signals and set(signals) <= {"baseline_diff", "new_errors"}:
            # Only diff-based signals, no actual payload effect
            if proof_score == 0:
                diff_penalty = self.PENALTY_ONLY_DIFF  # -40
                score += diff_penalty
        breakdown["diff_only_penalty"] = diff_penalty

        # ── Penalty: AI says payload was ineffective ──────────────────
        ai_penalty = 0
        if ai_interpretation:
            ai_lower = ai_interpretation.lower()
            if any(kw in ai_lower for kw in self.INEFFECTIVE_KEYWORDS):
                ai_penalty = self.PENALTY_AI_INEFFECTIVE  # -40
                score += ai_penalty
        breakdown["ai_ineffective_penalty"] = ai_penalty

        # ── Clamp and determine verdict ────────────────────────────────
        score = max(0, min(100, score))

        if score >= self.THRESHOLD_CONFIRMED:
            verdict = "confirmed"
        elif score >= self.THRESHOLD_LIKELY:
            verdict = "likely"
        else:
            verdict = "rejected"

        # Build detail string
        detail_parts = []
        if proof_result and proof_result.proven:
            detail_parts.append(f"Proof: {proof_result.proof_type} ({proof_score}pts)")
        else:
            detail_parts.append("No proof of execution (0pts)")

        if impact_score > 0:
            detail_parts.append(f"Impact: +{impact_score}pts")

        if control_result:
            if control_result.same_behavior:
                detail_parts.append(
                    f"NEGATIVE CONTROL FAIL: {control_result.controls_matching}/"
                    f"{control_result.controls_run} same behavior ({controls_score}pts)")
            else:
                detail_parts.append(f"Controls passed (+{controls_score}pts)")

        if diff_penalty:
            detail_parts.append(f"Only-diff penalty ({diff_penalty}pts)")

        if ai_penalty:
            detail_parts.append(f"AI-ineffective penalty ({ai_penalty}pts)")

        detail = f"Score: {score}/100 [{verdict}] — " + "; ".join(detail_parts)

        return ConfidenceResult(
            score=score,
            verdict=verdict,
            breakdown=breakdown,
            detail=detail,
        )
