"""
Stage 7: Risk Score Calculation
Combines every finding from every module using a severity-weighted
formula, then compresses the result through a sigmoid function so
no single finding (or flood of trivial findings) can unfairly
dominate the final score.
"""

import math

SEVERITY_WEIGHTS = {
    "CRITICAL": 32,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}

SEVERITY_MULTIPLIERS = {
    "CRITICAL": 1.5,
    "HIGH": 1.0,
    "MEDIUM": 0.6,
    "LOW": 0.3,
    "INFO": 0.0,
}


def _sigmoid_compress(raw_sum, midpoint=40, steepness=0.09):
    """Map an unbounded weighted sum onto a 0-100 scale."""
    value = 1 / (1 + math.exp(-steepness * (raw_sum - midpoint)))
    return round(value * 100, 1)


def calculate_risk_score(all_findings):
    raw_sum = 0.0
    severity_counts = {k: 0 for k in SEVERITY_WEIGHTS}

    for finding in all_findings:
        sev = finding.get("severity", "INFO").upper()
        weight = finding.get("weight", SEVERITY_WEIGHTS.get(sev, 0))
        multiplier = SEVERITY_MULTIPLIERS.get(sev, 0.0)
        raw_sum += weight * multiplier
        if sev in severity_counts:
            severity_counts[sev] += 1

    score = _sigmoid_compress(raw_sum)
    label = score_to_label(score)

    per_module = {}
    for finding in all_findings:
        mod = finding.get("module", "unknown")
        sev = finding.get("severity", "INFO").upper()
        weight = finding.get("weight", SEVERITY_WEIGHTS.get(sev, 0))
        multiplier = SEVERITY_MULTIPLIERS.get(sev, 0.0)
        per_module[mod] = per_module.get(mod, 0.0) + weight * multiplier

    return {
        "score": score,
        "label": label,
        "raw_weighted_sum": round(raw_sum, 1),
        "severity_counts": severity_counts,
        "per_module_contribution": {k: round(v, 1) for k, v in per_module.items()},
    }


def score_to_label(score):
    if score == 0:
        return "Clean"
    if score < 25:
        return "Low"
    if score < 50:
        return "Medium"
    if score < 80:
        return "High"
    return "Critical"
