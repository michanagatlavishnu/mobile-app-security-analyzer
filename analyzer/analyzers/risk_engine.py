"""
Risk Scoring Engine
Calculates transparent 0-100 security score derived from verified findings.
Risk Levels:
90-100: LOW
70-89:  MEDIUM
40-69:  HIGH
0-39:   CRITICAL
"""

from typing import Dict, Any, List

# Deductions per verified finding severity
SEVERITY_DEDUCTIONS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFORMATIONAL": 0
}

def calculate_security_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    score = 100
    breakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0
    }

    for finding in findings:
        sev = (finding.get("severity") or "INFORMATIONAL").upper()
        if sev == "CRITICAL":
            breakdown["critical"] += 1
            score -= SEVERITY_DEDUCTIONS["CRITICAL"]
        elif sev == "HIGH":
            breakdown["high"] += 1
            score -= SEVERITY_DEDUCTIONS["HIGH"]
        elif sev == "MEDIUM":
            breakdown["medium"] += 1
            score -= SEVERITY_DEDUCTIONS["MEDIUM"]
        elif sev == "LOW":
            breakdown["low"] += 1
            score -= SEVERITY_DEDUCTIONS["LOW"]
        else:
            breakdown["informational"] += 1

    # Clamp score to [0, 100]
    score = max(0, min(100, score))

    if score >= 90:
        risk_level = "LOW"
    elif score >= 70:
        risk_level = "MEDIUM"
    elif score >= 40:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "score": score,
        "risk_level": risk_level,
        "breakdown": breakdown
    }
