from __future__ import annotations

from vuln_report.normalize import SEVERITY_RANK

REVIEW_TERMS = (
    "remote code execution",
    "rce",
    "auth bypass",
    "authentication bypass",
    "deserialization",
    "privilege escalation",
    "supply chain",
    "sandbox escape",
    "zero day",
    "0-day",
    "actively exploited",
    "known exploited",
)


def analyze_with_local_rules(normalized: dict, confidence_threshold: float) -> dict:
    analyzed = []
    warnings = ["Used deterministic local rules. Set OPENROUTER_API_KEY for LLM-assisted triage."]

    for finding in normalized["findings"]:
        text = " ".join(
            [
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("severity", ""),
            ]
        ).lower()
        severity = finding["severity"]
        has_fix = bool(finding.get("fixed_version"))
        keyword_review = any(term in text for term in REVIEW_TERMS)
        human_review = (
            SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["CRITICAL"]
            or not has_fix
            or keyword_review
        )
        confidence = 0.84 if has_fix else 0.66
        if human_review and confidence < confidence_threshold:
            confidence_label = "low"
        elif confidence >= 0.80:
            confidence_label = "medium"
        else:
            confidence_label = "borderline"

        analyzed.append(
            {
                "id": finding["id"],
                "package": finding["package"],
                "severity": severity,
                "risk_summary": _risk_summary(finding),
                "exploitability_notes": _exploitability_notes(finding, keyword_review),
                "recommended_action": _recommended_action(finding),
                "human_review_required": human_review,
                "human_review_reason": _review_reason(finding, keyword_review),
                "confidence": confidence,
                "confidence_label": confidence_label,
                "confidence_rationale": "Rule-derived confidence in the generated triage recommendation. Local rules can rank and route the finding, but they do not perform contextual exploitability analysis.",
            }
        )

    return {
        "summary": _summary(analyzed),
        "findings": analyzed,
        "warnings": warnings,
        "usage": {
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
            "estimated_cost_usd": None,
        },
    }


def _risk_summary(finding: dict) -> str:
    title = finding.get("title") or finding["id"]
    return f"{finding['severity']} vulnerability in {finding.get('package')} ({title})."


def _exploitability_notes(finding: dict, keyword_review: bool) -> str:
    if keyword_review:
        return "Description contains terms associated with high-impact exploitability; validate exposure and reachable code paths."
    return "No application context was provided, so exploitability should be validated against runtime exposure and package usage."


def _recommended_action(finding: dict) -> str:
    fixed_version = finding.get("fixed_version")
    if fixed_version:
        return f"Upgrade {finding.get('package')} from {finding.get('installed_version')} to {fixed_version} or later."
    return f"No fixed version was reported for {finding.get('package')}; assess compensating controls, exposure, and vendor guidance."


def _review_reason(finding: dict, keyword_review: bool) -> str:
    if finding["severity"] == "CRITICAL":
        return "Critical severity findings require human confirmation before closure."
    if not finding.get("fixed_version"):
        return "No fixed version was reported."
    if keyword_review:
        return "Finding text contains high-impact exploitability terms."
    return ""


def _summary(findings: list[dict]) -> str:
    review_count = sum(1 for finding in findings if finding["human_review_required"])
    return f"Analyzed {len(findings)} findings; {review_count} require human review."
