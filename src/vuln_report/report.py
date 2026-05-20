from __future__ import annotations

from collections import Counter


def render_markdown_report(title: str, normalized: dict, triage: dict) -> str:
    metrics = normalized["metrics"]
    findings = triage.get("findings", [])
    review_findings = [finding for finding in findings if finding.get("human_review_required")]
    confidence_values = [
        finding.get("confidence")
        for finding in findings
        if isinstance(finding.get("confidence"), (int, float))
    ]
    average_confidence = (
        round(sum(confidence_values) / len(confidence_values), 3)
        if confidence_values
        else "n/a"
    )
    package_counts = Counter(finding.get("package") for finding in findings)

    lines = [
        f"# {title}",
        "",
        f"Generated: `{normalized.get('generated_at')}`",
        f"Scan source: `{normalized.get('scan_source')}`",
        f"Analyzer: `{triage.get('run', {}).get('analyzer')}`",
        "",
        "## Executive summary",
        "",
        triage.get("summary") or "No summary was provided.",
        "",
        "## Metrics",
        "",
        f"- Total Trivy findings ingested: `{metrics['total_findings']}`",
        f"- Findings sent to analyzer: `{metrics['findings_sent_to_analyzer']}`",
        f"- Findings omitted by limit: `{metrics['findings_omitted_by_limit']}`",
        f"- Findings requiring human review: `{len(review_findings)}`",
        f"- Findings with a reported fix: `{metrics['fix_available_count']}`",
        f"- Findings without a reported fix: `{metrics['fix_unavailable_count']}`",
        f"- Average confidence: `{average_confidence}`",
        f"- LLM/runtime seconds: `{triage.get('run', {}).get('llm_runtime_seconds')}`",
        f"- Total runtime seconds: `{triage.get('run', {}).get('total_runtime_seconds')}`",
        "",
        "### Severity counts",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity, count in metrics["severity_counts"].items():
        lines.append(f"| {severity} | {count} |")

    usage = triage.get("usage", {})
    lines.extend(
        [
            "",
            "### Analyzer usage",
            "",
            f"- Prompt tokens: `{usage.get('prompt_tokens')}`",
            f"- Completion tokens: `{usage.get('completion_tokens')}`",
            f"- Total tokens: `{usage.get('total_tokens')}`",
            f"- Estimated cost USD: `{usage.get('estimated_cost_usd')}`",
            "",
            "## Human review queue",
            "",
        ]
    )

    if review_findings:
        lines.extend(["| CVE | Package | Severity | Reason | Confidence |", "| --- | --- | --- | --- | ---: |"])
        for finding in review_findings:
            lines.append(
                "| {id} | {package} | {severity} | {reason} | {confidence} |".format(
                    id=_link_cve(finding.get("id")),
                    package=finding.get("package") or "",
                    severity=finding.get("severity") or "",
                    reason=_escape(finding.get("human_review_reason") or ""),
                    confidence=finding.get("confidence", ""),
                )
            )
    else:
        lines.append("No findings crossed the configured human-review gates.")

    lines.extend(
        [
            "",
            "## Prioritized findings",
            "",
        ]
    )

    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. {finding.get('id')} in `{finding.get('package')}`",
                    "",
                    f"- Severity: `{finding.get('severity')}`",
                    f"- Confidence: `{finding.get('confidence')}` ({finding.get('confidence_label')})",
                    f"- Human review required: `{finding.get('human_review_required')}`",
                    f"- Risk summary: {finding.get('risk_summary')}",
                    f"- Exploitability notes: {finding.get('exploitability_notes')}",
                    f"- Recommended action: {finding.get('recommended_action')}",
                    f"- Confidence rationale: {finding.get('confidence_rationale')}",
                    "",
                ]
            )
    else:
        lines.append("No findings were analyzed.")

    lines.extend(
        [
            "## Top affected packages",
            "",
            "| Package | Analyzed findings |",
            "| --- | ---: |",
        ]
    )
    for package, count in package_counts.most_common(10):
        lines.append(f"| `{package}` | {count} |")

    warnings = triage.get("warnings", [])
    lines.extend(["", "## Caveats and validation notes", ""])
    if warnings:
        for warning in warnings:
            lines.append(f"- {warning}")
    lines.extend(
        [
            "- Scanner severity is not the same as product risk; validate package reachability, runtime exposure, and compensating controls.",
            "- This tool does not perform automatic remediation or suppress findings.",
            "- Critical findings and low-confidence analysis are intentionally routed to human review.",
            "",
        ]
    )
    return "\n".join(lines)


def _link_cve(cve_id: str | None) -> str:
    if not cve_id:
        return ""
    if cve_id.startswith("CVE-"):
        return f"[{cve_id}](https://www.cve.org/CVERecord?id={cve_id})"
    return cve_id


def _escape(value: str) -> str:
    return value.replace("|", "\\|")

