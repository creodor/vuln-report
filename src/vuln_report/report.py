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
        f"Analysis mode: `{_analysis_mode(triage)}`",
        "",
        "## Metrics",
        "",
        f"- Total Trivy findings ingested: `{metrics['total_findings']}`",
        f"- Findings sent to analyzer: `{metrics['findings_sent_to_analyzer']}`",
        f"- Included severities: `{', '.join(metrics.get('included_severities', []))}`",
        f"- Findings omitted by severity filter: `{metrics.get('findings_omitted_by_severity', 0)}`",
        f"- Findings requiring human review: `{len(review_findings)}`",
        f"- Findings with a reported fix: `{metrics['fix_available_count']}`",
        f"- Findings without a reported fix: `{metrics['fix_unavailable_count']}`",
        f"- Average recommendation confidence: `{average_confidence}`",
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
            f"- Estimated cost USD: `{_format_estimated_cost(usage)}`",
            "",
            "## Human review queue",
            "",
        ]
    )

    if review_findings:
        lines.extend(["| CVE | Package | Severity | Reason | Recommendation confidence |", "| --- | --- | --- | --- | ---: |"])
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

    lines.extend(_render_remediation_groups(findings))

    lines.extend(
        [
            "",
            "## Top affected packages",
            "",
            "| Package | Analyzed findings |",
            "| --- | ---: |",
        ]
    )
    for package, count in package_counts.most_common(10):
        lines.append(f"| `{package}` | {count} |")

    lines.extend(_render_prioritized_findings(findings))

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


def _render_prioritized_findings(findings: list[dict]) -> list[str]:
    lines = ["", "## Prioritized findings", ""]

    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. {finding.get('id')} in `{finding.get('package')}`",
                    "",
                    f"- Severity: `{finding.get('severity')}`",
                    f"- Recommendation confidence: `{finding.get('confidence')}` ({finding.get('confidence_label')})",
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
    return lines


def _link_cve(cve_id: str | None) -> str:
    if not cve_id:
        return ""
    if cve_id.startswith("CVE-"):
        return f"[{cve_id}](https://www.cve.org/CVERecord?id={cve_id})"
    return cve_id


def _render_remediation_groups(findings: list[dict]) -> list[str]:
    lines = ["", "## Recommended remediation groups", ""]
    groups = _remediation_groups(findings)
    if not groups:
        lines.append("No remediation groups were generated.")
        return lines

    lines.extend(
        [
            "| Remediation | Package | Findings | Highest severity | Human review | Affected CVEs |",
            "| --- | --- | ---: | --- | --- | --- |",
        ]
    )
    for group in groups:
        cves = ", ".join(_link_cve(finding.get("id")) for finding in group["findings"])
        review_required = any(finding.get("human_review_required") for finding in group["findings"])
        lines.append(
            "| {action} | `{package}` | {count} | {severity} | {review} | {cves} |".format(
                action=_escape(group["action"]),
                package=_escape(group["package"]),
                count=len(group["findings"]),
                severity=group["highest_severity"],
                review="yes" if review_required else "no",
                cves=_escape(cves),
            )
        )
    return lines


def _remediation_groups(findings: list[dict]) -> list[dict]:
    groups = {}
    for finding in findings:
        key = _remediation_key(finding)
        if key not in groups:
            groups[key] = {
                "package": finding.get("package") or "unknown",
                "action": finding.get("recommended_action") or "Review finding manually.",
                "findings": [],
            }
        groups[key]["findings"].append(finding)

    grouped = []
    for group in groups.values():
        group["findings"].sort(key=lambda item: item.get("id") or "")
        group["highest_severity"] = _highest_severity(group["findings"])
        grouped.append(group)

    grouped.sort(
        key=lambda group: (
            _severity_rank(group["highest_severity"]),
            len(group["findings"]),
            group["package"],
        ),
        reverse=True,
    )
    return grouped


def _remediation_key(finding: dict) -> tuple[str, str, str]:
    package = finding.get("package") or "unknown"
    fixed_version = finding.get("fixed_version") or ""
    action = finding.get("recommended_action") or "Review finding manually."
    if action:
        return (package, "", action)
    return (package, fixed_version, "")


def _highest_severity(findings: list[dict]) -> str:
    return max((finding.get("severity") or "UNKNOWN" for finding in findings), key=_severity_rank)


def _severity_rank(severity: str) -> int:
    return {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "UNKNOWN": 1,
    }.get(severity, 0)


def _format_estimated_cost(usage: dict) -> str:
    cost = usage.get("estimated_cost_usd")
    note = usage.get("estimated_cost_note")
    if cost is None:
        return note or "unavailable: pricing was not calculated"
    if note:
        return f"{cost:.6f} ({note})"
    return f"{cost:.6f}"


def _analysis_mode(triage: dict) -> str:
    status = triage.get("analysis_status") or {}
    mode = status.get("mode") or triage.get("run", {}).get("analyzer") or "unknown"
    message = status.get("message")
    if message:
        return f"{mode} - {message}"
    return mode


def _escape(value: str) -> str:
    return value.replace("|", "\\|")
