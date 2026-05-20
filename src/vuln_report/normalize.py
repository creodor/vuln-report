from __future__ import annotations

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "UNKNOWN": 1,
}


def normalize_trivy_report(report: dict, max_findings: int = 75) -> dict:
    findings = []
    severity_counts = {severity: 0 for severity in SEVERITY_RANK}
    fix_available = 0

    for result in report.get("Results", []):
        target = result.get("Target", "unknown")
        result_type = result.get("Type", "unknown")
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = (vuln.get("Severity") or "UNKNOWN").upper()
            severity_counts.setdefault(severity, 0)
            severity_counts[severity] += 1
            fixed_version = vuln.get("FixedVersion") or ""
            if fixed_version:
                fix_available += 1

            finding = {
                "id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": fixed_version,
                "severity": severity,
                "title": vuln.get("Title") or "",
                "description": _trim(vuln.get("Description") or "", 900),
                "primary_url": vuln.get("PrimaryURL") or "",
                "target": target,
                "type": result_type,
                "cvss": vuln.get("CVSS") or {},
                "published_date": vuln.get("PublishedDate") or "",
                "last_modified_date": vuln.get("LastModifiedDate") or "",
            }
            findings.append(finding)

    findings.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], 0),
            bool(item["fixed_version"]),
            item["id"] or "",
        ),
        reverse=True,
    )
    selected = findings[:max_findings]

    return {
        "scanner": {
            "name": "trivy",
            "artifact_name": report.get("ArtifactName"),
            "artifact_type": report.get("ArtifactType"),
            "schema_version": report.get("SchemaVersion"),
        },
        "metrics": {
            "total_findings": len(findings),
            "findings_sent_to_analyzer": len(selected),
            "findings_omitted_by_limit": max(len(findings) - len(selected), 0),
            "severity_counts": severity_counts,
            "fix_available_count": fix_available,
            "fix_unavailable_count": max(len(findings) - fix_available, 0),
        },
        "findings": selected,
    }


def _trim(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."
