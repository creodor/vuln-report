# Planning Log

## Problem selection

- Considered compliance framework report generation.
  - Rejected for the assignment scope because reliable evidence mapping and framework-specific assertions would need more integrations and validation than a 2-4 hour demo should carry.
- Considered general security posture analysis.
  - Rejected for the MVP because useful posture analysis depends on cloud, source, identity, CI/CD, and policy context.
- Considered SAST finding triage.
  - Deferred because findings vary heavily by scanner, language, rule pack, and local code context.
- Chose Trivy CVE triage for container images.
  - The input is structured, common in CI, and directly maps to vulnerability response work: intake, prioritization, owner-ready reporting, and remediation tracking.

## Design decisions

- Normalize Trivy JSON before sending anything to the analyzer.
  - This reduces noisy scanner metadata, lowers token usage, and creates a stable contract that can be tested.
- Make Markdown the primary human artifact.
  - Async security work needs a reviewable written output that can be attached to issues, audit trails, or customer-facing follow-up.
- Keep raw, normalized, and analyzed JSON as artifacts.
  - The report is human-readable, but the intermediate data should remain machine-readable for later routing, metrics, Jira creation, Slack summaries, or dashboards.
- Require human review for critical findings, low-confidence analysis, missing fixed versions, and likely high-impact exploitability terms.
  - The LLM accelerates triage but should not silently become the authority for closure.
- Avoid auto-remediation.
  - Remediation requires owner context, compatibility testing, and release judgment that are outside this assignment scope.
- Split large LLM analysis into chunks.
  - Large structured responses caused omissions even with stronger models, so the tool now keeps per-finding coverage while limiting each OpenRouter call to a smaller batch.
- Keep analysis mode visible in the report.
  - If OpenRouter fails and local rules are used, the report records that fallback near the executive summary so a reviewer can immediately tell what kind of analysis they are reading.
- Estimate cost from OpenRouter model pricing.
  - The tool uses OpenRouter's models endpoint when token usage is returned and clearly reports when pricing is unavailable.

## Follow-up improvements

- Add Jira routing based on package owner metadata.
- Add Slack summaries with links to artifacts.
- Add multi-model or retry analysis only for high-risk findings.
- Enrich findings with EPSS, KEV, or vendor advisories.
- Track SLA windows and generate overdue remediation reports.
- Pin Trivy source image by digest or verify a downloaded Trivy release artifact
  with signature/checksum validation.
