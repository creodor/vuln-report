# vuln-report

`vuln-report` turns Trivy container vulnerability output into a reviewer-ready
Markdown triage report with structured JSON artifacts, confidence scoring, and
human-review gates.

It is intentionally small: the goal is to reduce the repetitive work between
scanner output and a remediation decision, not to replace security judgment.

## What it builds

Input:

- A container image, scanned through Trivy's Docker image, or
- An existing Trivy JSON report

Output:

- `reports/trivy-raw.json`
- `reports/normalized-findings.json`
- `reports/triage.json`
- `reports/vulnerability-report.md`

## Quick start

Run against the included sample fixture:

```powershell
python -m pip install -e .
vuln-report --input fixtures/trivy-example.json --offline
```

Run against a container image with Trivy via Docker:

```powershell
vuln-report --image python:3.9.0-slim-buster --offline
```

Use OpenRouter for LLM-assisted triage:

```powershell
$env:OPENROUTER_API_KEY="..."
vuln-report --input fixtures/trivy-example.json --model openai/gpt-4.1-mini
```

## GitHub Actions

The workflow in `.github/workflows/vulnerability-report.yml` supports:

- Manual runs with a target image input
- Push runs against a default demo image
- Artifact upload for all generated reports
- Optional OpenRouter use through the `OPENROUTER_API_KEY` repository secret

The scheduled trigger is included as a commented example but is disabled for
demo cost control.

## Tests

The tests use Python's standard library:

```powershell
$env:PYTHONPATH="src"
python -m unittest discover -s tests
```

## AI guardrails

- Trivy output is normalized before analysis to reduce noisy input and token use.
- The analyzer must return structured JSON.
- Critical findings always require human review.
- Findings without fixed versions require human review.
- Low-confidence analysis requires human review.
- The tool does not perform automatic remediation or suppress findings.

If `OPENROUTER_API_KEY` is not present, the tool uses deterministic local rules
and clearly marks that in the output.

## Why this problem

Vulnerability scanners are easy to run and hard to operationalize. A solo
security/compliance owner needs repeatable intake, prioritization, written
status, and evidence artifacts that can move across GitHub Actions, Jira, Slack,
audits, and customer-facing conversations.

This MVP focuses on the handoff from raw CVE output to an owner-readable report.
The same artifact structure can later support routing, SLA tracking, dashboards,
or compliance evidence.

## Planning log

See [PLANNING.md](PLANNING.md) for the decision log, rejected ideas, and follow-up
improvements.
