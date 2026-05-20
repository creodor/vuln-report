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

Build the reporter image:

```powershell
docker build -t vuln-report .
```

The Dockerfile copies the Trivy binary from the official `aquasec/trivy` image
using a pinned `TRIVY_VERSION` build argument. This keeps local image scanning
self-contained while avoiding a floating `latest` scanner dependency.

Why this approach:

- Trivy's official installation docs list the `aquasec/trivy` container image
  and GitHub release binary as official installation methods.
- A multi-stage copy keeps the reporter image self-contained without piping an
  install script into a shell during the build.
- The version is pinned for reproducibility; a production hardening pass would
  pin the source image by digest or download and verify the release checksum.
- Docker Compose is intentionally not used because the reporter and scanner are
  short-lived CLI tools, not cooperating long-running services.

Run against the included sample fixture:

```powershell
docker run --rm `
  -v ${PWD}/fixtures:/input `
  -v ${PWD}/reports:/reports `
  vuln-report --input /input/trivy-example.json --output-dir /reports --offline
```

Run against a container image:

```powershell
docker run --rm `
  -v ${PWD}/reports:/reports `
  vuln-report --image python:3.9.0-slim-buster --output-dir /reports --offline
```

Use OpenRouter for LLM-assisted triage:

```powershell
$env:OPENROUTER_API_KEY="..."
docker run --rm `
  -e OPENROUTER_API_KEY=$env:OPENROUTER_API_KEY `
  -v ${PWD}/fixtures:/input `
  -v ${PWD}/reports:/reports `
  vuln-report --input /input/trivy-example.json --output-dir /reports --model openrouter/free
```

## GitHub Actions

The workflow in `.github/workflows/vulnerability-report.yml` supports:

- Manual runs with a target image input
- Push runs against a default demo image
- Docker image build from this repo's `Dockerfile`
- Tests run inside the built container
- Artifact upload for all generated reports
- Optional OpenRouter use through the `OPENROUTER_API_KEY` repository secret
- Default model set to `openrouter/free` for zero-cost demo runs

The scheduled trigger is included as a commented example but is disabled for
demo cost control.

## Tests

The tests run inside the Docker image:

```powershell
docker run --rm --entrypoint python vuln-report -m unittest discover -s tests
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
