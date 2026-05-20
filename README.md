# vuln-report

`vuln-report` turns Trivy container vulnerability output into a reviewer-ready
Markdown triage report with structured JSON artifacts, confidence scoring, and
human-review gates.

It is intentionally small: the goal is to reduce the repetitive work between
scanner output and a remediation decision, not to replace security judgment.

## What it builds

Input:

- A container image, scanned by Trivy, or
- An existing Trivy JSON report

Output:

- `reports/<timestamp>-trivy-raw.json`
- `reports/<timestamp>-normalized-findings.json`
- `reports/<timestamp>-triage.json`
- `reports/<timestamp>-vulnerability-report.md`
- `reports/vulnerability-report.md` as a stable copy for GitHub job summaries

## Quick start

Build the reporter image:

```bash
docker build -t vuln-report .
```

Run against the included sample fixture:

```bash
docker run --rm \
  -v "$(pwd)/fixtures:/input" \
  -v "$(pwd)/reports:/reports" \
  vuln-report --input /input/trivy-example.json --output-dir /reports --offline
```

Run against a container image:

```bash
docker run --rm \
  -v "$(pwd)/reports:/reports" \
  vuln-report --image python:3.9.0-slim-buster --output-dir /reports --offline
```

Use OpenRouter for LLM-assisted triage:

```bash
export OPENROUTER_API_KEY="..."
docker run --rm \
  -e OPENROUTER_API_KEY="$OPENROUTER_API_KEY" \
  -v "$(pwd)/fixtures:/input" \
  -v "$(pwd)/reports:/reports" \
  vuln-report --input /input/trivy-example.json --output-dir /reports
```

## GitHub Actions

The workflow in `.github/workflows/vulnerability-report.yml` supports:

- Manual runs with a target image input
- Push runs against a default demo image
- Pull request runs targeting `main`
- Docker image build from this repo's `Dockerfile`
- Tests run inside the built container
- Artifact upload for all generated reports
- Optional OpenRouter use through the `OPENROUTER_API_KEY` repository secret
- Default model set to `z-ai/glm-4.5-air:free` for zero-cost demo runs

To enable LLM-assisted reports in GitHub Actions, create a repository secret:

- Name: `OPENROUTER_API_KEY`
- Value: an OpenRouter API key

Optional repository variable:

- `TRIVY_VERSION`: overrides the Trivy version used when building the reporter
  image. The workflow defaults to `0.70.0` if this variable is not set.

Manual workflow inputs:

- `image`: container image to scan. Defaults to `python:3.9.0-slim-buster`.
- `model`: OpenRouter model. Defaults to `z-ai/glm-4.5-air:free`.
- `include_severities`: comma-separated severities sent to analysis. Defaults
  to `CRITICAL,HIGH`.
- `llm_chunk_size`: maximum findings per OpenRouter call. Defaults to `25`.

The scheduled trigger is included as a commented example but is disabled for
demo cost control.

In CI, Trivy scanning and report generation are deliberately separate steps:
the official Trivy Action produces `reports/trivy-raw.json`, then the
containerized reporter converts that raw scanner output into normalized JSON,
triage JSON, and Markdown.

The report generation step prints phase-level progress only: input source,
normalization counts, analyzer selection, and artifact paths. It avoids logging
raw findings, prompts, model output, or secrets.

## CLI options

- `--input`: analyze an existing Trivy JSON report.
- `--image`: scan a container image with Trivy, then analyze the result.
- `--output-dir`: directory for `trivy-raw.json`, `normalized-findings.json`,
  `triage.json`, and `vulnerability-report.md` artifacts. Generated artifacts
  are timestamped, with `vulnerability-report.md` also written as a stable copy
  for GitHub job summaries.
- `--model`: OpenRouter model name. Defaults to `z-ai/glm-4.5-air:free`.
- `--include-severities`: comma-separated severities sent to the analyzer.
  Defaults to `CRITICAL,HIGH`.
- `--confidence-threshold`: confidence value below which human review is
  required. Defaults to `0.70`.
- `--llm-chunk-size`: maximum findings per OpenRouter call. Defaults to `25`.
- `--offline`: skip OpenRouter and use deterministic local rules.
- `--require-llm`: fail if OpenRouter is unavailable or returns unusable output.

## Tests

The tests run inside the Docker image:

```bash
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

`confidence` means confidence in the generated triage recommendation for a
finding: the risk summary, exploitability notes, and recommended action based on
the supplied Trivy data. In LLM mode this value is supplied by the model and then
checked by deterministic guardrails. In offline fallback mode it is rule-derived
and labeled in the confidence rationale.

The script decides which findings are analyzed. It filters Trivy findings by
severity, defaulting to `CRITICAL,HIGH`, then sorts those findings by severity,
fix availability, and CVE id. The final triage JSON and Markdown report include
exactly one entry for each finding sent to the analyzer. If the model omits a
finding, the script adds a low-confidence human-review fallback entry instead of
silently dropping it.

The Markdown report also groups findings that share the same package/fixed
version or remediation action. This keeps the human-facing report focused on
work to be done while preserving per-CVE traceability in the detailed findings
and `triage.json`.

When more findings are selected than `--llm-chunk-size`, the tool splits
OpenRouter analysis into multiple calls. This reduces the chance that a model
truncates or omits findings in a very large structured response.

OpenRouter token usage is recorded when the provider returns it. Estimated cost
is calculated from OpenRouter's `/models` pricing endpoint and cached for the
duration of the run. If pricing cannot be retrieved, the report shows an explicit
unavailable reason instead of implying that the run was free.

## Dockerfile Trivy Inclusion
The Dockerfile copies the Trivy binary from the official `aquasec/trivy` image
using a pinned `TRIVY_VERSION` build argument. This keeps local image scanning
self-contained while avoiding a floating `latest` scanner dependency.

In GitHub Actions, `TRIVY_VERSION` can be overridden with a repository variable
named `TRIVY_VERSION`. If the variable is not set, the workflow builds with the
Dockerfile default.

Why this approach:

- Trivy's official installation docs list the `aquasec/trivy` container image
  and GitHub release binary as official installation methods.
- A multi-stage copy keeps the reporter image self-contained without piping an
  install script into a shell during the build.
- The version is pinned for reproducibility; a production hardening pass would
  pin the source image by digest or download and verify the release checksum.
- Docker Compose is intentionally not used because the reporter and scanner are
  short-lived CLI tools, not cooperating long-running services.

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
