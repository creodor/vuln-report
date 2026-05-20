from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

from vuln_report.llm import OpenRouterError, analyze_with_openrouter
from vuln_report.normalize import normalize_trivy_report
from vuln_report.report import render_markdown_report
from vuln_report.triage import analyze_with_local_rules
from vuln_report.trivy import run_trivy_image_scan


DEFAULT_MODEL = "z-ai/glm-4.5-air:free"
DEFAULT_INCLUDED_SEVERITIES = "CRITICAL,HIGH"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-report",
        description="Turn Trivy JSON into a reviewer-ready vulnerability triage report.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="Path to an existing Trivy JSON report.")
    source.add_argument("--image", help="Container image to scan with Trivy.")

    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--model", default=os.getenv("OPENROUTER_MODEL", DEFAULT_MODEL))
    parser.add_argument(
        "--include-severities",
        default=DEFAULT_INCLUDED_SEVERITIES,
        help="Comma-separated severities to analyze. Defaults to CRITICAL,HIGH.",
    )
    parser.add_argument("--confidence-threshold", type=float, default=0.70)
    parser.add_argument("--require-llm", action="store_true", help="Fail instead of using local fallback.")
    parser.add_argument("--offline", action="store_true", help="Skip LLM calls and use deterministic local rules.")
    parser.add_argument("--report-title", default="Vulnerability Triage Report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    started_at = time.time()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    raw_path = args.output_dir / "trivy-raw.json"
    normalized_path = args.output_dir / "normalized-findings.json"
    triage_path = args.output_dir / "triage.json"
    report_path = args.output_dir / "vulnerability-report.md"

    if args.image:
        _log(f"Scanning image with Trivy: {args.image}")
        run_trivy_image_scan(args.image, raw_path)
        scan_source = args.image
    else:
        if not args.input.exists():
            print(f"Input report not found: {args.input}", file=sys.stderr)
            return 2
        _log(f"Using existing Trivy report: {args.input}")
        _copy_unless_same_file(args.input, raw_path)
        scan_source = str(args.input)

    _log("Normalizing Trivy findings")
    raw_report = _read_json(raw_path)
    try:
        normalized = normalize_trivy_report(raw_report, included_severities=_parse_severities(args.include_severities))
    except ValueError as exc:
        print(f"Invalid severity filter: {exc}", file=sys.stderr)
        return 2
    normalized["scan_source"] = scan_source
    normalized["generated_at"] = _utc_timestamp()
    _write_json(normalized_path, normalized)
    _log(
        "Prepared "
        f"{normalized['metrics']['findings_sent_to_analyzer']} of "
        f"{normalized['metrics']['total_findings']} findings for analysis"
    )

    api_key = os.getenv("OPENROUTER_API_KEY")
    analyzer_started = time.time()
    analyzer = "local-rules"

    if args.offline or not api_key:
        if args.require_llm:
            print("OPENROUTER_API_KEY is required when --require-llm is set.", file=sys.stderr)
            return 3
        _log("Analyzing findings with deterministic local rules")
        triage = analyze_with_local_rules(normalized, args.confidence_threshold)
    else:
        try:
            _log(f"Analyzing findings with OpenRouter model: {args.model}")
            triage = analyze_with_openrouter(
                normalized,
                api_key=api_key,
                model=args.model,
                confidence_threshold=args.confidence_threshold,
            )
            analyzer = f"openrouter:{args.model}"
        except OpenRouterError as exc:
            if args.require_llm:
                print(f"OpenRouter analysis failed: {exc}", file=sys.stderr)
                return 4
            _log(f"OpenRouter analysis failed; falling back to deterministic local rules: {exc}")
            triage = analyze_with_local_rules(normalized, args.confidence_threshold)
            triage["warnings"].append(f"OpenRouter failed; used local fallback: {exc}")

    triage["run"] = {
        "analyzer": analyzer,
        "model": args.model if analyzer.startswith("openrouter:") else None,
        "llm_runtime_seconds": round(time.time() - analyzer_started, 3),
        "total_runtime_seconds": round(time.time() - started_at, 3),
        "confidence_threshold": args.confidence_threshold,
    }
    _write_json(triage_path, triage)

    _log("Rendering Markdown report")
    markdown = render_markdown_report(
        title=args.report_title,
        normalized=normalized,
        triage=triage,
    )
    report_path.write_text(markdown, encoding="utf-8")

    print(f"Wrote raw Trivy JSON: {raw_path}")
    print(f"Wrote normalized JSON: {normalized_path}")
    print(f"Wrote triage JSON: {triage_path}")
    print(f"Wrote Markdown report: {report_path}")
    return 0


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _copy_unless_same_file(source: Path, destination: Path) -> None:
    try:
        if source.resolve() == destination.resolve():
            return
    except FileNotFoundError:
        pass
    shutil.copyfile(source, destination)


def _log(message: str) -> None:
    print(f"[vuln-report] {message}", flush=True)


def _parse_severities(value: str) -> tuple[str, ...]:
    return tuple(part.strip().upper() for part in value.split(",") if part.strip())


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
