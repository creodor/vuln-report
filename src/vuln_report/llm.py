from __future__ import annotations

import json
import re
import urllib.error
import urllib.request


class OpenRouterError(RuntimeError):
    pass


SYSTEM_PROMPT = """You are a security engineer performing vulnerability triage from normalized Trivy findings.
Return strict JSON only. Do not include Markdown, comments, or extra prose.
Be conservative: if context is missing, say what must be verified by a human.
Never claim exploitability is proven unless the finding data directly supports it.
Confidence means confidence in your generated triage recommendation for a finding,
including the risk summary, exploitability notes, and recommended action, based only
on the supplied normalized Trivy data."""


def analyze_with_openrouter(
    normalized: dict,
    api_key: str,
    model: str,
    confidence_threshold: float,
) -> dict:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _user_prompt(normalized, confidence_threshold)},
        ],
        "temperature": 0.1,
    }
    request = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/creodor/vuln-report",
            "X-Title": "vuln-report",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            response_payload = _parse_openrouter_response_body(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise OpenRouterError(_format_openrouter_http_error(exc.code, body)) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise OpenRouterError(str(exc)) from exc

    try:
        choice = response_payload["choices"][0]
        message = choice.get("message") or {}
    except (KeyError, IndexError, TypeError) as exc:
        raise OpenRouterError(f"OpenRouter response did not include a chat message: {exc}") from exc

    content = _extract_message_content(message, choice)
    try:
        triage = json.loads(_strip_code_fences(content))
    except json.JSONDecodeError as exc:
        raise OpenRouterError(f"Could not parse model response as JSON: {exc}") from exc

    triage.setdefault("warnings", [])
    triage.setdefault("findings", [])
    triage.setdefault("summary", "")
    triage["findings"] = _merge_model_findings(normalized, triage["findings"])
    if any(finding.get("human_review_reason") == "Model omitted this finding from its structured response." for finding in triage["findings"]):
        triage["warnings"].append("One or more findings were omitted by the model and replaced with low-confidence human-review fallback entries.")
    triage["usage"] = _usage(response_payload)
    _apply_required_guardrails(triage, confidence_threshold)
    return triage


def _user_prompt(normalized: dict, confidence_threshold: float) -> str:
    contract = {
        "summary": "Short executive summary.",
        "findings": [
            {
                "id": "CVE identifier",
                "package": "Package name",
                "installed_version": "Installed package version from the input finding.",
                "fixed_version": "Fixed package version from the input finding, or empty string.",
                "severity": "CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN",
                "risk_summary": "Plain-English risk summary.",
                "exploitability_notes": "What is known and what needs validation.",
                "recommended_action": "Concrete remediation/control recommendation.",
                "human_review_required": True,
                "human_review_reason": "Reason if review is required.",
                "confidence": 0.0,
                "confidence_label": "low|borderline|medium|high",
                "confidence_rationale": "Why this confidence in the generated triage recommendation is appropriate.",
            }
        ],
        "warnings": ["Any limitations or notable assumptions."],
    }
    return (
        "Analyze the normalized Trivy vulnerability data below.\n"
        f"Confidence threshold for human review is {confidence_threshold}.\n"
        "Require human review for any critical severity finding, missing fixed version, "
        "likely RCE/auth bypass/privilege escalation/supply-chain issue, or confidence below threshold.\n"
        "Return exactly one findings entry for every finding in normalized.findings. "
        "Do not summarize, group, omit, or deduplicate findings.\n"
        "Confidence must mean confidence in your generated triage recommendation for that finding, "
        "including the risk summary, exploitability notes, and recommended action, based only on the supplied data.\n"
        "Use this exact JSON shape:\n"
        f"{json.dumps(contract, indent=2)}\n\n"
        "Normalized Trivy data:\n"
        f"{json.dumps(normalized, indent=2)}"
    )


def _extract_message_content(message: dict, choice: dict) -> str:
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif isinstance(item, str):
                parts.append(item)
        joined = "\n".join(part for part in parts if part.strip()).strip()
        if joined:
            return joined

    finish_reason = choice.get("finish_reason")
    message_keys = ", ".join(sorted(message.keys())) or "none"
    error_text = _extract_error_text(message) or _extract_error_text(choice)
    if error_text:
        raise OpenRouterError(
            "Model response did not include text content; "
            f"provider reported: {_sanitize_error_text(error_text)}"
        )
    raise OpenRouterError(
        "Model response did not include text content "
        f"(finish_reason={finish_reason}, message_keys={message_keys})."
    )


def _strip_code_fences(value: str) -> str:
    value = value.strip()
    if not value:
        raise OpenRouterError("Model response content was empty.")
    if value.startswith("```"):
        lines = value.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return value


def _usage(response_payload: dict) -> dict:
    usage = response_payload.get("usage") or {}
    return {
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "total_tokens": usage.get("total_tokens"),
        "estimated_cost_usd": None,
    }


def _parse_openrouter_response_body(body: str) -> dict:
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        excerpt = _sanitize_error_text(body)
        raise OpenRouterError(
            "OpenRouter returned a non-JSON or truncated response body "
            f"at line {exc.lineno}, column {exc.colno}: {excerpt}"
        ) from exc


def _format_openrouter_http_error(status_code: int, body: str) -> str:
    message = _extract_error_text(_safe_json(body)) or body
    message = _sanitize_error_text(message)
    if status_code in {402, 429}:
        return f"OpenRouter HTTP {status_code}: model is likely quota-limited or throttled ({message})"
    if status_code in {400, 404}:
        return f"OpenRouter HTTP {status_code}: model or request was rejected ({message})"
    return f"OpenRouter HTTP {status_code}: {message}"


def _safe_json(value: str) -> dict | str:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _extract_error_text(value) -> str:
    if isinstance(value, dict):
        for key in ("error", "message", "detail"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
            if isinstance(candidate, dict):
                nested = _extract_error_text(candidate)
                if nested:
                    return nested
        return ""
    if isinstance(value, str):
        return value
    return ""


def _sanitize_error_text(value: str, limit: int = 240) -> str:
    value = re.sub(r"sk-or-v1-[A-Za-z0-9_-]+", "[redacted-openrouter-key]", value)
    value = " ".join(value.split())
    if len(value) > limit:
        return value[: limit - 3].rstrip() + "..."
    return value


def _merge_model_findings(normalized: dict, model_findings: list[dict]) -> list[dict]:
    by_exact_key = {}
    by_loose_key = {}
    for finding in model_findings:
        if not isinstance(finding, dict):
            continue
        exact_key = _exact_finding_key(finding)
        loose_key = _loose_finding_key(finding)
        if exact_key and exact_key not in by_exact_key:
            by_exact_key[exact_key] = finding
        if loose_key and loose_key not in by_loose_key:
            by_loose_key[loose_key] = finding

    merged = []
    for source in normalized.get("findings", []):
        model_finding = by_exact_key.get(_exact_finding_key(source))
        if not model_finding:
            model_finding = by_loose_key.get(_loose_finding_key(source))
        if model_finding:
            merged.append(_with_source_defaults(source, model_finding))
        else:
            merged.append(_omitted_model_finding(source))

    return merged


def _exact_finding_key(finding: dict) -> tuple[str, str, str] | None:
    cve_id = finding.get("id")
    package = finding.get("package")
    installed_version = finding.get("installed_version") or ""
    if not cve_id or not package:
        return None
    return (str(cve_id), str(package), str(installed_version))


def _loose_finding_key(finding: dict) -> tuple[str, str] | None:
    cve_id = finding.get("id")
    package = finding.get("package")
    if not cve_id or not package:
        return None
    return (str(cve_id), str(package))


def _with_source_defaults(source: dict, finding: dict) -> dict:
    merged = dict(finding)
    for key in ("id", "package", "severity", "installed_version", "fixed_version", "primary_url"):
        if not merged.get(key):
            merged[key] = source.get(key)
    return merged


def _omitted_model_finding(source: dict) -> dict:
    fixed_version = source.get("fixed_version")
    if fixed_version:
        action = f"Upgrade {source.get('package')} from {source.get('installed_version')} to {fixed_version} or later."
    else:
        action = f"No fixed version was reported for {source.get('package')}; route to human review."
    return {
        "id": source.get("id"),
        "package": source.get("package"),
        "severity": source.get("severity"),
        "installed_version": source.get("installed_version"),
        "fixed_version": fixed_version,
        "risk_summary": f"{source.get('severity')} vulnerability in {source.get('package')} ({source.get('title') or source.get('id')}).",
        "exploitability_notes": "The model did not return analysis for this finding; validate exposure and reachable code paths manually.",
        "recommended_action": action,
        "human_review_required": True,
        "human_review_reason": "Model omitted this finding from its structured response.",
        "confidence": 0.0,
        "confidence_label": "low",
        "confidence_rationale": "No model-generated triage recommendation was returned for this finding.",
    }


def _apply_required_guardrails(triage: dict, confidence_threshold: float) -> None:
    for finding in triage.get("findings", []):
        confidence = finding.get("confidence")
        if isinstance(confidence, (int, float)) and confidence < confidence_threshold:
            finding["human_review_required"] = True
            if not finding.get("human_review_reason"):
                finding["human_review_reason"] = "Confidence below configured threshold."
        if finding.get("severity") == "CRITICAL":
            finding["human_review_required"] = True
            if not finding.get("human_review_reason"):
                finding["human_review_reason"] = "Critical severity findings require human confirmation before closure."
