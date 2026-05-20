from __future__ import annotations

import json
import urllib.error
import urllib.request


class OpenRouterError(RuntimeError):
    pass


SYSTEM_PROMPT = """You are a security engineer performing vulnerability triage from normalized Trivy findings.
Return strict JSON only. Do not include Markdown, comments, or extra prose.
Be conservative: if context is missing, say what must be verified by a human.
Never claim exploitability is proven unless the finding data directly supports it."""


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
        "response_format": {"type": "json_object"},
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
            response_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise OpenRouterError(f"HTTP {exc.code}: {body}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise OpenRouterError(str(exc)) from exc

    try:
        content = response_payload["choices"][0]["message"]["content"]
        triage = json.loads(_strip_code_fences(content))
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        raise OpenRouterError(f"Could not parse model response: {exc}") from exc

    triage.setdefault("warnings", [])
    triage.setdefault("findings", [])
    triage.setdefault("summary", "")
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
                "severity": "CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN",
                "risk_summary": "Plain-English risk summary.",
                "exploitability_notes": "What is known and what needs validation.",
                "recommended_action": "Concrete remediation/control recommendation.",
                "human_review_required": True,
                "human_review_reason": "Reason if review is required.",
                "confidence": 0.0,
                "confidence_label": "low|borderline|medium|high",
                "confidence_rationale": "Why this confidence is appropriate.",
            }
        ],
        "warnings": ["Any limitations or notable assumptions."],
    }
    return (
        "Analyze the normalized Trivy vulnerability data below.\n"
        f"Confidence threshold for human review is {confidence_threshold}.\n"
        "Require human review for any critical severity finding, missing fixed version, "
        "likely RCE/auth bypass/privilege escalation/supply-chain issue, or confidence below threshold.\n"
        "Use this exact JSON shape:\n"
        f"{json.dumps(contract, indent=2)}\n\n"
        "Normalized Trivy data:\n"
        f"{json.dumps(normalized, indent=2)}"
    )


def _strip_code_fences(value: str) -> str:
    value = value.strip()
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

