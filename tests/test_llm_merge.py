import unittest
from unittest.mock import patch

from vuln_report.llm import _analyze_with_openrouter_chunks, _merge_model_findings


class LlmMergeTests(unittest.TestCase):
    def test_merge_model_findings_preserves_sent_findings(self):
        normalized = {
            "findings": [
                {
                    "id": "CVE-1",
                    "package": "openssl",
                    "installed_version": "1.0",
                    "fixed_version": "1.1",
                    "severity": "CRITICAL",
                    "title": "first",
                },
                {
                    "id": "CVE-2",
                    "package": "zlib",
                    "installed_version": "1.0",
                    "fixed_version": "",
                    "severity": "HIGH",
                    "title": "second",
                },
            ]
        }
        model_findings = [
            {
                "id": "CVE-1",
                "package": "openssl",
                "installed_version": "1.0",
                "severity": "CRITICAL",
                "risk_summary": "model returned this one",
                "confidence": 0.9,
            }
        ]

        merged = _merge_model_findings(normalized, model_findings)

        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["risk_summary"], "model returned this one")
        self.assertEqual(merged[1]["id"], "CVE-2")
        self.assertTrue(merged[1]["human_review_required"])
        self.assertEqual(merged[1]["confidence"], 0.0)

    def test_chunked_analysis_combines_results_and_usage(self):
        normalized = {
            "findings": [
                {"id": "CVE-1", "package": "a", "installed_version": "1"},
                {"id": "CVE-2", "package": "b", "installed_version": "1"},
                {"id": "CVE-3", "package": "c", "installed_version": "1"},
            ],
            "metrics": {"findings_sent_to_analyzer": 3},
        }

        def fake_chunk(chunk, **_kwargs):
            return {
                "summary": "ok",
                "findings": chunk["findings"],
                "warnings": [],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 20,
                    "total_tokens": 30,
                    "estimated_cost_usd": 0.001,
                    "estimated_cost_note": "estimated from OpenRouter model pricing",
                },
            }

        with patch("vuln_report.llm._analyze_single_openrouter_chunk", side_effect=fake_chunk):
            result = _analyze_with_openrouter_chunks(
                normalized,
                api_key="key",
                model="model",
                confidence_threshold=0.7,
                chunk_size=2,
            )

        self.assertEqual(len(result["findings"]), 3)
        self.assertEqual(result["usage"]["prompt_tokens"], 20)
        self.assertEqual(result["usage"]["completion_tokens"], 40)
        self.assertEqual(result["usage"]["total_tokens"], 60)
        self.assertEqual(result["usage"]["estimated_cost_usd"], 0.002)
        self.assertEqual(
            result["usage"]["estimated_cost_note"],
            "estimated from OpenRouter model pricing",
        )


if __name__ == "__main__":
    unittest.main()
