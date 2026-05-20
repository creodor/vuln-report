import unittest

from vuln_report.llm import _merge_model_findings


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


if __name__ == "__main__":
    unittest.main()

