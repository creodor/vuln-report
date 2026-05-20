import unittest

from vuln_report.report import render_markdown_report


class ReportTests(unittest.TestCase):
    def test_report_groups_shared_remediations_without_losing_cves(self):
        normalized = {
            "generated_at": "2026-01-01T00:00:00Z",
            "scan_source": "fixture",
            "metrics": {
                "total_findings": 2,
                "findings_sent_to_analyzer": 2,
                "findings_omitted_by_severity": 0,
                "included_severities": ["CRITICAL", "HIGH"],
                "fix_available_count": 2,
                "fix_unavailable_count": 0,
                "severity_counts": {
                    "CRITICAL": 1,
                    "HIGH": 1,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "UNKNOWN": 0,
                },
            },
        }
        triage = {
            "summary": "Two findings.",
            "run": {"analyzer": "test"},
            "usage": {},
            "warnings": [],
            "findings": [
                {
                    "id": "CVE-1",
                    "package": "openssl",
                    "fixed_version": "1.1.1",
                    "severity": "CRITICAL",
                    "recommended_action": "Upgrade openssl to 1.1.1 or later.",
                    "human_review_required": True,
                    "confidence": 0.8,
                    "confidence_label": "medium",
                },
                {
                    "id": "CVE-2",
                    "package": "openssl",
                    "fixed_version": "1.1.1",
                    "severity": "HIGH",
                    "recommended_action": "Upgrade openssl to 1.1.1 or later.",
                    "human_review_required": False,
                    "confidence": 0.9,
                    "confidence_label": "high",
                },
            ],
        }

        report = render_markdown_report("Report", normalized, triage)

        self.assertIn("## Recommended remediation groups", report)
        self.assertIn("Upgrade openssl to 1.1.1 or later.", report)
        self.assertIn("CVE-1", report)
        self.assertIn("CVE-2", report)


if __name__ == "__main__":
    unittest.main()
