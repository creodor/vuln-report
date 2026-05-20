import json
import unittest
from pathlib import Path

from vuln_report.normalize import normalize_trivy_report


class NormalizeTests(unittest.TestCase):
    def test_normalize_counts_and_filters_by_severity(self):
        report = json.loads(Path("fixtures/trivy-example.json").read_text(encoding="utf-8"))

        normalized = normalize_trivy_report(report, included_severities=("CRITICAL", "HIGH"))

        self.assertEqual(normalized["metrics"]["total_findings"], 5)
        self.assertEqual(normalized["metrics"]["findings_sent_to_analyzer"], 4)
        self.assertEqual(normalized["metrics"]["findings_omitted_by_severity"], 1)
        self.assertEqual(normalized["metrics"]["included_severities"], ["CRITICAL", "HIGH"])
        self.assertEqual(normalized["metrics"]["severity_counts"]["CRITICAL"], 2)
        self.assertEqual(normalized["metrics"]["fix_available_count"], 4)
        self.assertEqual(normalized["findings"][0]["severity"], "CRITICAL")
        self.assertNotIn("MEDIUM", {finding["severity"] for finding in normalized["findings"]})


if __name__ == "__main__":
    unittest.main()
