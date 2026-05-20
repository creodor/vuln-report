import json
import unittest
from pathlib import Path

from vuln_report.normalize import normalize_trivy_report
from vuln_report.triage import analyze_with_local_rules


class LocalTriageTests(unittest.TestCase):
    def test_local_rules_require_review_for_critical_and_missing_fix(self):
        report = json.loads(Path("fixtures/trivy-example.json").read_text(encoding="utf-8"))
        normalized = normalize_trivy_report(report, included_severities=("CRITICAL", "HIGH"))

        triage = analyze_with_local_rules(normalized, confidence_threshold=0.70)

        by_id = {finding["id"]: finding for finding in triage["findings"]}
        self.assertIs(by_id["CVE-2022-1292"]["human_review_required"], True)
        self.assertIs(by_id["CVE-2023-45853"]["human_review_required"], True)
        self.assertLess(by_id["CVE-2023-45853"]["confidence"], 0.70)
        self.assertIs(by_id["CVE-2022-37434"]["human_review_required"], False)


if __name__ == "__main__":
    unittest.main()
