import tempfile
import unittest
from pathlib import Path

from vuln_report.cli import _copy_unless_same_file


class CliFileTests(unittest.TestCase):
    def test_copy_unless_same_file_noops_for_same_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "trivy-raw.json"
            path.write_text("{}", encoding="utf-8")

            _copy_unless_same_file(path, path)

            self.assertEqual(path.read_text(encoding="utf-8"), "{}")

    def test_copy_unless_same_file_copies_different_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.json"
            destination = Path(temp_dir) / "destination.json"
            source.write_text('{"ok": true}', encoding="utf-8")

            _copy_unless_same_file(source, destination)

            self.assertEqual(destination.read_text(encoding="utf-8"), '{"ok": true}')


if __name__ == "__main__":
    unittest.main()

