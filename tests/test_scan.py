"""Exercise the CLI against temporary synthetic input, never a user's files."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="scanner-fixtures-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.surface = self.root / "input"
        self.surface.mkdir()
        self.state = self.root / "state"
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"surfaces": {"demo": str(self.surface)},
            "state_dir": str(self.state), "report_brand_line": "FICTIONAL TEST REPORT"}))
        self.env = dict(os.environ, SECURITY_SWEEP_CONFIG=str(self.config))

    def run_scan(self, *args):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/scan.py"), *args],
            env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def findings(self):
        return json.loads((self.state / "findings.json").read_text())

    def seed_token(self):
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        path = self.surface / "notes.txt"
        path.write_text(token + "\n" + token + "\n")
        return path, token

    def test_detection_masking_dedup_and_read_only(self):
        path, token = self.seed_token()
        original = path.read_bytes()
        result = self.run_scan()
        data = self.findings()
        self.assertEqual(data["stats"]["demo"]["content_scanned"], 1)
        match = next(f for f in data["findings"] if f["rule"] == "github-token")
        self.assertEqual(match["count"], 2)
        self.assertNotIn(token, json.dumps(data) + result.stdout + result.stderr)
        self.assertNotIn(token, (self.state / "findings.md").read_text())
        self.assertEqual(path.read_bytes(), original)

    def test_false_positive_numbers_and_placeholders(self):
        (self.surface / "notes.txt").write_text(
            "SSN placeholder without value\n000-00-0000\n4111 1111 1111 1112\n"
            "const token = process.env.API_KEY\n")
        self.run_scan()
        self.assertEqual(self.findings()["findings"], [])

    def test_valid_card_is_masked(self):
        card = "4111 " + "1111 " * 2 + "1111"
        (self.surface / "notes.txt").write_text(card)
        self.run_scan()
        self.assertTrue(any(f["rule"] == "credit-card" for f in self.findings()["findings"]))
        self.assertNotIn(card.replace(" ", ""), json.dumps(self.findings()))

    def test_allowlist_and_verification_preserve_baseline(self):
        path, token = self.seed_token()
        self.run_scan()
        baseline = (self.state / "findings.json").read_bytes()
        path.write_text("resolved\n")
        result = self.run_scan("--verify")
        self.assertIn("resolved since baseline: 1", result.stdout)
        self.assertEqual((self.state / "findings.json").read_bytes(), baseline)
        path.write_text(token)
        (self.state / "allowlist.json").write_text(json.dumps({"keys": ["demo|notes.txt|github-token"]}))
        self.run_scan()
        self.assertEqual(self.findings()["findings"], [])
        self.assertEqual(self.findings()["counts"]["suppressed_allowlist"], 1)

    def test_report_masks_values_and_escapes_paths(self):
        path, token = self.seed_token()
        path.rename(self.surface / "<script>alert(1)</script>.txt".replace("/", "_"))
        self.run_scan()
        out = self.root / "reports"
        result = subprocess.run([sys.executable, str(ROOT / "scripts/build_report.py"), "--out", str(out)],
            env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = next(out.glob("*.html")).read_text()
        self.assertNotIn(token, report)
        self.assertNotIn("<script>alert(1)", report)
        self.assertIn("&lt;script&gt;", report)

if __name__ == "__main__":
    unittest.main()
