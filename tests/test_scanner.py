import unittest

from sensitive_leak_detector.scanner import has_failure, scan_text
from sensitive_leak_detector.web import EndpointProbe, looks_interesting, normalize_base_url


class ScannerTests(unittest.TestCase):
    def test_detects_github_token_and_masks_value(self):
        fake_token = "ghp_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        findings = scan_text(f"TOKEN='{fake_token}'", "sample.env")

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"github-token", "high-entropy-assignment"},
        )
        self.assertTrue(all("..." in finding.match for finding in findings))
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", findings[0].match)

    def test_detects_private_key_header(self):
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        findings = scan_text(marker, "key.pem")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].rule_id, "private-key")

    def test_failure_threshold_respects_severity(self):
        fake_key = "abc123XYZ789" * 2
        findings = scan_text(f"api_key = '{fake_key}'", "config.txt")

        self.assertTrue(has_failure(findings, "medium"))
        self.assertFalse(has_failure(findings, "high"))

    def test_normalizes_web_target(self):
        self.assertEqual(normalize_base_url("example.com/app/"), "https://example.com/app")

    def test_web_probe_detects_signature(self):
        probe = EndpointProbe("/.env", "env-file", "Exposed env", "critical", signatures=("DB_PASSWORD=",))

        self.assertTrue(looks_interesting(200, "text/plain", "DB_PASSWORD=example", probe))
        self.assertFalse(looks_interesting(404, "text/plain", "DB_PASSWORD=example", probe))


if __name__ == "__main__":
    unittest.main()
