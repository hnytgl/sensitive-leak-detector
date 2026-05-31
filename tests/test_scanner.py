import unittest

from sensitive_leak_detector.scanner import has_failure, scan_text
from sensitive_leak_detector.web import (
    EndpointProbe,
    build_api_probes,
    extract_api_paths,
    extract_page_links,
    looks_interesting,
    looks_like_sensitive_api_response,
    normalize_base_url,
    scan_url,
)


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

    def test_sensitive_api_response_detection(self):
        body = '{"data":[{"user_id":1,"email":"a@example.com","phone":"13800138000"}],"total":1}'

        self.assertTrue(looks_like_sensitive_api_response("application/json", body))
        self.assertFalse(looks_like_sensitive_api_response("text/html", "<html>ok</html>"))

    def test_custom_api_paths_are_normalized_and_deduplicated(self):
        probes = build_api_probes(["api/private/users", "/api/private/users"])

        matches = [probe for probe in probes if probe.path == "/api/private/users"]
        self.assertEqual(len(matches), 1)
        self.assertTrue(matches[0].api_probe)

    def test_scan_url_reports_progress(self):
        messages: list[str] = []

        scan_url("https://example.invalid", timeout=0.01, api_paths=[], progress=messages.append)

        self.assertTrue(any("Prepared" in message for message in messages))
        self.assertTrue(any("Testing" in message for message in messages))

    def test_extract_page_links_keeps_same_origin_pages(self):
        html = '<a href="/next">next</a><script src="/app.js"></script><a href="https://other.example/x">offsite</a>'

        links = extract_page_links("https://example.com/start", html)

        self.assertIn("https://example.com/next", links)
        self.assertIn("https://example.com/app.js", links)
        self.assertNotIn("https://other.example/x", links)

    def test_extract_api_paths_from_page_source(self):
        html = """
        <script>
        fetch('/api/v1/users?active=true')
        axios.get("https://example.com/api/orders")
        fetch("https://other.example/api/private")
        </script>
        """

        paths = extract_api_paths("https://example.com/app", html)

        self.assertIn("/api/v1/users?active=true", paths)
        self.assertIn("/api/orders", paths)
        self.assertNotIn("/api/private", paths)


if __name__ == "__main__":
    unittest.main()
