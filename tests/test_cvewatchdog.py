import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).parents[1] / "CVEWatchdog.py"
SPEC = importlib.util.spec_from_file_location("cvewatchdog", SCRIPT)
cvewatchdog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cvewatchdog)


class APIClientTests(unittest.TestCase):
    @patch.object(cvewatchdog.requests, "get")
    def test_cli_defaults_to_local_api(self, get):
        get.side_effect = cvewatchdog.requests.RequestException("offline")

        with patch("sys.argv", ["CVEWatchdog.py"]), self.assertRaises(SystemExit):
            cvewatchdog.main()

        get.assert_called_once_with("http://localhost:8001/health", timeout=5)

    @patch.object(cvewatchdog.requests, "post")
    def test_resolve_uses_the_shared_api_contract(self, post):
        response = Mock()
        response.json.return_value = {
            "matched_cpe": {"cpe": "cpe:2.3:a:videolan:vlc:*", "score": 0.95},
            "results": [],
        }
        post.return_value = response

        result = cvewatchdog.resolve_software(
            "http://localhost:8000/", "VLC media player", "3.0.21", "VideoLAN"
        )

        post.assert_called_once_with(
            "http://localhost:8000/api/resolve",
            json={
                "software": "VLC media player",
                "version": "3.0.21",
                "context": "VideoLAN",
                "platform": "linux",
            },
            timeout=10,
        )
        response.raise_for_status.assert_called_once_with()
        self.assertEqual([], result["results"])

    @patch.object(cvewatchdog.subprocess, "run")
    def test_linux_inventory_normalizes_epoch_and_release(self, run):
        run.return_value = Mock(
            returncode=0,
            stdout="firefox\t1:123.0-1ubuntu1\n",
        )

        software, ignored = cvewatchdog.get_installed_software()

        self.assertEqual(0, ignored)
        self.assertEqual(("firefox", "123.0"), (software[0].name, software[0].version))
        self.assertEqual("C", run.call_args.kwargs["env"]["LC_ALL"])

    def test_pacman_inventory_includes_package_context(self):
        output = """Name            : base
Version         : 3-3
Description     : Minimal Arch Linux installation
URL             : https://archlinux.org
Packager        : Arch Linux

"""

        software = cvewatchdog.parse_pacman_inventory(output)

        self.assertEqual(("base", "3"), (software[0].name, software[0].version))
        self.assertIn("archlinux.org", software[0].context)

    @patch.object(cvewatchdog.subprocess, "run")
    def test_empty_inventory_is_an_error(self, run):
        run.return_value = Mock(returncode=0, stdout="")

        with self.assertRaises(SystemExit):
            cvewatchdog.get_installed_software()

    def test_html_report_is_standalone_and_escapes_nvd_content(self):
        applications = [{
            "name": "Widget <script>",
            "version": "1.0",
            "cpe": "cpe:2.3:a:acme:widget:*",
            "cves": [{
                "cve_id": "CVE-2026-0001",
                "cvss_score": 9.8,
                "version": "<2.0",
                "published": "2026-01-01T00:00:00Z",
                "description": "A local attacker can gain elevated privileges. <img src=x onerror=alert(1)>",
            }],
        }]
        summary = {
            "software_scanned": 1,
            "software_resolved": 1,
            "api_errors": 0,
            "total_cves": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "risk_level": "CRITICAL RISK",
        }

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            result = cvewatchdog.write_html_report(path, applications, summary)
            document = path.read_text(encoding="utf-8")

        self.assertEqual(path.resolve(), result)
        self.assertIn("CVE-2026-0001", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertNotIn("<img src=x", document)
        self.assertIn('id="report-search"', document)
        self.assertIn('id="severity-filter"', document)
        self.assertIn('id="type-filter"', document)
        self.assertIn('class="software-choice"', document)
        self.assertIn('data-software="software-0"', document)
        self.assertIn("Vulnerable software", document)
        self.assertIn("(1 CVEs)", document)
        self.assertIn('data-severity="critical"', document)
        self.assertIn('data-types="lpe"', document)
        self.assertIn(">LPE</td>", document)
        self.assertIn("function filterReport()", document)

    def test_vulnerability_type_classification_is_conservative(self):
        self.assertIn(("lpe", "LPE"), cvewatchdog.classify_vulnerability(
            "A local attacker can elevate their privileges."
        ))
        self.assertIn(("rce", "RCE"), cvewatchdog.classify_vulnerability(
            "This allows remote code execution."
        ))
        self.assertEqual([("other", "Other")], cvewatchdog.classify_vulnerability(
            "An attacker can modify application settings."
        ))


if __name__ == "__main__":
    unittest.main()
