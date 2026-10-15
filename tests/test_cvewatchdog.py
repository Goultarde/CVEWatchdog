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
                "cwes": ["CWE-863"],
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
        self.assertIn('id="cwe-filter"', document)
        self.assertNotIn('id="poc-filter"', document)
        self.assertIn('<option value="CWE-863">CWE-863: Incorrect Authorization</option>', document)
        self.assertNotIn("—", document)
        self.assertNotIn("–", document)
        self.assertIn('class="software-choice"', document)
        self.assertIn('data-software="software-0"', document)
        self.assertIn("Vulnerable software", document)
        self.assertIn('class="software-cve-count">1 CVE</span>', document)
        self.assertIn('data-severity="critical"', document)
        self.assertIn('data-types="lpe"', document)
        self.assertIn('data-cwes="CWE-863"', document)
        self.assertIn('class="cwe-chip" title="Incorrect Authorization">CWE-863</span>', document)
        self.assertIn("row.dataset.cwes", document)
        self.assertIn("scrollbar-color", document)
        self.assertIn('class="type-chip">LPE</span>', document)
        self.assertIn('class="hero"', document)
        self.assertIn('class="panel filter-panel"', document)
        self.assertIn("function filterReport()", document)
        self.assertIn("background:var(--bg)", document)
        self.assertNotIn("backdrop-filter", document)
        self.assertNotIn("background-attachment:fixed", document)
        self.assertIn("transition:transform .12s ease", document)
        self.assertIn("transform:translateY(-1px)", document)
        self.assertIn("row.filterText.includes(query)", document)
        self.assertNotIn("scroll-behavior:smooth", document)

    @patch.object(cvewatchdog.subprocess, "Popen")
    def test_sploitscan_results_are_indexed_by_cve(self, popen):
        progress = Mock()

        def export_json(command, **kwargs):
            export = Path(kwargs["cwd"]) / "result.json"
            export.write_text('[{"CVE Data":{"cveMetadata":{"cveId":"CVE-2026-0001"}}}]', encoding="utf-8")
            return Mock(
                stdout=iter([
                    "║ CVE ID: CVE-2026-0001 ║\n",
                    "Data exported to file: result.json\n",
                ]),
                wait=Mock(return_value=0),
            )

        popen.side_effect = export_json
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "sploitscan"
            launcher.write_text(f"#!{cvewatchdog.sys.executable} -E\n", encoding="utf-8")
            with patch.object(cvewatchdog.shutil, "which", return_value=str(launcher)):
                result = cvewatchdog.run_sploitscan([
                    {"cve_id": "CVE-2026-0001"},
                    {"cve_id": "CVE-2026-0001"},
                    {"cve_id": "invalid"},
                ], progress)

        self.assertIn("CVE-2026-0001", result)
        progress.assert_called_once_with("CVE-2026-0001")
        command = popen.call_args.args[0]
        self.assertEqual([cvewatchdog.sys.executable, "-u", str(launcher)], command[:3])
        self.assertIn("cisa,epss,prio", command)

    def test_html_report_includes_sploitscan_intelligence(self):
        applications = [{
            "name": "Widget", "version": "1.0", "cpe": "cpe:2.3:a:acme:widget:*",
            "cves": [{"cve_id": "CVE-2026-0001", "cvss_score": 9.8, "description": "Test"}],
        }]
        summary = {
            "software_scanned": 1, "software_resolved": 1, "api_errors": 0,
            "total_cves": 1, "critical": 1, "high": 0, "medium": 0, "low": 0,
            "risk_level": "CRITICAL RISK",
        }
        intelligence = {"CVE-2026-0001": {
            "EPSS Data": {"data": [{"epss": "0.42"}]},
            "CISA Data": {"cisa_status": "Yes"},
            "Priority": {"Priority": "A+"},
            "GitHub Data": {"pocs": [{"html_url": "https://example.test/poc"}]},
            "Metasploit Data": {"modules": [{"name": "exploit/test"}]},
        }}

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            cvewatchdog.write_html_report(path, applications, summary, intelligence)
            document = path.read_text(encoding="utf-8")

        self.assertIn("<th>EPSS</th><th>CISA KEV</th><th>Priority</th><th>Exploits</th>", document)
        self.assertIn("42.0%", document)
        self.assertIn('class="intel-chip">Yes</span>', document)
        self.assertIn('class="intel-chip">A+</span>', document)
        self.assertIn("<summary>2 exploit(s)</summary>", document)
        self.assertIn('href="https://example.test/poc"', document)
        self.assertIn('target="_blank" rel="noopener noreferrer">GitHub PoC</a>', document)
        self.assertIn('id="poc-filter"', document)
        self.assertIn('<option value="true">With PoC</option>', document)
        self.assertIn('data-poc="true"', document)
        self.assertIn("row.dataset.poc===poc.value", document)

    def test_vulnerability_type_classification_is_conservative(self):
        self.assertIn(("lpe", "LPE"), cvewatchdog.classify_vulnerability(
            "A local attacker can elevate their privileges."
        ))
        self.assertIn(("lpe", "LPE"), cvewatchdog.classify_vulnerability(
            "A local privilege escalation vulnerability exists in NSClient++ 0.5.2.35."
        ))
        self.assertIn(("lpe", "LPE"), cvewatchdog.classify_vulnerability(
            "This is a local elevation of privilege vulnerability."
        ))
        self.assertIn(("rce", "RCE"), cvewatchdog.classify_vulnerability(
            "This allows remote code execution."
        ))
        self.assertIn(("rce", "RCE"), cvewatchdog.classify_vulnerability(
            "A remote attacker leveraging social engineering could potentially execute arbitrary code outside the sandbox."
        ))
        self.assertEqual([("other", "Other")], cvewatchdog.classify_vulnerability(
            "An attacker can modify application settings."
        ))

    @patch.object(cvewatchdog.time, "sleep")
    @patch.object(cvewatchdog.requests, "get")
    @patch.object(cvewatchdog.requests, "post")
    def test_client_downloads_remote_server_report(self, post, get, sleep):
        submitted = Mock()
        submitted.json.return_value = {"id": "job-1"}
        post.return_value = submitted
        completed = Mock()
        completed.json.return_value = {"status": "completed", "stage": "completed"}
        report = Mock(content=b"<html>report</html>")
        get.side_effect = [completed, report]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            result = cvewatchdog.request_server_report(
                "http://server:8002/",
                [cvewatchdog.Software("Widget", "1.0", "Acme")],
                path,
            )
            self.assertEqual(b"<html>report</html>", path.read_bytes())

        self.assertEqual(path.resolve(), result)
        payload = post.call_args.kwargs["json"]
        self.assertEqual(cvewatchdog.PLATFORM, payload["platform"])
        self.assertEqual("Widget", payload["software"][0]["name"])
        self.assertTrue(payload["options"]["sploitscan"])
        get.assert_any_call("http://server:8002/api/v1/reports/job-1/html", timeout=60)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
