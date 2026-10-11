import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cvewatchdog_server


class ServerTests(unittest.TestCase):
    def tearDown(self):
        cvewatchdog_server.JOBS.clear()

    def test_inventory_validation_preserves_windows_platform(self):
        inventory = cvewatchdog_server.validate_inventory({
            "hostname": "workstation",
            "platform": "windows",
            "software": [{"name": "NSClient++", "version": "0.5.2.35", "context": "service"}],
            "options": {"sploitscan": False},
        })

        self.assertEqual("windows", inventory["platform"])
        self.assertFalse(inventory["sploitscan"])
        self.assertEqual("NSClient++", inventory["software"][0]["name"])

    @patch.object(cvewatchdog_server, "run_sploitscan")
    @patch.object(cvewatchdog_server, "resolve_software")
    def test_worker_resolves_inventory_and_writes_report(self, resolve, run_sploitscan):
        resolve.return_value = {
            "matched_cpe": {"cpe": "cpe:2.3:a:acme:widget:*", "score": 1},
            "results": [{
                "cve_id": "CVE-2026-0001", "cvss_score": 9.8, "description": "Test",
                "version": "1.0", "published": "2026-01-01", "cwes": [],
            }],
        }
        run_sploitscan.return_value = {}
        inventory = {
            "hostname": "pc", "platform": "windows", "sploitscan": True,
            "software": [{"name": "Widget", "version": "1.0", "context": "Acme"}],
        }
        cvewatchdog_server.JOBS["job"] = {
            "id": "job", "status": "queued", "stage": "queued", "processed": 0, "total": 1,
        }

        with tempfile.TemporaryDirectory() as directory:
            cvewatchdog_server.build_report("job", inventory, "http://fastcve:8001", Path(directory))
            report = Path(directory) / "job.html"
            self.assertTrue(report.exists())
            self.assertIn("CVE-2026-0001", report.read_text(encoding="utf-8"))

        self.assertEqual("completed", cvewatchdog_server.JOBS["job"]["status"])
        self.assertEqual(1, cvewatchdog_server.JOBS["job"]["summary"]["critical"])
        resolve.assert_called_once_with("http://fastcve:8001", "Widget", "1.0", "Acme", "windows")
        run_sploitscan.assert_called_once()

    def test_http_api_exposes_report_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            app = cvewatchdog_server.create_app("http://fastcve:8001", directory)

        paths = {route.path for route in app.routes}
        self.assertIn("/health", paths)
        self.assertIn("/api/v1/reports", paths)
        self.assertIn("/api/v1/reports/{job_id}", paths)
        self.assertIn("/api/v1/reports/{job_id}/html", paths)

    @patch.object(cvewatchdog_server, "resolve_software")
    def test_worker_fails_instead_of_reporting_safe_when_fastcve_is_down(self, resolve):
        resolve.side_effect = cvewatchdog_server.requests.RequestException("offline")
        inventory = {
            "hostname": "pc", "platform": "windows", "sploitscan": False,
            "software": [{"name": "Widget", "version": "1.0", "context": ""}],
        }
        cvewatchdog_server.JOBS["job"] = {
            "id": "job", "status": "queued", "stage": "queued", "processed": 0, "total": 1,
        }

        with tempfile.TemporaryDirectory() as directory:
            cvewatchdog_server.build_report("job", inventory, "http://fastcve:8001", Path(directory))

        self.assertEqual("failed", cvewatchdog_server.JOBS["job"]["status"])
        self.assertIn("every software entry", cvewatchdog_server.JOBS["job"]["error"])


if __name__ == "__main__":
    unittest.main()
