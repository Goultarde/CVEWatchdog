import asyncio
import logging
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

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

    @patch.object(cvewatchdog_server.LOGGER, "info")
    @patch.object(cvewatchdog_server, "run_sploitscan")
    def test_worker_resolves_inventory_and_writes_report(self, run_sploitscan, log_info):
        resolve = Mock()
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
            cvewatchdog_server.build_report("job", inventory, resolve, Path(directory))
            report = Path(directory) / "job.html"
            self.assertTrue(report.exists())
            self.assertIn("CVE-2026-0001", report.read_text(encoding="utf-8"))

        self.assertEqual("completed", cvewatchdog_server.JOBS["job"]["status"])
        self.assertEqual(1, cvewatchdog_server.JOBS["job"]["summary"]["critical"])
        resolve.assert_called_once_with("Widget", "1.0", "Acme", "windows")
        run_sploitscan.assert_called_once()
        log_info.assert_any_call("SploitScan enrichment started for %d CVEs (report %s)", 1, "job")
        log_info.assert_any_call("SploitScan enrichment completed for %d CVEs (report %s)", 1, "job")

    def test_http_api_exposes_report_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            app = cvewatchdog_server.create_app(
                fastcve_url="http://fastcve:8001", reports_dir=directory
            )

        paths = {route.path for route in app.routes}
        self.assertIn("/health", paths)
        self.assertIn("/api/v1/reports", paths)
        self.assertIn("/api/v1/reports/{job_id}", paths)
        self.assertIn("/api/v1/reports/{job_id}/html", paths)

    def test_worker_fails_instead_of_reporting_safe_when_fastcve_is_down(self):
        resolve = Mock()
        resolve.side_effect = cvewatchdog_server.requests.RequestException("offline")
        inventory = {
            "hostname": "pc", "platform": "windows", "sploitscan": False,
            "software": [{"name": "Widget", "version": "1.0", "context": ""}],
        }
        cvewatchdog_server.JOBS["job"] = {
            "id": "job", "status": "queued", "stage": "queued", "processed": 0, "total": 1,
        }

        with tempfile.TemporaryDirectory() as directory:
            cvewatchdog_server.build_report("job", inventory, resolve, Path(directory))

        self.assertEqual("failed", cvewatchdog_server.JOBS["job"]["status"])
        self.assertIn("every software entry", cvewatchdog_server.JOBS["job"]["error"])

    def test_embedded_engine_is_loaded_and_reported_by_health(self):
        class Engine:
            data_path = Path("/tmp/fastcve-test")

            def __init__(self):
                self.loaded = False
                self.closed = False

            async def load(self):
                self.loaded = True

            def close(self):
                self.closed = True

            def resolve(self, *args):
                return {}

            def health(self):
                return {
                    "status": "healthy" if self.loaded else "loading", "cves_indexed": 42,
                    "data_path": str(self.data_path),
                }

        engine = Engine()
        fastcve_logger = logging.getLogger("app.config")
        handlers = fastcve_logger.handlers[:]
        propagate = fastcve_logger.propagate
        with tempfile.TemporaryDirectory() as directory:
            app = cvewatchdog_server.create_app(reports_dir=directory, engine=engine)

            async def run_lifecycle():
                async with app.router.lifespan_context(app):
                    self.assertTrue(engine.loaded)
                    return next(route.endpoint for route in app.routes if route.path == "/health")()

            with patch.object(cvewatchdog_server.CONSOLE, "status") as status:
                health = asyncio.run(run_lifecycle())

        self.assertTrue(engine.loaded)
        self.assertTrue(engine.closed)
        self.assertEqual(handlers, fastcve_logger.handlers)
        self.assertEqual(propagate, fastcve_logger.propagate)
        status.assert_called_once_with(
            "[cyan]Loading FastCVE data and indexes...[/]", spinner="dots"
        )
        self.assertEqual("embedded", health["fastcve"])
        self.assertEqual(42, health["cves_indexed"])
        self.assertEqual({}, app.state.fastcve_resolver("Widget", "1.0", "Acme", "windows"))

    @patch("uvicorn.run")
    @patch.object(cvewatchdog_server, "create_app")
    @patch.object(cvewatchdog_server, "FastCVE")
    def test_server_cli_uses_embedded_fastcve_data_path(self, fastcve, create_app, uvicorn_run):
        application = object()
        engine = fastcve.return_value
        engine.load = AsyncMock()
        create_app.return_value = application
        with patch.object(sys, "argv", [
            "cvewatchdog-server", "--data-path", "/srv/fastcve", "--port", "9000",
        ]):
            cvewatchdog_server.main()

        create_app.assert_called_once_with(
            fastcve_url=None,
            reports_dir="~/.local/share/cvewatchdog/reports",
            data_path="/srv/fastcve",
            engine=engine,
        )
        fastcve.assert_called_once_with("/srv/fastcve")
        engine.load.assert_awaited_once()
        uvicorn_run.assert_called_once_with(
            application, host="127.0.0.1", port=9000, access_log=False
        )

    @patch("uvicorn.run")
    @patch.object(cvewatchdog_server, "FastCVE")
    def test_ctrl_c_cancels_fastcve_startup(self, fastcve, uvicorn_run):
        engine = fastcve.return_value
        engine.load = AsyncMock(side_effect=KeyboardInterrupt)
        with (
            patch.object(sys, "argv", ["cvewatchdog-server"]),
            patch.object(cvewatchdog_server.CONSOLE, "status"),
            patch.object(cvewatchdog_server.CONSOLE, "print") as console_print,
        ):
            cvewatchdog_server.main()

        engine.close.assert_called_once_with()
        console_print.assert_called_once_with("[yellow]FastCVE startup cancelled.[/]")
        uvicorn_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
