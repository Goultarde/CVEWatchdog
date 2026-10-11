import importlib.util
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
            "http://localhost:8000/", "VLC media player", "3.0.21"
        )

        post.assert_called_once_with(
            "http://localhost:8000/api/resolve",
            json={"software": "VLC media player", "version": "3.0.21"},
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


if __name__ == "__main__":
    unittest.main()
