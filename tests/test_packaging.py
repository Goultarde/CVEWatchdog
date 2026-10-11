import unittest

import CVEWatchdog
import cvewatchdog_server


class PackagingTests(unittest.TestCase):
    def test_console_entry_point_targets_main(self):
        self.assertTrue(callable(CVEWatchdog.main))
        self.assertTrue(callable(cvewatchdog_server.main))


if __name__ == "__main__":
    unittest.main()
