import unittest

import CVEWatchdog


class PackagingTests(unittest.TestCase):
    def test_console_entry_point_targets_main(self):
        self.assertTrue(callable(CVEWatchdog.main))


if __name__ == "__main__":
    unittest.main()
