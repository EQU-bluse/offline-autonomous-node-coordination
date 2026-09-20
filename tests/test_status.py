import json
import subprocess
import sys
import unittest


class StatusCommandTest(unittest.TestCase):
    def test_status_is_machine_readable(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "offline_coordination", "status"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            json.loads(result.stdout),
            {
                "connectivity": "offline",
                "nodeId": "local-node",
                "pendingChanges": 0,
                "revision": 0,
            },
        )


if __name__ == "__main__":
    unittest.main()
