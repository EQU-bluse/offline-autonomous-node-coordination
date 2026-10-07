"""Subcommand tests for ``replication export`` and ``replication import``."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

from offline_coordination.audit import append


SECRET = "a" * 64
ISSUER = "node-a"
SESSION = "transfer-1"
NOW = 100


def keyring(secret=SECRET, not_after=1000, issuer=ISSUER):
    return {
        issuer: [
            {
                "version": 1,
                "secret": secret,
                "notBefore": 0,
                "notAfter": not_after,
                "revoked": False,
            }
        ]
    }


class ReplicationCommandTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.audit = os.path.join(self.dir, "audit.jsonl")
        self.other = os.path.join(self.dir, "other.jsonl")
        self.packet = os.path.join(self.dir, "packet.bin")
        self.keyring = os.path.join(self.dir, "keyring.json")
        for i in range(3):
            append(
                self.audit,
                {"source": ISSUER, "kind": "local", "detail": f"event {i} ☃"},
            )
        with open(self.keyring, "w", encoding="utf-8") as handle:
            json.dump(keyring(), handle)

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "offline_coordination", *arguments],
            capture_output=True,
            text=True,
        )

    def export_args(self, output=None, **overrides):
        args = [
            "replication", "export", self.audit,
            output or self.packet,
            "--after", "0",
            "--max-bytes", "10000000",
            "--session", SESSION,
            "--keyring", self.keyring,
            "--issuer", ISSUER,
            "--key-version", "1",
            "--moment", str(NOW),
        ]
        for flag, value in overrides.items():
            args.extend([flag, str(value)])
        return args

    def import_args(self, audit, packet=None, *extra):
        return [
            "replication", "import", audit, packet or self.packet,
            "--keyring", self.keyring, "--moment", str(NOW), *extra,
        ]

    def test_export_reports_bytes_and_digest_of_file(self) -> None:
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        data = open(self.packet, "rb").read()
        self.assertEqual(report["status"], "exported")
        self.assertEqual(report["output"], self.packet)
        self.assertEqual(report["bytes"], len(data))
        self.assertEqual(
            report["digest"], hashlib.sha256(data).hexdigest()
        )
        self.assertEqual(set(report), {"status", "output", "bytes", "digest"})
        # One compact, sorted-key JSON line with no prose around it.
        self.assertEqual(result.stdout.count("\n"), 1)
        self.assertNotIn(" ", result.stdout.strip())

    def test_export_refuses_to_overwrite(self) -> None:
        with open(self.packet, "wb") as handle:
            handle.write(b"original")
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("already exists", result.stderr)
        self.assertEqual(open(self.packet, "rb").read(), b"original")

    def test_export_failure_leaves_no_file(self) -> None:
        result = self.run_cli(*self.export_args(**{"--after": "99"}))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(os.path.exists(self.packet))

    def test_export_bad_keyring_paths_exit_two(self) -> None:
        missing = self.run_cli(
            *self.export_args(**{"--keyring": os.path.join(self.dir, "nope")})
        )
        self.assertEqual((missing.returncode, missing.stdout), (2, ""))
        bad = os.path.join(self.dir, "bad.json")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        result = self.run_cli(*self.export_args(**{"--keyring": bad}))
        self.assertEqual((result.returncode, result.stdout), (2, ""))

    def test_import_applied_then_duplicate(self) -> None:
        self.assertEqual(self.run_cli(*self.export_args()).returncode, 0)
        applied = self.run_cli(*self.import_args(self.other))
        self.assertEqual(applied.returncode, 0)
        self.assertEqual(json.loads(applied.stdout)["status"], "applied")
        duplicate = self.run_cli(*self.import_args(self.other))
        self.assertEqual(duplicate.returncode, 0)
        self.assertEqual(json.loads(duplicate.stdout)["status"], "duplicate")

    def test_import_missing_exits_one_and_does_not_write(self) -> None:
        tail = os.path.join(self.dir, "tail.bin")
        self.assertEqual(
            self.run_cli(*self.export_args(output=tail, **{"--after": "2"})).returncode,
            0,
        )
        target = os.path.join(self.dir, "empty.jsonl")
        result = self.run_cli(
            "replication", "import", target, tail,
            "--keyring", self.keyring, "--moment", str(NOW),
        )
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["status"], "missing")
        self.assertEqual(report["need"], [1, 2])
        self.assertFalse(os.path.exists(target))

    def test_import_fork_exits_one(self) -> None:
        self.assertEqual(self.run_cli(*self.export_args()).returncode, 0)
        append(
            self.other,
            {"source": ISSUER, "kind": "local", "detail": "divergent"},
        )
        for i in range(1, 3):
            append(
                self.other,
                {"source": ISSUER, "kind": "local", "detail": f"event {i} ☃"},
            )
        result = self.run_cli(*self.import_args(self.other))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "fork")

    def test_import_over_budget_rejected_before_target_touched(self) -> None:
        self.assertEqual(self.run_cli(*self.export_args()).returncode, 0)
        result = self.run_cli(
            *self.import_args(self.other, None, "--max-bytes", "8")
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("max_bytes", result.stderr)
        self.assertFalse(os.path.exists(self.other))

    def test_import_authentication_failure_exits_two(self) -> None:
        self.assertEqual(self.run_cli(*self.export_args()).returncode, 0)
        result = self.run_cli(*self.import_args(self.other, "--moment", "99999"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_default_max_bytes_matches_python_interface(self) -> None:
        from offline_coordination.replication import import_signed_batch
        import inspect

        default = inspect.signature(
            import_signed_batch
        ).parameters["max_bytes"].default
        self.assertEqual(default, 67108864)


if __name__ == "__main__":
    unittest.main()
