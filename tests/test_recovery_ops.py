"""Tests for read-only recovery diagnostics and controlled batch recovery.

Covers :func:`inspect_recovery`, :func:`recover_many`, the ``recovery
check``/``recovery run`` module entry points and the corrected ``clean``
digest of :func:`recover_ledger`.
"""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication as R
from offline_coordination.replication import (
    CorruptRecoveryError,
    inspect_recovery,
    recover_many,
)


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, n, writer="node-a"):
    return [value, False, {writer: n}, writer]


def make_request(rid, base, remote, source="node-a"):
    return {"id": rid, "source": source, "base": base, "remote": remote}


S0 = state()
S1 = state({"node-a": 1}, {"k": record("v1", 1)})
S2 = state({"node-a": 2}, {"k": record("v2", 2)})


def digest_of(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def snapshot_dir(directory):
    snap = {}
    for name in os.listdir(directory):
        full = os.path.join(directory, name)
        if os.path.isfile(full):
            with open(full, "rb") as handle:
                snap[name] = handle.read()
    return snap


def restore_dir(directory, snap):
    for name in os.listdir(directory):
        os.unlink(os.path.join(directory, name))
    for name, data in snap.items():
        with open(os.path.join(directory, name), "wb") as handle:
            handle.write(data)


class CrashCapture:
    """Snapshot the commit directory at one exact interruption point."""

    def __init__(self, path, moment):
        self.path = path
        self.moment = moment
        self.directory = os.path.dirname(path)
        self.snapshot = None
        self._intent_publishes = 0

    def __enter__(self):
        self._real_replace = os.replace
        self._replace_patch = mock.patch("os.replace", self._replace)
        self._replace_patch.start()
        return self

    def __exit__(self, *exc):
        self._replace_patch.stop()
        return False

    def _snap(self):
        if self.snapshot is None:
            self.snapshot = snapshot_dir(self.directory)

    def _replace(self, src, dst):
        if dst == self.path + ".txn":
            self._intent_publishes += 1
        if self.moment == "before-install" and dst == self.path:
            self._snap()
        result = self._real_replace(src, dst)
        if (
            self.moment == "confirmed"
            and dst == self.path + ".txn"
            and self._intent_publishes == 2
        ):
            self._snap()
        return result


class BatchCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def ledger_path(self, tag="ledger"):
        return os.path.join(self.dir, f"{tag}.json")

    def committed_ledger(self, tag="ledger"):
        path = self.ledger_path(tag)
        R.apply_remote(path, make_request("r1", S0, S1))
        return path

    def crash_state(self, tag, moment):
        """A fresh directory holding exactly the files at the crash."""
        src_dir = tempfile.mkdtemp(dir=self.dir)
        src = os.path.join(src_dir, "ledger.json")
        R.apply_remote(src, make_request("r1", S0, S1))
        old = read_bytes(src)
        with CrashCapture(src, moment) as crash:
            R.apply_remote(src, make_request("r2", S1, S2))
        self.assertIsNotNone(crash.snapshot, f"no snapshot at {moment}")
        new = read_bytes(src)
        fresh = tempfile.mkdtemp(dir=self.dir)
        restore_dir(fresh, crash.snapshot)
        return os.path.join(fresh, "ledger.json"), old, new


class PathListValidationTest(BatchCase):
    def assert_untouched(self, func, paths):
        before = snapshot_dir(self.dir)
        return_before = os.listdir(self.dir)
        with self.assertRaises((TypeError, ValueError)):
            func(paths)
        self.assertEqual(os.listdir(self.dir), return_before)
        self.assertEqual(snapshot_dir(self.dir), before)

    def test_type_errors(self):
        for bad in (None, 1, True, "ledger.json", b"x", (self.ledger_path(),),
                    {"a": 1}):
            with self.subTest(bad=bad):
                for func in (inspect_recovery, recover_many):
                    self.assert_untouched(func, bad)
        with self.assertRaises(TypeError):
            inspect_recovery([self.ledger_path(), 1])
        with self.assertRaises(TypeError):
            recover_many([None])

    def test_value_errors(self):
        for bad in ([], [""], ["a", "a"], ["a", "b", "a"]):
            with self.subTest(bad=bad):
                for func in (inspect_recovery, recover_many):
                    self.assert_untouched(func, bad)

    def test_type_error_precedes_value_error_and_io(self):
        # Full validation happens before any file is read: a type fault
        # anywhere in the list raises TypeError even alongside an empty
        # path, and nothing is touched.
        with self.assertRaises(TypeError):
            inspect_recovery(["", 1])
        with self.assertRaises(TypeError):
            recover_many([os.path.join(self.dir, "missing.json"), 1.5])


class InspectCleanTest(BatchCase):
    def test_clean_with_existing_ledger_reports_full_digest(self):
        path = self.committed_ledger()
        (item,) = inspect_recovery([path])
        self.assertEqual(
            list(item.keys()),
            ["path", "status", "phase", "digest", "artifacts", "action",
             "error"],
        )
        self.assertEqual(
            item,
            {
                "path": path,
                "status": "clean",
                "phase": None,
                "digest": digest_of(read_bytes(path)),
                "artifacts": None,
                "action": None,
                "error": None,
            },
        )

    def test_clean_with_missing_ledger_reports_null_digest(self):
        path = self.ledger_path()
        (item,) = inspect_recovery([path])
        self.assertEqual(item["status"], "clean")
        self.assertIsNone(item["digest"])
        self.assertIsNone(item["phase"])
        self.assertIsNone(item["action"])

    def test_clean_scans_no_random_artifacts(self):
        path = self.ledger_path()
        for suffix in (".tmp.1234abcd", ".old.5678efab", ".txn.9999aaaa"):
            with open(path + suffix, "wb") as handle:
                handle.write(b"leftover\n")
        before = snapshot_dir(self.dir)
        (item,) = inspect_recovery([path])
        self.assertEqual(item["status"], "clean")
        self.assertEqual(snapshot_dir(self.dir), before)


class InspectPendingTest(BatchCase):
    def test_prepared_intent_suggests_rollback(self):
        path, old, new = self.crash_state("a", "before-install")
        before = snapshot_dir(os.path.dirname(path))
        (item,) = inspect_recovery([path])
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["phase"], "prepared")
        self.assertEqual(item["action"], "rollback")
        self.assertEqual(item["digest"], digest_of(old))
        self.assertIsNone(item["error"])
        artifacts = item["artifacts"]
        self.assertEqual(artifacts["candidate"], {"exists": True, "matches": True})
        self.assertEqual(
            artifacts["predecessor"], {"exists": True, "matches": True}
        )
        self.assertTrue(artifacts["complete"])
        # Read-only: nothing changed.
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_installed_intent_suggests_complete(self):
        path, _old, new = self.crash_state("b", "confirmed")
        before = snapshot_dir(os.path.dirname(path))
        (item,) = inspect_recovery([path])
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["phase"], "installed")
        self.assertEqual(item["action"], "complete")
        self.assertEqual(item["digest"], digest_of(new))
        self.assertTrue(item["artifacts"]["complete"])
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_missing_ledger_and_candidate_reported(self):
        path, _old, _new = self.crash_state("c", "before-install")
        names = os.listdir(os.path.dirname(path))
        candidate = [n for n in names if ".tmp." in n][0]
        os.unlink(os.path.join(os.path.dirname(path), candidate))
        os.unlink(path)
        (item,) = inspect_recovery([path])
        self.assertEqual(item["status"], "pending")
        self.assertIsNone(item["digest"])
        self.assertEqual(
            item["artifacts"]["candidate"], {"exists": False, "matches": None}
        )
        self.assertTrue(item["artifacts"]["complete"])


class InspectBlockedTest(BatchCase):
    def test_malformed_intent_is_blocked_corrupt(self):
        path, _old, _new = self.crash_state("d", "before-install")
        with open(path + ".txn", "wb") as handle:
            handle.write(b"this is not json\n")
        before = snapshot_dir(os.path.dirname(path))
        (item,) = inspect_recovery([path])
        self.assertEqual(item["status"], "blocked")
        self.assertEqual(item["error"], "corrupt")
        self.assertIsNone(item["phase"])
        self.assertIsNone(item["action"])
        self.assertIsNone(item["artifacts"])
        self.assertEqual(item["digest"], digest_of(read_bytes(path)))
        # Blocked diagnostics never touch the files.
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_missing_predecessor_is_blocked_corrupt(self):
        path, _old, new = self.crash_state("e", "before-install")
        # Move the ledger to the new bytes so the predecessor is needed.
        names = os.listdir(os.path.dirname(path))
        candidate = [n for n in names if ".tmp." in n][0]
        os.replace(os.path.join(os.path.dirname(path), candidate), path)
        names = os.listdir(os.path.dirname(path))
        predecessor = [n for n in names if ".old." in n][0]
        os.unlink(os.path.join(os.path.dirname(path), predecessor))
        before = snapshot_dir(os.path.dirname(path))
        (item,) = inspect_recovery([path])
        self.assertEqual(item["status"], "blocked")
        self.assertEqual(item["error"], "corrupt")
        self.assertEqual(item["phase"], "prepared")
        self.assertEqual(item["action"], "rollback")
        self.assertEqual(
            item["artifacts"]["predecessor"],
            {"exists": False, "matches": None},
        )
        self.assertFalse(item["artifacts"]["complete"])
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_installed_intent_with_foreign_ledger_is_blocked(self):
        path, _old, _new = self.crash_state("f", "confirmed")
        with open(path, "wb") as handle:
            handle.write(b"foreign ledger bytes\n")
        (item,) = inspect_recovery([path])
        self.assertEqual(item["status"], "blocked")
        self.assertEqual(item["error"], "corrupt")
        self.assertEqual(item["phase"], "installed")
        self.assertEqual(item["action"], "complete")
        self.assertFalse(item["artifacts"]["complete"])


class InspectOSErrorTest(BatchCase):
    def test_os_error_is_failed_and_remaining_paths_continue(self):
        good = self.committed_ledger("good")
        bad = self.ledger_path("bad")
        with open(bad + ".txn", "wb") as handle:
            handle.write(b"{}")
        sentinel = OSError("read denied")
        real_open = open

        def failing_open(target, *args, **kwargs):
            if isinstance(target, str) and target == bad + ".txn":
                raise sentinel
            return real_open(target, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=failing_open):
            items = inspect_recovery([bad, good])
        self.assertEqual(
            items[0],
            {
                "path": bad,
                "status": "failed",
                "phase": None,
                "digest": None,
                "artifacts": None,
                "action": None,
                "error": "os-error",
            },
        )
        self.assertEqual(items[1]["status"], "clean")
        self.assertEqual(items[1]["digest"], digest_of(read_bytes(good)))


class RecoverManyTest(BatchCase):
    def test_recovers_each_status_in_order(self):
        clean = self.committed_ledger("clean")
        prepared, old, _new = self.crash_state("g", "before-install")
        confirmed, _old, new = self.crash_state("h", "confirmed")
        missing = os.path.join(self.dir, "missing.json")
        items = recover_many([clean, prepared, confirmed, missing])
        self.assertEqual(
            [list(item.keys()) for item in items],
            [["path", "status", "digest", "error"]] * 4,
        )
        self.assertEqual(
            items[0],
            {
                "path": clean,
                "status": "clean",
                "digest": digest_of(read_bytes(clean)),
                "error": None,
            },
        )
        self.assertEqual(
            items[1],
            {
                "path": prepared,
                "status": "rolled-back",
                "digest": digest_of(old),
                "error": None,
            },
        )
        self.assertEqual(
            items[2],
            {
                "path": confirmed,
                "status": "completed",
                "digest": digest_of(new),
                "error": None,
            },
        )
        self.assertEqual(
            items[3],
            {"path": missing, "status": "clean", "digest": None, "error": None},
        )

    def test_corrupt_item_does_not_stop_or_roll_back_others(self):
        first, old, _new = self.crash_state("i", "before-install")
        corrupt, _o2, _n2 = self.crash_state("j", "before-install")
        with open(corrupt + ".txn", "wb") as handle:
            handle.write(b"not json\n")
        third, _o3, new3 = self.crash_state("k", "confirmed")
        items = recover_many([first, corrupt, third])
        self.assertEqual(items[0]["status"], "rolled-back")
        self.assertEqual(
            items[1],
            {
                "path": corrupt,
                "status": "blocked",
                "digest": None,
                "error": "corrupt",
            },
        )
        self.assertEqual(items[2]["status"], "completed")
        # The earlier success was not rolled back by the later failure.
        self.assertEqual(read_bytes(first), old)
        self.assertEqual(read_bytes(third), new3)
        # The corrupt ledger keeps its material for an independent retry.
        self.assertTrue(os.path.exists(corrupt + ".txn"))

    def test_os_error_item_and_independent_retry(self):
        path, old, _new = self.crash_state("l", "before-install")
        sentinel = OSError("sync denied")
        with mock.patch(
            "offline_coordination.storage._fsync_dir", side_effect=sentinel
        ):
            (item,) = recover_many([path])
        self.assertEqual(
            item,
            {"path": path, "status": "failed", "digest": None,
             "error": "os-error"},
        )
        # The intent survived, so a re-run retries and settles the ledger.
        (retry,) = recover_many([path])
        self.assertEqual(retry["status"], "rolled-back")
        self.assertEqual(retry["digest"], digest_of(old))
        self.assertEqual(read_bytes(path), old)


class CleanDigestTest(BatchCase):
    def test_clean_digest_is_full_byte_sha256(self):
        path = self.committed_ledger()
        result = R.recover_ledger(path)
        self.assertEqual(
            result, {"digest": digest_of(read_bytes(path)), "status": "clean"}
        )

    def test_clean_digest_is_null_when_missing(self):
        result = R.recover_ledger(self.ledger_path())
        self.assertEqual(result, {"digest": None, "status": "clean"})


class RecoveryCommandTest(BatchCase):
    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "offline_coordination", *argv],
            capture_output=True,
            text=True,
        )

    def write_materials(self, paths, nonce="nonce-1"):
        """Write a keyring and a matching ticket, returning CLI options."""
        secret = "ab" * 32
        keyring = {
            "issuer-a": [
                {
                    "version": 1,
                    "secret": secret,
                    "notBefore": 0,
                    "notAfter": 10 ** 9,
                    "revoked": False,
                }
            ]
        }
        payload = {
            "issuer": "issuer-a",
            "keyVersion": 1,
            "nonce": nonce,
            "notBefore": 0,
            "notAfter": 10 ** 9,
            "paths": list(paths),
        }
        compact = lambda obj: json.dumps(
            obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        signature = hmac.new(
            bytes.fromhex(secret), compact(payload), hashlib.sha256
        ).hexdigest()
        keyring_path = os.path.join(self.dir, f"keyring-{nonce}.json")
        with open(keyring_path, "wb") as handle:
            handle.write(compact(keyring))
        ticket_path = os.path.join(self.dir, f"ticket-{nonce}.json")
        with open(ticket_path, "wb") as handle:
            handle.write(compact({"payload": payload, "signature": signature}) + b"\n")
        audit_path = os.path.join(self.dir, f"audit-{nonce}.jsonl")
        return (
            "--keyring", keyring_path,
            "--ticket", ticket_path,
            "--moment", "7",
            "--audit", audit_path,
        )

    def test_check_outputs_one_sorted_compact_json_line(self):
        path = self.committed_ledger()
        result = self.run_cli("recovery", "check", path)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("\n"), 1)
        payload = json.loads(result.stdout)
        self.assertEqual(
            payload,
            [
                {
                    "action": None,
                    "artifacts": None,
                    "digest": digest_of(read_bytes(path)),
                    "error": None,
                    "path": path,
                    "phase": None,
                    "status": "clean",
                }
            ],
        )
        # Compact with recursively sorted keys.
        self.assertEqual(
            result.stdout.strip(),
            json.dumps(payload, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")),
        )

    def test_run_recovers_and_exits_zero(self):
        prepared, old, _new = self.crash_state("m", "before-install")
        materials = self.write_materials([prepared])
        result = self.run_cli("recovery", "run", prepared, *materials)
        self.assertEqual(result.returncode, 0, result.stderr)
        (item,) = json.loads(result.stdout)
        self.assertEqual(item["status"], "rolled-back")
        self.assertEqual(item["digest"], digest_of(old))

    def test_run_without_materials_exits_two(self):
        prepared, _old, _new = self.crash_state("m2", "before-install")
        result = self.run_cli("recovery", "run", prepared)
        self.assertEqual(result.returncode, 2)

    def test_blocked_ledger_exits_one(self):
        path, _old, _new = self.crash_state("n", "before-install")
        with open(path + ".txn", "wb") as handle:
            handle.write(b"not json\n")
        result = self.run_cli("recovery", "check", path)
        self.assertEqual(result.returncode, 1)
        (item,) = json.loads(result.stdout)
        self.assertEqual(item["error"], "corrupt")
        materials = self.write_materials([path])
        result = self.run_cli("recovery", "run", path, *materials)
        self.assertEqual(result.returncode, 1)
        (item,) = json.loads(result.stdout)
        self.assertEqual(item["error"], "corrupt")

    def test_argument_errors_exit_two(self):
        for argv in (
            ("recovery",),
            ("recovery", "check"),
            ("recovery", "peek", "x"),
            ("recovery", "check", "a", "a"),
            ("recovery", "run", ""),
            ("nonsense",),
        ):
            with self.subTest(argv=argv):
                result = self.run_cli(*argv)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
