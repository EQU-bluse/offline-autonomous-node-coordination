"""Tests for node-level ledger inspection: ``inspect_node``.

Covers the read-only per-ledger classification (healthy empty/stable,
oversize, pending with a valid recovery intent, blocked corrupt intent,
corrupt ledger, os-error), per-item failure isolation, the node-level
summaries and health, batch argument validation, and the
``status --ledger`` module entry point.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication as R
from offline_coordination.replication import inspect_node


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
    """Snapshot the ledger directory at one interruption point."""

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


class InspectNodeCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def ledger_path(self, tag="ledger"):
        return os.path.join(self.dir, f"{tag}.json")

    def committed_ledger(self, tag="ledger", commits=1):
        path = self.ledger_path(tag)
        if commits >= 1:
            R.apply_remote(path, make_request("r1", S0, S1))
        if commits >= 2:
            R.apply_remote(path, make_request("r2", S1, S2))
        return path

    def crash_state(self, tag, moment, existed=True):
        """A fresh directory holding exactly the files at the crash."""
        src_dir = tempfile.mkdtemp(dir=self.dir)
        src = os.path.join(src_dir, "ledger.json")
        if existed:
            R.apply_remote(src, make_request("r1", S0, S1))
            old = read_bytes(src)
            request = make_request("r2", S1, S2)
        else:
            old = None
            request = make_request("r1", S0, S1)
        with CrashCapture(src, moment) as crash:
            R.apply_remote(src, request)
        self.assertIsNotNone(crash.snapshot, f"no snapshot at {moment}")
        new = read_bytes(src)
        fresh = tempfile.mkdtemp(dir=self.dir)
        restore_dir(fresh, crash.snapshot)
        return os.path.join(fresh, "ledger.json"), old, new

    def state_digest_of_ledger(self, path):
        parsed_state, _requests, _entries = R._parse_ledger(read_bytes(path))
        return digest_of(R._state_bytes(parsed_state))


class ItemShapeTest(InspectNodeCase):
    def test_item_and_top_level_key_order(self):
        path = self.committed_ledger()
        report = inspect_node([path])
        self.assertEqual(
            list(report.keys()),
            [
                "connectivity",
                "health",
                "items",
                "maxBytes",
                "nodeId",
                "pendingChanges",
                "revision",
                "totalBytes",
                "version",
            ],
        )
        (item,) = report["items"]
        self.assertEqual(
            list(item.keys()),
            [
                "path",
                "status",
                "digest",
                "bytes",
                "lastSeq",
                "requestCount",
                "stateDigest",
                "phase",
                "action",
                "error",
            ],
        )

    def test_static_top_level_fields(self):
        report = inspect_node([self.ledger_path()])
        self.assertEqual(report["connectivity"], "offline")
        self.assertEqual(report["nodeId"], "local-node")
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["maxBytes"], 67108864)
        # Fresh independent objects per call.
        again = inspect_node([self.ledger_path()])
        self.assertIsNot(report, again)
        self.assertIsNot(report["items"], again["items"])

    def test_items_keep_input_order(self):
        first = self.committed_ledger("b")
        second = self.committed_ledger("a")
        third = self.ledger_path("c")
        report = inspect_node([third, first, second])
        self.assertEqual(
            [item["path"] for item in report["items"]],
            [third, first, second],
        )


class MissingAndStableLedgerTest(InspectNodeCase):
    def test_missing_ledger_is_healthy_empty(self):
        path = self.ledger_path()
        (item,) = inspect_node([path])["items"]
        self.assertEqual(
            item,
            {
                "path": path,
                "status": "healthy",
                "digest": None,
                "bytes": None,
                "lastSeq": 0,
                "requestCount": 0,
                "stateDigest": None,
                "phase": None,
                "action": None,
                "error": None,
            },
        )

    def test_stable_ledger_summaries(self):
        path = self.committed_ledger(commits=2)
        raw = read_bytes(path)
        (item,) = inspect_node([path])["items"]
        self.assertEqual(item["status"], "healthy")
        self.assertEqual(item["digest"], digest_of(raw))
        self.assertEqual(item["bytes"], len(raw))
        self.assertEqual(item["lastSeq"], 2)
        self.assertEqual(item["requestCount"], 2)
        self.assertEqual(item["stateDigest"], self.state_digest_of_ledger(path))
        self.assertIsNone(item["phase"])
        self.assertIsNone(item["action"])
        self.assertIsNone(item["error"])

    def test_oversize_ledger_keeps_summaries(self):
        path = self.committed_ledger(commits=1)
        raw = read_bytes(path)
        (item,) = inspect_node([path], max_bytes=len(raw) - 1)["items"]
        self.assertEqual(item["status"], "oversize")
        self.assertEqual(item["digest"], digest_of(raw))
        self.assertEqual(item["bytes"], len(raw))
        self.assertEqual(item["lastSeq"], 1)
        self.assertEqual(item["requestCount"], 1)
        self.assertEqual(item["stateDigest"], self.state_digest_of_ledger(path))
        self.assertIsNone(item["error"])
        # Exactly the limit is still healthy.
        (at_limit,) = inspect_node([path], max_bytes=len(raw))["items"]
        self.assertEqual(at_limit["status"], "healthy")

    def test_missing_ledger_is_not_oversize(self):
        (item,) = inspect_node([self.ledger_path()], max_bytes=1)["items"]
        self.assertEqual(item["status"], "healthy")


class PendingLedgerTest(InspectNodeCase):
    def test_prepared_pending_preserves_phase_action_and_stable_summaries(self):
        path, old, _new = self.crash_state("p", "before-install")
        before = snapshot_dir(os.path.dirname(path))
        (item,) = inspect_node([path])["items"]
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["phase"], "prepared")
        self.assertEqual(item["action"], "rollback")
        # The ledger on disk is still the old, stable ledger.
        self.assertEqual(item["digest"], digest_of(old))
        self.assertEqual(item["bytes"], len(old))
        self.assertEqual(item["lastSeq"], 1)
        self.assertEqual(item["requestCount"], 1)
        old_state, _, _ = R._parse_ledger(old)
        self.assertEqual(item["stateDigest"], digest_of(R._state_bytes(old_state)))
        self.assertIsNone(item["error"])
        # Read-only.
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_installed_pending_suggests_complete(self):
        path, _old, new = self.crash_state("i", "confirmed")
        (item,) = inspect_node([path])["items"]
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["phase"], "installed")
        self.assertEqual(item["action"], "complete")
        self.assertEqual(item["digest"], digest_of(new))
        self.assertEqual(item["lastSeq"], 2)
        self.assertEqual(item["requestCount"], 2)

    def test_pending_missing_ledger_is_empty_stable_ledger(self):
        path, _old, _new = self.crash_state("m", "before-install", existed=False)
        self.assertFalse(os.path.exists(path))
        (item,) = inspect_node([path])["items"]
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["phase"], "prepared")
        self.assertEqual(item["action"], "rollback")
        self.assertIsNone(item["digest"])
        self.assertIsNone(item["stateDigest"])
        self.assertIsNone(item["bytes"])
        self.assertEqual(item["lastSeq"], 0)
        self.assertEqual(item["requestCount"], 0)

    def test_pending_is_not_oversize(self):
        path, old, _new = self.crash_state("o", "before-install")
        (item,) = inspect_node([path], max_bytes=1)["items"]
        self.assertEqual(item["status"], "pending")


class CorruptionAndFailureTest(InspectNodeCase):
    def test_corrupt_ledger(self):
        path = self.ledger_path()
        with open(path, "wb") as handle:
            handle.write(b"not a ledger\n")
        (item,) = inspect_node([path])["items"]
        self.assertEqual(item["status"], "corrupt")
        self.assertEqual(item["error"], "corrupt-ledger")
        self.assertEqual(item["digest"], digest_of(b"not a ledger\n"))
        self.assertEqual(item["bytes"], len(b"not a ledger\n"))
        for key in ("lastSeq", "requestCount", "stateDigest", "phase", "action"):
            self.assertIsNone(item[key], key)

    def test_corrupt_intent_is_blocked(self):
        path, _old, _new = self.crash_state("b", "before-install")
        ledger_bytes = read_bytes(path)
        with open(path + ".txn", "wb") as handle:
            handle.write(b"not json\n")
        (item,) = inspect_node([path])["items"]
        self.assertEqual(item["status"], "blocked")
        self.assertEqual(item["error"], "corrupt-recovery")
        self.assertEqual(item["digest"], digest_of(ledger_bytes))
        self.assertEqual(item["bytes"], len(ledger_bytes))
        for key in ("lastSeq", "requestCount", "stateDigest", "phase", "action"):
            self.assertIsNone(item[key], key)

    def test_corrupt_intent_with_missing_ledger_is_blocked(self):
        path = self.ledger_path()
        with open(path + ".txn", "wb") as handle:
            handle.write(b"broken\n")
        (item,) = inspect_node([path])["items"]
        self.assertEqual(item["status"], "blocked")
        self.assertEqual(item["error"], "corrupt-recovery")
        self.assertIsNone(item["digest"])
        self.assertIsNone(item["bytes"])

    def test_invalid_ledger_with_structurally_valid_intent_is_corrupt(self):
        # Intent parsing is structural; it does not cross-check the
        # artifacts, so a valid intent over an unparseable ledger cannot
        # be reported as pending -- the ledger itself is corrupt.
        path, _old, _new = self.crash_state("c", "before-install")
        with open(path, "wb") as handle:
            handle.write(b"garbage\n")
        (item,) = inspect_node([path])["items"]
        self.assertEqual(item["status"], "corrupt")
        self.assertEqual(item["error"], "corrupt-ledger")
        self.assertIsNone(item["phase"])
        self.assertIsNone(item["action"])

    def test_os_error_is_isolated_and_reported(self):
        ledger = self.committed_ledger("good")
        other = self.committed_ledger("other")
        bad = os.path.join(self.dir, "a-directory")
        os.mkdir(bad)
        report = inspect_node([ledger, bad, other])
        statuses = [item["status"] for item in report["items"]]
        self.assertEqual(statuses, ["healthy", "failed", "healthy"])
        bad_item = report["items"][1]
        self.assertEqual(bad_item["error"], "os-error")
        self.assertIsNone(bad_item["digest"])
        self.assertIsNone(bad_item["bytes"])
        self.assertIsNone(bad_item["lastSeq"])


class NodeSummaryTest(InspectNodeCase):
    def test_all_healthy_is_healthy(self):
        first = self.committed_ledger("a")
        second = self.ledger_path("missing")
        report = inspect_node([first, second])
        self.assertEqual(report["health"], "healthy")
        self.assertEqual(report["pendingChanges"], 0)
        self.assertEqual(report["revision"], 1)
        self.assertEqual(report["totalBytes"], len(read_bytes(first)))

    def test_revision_is_max_stable_last_seq(self):
        two = self.committed_ledger("two", commits=2)
        one = self.committed_ledger("one", commits=1)
        missing = self.ledger_path("m")
        report = inspect_node([missing, one, two])
        self.assertEqual(report["revision"], 2)
        # A pending ledger's stable seq still participates.
        pending, _old, _new = self.crash_state("p", "before-install")
        report = inspect_node([two, pending])
        self.assertEqual(report["revision"], 2)
        pending_installed, _o, _n = self.crash_state("q", "confirmed")
        report = inspect_node([one, pending_installed])
        self.assertEqual(report["revision"], 2)

    def test_pending_changes_counts_pending(self):
        a, _o, _n = self.crash_state("a", "before-install")
        b, _o2, _n2 = self.crash_state("b", "confirmed")
        healthy = self.committed_ledger("h")
        report = inspect_node([a, healthy, b])
        self.assertEqual(report["pendingChanges"], 2)

    def test_total_bytes_counts_ledger_bytes_only(self):
        good = self.committed_ledger("g", commits=2)
        garbage_path = self.ledger_path("bad")
        with open(garbage_path, "wb") as handle:
            handle.write(b"x" * 7)
        missing = self.ledger_path("missing")
        report = inspect_node([good, garbage_path, missing])
        self.assertEqual(
            report["totalBytes"], len(read_bytes(good)) + 7
        )

    def test_only_oversize_is_degraded(self):
        path = self.committed_ledger()
        report = inspect_node([path], max_bytes=1)
        self.assertEqual(report["health"], "degraded")

    def test_only_pending_is_degraded(self):
        path, _old, _new = self.crash_state("a", "before-install")
        report = inspect_node([path])
        self.assertEqual(report["health"], "degraded")

    def test_blocked_corrupt_failed_are_unhealthy(self):
        healthy = self.committed_ledger("h")

        blocked, _o, _n = self.crash_state("b", "before-install")
        with open(blocked + ".txn", "wb") as handle:
            handle.write(b"bad\n")

        corrupt = self.ledger_path("c")
        with open(corrupt, "wb") as handle:
            handle.write(b"bad\n")

        failed = os.path.join(self.dir, "dir-ledger")
        os.mkdir(failed)

        for bad in (blocked, corrupt, failed):
            report = inspect_node([healthy, bad])
            self.assertEqual(report["health"], "unhealthy", bad)

    def test_no_revision_when_no_stable_ledger(self):
        corrupt = self.ledger_path("c")
        with open(corrupt, "wb") as handle:
            handle.write(b"bad\n")
        failed = os.path.join(self.dir, "d")
        os.mkdir(failed)
        report = inspect_node([corrupt, failed])
        self.assertEqual(report["health"], "unhealthy")
        self.assertEqual(report["revision"], 0)
        self.assertEqual(report["totalBytes"], 4)


class ValidationTest(InspectNodeCase):
    def test_path_type_errors(self):
        for bad in (None, 1, True, "ledger.json", b"x", (self.ledger_path(),),
                    {"a": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    inspect_node(bad)

    def test_element_type_error(self):
        with self.assertRaises(TypeError):
            inspect_node([self.ledger_path(), 1])
        with self.assertRaises(TypeError):
            inspect_node([None])

    def test_path_value_errors(self):
        for bad in ([], [""], ["a", "a"], ["a", "b", "a"]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    inspect_node(bad)

    def test_max_bytes_validation(self):
        path = self.ledger_path()
        for bad in (True, False):
            with self.assertRaises(TypeError):
                inspect_node([path], bad)
        for bad in (1.5, "8", None):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    inspect_node([path], bad)
        for bad in (0, -1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    inspect_node([path], bad)

    def test_validation_precedes_file_access(self):
        bad_dir = os.path.join(self.dir, "actually-a-dir")
        os.mkdir(bad_dir)
        before = snapshot_dir(self.dir)
        with self.assertRaises(TypeError):
            inspect_node([bad_dir, 1])
        with self.assertRaises(ValueError):
            inspect_node([bad_dir, bad_dir])
        with self.assertRaises(TypeError):
            inspect_node([bad_dir], True)
        with self.assertRaises(ValueError):
            inspect_node([bad_dir], 0)
        self.assertEqual(snapshot_dir(self.dir), before)

    def test_read_only_leaves_random_artifacts(self):
        path = self.ledger_path()
        for suffix in (".tmp.1234abcd", ".old.5678efab", ".txn.9999aaaa"):
            with open(path + suffix, "wb") as handle:
                handle.write(b"leftover\n")
        before = snapshot_dir(self.dir)
        inspect_node([path])
        self.assertEqual(snapshot_dir(self.dir), before)


class StatusCommandTest(InspectNodeCase):
    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "offline_coordination", *argv],
            capture_output=True,
            text=True,
        )

    def test_status_without_flags_is_unchanged(self):
        result = self.run_cli("status")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            json.loads(result.stdout),
            {
                "connectivity": "offline",
                "nodeId": "local-node",
                "pendingChanges": 0,
                "revision": 0,
            },
        )

    def test_ledger_status_one_sorted_compact_line_healthy(self):
        path = self.ledger_path("missing")
        result = self.run_cli("status", "--ledger", path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("\n"), 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload, inspect_node([path]))
        self.assertEqual(
            result.stdout.strip(),
            json.dumps(
                payload, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ),
        )

    def test_ledger_status_degraded_exits_one(self):
        path, _old, _new = self.crash_state("a", "before-install")
        result = self.run_cli("status", "--ledger", path)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["health"], "degraded")

    def test_ledger_status_unhealthy_exits_one(self):
        path = self.ledger_path()
        with open(path, "wb") as handle:
            handle.write(b"garbage\n")
        result = self.run_cli("status", "--ledger", path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["health"], "unhealthy")

    def test_max_bytes_is_forwarded(self):
        path = self.committed_ledger()
        result = self.run_cli("status", "--ledger", path, "--max-bytes", "1")
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["maxBytes"], 1)
        self.assertEqual(payload["items"][0]["status"], "oversize")

    def test_multiple_ledgers(self):
        good = self.committed_ledger("g")
        missing = self.ledger_path("m")
        result = self.run_cli("status", "--ledger", good, missing)
        self.assertEqual(result.returncode, 0)

    def test_argument_errors_exit_two(self):
        good = self.committed_ledger()
        for argv in (
            ("status", "--ledger"),
            ("status", "--ledger", good, good),
            ("status", "--ledger", good, "--max-bytes", "0"),
            ("status", "--ledger", good, "--max-bytes", "nope"),
            ("status", "--max-bytes", "10"),
        ):
            with self.subTest(argv=argv):
                result = self.run_cli(*argv)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
