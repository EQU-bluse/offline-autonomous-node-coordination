"""Regression tests for cross-process ledger crash recovery.

Each crash-window test drives a real commit and snapshots the directory
at the exact interruption point (intent landing, formal replacement,
confirmation, cleanup), then restarts into a fresh directory holding
exactly those files and checks what :func:`recover_ledger` makes of it.
"""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication as R
from offline_coordination.replication import CorruptRecoveryError, recover_ledger

SECRET_B = "b" * 64
NOW = 10


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, n, writer="node-a"):
    return [value, False, {writer: n}, writer]


def make_request(rid, base, remote, source="node-a"):
    return {"id": rid, "source": source, "base": base, "remote": remote}


def keyring():
    return {
        "node-b": [
            {
                "version": 1,
                "secret": SECRET_B,
                "notBefore": 0,
                "notAfter": 100,
                "revoked": False,
            }
        ]
    }


def signed_envelope(request_obj, node="node-b", key_version=1, secret=SECRET_B):
    payload = json.dumps(
        {"keyVersion": key_version, "node": node, "request": request_obj},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(
        bytes.fromhex(secret), payload, hashlib.sha256
    ).hexdigest()
    return {
        "node": node,
        "keyVersion": key_version,
        "request": request_obj,
        "signature": signature,
    }


S0 = state()
S1 = state({"node-a": 1}, {"k": record("v1", 1)})
S2 = state({"node-a": 2}, {"k": record("v2", 2)})
S3L = state({"node-a": 3}, {"k": record("v3l", 3)})
S3R = state(
    {"node-a": 2, "node-b": 1},
    {"k": record("v2", 2), "j": record("w1", 1, "node-b")},
)
S4R = state(
    {"node-a": 2, "node-b": 2},
    {"k": record("v2", 2), "j": record("w2", 2, "node-b")},
)


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
    """Snapshot the commit directory at one exact interruption point.

    Moments:
      ``intent-write``   the intent temporary is written but the prepared
                         intent is not yet published (no ``.txn`` exists)
      ``before-install`` the prepared intent is durable, the ledger not
                         yet replaced
      ``after-install``  the new ledger replaced the old one, the intent
                         still says ``prepared``
      ``confirmed``      the ``installed`` intent is durable, cleanup has
                         not started
      ``cleanup``        the predecessor link is already removed, the
                         installed intent still present
    """

    def __init__(self, path, moment):
        self.path = path
        self.moment = moment
        self.directory = os.path.dirname(path)
        self.snapshot = None
        self._intent_publishes = 0

    def __enter__(self):
        self._real_replace = os.replace
        self._real_unlink = os.unlink
        self._replace_patch = mock.patch("os.replace", self._replace)
        self._unlink_patch = mock.patch("os.unlink", self._unlink)
        self._replace_patch.start()
        self._unlink_patch.start()
        return self

    def __exit__(self, *exc):
        self._replace_patch.stop()
        self._unlink_patch.stop()
        return False

    def _snap(self):
        if self.snapshot is None:
            self.snapshot = snapshot_dir(self.directory)

    def _replace(self, src, dst):
        if dst == self.path + ".txn":
            self._intent_publishes += 1
            if self.moment == "intent-write" and self._intent_publishes == 1:
                self._snap()
        if self.moment == "before-install" and dst == self.path:
            self._snap()
        result = self._real_replace(src, dst)
        if self.moment == "after-install" and dst == self.path:
            self._snap()
        if (
            self.moment == "confirmed"
            and dst == self.path + ".txn"
            and self._intent_publishes == 2
        ):
            self._snap()
        return result

    def _unlink(self, target):
        result = self._real_unlink(target)
        if self.moment == "cleanup" and ".old." in os.path.basename(target):
            self._snap()
        return result


class RecoveryCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def crash_state(self, tag, moment, existed=True):
        """Commit into a source dir, snapshotting at ``moment``.

        Returns ``(path_in_fresh_dir, old_bytes, new_bytes)`` where the
        fresh directory holds exactly the files present at the crash.
        """
        src_dir = tempfile.mkdtemp(dir=self.dir)
        src = os.path.join(src_dir, "ledger.json")
        if existed:
            result = R.apply_remote(src, make_request("r1", S0, S1))
            self.assertEqual(result["status"], "applied")
            old = read_bytes(src)
            request = make_request("r2", S1, S2)
        else:
            old = None
            request = make_request("r1", S0, S1)
        with CrashCapture(src, moment) as crash:
            result = R.apply_remote(src, request)
            self.assertEqual(result["status"], "applied")
        self.assertIsNotNone(crash.snapshot, f"no snapshot at {moment}")
        new = read_bytes(src)
        fresh = tempfile.mkdtemp(dir=self.dir)
        restore_dir(fresh, crash.snapshot)
        return os.path.join(fresh, "ledger.json"), old, new

    def assert_only_ledger_remains(self, path):
        self.assertEqual(os.listdir(os.path.dirname(path)), ["ledger.json"])


class CleanStatusTest(RecoveryCase):
    def test_missing_intent_is_clean_and_scans_nothing(self):
        path = os.path.join(self.dir, "ledger.json")
        # Random leftover artifacts are never scanned without an intent.
        for suffix in (".tmp.1234abcd", ".old.5678efab", ".txn.9999aaaa"):
            with open(path + suffix, "wb") as handle:
                handle.write(b"leftover\n")
        result = recover_ledger(path)
        self.assertEqual(list(result.keys()), ["digest", "status"])
        self.assertEqual(result, {"digest": None, "status": "clean"})
        for suffix in (".tmp.1234abcd", ".old.5678efab", ".txn.9999aaaa"):
            self.assertTrue(os.path.exists(path + suffix))

    def test_successful_commit_leaves_no_intent_and_is_clean(self):
        path = os.path.join(self.dir, "ledger.json")
        R.apply_remote(path, make_request("r1", S0, S1))
        self.assertFalse(os.path.exists(path + ".txn"))
        self.assert_only_ledger = [os.path.basename(path)]
        self.assertEqual(os.listdir(self.dir), ["ledger.json"])
        self.assertEqual(
            recover_ledger(path),
            {"digest": digest_of(read_bytes(path)), "status": "clean"},
        )

    def test_result_is_a_fresh_dict_per_call(self):
        path = os.path.join(self.dir, "ledger.json")
        first = recover_ledger(path)
        second = recover_ledger(path)
        self.assertIsNot(first, second)
        self.assertEqual(first, second)

    def test_non_str_path_raises_type_error(self):
        for bad in (None, 1, True, b"ledger.json", 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recover_ledger(bad)


class PreparedCrashTest(RecoveryCase):
    def test_crash_during_intent_write_is_clean_and_keeps_old_bytes(self):
        path, old, _new = self.crash_state("a", "intent-write")
        names = os.listdir(os.path.dirname(path))
        # The crash left the candidate, the predecessor link and the
        # intent temporary behind, but no intent.
        self.assertNotIn("ledger.json.txn", names)
        self.assertTrue(any(".tmp." in name for name in names))
        self.assertTrue(any(".old." in name for name in names))
        self.assertTrue(any(".txn." in name for name in names))
        result = recover_ledger(path)
        self.assertEqual(result, {"digest": digest_of(old), "status": "clean"})
        # Without an intent nothing is scanned or removed.
        self.assertEqual(read_bytes(path), old)
        self.assertGreater(len(os.listdir(os.path.dirname(path))), 1)
        # A fresh commit is unaffected by the orphans.
        result = R.apply_remote(path, make_request("r2", S1, S2))
        self.assertEqual(result["status"], "applied")

    def test_crash_after_intent_persisted_rolls_back(self):
        path, old, _new = self.crash_state("b", "before-install")
        self.assertEqual(read_bytes(path), old)
        result = recover_ledger(path)
        self.assertEqual(
            result, {"digest": digest_of(old), "status": "rolled-back"}
        )
        self.assertEqual(read_bytes(path), old)
        self.assert_only_ledger_remains(path)
        self.assertEqual(
            recover_ledger(path), {"digest": digest_of(old), "status": "clean"}
        )

    def test_crash_after_replacement_restores_old_bytes(self):
        path, old, new = self.crash_state("c", "after-install")
        # The formal replacement happened but was never confirmed.
        self.assertEqual(read_bytes(path), new)
        result = recover_ledger(path)
        self.assertEqual(
            result, {"digest": digest_of(old), "status": "rolled-back"}
        )
        # The old bytes are back byte-for-byte.
        self.assertEqual(read_bytes(path), old)
        self.assert_only_ledger_remains(path)
        self.assertEqual(
            recover_ledger(path), {"digest": digest_of(old), "status": "clean"}
        )

    def test_crash_after_intent_persisted_on_missing_ledger(self):
        path, _old, _new = self.crash_state("d", "before-install", existed=False)
        self.assertFalse(os.path.exists(path))
        result = recover_ledger(path)
        self.assertEqual(result, {"digest": None, "status": "rolled-back"})
        self.assertFalse(os.path.exists(path))
        self.assertEqual(os.listdir(os.path.dirname(path)), [])
        self.assertEqual(
            recover_ledger(path), {"digest": None, "status": "clean"}
        )

    def test_crash_after_replacement_on_missing_ledger(self):
        path, _old, _new = self.crash_state("e", "after-install", existed=False)
        self.assertTrue(os.path.exists(path))
        result = recover_ledger(path)
        # The path was missing before the transaction and must be
        # missing again after the rollback.
        self.assertEqual(result, {"digest": None, "status": "rolled-back"})
        self.assertFalse(os.path.exists(path))
        self.assertEqual(os.listdir(os.path.dirname(path)), [])


class InstalledCrashTest(RecoveryCase):
    def test_crash_after_confirmation_completes(self):
        path, _old, new = self.crash_state("f", "confirmed")
        self.assertEqual(read_bytes(path), new)
        result = recover_ledger(path)
        self.assertEqual(
            result, {"digest": digest_of(new), "status": "completed"}
        )
        self.assertEqual(read_bytes(path), new)
        self.assert_only_ledger_remains(path)
        self.assertEqual(
            recover_ledger(path), {"digest": digest_of(new), "status": "clean"}
        )

    def test_crash_during_cleanup_completes(self):
        path, _old, new = self.crash_state("g", "cleanup")
        # The predecessor is already gone; only the intent remains.
        names = os.listdir(os.path.dirname(path))
        self.assertEqual(sorted(names), ["ledger.json", "ledger.json.txn"])
        result = recover_ledger(path)
        self.assertEqual(
            result, {"digest": digest_of(new), "status": "completed"}
        )
        self.assertEqual(read_bytes(path), new)
        self.assert_only_ledger_remains(path)

    def test_crash_after_confirmation_on_missing_ledger(self):
        path, _old, new = self.crash_state("h", "confirmed", existed=False)
        result = recover_ledger(path)
        self.assertEqual(
            result, {"digest": digest_of(new), "status": "completed"}
        )
        self.assertEqual(read_bytes(path), new)
        self.assert_only_ledger_remains(path)

    def test_recovery_preserves_unrelated_files(self):
        path, _old, new = self.crash_state("i", "confirmed")
        unrelated = os.path.join(os.path.dirname(path), "unrelated.keep")
        with open(unrelated, "wb") as handle:
            handle.write(b"do not touch\n")
        result = recover_ledger(path)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(read_bytes(unrelated), b"do not touch\n")


class IntentFormatTest(RecoveryCase):
    def test_prepared_intent_byte_contract(self):
        path, old, new = self.crash_state("j", "before-install")
        raw = read_bytes(path + ".txn")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        intent = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            set(intent.keys()),
            {"candidate", "newDigest", "oldDigest", "phase",
             "predecessor", "version"},
        )
        self.assertEqual(intent["version"], 1)
        self.assertEqual(intent["phase"], "prepared")
        self.assertEqual(intent["newDigest"], digest_of(new))
        self.assertEqual(intent["oldDigest"], digest_of(old))
        base = os.path.basename(path)
        for key in ("candidate", "predecessor"):
            name = intent[key]
            self.assertEqual(os.path.basename(name), name)
            self.assertTrue(name.startswith(base + "."))
            self.assertTrue(
                os.path.exists(os.path.join(os.path.dirname(path), name))
            )
        # Canonical compact encoding with sorted keys and one LF.
        canonical = json.dumps(
            intent, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        self.assertEqual(raw, canonical)

    def test_installed_intent_phase_and_null_predecessor(self):
        path, _old, new = self.crash_state("k", "confirmed", existed=False)
        intent = json.loads(read_bytes(path + ".txn").decode("utf-8"))
        self.assertEqual(intent["phase"], "installed")
        self.assertEqual(intent["newDigest"], digest_of(new))
        # A ledger that did not exist records null digests and names.
        self.assertIsNone(intent["oldDigest"])
        self.assertIsNone(intent["predecessor"])


class CorruptIntentTest(RecoveryCase):
    def prepared_state(self, tag="p"):
        return self.crash_state(tag, "before-install")

    def assert_corrupt(self, path, raw):
        before = snapshot_dir(os.path.dirname(path))
        with open(path + ".txn", "wb") as handle:
            handle.write(raw)
        before[os.path.basename(path) + ".txn"] = raw
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(path)
        # A corrupt intent changes nothing: the ledger, the artifacts
        # and the intent itself are all left in place.
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_corrupt_recovery_error_is_a_value_error(self):
        self.assertTrue(issubclass(CorruptRecoveryError, ValueError))

    def test_malformed_intents(self):
        path, old, new = self.prepared_state("p1")
        valid = json.loads(read_bytes(path + ".txn").decode("utf-8"))
        base = os.path.basename(path)

        def encoded(intent):
            return json.dumps(
                intent, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"

        variants = []
        variants.append(b"this is not json\n")
        variants.append(b"\xff\xfe not utf-8\n")
        variants.append(encoded(valid)[:-1])  # missing the trailing LF
        variants.append(encoded(valid) + b"\n")  # two trailing LFs
        missing_key = {k: v for k, v in valid.items() if k != "phase"}
        variants.append(encoded(missing_key))
        variants.append(encoded(dict(valid, extra=1)))
        variants.append(encoded(dict(valid, version=2)))
        variants.append(encoded(dict(valid, version="1")))
        variants.append(encoded(dict(valid, version=True)))
        variants.append(encoded(dict(valid, phase="committed")))
        variants.append(encoded(dict(valid, newDigest="Z" * 64)))
        variants.append(encoded(dict(valid, newDigest=valid["newDigest"][:-1])))
        variants.append(encoded(dict(valid, oldDigest=None)))
        variants.append(encoded(dict(valid, predecessor=None)))
        variants.append(encoded(dict(valid, candidate="../escape")))
        variants.append(encoded(dict(valid, candidate="sub/dir")))
        variants.append(encoded(dict(valid, candidate="")))
        variants.append(encoded(dict(valid, candidate=base)))
        variants.append(encoded(dict(valid, candidate=base + ".txn")))
        variants.append(encoded(dict(valid, candidate=1)))
        # Non-canonical encodings: permuted keys and added whitespace.
        permuted = (
            b'{"version":1,"phase":"prepared","predecessor":'
            + json.dumps(valid["predecessor"]).encode("utf-8")
            + b',"oldDigest":' + json.dumps(valid["oldDigest"]).encode("utf-8")
            + b',"newDigest":"' + valid["newDigest"].encode("utf-8")
            + b'","candidate":"' + valid["candidate"].encode("utf-8") + b'"}\n'
        )
        variants.append(permuted)
        variants.append(
            json.dumps(valid, ensure_ascii=False).encode("utf-8") + b"\n"
        )
        # A duplicate key makes the bytes non-canonical.
        duplicate = (
            b'{"candidate":"' + valid["candidate"].encode("utf-8") + b'",'
            + encoded(valid)[1:]
        )
        variants.append(duplicate)
        for index, raw in enumerate(variants):
            with self.subTest(variant=index):
                self.assert_corrupt(path, raw)

    def test_missing_predecessor_artifact_is_corrupt(self):
        path, _old, new = self.crash_state("p2", "after-install")
        names = os.listdir(os.path.dirname(path))
        predecessor = [n for n in names if ".old." in n][0]
        os.unlink(os.path.join(os.path.dirname(path), predecessor))
        before = snapshot_dir(os.path.dirname(path))
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(path)
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_mismatched_predecessor_artifact_is_corrupt(self):
        path, _old, new = self.crash_state("p3", "after-install")
        names = os.listdir(os.path.dirname(path))
        predecessor = [n for n in names if ".old." in n][0]
        with open(os.path.join(os.path.dirname(path), predecessor), "wb") as h:
            h.write(b"tampered predecessor\n")
        before = snapshot_dir(os.path.dirname(path))
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(path)
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_ledger_matching_neither_digest_is_corrupt(self):
        path, _old, _new = self.crash_state("p4", "after-install")
        with open(path, "wb") as handle:
            handle.write(b"foreign ledger bytes\n")
        before = snapshot_dir(os.path.dirname(path))
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(path)
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_installed_intent_requires_the_new_bytes(self):
        path, _old, _new = self.crash_state("p5", "confirmed")
        with open(path, "wb") as handle:
            handle.write(b"not the installed ledger\n")
        before = snapshot_dir(os.path.dirname(path))
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(path)
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_installed_intent_requires_the_ledger(self):
        path, _old, _new = self.crash_state("p6", "confirmed")
        os.unlink(path)
        before = snapshot_dir(os.path.dirname(path))
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(path)
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)

    def test_prepared_missing_ledger_rejects_foreign_bytes(self):
        path, _old, _new = self.crash_state("p7", "before-install", existed=False)
        with open(path, "wb") as handle:
            handle.write(b"foreign content\n")
        before = snapshot_dir(os.path.dirname(path))
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(path)
        self.assertEqual(snapshot_dir(os.path.dirname(path)), before)


class RecoveryOSErrorTest(RecoveryCase):
    def test_dir_sync_failure_propagates_and_recovery_retries(self):
        path, old, _new = self.crash_state("o1", "before-install")
        sentinel = OSError("sync denied")
        with mock.patch(
            "offline_coordination.storage._fsync_dir", side_effect=sentinel
        ):
            with self.assertRaises(OSError) as caught:
                recover_ledger(path)
        self.assertIs(caught.exception, sentinel)
        # The intent survived, so the recovery can be retried.
        self.assertTrue(os.path.exists(path + ".txn"))
        result = recover_ledger(path)
        self.assertEqual(
            result, {"digest": digest_of(old), "status": "rolled-back"}
        )
        self.assertEqual(
            recover_ledger(path), {"digest": digest_of(old), "status": "clean"}
        )

    def test_restore_replace_failure_keeps_intent_and_artifacts(self):
        path, old, new = self.crash_state("o2", "after-install")
        sentinel = OSError("rename denied")
        with mock.patch("os.replace", side_effect=sentinel):
            with self.assertRaises(OSError) as caught:
                recover_ledger(path)
        self.assertIs(caught.exception, sentinel)
        # Nothing was settled: the intent, the new candidate bytes at the
        # ledger path and the predecessor all remain for a retry.
        self.assertTrue(os.path.exists(path + ".txn"))
        self.assertEqual(read_bytes(path), new)
        names = os.listdir(os.path.dirname(path))
        self.assertTrue(any(".old." in name for name in names))
        result = recover_ledger(path)
        self.assertEqual(
            result, {"digest": digest_of(old), "status": "rolled-back"}
        )
        self.assertEqual(read_bytes(path), old)

    def test_intent_read_failure_propagates(self):
        path, _old, _new = self.crash_state("o3", "before-install")
        sentinel = OSError("read denied")
        real_open = open

        def failing_open(target, *args, **kwargs):
            if isinstance(target, str) and target.endswith(".txn"):
                raise sentinel
            return real_open(target, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=failing_open):
            with self.assertRaises(OSError) as caught:
                recover_ledger(path)
        self.assertIs(caught.exception, sentinel)


class AutoRecoveryTest(RecoveryCase):
    def test_apply_remote_recovers_interrupted_commit_then_applies(self):
        path, old, new = self.crash_state("w1", "after-install")
        # The interrupted commit never confirmed: the write entry point
        # rolls it back and the retried request applies on the old base.
        result = R.apply_remote(path, make_request("r2", S1, S2))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_bytes(path), new)
        self.assertFalse(os.path.exists(path + ".txn"))
        self.assertEqual(
            recover_ledger(path), {"digest": digest_of(new), "status": "clean"}
        )

    def test_apply_remote_completes_confirmed_commit_then_replays(self):
        path, _old, new = self.crash_state("w2", "confirmed")
        # The interrupted commit was confirmed: recovery completes it and
        # the replayed request is a duplicate of the recovered commit.
        result = R.apply_remote(path, make_request("r2", S1, S2))
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(read_bytes(path), new)
        self.assertEqual(
            recover_ledger(path), {"digest": digest_of(new), "status": "clean"}
        )

    def test_apply_signed_remote_recovers_interrupted_commit(self):
        src_dir = tempfile.mkdtemp(dir=self.dir)
        src = os.path.join(src_dir, "ledger.json")
        ring = keyring()
        env1 = signed_envelope(make_request("r1", S0, S1, source="node-b"))
        R.apply_signed_remote(src, ring, env1, NOW)
        old = read_bytes(src)
        env2 = signed_envelope(make_request("r2", S1, S2, source="node-b"))
        with CrashCapture(src, "after-install") as crash:
            R.apply_signed_remote(src, ring, env2, NOW)
        fresh = tempfile.mkdtemp(dir=self.dir)
        restore_dir(fresh, crash.snapshot)
        path = os.path.join(fresh, "ledger.json")
        result = R.apply_signed_remote(path, ring, env2, NOW)
        self.assertEqual(result["status"], "applied")
        _, _, entries = R._parse_ledger(read_bytes(path))
        self.assertEqual(
            entries[-1]["auth"], {"keyVersion": 1, "node": "node-b"}
        )
        self.assertEqual(
            recover_ledger(path),
            {"digest": digest_of(read_bytes(path)), "status": "clean"},
        )

    def test_commit_resolution_recovers_interrupted_commit(self):
        directory = tempfile.mkdtemp(dir=self.dir)
        target = os.path.join(directory, "target.json")
        left = os.path.join(directory, "left.json")
        right = os.path.join(directory, "right.json")
        for path in (target, left, right):
            R.apply_remote(path, make_request("r1", S0, S1))
            R.apply_remote(path, make_request("r2", S1, S2))
        R.apply_remote(left, make_request("r3l", S2, S3L))
        R.apply_remote(right, make_request("r3r", S2, S3R, source="node-b"))
        R.apply_remote(right, make_request("r4r", S3R, S4R, source="node-b"))
        left_proof = R.export_proof(left, 1)
        right_proof = R.export_proof(right, 1)
        plan = R.plan_merge(left_proof, right_proof, "manual")
        decisions = [
            {"side": "left", "seq": 3, "action": "reject"},
            {"side": "right", "seq": 3, "action": "accept"},
            {"side": "right", "seq": 4, "action": "accept"},
        ]
        resolution = R.resolve_merge(plan, left_proof, right_proof, decisions)
        _, right_requests, _ = R._parse_ledger(read_bytes(right))
        material = {
            "state": S4R,
            "requests": {
                "r3r": right_requests["r3r"], "r4r": right_requests["r4r"]
            },
        }
        args = dict(
            resolution=resolution, plan=plan,
            left=left_proof, right=right_proof, material=material,
        )
        before = read_bytes(target)
        with CrashCapture(target, "before-install") as crash:
            result = R.commit_resolution(target, **args)
            self.assertEqual(result["status"], "applied")
        # Restart into exactly the interrupted state.
        restore_dir(directory, crash.snapshot)
        self.assertEqual(read_bytes(target), before)
        recovered = recover_ledger(target)
        self.assertEqual(recovered["status"], "rolled-back")
        self.assertEqual(recovered["digest"], digest_of(before))
        # The write entry point would have done this itself.
        restore_dir(directory, crash.snapshot)
        result = R.commit_resolution(target, **args)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["next"], 4)
        self.assertEqual(
            recover_ledger(target),
            {"digest": digest_of(read_bytes(target)), "status": "clean"},
        )
        replay = R.commit_resolution(target, **args)
        self.assertEqual(replay["status"], "duplicate")

    def test_input_validation_precedes_recovery(self):
        path, _old, _new = self.crash_state("w3", "before-install")
        # A request that fails validation never reaches recovery, so a
        # leftover intent is untouched and no CorruptRecoveryError can
        # mask the validation failure.
        with self.assertRaises(ValueError) as caught:
            R.apply_remote(path, make_request("", S1, S2))
        self.assertNotIsInstance(caught.exception, CorruptRecoveryError)
        self.assertTrue(os.path.exists(path + ".txn"))
        with self.assertRaises(TypeError):
            R.apply_remote(1, make_request("r2", S1, S2))


if __name__ == "__main__":
    unittest.main()
