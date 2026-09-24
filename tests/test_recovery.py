"""Tests for cross-process crash recovery of the ledger replacement.

The transaction intent at ``path + ".txn"`` and :func:`recover_ledger`
are exercised through hand-built crash states (the exact files a killed
process would leave behind) and through in-call OSError injection at
every stage of the commit boundary, verifying the post-restart result.
"""

import hashlib
import hmac
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication, storage
from offline_coordination.replication import (
    CorruptRecoveryError,
    commit_resolution,
    export_proof,
    plan_merge,
    recover_ledger,
    resolve_merge,
)


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, deleted, clock, writer):
    return [value, deleted, dict(clock), writer]


def request(rid="r1", source="node-a", base=None, remote=None):
    return {
        "id": rid,
        "source": source,
        "base": state() if base is None else base,
        "remote": state() if remote is None else remote,
    }


S1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
S2 = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})

SECRET_B = "b" * 64


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


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


class RecoveryCase(unittest.TestCase):
    """Base fixture: a seeded one-entry ledger and its next commit payload."""

    CANDIDATE = "ledger.json.tmp.0123456789abcdef"
    PREDECESSOR = "ledger.json.old.0123456789abcdef"

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.intent_path = self.path + ".txn"
        self.candidate_path = os.path.join(self.dir, self.CANDIDATE)
        self.predecessor_path = os.path.join(self.dir, self.PREDECESSOR)

    def seed_ledger(self):
        replication.apply_remote(self.path, request(remote=S1))
        return read_bytes(self.path)

    def next_bytes(self):
        # The exact payload a commit of r2 over the seeded ledger installs.
        clone = os.path.join(self.dir, "clone.json")
        shutil.copyfile(self.path, clone)
        replication.apply_remote(clone, request(rid="r2", base=S1, remote=S2))
        payload = read_bytes(clone)
        os.unlink(clone)
        return payload

    def plant_candidate(self, payload, name=None):
        target = os.path.join(self.dir, name or self.CANDIDATE)
        with open(target, "wb") as handle:
            handle.write(payload)
        return target

    def plant_predecessor(self, name=None):
        target = os.path.join(self.dir, name or self.PREDECESSOR)
        os.link(self.path, target)
        return target

    def replace_ledger_bytes(self, payload):
        # Install new ledger bytes the way the atomic replacement does:
        # renaming over the path, so a retained predecessor hard link
        # keeps the old bytes on its own inode.
        scratch = os.path.join(self.dir, "scratch.bin")
        with open(scratch, "wb") as handle:
            handle.write(payload)
        os.replace(scratch, self.path)

    def plant_intent(self, phase, old, new, candidate=None, predecessor="default"):
        if predecessor == "default":
            predecessor = self.PREDECESSOR
        payload = replication._intent_payload(
            phase,
            sha(old) if old is not None else None,
            sha(new),
            candidate or self.CANDIDATE,
            predecessor,
        )
        replication._write_intent_payload(self.path, payload)
        return payload

    def artifacts(self):
        return sorted(
            name
            for name in os.listdir(self.dir)
            if name.startswith("ledger.json") and name != "ledger.json"
        )

    def assert_clean_slate(self, digest):
        self.assertEqual(self.artifacts(), [])
        again = recover_ledger(self.path)
        self.assertEqual(again, {"digest": digest, "status": "clean"})


class IntentFormatTest(RecoveryCase):
    def capture_intents(self, apply_call):
        payloads = []
        real = replication._write_intent_payload

        def spy(path, payload):
            payloads.append((path, payload))
            return real(path, payload)

        with mock.patch.object(
            replication, "_write_intent_payload", side_effect=spy
        ):
            apply_call()
        return payloads

    def test_commit_persists_prepared_then_installed_intent(self) -> None:
        l1 = self.seed_ledger()
        payloads = self.capture_intents(
            lambda: replication.apply_remote(
                self.path, request(rid="r2", base=S1, remote=S2)
            )
        )
        self.assertEqual(len(payloads), 2)
        new_digest = sha(read_bytes(self.path))
        for (intent_path, payload), phase in zip(
            payloads, ("prepared", "installed")
        ):
            # The intent lives at the fixed path + ".txn" name.
            self.assertEqual(intent_path + ".txn", self.intent_path)
            self.assertTrue(payload.endswith(b"\n"))
            self.assertFalse(payload.endswith(b"\n\n"))
            self.assertNotIn(b" ", payload)
            intent = json.loads(payload)
            # Only the version, the phase, both digests and the two safe
            # base names are recorded.
            self.assertEqual(
                set(intent),
                {
                    "candidate",
                    "newDigest",
                    "oldDigest",
                    "phase",
                    "predecessor",
                    "version",
                },
            )
            self.assertEqual(intent["version"], 1)
            self.assertEqual(intent["phase"], phase)
            self.assertEqual(intent["oldDigest"], sha(l1))
            self.assertEqual(intent["newDigest"], new_digest)
            for key, prefix in (
                ("candidate", "ledger.json.tmp."),
                ("predecessor", "ledger.json.old."),
            ):
                name = intent[key]
                # A safe base name: the artifact stays in the ledger's
                # own directory.
                self.assertEqual(name, os.path.basename(name))
                self.assertTrue(name.startswith(prefix))
                self.assertNotIn("/", name)
            # Canonical compact form with recursively sorted keys.
            self.assertEqual(canonical(intent) + b"\n", payload)
        self.assertEqual(payloads[0][0], payloads[1][0])

    def test_commit_on_missing_ledger_records_null_old_values(self) -> None:
        payloads = self.capture_intents(
            lambda: replication.apply_remote(self.path, request(remote=S1))
        )
        self.assertEqual(len(payloads), 2)
        new_digest = sha(read_bytes(self.path))
        for _path, payload in payloads:
            intent = json.loads(payload)
            self.assertIsNone(intent["oldDigest"])
            self.assertIsNone(intent["predecessor"])
            self.assertEqual(intent["newDigest"], new_digest)

    def test_successful_commit_leaves_no_intent(self) -> None:
        self.seed_ledger()
        self.assertFalse(os.path.exists(self.intent_path))
        self.assertEqual(self.artifacts(), [])


class CleanRecoveryTest(RecoveryCase):
    def test_clean_result_shape_and_digest(self) -> None:
        l1 = self.seed_ledger()
        result = recover_ledger(self.path)
        self.assertEqual(tuple(result.keys()), ("digest", "status"))
        self.assertEqual(result, {"digest": sha(l1), "status": "clean"})

    def test_clean_missing_path_has_null_digest(self) -> None:
        self.assertEqual(
            recover_ledger(self.path), {"digest": None, "status": "clean"}
        )

    def test_clean_does_not_scan_stray_artifacts(self) -> None:
        l1 = self.seed_ledger()
        strays = []
        for name, content in (
            ("ledger.json.tmp.1", b"stale tmp\n"),
            ("ledger.json.old.1", b"stale old\n"),
            ("unrelated.keep", b"do not touch\n"),
        ):
            strays.append(self.plant_candidate(content, name=name))
        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": sha(l1), "status": "clean"})
        # Nothing is scanned or swept: every stray file survives untouched.
        for stray, (_name, content) in zip(
            strays,
            (
                ("ledger.json.tmp.1", b"stale tmp\n"),
                ("ledger.json.old.1", b"stale old\n"),
                ("unrelated.keep", b"do not touch\n"),
            ),
        ):
            self.assertEqual(read_bytes(stray), content)

    def test_result_is_a_fresh_dict_per_call(self) -> None:
        self.seed_ledger()
        first = recover_ledger(self.path)
        second = recover_ledger(self.path)
        self.assertIsNot(first, second)
        self.assertEqual(first, second)


class PreparedRecoveryTest(RecoveryCase):
    def test_crash_after_intent_landing_keeps_old_bytes(self) -> None:
        # Killed after the prepared intent landed, before the replacement:
        # candidate and predecessor link still present, ledger untouched.
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_candidate(l2)
        self.plant_predecessor()
        self.plant_intent("prepared", l1, l2)

        result = recover_ledger(self.path)
        self.assertEqual(tuple(result.keys()), ("digest", "status"))
        self.assertEqual(result, {"digest": sha(l1), "status": "rolled-back"})
        self.assertEqual(read_bytes(self.path), l1)
        self.assert_clean_slate(sha(l1))

    def test_crash_after_replacement_restores_old_bytes(self) -> None:
        # Killed after the replacement but before the confirmation: the
        # ledger already holds the new bytes, the predecessor link the old.
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_predecessor()
        predecessor_inode = os.stat(self.predecessor_path).st_ino
        self.replace_ledger_bytes(l2)
        self.plant_intent("prepared", l1, l2)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": sha(l1), "status": "rolled-back"})
        # The old bytes return byte-for-byte as the very same inode.
        self.assertEqual(read_bytes(self.path), l1)
        self.assertEqual(os.stat(self.path).st_ino, predecessor_inode)
        self.assert_clean_slate(sha(l1))

    def test_prepared_rollback_removes_only_intent_referenced_files(self) -> None:
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_candidate(l2)
        self.plant_predecessor()
        self.plant_intent("prepared", l1, l2)
        stray = self.plant_candidate(b"not mine\n", name="ledger.json.tmp.zz")

        recover_ledger(self.path)
        # A random artifact the intent does not reference is never scanned
        # or removed.
        self.assertEqual(read_bytes(stray), b"not mine\n")
        self.assertFalse(os.path.exists(self.candidate_path))
        self.assertFalse(os.path.exists(self.predecessor_path))
        self.assertFalse(os.path.exists(self.intent_path))


class InstalledRecoveryTest(RecoveryCase):
    def test_crash_after_confirmation_completes_cleanup(self) -> None:
        # Killed after the installed intent landed: the new ledger is in
        # place, the predecessor link still waits for its cleanup.
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_predecessor()
        self.replace_ledger_bytes(l2)
        self.plant_intent("installed", l1, l2)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": sha(l2), "status": "completed"})
        self.assertEqual(read_bytes(self.path), l2)
        self.assert_clean_slate(sha(l2))

    def test_crash_during_cleanup_with_predecessor_gone(self) -> None:
        # Killed after the predecessor cleanup, before the intent removal.
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.replace_ledger_bytes(l2)
        self.plant_intent("installed", l1, l2)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": sha(l2), "status": "completed"})
        self.assertEqual(read_bytes(self.path), l2)
        self.assert_clean_slate(sha(l2))


class MissingLedgerRecoveryTest(RecoveryCase):
    def first_commit_bytes(self):
        clone = os.path.join(self.dir, "clone.json")
        replication.apply_remote(clone, request(remote=S1))
        payload = read_bytes(clone)
        os.unlink(clone)
        return payload

    def test_prepared_missing_ledger_stays_missing(self) -> None:
        # Killed after the prepared intent landed, before the replacement:
        # the ledger never existed and must stay missing.
        new = self.first_commit_bytes()
        self.plant_candidate(new)
        self.plant_intent("prepared", None, new, predecessor=None)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": None, "status": "rolled-back"})
        self.assertFalse(os.path.exists(self.path))
        self.assertFalse(os.path.exists(self.candidate_path))
        self.assertFalse(os.path.exists(self.intent_path))
        self.assertEqual(
            recover_ledger(self.path), {"digest": None, "status": "clean"}
        )

    def test_prepared_missing_ledger_unlinks_unconfirmed_replacement(self) -> None:
        # Killed after the replacement: the path the transaction created
        # must be missing again.
        new = self.first_commit_bytes()
        with open(self.path, "wb") as handle:
            handle.write(new)
        self.plant_intent("prepared", None, new, predecessor=None)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": None, "status": "rolled-back"})
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(
            recover_ledger(self.path), {"digest": None, "status": "clean"}
        )

    def test_installed_missing_origin_completes(self) -> None:
        new = self.first_commit_bytes()
        with open(self.path, "wb") as handle:
            handle.write(new)
        self.plant_intent("installed", None, new, predecessor=None)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": sha(new), "status": "completed"})
        self.assertEqual(read_bytes(self.path), new)
        self.assertFalse(os.path.exists(self.intent_path))


class CorruptIntentTest(RecoveryCase):
    def setUp(self) -> None:
        super().setUp()
        self.l1 = self.seed_ledger()
        self.l2 = self.next_bytes()

    def intent_obj(self, **overrides):
        obj = {
            "candidate": self.CANDIDATE,
            "newDigest": sha(self.l2),
            "oldDigest": sha(self.l1),
            "phase": "prepared",
            "predecessor": self.PREDECESSOR,
            "version": 1,
        }
        obj.update(overrides)
        return obj

    def write_intent_raw(self, raw):
        with open(self.intent_path, "wb") as handle:
            handle.write(raw)

    def write_intent_obj(self, obj):
        self.write_intent_raw(canonical(obj) + b"\n")

    def assert_corrupt(self, raw):
        self.write_intent_raw(raw)
        before_dir = sorted(os.listdir(self.dir))
        with self.assertRaises(CorruptRecoveryError) as caught:
            recover_ledger(self.path)
        self.assertIsInstance(caught.exception, ValueError)
        # The failure changes nothing: the ledger, the intent and every
        # other file are exactly as before.
        self.assertEqual(read_bytes(self.path), self.l1)
        self.assertEqual(read_bytes(self.intent_path), raw)
        self.assertEqual(sorted(os.listdir(self.dir)), before_dir)

    def test_error_is_a_value_error(self) -> None:
        self.assertTrue(issubclass(CorruptRecoveryError, ValueError))

    def test_encoding_faults(self) -> None:
        for raw in (
            b"",
            b"not json\n",
            b"\xff\xfe\n",
            b"{}",
            b"{}\n\n",
            b"[1, 2]\n",
            b'"text"\n',
        ):
            with self.subTest(raw=raw):
                self.assert_corrupt(raw)

    def test_duplicate_keys(self) -> None:
        good = canonical(self.intent_obj()).decode("utf-8")
        dup = good[:-1] + ',"phase":"prepared"}'
        self.assert_corrupt(dup.encode("utf-8") + b"\n")

    def test_non_canonical_encoding(self) -> None:
        obj = self.intent_obj()
        spaced = json.dumps(obj, ensure_ascii=False, sort_keys=True)
        self.assertIn(" ", spaced)
        self.assert_corrupt(spaced.encode("utf-8") + b"\n")
        unsorted = json.dumps(
            dict(reversed(list(obj.items()))),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        self.assert_corrupt(unsorted.encode("utf-8") + b"\n")

    def test_key_set_faults(self) -> None:
        obj = self.intent_obj()
        del obj["phase"]
        self.assert_corrupt(canonical(obj) + b"\n")
        self.assert_corrupt(canonical(self.intent_obj(extra=1)) + b"\n")

    def test_version_faults(self) -> None:
        for bad in (2, "1", True, None):
            with self.subTest(version=bad):
                self.assert_corrupt(canonical(self.intent_obj(version=bad)) + b"\n")

    def test_phase_faults(self) -> None:
        for bad in ("unknown", "PREPARED", 1, None):
            with self.subTest(phase=bad):
                self.assert_corrupt(canonical(self.intent_obj(phase=bad)) + b"\n")

    def test_digest_faults(self) -> None:
        for key in ("newDigest", "oldDigest"):
            for bad in ("A" * 64, "0" * 63, 1, None if key == "newDigest" else "zz"):
                with self.subTest(key=key, digest=bad):
                    self.assert_corrupt(canonical(self.intent_obj(**{key: bad})) + b"\n")

    def test_old_digest_and_predecessor_must_be_null_together(self) -> None:
        self.assert_corrupt(
            canonical(self.intent_obj(oldDigest=None)) + b"\n"
        )
        self.assert_corrupt(
            canonical(self.intent_obj(predecessor=None)) + b"\n"
        )

    def test_unsafe_or_conflicting_names(self) -> None:
        for key in ("candidate", "predecessor"):
            for bad in ("..", "a/b", "", "ledger.json", "ledger.json.txn", 1):
                with self.subTest(key=key, name=bad):
                    self.assert_corrupt(
                        canonical(self.intent_obj(**{key: bad})) + b"\n"
                    )
        self.assert_corrupt(
            canonical(self.intent_obj(predecessor=self.CANDIDATE)) + b"\n"
        )

    def test_ledger_matching_neither_digest_is_corrupt(self) -> None:
        with open(self.path, "wb") as handle:
            handle.write(b"unexpected ledger content\n")
        self.plant_intent("prepared", self.l1, self.l2)
        before = sorted(os.listdir(self.dir))
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(self.path)
        self.assertEqual(read_bytes(self.path), b"unexpected ledger content\n")
        self.assertEqual(sorted(os.listdir(self.dir)), before)

    def test_missing_predecessor_for_restore_is_corrupt(self) -> None:
        # The replacement went through but the retained predecessor link
        # the rollback needs is gone.
        with open(self.path, "wb") as handle:
            handle.write(self.l2)
        self.plant_intent("prepared", self.l1, self.l2)
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(self.path)
        self.assertEqual(read_bytes(self.path), self.l2)

    def test_mismatched_predecessor_for_restore_is_corrupt(self) -> None:
        with open(self.path, "wb") as handle:
            handle.write(self.l2)
        self.plant_candidate(b"not the old ledger\n", name=self.PREDECESSOR)
        self.plant_intent("prepared", self.l1, self.l2)
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(self.path)
        self.assertEqual(read_bytes(self.path), self.l2)
        self.assertEqual(read_bytes(self.predecessor_path), b"not the old ledger\n")

    def test_installed_with_unconfirmed_bytes_is_corrupt(self) -> None:
        # The installed phase confirms the new bytes; anything else at the
        # ledger path contradicts the confirmation.
        self.plant_intent("installed", self.l1, self.l2)
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(self.path)
        self.assertEqual(read_bytes(self.path), self.l1)

    def test_installed_missing_ledger_is_corrupt(self) -> None:
        os.unlink(self.path)
        self.plant_intent("installed", self.l1, self.l2)
        with self.assertRaises(CorruptRecoveryError):
            recover_ledger(self.path)
        self.assertFalse(os.path.exists(self.path))


class RecoveryErrorTest(RecoveryCase):
    def test_non_str_path_raises_type_error(self) -> None:
        for bad in (None, 1, b"path", True, 1.5):
            with self.subTest(path=bad):
                with self.assertRaises(TypeError):
                    recover_ledger(bad)
        self.assertEqual(os.listdir(self.dir), [])

    def test_restore_replace_failure_keeps_intent_and_artifacts(self) -> None:
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_predecessor()
        self.replace_ledger_bytes(l2)
        self.plant_candidate(l2)
        intent = self.plant_intent("prepared", l1, l2)

        sentinel = OSError("replace denied")
        with mock.patch("os.replace", side_effect=sentinel):
            with self.assertRaises(OSError) as caught:
                recover_ledger(self.path)
        self.assertIs(caught.exception, sentinel)
        # Everything needed for a retry survives the failed recovery.
        self.assertEqual(read_bytes(self.path), l2)
        self.assertEqual(read_bytes(self.predecessor_path), l1)
        self.assertEqual(read_bytes(self.candidate_path), l2)
        self.assertEqual(read_bytes(self.intent_path), intent)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": sha(l1), "status": "rolled-back"})
        self.assertEqual(read_bytes(self.path), l1)
        self.assert_clean_slate(sha(l1))

    def test_dir_sync_failure_keeps_intent_and_artifacts(self) -> None:
        # The restore's directory sync fails: the rollback already
        # happened, and the intent plus the remaining artifacts stay
        # behind for the retry.
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_predecessor()
        self.replace_ledger_bytes(l2)
        self.plant_candidate(l2)
        intent = self.plant_intent("prepared", l1, l2)

        sentinel = OSError("sync denied")
        with mock.patch.object(storage, "_fsync_dir", side_effect=sentinel):
            with self.assertRaises(OSError) as caught:
                recover_ledger(self.path)
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(read_bytes(self.path), l1)
        self.assertEqual(read_bytes(self.candidate_path), l2)
        self.assertEqual(read_bytes(self.intent_path), intent)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": sha(l1), "status": "rolled-back"})
        self.assert_clean_slate(sha(l1))

    def test_delete_failure_keeps_the_intent_for_retry(self) -> None:
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_candidate(l2)
        self.plant_predecessor()
        intent = self.plant_intent("prepared", l1, l2)

        real_unlink = os.unlink
        sentinel = OSError("unlink denied")

        def picky_unlink(target, *args, **kwargs):
            if target == self.intent_path:
                raise sentinel
            return real_unlink(target, *args, **kwargs)

        with mock.patch("os.unlink", side_effect=picky_unlink):
            with self.assertRaises(OSError) as caught:
                recover_ledger(self.path)
        self.assertIs(caught.exception, sentinel)
        # The rollback already happened; only the intent removal failed,
        # so the intent and the restored ledger are still there.
        self.assertEqual(read_bytes(self.path), l1)
        self.assertEqual(read_bytes(self.intent_path), intent)

        result = recover_ledger(self.path)
        self.assertEqual(result, {"digest": sha(l1), "status": "rolled-back"})
        self.assert_clean_slate(sha(l1))

    def test_intent_read_failure_propagates(self) -> None:
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_intent("prepared", l1, l2)
        real_open = open
        sentinel = OSError("read denied")

        def picky_open(target, *args, **kwargs):
            if target == self.intent_path:
                raise sentinel
            return real_open(target, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=picky_open):
            with self.assertRaises(OSError) as caught:
                recover_ledger(self.path)
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(read_bytes(self.path), l1)

    def test_unrelated_files_are_never_touched(self) -> None:
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_candidate(l2)
        self.plant_predecessor()
        self.plant_intent("prepared", l1, l2)
        unrelated = self.plant_candidate(b"do not touch\n", name="unrelated.keep")

        recover_ledger(self.path)
        self.assertEqual(read_bytes(unrelated), b"do not touch\n")


class AutoRecoveryTest(RecoveryCase):
    def test_apply_remote_recovers_prepared_crash_then_applies(self) -> None:
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_candidate(l2)
        self.plant_predecessor()
        self.plant_intent("prepared", l1, l2)

        result = replication.apply_remote(
            self.path, request(rid="r2", base=S1, remote=S2)
        )
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_bytes(self.path), l2)
        self.assert_clean_slate(sha(l2))
        replay = replication.apply_remote(
            self.path, request(rid="r2", base=S1, remote=S2)
        )
        self.assertEqual(replay["status"], "duplicate")

    def test_apply_remote_recovers_installed_crash_then_replays(self) -> None:
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_predecessor()
        self.replace_ledger_bytes(l2)
        self.plant_intent("installed", l1, l2)

        # The interrupted commit had already landed: the same request
        # replays as duplicate once the recovery finishes the cleanup.
        result = replication.apply_remote(
            self.path, request(rid="r2", base=S1, remote=S2)
        )
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(read_bytes(self.path), l2)
        self.assert_clean_slate(sha(l2))

    def test_apply_signed_remote_recovers_before_applying(self) -> None:
        l1 = self.seed_ledger()
        l2 = self.next_bytes()
        self.plant_candidate(l2)
        self.plant_predecessor()
        self.plant_intent("prepared", l1, l2)

        req = request(rid="r2", source="node-b", base=S1, remote=S2)
        envelope = signed_envelope(req)
        result = replication.apply_signed_remote(
            self.path, keyring(), envelope, 10
        )
        self.assertEqual(result["status"], "applied")
        ledger = json.loads(read_bytes(self.path))
        self.assertEqual(ledger["audit"][-1]["auth"], {"keyVersion": 1, "node": "node-b"})
        self.assertFalse(os.path.exists(self.intent_path))

    def test_corrupt_intent_blocks_the_write_entry(self) -> None:
        l1 = self.seed_ledger()
        self.write_garbage = b"garbage\n"
        with open(self.intent_path, "wb") as handle:
            handle.write(self.write_garbage)
        with self.assertRaises(CorruptRecoveryError):
            replication.apply_remote(self.path, request(rid="r2", base=S1, remote=S2))
        self.assertEqual(read_bytes(self.path), l1)
        self.assertEqual(read_bytes(self.intent_path), self.write_garbage)


class CommitResolutionRecoveryTest(unittest.TestCase):
    """Automatic recovery inside commit_resolution, over a real fork."""

    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp()
        self.target = os.path.join(self.directory, "target.json")
        self.left = os.path.join(self.directory, "left.json")
        self.right = os.path.join(self.directory, "right.json")
        s0 = state()
        s1 = state({"node-a": 1}, {"k": record("v1", False, {"node-a": 1}, "node-a")})
        s2 = state({"node-a": 2}, {"k": record("v2", False, {"node-a": 2}, "node-a")})
        s3l = state({"node-a": 3}, {"k": record("v3l", False, {"node-a": 3}, "node-a")})
        s3r = state(
            {"node-a": 2, "node-b": 1},
            {
                "k": record("v2", False, {"node-a": 2}, "node-a"),
                "j": record("w1", False, {"node-b": 1}, "node-b"),
            },
        )
        self.s4r = state(
            {"node-a": 2, "node-b": 2},
            {
                "k": record("v2", False, {"node-a": 2}, "node-a"),
                "j": record("w2", False, {"node-b": 2}, "node-b"),
            },
        )
        for path in (self.target, self.left, self.right):
            for rid, base, nxt in (("r1", s0, s1), ("r2", s1, s2)):
                result = replication.apply_remote(
                    path, request(rid=rid, base=base, remote=nxt)
                )
                assert result["status"] == "applied"
        for path, rid, base, nxt, source in (
            (self.left, "r3l", s2, s3l, "node-a"),
            (self.right, "r3r", s2, s3r, "node-b"),
            (self.right, "r4r", s3r, self.s4r, "node-b"),
        ):
            result = replication.apply_remote(
                path, request(rid=rid, source=source, base=base, remote=nxt)
            )
            assert result["status"] == "applied"
        self.left_proof = export_proof(self.left, 1)
        self.right_proof = export_proof(self.right, 1)
        self.plan = plan_merge(self.left_proof, self.right_proof, "manual")
        self.resolution = resolve_merge(
            self.plan,
            self.left_proof,
            self.right_proof,
            [
                {"side": "left", "seq": 3, "action": "reject"},
                {"side": "right", "seq": 3, "action": "accept"},
                {"side": "right", "seq": 4, "action": "accept"},
            ],
        )
        _state, requests, _entries = replication._parse_ledger(read_bytes(self.right))
        self.material = {
            "state": self.s4r,
            "requests": {"r3r": requests["r3r"], "r4r": requests["r4r"]},
        }

    def commit(self):
        return commit_resolution(
            self.target,
            self.resolution,
            self.plan,
            self.left_proof,
            self.right_proof,
            self.material,
        )

    def plant_prepared_crash(self):
        old = read_bytes(self.target)
        clone = os.path.join(self.directory, "clone.json")
        shutil.copyfile(self.target, clone)
        new = read_bytes(clone)
        os.unlink(clone)
        candidate = "target.json.tmp.0123456789abcdef"
        predecessor = "target.json.old.0123456789abcdef"
        with open(os.path.join(self.directory, candidate), "wb") as handle:
            handle.write(new)
        os.link(self.target, os.path.join(self.directory, predecessor))
        replication._write_intent_payload(
            self.target,
            replication._intent_payload(
                "prepared", sha(old), sha(new), candidate, predecessor
            ),
        )

    def test_commit_resolution_recovers_prepared_crash_then_applies(self) -> None:
        self.plant_prepared_crash()
        result = self.commit()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(
            sorted(os.listdir(self.directory)),
            ["left.json", "right.json", "target.json"],
        )
        self.assertEqual(self.commit()["status"], "duplicate")

    def test_commit_resolution_surfaces_corrupt_intent(self) -> None:
        before = read_bytes(self.target)
        with open(self.target + ".txn", "wb") as handle:
            handle.write(b"garbage\n")
        with self.assertRaises(CorruptRecoveryError):
            self.commit()
        self.assertEqual(read_bytes(self.target), before)


class InterruptedCommitRegressionTest(RecoveryCase):
    """In-call interruptions at every commit stage, then a fresh recovery."""

    def setUp(self) -> None:
        super().setUp()
        self.l1 = self.seed_ledger()
        self.l2 = self.next_bytes()

    def advance(self):
        return replication.apply_remote(
            self.path, request(rid="r2", base=S1, remote=S2)
        )

    def fail_nth_dirsync(self, n, exc):
        calls = []
        real = storage._fsync_dir

        def flaky(path):
            calls.append(path)
            if len(calls) == n:
                raise exc
            return real(path)

        return mock.patch.object(storage, "_fsync_dir", side_effect=flaky)

    def assert_rolled_back_and_retryable(self):
        self.assertEqual(read_bytes(self.path), self.l1)
        self.assertEqual(self.artifacts(), [])
        self.assertEqual(
            recover_ledger(self.path), {"digest": sha(self.l1), "status": "clean"}
        )
        self.assertEqual(self.advance()["status"], "applied")
        self.assertEqual(read_bytes(self.path), self.l2)
        self.assertEqual(
            replication.apply_remote(
                self.path, request(rid="r2", base=S1, remote=S2)
            )["status"],
            "duplicate",
        )

    def test_interrupted_intent_landing_rolls_back(self) -> None:
        # The prepared intent's directory sync fails: nothing of the
        # transaction may survive.
        sentinel = OSError("intent sync failed")
        with self.fail_nth_dirsync(1, sentinel):
            with self.assertRaises(OSError) as caught:
                self.advance()
        self.assertIs(caught.exception, sentinel)
        self.assert_rolled_back_and_retryable()

    def test_interrupted_replacement_rolls_back(self) -> None:
        sentinel = OSError("replace failed")
        with mock.patch("os.replace", side_effect=sentinel):
            with self.assertRaises(OSError) as caught:
                self.advance()
        self.assertIs(caught.exception, sentinel)
        self.assert_rolled_back_and_retryable()

    def test_interrupted_confirmation_rolls_back(self) -> None:
        # The installed intent's directory sync fails after the new ledger
        # already replaced the old one: the predecessor returns.
        sentinel = OSError("confirm sync failed")
        inode_before = os.stat(self.path).st_ino
        with self.fail_nth_dirsync(3, sentinel):
            with self.assertRaises(OSError) as caught:
                self.advance()
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(os.stat(self.path).st_ino, inode_before)
        self.assert_rolled_back_and_retryable()

    def test_interrupted_cleanup_rolls_back(self) -> None:
        # The directory sync after the predecessor cleanup fails.
        sentinel = OSError("cleanup sync failed")
        with self.fail_nth_dirsync(4, sentinel):
            with self.assertRaises(OSError) as caught:
                self.advance()
        self.assertIs(caught.exception, sentinel)
        self.assert_rolled_back_and_retryable()

    def test_interrupted_finalize_rolls_back(self) -> None:
        # The directory sync after the intent removal fails.
        sentinel = OSError("finalize sync failed")
        with self.fail_nth_dirsync(5, sentinel):
            with self.assertRaises(OSError) as caught:
                self.advance()
        self.assertIs(caught.exception, sentinel)
        self.assert_rolled_back_and_retryable()

    def test_failed_intent_removal_leaves_a_recoverable_commit(self) -> None:
        # The intent removal itself is best-effort: the commit stands and
        # the leftover installed intent is finished by the next recovery.
        real_unlink = os.unlink

        def picky_unlink(target, *args, **kwargs):
            if target == self.intent_path:
                raise OSError("unlink denied")
            return real_unlink(target, *args, **kwargs)

        with mock.patch("os.unlink", side_effect=picky_unlink):
            result = self.advance()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_bytes(self.path), self.l2)
        intent = json.loads(read_bytes(self.intent_path))
        self.assertEqual(intent["phase"], "installed")
        self.assertEqual(intent["newDigest"], sha(self.l2))

        recovered = recover_ledger(self.path)
        self.assertEqual(recovered, {"digest": sha(self.l2), "status": "completed"})
        self.assert_clean_slate(sha(self.l2))
        replay = replication.apply_remote(
            self.path, request(rid="r2", base=S1, remote=S2)
        )
        self.assertEqual(replay["status"], "duplicate")

    def test_unremovable_confirmed_intent_rolls_back_as_prepared(self) -> None:
        # A confirmed intent whose removal fails during the rollback is
        # rewritten to its prepared form, so the leftover stays consistent
        # with the restored pre-call bytes.
        real_unlink = os.unlink

        def picky_unlink(target, *args, **kwargs):
            if target == self.intent_path:
                raise OSError("unlink denied")
            return real_unlink(target, *args, **kwargs)

        sentinel = OSError("finalize sync failed")
        with self.fail_nth_dirsync(5, sentinel), mock.patch(
            "os.unlink", side_effect=picky_unlink
        ):
            with self.assertRaises(OSError) as caught:
                self.advance()
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(read_bytes(self.path), self.l1)
        intent = json.loads(read_bytes(self.intent_path))
        self.assertEqual(intent["phase"], "prepared")
        self.assertEqual(intent["oldDigest"], sha(self.l1))
        self.assertEqual(intent["newDigest"], sha(self.l2))

        recovered = recover_ledger(self.path)
        self.assertEqual(recovered, {"digest": sha(self.l1), "status": "rolled-back"})
        self.assert_rolled_back_and_retryable()


if __name__ == "__main__":
    unittest.main()
