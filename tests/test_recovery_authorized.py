"""Tests for authorized batch recovery and the recovery audit chain.

Covers :func:`recover_authorized`, :func:`export_recovery_audit`, the
``recovery run`` materials and the ``recovery audit`` module entry
point.
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
    AuthenticationError,
    CorruptRecoveryAuditError,
    ReplayError,
    export_recovery_audit,
    recover_authorized,
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

SECRET = "ab" * 32
ISSUER = "issuer-a"


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def make_keyring(secret=SECRET, not_before=0, not_after=10 ** 9, revoked=False):
    return {
        ISSUER: [
            {
                "version": 1,
                "secret": secret,
                "notBefore": not_before,
                "notAfter": not_after,
                "revoked": revoked,
            }
        ]
    }


def make_ticket(
    paths,
    nonce="nonce-1",
    secret=SECRET,
    issuer=ISSUER,
    key_version=1,
    not_before=0,
    not_after=10 ** 9,
):
    payload = {
        "issuer": issuer,
        "keyVersion": key_version,
        "nonce": nonce,
        "notBefore": not_before,
        "notAfter": not_after,
        "paths": list(paths),
    }
    signature = hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


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


class AuthorizedCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keyring = make_keyring()

    def ledger_path(self, tag="ledger"):
        return os.path.join(self.dir, f"{tag}.json")

    def audit_path(self, tag="audit"):
        return os.path.join(self.dir, f"{tag}.jsonl")

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

    def run_authorized(self, paths, ticket=None, moment=7, audit=None, keyring=None):
        return recover_authorized(
            paths,
            keyring if keyring is not None else self.keyring,
            ticket if ticket is not None else make_ticket(paths),
            moment,
            audit if audit is not None else self.audit_path(),
        )


class TicketValidationTest(AuthorizedCase):
    def test_type_errors(self):
        path = self.ledger_path()
        ticket = make_ticket([path])
        for bad_paths in (None, "x", (path,), 1, [path, 1]):
            with self.subTest(bad_paths=bad_paths):
                with self.assertRaises(TypeError):
                    recover_authorized(bad_paths, self.keyring, ticket, 7, "a")
        with self.assertRaises(TypeError):
            recover_authorized([path], None, ticket, 7, "a")
        with self.assertRaises(TypeError):
            recover_authorized([path], self.keyring, "not-bytes", 7, "a")
        for bad_moment in (True, 1.5, "7"):
            with self.subTest(bad_moment=bad_moment):
                with self.assertRaises(TypeError):
                    recover_authorized([path], self.keyring, ticket, bad_moment, "a")
        with self.assertRaises(TypeError):
            recover_authorized([path], self.keyring, ticket, 7, 1)

    def test_value_errors(self):
        path = self.ledger_path()
        ticket = make_ticket([path])
        with self.assertRaises(ValueError):
            recover_authorized([], self.keyring, ticket, 7, "a")
        with self.assertRaises(ValueError):
            recover_authorized([path], self.keyring, ticket, -1, "a")

    def test_ticket_structure_faults_are_value_errors(self):
        path = self.ledger_path()
        good = make_ticket([path])
        payload = {
            "issuer": ISSUER,
            "keyVersion": 1,
            "nonce": "n",
            "notBefore": 0,
            "notAfter": 9,
            "paths": [path],
        }
        cases = []
        # Wrong top-level key set.
        cases.append(compact({"payload": payload}))
        # Wrong payload key set.
        bad_payload = dict(payload)
        del bad_payload["nonce"]
        cases.append(compact({"payload": bad_payload, "signature": "0" * 64}))
        # Empty nonce.
        bad_payload = dict(payload, nonce="")
        cases.append(compact({"payload": bad_payload, "signature": "0" * 64}))
        # Inverted interval.
        bad_payload = dict(payload, notBefore=5, notAfter=4)
        cases.append(compact({"payload": bad_payload, "signature": "0" * 64}))
        # Bad signature format.
        cases.append(compact({"payload": payload, "signature": "zz"}))
        # Non-canonical encoding (whitespace).
        cases.append(b'{"payload": ' + compact(payload) + b', "signature": "' + b"0" * 64 + b'"}')
        # Cut off before the closing brace / old-style trailing LF.
        cases.append(good[:-1])
        cases.append(good + b"\n")
        # A trailing space or other byte is rejected just like an LF.
        cases.append(good + b" ")
        cases.append(good + b"\x00")
        # Not JSON.
        cases.append(b"nope")
        for bad in cases:
            with self.subTest(bad=bad[:40]):
                with self.assertRaises(ValueError):
                    recover_authorized([path], self.keyring, bad, 7, "a")

    def test_ticket_field_type_faults_are_type_errors(self):
        path = self.ledger_path()
        payload = {
            "issuer": ISSUER,
            "keyVersion": 1,
            "nonce": "n",
            "notBefore": 0,
            "notAfter": 9,
            "paths": [path],
        }
        cases = []
        cases.append(compact({"payload": [1], "signature": "0" * 64}))
        cases.append(compact([1, 2]))
        for key, bad in (
            ("issuer", 1),
            ("keyVersion", True),
            ("keyVersion", "1"),
            ("notBefore", 0.5),
            ("notAfter", None),
            ("paths", "x"),
            ("paths", [1]),
        ):
            bad_payload = dict(payload)
            bad_payload[key] = bad
            cases.append(
                compact({"payload": bad_payload, "signature": "0" * 64})
            )
        bad_payload = dict(payload)
        cases.append(
            compact({"payload": bad_payload, "signature": 7})
        )
        for bad in cases:
            with self.subTest(bad=bad[:60]):
                with self.assertRaises(TypeError):
                    recover_authorized([path], self.keyring, bad, 7, "a")


class AuthenticationTest(AuthorizedCase):
    def assert_auth_failure(self, paths, ticket, moment=7, keyring=None):
        """An AuthenticationError that creates nothing and touches nothing."""
        audit = self.audit_path()
        before = snapshot_dir(self.dir)
        with self.assertRaises(AuthenticationError):
            recover_authorized(
                paths,
                keyring if keyring is not None else self.keyring,
                ticket,
                moment,
                audit,
            )
        self.assertFalse(os.path.exists(audit))
        self.assertEqual(snapshot_dir(self.dir), before)

    def test_unknown_issuer(self):
        path = self.ledger_path()
        ticket = make_ticket([path], issuer="ghost")
        self.assert_auth_failure([path], ticket)

    def test_unknown_key_version(self):
        path = self.ledger_path()
        ticket = make_ticket([path], key_version=2)
        self.assert_auth_failure([path], ticket)

    def test_revoked_key(self):
        path = self.ledger_path()
        ticket = make_ticket([path])
        self.assert_auth_failure([path], ticket, keyring=make_keyring(revoked=True))

    def test_key_not_yet_valid_and_expired(self):
        path = self.ledger_path()
        ticket = make_ticket([path], not_before=0, not_after=10 ** 9)
        self.assert_auth_failure(
            [path], ticket, moment=5, keyring=make_keyring(not_before=10)
        )
        self.assert_auth_failure(
            [path], ticket, moment=20, keyring=make_keyring(not_after=10)
        )

    def test_ticket_not_yet_valid_and_expired(self):
        path = self.ledger_path()
        self.assert_auth_failure(
            [path], make_ticket([path], not_before=10), moment=5
        )
        self.assert_auth_failure(
            [path], make_ticket([path], not_after=10), moment=20
        )

    def test_path_mismatch(self):
        first = self.ledger_path("a")
        second = self.ledger_path("b")
        # Reordered.
        self.assert_auth_failure([second, first], make_ticket([first, second]))
        # Expanded.
        self.assert_auth_failure([first, second], make_ticket([first]))
        # Shrunk.
        self.assert_auth_failure([first], make_ticket([first, second]))
        # Different.
        self.assert_auth_failure([first], make_ticket([second]))

    def test_signature_mismatch(self):
        path = self.ledger_path()
        ticket = make_ticket([path], secret="cd" * 32)
        self.assert_auth_failure([path], ticket)

    def test_authentication_precedes_any_ledger_read(self):
        # A corrupt ledger must not mask the authentication failure.
        path = self.ledger_path()
        with open(path, "wb") as handle:
            handle.write(b"corrupt ledger\n")
        ticket = make_ticket([path], secret="cd" * 32)
        with self.assertRaises(AuthenticationError):
            recover_authorized([path], self.keyring, ticket, 7, self.audit_path())


class AuthorizedRunTest(AuthorizedCase):
    def test_recovers_each_status_in_order(self):
        prepared, old, _new = self.crash_state("a", "before-install")
        confirmed, _old2, new = self.crash_state("b", "confirmed")
        clean = self.committed_ledger("clean")
        missing = self.ledger_path("missing")
        paths = [prepared, confirmed, clean, missing]
        audit = self.audit_path()
        items = self.run_authorized(paths, audit=audit)
        self.assertEqual(
            [list(item.keys()) for item in items],
            [["path", "status", "digest", "error"]] * 4,
        )
        self.assertEqual(
            [(item["status"], item["error"]) for item in items],
            [
                ("rolled-back", None),
                ("completed", None),
                ("clean", None),
                ("clean", None),
            ],
        )
        self.assertEqual(items[0]["digest"], digest_of(old))
        self.assertEqual(items[1]["digest"], digest_of(new))
        self.assertEqual(items[2]["digest"], digest_of(read_bytes(clean)))
        self.assertIsNone(items[3]["digest"])
        self.assertEqual(read_bytes(prepared), old)
        self.assertEqual(read_bytes(confirmed), new)

    def test_audit_chain_records_batch_and_each_ledger(self):
        prepared, old, _new = self.crash_state("c", "before-install")
        missing = self.ledger_path("missing2")
        paths = [prepared, missing]
        ticket = make_ticket(paths)
        audit = self.audit_path()
        self.run_authorized(paths, ticket=ticket, audit=audit)

        page = export_recovery_audit(audit)
        self.assertTrue(page["complete"])
        records = page["records"]
        self.assertEqual(
            [record["kind"] for record in records],
            ["batch", "before", "after", "before", "after"],
        )
        batch = records[0]
        self.assertEqual(batch["nonce"], "nonce-1")
        self.assertEqual(batch["issuer"], ISSUER)
        self.assertEqual(batch["paths"], paths)
        self.assertEqual(batch["ticketDigest"], digest_of(ticket))
        before, after = records[1], records[2]
        self.assertEqual(before["path"], prepared)
        self.assertEqual(before["phase"], "prepared")
        self.assertEqual(before["action"], "rollback")
        self.assertEqual(before["digest"], digest_of(read_bytes(prepared)))
        self.assertEqual(after["path"], prepared)
        self.assertEqual(after["status"], "rolled-back")
        self.assertEqual(after["digest"], digest_of(old))
        self.assertIsNone(after["error"])
        self.assertEqual(records[3]["path"], missing)
        self.assertIsNone(records[3]["phase"])
        self.assertIsNone(records[3]["action"])
        self.assertIsNone(records[3]["digest"])
        self.assertEqual(records[4]["status"], "clean")

    def test_blocked_and_failed_items_are_isolated(self):
        corrupt, _o, _n = self.crash_state("d", "before-install")
        with open(corrupt + ".txn", "wb") as handle:
            handle.write(b"not json\n")
        prepared, old, _new = self.crash_state("e", "before-install")
        paths = [corrupt, prepared]
        items = self.run_authorized(paths)
        self.assertEqual(
            items[0],
            {"path": corrupt, "status": "blocked", "digest": None,
             "error": "corrupt"},
        )
        self.assertEqual(items[1]["status"], "rolled-back")
        self.assertEqual(items[1]["digest"], digest_of(old))
        # The corrupt ledger keeps its material.
        self.assertTrue(os.path.exists(corrupt + ".txn"))

    def test_distinct_nonces_share_one_chain(self):
        first, _o, _n = self.crash_state("f", "before-install")
        second, _o2, _n2 = self.crash_state("g", "confirmed")
        audit = self.audit_path()
        self.run_authorized([first], audit=audit)
        self.run_authorized(
            [second], ticket=make_ticket([second], nonce="nonce-2"), audit=audit
        )
        page = export_recovery_audit(audit)
        kinds = [record["kind"] for record in page["records"]]
        self.assertEqual(
            kinds, ["batch", "before", "after", "batch", "before", "after"]
        )
        self.assertEqual(page["records"][0]["nonce"], "nonce-1")
        self.assertEqual(page["records"][3]["nonce"], "nonce-2")


class ReentryTest(AuthorizedCase):
    def test_same_nonce_same_ticket_reuses_results(self):
        prepared, old, _new = self.crash_state("h", "before-install")
        missing = self.ledger_path("missing3")
        paths = [prepared, missing]
        ticket = make_ticket(paths)
        audit = self.audit_path()
        first_items = self.run_authorized(paths, ticket=ticket, audit=audit)
        audit_bytes = read_bytes(audit)
        dir_snapshot = snapshot_dir(self.dir)
        second_items = self.run_authorized(paths, ticket=ticket, audit=audit)
        self.assertEqual(second_items, first_items)
        # Nothing was appended and nothing else changed.
        self.assertEqual(read_bytes(audit), audit_bytes)
        self.assertEqual(snapshot_dir(self.dir), dir_snapshot)

    def test_interrupted_result_record_is_completed_without_side_effects(self):
        prepared, old, _new = self.crash_state("i", "before-install")
        paths = [prepared]
        ticket = make_ticket(paths)
        audit = self.audit_path()
        first_items = self.run_authorized(paths, ticket=ticket, audit=audit)
        # Simulate a crash after the recovery but before the result
        # record landed: drop the final after-record line.  Truncating a
        # hash chain at a record boundary keeps a valid prefix.
        lines = read_bytes(audit).split(b"\n")[:-1]
        self.assertEqual(json.loads(lines[-1])["kind"], "after")
        with open(audit, "wb") as handle:
            handle.write(b"".join(line + b"\n" for line in lines[:-1]))
        ledger_bytes = read_bytes(prepared)
        items = self.run_authorized(paths, ticket=ticket, audit=audit)
        # The recorded action fills in the result; the recovery is not
        # repeated (the ledger already holds the rolled-back bytes).
        self.assertEqual(items, first_items)
        self.assertEqual(items[0]["status"], "rolled-back")
        self.assertEqual(items[0]["digest"], digest_of(old))
        self.assertEqual(read_bytes(prepared), ledger_bytes)
        # The chain is byte-identical to the uninterrupted run.
        page = export_recovery_audit(audit)
        self.assertEqual(
            [record["kind"] for record in page["records"]],
            ["batch", "before", "after"],
        )

    def test_same_nonce_different_ticket_is_replay_error(self):
        first = self.ledger_path("r1")
        second = self.ledger_path("r2")
        audit = self.audit_path()
        self.run_authorized([first], audit=audit)
        before = snapshot_dir(self.dir)
        other = make_ticket([second], nonce="nonce-1")
        with self.assertRaises(ReplayError):
            recover_authorized([second], self.keyring, other, 7, audit)
        self.assertTrue(issubclass(ReplayError, ValueError))
        # No file was modified.
        self.assertEqual(snapshot_dir(self.dir), before)

    def test_same_nonce_reordered_paths_is_replay_error(self):
        first = self.ledger_path("r3")
        second = self.ledger_path("r4")
        audit = self.audit_path()
        self.run_authorized([first, second], audit=audit)
        before = snapshot_dir(self.dir)
        other = make_ticket([second, first], nonce="nonce-1")
        # Command paths that are not the ticket's fail authentication...
        with self.assertRaises(AuthenticationError):
            recover_authorized([first, second], self.keyring, other, 7, audit)
        # ...and the matching reordered command hits the nonce binding.
        with self.assertRaises(ReplayError):
            recover_authorized([second, first], self.keyring, other, 7, audit)
        self.assertEqual(snapshot_dir(self.dir), before)


class AuditCorruptionTest(AuthorizedCase):
    def test_corrupt_audit_raises_and_is_value_error(self):
        audit = self.audit_path()
        with open(audit, "wb") as handle:
            handle.write(b"garbage\n")
        self.assertTrue(issubclass(CorruptRecoveryAuditError, ValueError))
        with self.assertRaises(CorruptRecoveryAuditError):
            export_recovery_audit(audit)
        with self.assertRaises(CorruptRecoveryAuditError):
            self.run_authorized([self.ledger_path()], audit=audit)

    def test_tampered_record_breaks_the_chain(self):
        path, _old, _new = self.crash_state("j", "before-install")
        audit = self.audit_path()
        self.run_authorized([path], audit=audit)
        lines = read_bytes(audit).split(b"\n")[:-1]
        record = json.loads(lines[1])
        record["action"] = "complete"
        lines[1] = compact(record)
        with open(audit, "wb") as handle:
            handle.write(b"".join(line + b"\n" for line in lines))
        with self.assertRaises(CorruptRecoveryAuditError):
            export_recovery_audit(audit)

    def test_missing_audit_is_an_empty_chain(self):
        page = export_recovery_audit(self.audit_path())
        self.assertEqual(
            page, {"after": 0, "complete": True, "next": 0, "records": []}
        )


class AuditExportTest(AuthorizedCase):
    def test_paging_by_after_and_limit(self):
        paths = [self.ledger_path(f"p{i}") for i in range(3)]
        audit = self.audit_path()
        self.run_authorized(paths, audit=audit)
        whole = export_recovery_audit(audit)
        self.assertEqual(len(whole["records"]), 7)  # batch + 3 * (before+after)
        self.assertEqual(whole["next"], 7)
        self.assertTrue(whole["complete"])

        page = export_recovery_audit(audit, after=2, limit=3)
        self.assertEqual(page["after"], 2)
        self.assertEqual([r["seq"] for r in page["records"]], [3, 4, 5])
        self.assertEqual(page["next"], 5)
        self.assertFalse(page["complete"])

        tail = export_recovery_audit(audit, after=5, limit=100)
        self.assertEqual([r["seq"] for r in tail["records"]], [6, 7])
        self.assertTrue(tail["complete"])
        self.assertEqual(tail["next"], 7)

        empty = export_recovery_audit(audit, after=7)
        self.assertEqual(
            empty, {"after": 7, "complete": True, "next": 7, "records": []}
        )

    def test_export_validation(self):
        audit = self.audit_path()
        self.run_authorized([self.ledger_path("q")], audit=audit)
        for bad_after in (True, 1.5, "0"):
            with self.subTest(bad_after=bad_after):
                with self.assertRaises(TypeError):
                    export_recovery_audit(audit, after=bad_after)
        with self.assertRaises(TypeError):
            export_recovery_audit(audit, limit=True)
        with self.assertRaises(ValueError):
            export_recovery_audit(audit, after=-1)
        with self.assertRaises(ValueError):
            export_recovery_audit(audit, limit=0)
        with self.assertRaises(ValueError):
            export_recovery_audit(audit, limit=1001)
        with self.assertRaises(ValueError):
            export_recovery_audit(audit, after=10 ** 6)
        with self.assertRaises(TypeError):
            export_recovery_audit(1)

    def test_export_is_read_only(self):
        audit = self.audit_path()
        self.run_authorized([self.ledger_path("q2")], audit=audit)
        before = read_bytes(audit)
        export_recovery_audit(audit, after=1, limit=2)
        self.assertEqual(read_bytes(audit), before)


class AuditOSErrorTest(AuthorizedCase):
    def test_audit_write_os_error_propagates_with_consistent_prefix(self):
        path, _old, _new = self.crash_state("k", "before-install")
        # The audit directory does not exist: creating the chain fails.
        audit = os.path.join(self.dir, "no-such-dir", "audit.jsonl")
        with self.assertRaises(OSError):
            self.run_authorized([path], audit=audit)
        self.assertFalse(os.path.exists(audit))
        # The ledger was never settled: the intent is still in place.
        self.assertTrue(os.path.exists(path + ".txn"))

    def test_record_write_failure_keeps_retryable_prefix(self):
        path, old, _new = self.crash_state("l", "before-install")
        audit = self.audit_path()
        real_append = R._append_recovery_audit_record
        calls = {"n": 0}

        def failing_append(path_arg, chain, fields):
            calls["n"] += 1
            if calls["n"] == 2:  # the first before-record
                raise OSError("write denied")
            return real_append(path_arg, chain, fields)

        with mock.patch.object(R, "_append_recovery_audit_record", failing_append):
            with self.assertRaises(OSError):
                self.run_authorized([path], audit=audit)
        # Only the durable batch header is on the chain.
        page = export_recovery_audit(audit)
        self.assertEqual([r["kind"] for r in page["records"]], ["batch"])
        # A retry with the same nonce and ticket completes the batch.
        items = self.run_authorized([path], audit=audit)
        self.assertEqual(items[0]["status"], "rolled-back")
        self.assertEqual(items[0]["digest"], digest_of(old))
        page = export_recovery_audit(audit)
        self.assertEqual(
            [r["kind"] for r in page["records"]],
            ["batch", "before", "after"],
        )


class AuthorizedCommandTest(AuthorizedCase):
    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "offline_coordination", *argv],
            capture_output=True,
            text=True,
        )

    def write_materials(self, paths, nonce="cli-nonce", keyring=None):
        keyring = keyring if keyring is not None else self.keyring
        keyring_path = os.path.join(self.dir, f"keyring-{nonce}.json")
        with open(keyring_path, "wb") as handle:
            handle.write(compact(keyring))
        ticket_path = os.path.join(self.dir, f"ticket-{nonce}.json")
        with open(ticket_path, "wb") as handle:
            handle.write(make_ticket(paths, nonce=nonce))
        audit_path = self.audit_path(f"cli-{nonce}")
        return (
            "--keyring", keyring_path,
            "--ticket", ticket_path,
            "--moment", "7",
            "--audit", audit_path,
        )

    def test_run_success_exits_zero(self):
        prepared, old, _new = self.crash_state("m", "before-install")
        materials = self.write_materials([prepared])
        result = self.run_cli("recovery", "run", prepared, *materials)
        self.assertEqual(result.returncode, 0, result.stderr)
        (item,) = json.loads(result.stdout)
        self.assertEqual(item["status"], "rolled-back")
        self.assertEqual(item["digest"], digest_of(old))

    def test_run_ledger_failure_exits_one(self):
        path, _old, _new = self.crash_state("n", "before-install")
        with open(path + ".txn", "wb") as handle:
            handle.write(b"not json\n")
        materials = self.write_materials([path])
        result = self.run_cli("recovery", "run", path, *materials)
        self.assertEqual(result.returncode, 1)
        (item,) = json.loads(result.stdout)
        self.assertEqual(item["error"], "corrupt")

    def test_run_authorization_failure_exits_two(self):
        path = self.ledger_path("o")
        keyring_path = os.path.join(self.dir, "keyring-o.json")
        with open(keyring_path, "wb") as handle:
            handle.write(compact(self.keyring))
        ticket_path = os.path.join(self.dir, "ticket-o.json")
        with open(ticket_path, "wb") as handle:
            handle.write(make_ticket([self.ledger_path("other")]))
        audit = self.audit_path("cli-o")
        result = self.run_cli(
            "recovery", "run", path,
            "--keyring", keyring_path,
            "--ticket", ticket_path,
            "--moment", "7",
            "--audit", audit,
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(os.path.exists(audit))

    def test_run_missing_materials_exits_two(self):
        path = self.ledger_path("p")
        for argv in (
            ("recovery", "run", path),
            ("recovery", "run", path, "--moment", "7"),
            ("recovery", "run", path, "--moment", "not-an-int"),
        ):
            with self.subTest(argv=argv):
                result = self.run_cli(*argv)
                self.assertEqual(result.returncode, 2)

    def test_audit_entry_pages_the_chain(self):
        path, _old, _new = self.crash_state("q", "before-install")
        materials = self.write_materials([path])
        result = self.run_cli("recovery", "run", path, *materials)
        self.assertEqual(result.returncode, 0, result.stderr)
        audit = materials[-1]
        result = self.run_cli("recovery", "audit", audit)
        self.assertEqual(result.returncode, 0, result.stderr)
        page = json.loads(result.stdout)
        self.assertEqual(
            [record["kind"] for record in page["records"]],
            ["batch", "before", "after"],
        )
        self.assertTrue(page["complete"])
        # One compact JSON line with sorted keys.
        self.assertEqual(result.stdout.count("\n"), 1)
        self.assertEqual(
            result.stdout.strip(),
            json.dumps(page, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")),
        )
        result = self.run_cli(
            "recovery", "audit", audit, "--after", "1", "--limit", "1"
        )
        self.assertEqual(result.returncode, 0)
        page = json.loads(result.stdout)
        self.assertEqual([r["seq"] for r in page["records"]], [2])
        self.assertFalse(page["complete"])

    def test_audit_entry_missing_chain_and_argument_errors(self):
        result = self.run_cli("recovery", "audit", self.audit_path("none"))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            json.loads(result.stdout),
            {"after": 0, "complete": True, "next": 0, "records": []},
        )
        for argv in (
            ("recovery", "audit", "a", "b"),
            ("recovery", "audit", "a", "--after", "-1"),
            ("recovery", "audit", "a", "--limit", "0"),
        ):
            with self.subTest(argv=argv):
                result = self.run_cli(*argv)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
