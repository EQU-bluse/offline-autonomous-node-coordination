"""Tests for signed recovery checkpoints and offline page verification.

Covers :func:`export_recovery_checkpoint` and
:func:`verify_recovery_page`.
"""

import hashlib
import hmac
import json
import os
import tempfile
import unittest

from offline_coordination import replication as R
from offline_coordination.replication import (
    AuthenticationError,
    CorruptRecoveryAuditError,
    InvalidRecoveryCheckpointError,
    InvalidRecoveryPageError,
    export_recovery_audit,
    export_recovery_checkpoint,
    recover_authorized,
    verify_recovery_page,
)


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, n, writer="node-a"):
    return [value, False, {writer: n}, writer]


def make_request(rid, base, remote, source="node-a"):
    return {"id": rid, "source": source, "base": base, "remote": remote}


S0 = state()
S1 = state({"node-a": 1}, {"k": record("v1", 1)})

SECRET = "ab" * 32
ISSUER = "issuer-a"
ZERO_HASH = "0" * 64


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


def make_ticket(paths, nonce="nonce-1", secret=SECRET, issuer=ISSUER):
    payload = {
        "issuer": issuer,
        "keyVersion": 1,
        "nonce": nonce,
        "notBefore": 0,
        "notAfter": 10 ** 9,
        "paths": list(paths),
    }
    signature = hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature}) + b"\n"


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


class CheckpointCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keyring = make_keyring()

    def ledger_path(self, tag="ledger"):
        return os.path.join(self.dir, f"{tag}.json")

    def audit_path(self, tag="audit"):
        return os.path.join(self.dir, f"{tag}.jsonl")

    def build_audit(self, tag="audit", batches=2):
        """A real recovery audit chain with ``batches`` batch headers."""
        audit = self.audit_path(tag)
        for index in range(batches):
            ledger = self.ledger_path(f"{tag}-{index}")
            R.apply_remote(ledger, make_request(f"r{index}", S0, S1))
            recover_authorized(
                [ledger],
                self.keyring,
                make_ticket([ledger], nonce=f"nonce-{index}"),
                7,
                audit,
            )
        return audit

    def make_checkpoint(self, audit, moment=7, keyring=None):
        return export_recovery_checkpoint(
            audit, keyring if keyring is not None else self.keyring,
            ISSUER, 1, moment,
        )


class ExportCheckpointTest(CheckpointCase):
    def test_missing_audit_yields_seq_zero_and_zero_hash(self):
        audit = self.audit_path()
        checkpoint = self.make_checkpoint(audit)
        data = json.loads(checkpoint.decode("utf-8"))
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        payload = data["payload"]
        self.assertEqual(
            payload,
            {
                "issuer": ISSUER,
                "keyVersion": 1,
                "lastHash": ZERO_HASH,
                "lastSeq": 0,
                "moment": 7,
                "version": 1,
            },
        )
        expected = hmac.new(
            bytes.fromhex(SECRET), compact(payload), hashlib.sha256
        ).hexdigest()
        self.assertEqual(data["signature"], expected)

    def test_checkpoint_is_compact_sorted_and_has_no_trailing_newline(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        self.assertFalse(checkpoint.endswith(b"\n"))
        self.assertEqual(checkpoint, compact(json.loads(checkpoint)))

    def test_checkpoint_binds_last_seq_and_last_hash(self):
        audit = self.build_audit()
        page = export_recovery_audit(audit)
        last = page["records"][-1]
        checkpoint = self.make_checkpoint(audit)
        payload = json.loads(checkpoint)["payload"]
        self.assertEqual(payload["lastSeq"], last["seq"])
        self.assertEqual(payload["lastHash"], last["hash"])
        # Read-only: the audit bytes are unchanged.
        self.assertEqual(export_recovery_audit(audit)["records"], page["records"])

    def test_type_errors(self):
        audit = self.build_audit()
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(1, self.keyring, ISSUER, 1, 7)
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(audit, [], ISSUER, 1, 7)
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(audit, self.keyring, 1, 1, 7)
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(audit, self.keyring, ISSUER, "1", 7)
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(audit, self.keyring, ISSUER, True, 7)
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(audit, self.keyring, ISSUER, 1, True)
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(audit, self.keyring, ISSUER, 1, "7")

    def test_value_errors(self):
        audit = self.build_audit()
        with self.assertRaises(ValueError):
            export_recovery_checkpoint(audit, self.keyring, "", 1, 7)
        with self.assertRaises(ValueError):
            export_recovery_checkpoint(audit, self.keyring, ISSUER, 0, 7)
        with self.assertRaises(ValueError):
            export_recovery_checkpoint(audit, self.keyring, ISSUER, 1, -1)
        with self.assertRaises(ValueError):
            export_recovery_checkpoint(audit, make_keyring(secret="zz"), ISSUER, 1, 7)

    def test_unusable_credentials_raise_authentication_error(self):
        audit = self.build_audit()
        before = read_bytes(audit)
        for keyring in (
            {},
            make_keyring(revoked=True),
            make_keyring(not_before=100),
            make_keyring(not_after=5),
        ):
            with self.subTest(keyring=keyring):
                with self.assertRaises(AuthenticationError):
                    export_recovery_checkpoint(audit, keyring, ISSUER, 1, 7)
        # No fallback to another version or another issuer.
        with self.assertRaises(AuthenticationError):
            export_recovery_checkpoint(audit, self.keyring, ISSUER, 2, 7)
        with self.assertRaises(AuthenticationError):
            export_recovery_checkpoint(audit, self.keyring, "issuer-b", 1, 7)
        self.assertEqual(read_bytes(audit), before)

    def test_corrupt_audit_raises(self):
        audit = self.build_audit()
        with open(audit, "ab") as handle:
            handle.write(b"not json\n")
        with self.assertRaises(CorruptRecoveryAuditError):
            self.make_checkpoint(audit)


class VerifyPageTest(CheckpointCase):
    def test_empty_checkpoint_accepts_only_empty_page_from_zero(self):
        checkpoint = self.make_checkpoint(self.audit_path())
        result = verify_recovery_page(
            checkpoint,
            {"after": 0, "complete": True, "next": 0, "records": []},
            self.keyring,
            7,
        )
        self.assertEqual(
            list(result.keys()), ["checkpointDigest", "next", "tail", "status"]
        )
        self.assertEqual(
            result,
            {
                "checkpointDigest": hashlib.sha256(checkpoint).hexdigest(),
                "next": 0,
                "tail": ZERO_HASH,
                "status": "verified",
            },
        )
        # A non-empty page crosses the signed last seq.
        audit = self.build_audit("other")
        record = export_recovery_audit(audit)["records"][0]
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(
                checkpoint,
                {"after": 0, "complete": False, "next": 1, "records": [record]},
                self.keyring,
                7,
            )

    def test_paged_verification_reaches_verified(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        cursor = None
        seen = []
        while True:
            after = 0 if cursor is None else cursor["next"]
            page = export_recovery_audit(audit, after=after, limit=2)
            cursor = verify_recovery_page(
                checkpoint, page, self.keyring, 8, cursor=cursor
            )
            seen.append(cursor["status"])
            if cursor["status"] == "verified":
                break
        self.assertEqual(seen, ["continue"] * (len(seen) - 1) + ["verified"])
        last_page = export_recovery_audit(audit)
        self.assertEqual(cursor["next"], last_page["next"])
        self.assertEqual(cursor["tail"], last_page["records"][-1]["hash"])
        self.assertEqual(
            cursor["checkpointDigest"], hashlib.sha256(checkpoint).hexdigest()
        )

    def test_single_full_page_verifies(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit)
        result = verify_recovery_page(checkpoint, page, self.keyring, 7)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["next"], page["next"])

    def test_verification_reads_no_files(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit)
        os.unlink(audit)
        result = verify_recovery_page(checkpoint, page, self.keyring, 7)
        self.assertEqual(result["status"], "verified")

    def test_inputs_are_not_modified(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit)
        snapshot = json.loads(json.dumps(page))
        before = snapshot_dir(self.dir)
        verify_recovery_page(checkpoint, page, self.keyring, 7)
        self.assertEqual(page, snapshot)
        self.assertEqual(snapshot_dir(self.dir), before)

    def test_whole_history_replacement_is_detected(self):
        audit = self.build_audit("first")
        checkpoint = self.make_checkpoint(audit)
        # A fully recomputed, internally consistent replacement chain.
        replacement = self.build_audit("second")
        page = export_recovery_audit(replacement)
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(checkpoint, page, self.keyring, 7)

    def test_reordered_duplicate_and_gapped_pages_are_rejected(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        records = export_recovery_audit(audit)["records"]

        def page(selected, complete=False):
            return {
                "after": 0,
                "complete": complete,
                "next": selected[-1]["seq"],
                "records": selected,
            }

        reordered = [records[1], records[0]] + records[2:]
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(
                checkpoint, page(reordered), self.keyring, 7
            )
        duplicated = [records[0], records[0]] + records[1:]
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(
                checkpoint, page(duplicated), self.keyring, 7
            )
        gapped = [records[0]] + records[2:]
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(checkpoint, page(gapped), self.keyring, 7)
        # A prev mismatch inside an otherwise contiguous page.
        tampered = [dict(r) for r in records]
        tampered[1]["prev"] = ZERO_HASH
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(
                checkpoint, page(tampered), self.keyring, 7
            )

    def test_empty_page_before_the_signed_end_is_rejected(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(
                checkpoint,
                {"after": 0, "complete": True, "next": 0, "records": []},
                self.keyring,
                7,
            )

    def test_records_beyond_the_signed_last_seq_are_rejected(self):
        audit = self.build_audit("short", batches=1)
        checkpoint = self.make_checkpoint(audit)
        # The chain grows after the checkpoint is signed.
        longer = self.build_audit("long", batches=2)
        grown_page = export_recovery_audit(longer)
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(checkpoint, grown_page, self.keyring, 7)

    def test_page_after_must_follow_the_cursor(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        first = export_recovery_audit(audit, after=0, limit=1)
        cursor = verify_recovery_page(checkpoint, first, self.keyring, 7)
        self.assertEqual(cursor["status"], "continue")
        # Skipping ahead instead of continuing at the cursor's next.
        skipped = export_recovery_audit(audit, after=2, limit=2)
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(
                checkpoint, skipped, self.keyring, 7, cursor=cursor
            )
        # The honest continuation verifies.
        continuation = export_recovery_audit(audit, after=1, limit=2)
        result = verify_recovery_page(
            checkpoint, continuation, self.keyring, 7, cursor=cursor
        )
        self.assertEqual(result["status"], "continue")
        self.assertEqual(result["next"], 3)

    def test_cursor_must_bind_the_same_checkpoint(self):
        audit = self.build_audit("one")
        other = self.build_audit("two")
        checkpoint = self.make_checkpoint(audit)
        other_checkpoint = self.make_checkpoint(other)
        cursor = verify_recovery_page(
            other_checkpoint,
            export_recovery_audit(other, after=0, limit=1),
            self.keyring,
            7,
        )
        page = export_recovery_audit(audit, after=1, limit=1)
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(
                checkpoint, page, self.keyring, 7, cursor=cursor
            )

    def test_first_page_must_start_at_zero(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit, after=1, limit=1)
        with self.assertRaises(InvalidRecoveryPageError):
            verify_recovery_page(checkpoint, page, self.keyring, 7)

    def test_type_errors(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit)
        with self.assertRaises(TypeError):
            verify_recovery_page("x", page, self.keyring, 7)
        with self.assertRaises(TypeError):
            verify_recovery_page(checkpoint, [], self.keyring, 7)
        with self.assertRaises(TypeError):
            verify_recovery_page(checkpoint, page, [], 7)
        with self.assertRaises(TypeError):
            verify_recovery_page(checkpoint, page, self.keyring, True)
        with self.assertRaises(TypeError):
            verify_recovery_page(checkpoint, page, self.keyring, 7, cursor=1)
        for key, bad in (
            ("after", True),
            ("after", "0"),
            ("complete", 1),
            ("next", True),
            ("records", {}),
        ):
            with self.subTest(key=key, bad=bad):
                broken = dict(page)
                broken[key] = bad
                with self.assertRaises(TypeError):
                    verify_recovery_page(checkpoint, broken, self.keyring, 7)

    def test_malformed_checkpoints_raise_invalid_checkpoint(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit)
        for bad in (
            b"",
            b"not json",
            checkpoint + b"\n",
            checkpoint + b" ",
            compact({"payload": {}, "signature": "0" * 64, "extra": 1}),
            compact({"payload": {}, "signature": "0" * 64}),
            compact({"payload": {"issuer": ISSUER}, "signature": "0" * 64}),
            compact({"signature": "0" * 64, "payload": {"a": 1}})[:-1] + b"}",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidRecoveryCheckpointError):
                    verify_recovery_page(checkpoint=bad, page=page,
                                         keyring=self.keyring, moment=7)
        # A non-canonical encoding (unsorted keys) is rejected.
        data = json.loads(checkpoint)
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        if raw.encode("utf-8") != checkpoint:
            with self.assertRaises(InvalidRecoveryCheckpointError):
                verify_recovery_page(raw.encode("utf-8"), page, self.keyring, 7)

    def test_checkpoint_field_type_faults_raise_type_error(self):
        page_source = self.build_audit()
        checkpoint = self.make_checkpoint(page_source)
        page = export_recovery_audit(page_source)
        data = json.loads(checkpoint)
        for key, bad in (
            ("issuer", 1),
            ("keyVersion", True),
            ("lastSeq", "5"),
            ("lastHash", 5),
            ("moment", "7"),
            ("version", True),
        ):
            with self.subTest(key=key):
                broken = json.loads(json.dumps(data))
                broken["payload"][key] = bad
                with self.assertRaises(TypeError):
                    verify_recovery_page(
                        compact(broken), page, self.keyring, 7
                    )

    def test_signature_mismatch_raises_authentication_error(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit)
        data = json.loads(checkpoint)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(compact(data), page, self.keyring, 7)
        # A checkpoint signed by another secret fails against this keyring.
        other = export_recovery_checkpoint(
            audit, make_keyring(secret="cd" * 32), ISSUER, 1, 7
        )
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(other, page, self.keyring, 7)

    def test_unusable_credentials_raise_authentication_error(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit)
        for keyring in (
            {},
            make_keyring(revoked=True),
            make_keyring(not_before=100),
            make_keyring(not_after=5),
        ):
            with self.subTest(keyring=keyring):
                with self.assertRaises(AuthenticationError):
                    verify_recovery_page(checkpoint, page, keyring, 7)

    def test_malformed_pages_and_cursors_raise_invalid_page(self):
        audit = self.build_audit()
        checkpoint = self.make_checkpoint(audit)
        page = export_recovery_audit(audit)
        for bad_page in (
            {},
            {"after": 0, "complete": True, "next": 0},
            {"after": -1, "complete": True, "next": 0, "records": []},
            {"after": 0, "complete": True, "next": -1, "records": []},
            dict(page, next=page["next"] + 1),
            dict(page, records=page["records"] + [page["records"][-1]]),
        ):
            with self.subTest(bad_page=bad_page):
                with self.assertRaises(InvalidRecoveryPageError):
                    verify_recovery_page(checkpoint, bad_page, self.keyring, 7)
        cursor = verify_recovery_page(
            checkpoint, export_recovery_audit(audit, after=0, limit=1),
            self.keyring, 7,
        )
        next_page = export_recovery_audit(audit, after=1, limit=1)
        for bad_cursor in (
            {},
            dict(cursor, tail="z" * 64),
            dict(cursor, status="done"),
            dict(cursor, checkpointDigest="0" * 64),
        ):
            with self.subTest(bad_cursor=bad_cursor):
                with self.assertRaises(InvalidRecoveryPageError):
                    verify_recovery_page(
                        checkpoint, next_page, self.keyring, 7,
                        cursor=bad_cursor,
                    )


if __name__ == "__main__":
    unittest.main()
