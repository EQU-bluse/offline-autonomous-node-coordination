"""Tests for signed recovery checkpoints and offline page verification.

Covers :func:`export_recovery_checkpoint` and
:func:`verify_recovery_page`: the canonical, terminator-free checkpoint
bytes, the HMAC anchor over the chain prefix, the empty-chain case, the
exact error taxonomy and the purely offline paging verification with
cursors, gaps, reordering, duplicates and boundary chaining.
"""

import copy
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

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

SECRET = "ab" * 32
ISSUER = "issuer-a"
ZERO_HASH = "0" * 64
MOMENT = 7


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def make_keyring(secret=SECRET, not_before=0, not_after=10 ** 9, revoked=False,
                 version=1):
    return {
        ISSUER: [
            {
                "version": version,
                "secret": secret,
                "notBefore": not_before,
                "notAfter": not_after,
                "revoked": revoked,
            }
        ]
    }


def make_ticket(paths, nonce="nonce-1", secret=SECRET, issuer=ISSUER,
                key_version=1):
    payload = {
        "issuer": issuer,
        "keyVersion": key_version,
        "nonce": nonce,
        "notBefore": 0,
        "notAfter": 10 ** 9,
        "paths": list(paths),
    }
    signature = hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def sign_payload(payload, secret=SECRET):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def make_checkpoint(payload, secret=SECRET):
    """Canonical checkpoint bytes for an arbitrary payload."""
    return compact(
        {
            "payload": payload,
            "signature": sign_payload(payload, secret),
        }
    )


def cursor_of(result):
    return {
        "digest": result["digest"],
        "next": result["lastSeq"],
        "tail": result["tail"],
    }


class CheckpointCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keyring = make_keyring()

    def ledger_path(self, tag="ledger"):
        return os.path.join(self.dir, f"{tag}.json")

    def audit_path(self, tag="audit"):
        return os.path.join(self.dir, f"{tag}.jsonl")

    def build_chain(self, n=2, audit=None):
        """Run n clean ledger recoveries, returning (paths, audit bytes)."""
        audit = audit or self.audit_path()
        paths = []
        for i in range(n):
            path = self.ledger_path(f"l{i}")
            with open(path, "wb") as handle:
                handle.write(f"ledger-{i}".encode())
            paths.append(path)
        recover_authorized(
            paths, self.keyring, make_ticket(paths), MOMENT, audit
        )
        return paths, audit

    def make_cp(self, audit=None, moment=MOMENT, issuer=ISSUER, version=1,
                 keyring=None):
        audit = audit or self.audit_path()
        return export_recovery_checkpoint(
            audit, keyring or self.keyring, issuer, version, moment
        )


class ExportCheckpointTest(CheckpointCase):
    def test_missing_audit_binds_zero_seq_and_zero_hash(self):
        checkpoint = self.make_cp(self.audit_path("missing"))
        self.assertFalse(checkpoint.endswith(b"\n"))
        data = json.loads(checkpoint)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        payload = data["payload"]
        self.assertEqual(
            payload,
            {
                "issuer": ISSUER,
                "keyVersion": 1,
                "lastSeq": 0,
                "moment": MOMENT,
                "tail": ZERO_HASH,
                "version": 1,
            },
        )

    def test_binds_last_seq_and_chain_tail(self):
        _paths, audit = self.build_chain(n=2)
        checkpoint = self.make_cp(audit)
        page = export_recovery_audit(audit)
        last = page["records"][-1]
        payload = json.loads(checkpoint)["payload"]
        self.assertEqual(payload["lastSeq"], last["seq"])
        self.assertEqual(payload["tail"], last["hash"])
        self.assertNotEqual(payload["tail"], ZERO_HASH)

    def test_signature_is_hmac_of_canonical_payload(self):
        _paths, audit = self.build_chain(n=1)
        checkpoint = self.make_cp(audit)
        data = json.loads(checkpoint)
        self.assertEqual(
            data["signature"], sign_payload(data["payload"])
        )
        # The signed material is the payload alone, compact and sorted.
        self.assertEqual(
            checkpoint,
            compact({"payload": data["payload"],
                     "signature": data["signature"]}),
        )

    def test_bytes_are_compact_sorted_and_have_no_trailing_byte(self):
        _paths, audit = self.build_chain(n=1)
        checkpoint = self.make_cp(audit)
        self.assertTrue(checkpoint.endswith(b"}"))
        self.assertNotIn(b"\n", checkpoint)
        self.assertNotIn(b", ", checkpoint)
        self.assertNotIn(b': ', checkpoint)
        data = json.loads(checkpoint)
        # Re-encoding the parsed object reproduces the bytes exactly.
        self.assertEqual(checkpoint, compact(data))
        # The top-level key order is payload before signature; the key
        # "signature" only occurs once, as the second top-level key.
        self.assertLess(
            checkpoint.index(b'"payload"'),
            checkpoint.index(b'"signature"'),
        )
        self.assertEqual(checkpoint.count(b'"signature"'), 1)

    def test_distinct_anchors_for_distinct_chains(self):
        _p1, audit1 = self.build_chain(n=1, audit=self.audit_path("a1"))
        _p2, audit2 = self.build_chain(n=2, audit=self.audit_path("a2"))
        self.assertNotEqual(
            self.make_cp(audit1), self.make_cp(audit2)
        )

    def test_non_ascii_issuer_is_preserved_unencoded(self):
        issuer = "签发者-α"
        keyring = make_keyring()
        keyring[issuer] = keyring.pop(ISSUER)
        audit = self.audit_path("uni")
        checkpoint = export_recovery_checkpoint(
            audit, keyring, issuer, 1, MOMENT
        )
        self.assertIn(issuer.encode("utf-8"), checkpoint)
        page = {"after": 0, "complete": True, "next": 0, "records": []}
        result = verify_recovery_page(checkpoint, page, keyring, MOMENT)
        self.assertEqual(result["status"], "verified")

    def test_is_read_only(self):
        _paths, audit = self.build_chain(n=2)
        before = read_bytes(audit)
        self.make_cp(audit)
        self.assertEqual(read_bytes(audit), before)

    def test_corrupt_audit_raises(self):
        audit = self.audit_path()
        with open(audit, "wb") as handle:
            handle.write(b"not a chain\n")
        with self.assertRaises(CorruptRecoveryAuditError):
            self.make_cp(audit)

    def test_os_error_other_than_missing_propagates(self):
        # A path inside a missing directory is "missing" (empty chain);
        # a directory passed where a file is expected raises IsADirectoryError.
        with self.assertRaises(OSError):
            self.make_cp(self.dir)

    def test_argument_type_errors(self):
        audit = self.audit_path()
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(1, self.keyring, ISSUER, 1, MOMENT)
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(audit, self.keyring, 1, 1, MOMENT)
        for bad_version in (True, 1.5, "1"):
            with self.subTest(bad_version=bad_version):
                with self.assertRaises(TypeError):
                    self.make_cp(audit, version=bad_version)
        for bad_moment in (True, 1.5, "7"):
            with self.subTest(bad_moment=bad_moment):
                with self.assertRaises(TypeError):
                    self.make_cp(audit, moment=bad_moment)

    def test_argument_value_errors(self):
        audit = self.audit_path()
        with self.assertRaises(ValueError):
            self.make_cp(audit, issuer="")
        with self.assertRaises(ValueError):
            self.make_cp(audit, version=0)
        with self.assertRaises(ValueError):
            self.make_cp(audit, moment=-1)
        with self.assertRaises(TypeError):
            export_recovery_checkpoint(audit, None, ISSUER, 1, MOMENT)
        with self.assertRaises(ValueError):
            export_recovery_checkpoint(
                audit, {ISSUER: [{"version": 1}]}, ISSUER, 1, MOMENT
            )

    def test_unknown_revoked_unready_and_expired_credentials(self):
        _paths, audit = self.build_chain(n=1)
        with self.assertRaises(AuthenticationError):
            self.make_cp(audit, issuer="ghost")
        with self.assertRaises(AuthenticationError):
            self.make_cp(audit, version=2)
        with self.assertRaises(AuthenticationError):
            self.make_cp(audit, keyring=make_keyring(revoked=True))
        with self.assertRaises(AuthenticationError):
            self.make_cp(
                audit, keyring=make_keyring(not_before=MOMENT + 1)
            )
        with self.assertRaises(AuthenticationError):
            self.make_cp(
                audit, keyring=make_keyring(not_after=MOMENT - 1)
            )

    def test_key_version_selected_without_fallback(self):
        # Two versions: only the exact one signs; a request for v2 never
        # falls back to v1.
        two = {
            ISSUER: [
                {"version": 1, "secret": SECRET, "notBefore": 0,
                 "notAfter": 10 ** 9, "revoked": False},
                {"version": 2, "secret": "cd" * 32, "notBefore": 0,
                 "notAfter": 10 ** 9, "revoked": False},
            ]
        }
        _paths, audit = self.build_chain(n=1)
        cp1 = self.make_cp(audit, version=1, keyring=two)
        cp2 = self.make_cp(audit, version=2, keyring=two)
        self.assertNotEqual(cp1, cp2)
        self.assertEqual(
            json.loads(cp2)["payload"]["keyVersion"], 2
        )
        self.assertEqual(
            json.loads(cp2)["signature"],
            sign_payload(json.loads(cp2)["payload"], secret="cd" * 32),
        )


class VerifyPageTest(CheckpointCase):
    def setUp(self):
        super().setUp()
        self.paths, self.audit = self.build_chain(n=2)
        # 2 ledgers -> batch + 2 * (before, after) = 5 records.
        self.checkpoint = self.make_cp(self.audit)
        self.page1 = export_recovery_audit(self.audit, after=0, limit=2)
        self.page2 = export_recovery_audit(self.audit, after=2, limit=2)
        self.page3 = export_recovery_audit(self.audit, after=4, limit=2)

    def verify(self, page, cursor=None, checkpoint=None, moment=MOMENT):
        return verify_recovery_page(
            checkpoint if checkpoint is not None else self.checkpoint,
            page,
            self.keyring,
            moment,
            cursor,
        )

    def test_full_walk_reports_continue_then_verified(self):
        r1 = self.verify(self.page1)
        self.assertEqual(
            list(r1.keys()), ["digest", "lastSeq", "status", "tail"]
        )
        self.assertEqual(r1["status"], "continue")
        self.assertEqual(r1["lastSeq"], 2)
        self.assertEqual(r1["tail"], self.page1["records"][-1]["hash"])
        self.assertEqual(
            r1["digest"], hashlib.sha256(self.checkpoint).hexdigest()
        )
        r2 = self.verify(self.page2, cursor_of(r1))
        self.assertEqual(r2["status"], "continue")
        self.assertEqual(r2["lastSeq"], 4)
        r3 = self.verify(self.page3, cursor_of(r2))
        self.assertEqual(r3["status"], "verified")
        self.assertEqual(r3["lastSeq"], 5)
        payload = json.loads(self.checkpoint)["payload"]
        self.assertEqual(r3["tail"], payload["tail"])
        # The checkpoint digest stays the anchor on every round.
        digest = r1["digest"]
        self.assertEqual(r2["digest"], digest)
        self.assertEqual(r3["digest"], digest)

    def test_whole_chain_in_one_page_verifies(self):
        whole = export_recovery_audit(self.audit)
        result = self.verify(whole)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["lastSeq"], 5)

    def test_first_page_after_must_be_zero(self):
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(self.page2)
        # after zero with the wrong records is caught as a gap.
        page = copy.deepcopy(self.page2)
        page["after"] = 0
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(page)

    def test_cursor_after_must_equal_cursor_next(self):
        r1 = self.verify(self.page1)
        cursor = cursor_of(r1)
        cursor["next"] = 1
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(self.page2, cursor)

    def test_cursor_must_bind_the_same_checkpoint(self):
        r1 = self.verify(self.page1)
        other = self.make_cp(self.audit, moment=MOMENT + 100)
        cursor = cursor_of(r1)
        cursor["digest"] = hashlib.sha256(other).hexdigest()
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(self.page2, cursor)

    def test_opening_predecessor_must_chain_across_boundary(self):
        r1 = self.verify(self.page1)
        cursor = cursor_of(r1)
        cursor["tail"] = ZERO_HASH
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(self.page2, cursor)

    def test_empty_page_before_last_seq_is_rejected(self):
        empty = {"after": 0, "complete": False, "next": 0, "records": []}
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(empty)
        # An empty page claiming complete mid-chain is rejected too.
        empty_complete = dict(empty, complete=True)
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(empty_complete)

    def test_complete_flag_must_match_the_tail(self):
        page = copy.deepcopy(self.page1)
        page["complete"] = True  # seq 2 is not the signed seq 5
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(page)
        whole = export_recovery_audit(self.audit)
        tail_page = copy.deepcopy(whole)
        tail_page["complete"] = False
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(tail_page)

    def test_gap_reorder_duplicate_and_predecessor_are_rejected(self):
        base = self.page1["records"]
        # Gap: records seqs 1 and 2 -> keep only seq 2.
        gapped = copy.deepcopy(self.page1)
        gapped["records"] = [copy.deepcopy(base[1])]
        gapped["next"] = 2
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(gapped)
        # Reorder: seqs 2 then 1.
        reordered = copy.deepcopy(self.page1)
        reordered["records"] = [copy.deepcopy(base[1]), copy.deepcopy(base[0])]
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(reordered)
        # Duplicate: seq 1 twice.
        duplicated = copy.deepcopy(self.page1)
        duplicated["records"] = [copy.deepcopy(base[0]), copy.deepcopy(base[0])]
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(duplicated)
        # Predecessor mismatch inside the page.
        broken = copy.deepcopy(self.page1)
        broken["records"][1]["prev"] = ZERO_HASH
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(broken)

    def test_tampered_record_hash_is_rejected(self):
        page = copy.deepcopy(self.page1)
        page["records"][0]["nonce"] = "other"
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(page)
        page = copy.deepcopy(self.page1)
        page["records"][0]["hash"] = ZERO_HASH
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(page)

    def test_page_cannot_cross_the_signed_last_seq(self):
        page = copy.deepcopy(self.page3)
        page["next"] = 6  # beyond the signed seq 5
        r2 = self.verify(self.page2, cursor_of(self.verify(self.page1)))
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(page, cursor_of(r2))

    def test_signed_tail_mismatch_at_the_end_is_rejected(self):
        # A page reaching lastSeq whose last hash differs from the
        # checkpoint tail (history replaced and re-hashed past the anchor).
        whole = export_recovery_audit(self.audit)
        tail_record = copy.deepcopy(whole["records"][-1])
        tail_record["status"] = "failed"
        tail_record["error"] = "os-error"
        tail_record["hash"] = R._audit_record_hash(
            {k: v for k, v in tail_record.items() if k != "hash"}
        )
        page = copy.deepcopy(whole)
        page["records"][-1] = tail_record
        # The prev of the replaced record still matches, but the signed
        # tail anchor does not.
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(page)

    def test_empty_final_page_restates_the_verified_tail(self):
        whole = export_recovery_audit(self.audit)
        first = self.verify(whole)
        self.assertEqual(first["status"], "verified")
        restate = {
            "after": 5,
            "complete": True,
            "next": 5,
            "records": [],
        }
        again = self.verify(restate, cursor_of(first))
        self.assertEqual(again["status"], "verified")
        self.assertEqual(again["lastSeq"], 5)
        self.assertEqual(again["tail"], first["tail"])

    def test_empty_checkpoint_accepts_only_empty_page_from_zero(self):
        empty_cp = self.make_cp(self.audit_path("none"))
        empty_page = {"after": 0, "complete": True, "next": 0, "records": []}
        result = self.verify(empty_page, checkpoint=empty_cp)
        self.assertEqual(
            result,
            {
                "digest": hashlib.sha256(empty_cp).hexdigest(),
                "lastSeq": 0,
                "status": "verified",
                "tail": ZERO_HASH,
            },
        )
        # A non-empty page cannot verify against the empty anchor.
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(self.page1, checkpoint=empty_cp)
        # An empty page not starting at zero is invalid as well.
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(
                {"after": 1, "complete": True, "next": 1, "records": []},
                checkpoint=empty_cp,
            )
        # A first empty page mislabeled incomplete is rejected.
        with self.assertRaises(InvalidRecoveryPageError):
            self.verify(
                {"after": 0, "complete": False, "next": 0, "records": []},
                checkpoint=empty_cp,
            )


class CheckpointValidationTest(CheckpointCase):
    def setUp(self):
        super().setUp()
        self.paths, self.audit = self.build_chain(n=1)
        self.checkpoint = self.make_cp(self.audit)
        self.page = export_recovery_audit(self.audit)

    def verify(self, checkpoint=None, page=None, moment=MOMENT):
        return verify_recovery_page(
            self.checkpoint if checkpoint is None else checkpoint,
            self.page if page is None else page,
            self.keyring,
            moment,
        )

    def test_checkpoint_must_be_bytes(self):
        with self.assertRaises(TypeError):
            verify_recovery_page("x", self.page, self.keyring, MOMENT)

    def test_trailing_or_leading_bytes_are_format_errors(self):
        for bad in (
            self.checkpoint + b"\n",
            self.checkpoint + b" ",
            b" " + self.checkpoint,
        ):
            with self.subTest(bad=bad[:5]):
                with self.assertRaises(InvalidRecoveryCheckpointError):
                    self.verify(checkpoint=bad)

    def test_checkpoint_structure_faults(self):
        good = json.loads(self.checkpoint)
        payload = good["payload"]
        cases = [
            b"nope",
            compact({"payload": payload}),
            compact({"payload": payload, "signature": good["signature"],
                     "extra": 1}),
            compact({"payload": payload, "signature": "z" * 64}),
            compact({"payload": payload, "signature": "0" * 63}),
        ]
        for key in ("issuer", "keyVersion", "lastSeq", "moment", "tail",
                    "version"):
            bad_payload = dict(payload)
            del bad_payload[key]
            cases.append(
                compact({"payload": bad_payload,
                         "signature": "0" * 64})
            )
        # Version other than 1; zero/negative ranges; bad tail.
        for mutated in (
            dict(payload, version=2),
            dict(payload, keyVersion=0),
            dict(payload, moment=-1),
            dict(payload, lastSeq=-1),
            dict(payload, tail="z" * 64),
            dict(payload, issuer=""),
            dict(payload, lastSeq=0, tail="a" * 64),
        ):
            cases.append(make_checkpoint(mutated))
        # Non-canonical encoding (whitespace).
        cases.append(
            b'{"payload": ' + compact(payload)
            + b', "signature": "' + good["signature"].encode() + b'"}'
        )
        for bad in cases:
            with self.subTest(bad=bad[:60]):
                with self.assertRaises(InvalidRecoveryCheckpointError):
                    self.verify(checkpoint=bad)

    def test_checkpoint_field_type_faults_are_type_errors(self):
        payload = json.loads(self.checkpoint)["payload"]
        cases = []
        for key, bad in (
            ("issuer", 1),
            ("keyVersion", True),
            ("keyVersion", "1"),
            ("moment", 0.5),
            ("lastSeq", True),
            ("tail", 0),
            ("version", True),
        ):
            cases.append(make_checkpoint(dict(payload, **{key: bad})))
        cases.append(compact([1, 2]))
        cases.append(
            compact({"payload": [], "signature": "0" * 64})
        )
        cases.append(
            compact({"payload": payload, "signature": 7})
        )
        for bad in cases:
            with self.subTest(bad=bad[:60]):
                with self.assertRaises(TypeError):
                    self.verify(checkpoint=bad)

    def test_signature_mismatch_is_authentication_error(self):
        data = json.loads(self.checkpoint)
        sig = data["signature"]
        data["signature"] = ("a" if sig[0] != "a" else "b") + sig[1:]
        with self.assertRaises(AuthenticationError):
            self.verify(checkpoint=compact(data))

    def test_credentials_unavailable_or_unusable(self):
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(
                self.checkpoint, self.page,
                make_keyring(secret="cd" * 32), MOMENT,
            )
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(
                self.checkpoint, self.page, {}, MOMENT
            )
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(
                self.checkpoint, self.page,
                make_keyring(revoked=True), MOMENT,
            )
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(
                self.checkpoint, self.page,
                make_keyring(not_before=MOMENT + 1), MOMENT,
            )
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(
                self.checkpoint, self.page,
                make_keyring(not_after=MOMENT - 1), MOMENT,
            )

    def test_bound_moment_need_not_match_but_key_must_be_usable(self):
        # The bound moment is signed content; verification at a later
        # moment succeeds while the key is still valid there.
        later = self.verify(moment=MOMENT + 100)
        self.assertEqual(later["status"], "verified")
        # ...and fails once the key has expired by that moment.
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(
                self.checkpoint, self.page,
                make_keyring(not_after=MOMENT + 50), MOMENT + 100,
            )
        # A moment before the key becomes valid is rejected too.
        with self.assertRaises(AuthenticationError):
            verify_recovery_page(
                self.checkpoint, self.page,
                make_keyring(not_before=MOMENT + 200), MOMENT + 100,
            )

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(InvalidRecoveryCheckpointError, ValueError))
        self.assertTrue(issubclass(InvalidRecoveryPageError, ValueError))
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class PageValidationTest(CheckpointCase):
    def setUp(self):
        super().setUp()
        self.paths, self.audit = self.build_chain(n=1)
        self.checkpoint = self.make_cp(self.audit)
        self.page = export_recovery_audit(self.audit)

    def verify(self, page=None, cursor=None):
        return verify_recovery_page(
            self.checkpoint,
            self.page if page is None else page,
            self.keyring,
            MOMENT,
            cursor,
        )

    def test_page_argument_types(self):
        with self.assertRaises(TypeError):
            verify_recovery_page(self.checkpoint, [], self.keyring, MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_page(self.checkpoint, None, self.keyring, MOMENT)

    def test_page_top_level_faults(self):
        for bad in (
            {},
            {"after": 0, "complete": True, "next": 3, "records": []},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidRecoveryPageError):
                    self.verify(page=bad)

    def test_page_field_type_faults_are_type_errors(self):
        for key, bad in (
            ("after", True),
            ("after", "0"),
            ("next", 1.5),
            ("complete", 1),
            ("records", {}),
        ):
            page = copy.deepcopy(self.page)
            page[key] = bad
            with self.subTest(key=key):
                with self.assertRaises(TypeError):
                    self.verify(page=page)
        record = copy.deepcopy(self.page["records"][0])
        for key, bad in (("seq", True), ("prev", 0), ("hash", 0),
                        ("nonce", 1), ("kind", 1)):
            page = copy.deepcopy(self.page)
            page["records"][0] = copy.deepcopy(record)
            page["records"][0][key] = bad
            with self.subTest(record_key=key):
                with self.assertRaises(TypeError):
                    self.verify(page=page)

    def test_page_record_format_faults_are_page_errors(self):
        base = self.page["records"][0]
        record_cases = []
        bad_kind = copy.deepcopy(base)
        bad_kind["kind"] = "nope"
        record_cases.append(bad_kind)
        wrong_keys = copy.deepcopy(base)
        del wrong_keys["nonce"]
        record_cases.append(wrong_keys)
        bad_hex = copy.deepcopy(base)
        bad_hex["prev"] = "Z" * 64
        record_cases.append(bad_hex)
        for bad_record in record_cases:
            page = copy.deepcopy(self.page)
            page["records"][0] = bad_record
            with self.subTest(bad_record=bad_record.get("kind")):
                with self.assertRaises(InvalidRecoveryPageError):
                    self.verify(page=page)

    def test_cursor_format_faults(self):
        for bad_cursor in (
            [],
            {},
            {"digest": "a", "next": 3},
            {"digest": "a" * 64, "next": 3, "tail": "b" * 64, "x": 1},
            {"digest": "z" * 64, "next": 3, "tail": "b" * 64},
            {"digest": "a" * 64, "next": -1, "tail": "b" * 64},
            {"digest": "a" * 64, "next": 3, "tail": "z" * 64},
        ):
            with self.subTest(bad_cursor=bad_cursor):
                with self.assertRaises((InvalidRecoveryPageError, TypeError)):
                    self.verify(cursor=bad_cursor)
        with self.assertRaises(TypeError):
            self.verify(cursor="not-a-dict")
        with self.assertRaises(TypeError):
            self.verify(cursor={"digest": 0, "next": 3, "tail": "b" * 64})
        with self.assertRaises(TypeError):
            self.verify(
                cursor={"digest": "a" * 64, "next": True,
                        "tail": "b" * 64}
            )

    def test_keyring_faults_are_value_or_type_errors(self):
        with self.assertRaises(TypeError):
            verify_recovery_page(self.checkpoint, self.page, None, MOMENT)
        with self.assertRaises(ValueError):
            verify_recovery_page(
                self.checkpoint, self.page,
                {ISSUER: [{"version": 1, "secret": "zz",
                           "notBefore": 0, "notAfter": 1, "revoked": False}]},
                MOMENT,
            )
        with self.assertRaises(TypeError):
            verify_recovery_page(self.checkpoint, self.page, [], MOMENT)

    def test_moment_argument_validation(self):
        with self.assertRaises(TypeError):
            verify_recovery_page(self.checkpoint, self.page, self.keyring, True)
        with self.assertRaises(ValueError):
            verify_recovery_page(self.checkpoint, self.page, self.keyring, -1)


class OfflineAndImmutabilityTest(CheckpointCase):
    def test_verify_reads_no_file_and_touches_no_input(self):
        paths, audit = self.build_chain(n=2)
        checkpoint = self.make_cp(audit)
        pages = [
            export_recovery_audit(audit, after=0, limit=2),
            export_recovery_audit(audit, after=2, limit=10),
        ]
        # The audit stays on disk, but verification must not open it (or
        # anything else): run with the builtin open instrumented.
        cp_before = checkpoint
        page_copies = [copy.deepcopy(p) for p in pages]
        with mock.patch("builtins.open", side_effect=AssertionError("no file I/O")):
            result = verify_recovery_page(
                checkpoint, pages[0], self.keyring, MOMENT
            )
            final = verify_recovery_page(
                checkpoint, pages[1], self.keyring, MOMENT, cursor_of(result)
            )
        self.assertEqual(final["status"], "verified")
        self.assertEqual(checkpoint, cp_before)
        self.assertEqual(pages, page_copies)

    def test_verify_works_after_the_audit_is_deleted(self):
        paths, audit = self.build_chain(n=1)
        checkpoint = self.make_cp(audit)
        page = export_recovery_audit(audit)
        os.unlink(audit)
        result = verify_recovery_page(
            checkpoint, page, self.keyring, MOMENT
        )
        self.assertEqual(result["status"], "verified")


if __name__ == "__main__":
    unittest.main()
