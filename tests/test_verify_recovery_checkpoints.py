"""Tests for offline batch verification of signed recovery checkpoints.

Covers :func:`verify_recovery_checkpoints`: batch-level argument
validation, the verified/incomplete/invalid-checkpoint/invalid-page/
unauthenticated report taxonomy, per-item isolation, exact key
selection across a key rotation, the stable version-1 result shape and
the purely offline, non-mutating execution.
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
    export_recovery_audit,
    export_recovery_checkpoint,
    recover_authorized,
    verify_recovery_checkpoints,
)

SECRET = "ab" * 32
SECRET2 = "cd" * 32
ISSUER = "issuer-a"
OTHER = "issuer-b"
MOMENT = 7


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


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


def key_entry(version=1, secret=SECRET, not_before=0, not_after=10 ** 9,
              revoked=False):
    return {
        "version": version,
        "secret": secret,
        "notBefore": not_before,
        "notAfter": not_after,
        "revoked": revoked,
    }


def sign_payload(payload, secret=SECRET):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def make_checkpoint(payload, secret=SECRET):
    """Canonical checkpoint bytes for an arbitrary payload."""
    return compact(
        {"payload": payload, "signature": sign_payload(payload, secret)}
    )


def valid_payload(last_seq, tail, issuer=ISSUER, key_version=1,
                  moment=MOMENT):
    return {
        "issuer": issuer,
        "keyVersion": key_version,
        "lastSeq": last_seq,
        "moment": moment,
        "tail": tail,
        "version": 1,
    }


class BatchCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keyring = {
            ISSUER: [key_entry(1, SECRET), key_entry(2, SECRET2)],
        }

    def ledger_path(self, tag):
        return os.path.join(self.dir, f"{tag}.json")

    def audit_path(self, tag):
        return os.path.join(self.dir, f"{tag}.jsonl")

    def build_chain(self, tag, n=2, key_version=1, secret=SECRET,
                    nonce="nonce-1", issuer=ISSUER):
        """Run n clean recoveries under one key version; return audit."""
        audit = self.audit_path(tag)
        paths = []
        for i in range(n):
            path = self.ledger_path(f"{tag}-{i}")
            with open(path, "wb") as handle:
                handle.write(f"ledger-{tag}-{i}".encode())
            paths.append(path)
        kr = {issuer: [key_entry(key_version, secret)]}
        recover_authorized(
            paths, kr,
            make_ticket(paths, nonce=nonce, secret=secret, issuer=issuer,
                        key_version=key_version),
            MOMENT, audit,
        )
        return audit

    def checkpoint(self, audit, key_version=1, moment=MOMENT,
                   issuer=ISSUER, keyring=None):
        return export_recovery_checkpoint(
            audit, keyring or self.keyring, issuer, key_version, moment
        )

    def pages(self, audit, *windows):
        """Pages for (after, limit) windows; no windows means the chain."""
        if not windows:
            return [export_recovery_audit(audit)]
        result = []
        for window in windows:
            if isinstance(window, tuple):
                after, limit = window
            else:
                after, limit = window, 100
            result.append(export_recovery_audit(audit, after=after,
                                                limit=limit))
        return result

    def item(self, item_id, checkpoint, pages):
        return {"id": item_id, "checkpoint": checkpoint, "pages": pages}

    def verify(self, items, keyring=None, moment=MOMENT):
        return verify_recovery_checkpoints(
            items, keyring if keyring is not None else self.keyring, moment
        )


class BatchValidationTest(BatchCase):
    def setUp(self):
        super().setUp()
        audit = self.build_chain("v", n=1)
        self.good_item = self.item(
            "a", self.checkpoint(audit), self.pages(audit)
        )

    def test_container_and_element_type_faults_are_type_errors(self):
        good = self.good_item
        for bad_items in (None, "x", (good,), {"id": "a"}, 1):
            with self.subTest(bad_items=type(bad_items)):
                with self.assertRaises(TypeError):
                    self.verify(bad_items)
        for bad_item in (None, 1, "x", []):
            with self.subTest(bad_item=type(bad_item)):
                with self.assertRaises(TypeError):
                    self.verify([bad_item])
        for bad_id in (1, None, b"a", ["a"]):
            item = dict(good, id=bad_id)
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(TypeError):
                    self.verify([item])
        for bad_cp in ("bytes", None, 1, [b"x"]):
            item = dict(good, checkpoint=bad_cp)
            with self.subTest(bad_cp=type(bad_cp)):
                with self.assertRaises(TypeError):
                    self.verify([item])
        for bad_pages in (None, "x", {}, (good["pages"][0],)):
            item = dict(good, pages=bad_pages)
            with self.subTest(bad_pages=type(bad_pages)):
                with self.assertRaises(TypeError):
                    self.verify([item])
        item = dict(good, pages=[None])
        with self.assertRaises(TypeError):
            self.verify([item])
        item = dict(good, pages=["page"])
        with self.assertRaises(TypeError):
            self.verify([item])

    def test_value_faults_are_value_errors(self):
        good = self.good_item
        with self.assertRaises(ValueError):
            self.verify([])
        with self.assertRaises(ValueError):
            self.verify([dict(good, id="")])
        with self.assertRaises(ValueError):
            self.verify([good, dict(good, id="a")])
        with self.assertRaises(ValueError):
            self.verify([dict(good, pages=[])])
        with self.assertRaises(ValueError):
            self.verify([{"id": "a", "checkpoint": good["checkpoint"],
                          "pages": good["pages"], "extra": 1}])
        with self.assertRaises(ValueError):
            self.verify([{"id": "a", "checkpoint": good["checkpoint"]}])

    def test_keyring_faults_keep_existing_taxonomy(self):
        with self.assertRaises(TypeError):
            verify_recovery_checkpoints([self.good_item], None, MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_checkpoints([self.good_item], [], MOMENT)
        with self.assertRaises(ValueError):
            self.verify(
                [self.good_item],
                keyring={ISSUER: [dict(key_entry(), secret="zz")]},
            )

    def test_moment_validation(self):
        for bad_moment in (True, 1.5, "7", None):
            with self.subTest(bad_moment=bad_moment):
                with self.assertRaises(TypeError):
                    self.verify([self.good_item], moment=bad_moment)
        with self.assertRaises(ValueError):
            self.verify([self.good_item], moment=-1)

    def test_the_whole_batch_validates_before_anything_is_verified(self):
        # A valid first item must not be processed when a later item has
        # a batch-level fault: verification raises instead of reporting.
        good = self.good_item
        with self.assertRaises(ValueError):
            self.verify([good, dict(good, id="a")])
        with self.assertRaises(TypeError):
            self.verify([good, dict(good, checkpoint="x")])


class BatchResultShapeTest(BatchCase):
    def test_top_level_and_item_key_order(self):
        audit = self.build_chain("s", n=1)
        result = self.verify(
            [self.item("a", self.checkpoint(audit), self.pages(audit))]
        )
        self.assertEqual(list(result.keys()), ["items", "version"])
        self.assertEqual(result["version"], 1)
        (report,) = result["items"]
        self.assertEqual(
            list(report.keys()),
            ["id", "digest", "issuer", "keyVersion", "lastSeq",
             "status", "error"],
        )

    def test_verified_report_fields(self):
        audit = self.build_chain("s2", n=2)  # batch + 4 = 5 records
        checkpoint = self.checkpoint(audit)
        result = self.verify(
            [self.item("a", checkpoint, self.pages(audit))]
        )
        report = result["items"][0]
        self.assertEqual(report["id"], "a")
        self.assertEqual(
            report["digest"],
            hashlib.sha256(checkpoint).hexdigest(),
        )
        self.assertEqual(report["issuer"], ISSUER)
        self.assertEqual(report["keyVersion"], 1)
        self.assertEqual(report["lastSeq"], 5)
        self.assertEqual(report["status"], "verified")
        self.assertIsNone(report["error"])

    def test_multi_page_walk_verifies_within_one_item(self):
        audit = self.build_chain("m", n=2)
        checkpoint = self.checkpoint(audit)
        result = self.verify(
            [self.item(
                "a", checkpoint, self.pages(audit, (0, 2), (2, 2), (4, 2))
            )]
        )
        self.assertEqual(result["items"][0]["status"], "verified")
        self.assertEqual(result["items"][0]["lastSeq"], 5)

    def test_empty_checkpoint_verifies_with_empty_page(self):
        missing = self.audit_path("none")
        checkpoint = self.checkpoint(missing)
        empty_page = {"after": 0, "complete": True, "next": 0,
                      "records": []}
        result = self.verify(
            [self.item("e", checkpoint, [empty_page])]
        )
        report = result["items"][0]
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["lastSeq"], 0)
        self.assertIsNone(report["error"])
        # A non-empty page against the empty anchor is an invalid page.
        other = self.build_chain("o", n=1)
        result = self.verify(
            [self.item("e2", checkpoint, self.pages(other))]
        )
        self.assertEqual(result["items"][0]["status"], "invalid-page")


class IncompleteTest(BatchCase):
    def test_pages_exhausted_before_tail_are_incomplete(self):
        audit = self.build_chain("i", n=2)  # 5 records
        checkpoint = self.checkpoint(audit)
        result = self.verify(
            [self.item("a", checkpoint, self.pages(audit, (0, 2)))]
        )
        report = result["items"][0]
        self.assertEqual(report["status"], "incomplete")
        self.assertIsNone(report["error"])
        # The verified boundary (2 records) is retained.
        self.assertEqual(report["lastSeq"], 2)
        self.assertEqual(report["issuer"], ISSUER)
        self.assertEqual(report["keyVersion"], 1)

    def test_multi_page_walk_stopping_mid_chain_keeps_boundary(self):
        audit = self.build_chain("i2", n=2)
        checkpoint = self.checkpoint(audit)
        result = self.verify(
            [self.item(
                "a", checkpoint, self.pages(audit, (0, 2), (2, 1))
            )]
        )
        report = result["items"][0]
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["lastSeq"], 3)
        self.assertIsNone(report["error"])

    def test_incomplete_boundary_is_zero_when_first_page_covers_nothing(self):
        # An empty first page before the tail is invalid, not incomplete.
        audit = self.build_chain("i3", n=1)
        checkpoint = self.checkpoint(audit)
        empty = {"after": 0, "complete": False, "next": 0, "records": []}
        result = self.verify([self.item("a", checkpoint, [empty])])
        self.assertEqual(result["items"][0]["status"], "invalid-page")


class FailureTaxonomyTest(BatchCase):
    def setUp(self):
        super().setUp()
        self.audit = self.build_chain("f", n=1)
        self.signed = self.checkpoint(self.audit)

    def _verify_raw(self, checkpoint, pages=None):
        pages = pages if pages is not None else self.pages(self.audit)
        return self.verify([self.item("a", checkpoint, pages)])["items"][0]

    def test_malformed_checkpoint_is_invalid_checkpoint(self):
        for bad in (
            b"nope",
            self.signed + b"\n",
            self.signed + b" ",
            b'{"payload":{},"signature":"' + b"0" * 64 + b'"}',
        ):
            with self.subTest(bad=bad[:20]):
                report = self._verify_raw(bad)
                self.assertEqual(report["status"], "invalid-checkpoint")
                self.assertIsNone(report["issuer"])
                self.assertIsNone(report["keyVersion"])
                self.assertIsNone(report["lastSeq"])
                self.assertIsInstance(report["error"], str)
                self.assertEqual(
                    report["digest"],
                    hashlib.sha256(bad).hexdigest(),
                )

    def test_bad_page_is_invalid_page(self):
        page = export_recovery_audit(self.audit, after=2)  # after != 0
        report = self._verify_raw(self.signed, [page])
        self.assertEqual(report["status"], "invalid-page")
        self.assertEqual(report["lastSeq"], 0)
        self.assertEqual(report["issuer"], ISSUER)

    def test_bad_page_after_verified_pages_keeps_boundary(self):
        # First page verifies seqs 1-2; the second opens at the wrong
        # position instead of continuing.
        good_first = export_recovery_audit(self.audit_path("f"), after=0,
                                           limit=2)
        bad_second = copy.deepcopy(good_first)  # after 0 again
        report = self._verify_raw(self.signed, [good_first, bad_second])
        self.assertEqual(report["status"], "invalid-page")
        self.assertEqual(report["lastSeq"], 2)

    def test_page_past_the_signed_tail_is_invalid_page(self):
        whole = export_recovery_audit(self.audit)
        # A page may not follow the page that already reached lastSeq.
        report = self._verify_raw(self.signed, [whole, whole])
        self.assertEqual(report["status"], "invalid-page")

    def test_signature_mismatch_is_unauthenticated(self):
        data = json.loads(self.signed)
        sig = data["signature"]
        data["signature"] = ("a" if sig[0] != "a" else "b") + sig[1:]
        report = self._verify_raw(compact(data))
        self.assertEqual(report["status"], "unauthenticated")
        self.assertEqual(report["lastSeq"], 0)
        self.assertIsInstance(report["error"], str)

    def test_unknown_credentials_are_unauthenticated(self):
        cp = make_checkpoint(
            valid_payload(3, "a" * 64, issuer="ghost"), secret=SECRET
        )
        report = self._verify_raw(cp)
        self.assertEqual(report["status"], "unauthenticated")
        self.assertEqual(report["issuer"], "ghost")

    def test_unknown_key_version_is_unauthenticated(self):
        cp = make_checkpoint(
            valid_payload(3, "a" * 64, key_version=9), secret=SECRET
        )
        report = self._verify_raw(cp)
        self.assertEqual(report["status"], "unauthenticated")
        self.assertEqual(report["keyVersion"], 9)

    def test_revoked_key_is_unauthenticated(self):
        kr = {ISSUER: [key_entry(1, SECRET, revoked=True),
                       key_entry(2, SECRET2)]}
        result = self.verify(
            [self.item("a", self.signed, self.pages(self.audit))],
            keyring=kr,
        )
        self.assertEqual(result["items"][0]["status"], "unauthenticated")

    def test_expired_key_is_unauthenticated(self):
        kr = {ISSUER: [key_entry(1, SECRET, not_after=MOMENT - 1),
                       key_entry(2, SECRET2)]}
        result = self.verify(
            [self.item("a", self.signed, self.pages(self.audit))],
            keyring=kr,
        )
        self.assertEqual(result["items"][0]["status"], "unauthenticated")

    def test_page_crossing_signed_last_seq_is_invalid_page(self):
        # Build a 5-record chain, checkpoint it, then present pages
        # claiming a 6th seq.
        audit = self.build_chain("fx", n=2)
        cp = self.checkpoint(audit)
        page3 = export_recovery_audit(audit, after=4, limit=2)
        page3["next"] = 6
        page3["complete"] = False
        pages = self.pages(audit, (0, 2), (2, 2)) + [page3]
        report = self._verify_raw(cp, pages)
        self.assertEqual(report["status"], "invalid-page")
        self.assertEqual(report["lastSeq"], 4)


class KeyRotationTest(BatchCase):
    def test_pre_and_post_rotation_checkpoints_verify_in_one_batch(self):
        audit1 = self.build_chain("old", n=1, key_version=1, secret=SECRET,
                                  nonce="n-old")
        audit2 = self.build_chain("new", n=2, key_version=2, secret=SECRET2,
                                  nonce="n-new")
        cp1 = self.checkpoint(audit1, key_version=1)
        cp2 = self.checkpoint(audit2, key_version=2)
        result = self.verify([
            self.item("old", cp1, self.pages(audit1)),
            self.item("new", cp2, self.pages(audit2)),
        ])
        statuses = [(r["id"], r["status"], r["keyVersion"])
                    for r in result["items"]]
        self.assertEqual(
            statuses, [("old", "verified", 1), ("new", "verified", 2)]
        )

    def test_rotation_never_falls_back_to_another_version(self):
        # The v1 key is revoked; a v1 checkpoint must fail even though a
        # valid v2 key sits right next to it.
        audit1 = self.build_chain("old2", n=1, key_version=1, secret=SECRET,
                                  nonce="n-old2")
        audit2 = self.build_chain("new2", n=1, key_version=2, secret=SECRET2,
                                  nonce="n-new2")
        rotated = {ISSUER: [
            key_entry(1, SECRET, revoked=True),
            key_entry(2, SECRET2),
        ]}
        result = self.verify([
            self.item("old2", self.checkpoint(audit1, 1),
                      self.pages(audit1)),
            self.item("new2", self.checkpoint(audit2, 2),
                      self.pages(audit2)),
        ], keyring=rotated)
        self.assertEqual(result["items"][0]["status"], "unauthenticated")
        self.assertEqual(result["items"][0]["keyVersion"], 1)
        self.assertEqual(result["items"][1]["status"], "verified")
        self.assertEqual(result["items"][1]["keyVersion"], 2)

    def test_distinct_issuers_select_distinct_keys(self):
        audit = self.build_chain("b", n=1, secret=SECRET2, issuer=OTHER,
                                 nonce="n-b")
        kr = {
            ISSUER: [key_entry(1, SECRET)],
            OTHER: [key_entry(1, SECRET2)],
        }
        checkpoint = self.checkpoint(audit, key_version=1, issuer=OTHER,
                                     keyring=kr)
        result = self.verify(
            [self.item("b", checkpoint, self.pages(audit))], keyring=kr
        )
        self.assertEqual(result["items"][0]["status"], "verified")
        self.assertEqual(result["items"][0]["issuer"], OTHER)


class IsolationAndOrderTest(BatchCase):
    def test_one_failure_never_stops_later_items(self):
        audit = self.build_chain("iso", n=1)
        cp = self.checkpoint(audit)
        pages = self.pages(audit)
        result = self.verify([
            self.item("bad-cp", b"nope", pages),
            self.item("bad-page", cp,
                      [dict(pages[0], after=1, complete=False)]),
            self.item("good", cp, pages),
            self.item("incomplete", cp, self.pages(audit, (0, 1))),
        ])
        self.assertEqual(
            [r["status"] for r in result["items"]],
            ["invalid-checkpoint", "invalid-page", "verified", "incomplete"],
        )
        self.assertEqual([r["id"] for r in result["items"]],
                         ["bad-cp", "bad-page", "good", "incomplete"])

    def test_each_item_uses_its_own_zero_cursor(self):
        # A page that only works as a first page (after 0) verifies for
        # two different checkpoints independently in the same batch.
        a1 = self.build_chain("z1", n=1, nonce="n-z1")
        a2 = self.build_chain("z2", n=1, nonce="n-z2")
        result = self.verify([
            self.item("z1", self.checkpoint(a1), self.pages(a1)),
            self.item("z2", self.checkpoint(a2), self.pages(a2)),
        ])
        self.assertEqual([r["status"] for r in result["items"]],
                         ["verified", "verified"])


class OfflineAndImmutabilityTest(BatchCase):
    def test_no_file_is_read(self):
        audit = self.build_chain("off", n=2)
        checkpoint = self.checkpoint(audit)
        items = [
            self.item("a", checkpoint, self.pages(audit, (0, 2))),
            self.item("b", b"garbage", self.pages(audit)),
            self.item("c", checkpoint, self.pages(audit)),
        ]
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            result = self.verify(items)
        self.assertEqual(
            [r["status"] for r in result["items"]],
            ["incomplete", "invalid-checkpoint", "verified"],
        )

    def test_no_input_is_modified(self):
        audit = self.build_chain("imm", n=2)
        checkpoint = self.checkpoint(audit)
        items = [
            self.item("a", checkpoint, self.pages(audit, (0, 2), (2, 2))),
            self.item("b", b"garbage", self.pages(audit)),
        ]
        snapshot = copy.deepcopy(items)
        keyring_snapshot = copy.deepcopy(self.keyring)
        self.verify(items)
        self.assertEqual(items, snapshot)
        self.assertEqual(self.keyring, keyring_snapshot)

    def test_checkpoint_pages_are_not_required_on_disk(self):
        # The audit may be deleted after export; verification is offline.
        audit = self.build_chain("del", n=1)
        checkpoint = self.checkpoint(audit)
        pages = self.pages(audit)
        os.unlink(audit)
        result = self.verify([self.item("a", checkpoint, pages)])
        self.assertEqual(result["items"][0]["status"], "verified")


class ErrorHierarchyTest(BatchCase):
    def test_batch_only_raises_batch_level_errors(self):
        # Per-item failures are reports, not exceptions; the exceptions
        # used by the single-checkpoint API never escape the batch.
        audit = self.build_chain("h", n=1)
        cp = self.checkpoint(audit)
        data = json.loads(cp)
        data["signature"] = "0" * 64
        items = [
            self.item("ua", compact(data), self.pages(audit)),
            self.item("icp", b"nope", self.pages(audit)),
        ]
        result = self.verify(items)
        self.assertEqual(
            [r["status"] for r in result["items"]],
            ["unauthenticated", "invalid-checkpoint"],
        )
        # AuthenticationError remains the single-checkpoint exception.
        self.assertTrue(issubclass(AuthenticationError, ValueError))


if __name__ == "__main__":
    unittest.main()
