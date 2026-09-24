"""Tests for offline batch verification of recovery checkpoints.

Covers :func:`verify_recovery_checkpoints`: the batch container
contract and its type/value taxonomy, per-item isolation, the
``verified``/``incomplete``/``invalid-checkpoint``/``invalid-page``/
``unauthenticated`` statuses, key rotation with exact version
selection, the purely offline guarantee and input immutability.
"""

import copy
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination.replication import (
    verify_recovery_checkpoints,
    export_recovery_audit,
    export_recovery_checkpoint,
    recover_authorized,
)

SECRET_V1 = "ab" * 32
SECRET_V2 = "cd" * 32
ISSUER = "issuer-a"
ZERO_HASH = "0" * 64
MOMENT = 7


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_payload(payload, secret):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def make_checkpoint(payload, secret):
    return compact(
        {"payload": payload, "signature": sign_payload(payload, secret)}
    )


def keyring_v1(secret=SECRET_V1, revoked=False, not_before=0,
               not_after=10 ** 9, version=1):
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


def make_ticket(paths, nonce="nonce-1", secret=SECRET_V1, issuer=ISSUER,
                key_version=1):
    payload = {
        "issuer": issuer,
        "keyVersion": key_version,
        "nonce": nonce,
        "notBefore": 0,
        "notAfter": 10 ** 9,
        "paths": list(paths),
    }
    return compact(
        {"payload": payload,
         "signature": sign_payload(payload, secret)}
    )


def cursor_of(result):
    return {
        "digest": result["digest"],
        "next": result["lastSeq"],
        "tail": result["tail"],
    }


ITEM_KEY_ORDER = [
    "id", "digest", "issuer", "keyVersion", "boundary", "status", "error",
]


class BatchCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keyring = keyring_v1()
        self.rotated = {
            ISSUER: [
                {"version": 1, "secret": SECRET_V1, "notBefore": 0,
                 "notAfter": 10 ** 9, "revoked": False},
                {"version": 2, "secret": SECRET_V2, "notBefore": 0,
                 "notAfter": 10 ** 9, "revoked": False},
            ]
        }

    def ledger_path(self, tag):
        return os.path.join(self.dir, f"{tag}.json")

    def audit_path(self, tag="audit"):
        return os.path.join(self.dir, f"{tag}.jsonl")

    def build_chain(self, tag, n=2, keyring=None, secret=SECRET_V1,
                    key_version=1, nonce=None):
        audit = self.audit_path(tag)
        paths = []
        for i in range(n):
            path = self.ledger_path(f"{tag}-l{i}")
            with open(path, "wb") as handle:
                handle.write(f"{tag}-{i}".encode())
            paths.append(path)
        recover_authorized(
            paths,
            keyring or self.keyring,
            make_ticket(
                paths,
                secret=secret,
                key_version=key_version,
                nonce=nonce or f"nonce-{tag}",
            ),
            MOMENT,
            audit,
        )
        return audit

    def checkpoint(self, audit, keyring=None, issuer=ISSUER, version=1):
        return export_recovery_checkpoint(
            audit, keyring or self.keyring, issuer, version, MOMENT
        )

    def pages(self, audit, windows=None):
        """Whole-chain page or explicit (after, limit) paging windows."""
        if windows is None:
            return [export_recovery_audit(audit)]
        return [
            export_recovery_audit(audit, after=after, limit=limit)
            for after, limit in windows
        ]

    def item(self, item_id, audit=None, checkpoint=None, pages=None,
             keyring=None, version=1, windows=None):
        audit = audit or self.audit_path(item_id)
        checkpoint = checkpoint or self.checkpoint(
            audit, keyring=keyring, version=version
        )
        pages = pages if pages is not None else self.pages(audit, windows)
        return {"id": item_id, "checkpoint": checkpoint, "pages": pages}

    def verify(self, items, keyring=None, moment=MOMENT):
        return verify_recovery_checkpoints(
            items,
            self.keyring if keyring is None else keyring,
            moment,
        )


class BatchStructureTest(BatchCase):
    def test_container_and_element_types_are_type_errors(self):
        good = self.item("good", self.build_chain("good", n=1))
        for bad_items in (None, "x", (good,), 1, {"id": "x"}):
            with self.subTest(bad=type(bad_items)):
                with self.assertRaises(TypeError):
                    self.verify(bad_items)
        for bad in (None, 1, "x", []):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    self.verify([bad])
        # Field type faults.
        with self.assertRaises(TypeError):
            self.verify([{"id": 1, "checkpoint": b"x", "pages": [{}]}])
        with self.assertRaises(TypeError):
            self.verify([{"id": "x", "checkpoint": "x", "pages": [{}]}])
        with self.assertRaises(TypeError):
            self.verify([{"id": "x", "checkpoint": b"x", "pages": ({},)}])
        with self.assertRaises(TypeError):
            self.verify(
                [{"id": "x", "checkpoint": b"x", "pages": [[]]}]
            )

    def test_value_faults(self):
        with self.assertRaises(ValueError):
            self.verify([])
        with self.assertRaises(ValueError):
            self.verify([{"id": "", "checkpoint": b"x", "pages": [{}]}])
        with self.assertRaises(ValueError):
            self.verify(
                [
                    {"id": "x", "checkpoint": b"x", "pages": [{}]},
                    {"id": "x", "checkpoint": b"y", "pages": [{}]},
                ]
            )
        with self.assertRaises(ValueError):
            self.verify([{"id": "x", "checkpoint": b"x", "pages": []}])
        with self.assertRaises(ValueError):
            self.verify(
                [{"id": "x", "checkpoint": b"x", "pages": [{}], "extra": 1}]
            )
        with self.assertRaises(ValueError):
            self.verify([{"id": "x", "checkpoint": b"x"}])

    def test_whole_batch_is_validated_before_any_item_is_verified(self):
        good = self.item("good", self.build_chain("good", n=1))
        # A structural fault on the second item raises instead of
        # producing a result for the first.
        with self.assertRaises(ValueError):
            self.verify([good, {"id": "dup", "checkpoint": b"x",
                                "pages": []}])

    def test_keyring_and_moment_faults_keep_their_classification(self):
        audit = self.build_chain("k", n=1)
        good = [self.item("k", audit)]
        with self.assertRaises(TypeError):
            verify_recovery_checkpoints(good, None, MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_checkpoints(good, [], MOMENT)
        with self.assertRaises(ValueError):
            verify_recovery_checkpoints(
                good,
                {ISSUER: [{"version": 1, "secret": "zz",
                           "notBefore": 0, "notAfter": 1, "revoked": False}]},
                MOMENT,
            )
        for bad_moment in (True, 1.5, "7"):
            with self.subTest(bad=bad_moment):
                with self.assertRaises(TypeError):
                    verify_recovery_checkpoints(good, self.keyring, bad_moment)
        with self.assertRaises(ValueError):
            verify_recovery_checkpoints(good, self.keyring, -1)


class VerifiedBatchTest(BatchCase):
    def test_whole_chain_pages_verify(self):
        audit = self.build_chain("a", n=2)  # 5 records
        result = self.verify([self.item("a", audit)])
        self.assertEqual(list(result.keys()), ["items", "version"])
        self.assertEqual(result["version"], 1)
        (item,) = result["items"]
        self.assertEqual(list(item.keys()), ITEM_KEY_ORDER)
        self.assertEqual(item["id"], "a")
        self.assertEqual(
            item["digest"],
            hashlib.sha256(self.checkpoint(audit)).hexdigest(),
        )
        self.assertEqual(item["issuer"], ISSUER)
        self.assertEqual(item["keyVersion"], 1)
        self.assertEqual(
            item["boundary"],
            {"lastSeq": 5, "tail": export_recovery_audit(audit)
             ["records"][-1]["hash"]},
        )
        self.assertEqual(item["status"], "verified")
        self.assertIsNone(item["error"])

    def test_walk_across_pages_verifies(self):
        audit = self.build_chain("p", n=2)
        item = self.item("p", audit, windows=[(0, 2), (2, 2), (4, 2)])
        (report,) = self.verify([item])["items"]
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["boundary"]["lastSeq"], 5)

    def test_empty_checkpoint_verifies_with_empty_page(self):
        missing = self.audit_path("missing")
        checkpoint = self.checkpoint(missing)
        empty_page = {
            "after": 0, "complete": True, "next": 0, "records": []
        }
        report = self.verify(
            [{"id": "e", "checkpoint": checkpoint,
              "pages": [empty_page]}]
        )["items"][0]
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["boundary"], {"lastSeq": 0, "tail": ZERO_HASH})

    def test_inputs_are_not_modified_and_result_is_fresh(self):
        audit = self.build_chain("i", n=2)
        item = self.item("i", audit, windows=[(0, 2), (2, 10)])
        item_copy = copy.deepcopy(item)
        result = self.verify([item])
        self.assertEqual(item, item_copy)
        # Mutating the report never reaches back into the inputs.
        result["items"][0]["status"] = "tampered"
        result["items"][0]["boundary"]["lastSeq"] = -1
        self.assertEqual(item, item_copy)


class IncompleteBatchTest(BatchCase):
    def test_pages_exhausted_before_tail_is_incomplete_with_boundary(self):
        audit = self.build_chain("inc", n=2)
        # Only the first two pages: prefix ends at seq 4, tail unsigned.
        item = self.item("inc", audit, windows=[(0, 2), (2, 2)])
        report = self.verify([item])["items"][0]
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["boundary"]["lastSeq"], 4)
        page2 = export_recovery_audit(audit, after=2, limit=2)
        self.assertEqual(
            report["boundary"]["tail"], page2["records"][-1]["hash"]
        )
        self.assertEqual(report["issuer"], ISSUER)
        self.assertEqual(report["keyVersion"], 1)
        self.assertIsInstance(report["error"], str)

    def test_single_prefix_page_is_incomplete(self):
        audit = self.build_chain("inc2", n=2)
        item = self.item("inc2", audit, windows=[(0, 2)])
        report = self.verify([item])["items"][0]
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["boundary"]["lastSeq"], 2)

    def test_pages_continuing_past_the_tail_are_invalid_page(self):
        audit = self.build_chain("past", n=1)  # 3 records
        whole = export_recovery_audit(audit)
        restate = {"after": 3, "complete": True, "next": 3, "records": []}
        checkpoint = self.checkpoint(audit)
        report = self.verify(
            [{"id": "past", "checkpoint": checkpoint,
              "pages": [whole, restate]}]
        )["items"][0]
        self.assertEqual(report["status"], "invalid-page")
        # The verified tail boundary is still reported.
        self.assertEqual(report["boundary"]["lastSeq"], 3)
        self.assertEqual(report["boundary"]["tail"],
                         whole["records"][-1]["hash"])
        self.assertIsInstance(report["error"], str)


class FaultyItemTest(BatchCase):
    def test_unparseable_checkpoint_is_invalid_checkpoint(self):
        page = {"after": 0, "complete": True, "next": 0, "records": []}
        for raw in (b"nope", b'{"payload":{}}', b" "):
            with self.subTest(raw=raw):
                report = self.verify(
                    [{"id": "bad", "checkpoint": raw, "pages": [page]}]
                )["items"][0]
                self.assertEqual(report["status"], "invalid-checkpoint")
                self.assertEqual(
                    report["digest"],
                    hashlib.sha256(raw).hexdigest(),
                )
                self.assertIsNone(report["issuer"])
                self.assertIsNone(report["keyVersion"])
                self.assertIsNone(report["boundary"])
                self.assertIsInstance(report["error"], str)

    def test_structurally_invalid_checkpoint_is_invalid_checkpoint(self):
        audit = self.build_chain("str", n=1)
        good = json.loads(self.checkpoint(audit))
        bad = compact({"payload": good["payload"], "signature": "z" * 64})
        item = {"id": "str", "checkpoint": bad,
                "pages": [export_recovery_audit(audit)]}
        report = self.verify([item])["items"][0]
        self.assertEqual(report["status"], "invalid-checkpoint")
        self.assertIsNone(report["issuer"])

    def test_first_page_fault_leaves_no_boundary(self):
        audit = self.build_chain("fp", n=1)
        page = export_recovery_audit(audit)
        page["after"] = 1  # first round must start at zero
        item = self.item("fp", audit, pages=[page])
        report = self.verify([item])["items"][0]
        self.assertEqual(report["status"], "invalid-page")
        self.assertIsNone(report["boundary"])
        self.assertEqual(report["issuer"], ISSUER)
        self.assertEqual(report["keyVersion"], 1)

    def test_later_page_fault_keeps_the_verified_boundary(self):
        audit = self.build_chain("lp", n=2)
        page1 = export_recovery_audit(audit, after=0, limit=2)
        page2 = export_recovery_audit(audit, after=2, limit=2)
        page2["records"][0]["nonce"] = "tampered"
        checkpoint = self.checkpoint(audit)
        report = self.verify(
            [{"id": "lp", "checkpoint": checkpoint,
              "pages": [page1, page2]}]
        )["items"][0]
        self.assertEqual(report["status"], "invalid-page")
        self.assertEqual(report["boundary"]["lastSeq"], 2)
        self.assertEqual(
            report["boundary"]["tail"], page1["records"][-1]["hash"]
        )

    def test_unknown_revoked_expired_credentials_are_unauthenticated(self):
        audit = self.build_chain("u", n=1)
        pages = [export_recovery_audit(audit)]
        checkpoint = self.checkpoint(audit)
        cases = {
            "unknown-issuer": ({}, checkpoint),
            "wrong-secret": (keyring_v1(secret=SECRET_V2), checkpoint),
            "unknown-version": (
                self.keyring,
                self.checkpoint(audit, keyring=keyring_v1(version=2),
                                version=2),
            ),
            "revoked": (keyring_v1(revoked=True), checkpoint),
            "expired": (
                keyring_v1(not_after=MOMENT - 1), checkpoint
            ),
            "unready": (
                keyring_v1(not_before=MOMENT + 1), checkpoint
            ),
        }
        for label, (ring, cp) in cases.items():
            with self.subTest(label=label):
                report = self.verify(
                    [{"id": label, "checkpoint": cp, "pages": pages}],
                    keyring=ring,
                )["items"][0]
                self.assertEqual(report["status"], "unauthenticated")
                self.assertEqual(report["issuer"], ISSUER)
                self.assertIsNone(report["boundary"])
                self.assertIsInstance(report["error"], str)

    def test_signature_tamper_is_unauthenticated(self):
        audit = self.build_chain("sig", n=1)
        data = json.loads(self.checkpoint(audit))
        old = data["signature"]
        data["signature"] = ("a" if old[0] != "a" else "b") + old[1:]
        item = {
            "id": "sig",
            "checkpoint": compact(data),
            "pages": [export_recovery_audit(audit)],
        }
        report = self.verify([item])["items"][0]
        self.assertEqual(report["status"], "unauthenticated")

    def test_claimed_version_is_never_satisfied_by_fallback(self):
        audit = self.build_chain("fb", n=1)
        # Claims v2 but carries an HMAC made with the v1 secret.
        data = json.loads(self.checkpoint(audit))
        payload = dict(data["payload"], keyVersion=2)
        checkpoint = make_checkpoint(payload, SECRET_V1)
        item = {
            "id": "fb",
            "checkpoint": checkpoint,
            "pages": [export_recovery_audit(audit)],
        }
        report = self.verify([item], keyring=self.rotated)["items"][0]
        self.assertEqual(report["status"], "unauthenticated")
        self.assertEqual(report["keyVersion"], 2)


class IsolationTest(BatchCase):
    def test_one_failure_never_stops_later_items(self):
        audits = {
            tag: self.build_chain(tag, n=1)
            for tag in ("o1", "o2", "o3", "o4")
        }
        good_cp = self.checkpoint(audits["o2"])
        items = [
            # unparseable checkpoint
            {"id": "invalid", "checkpoint": b"nope",
             "pages": [export_recovery_audit(audits["o1"])]},
            # fully verified
            {"id": "ok", "checkpoint": good_cp,
             "pages": [export_recovery_audit(audits["o2"])]},
            # valid checkpoint, bad first page
            self.item("bad-page", audits["o3"],
                      pages=[{"after": 0, "complete": True,
                              "next": 0, "records": []}]),
            # incomplete prefix
            self.item("incomplete", audits["o4"], windows=[(0, 1)]),
        ]
        reports = self.verify(items)["items"]
        self.assertEqual(
            [r["status"] for r in reports],
            ["invalid-checkpoint", "verified", "invalid-page", "incomplete"],
        )
        self.assertEqual([r["id"] for r in reports],
                         ["invalid", "ok", "bad-page", "incomplete"])
        self.assertEqual(
            [r["error"] is None for r in reports],
            [False, True, False, False],
        )

    def test_results_follow_input_order(self):
        a = self.build_chain("oa", n=1)
        b = self.build_chain("ob", n=1)
        reports = self.verify(
            [self.item("b", b), self.item("a", a)]
        )["items"]
        self.assertEqual([r["id"] for r in reports], ["b", "a"])


class KeyRotationTest(BatchCase):
    def test_pre_and_post_rotation_checkpoints_verify_in_one_batch(self):
        # Chain/checkpoint signed under v1 and another under v2; the
        # current keyring retains both versions.
        audit_v1 = self.build_chain(
            "v1", n=1, keyring=self.rotated, secret=SECRET_V1,
            key_version=1,
        )
        audit_v2 = self.build_chain(
            "v2", n=2, keyring=self.rotated, secret=SECRET_V2,
            key_version=2,
        )
        items = [
            self.item("v1", audit_v1, keyring=self.rotated, version=1),
            self.item("v2", audit_v2, keyring=self.rotated, version=2),
        ]
        reports = self.verify(items, keyring=self.rotated)["items"]
        self.assertEqual(
            [(r["keyVersion"], r["status"]) for r in reports],
            [(1, "verified"), (2, "verified")],
        )

    def test_revoking_the_retained_old_version_rejects_only_that_item(self):
        audit_v1 = self.build_chain(
            "rv1", n=1, keyring=self.rotated, secret=SECRET_V1,
            key_version=1,
        )
        audit_v2 = self.build_chain(
            "rv2", n=1, keyring=self.rotated, secret=SECRET_V2,
            key_version=2,
        )
        rotated = copy.deepcopy(self.rotated)
        rotated[ISSUER][0]["revoked"] = True
        reports = self.verify(
            [
                self.item("rv1", audit_v1, keyring=self.rotated, version=1),
                self.item("rv2", audit_v2, keyring=self.rotated, version=2),
            ],
            keyring=rotated,
        )["items"]
        self.assertEqual(
            [r["status"] for r in reports], ["unauthenticated", "verified"]
        )


class OfflineTest(BatchCase):
    def test_no_file_is_read(self):
        audit = self.build_chain("off", n=2)
        checkpoint = self.checkpoint(audit)
        pages = [
            export_recovery_audit(audit, after=0, limit=2),
            export_recovery_audit(audit, after=2, limit=10),
        ]
        item = {"id": "off", "checkpoint": checkpoint, "pages": pages}
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            result = self.verify([item])
        self.assertEqual(result["items"][0]["status"], "verified")
        # Verification also works after the audit itself is gone.
        os.unlink(audit)
        result = self.verify([copy.deepcopy(item)])
        self.assertEqual(result["items"][0]["status"], "verified")


if __name__ == "__main__":
    unittest.main()
