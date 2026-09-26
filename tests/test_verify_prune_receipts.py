"""Tests for offline verification of chain prune receipts.

Covers :func:`verify_prune_receipt` and the batch
:func:`verify_prune_receipts`: the canonical receipt/plan contract, the
checkpoint/plan/receipt three-signature re-check with exact
issuer/version key selection and no fallback, the delete/retain and
checkpoint digest bindings, the unique project located from status and
before/after digests, the independently regenerated prune marker, the
fixed single-entry result and batch report shapes, the
verified/invalid/unauthenticated taxonomy with full batch
pre-validation and per-item isolation, error hierarchy, result
freshness/independence, input immutability and the purely offline
guarantee.
"""

import copy
import hashlib
import hmac
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidPruneError,
    InvalidPruneReceiptError,
    plan_chain_prune,
    prune_chain_archives,
    verify_prune_receipt,
    verify_prune_receipts,
)

from test_chain_prune import PruneFixtures
from test_fork_convergence import (
    COORD,
    RING,
    SECRET_COORD,
    compact,
    entry,
    parse,
)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def hmac_hex(secret_hex, raw):
    return hmac.new(bytes.fromhex(secret_hex), raw, hashlib.sha256).hexdigest()


def sign(payload, secret=SECRET_COORD):
    return hmac_hex(secret, compact(payload))


def envelope(payload, signature):
    return compact({"payload": payload, "signature": signature})


RESULT_KEYS = [
    "project", "status", "beforeDigest", "afterDigest", "checkpoint",
    "planDigest", "moment", "version",
]
REPORT_KEYS = ["error", "id", "result", "status"]
TOP_KEYS = ["items", "version"]


class ReceiptVerificationTest(PruneFixtures, unittest.TestCase):
    def pruned_receipt(self, names=("c", "a", "g"), name="c", plan=None):
        plan = self.make_plan(names) if plan is None else plan
        report = prune_chain_archives(
            [self.batch_item("i", name, plan)], RING
        )[0]
        self.assertIsNone(report["error"], report["error"])
        return report["receipt"], plan

    def duplicate_receipt(self, names=("c",), name="c"):
        plan = self.make_plan(names)
        first = prune_chain_archives(
            [self.batch_item("i", name, plan)], RING
        )[0]
        second = prune_chain_archives(
            [self.batch_item("j", name, plan)], RING
        )[0]
        self.assertIsNone(second["error"])
        return first["receipt"], second["receipt"], plan

    def test_pruned_receipt_verifies_with_the_fixed_result_shape(self):
        receipt, plan = self.pruned_receipt()
        result = verify_prune_receipt(receipt, self.checkpoint, RING,
                                     self.moment)
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertEqual(result["project"], "c")
        self.assertEqual(result["status"], "pruned")
        plan_payload = parse(plan)["payload"]
        self.assertEqual(result["beforeDigest"], plan_payload["source"]["c"])
        self.assertEqual(result["afterDigest"], plan_payload["target"]["c"])
        self.assertEqual(result["checkpoint"], sha256(self.checkpoint))
        self.assertEqual(result["planDigest"], sha256(plan))
        self.assertEqual(result["moment"], self.moment)
        self.assertEqual(result["version"], 1)
        self.assertNotIsInstance(result["version"], bool)

    def test_duplicate_receipt_verifies_with_equal_digests(self):
        _first, duplicate, plan = self.duplicate_receipt()
        result = verify_prune_receipt(duplicate, self.checkpoint, RING,
                                      self.moment)
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(result["project"], "c")
        target = parse(plan)["payload"]["target"]["c"]
        self.assertEqual(result["beforeDigest"], target)
        self.assertEqual(result["afterDigest"], target)

    def test_repeated_verification_is_equal_and_independent(self):
        receipt, _plan = self.pruned_receipt()
        first = verify_prune_receipt(receipt, self.checkpoint, RING,
                                    self.moment)
        second = verify_prune_receipt(receipt, self.checkpoint, RING,
                                     self.moment)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["status"] = "tampered"
        self.assertEqual(second["status"], "pruned")

    def test_result_is_built_from_authenticated_material_only(self):
        receipt, _plan = self.pruned_receipt()
        result = verify_prune_receipt(receipt, self.checkpoint, RING,
                                     self.moment)
        # The result exposes exactly the eight documented keys.
        self.assertEqual(set(result), set(RESULT_KEYS))

    def test_non_ascii_project_verifies(self):
        name = "项目"
        path = os.path.join(self.tmp, f"{name}.arc")
        with open(path, "wb") as handle:
            handle.write(self.archive_bytes(name, self.cert_coord))
        plan = plan_chain_prune(
            [path], self.checkpoint, self.decision, self.pol, RING,
            self.moment,
        )
        report = prune_chain_archives([{
            "id": "i", "path": path, "plan": plan,
            "checkpoint": self.checkpoint, "header": dict(self.header),
        }], RING)[0]
        self.assertIsNone(report["error"])
        result = verify_prune_receipt(
            report["receipt"], self.checkpoint, RING, self.moment
        )
        self.assertEqual(result["project"], "项目")


class ReceiptErrorHierarchyTest(PruneFixtures, unittest.TestCase):
    def test_invalid_prune_receipt_is_a_value_error(self):
        self.assertTrue(issubclass(InvalidPruneReceiptError, ValueError))
        self.assertIsNot(InvalidPruneReceiptError, InvalidPruneError)


class PublicArgumentTaxonomyTest(PruneFixtures, unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        reports = prune_chain_archives([self.batch_item("i", "c")], RING)
        self.receipt = reports[0]["receipt"]

    def test_type_faults(self):
        with self.assertRaises(TypeError):
            verify_prune_receipt("x", self.checkpoint, RING, self.moment)
        with self.assertRaises(TypeError):
            verify_prune_receipt(self.receipt, "x", RING, self.moment)
        with self.assertRaises(TypeError):
            verify_prune_receipt(self.receipt, self.checkpoint, [],
                                 self.moment)
        with self.assertRaises(TypeError):
            verify_prune_receipt(self.receipt, self.checkpoint, RING, True)
        with self.assertRaises(TypeError):
            verify_prune_receipt(self.receipt, self.checkpoint, RING, "1")

    def test_illegal_moment_is_a_value_error(self):
        with self.assertRaises(ValueError):
            verify_prune_receipt(self.receipt, self.checkpoint, RING, -1)

    def test_bool_never_poses_as_an_int_inside_the_receipt(self):
        data = parse(self.receipt)
        data["payload"]["version"] = True
        raw = envelope(
            data["payload"], sign(data["payload"])
        )
        with self.assertRaises(InvalidPruneReceiptError):
            verify_prune_receipt(raw, self.checkpoint, RING, self.moment)


class InvalidReceiptClassificationTest(PruneFixtures, unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.plan = self.make_plan(("a", "c", "g"))
        report = prune_chain_archives(
            [self.batch_item("i", "c", self.plan)], RING
        )[0]
        self.assertIsNone(report["error"])
        self.receipt = report["receipt"]
        self.good = parse(self.receipt)

    def verify(self, raw=None, checkpoint=None):
        return verify_prune_receipt(
            self.receipt if raw is None else raw,
            self.checkpoint if checkpoint is None else checkpoint,
            RING, self.moment,
        )

    def resign(self, data):
        """Re-sign a manipulated receipt payload with the checkpoint key."""
        data["signature"] = sign(data["payload"])
        return compact(data)

    def resign_plan(self, data):
        """Re-sign the manipulated embedded plan and the outer receipt."""
        plan_data = data["payload"]["plan"]
        plan_data["signature"] = sign(plan_data["payload"])
        return self.resign(data)

    def expect_invalid(self, raw=None, checkpoint=None):
        with self.assertRaises(InvalidPruneReceiptError):
            self.verify(raw, checkpoint)

    def test_non_canonical_encodings_are_invalid(self):
        self.expect_invalid(self.receipt + b"\n")
        self.expect_invalid(self.receipt + b" ")
        self.expect_invalid(b"")
        self.expect_invalid(b"nope")
        indented = json.dumps(
            parse(self.receipt), ensure_ascii=False, sort_keys=True, indent=1
        ).encode()
        self.expect_invalid(indented)

    def test_wrong_key_sets_versions_digests_and_status_are_invalid(self):
        def clone():
            return copy.deepcopy(self.good)

        d = clone()
        del d["payload"]["moment"]
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["extra"] = 1
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["version"] = 2
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["checkpoint"] = "z" * 64
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["status"] = "rolled-back"
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["delete"] = ["c"]
        self.expect_invalid(self.resign_plan(d))

        d = clone()
        d["payload"]["retain"] = []
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["plan"] = {"payload": d["payload"]["plan"]["payload"]}
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["moment"] = -1
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["delete"] = ["c", "c", "a"]
        self.expect_invalid(self.resign_plan(d))

    def test_receipt_must_bind_the_supplied_checkpoint(self):
        self.expect_invalid(checkpoint=self.other_checkpoint())
        d = copy.deepcopy(self.good)
        d["payload"]["checkpoint"] = "00" * 32
        self.expect_invalid(self.resign(d))
        d = copy.deepcopy(self.good)
        d["payload"]["plan"]["payload"]["checkpoint"] = "00" * 32
        self.expect_invalid(self.resign_plan(d))

    def test_delete_and_retain_bindings_must_match_the_plan(self):
        def clone():
            return copy.deepcopy(self.good)

        d = clone()
        d["payload"]["delete"].reverse()
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["delete"] = ["a"]
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["delete"].append("zzz")
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["retain"][0] = "11" * 32
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["retain"].append("22" * 32)
        self.expect_invalid(self.resign(d))

        d = clone()
        d["payload"]["plan"]["payload"]["delete"].reverse()
        self.expect_invalid(self.resign_plan(d))

        d = clone()
        d["payload"]["plan"]["payload"]["retain"][0] = "33" * 32
        self.expect_invalid(self.resign_plan(d))

    def test_before_and_after_must_uniquely_locate_one_project(self):
        # Zero candidates: beforeDigest names no plan source project.
        d = copy.deepcopy(self.good)
        d["payload"]["beforeDigest"] = "44" * 32
        self.expect_invalid(self.resign(d))

        # A pruned receipt whose before digest is the target marker
        # matches no source project.
        d = copy.deepcopy(self.good)
        d["payload"]["beforeDigest"] = d["payload"]["afterDigest"]
        self.expect_invalid(self.resign(d))

        # A duplicate receipt whose digests name a source archive.
        d = copy.deepcopy(self.good)
        d["payload"]["status"] = "duplicate"
        self.expect_invalid(self.resign(d))

        # afterDigest disagreeing with the plan target for the project.
        d = copy.deepcopy(self.good)
        d["payload"]["afterDigest"] = "55" * 32
        self.expect_invalid(self.resign(d))

    def test_multiple_candidate_projects_are_rejected(self):
        # Forge a plan in which two delete projects share one source
        # digest, then a properly signed pruned receipt for that digest:
        # the project is no longer uniquely locatable.
        plan_data = parse(self.plan)
        plan_payload = plan_data["payload"]
        plan_payload["source"]["a"] = plan_payload["source"]["c"]
        plan_data["signature"] = sign(plan_payload)
        receipt_payload = {
            "afterDigest": plan_payload["target"]["c"],
            "beforeDigest": plan_payload["source"]["c"],
            "checkpoint": sha256(self.checkpoint),
            "delete": list(plan_payload["delete"]),
            "moment": self.moment,
            "plan": plan_data,
            "retain": list(plan_payload["retain"]),
            "status": "pruned",
            "version": 1,
        }
        forged = envelope(receipt_payload, sign(receipt_payload))
        self.expect_invalid(forged)

    def test_target_must_match_the_regenerated_marker(self):
        # A signed plan whose target digest does not equal the marker
        # bytes the verifier regenerates itself must fail, even when the
        # receipt agrees with the plan.
        plan_data = parse(self.plan)
        plan_payload = plan_data["payload"]
        plan_payload["target"]["c"] = "66" * 32
        plan_data["signature"] = sign(plan_payload)
        receipt_payload = {
            "afterDigest": "66" * 32,
            "beforeDigest": self.good["payload"]["beforeDigest"],
            "checkpoint": sha256(self.checkpoint),
            "delete": list(plan_payload["delete"]),
            "moment": self.moment,
            "plan": plan_data,
            "retain": list(plan_payload["retain"]),
            "status": "pruned",
            "version": 1,
        }
        self.expect_invalid(
            envelope(receipt_payload, sign(receipt_payload))
        )

    def test_malformed_checkpoint_is_invalid(self):
        self.expect_invalid(checkpoint=b"{}")
        self.expect_invalid(checkpoint=b"not json")

    def test_embedded_plan_field_type_faults_are_invalid(self):
        d = copy.deepcopy(self.good)
        d["payload"]["plan"]["payload"]["version"] = "1"
        self.expect_invalid(self.resign_plan(d))
        d = copy.deepcopy(self.good)
        d["payload"]["delete"] = [1, "a", "c"]
        self.expect_invalid(self.resign(d))


class UnauthenticatedReceiptTest(PruneFixtures, unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.plan = self.make_plan()
        report = prune_chain_archives(
            [self.batch_item("i", "c", self.plan)], RING
        )[0]
        self.receipt = report["receipt"]

    def verify(self, keyring=None, receipt=None, checkpoint=None,
               moment=None):
        return verify_prune_receipt(
            self.receipt if receipt is None else receipt,
            self.checkpoint if checkpoint is None else checkpoint,
            RING if keyring is None else keyring,
            self.moment if moment is None else moment,
        )

    def test_credential_states(self):
        with self.assertRaises(AuthenticationError):
            self.verify(keyring={"other": [entry(1, SECRET_COORD)]})
        with self.assertRaises(AuthenticationError):
            self.verify(keyring={
                COORD: [entry(1, SECRET_COORD, revoked=True)]
            })
        with self.assertRaises(AuthenticationError):
            self.verify(keyring={
                COORD: [entry(1, SECRET_COORD, not_before=self.moment + 1)]
            })
        with self.assertRaises(AuthenticationError):
            self.verify(keyring={
                COORD: [entry(1, SECRET_COORD, not_after=self.moment - 1)]
            })
        with self.assertRaises(AuthenticationError):
            self.verify(moment=10 ** 12)

    def test_no_fallback_to_another_key_version(self):
        # The checkpoint names coord v1; a ring holding only v2 must not
        # fall back to it.
        ring_v2 = {COORD: [entry(2, "22" * 32)]}
        with self.assertRaises(AuthenticationError):
            self.verify(keyring=ring_v2)

    def test_wrong_signatures_at_each_layer(self):
        def flip(hex_signature):
            return ("0" if hex_signature[0] != "0" else "1") + \
                hex_signature[1:]

        d = parse(self.receipt)
        d["signature"] = flip(d["signature"])
        with self.assertRaises(AuthenticationError):
            self.verify(receipt=compact(d))

        d = parse(self.receipt)
        d["payload"]["plan"]["signature"] = flip(
            d["payload"]["plan"]["signature"]
        )
        with self.assertRaises(AuthenticationError):
            self.verify(receipt=compact(d))

        # The checkpoint, plan and receipt were sealed with coord v1's
        # secret; a ring carrying a different usable secret for that exact
        # issuer/version fails the checkpoint HMAC with no fallback.
        rotated = {**RING, COORD: [entry(1, "22" * 32)]}
        with self.assertRaises(AuthenticationError):
            self.verify(keyring=rotated)

    def test_signed_with_a_different_secret(self):
        d = copy.deepcopy(parse(self.receipt))
        d["signature"] = hmac_hex("77" * 32, compact(d["payload"]))
        with self.assertRaises(AuthenticationError):
            self.verify(receipt=compact(d))


def batch_item(item_id, receipt, checkpoint):
    return {"id": item_id, "receipt": receipt, "checkpoint": checkpoint}


class VerifyPruneReceiptsBatchTest(PruneFixtures, unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.plan = self.make_plan()
        report = prune_chain_archives(
            [self.batch_item("i", "c", self.plan)], RING
        )[0]
        self.receipt = report["receipt"]

    def batch(self, items, keyring=None, moment=None):
        return verify_prune_receipts(
            items, RING if keyring is None else keyring,
            self.moment if moment is None else moment,
        )

    def good_item(self, item_id="ok"):
        return batch_item(item_id, self.receipt, self.checkpoint)

    def test_top_level_shape_and_fixed_report_order(self):
        result = self.batch([self.good_item()])
        self.assertEqual(list(result.keys()), TOP_KEYS)
        self.assertEqual(result["version"], 1)
        report = result["items"][0]
        self.assertEqual(list(report.keys()), REPORT_KEYS)
        self.assertEqual(report["id"], "ok")
        self.assertEqual(report["status"], "verified")
        self.assertIsNone(report["error"])
        self.assertEqual(
            list(report["result"].keys()), RESULT_KEYS
        )

    def test_batch_structure_is_fully_pre_validated(self):
        with self.assertRaises(TypeError):
            self.batch((self.good_item(),))
        with self.assertRaises(TypeError):
            self.batch(["not-a-dict"])
        with self.assertRaises(TypeError):
            self.batch([batch_item(1, self.receipt, self.checkpoint)])
        with self.assertRaises(TypeError):
            self.batch([{"id": "x", "receipt": "x",
                         "checkpoint": self.checkpoint}])
        with self.assertRaises(TypeError):
            self.batch([{"id": "x", "receipt": self.receipt,
                         "checkpoint": 1}])
        with self.assertRaises(ValueError):
            self.batch([])
        with self.assertRaises(ValueError):
            self.batch([batch_item("", self.receipt, self.checkpoint)])
        with self.assertRaises(ValueError):
            self.batch([self.good_item("dup"), self.good_item("dup")])
        with self.assertRaises(ValueError):
            self.batch([{"id": "x", "receipt": self.receipt}])
        with self.assertRaises(ValueError):
            self.batch([{"id": "x", "receipt": self.receipt,
                         "checkpoint": self.checkpoint, "extra": 1}])
        with self.assertRaises(TypeError):
            self.batch([self.good_item()], moment=True)
        with self.assertRaises(ValueError):
            self.batch([self.good_item()], moment=-1)

        # Broken receipts must not mask a later structural fault.
        with self.assertRaises(TypeError):
            self.batch([
                batch_item("bad", b"nope", self.checkpoint),
                batch_item(2, self.receipt, self.checkpoint),
            ])

    def test_each_item_is_reported_in_input_order_and_isolation(self):
        d = parse(self.receipt)
        d["signature"] = ("0" if d["signature"][0] != "0" else "1") + \
            d["signature"][1:]
        bad_sig = compact(d)

        result = self.batch([
            batch_item("garbage", b"nope", self.checkpoint),
            self.good_item("good"),
            batch_item("badsig", bad_sig, self.checkpoint),
            batch_item("badcp", self.receipt, b"{}"),
            self.good_item("fine"),
            self.good_item("good-again"),
        ])
        reports = result["items"]
        self.assertEqual(
            [r["id"] for r in reports],
            ["garbage", "good", "badsig", "badcp", "fine", "good-again"],
        )
        self.assertEqual(
            [r["status"] for r in reports],
            ["invalid", "verified", "unauthenticated", "invalid",
             "verified", "verified"],
        )
        # A ring missing the checkpoint's issuer makes every receipt in
        # that batch unauthenticated, independently of neighbor items.
        ring_minus_coord = {k: v for k, v in RING.items() if k != COORD}
        isolated = self.batch([
            self.good_item("before"),
            self.good_item("after"),
        ], keyring=ring_minus_coord)
        self.assertEqual(
            [r["status"] for r in isolated["items"]],
            ["unauthenticated", "unauthenticated"],
        )
        for report in reports:
            if report["status"] == "verified":
                self.assertIsNone(report["error"])
                self.assertIsNotNone(report["result"])
            else:
                self.assertIsNone(report["result"])
                self.assertIsInstance(report["error"], str)
                self.assertNotEqual(report["error"], "")

    def test_receipts_bound_to_distinct_checkpoints_verify_together(self):
        # Both checkpoints are sealed by coord v1 but bind distinct
        # bytes; each receipt is verified against its own checkpoint.
        other = self.other_checkpoint()
        with open(self.paths["c"], "wb") as handle:
            handle.write(self.archive_bytes("c", self.cert_coord))
        other_plan = plan_chain_prune(
            [self.paths["c"]], other, self.decision, self.pol, RING,
            self.moment,
        )
        other_report = prune_chain_archives([{
            "id": "z", "path": self.paths["c"], "plan": other_plan,
            "checkpoint": other,
            "header": {"issuer": COORD, "keyVersion": 1,
                       "moment": self.moment},
        }], RING)[0]
        self.assertIsNone(other_report["error"], other_report["error"])
        result = self.batch([
            batch_item("one", self.receipt, self.checkpoint),
            batch_item("two", other_report["receipt"], other),
        ])
        self.assertEqual(
            [r["status"] for r in result["items"]], ["verified", "verified"]
        )
        self.assertEqual(
            result["items"][1]["result"]["checkpoint"], sha256(other)
        )

    def test_batch_error_text_matches_single_entry(self):
        raw = self.receipt + b"\n"
        with self.assertRaises(InvalidPruneReceiptError) as caught:
            verify_prune_receipt(raw, self.checkpoint, RING, self.moment)
        report = self.batch([batch_item("x", raw, self.checkpoint)])[
            "items"
        ][0]
        self.assertEqual(report["status"], "invalid")
        self.assertEqual(report["error"], str(caught.exception))

    def test_repeated_calls_are_equal_and_independent(self):
        items = [self.good_item("a"), self.good_item("b")]
        first = self.batch(items)
        second = self.batch(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        for left, right in zip(first["items"], second["items"]):
            self.assertIsNot(left, right)
            self.assertIsNot(left["result"], right["result"])

    def test_no_input_is_modified(self):
        items = [self.good_item()]
        items_copy = copy.deepcopy(items)
        ring_copy = copy.deepcopy(RING)
        cp_copy = self.checkpoint
        self.batch(items)
        self.assertEqual(items, items_copy)
        self.assertEqual(RING, ring_copy)
        self.assertEqual(self.checkpoint, cp_copy)

    def test_no_file_is_read_or_written(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            result = self.batch([
                self.good_item(),
                batch_item("bad", b"nope", self.checkpoint),
            ])
        self.assertEqual(
            [r["status"] for r in result["items"]],
            ["verified", "invalid"],
        )


if __name__ == "__main__":
    unittest.main()
