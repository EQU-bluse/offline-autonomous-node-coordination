"""Equivalence regression tests for the refactored final fork decision
aggregate chain fork decision batch/aggregate boundary.

These tests pin the *public* behavior shared by the three entry points --
:func:`verify_final_fork_decision_aggregate_chain_fork_decisions`,
:func:`aggregate_final_fork_decision_aggregate_chain_fork_decisions` and
:func:`verify_final_fork_decision_aggregate_chain_fork_decision_aggregate`
-- across the dimensions the internal refactor had to preserve:

* success: byte-identical canonical packets and HMACs across repeated
  calls, batch item results equal to the single-decision entry, and the
  empty fork declaration of a fork-free consensus;
* isolation: one bad item never blocks or alters another item, in input
  order, and batch-level container, type, duplicate-id, policy or moment
  faults raise before any item is processed;
* votes: same-site duplicate and contradiction markings, cross-site
  declaration conflicts with no majority override and threshold
  shortfalls that keep the common declaration;
* credentials: key rotation keeps working at the rotated version while
  unknown, revoked, not-yet-valid and expired keys are authentication
  faults (batch items) or reject just one row (aggregation);
* tampering: every rebound policy digest, row ordering, input digest,
  tally or declaration field is rejected by the offline review with the
  dedicated error class, and a bare signature fault stays an
  authentication fault;

plus input immutability, the purely offline guarantee and
equal-but-deep-independent results.
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
    InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
    InvalidFinalForkDecisionAggregateChainForkDecisionError,
    SECRET,
    _prune_compact,
    _usable_checkpoint_key,
    _validated_keyring,
    aggregate_final_fork_decision_aggregate_chain_fork_decisions,
    verify_final_fork_decision_aggregate_chain_fork_decision,
    verify_final_fork_decision_aggregate_chain_fork_decision_aggregate,
    verify_final_fork_decision_aggregate_chain_fork_decisions,
)

from test_final_fork_decision_aggregate_chain_fork_decision_aggregates import (
    FinalForkDecisionAggregateChainForkDecisionFixtures,
    JUDGE_B,
    compact,
    parse,
)
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import entry
from test_prune_attestations import JUDGE, SITE_A

DIGEST_FIELDS = (
    "prunePolicyDigest",
    "authorizationPolicyDigest",
    "sitePolicyDigest",
    "signerSitePolicyDigest",
    "adjudicationSitePolicyDigest",
    "proofSitePolicyDigest",
    "decisionSitePolicyDigest",
)


class BatchEquivalenceTest(
    FinalForkDecisionAggregateChainForkDecisionFixtures, unittest.TestCase
):
    """The batch verifier reports each decision in input order and in
    isolation, through the exact single-decision rules."""

    def test_verified_items_match_the_single_entry(self):
        items = self.fdecision_items()
        report = self.cfd_batch_report(list(reversed(items)))
        self.assertEqual([i["id"] for i in report["items"]], ["two", "one"])
        for item, source in zip(report["items"], reversed(items)):
            self.assertEqual(item["status"], "verified")
            self.assertIsNone(item["error"])
            self.assertEqual(
                item["result"],
                verify_final_fork_decision_aggregate_chain_fork_decision(
                    source["decision"], self.policy, self.auth, self.ssp,
                    self.fsignerp, self.adjp, self.proofp, self.ring,
                    self.m))

    def test_repeated_reports_are_equal_and_deeply_independent(self):
        first = self.cfd_batch_report(self.fdecision_items())
        second = self.cfd_batch_report(self.fdecision_items())
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["items"][0]["result"]["common"].append("tampered")
        again = self.cfd_batch_report(self.fdecision_items())
        self.assertEqual(again, second)

    def test_one_bad_item_never_blocks_or_alters_another(self):
        tampered = parse(self.decision_ja)
        tampered["payload"]["proofs"] = list(
            reversed(tampered["payload"]["proofs"]))
        report = self.cfd_batch_report([
            decision_item("garbage", b"not a packet"),
            decision_item("ok", self.decision_jb),
            decision_item("rebound", self.rewrap(tampered["payload"])),
        ])
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["invalid-decision", "verified", "invalid-decision"])
        for item in report["items"]:
            if item["status"] == "verified":
                self.assertIsNone(item["error"])
                self.assertEqual(item["result"]["issuer"], JUDGE_B)
            else:
                self.assertTrue(item["error"])
                self.assertIsNone(item["result"])

    def test_empty_fork_declaration_verifies(self):
        report = self.cfd_batch_report([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb),
        ])
        for item in report["items"]:
            self.assertEqual(item["status"], "verified")
            self.assertEqual(item["result"]["status"], "accepted")
            self.assertEqual(item["result"]["common"], [])

    def test_batch_faults_raise_before_any_item_is_parsed(self):
        # A garbage decision that would be an item-level
        # ``invalid-decision`` report never gets that far when the batch
        # itself is faulty.
        garbage = decision_item("one", b"not a packet")
        with self.assertRaises(ValueError):
            self.cfd_batch_report([garbage, dict(garbage)])
        with self.assertRaises(ValueError):
            self.cfd_batch_report([garbage], proofp={
                "sites": {}, "threshold": 1})
        with self.assertRaises(ValueError):
            self.cfd_batch_report([garbage], moment=-1)
        with self.assertRaises(TypeError):
            self.cfd_batch_report([garbage], moment=True)
        with self.assertRaises(TypeError):
            self.cfd_batch_report((garbage,))
        with self.assertRaises(TypeError):
            self.cfd_batch_report([{"id": "one", "decision": "str"}])

    def test_key_rotation_and_invalidation(self):
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = [
            rotated[JUDGE][0], entry(2, "22" * 32)]
        decision_v2 = self.ffdacf_judge(
            self.fork_proof_items, issuer=JUDGE, version=2, ring=rotated)
        item = self.cfd_batch_report(
            [decision_item("one", decision_v2)], ring=rotated)["items"][0]
        self.assertEqual(item["status"], "verified")
        self.assertEqual(item["result"]["keyVersion"], 2)
        # The pre-rotation keyring does not know version 2.
        item = self.cfd_batch_report(
            [decision_item("one", decision_v2)])["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        # A revoked, not-yet-valid or expired rotated key rejects too.
        for changes in (
            {"revoked": True},
            {"not_before": self.m + 1},
            {"not_after": self.m - 1},
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = [
                ring[JUDGE][0], entry(2, "22" * 32, **changes)]
            item = self.cfd_batch_report(
                [decision_item("one", decision_v2)], ring=ring)["items"][0]
            self.assertEqual(item["status"], "unauthenticated", changes)
            self.assertIsNone(item["result"])

    def test_inputs_are_never_modified_and_no_file_is_read(self):
        items = self.fdecision_items()
        snapshot = copy.deepcopy(items)
        materials = [self.policy, self.auth, self.ssp, self.fsignerp,
                     self.adjp, self.proofp, self.ring]
        materials_snapshot = copy.deepcopy(materials)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file access")):
            self.cfd_batch_report(items)
        self.assertEqual(items, snapshot)
        self.assertEqual(materials, materials_snapshot)


class AggregateEquivalenceTest(
    FinalForkDecisionAggregateChainForkDecisionFixtures, unittest.TestCase
):
    """The cross-site aggregate seals the same votes byte-for-byte."""

    def test_sealing_is_byte_for_byte_deterministic(self):
        first = self.cfd_make_aggregate(self.fdecision_items())
        second = self.cfd_make_aggregate(self.fdecision_items())
        self.assertEqual(first, second)
        self.assertEqual(compact(parse(first)), first)
        self.assertFalse(first.endswith(b"\n"))
        # The bound HMAC is recomputed independently from the payload.
        data = parse(first)
        key = _usable_checkpoint_key(
            _validated_keyring(self.ring), JUDGE, 1, self.m)
        expected = hmac.new(
            bytes.fromhex(key[SECRET]), _prune_compact(data["payload"]),
            hashlib.sha256).hexdigest()
        self.assertEqual(data["signature"], expected)

    def test_empty_fork_declaration_is_the_fork_free_vote(self):
        raw = self.cfd_make_aggregate([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["declaration"]["common"], [])
        for row in result["items"]:
            self.assertEqual(row["declaration"]["common"], [])

    def test_same_site_duplicate_and_contradiction(self):
        raw = self.cfd_make_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.decision_ja)])
        rows = {r["id"]: r for r in self.cfd_verify_aggregate(raw)["items"]}
        self.assertEqual(rows["a"]["conclusion"], "valid")
        self.assertEqual(rows["b"]["conclusion"], "duplicate")
        self.assertEqual(rows["b"]["reason"], "duplicate")
        raw = self.cfd_make_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.free_ja)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])
        for row in result["items"]:
            self.assertEqual(row["conclusion"], "contradiction")

    def test_cross_site_disagreement_conflicts_with_no_majority_override(
            self):
        dsp3 = {"sites": {JUDGE: {1}, JUDGE_B: {1}, SITE_A: {1}},
                "threshold": 2}
        free_c = self.ffdacf_judge(self.free_proof_items, issuer=SITE_A)
        items = [
            decision_item("a", self.decision_ja),
            decision_item("b", self.decision_jb),
            decision_item("c", free_c),
        ]
        # Two agreeing fork sites against one fork-free site still
        # conflict: no majority outvotes a declaration difference.
        result = self.cfd_verify_aggregate(
            self.cfd_make_aggregate(items, dsp=dsp3), dsp=dsp3)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])

    def test_threshold_shortfall_keeps_the_common_declaration(self):
        raw = self.cfd_make_aggregate([decision_item("one", self.decision_ja)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declaration"])
        self.assertEqual(result["declaration"]["status"], "accepted")

    def test_one_bad_item_still_yields_rows_for_the_rest(self):
        raw = self.cfd_make_aggregate([
            decision_item("bad", b"not a packet"),
            decision_item("ok", self.decision_jb)])
        result = self.cfd_verify_aggregate(raw)
        rows = {r["id"]: r for r in result["items"]}
        self.assertEqual(rows["bad"]["conclusion"], "invalid")
        self.assertEqual(rows["bad"]["reason"], "invalid")
        self.assertIsNone(rows["bad"]["issuer"])
        self.assertIsNone(rows["bad"]["declaration"])
        self.assertEqual(rows["ok"]["conclusion"], "valid")
        self.assertEqual(rows["ok"]["issuer"], JUDGE_B)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declaration"])

    def test_key_rotation_and_invalidation(self):
        dsp2 = {"sites": {JUDGE: {1, 2}, JUDGE_B: {1}}, "threshold": 2}
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = [
            rotated[JUDGE][0], entry(2, "22" * 32)]
        decision_v2 = self.ffdacf_judge(
            self.fork_proof_items, issuer=JUDGE, version=2, ring=rotated)
        items = [decision_item("one", decision_v2),
                 decision_item("two", self.decision_jb)]
        raw = self.cfd_make_aggregate(items, dsp=dsp2, ring=rotated)
        result = self.cfd_verify_aggregate(raw, dsp=dsp2, ring=rotated)
        self.assertEqual(result["status"], "accepted")
        rows = {r["id"]: r for r in result["items"]}
        self.assertEqual(rows["one"]["keyVersion"], 2)
        # A revoked, not-yet-valid, expired or unknown rotated key
        # rejects just that row; the other site still votes.
        for changes in (
            {"revoked": True},
            {"not_before": self.m + 1},
            {"not_after": self.m - 1},
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = [
                ring[JUDGE][0], entry(2, "22" * 32, **changes)]
            result = self.cfd_verify_aggregate(
                self.cfd_make_aggregate(items, dsp=dsp2, ring=ring),
                dsp=dsp2, ring=ring)
            rows = {r["id"]: r for r in result["items"]}
            self.assertEqual(rows["one"]["reason"], "unauthenticated",
                             changes)
            self.assertEqual(rows["two"]["conclusion"], "valid", changes)
            self.assertEqual(result["status"], "insufficient", changes)
        # Sealed while the keyring does not know version 2 at all, the
        # row is unauthenticated the same way.
        unknown = self.cfd_verify_aggregate(
            self.cfd_make_aggregate(items, dsp=dsp2), dsp=dsp2)
        rows = {r["id"]: r for r in unknown["items"]}
        self.assertEqual(rows["one"]["reason"], "unauthenticated")

    def test_aggregate_credential_rotation_and_invalidation(self):
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = [
            rotated[JUDGE][0], entry(2, "22" * 32)]
        raw = self.cfd_make_aggregate(
            self.fdecision_items(), issuer=JUDGE, version=2, ring=rotated)
        result = self.cfd_verify_aggregate(raw, ring=rotated)
        self.assertEqual(result["keyVersion"], 2)
        self.assertEqual(result["status"], "accepted")
        # The pre-rotation keyring cannot authenticate the aggregate.
        with self.assertRaises(AuthenticationError):
            self.cfd_verify_aggregate(raw)
        # A revoked, not-yet-valid or expired aggregate key rejects both
        # sealing and verification.
        for changes in (
            {"revoked": True},
            {"not_before": self.m + 1},
            {"not_after": self.m - 1},
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = [
                ring[JUDGE][0], entry(2, "22" * 32, **changes)]
            with self.assertRaises(AuthenticationError):
                self.cfd_make_aggregate(
                    self.fdecision_items(), issuer=JUDGE, version=2,
                    ring=ring)
            with self.assertRaises(AuthenticationError):
                self.cfd_verify_aggregate(raw, ring=ring)

    def test_aggregate_faults_raise_before_any_item_is_parsed(self):
        garbage = decision_item("one", b"not a packet")
        with self.assertRaises(ValueError):
            self.cfd_make_aggregate([garbage, dict(garbage)])
        with self.assertRaises(ValueError):
            self.cfd_make_aggregate(
                [garbage], dsp={"sites": {}, "threshold": 1})
        with self.assertRaises(ValueError):
            self.cfd_make_aggregate([garbage], moment=-1)
        with self.assertRaises(TypeError):
            self.cfd_make_aggregate([garbage], moment=True)
        with self.assertRaises(TypeError):
            self.cfd_make_aggregate((garbage,))
        with self.assertRaises(TypeError):
            self.cfd_make_aggregate(self.fdecision_items(), version=True)
        with self.assertRaises(ValueError):
            self.cfd_make_aggregate(self.fdecision_items(), issuer="")

    def test_inputs_are_never_modified_and_no_file_is_read(self):
        items = self.fdecision_items()
        snapshot = copy.deepcopy(items)
        materials = [self.policy, self.auth, self.ssp, self.fsignerp,
                     self.adjp, self.proofp, self.dsp, self.ring]
        materials_snapshot = copy.deepcopy(materials)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file access")):
            raw = self.cfd_make_aggregate(items)
            self.cfd_verify_aggregate(raw)
        self.assertEqual(items, snapshot)
        self.assertEqual(materials, materials_snapshot)


class AggregateVerifyTamperTest(
    FinalForkDecisionAggregateChainForkDecisionFixtures, unittest.TestCase
):
    """The offline review recomputes every binding and never trusts the
    packet's self-reported tally."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.cfd_make_aggregate(self.fdecision_items())

    def tampered(self, mutate):
        payload = parse(self.raw)["payload"]
        mutate(payload)
        return self.rewrap(payload)

    def test_each_policy_digest_tamper_is_rejected(self):
        for field in DIGEST_FIELDS:
            self.assert_invalid(
                self.tampered(lambda p, f=field: p.__setitem__(f, "9" * 64)))

    def test_row_order_tamper_is_rejected(self):
        self.assert_invalid(self.tampered(
            lambda p: p.__setitem__("items", list(reversed(p["items"])))))

    def test_input_digest_tamper_is_rejected(self):
        self.assert_invalid(self.tampered(
            lambda p: p.__setitem__("inputs", ["8" * 64] + p["inputs"][1:])))

    def test_row_conclusion_tamper_is_rejected(self):
        def mutate(payload):
            payload["items"][0]["conclusion"] = "duplicate"
            payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid(self.tampered(mutate))

    def test_status_and_declaration_tamper_are_rejected(self):
        self.assert_invalid(self.tampered(
            lambda p: p.__setitem__("status", "insufficient")))
        self.assert_invalid(self.tampered(
            lambda p: p.__setitem__("declaration", None)))

    def test_declaration_ordering_tamper_is_rejected(self):
        def reorder_conclusions(payload):
            conclusions = payload["declaration"]["conclusions"]
            payload["declaration"]["conclusions"] = list(
                reversed(conclusions))
        self.assert_invalid(self.tampered(reorder_conclusions))

        def reorder_proofs(payload):
            declaration = payload["items"][0]["declaration"]
            declaration["proofs"] = list(reversed(declaration["proofs"]))
        self.assert_invalid(self.tampered(reorder_proofs))

    def test_bare_signature_fault_is_authentication_error(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.cfd_verify_aggregate(compact(data))

    def test_result_is_the_authenticated_payload_plus_the_digest(self):
        result = self.cfd_verify_aggregate(self.raw)
        payload = parse(self.raw)["payload"]
        self.assertEqual(
            result["aggregateDigest"], hashlib.sha256(self.raw).hexdigest())
        for key, value in payload.items():
            self.assertEqual(result[key], value, key)
        self.assertEqual(
            set(result) - set(payload), {"aggregateDigest"})

    def test_results_are_equal_but_deeply_independent(self):
        first = self.cfd_verify_aggregate(self.raw)
        second = self.cfd_verify_aggregate(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["items"][0]["declaration"]["conclusions"].append("tampered")
        first["declaration"]["common"].append("tampered")
        self.assertEqual(self.cfd_verify_aggregate(self.raw), second)

    def test_aggregate_bytes_are_never_modified(self):
        snapshot = bytes(self.raw)
        materials = [self.policy, self.auth, self.ssp, self.fsignerp,
                     self.adjp, self.proofp, self.dsp, self.ring]
        materials_snapshot = copy.deepcopy(materials)
        self.cfd_verify_aggregate(self.raw)
        self.assertEqual(self.raw, snapshot)
        self.assertEqual(materials, materials_snapshot)


class ErrorTaxonomyTest(
    FinalForkDecisionAggregateChainForkDecisionFixtures, unittest.TestCase
):
    def test_bool_never_poses_as_an_int_on_any_entry(self):
        with self.assertRaises(TypeError):
            self.cfd_batch_report(self.fdecision_items(), moment=True)
        with self.assertRaises(TypeError):
            self.cfd_make_aggregate(self.fdecision_items(), moment=True)
        with self.assertRaises(TypeError):
            self.cfd_make_aggregate(self.fdecision_items(), version=True)
        with self.assertRaises(TypeError):
            self.cfd_verify_aggregate(
                self.cfd_make_aggregate(self.fdecision_items()), moment=True)

    def test_item_faults_stay_item_statuses_never_exceptions(self):
        # Structural and authentication faults of one decision are item
        # statuses; only batch-level faults raise.
        wrong_ring = copy.deepcopy(self.ring)
        wrong_ring[JUDGE] = [
            dict(wrong_ring[JUDGE][0], secret="00" * 32)]
        report = self.cfd_batch_report(
            [decision_item("one", self.decision_ja),
             decision_item("two", b"{")], ring=wrong_ring)
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["unauthenticated", "invalid-decision"])

    def test_the_error_families_are_distinct(self):
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
            ValueError))
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateChainForkDecisionError,
            ValueError))
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
            InvalidFinalForkDecisionAggregateChainForkDecisionError)
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        self.assertIsNot(AuthenticationError,
                         InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError)

    def test_public_names_still_import_from_the_package(self):
        import offline_coordination.replication as replication
        self.assertIs(
            replication.verify_final_fork_decision_aggregate_chain_fork_decisions,
            verify_final_fork_decision_aggregate_chain_fork_decisions)
        self.assertIs(
            replication.aggregate_final_fork_decision_aggregate_chain_fork_decisions,
            aggregate_final_fork_decision_aggregate_chain_fork_decisions)
        self.assertIs(
            replication.verify_final_fork_decision_aggregate_chain_fork_decision_aggregate,
            verify_final_fork_decision_aggregate_chain_fork_decision_aggregate)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
