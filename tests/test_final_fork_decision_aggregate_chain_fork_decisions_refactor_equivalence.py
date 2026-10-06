"""Equivalence regression tests for the refactored final fork decision
aggregate chain fork decision batch/aggregate boundary.

These tests pin the *public* behavior of the three entry points whose
internals were consolidated onto shared components --
:func:`verify_final_fork_decision_aggregate_chain_fork_decisions`,
:func:`aggregate_final_fork_decision_aggregate_chain_fork_decisions` and
:func:`verify_final_fork_decision_aggregate_chain_fork_decision_aggregate`
-- across the dimensions the refactor had to preserve:

* determinism: identical canonical UTF-8 bytes and HMAC across repeated
  aggregate seals, and batch reports equal (but deeply independent)
  across repeated runs, with every verified batch row equal to the
  single-decision entry point's result;
* isolation: one garbage, tampered or unauthenticated decision never
  blocks or alters the report of a later one, in input order;
* declarations: the empty fork edge set of a fork-free consensus, the
  same-site duplicate/contradiction markings, the cross-site complete
  declaration agreement with no majority override and the threshold
  outcome with the common declaration kept on insufficient tallies;
* credentials: key rotation keeps working at the new version while
  revoked, not-yet-valid and expired keys fail closed, both for the
  decisions inside an aggregate and for the aggregate's own signature;
* tampering: every one of the seven policy digest bindings, the input
  digest vector, the row ordering, the tallied status and the counted
  declarations is recomputed, never trusted from the packet;

plus the batch-level TypeError/ValueError taxonomy that must raise
before any single decision is examined, input immutability and the
purely offline guarantee.
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
    SECRET,
    _prune_compact,
    _usable_checkpoint_key,
    _validated_keyring,
    verify_final_fork_decision_aggregate_chain_fork_decision,
)

from test_final_fork_decision_aggregate_chain_fork_decision_aggregates import (
    FinalForkDecisionAggregateChainForkDecisionFixtures,
    parse,
)
from test_adjudicate_prune_aggregate_forks import proof_item
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import entry
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C

JUDGE_B = SITE_C
SECRET_V2_A = "22" * 32
SECRET_V2_B = "33" * 32

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
    """The batch report is the single-decision ruling, per item, in
    input order, with total isolation between items."""

    def test_verified_rows_equal_the_single_entry_results(self):
        report = self.cfd_batch_report(self.fdecision_items())
        for item, decision in zip(
            report["items"], (self.decision_ja, self.decision_jb)
        ):
            self.assertEqual(item["status"], "verified")
            self.assertEqual(
                item["result"],
                verify_final_fork_decision_aggregate_chain_fork_decision(
                    decision, self.policy, self.auth, self.ssp,
                    self.fsignerp, self.adjp, self.proofp, self.ring,
                    self.m))

    def test_reports_are_equal_but_deeply_independent(self):
        first = self.cfd_batch_report(self.fdecision_items())
        second = self.cfd_batch_report(self.fdecision_items())
        self.assertEqual(first, second)
        first["items"][0]["result"]["items"][0]["conclusion"] = "x"
        again = self.cfd_batch_report(self.fdecision_items())
        self.assertEqual(again, second)
        self.assertEqual(
            again["items"][0]["result"]["items"][0]["conclusion"],
            "valid")

    def test_one_bad_item_never_blocks_or_alters_later_items(self):
        tampered = parse(self.decision_ja)["payload"]
        tampered["status"] = "insufficient"
        items = [
            decision_item("garbage", b"{"),
            decision_item("tampered", self.rewrap(tampered)),
            decision_item("ok", self.decision_jb),
        ]
        report = self.cfd_batch_report(items)
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["invalid-decision", "invalid-decision", "verified"])
        self.assertEqual([i["id"] for i in report["items"]],
                         ["garbage", "tampered", "ok"])
        self.assertIsNone(report["items"][0]["result"])
        self.assertIsNone(report["items"][1]["result"])
        self.assertEqual(
            report["items"][2]["result"],
            verify_final_fork_decision_aggregate_chain_fork_decision(
                self.decision_jb, self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.proofp, self.ring, self.m))

    def test_one_sites_revocation_isolates_to_its_own_items(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        report = self.cfd_batch_report(self.fdecision_items(), ring=revoked)
        first, second = report["items"]
        self.assertEqual(first["status"], "unauthenticated")
        self.assertIn("revoked", first["error"])
        self.assertIsNone(first["result"])
        self.assertEqual(second["status"], "verified")
        self.assertEqual(second["result"]["issuer"], JUDGE_B)

    def test_fork_free_decisions_verify_with_empty_common(self):
        report = self.cfd_batch_report([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb)])
        for item in report["items"]:
            self.assertEqual(item["status"], "verified")
            self.assertEqual(item["result"]["common"], [])
            self.assertEqual(item["result"]["status"], "accepted")

    def test_rotated_key_verifies_and_expired_key_fails_closed(self):
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = rotated[JUDGE] + [entry(2, SECRET_V2_A)]
        decision_v2 = self.ffdacf_judge(
            self.fork_proof_items, ring=rotated, issuer=JUDGE, version=2)
        report = self.cfd_batch_report(
            [decision_item("v2", decision_v2)], ring=rotated)
        self.assertEqual(report["items"][0]["status"], "verified")
        self.assertEqual(report["items"][0]["result"]["keyVersion"], 2)
        for broken in (
            [entry(2, SECRET_V2_A, revoked=True)],
            [entry(2, SECRET_V2_A, not_before=self.m + 1)],
            [entry(2, SECRET_V2_A, not_after=self.m - 1)],
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = broken
            item = self.cfd_batch_report(
                [decision_item("v2", decision_v2)], ring=ring)["items"][0]
            self.assertEqual(item["status"], "unauthenticated", broken)
            self.assertIsNone(item["result"])

    def test_batch_level_faults_raise_before_any_item_is_examined(self):
        # Every decision below is garbage that item processing would
        # report as invalid-decision; the batch-level fault must win.
        garbage = decision_item("one", b"{")
        with self.assertRaises(TypeError):
            self.cfd_batch_report((garbage,))
        with self.assertRaises(ValueError):
            self.cfd_batch_report([])
        with self.assertRaises(TypeError):
            self.cfd_batch_report([{"id": 1, "decision": b"{"}])
        with self.assertRaises(ValueError):
            self.cfd_batch_report([
                garbage, decision_item("one", b"{")])
        with self.assertRaises(ValueError):
            self.cfd_batch_report(
                [{"id": "one", "decision": b"{", "extra": 1}])
        with self.assertRaises(TypeError):
            self.cfd_batch_report([garbage], moment=True)
        with self.assertRaises(ValueError):
            self.cfd_batch_report([garbage], moment=-1)
        with self.assertRaises(ValueError):
            self.cfd_batch_report(
                [garbage], proofp={"sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.cfd_batch_report([garbage], ring={"x": "nope"})

    def test_inputs_are_never_modified_and_no_file_is_touched(self):
        items = self.fdecision_items()
        snapshot = copy.deepcopy(
            (items, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.proofp, self.ring))
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.cfd_batch_report(items)
        self.assertEqual(
            (items, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.proofp, self.ring), snapshot)


class AggregateEquivalenceTest(
    FinalForkDecisionAggregateChainForkDecisionFixtures, unittest.TestCase
):
    """The cross-site aggregate seals one canonical packet whose rows,
    tally and declaration are recomputed from the decisions alone."""

    def test_sealing_is_byte_for_byte_deterministic(self):
        first = self.cfd_make_aggregate(self.fdecision_items())
        second = self.cfd_make_aggregate(self.fdecision_items())
        self.assertEqual(first, second)
        self.assertEqual(_prune_compact(parse(first)), first)

    def test_signature_covers_the_canonical_payload(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        data = parse(raw)
        key = _usable_checkpoint_key(
            _validated_keyring(self.ring), JUDGE, 1, self.m)
        expected = hmac.new(
            bytes.fromhex(key[SECRET]), _prune_compact(data["payload"]),
            hashlib.sha256).hexdigest()
        self.assertEqual(data["signature"], expected)

    def test_row_declaration_matches_the_single_entry_result(self):
        raw = self.cfd_make_aggregate(
            [decision_item("one", self.decision_ja)])
        row = parse(raw)["payload"]["items"][0]
        result = verify_final_fork_decision_aggregate_chain_fork_decision(
            self.decision_ja, self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, self.proofp, self.ring, self.m)
        declaration = row["declaration"]
        self.assertEqual(declaration["common"], result["common"])
        self.assertEqual(declaration["proofs"], result["proofs"])
        self.assertEqual(declaration["status"], result["status"])
        for conclusion, item in zip(
            declaration["conclusions"], result["items"]
        ):
            self.assertEqual(conclusion["conclusion"], item["conclusion"])
            self.assertEqual(conclusion["digest"], item["digest"])
            self.assertEqual(conclusion["edges"], item["edges"])
            self.assertEqual(conclusion["id"], item["id"])
            self.assertEqual(conclusion["reason"], item["reason"])
            self.assertEqual(conclusion["issuer"], item["issuer"])

    def test_fork_free_consensus_binds_the_empty_common_set(self):
        raw = self.cfd_make_aggregate([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["declaration"]["common"], [])
        self.assertEqual(result["declaration"]["status"], "accepted")

    def test_same_site_repeat_is_duplicate_and_difference_contradicts(
            self):
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
        raw = self.cfd_make_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.decision_jb),
            decision_item("c", free_c)], dsp=dsp3)
        result = self.cfd_verify_aggregate(raw, dsp=dsp3)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])

    def test_threshold_shortfall_keeps_the_common_declaration(self):
        raw = self.cfd_make_aggregate(
            [decision_item("one", self.decision_ja)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declaration"])
        raw = self.cfd_make_aggregate([decision_item("bad", b"{}")])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["declaration"])

    def test_one_bad_item_never_blocks_the_other_votes(self):
        raw = self.cfd_make_aggregate([
            decision_item("bad", b"{"),
            decision_item("one", self.decision_ja),
            decision_item("two", self.decision_jb)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "accepted")
        rows = {r["id"]: r for r in result["items"]}
        self.assertEqual(rows["bad"]["conclusion"], "invalid")
        self.assertEqual(rows["bad"]["reason"], "invalid")
        self.assertIsNone(rows["bad"]["issuer"])
        self.assertEqual(rows["one"]["conclusion"], "valid")
        self.assertEqual(rows["two"]["conclusion"], "valid")

    def test_rotated_keys_aggregate_and_expire_closed(self):
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = rotated[JUDGE] + [entry(2, SECRET_V2_A)]
        rotated[JUDGE_B] = rotated[JUDGE_B] + [entry(2, SECRET_V2_B)]
        dsp2 = {"sites": {JUDGE: {2}, JUDGE_B: {2}}, "threshold": 2}
        items = [
            decision_item("one", self.ffdacf_judge(
                self.fork_proof_items, ring=rotated, issuer=JUDGE,
                version=2)),
            decision_item("two", self.ffdacf_judge(
                self.fork_proof_items, ring=rotated, issuer=JUDGE_B,
                version=2)),
        ]
        raw = self.cfd_make_aggregate(
            items, dsp=dsp2, ring=rotated, issuer=JUDGE, version=2)
        result = self.cfd_verify_aggregate(raw, dsp=dsp2, ring=rotated)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["keyVersion"], 2)
        for broken in (
            [entry(2, SECRET_V2_A, revoked=True)],
            [entry(2, SECRET_V2_A, not_before=self.m + 1)],
            [entry(2, SECRET_V2_A, not_after=self.m - 1)],
        ):
            # The decision key must already be unusable when the
            # aggregate is sealed: the row is rejected there and then.
            ring = copy.deepcopy(rotated)
            ring[JUDGE] = broken
            raw = self.cfd_make_aggregate(
                items, dsp=dsp2, ring=ring, issuer=JUDGE_B, version=2)
            rows = {
                r["id"]: r
                for r in self.cfd_verify_aggregate(
                    raw, dsp=dsp2, ring=ring)["items"]
            }
            self.assertEqual(
                rows["one"]["reason"], "unauthenticated", broken)
            self.assertEqual(rows["one"]["issuer"], JUDGE)
            self.assertEqual(rows["two"]["conclusion"], "valid")

    def test_aggregate_signing_credentials_have_no_fallback(self):
        items = self.fdecision_items()
        with self.assertRaises(AuthenticationError):
            self.cfd_make_aggregate(items, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.cfd_make_aggregate(items, issuer=JUDGE, version=2)
        for broken in (
            [entry(1, "11" * 32, revoked=True)],
            [entry(1, "11" * 32, not_before=self.m + 1)],
            [entry(1, "11" * 32, not_after=self.m - 1)],
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = broken
            with self.assertRaises(AuthenticationError):
                self.cfd_make_aggregate(items, ring=ring)

    def test_inputs_are_never_modified_and_no_file_is_touched(self):
        items = self.fdecision_items()
        snapshot = copy.deepcopy(
            (items, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.proofp, self.dsp, self.ring))
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.cfd_make_aggregate(items)
        self.assertEqual(
            (items, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.proofp, self.dsp, self.ring), snapshot)


class AggregateVerifyEquivalenceTest(
    FinalForkDecisionAggregateChainForkDecisionFixtures,
    unittest.TestCase
):
    """The offline aggregate review recomputes every binding and never
    trusts the packet's self-reported tally."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.cfd_make_aggregate(self.fdecision_items())

    def test_result_is_the_authenticated_payload_plus_digest(self):
        result = self.cfd_verify_aggregate(self.raw)
        payload = parse(self.raw)["payload"]
        self.assertEqual(result["aggregateDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        for key in payload:
            self.assertEqual(result[key], payload[key], key)

    def test_results_are_equal_but_deeply_independent(self):
        first = self.cfd_verify_aggregate(self.raw)
        second = self.cfd_verify_aggregate(self.raw)
        self.assertEqual(first, second)
        first["items"][0]["declaration"]["common"].append("x")
        first["declaration"]["status"] = "x"
        again = self.cfd_verify_aggregate(self.raw)
        self.assertEqual(again, second)

    def test_every_policy_digest_binding_is_recomputed(self):
        for field in DIGEST_FIELDS:
            payload = parse(self.raw)["payload"]
            payload[field] = "9" * 64
            self.assert_invalid(self.rewrap(payload), )

    def test_self_reported_tally_is_never_trusted(self):
        payload = parse(self.raw)["payload"]
        payload["status"] = "insufficient"
        self.assert_invalid(self.rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["declaration"]["status"] = "insufficient"
        self.assert_invalid(self.rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["items"][0]["conclusion"] = "duplicate"
        payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid(self.rewrap(payload))
        # A single-site tally may not be upgraded to accepted either.
        single = self.cfd_make_aggregate(
            [decision_item("one", self.decision_ja)])
        payload = parse(single)["payload"]
        payload["status"] = "accepted"
        self.assert_invalid(self.rewrap(payload))

    def test_ordering_and_input_bindings_are_recomputed(self):
        payload = parse(self.raw)["payload"]
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(self.rewrap(payload))
        # The inputs vector is bound to the per-item digests; a foreign
        # digest breaks the binding.  (The offline review binds the
        # digest set covered by the rows, so the sealer's input order is
        # a commitment only the byte digest of the packet itself pins.)
        payload = parse(self.raw)["payload"]
        payload["inputs"][0] = "ab" * 32
        self.assert_invalid(self.rewrap(payload))

    def test_counted_declaration_vectors_are_recomputed(self):
        payload = parse(self.raw)["payload"]
        declaration = payload["items"][0]["declaration"]
        declaration["proofs"] = list(reversed(declaration["proofs"]))
        self.assert_invalid(self.rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["declaration"]["common"] = []
        self.assert_invalid(self.rewrap(payload))

    def test_aggregate_credentials_are_checked_at_the_verify_moment(self):
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = rotated[JUDGE] + [entry(2, SECRET_V2_A)]
        raw = self.cfd_make_aggregate(
            self.fdecision_items(), ring=rotated, issuer=JUDGE, version=2)
        result = self.cfd_verify_aggregate(raw, ring=rotated)
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["keyVersion"], 2)
        for broken in (
            [entry(2, SECRET_V2_A, revoked=True)],
            [entry(2, SECRET_V2_A, not_before=self.m + 1)],
            [entry(2, SECRET_V2_A, not_after=self.m - 1)],
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = broken
            with self.assertRaises(AuthenticationError):
                self.cfd_verify_aggregate(raw, ring=ring)
        tampered = parse(self.raw)
        tampered["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.cfd_verify_aggregate(_prune_compact(tampered))

    def test_encoding_and_type_faults_keep_their_classification(self):
        with self.assertRaises(TypeError):
            self.cfd_verify_aggregate("bytes")
        with self.assertRaises(TypeError):
            self.cfd_verify_aggregate(
                _prune_compact({"payload": [], "signature": "0" * 64}))
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(self.raw.replace(b":", b": ", 1))
        self.assert_invalid(b"")
        with self.assertRaises(ValueError):
            self.cfd_verify_aggregate(self.raw, moment=-1)
        with self.assertRaises(TypeError):
            self.cfd_verify_aggregate(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.cfd_verify_aggregate(
                self.raw, dsp={"sites": {}, "threshold": 1})

    def test_error_class_stays_distinct(self):
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
            ValueError))
        try:
            self.cfd_verify_aggregate(self.raw + b"\n")
        except ValueError as exc:
            self.assertIsInstance(
                exc,
                InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError)
        else:
            self.fail("a trailing byte must raise")

    def test_inputs_are_never_modified_and_no_file_is_touched(self):
        snapshot = copy.deepcopy(
            (self.raw, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.proofp, self.dsp, self.ring))
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.cfd_verify_aggregate(self.raw)
        self.assertEqual(
            (self.raw, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.proofp, self.dsp, self.ring), snapshot)


if __name__ == "__main__":
    unittest.main()
