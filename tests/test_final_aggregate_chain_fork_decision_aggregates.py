"""Tests for batch verification and cross-site aggregation of final
aggregate chain fork decisions.

Covers :func:`verify_final_aggregate_chain_fork_decisions`,
:func:`aggregate_final_aggregate_chain_fork_decisions` and
:func:`verify_final_aggregate_chain_fork_decision_aggregate`: the
decision batch container and six shared materials validated in full
before any decision is parsed, the per-decision
verified/invalid-decision/unauthenticated taxonomy with input-order
reports and no cross-decision interference, the
verify-then-authenticate-then-authorize per-decision aggregation
pipeline with its fixed invalid/unauthenticated/unauthorized reasons,
same-site duplicate/contradiction handling over the complete
declaration (the common fork edge set, empty for a fork-free decision,
the per-item conclusions sorted by site then id, the term-by-term proof
digest vector and the overall status), cross-site declaration
agreement with no majority override, threshold acceptance with the
common declaration kept on insufficient tallies, the canonical signed
aggregate packet and its six policy digest bindings, the offline
re-tally verification recomputing every binding plus each counted
declaration, the aggregate credential rules, the distinct error
hierarchy, equal-but-independent results, input immutability and the
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
    InvalidFinalAggregateChainForkDecisionAggregateError,
    InvalidFinalAggregateChainForkDecisionError,
    SECRET,
    adjudicate_final_aggregate_chain_forks,
    aggregate_final_aggregate_chain_fork_decisions,
    sign_final_aggregate_chain_fork_proof,
    verify_final_aggregate_chain_fork_decision,
    verify_final_aggregate_chain_fork_decisions,
    verify_final_aggregate_chain_fork_decision_aggregate,
    _prune_batch_site_policy_bytes,
    _prune_compact,
    _usable_checkpoint_key,
    _validated_keyring,
    _verdict_policy_bytes,
)

from test_supersede_final_aggregate import FinalAggregateChainFixtures
from test_aggregate_prune_fork_decisions import decision_item
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C

JUDGE_B = SITE_C
BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
AGGREGATE_KEYS = ["payload", "signature"]
AGGREGATE_PAYLOAD_KEYS = [
    "adjudicationSitePolicyDigest", "authorizationPolicyDigest",
    "decisionSitePolicyDigest", "declaration", "inputs", "issuer",
    "items", "keyVersion", "prunePolicyDigest", "signerSitePolicyDigest",
    "sitePolicyDigest", "status", "version",
]
AGGREGATE_ROW_KEYS = [
    "conclusion", "declaration", "digest", "id", "issuer", "keyVersion",
    "reason",
]
DECLARATION_KEYS = ["common", "conclusions", "proofs", "status"]
AGGREGATE_RESULT_KEYS = [
    "aggregateDigest", "inputs", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "authorizationPolicyDigest", "sitePolicyDigest",
    "signerSitePolicyDigest", "adjudicationSitePolicyDigest",
    "decisionSitePolicyDigest", "declaration", "status", "version",
]
SINGLE_RESULT_KEYS = [
    "common", "proofDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "proofs", "authorizationPolicyDigest",
    "sitePolicyDigest", "signerSitePolicyDigest",
    "adjudicationSitePolicyDigest", "status", "version",
]


def compact(obj):
    """One canonical compact envelope, matching the production encoding."""
    return _prune_compact(obj)


def parse(raw):
    return json.loads(raw.decode("utf-8"))


class FinalFinalFixtures(FinalAggregateChainFixtures):
    """Signed final-layer decisions from two decision sites."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # The invariant fork-proof signer site policy digested inside
        # each final proof (distinct from the adjudication signer site
        # policy of the lower aggregate-decision layer).
        self.fsignerp = {
            "sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 2}
        # The invariant issuing/adjudication site policy authorizing the
        # exact proof signer identity and key version inside a decision.
        self.adjp = {
            "sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
            "threshold": 2}
        # The decision site policy authorizes the decision sites.
        self.dsp = {"sites": {JUDGE: {1}, JUDGE_B: {1}}, "threshold": 2}
        self.ffork_proofs = [
            {"id": "x", "proof": self.facf_proof(self.fork_items, SITE_A)},
            {"id": "y", "proof": self.facf_proof(self.fork_items, SITE_B)},
        ]
        self.ffree_proofs = [
            {"id": "x",
             "proof": self.facf_proof(self.clean_items, SITE_A)},
            {"id": "y",
             "proof": self.facf_proof(self.clean_items, SITE_B)},
        ]
        self.decision_ja = self.facf_decision(self.ffork_proofs, JUDGE)
        self.decision_jb = self.facf_decision(self.ffork_proofs, JUDGE_B)
        self.free_ja = self.facf_decision(self.ffree_proofs, JUDGE)
        self.free_jb = self.facf_decision(self.ffree_proofs, JUDGE_B)

    def facf_proof(self, items, issuer=SITE_A, moment=None):
        return sign_final_aggregate_chain_fork_proof(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.ring, self.m if moment is None else moment, issuer, 1)

    def facf_decision(self, proofs, issuer=JUDGE, moment=None, ring=None):
        return adjudicate_final_aggregate_chain_forks(
            proofs, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, 1)

    def fdecision_items(self):
        return [
            decision_item("one", self.decision_ja),
            decision_item("two", self.decision_jb),
        ]

    def fbatch_report(self, items, ring=None, moment=None):
        return verify_final_aggregate_chain_fork_decisions(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring if ring is None else ring,
            self.m if moment is None else moment)

    def fmake_aggregate(self, items, dsp=None, ring=None, moment=None,
                       issuer=JUDGE, version=1):
        return aggregate_final_aggregate_chain_fork_decisions(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.dsp if dsp is None else dsp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version)

    def fverify_aggregate(self, raw, dsp=None, ring=None, moment=None):
        return verify_final_aggregate_chain_fork_decision_aggregate(
            raw, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.dsp if dsp is None else dsp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment)

    def rewrap(self, payload, moment=None, issuer=None, version=None):
        """Re-seal an edited payload (default JUDGE aggregate key)."""
        sign_issuer = payload.get("issuer") if issuer is None else issuer
        sign_version = (
            payload.get("keyVersion") if version is None else version)
        at = self.m if moment is None else moment
        entry = _usable_checkpoint_key(
            _validated_keyring(self.ring), sign_issuer, sign_version, at)
        payload_bytes = _prune_compact(payload)
        signature = hmac.new(
            bytes.fromhex(entry[SECRET]), payload_bytes,
            hashlib.sha256).hexdigest()
        return _prune_compact(
            {"payload": payload, "signature": signature})

    def assert_invalid(self, raw, dsp=None, ring=None, moment=None):
        with self.assertRaises(
            InvalidFinalAggregateChainForkDecisionAggregateError
        ):
            self.fverify_aggregate(raw, dsp=dsp, ring=ring, moment=moment)


class BatchValidationTest(FinalFinalFixtures, unittest.TestCase):
    def test_non_list_items_is_type_error(self):
        with self.assertRaises(TypeError):
            self.fbatch_report((decision_item("one", self.decision_ja),))

    def test_empty_list_is_value_error(self):
        with self.assertRaises(ValueError):
            self.fbatch_report([])

    def test_non_dict_item_is_type_error(self):
        with self.assertRaises(TypeError):
            self.fbatch_report(["nope"])

    def test_wrong_item_key_set(self):
        with self.assertRaises(ValueError):
            self.fbatch_report([{"id": "one", "decision":
                                self.decision_ja, "extra": 1}])

    def test_non_str_id(self):
        with self.assertRaises(TypeError):
            self.fbatch_report([{"id": 1, "decision": self.decision_ja}])

    def test_empty_id(self):
        with self.assertRaises(ValueError):
            self.fbatch_report([{"id": "", "decision": self.decision_ja}])

    def test_duplicate_id(self):
        with self.assertRaises(ValueError):
            self.fbatch_report([
                decision_item("one", self.decision_ja),
                decision_item("one", self.decision_jb)])

    def test_non_bytes_decision(self):
        with self.assertRaises(TypeError):
            self.fbatch_report([{"id": "one", "decision": "bytes"}])

    def test_bool_moment_never_poses_as_int(self):
        with self.assertRaises(TypeError):
            self.fbatch_report(self.fdecision_items(), moment=True)
        with self.assertRaises(TypeError):
            self.fmake_aggregate(self.fdecision_items(), moment=True)

    def test_negative_moment_is_value_error(self):
        with self.assertRaises(ValueError):
            self.fbatch_report(self.fdecision_items(), moment=-1)

    def test_illegal_shared_policy_is_value_error(self):
        with self.assertRaises(ValueError):
            verify_final_aggregate_chain_fork_decisions(
                self.fdecision_items(), self.policy, self.auth, self.ssp,
                self.fsignerp, {"sites": {}, "threshold": 1},
                self.ring, self.m)

    def test_keyring_fault_is_type_error(self):
        with self.assertRaises(TypeError):
            self.fbatch_report(self.fdecision_items(), ring={"x": "nope"})


class BatchReportTest(FinalFinalFixtures, unittest.TestCase):
    def test_two_verified_decisions(self):
        report = self.fbatch_report(self.fdecision_items())
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual(len(report["items"]), 2)
        for item in report["items"]:
            self.assertEqual(list(item.keys()), ITEM_REPORT_KEYS)
            self.assertEqual(item["status"], "verified")
            self.assertIsNone(item["error"])
            self.assertIsInstance(item["result"], dict)
            self.assertEqual(set(item["result"]), set(SINGLE_RESULT_KEYS))

    def test_input_order_preserved(self):
        report = self.fbatch_report(list(reversed(self.fdecision_items())))
        self.assertEqual([i["id"] for i in report["items"]], ["two", "one"])

    def test_invalid_decision_does_not_block_later(self):
        report = self.fbatch_report([
            decision_item("bad", b"not a packet"),
            decision_item("ok", self.decision_jb)])
        bad, ok = report["items"]
        self.assertEqual(bad["status"], "invalid-decision")
        self.assertTrue(bad["error"])
        self.assertIsNone(bad["result"])
        self.assertEqual(ok["status"], "verified")
        self.assertIsNone(ok["error"])
        self.assertEqual(ok["result"]["issuer"], JUDGE_B)

    def test_garbage_bytes_and_json_are_invalid(self):
        for raw in (b"", b"\xff", b"{", b"[]", b'{"payload":{}}'):
            report = self.fbatch_report([decision_item("bad", raw)])
            self.assertEqual(
                report["items"][0]["status"], "invalid-decision", raw)

    def test_wrong_keyring_is_unauthenticated(self):
        wrong_ring = copy.deepcopy(self.ring)
        wrong_ring[JUDGE] = [
            dict(wrong_ring[JUDGE][0], secret="00" * 32)]
        report = self.fbatch_report(
            [decision_item("one", self.decision_ja)], ring=wrong_ring)
        item = report["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertIsNone(item["result"])
        self.assertIn("signature", item["error"])

    def test_unauthenticated_identity_never_enters_result(self):
        wrong_ring = copy.deepcopy(self.ring)
        wrong_ring[JUDGE] = [
            dict(wrong_ring[JUDGE][0], secret="00" * 32)]
        item = self.fbatch_report(
            [decision_item("one", self.decision_ja)], ring=wrong_ring
        )["items"][0]
        self.assertNotIn(JUDGE, str(item))

    def test_foreign_policy_digest_is_invalid_decision(self):
        foreign = {
            "sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 1}
        report = verify_final_aggregate_chain_fork_decisions(
            self.fdecision_items(), self.policy, self.auth, self.ssp,
            self.fsignerp, foreign, self.ring, self.m)
        for item in report["items"]:
            self.assertEqual(item["status"], "invalid-decision")

    def test_revoked_key_is_unauthenticated(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        item = self.fbatch_report(
            [decision_item("one", self.decision_ja)], ring=revoked
        )["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertIn("revoked", item["error"])

    def test_equal_but_independent_results(self):
        first = self.fbatch_report(self.fdecision_items())
        second = self.fbatch_report(self.fdecision_items())
        self.assertEqual(first, second)
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.fbatch_report(self.fdecision_items())["items"][0][
                "result"]["issuer"], JUDGE)

    def test_inputs_are_not_modified(self):
        items = self.fdecision_items()
        snapshot = copy.deepcopy(items)
        self.fbatch_report(items)
        self.assertEqual(items, snapshot)
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.fbatch_report(items)

    def test_single_entry_still_verifies(self):
        result = verify_final_aggregate_chain_fork_decision(
            self.decision_ja, self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, self.ring, self.m)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(set(result), set(SINGLE_RESULT_KEYS))


class AggregateShapeTest(FinalFinalFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.fmake_aggregate(self.fdecision_items())
        self.payload = parse(self.raw)

    def test_envelope_and_payload_keys(self):
        self.assertEqual(set(self.payload), set(AGGREGATE_KEYS))
        self.assertEqual(
            set(self.payload["payload"]), set(AGGREGATE_PAYLOAD_KEYS))

    def test_canonical_compact_encoding(self):
        self.assertFalse(self.raw.endswith(b"\n"))
        self.assertEqual(compact(parse(self.raw)), self.raw)
        decoded = self.raw.decode("utf-8")
        self.assertNotIn(" ", decoded)

    def test_rows_sorted_by_issuer_then_id(self):
        rows = self.payload["payload"]["items"]
        self.assertEqual(
            [r["id"] for r in rows], ["one", "two"])
        self.assertEqual(
            [r["id"] for r in rows],
            [r["id"] for r in sorted(
                rows, key=lambda r: (r["issuer"], r["id"]))])

    def test_row_shapes(self):
        for row in self.payload["payload"]["items"]:
            self.assertEqual(list(row.keys()), AGGREGATE_ROW_KEYS)
            self.assertEqual(row["conclusion"], "valid")
            self.assertIsNone(row["reason"])
            self.assertEqual(row["issuer"],
                             JUDGE if row["id"] == "one" else JUDGE_B)
            self.assertEqual(row["keyVersion"], 1)
            self.assertEqual(
                row["digest"], hashlib.sha256(
                    self.decision_ja if row["id"] == "one"
                    else self.decision_jb).hexdigest())
            self.assertEqual(
                set(row["declaration"]), set(DECLARATION_KEYS))

    def test_inputs_bound_in_original_order(self):
        self.assertEqual(
            self.payload["payload"]["inputs"],
            [hashlib.sha256(self.decision_ja).hexdigest(),
             hashlib.sha256(self.decision_jb).hexdigest()])
        reversed_raw = self.fmake_aggregate(
            list(reversed(self.fdecision_items())))
        self.assertEqual(
            parse(reversed_raw)["payload"]["inputs"],
            list(reversed(self.payload["payload"]["inputs"])))

    def test_six_policy_digest_bindings(self):
        payload = self.payload["payload"]
        self.assertEqual(
            payload["prunePolicyDigest"],
            hashlib.sha256(_verdict_policy_bytes(self.policy)).hexdigest())
        for name, policy in (
            ("authorizationPolicyDigest", self.auth),
            ("sitePolicyDigest", self.ssp),
            ("signerSitePolicyDigest", self.fsignerp),
            ("adjudicationSitePolicyDigest", self.adjp),
            ("decisionSitePolicyDigest", self.dsp),
        ):
            self.assertEqual(
                payload[name],
                hashlib.sha256(
                    _prune_batch_site_policy_bytes(policy)).hexdigest(),
                name)

    def test_version_is_one(self):
        self.assertEqual(self.payload["payload"]["version"], 1)


class AggregateTallyTest(FinalFinalFixtures, unittest.TestCase):
    def test_two_agreeing_sites_accepted(self):
        result = self.fverify_aggregate(
            self.fmake_aggregate(self.fdecision_items()))
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["declaration"])
        self.assertEqual(result["declaration"]["status"], "accepted")

    def test_one_site_is_insufficient_but_keeps_declaration(self):
        raw = self.fmake_aggregate(
            [decision_item("one", self.decision_ja)])
        result = self.fverify_aggregate(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declaration"])

    def test_no_valid_vote_is_insufficient_with_null_declaration(self):
        raw = self.fmake_aggregate([decision_item("bad", b"{}")])
        result = self.fverify_aggregate(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["declaration"])
        row = result["items"][0]
        self.assertEqual(row["conclusion"], "invalid")
        self.assertEqual(row["reason"], "invalid")
        self.assertIsNone(row["issuer"])
        self.assertIsNone(row["keyVersion"])
        self.assertIsNone(row["declaration"])

    def test_identical_same_site_decisions_are_duplicate(self):
        raw = self.fmake_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.decision_ja)])
        rows = self.fverify_aggregate(raw)["items"]
        by_id = {r["id"]: r for r in rows}
        self.assertEqual(by_id["a"]["conclusion"], "valid")
        self.assertIsNone(by_id["a"]["reason"])
        self.assertEqual(by_id["b"]["conclusion"], "duplicate")
        self.assertEqual(by_id["b"]["reason"], "duplicate")
        # The duplicate still carries the same authenticated identity
        # and declaration.
        self.assertEqual(by_id["b"]["issuer"], JUDGE)
        self.assertIsNotNone(by_id["b"]["declaration"])

    def test_different_same_site_decisions_contradict(self):
        raw = self.fmake_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.free_ja)])
        result = self.fverify_aggregate(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])
        for row in result["items"]:
            self.assertEqual(row["conclusion"], "contradiction")
            self.assertEqual(row["reason"], "contradiction")

    def test_cross_site_disagreement_is_conflicted(self):
        free_b = self.facf_decision(self.ffree_proofs, JUDGE_B)
        raw = self.fmake_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", free_b)])
        result = self.fverify_aggregate(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])

    def test_fork_free_consensus_accepted_with_empty_common(self):
        raw = self.fmake_aggregate([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb)])
        result = self.fverify_aggregate(raw)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["declaration"]["common"], [])

    def test_fork_vs_fork_free_difference_is_conflicted_even_with_majority(self):
        dsp3 = {"sites": {JUDGE: {1}, JUDGE_B: {1}, SITE_A: {1}},
                "threshold": 2}
        free_c = self.facf_decision(self.ffree_proofs, SITE_A)
        raw = self.fmake_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.decision_jb),
            decision_item("c", free_c)], dsp=dsp3)
        self.assertEqual(self.fverify_aggregate(raw, dsp=dsp3)["status"],
                         "conflicted")

    def test_unauthenticated_row_does_not_count(self):
        wrong_ring = copy.deepcopy(self.ring)
        wrong_ring[JUDGE] = [
            dict(wrong_ring[JUDGE][0], secret="00" * 32)]
        raw = self.fmake_aggregate(
            [decision_item("one", self.decision_ja)], ring=wrong_ring)
        result = self.fverify_aggregate(raw, ring=wrong_ring)
        row = result["items"][0]
        self.assertEqual(row["reason"], "unauthenticated")
        self.assertEqual(row["issuer"], JUDGE)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["declaration"])

    def test_unauthorized_site_does_not_count(self):
        dsp = {"sites": {JUDGE_B: {1}}, "threshold": 1}
        raw = self.fmake_aggregate(
            [decision_item("one", self.decision_ja)], dsp=dsp)
        result = self.fverify_aggregate(raw, dsp=dsp)
        row = result["items"][0]
        self.assertEqual(row["conclusion"], "invalid")
        self.assertEqual(row["reason"], "unauthorized")
        self.assertEqual(result["status"], "insufficient")

    def test_unauthorized_version_does_not_count(self):
        dsp = {"sites": {JUDGE: {2}}, "threshold": 1}
        raw = self.fmake_aggregate(
            [decision_item("one", self.decision_ja)], dsp=dsp)
        result = self.fverify_aggregate(raw, dsp=dsp)
        self.assertEqual(result["items"][0]["reason"], "unauthorized")

    def test_input_independence_of_sealed_bytes(self):
        first = self.fmake_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.decision_jb)])
        second = self.fmake_aggregate([
            decision_item("b", self.decision_jb),
            decision_item("a", self.decision_ja)])
        # Rows are sorted stably, so the declarations agree; only the
        # inputs vector follows the input order.
        p1, p2 = parse(first)["payload"], parse(second)["payload"]
        self.assertEqual(p1["items"], p2["items"])
        self.assertEqual(p1["inputs"], list(reversed(p2["inputs"])))


class AggregateVerifyTest(FinalFinalFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.fmake_aggregate(self.fdecision_items())

    def test_result_keys_and_digest(self):
        result = self.fverify_aggregate(self.raw)
        self.assertEqual(list(result.keys()), AGGREGATE_RESULT_KEYS)
        self.assertEqual(
            result["aggregateDigest"],
            hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["version"], 1)

    def test_equal_but_independent_results(self):
        first = self.fverify_aggregate(self.raw)
        second = self.fverify_aggregate(self.raw)
        self.assertEqual(first, second)
        first["items"][0]["declaration"]["status"] = "x"
        self.assertEqual(
            self.fverify_aggregate(self.raw)["items"][0][
                "declaration"]["status"], "accepted")

    def test_non_bytes_is_type_error(self):
        with self.assertRaises(TypeError):
            self.fverify_aggregate("bytes")

    def test_bad_signature_is_authentication_error(self):
        tampered = parse(self.raw)
        tampered["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.fverify_aggregate(compact(tampered))

    def test_unknown_aggregate_credential(self):
        with self.assertRaises(AuthenticationError):
            self.fmake_aggregate(self.fdecision_items(),
                                issuer="nobody", version=1)

    def test_aggregate_signer_validation(self):
        for issuer, version, error in (
            (1, 1, TypeError),
            ("", 1, ValueError),
            (JUDGE, True, TypeError),
            (JUDGE, 0, ValueError),
        ):
            with self.assertRaises(error):
                self.fmake_aggregate(self.fdecision_items(),
                                    issuer=issuer, version=version)

    def test_later_revocation_rejects(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.fverify_aggregate(self.raw, ring=revoked)

    def test_expired_at_verify_moment_rejects(self):
        expired = copy.deepcopy(self.ring)
        expired[JUDGE][0]["notAfter"] = self.m - 1
        with self.assertRaises(AuthenticationError):
            self.fverify_aggregate(self.raw, ring=expired)

    def test_foreign_decision_site_policy_is_invalid(self):
        foreign = {"sites": {JUDGE: {1}, JUDGE_B: {1}}, "threshold": 1}
        self.assert_invalid(self.raw, dsp=foreign)

    def test_foreign_base_policy_is_invalid(self):
        foreign = {
            "batch": "other",
            "sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
            "threshold": 2,
        }
        with self.assertRaises(
            InvalidFinalAggregateChainForkDecisionAggregateError
        ):
            verify_final_aggregate_chain_fork_decision_aggregate(
                self.raw, foreign, self.auth, self.ssp, self.fsignerp,
                self.adjp, self.dsp, self.ring, self.m)

    def test_status_tamper_is_invalid(self):
        payload = parse(self.raw)["payload"]
        payload["status"] = "insufficient"
        self.assert_invalid(self.rewrap(payload))

    def test_declaration_tamper_is_invalid(self):
        payload = parse(self.raw)["payload"]
        payload["declaration"]["status"] = "insufficient"
        self.assert_invalid(self.rewrap(payload))

    def test_row_conclusion_tamper_is_invalid(self):
        payload = parse(self.raw)["payload"]
        payload["items"][0]["conclusion"] = "duplicate"
        payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid(self.rewrap(payload))

    def test_extra_row_key_is_invalid(self):
        payload = parse(self.raw)["payload"]
        payload["items"][0]["extra"] = 1
        self.assert_invalid(self.rewrap(payload))

    def test_input_digest_binding_tamper_is_invalid(self):
        payload = parse(self.raw)["payload"]
        payload["inputs"][0] = "ab" * 32
        self.assert_invalid(self.rewrap(payload))

    def test_rows_must_stay_sorted(self):
        payload = parse(self.raw)["payload"]
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(self.rewrap(payload))

    def test_wrong_version_is_invalid(self):
        payload = parse(self.raw)["payload"]
        payload["version"] = 2
        self.assert_invalid(self.rewrap(payload))

    def test_declaration_recompute_mismatch_is_invalid(self):
        payload = parse(self.raw)["payload"]
        # Swap the proof vector order inside one counted declaration;
        # the digest multiset is unchanged but the positional binding
        # breaks.
        declaration = payload["items"][0]["declaration"]
        declaration["proofs"] = list(reversed(declaration["proofs"]))
        self.assert_invalid(self.rewrap(payload))

    def test_non_canonical_encoding_is_invalid(self):
        raw = self.raw.replace(b":", b": ", 1)
        with self.assertRaises(
            InvalidFinalAggregateChainForkDecisionAggregateError
        ):
            self.fverify_aggregate(raw)

    def test_trailing_byte_is_invalid(self):
        self.assert_invalid(self.raw + b"\n")

    def test_inputs_are_not_modified(self):
        items = self.fdecision_items()
        snapshot = copy.deepcopy(items)
        self.fmake_aggregate(items)
        self.assertEqual(items, snapshot)
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.fverify_aggregate(self.raw)

    def test_error_class_is_distinct(self):
        self.assertTrue(issubclass(
            InvalidFinalAggregateChainForkDecisionAggregateError,
            ValueError))
        self.assertIsNot(
            InvalidFinalAggregateChainForkDecisionAggregateError,
            InvalidFinalAggregateChainForkDecisionError)


if __name__ == "__main__":
    unittest.main()
