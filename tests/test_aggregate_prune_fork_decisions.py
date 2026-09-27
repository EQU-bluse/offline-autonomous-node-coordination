"""Tests for batch fork-decision verification and cross-adjudicator aggregation.

Covers :func:`verify_prune_aggregate_fork_decisions`,
:func:`aggregate_prune_fork_decisions` and
:func:`verify_prune_fork_decision_aggregate`: the batch container and
shared materials validated in full before any decision is parsed, the
verified/invalid/unauthenticated taxonomy with input-order reports and
no cross-decision interference, the review-then-authorize-then-authenticate
pipeline with its fixed reasons, same-adjudicator duplicate/contradiction
handling over the complete declaration (common fork edge set, ordered
per-proof conclusions and overall status), cross-site declaration
agreement, threshold acceptance with the declaration kept on
insufficient tallies, the canonical signed aggregate and its bindings,
the offline re-tally verification and aggregate credential rules, the
error hierarchies, equal-but-deeply-independent results, input
immutability and the purely offline guarantee.
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidAggregateForkDecisionAggregateError,
    InvalidAggregateForkDecisionError,
    adjudicate_prune_aggregate_forks,
    aggregate_prune_fork_decisions,
    verify_prune_aggregate_fork_decisions,
    verify_prune_fork_decision_aggregate,
)

from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_adjudicate_prune_aggregate_forks import (
    PruneAggregateForkAdjudicationFixtures,
    proof_item,
    site_policy,
    rewrap,
)

BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
AGGREGATE_KEYS = ["payload", "signature"]
AGGREGATE_PAYLOAD_KEYS = [
    "decisionSitePolicyDigest", "decisions", "declaration", "issuer",
    "items", "keyVersion", "prunePolicyDigest", "sitePolicyDigest",
    "status", "version",
]
ROW_KEYS = ["conclusion", "decisionDigest", "declaration", "id",
            "issuer", "keyVersion", "reason"]
DECLARATION_KEYS = ["common", "conclusions", "status"]
CONCLUSION_KEYS = ["conclusion", "id", "issuer"]
AGGREGATE_RESULT_KEYS = [
    "aggregateDigest", "decisions", "declaration",
    "decisionSitePolicyDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "sitePolicyDigest", "status", "version",
]
DECISION_RESULT_KEYS = [
    "common", "proofDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "proofs", "sitePolicyDigest", "status", "version",
]


def decision_item(item_id, decision):
    """One aggregate item: a batch-unique id and decision bytes."""
    return {"id": item_id, "decision": decision}


class PruneForkDecisionAggregateFixtures(PruneAggregateForkAdjudicationFixtures):
    """Signed fork decisions from several adjudicators and aggregate helpers."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # The two fork sites are also the two legitimate adjudicator sites.
        self.dsp = site_policy(sites=(SITE_A, SITE_B, SITE_C), threshold=2)
        self.items_ab = [
            proof_item("x", self.proof(issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]

    def fdecision(self, items, issuer=SITE_A, sp=None):
        return adjudicate_prune_aggregate_forks(
            items, self.policy, self.sp if sp is None else sp,
            self.ring, self.m, issuer, 1,
        )

    def make_aggregate(self, items, dsp=None, sp=None, ring=None,
                       moment=None, issuer=JUDGE, version=1):
        return aggregate_prune_fork_decisions(
            items, self.policy,
            self.dsp if dsp is None else dsp,
            self.sp if sp is None else sp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def verify_aggregate(self, raw, dsp=None, sp=None, ring=None,
                         moment=None):
        return verify_prune_fork_decision_aggregate(
            raw, self.policy,
            self.dsp if dsp is None else dsp,
            self.sp if sp is None else sp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def decisions_report(self, items, sp=None):
        return verify_prune_aggregate_fork_decisions(
            items, self.policy, self.sp if sp is None else sp,
            self.ring, self.m,
        )


class BatchVerificationTest(PruneForkDecisionAggregateFixtures):
    def test_verified_reports_in_input_order(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        d_b = self.fdecision(self.items_ab, issuer=SITE_B)
        report = self.decisions_report([
            decision_item("a", d_a), decision_item("b", b"{}"),
            decision_item("c", d_b),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual([row["id"] for row in report["items"]],
                         ["a", "b", "c"])
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["verified", "invalid", "verified"],
        )
        for row in report["items"]:
            self.assertEqual(list(row.keys()), ITEM_REPORT_KEYS)
        self.assertIsNone(report["items"][0]["error"])
        self.assertEqual(
            report["items"][0]["result"]["proofDigest"],
            hashlib.sha256(d_a).hexdigest(),
        )
        self.assertEqual(list(report["items"][0]["result"].keys()),
                         DECISION_RESULT_KEYS)
        bad = report["items"][1]
        self.assertIsNone(bad["result"])
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")

    def test_unauthenticated_is_isolated(self):
        ring = {
            site: [entry(1, "77" * 32)]
            for site in (SITE_A, SITE_B, SITE_C, JUDGE)
        }
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        d_b = self.fdecision(self.items_ab, issuer=SITE_B)
        report = verify_prune_aggregate_fork_decisions(
            [decision_item("a", d_a), decision_item("b", d_b)],
            self.policy, self.sp, ring, self.m,
        )
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["unauthenticated", "unauthenticated"],
        )
        self.assertTrue(all(row["error"] for row in report["items"]))

    def test_structure_validated_upfront(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        with self.assertRaises(TypeError):
            self.decisions_report("x")
        with self.assertRaises(TypeError):
            self.decisions_report(["x"])
        with self.assertRaises(ValueError):
            self.decisions_report([])
        with self.assertRaises(ValueError):
            self.decisions_report([
                decision_item("a", d_a), decision_item("a", d_a),
            ])
        with self.assertRaises(ValueError):
            self.decisions_report([{"id": "a", "decision": d_a, "x": 1}])
        with self.assertRaises(ValueError):
            self.decisions_report([decision_item("", d_a)])
        with self.assertRaises(TypeError):
            self.decisions_report([decision_item(1, d_a)])
        with self.assertRaises(TypeError):
            self.decisions_report([decision_item("a", "x")])

    def test_shared_materials_validated_upfront(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        items = [decision_item("a", d_a)]
        with self.assertRaises(ValueError):
            verify_prune_aggregate_fork_decisions(
                items, {"batch": "x"}, self.sp, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_fork_decisions(
                items, self.policy, "x", self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_fork_decisions(
                items, self.policy, self.sp, "ring", self.m)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_fork_decisions(
                items, self.policy, self.sp, self.ring, True)
        with self.assertRaises(ValueError):
            verify_prune_aggregate_fork_decisions(
                items, self.policy, self.sp, self.ring, -1)

    def test_batch_fault_surfaces_even_when_a_decision_is_bad(self):
        with self.assertRaises(ValueError):
            self.decisions_report([
                decision_item("a", b"{}"), decision_item("a", b"{}"),
            ])

    def test_results_are_fresh_and_independent(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        items = [decision_item("a", d_a)]
        first = self.decisions_report(items)
        second = self.decisions_report(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.decisions_report(items)["items"][0]["result"]["issuer"],
            SITE_A,
        )

    def test_inputs_are_not_modified(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        items = [decision_item("a", d_a)]
        snapshot = copy.deepcopy((items, self.policy, self.sp, self.ring))
        self.decisions_report(items)
        self.assertEqual((items, self.policy, self.sp, self.ring), snapshot)


class AggregateValidationTest(PruneForkDecisionAggregateFixtures):
    def test_items_container_faults(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        with self.assertRaises(TypeError):
            self.make_aggregate("x")
        with self.assertRaises(TypeError):
            self.make_aggregate(["x"])
        with self.assertRaises(TypeError):
            self.make_aggregate([decision_item(1, d_a)])
        with self.assertRaises(TypeError):
            self.make_aggregate([decision_item("a", 1)])

    def test_items_value_faults(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        with self.assertRaises(ValueError):
            self.make_aggregate([])
        with self.assertRaises(ValueError):
            self.make_aggregate([decision_item("", d_a)])
        with self.assertRaises(ValueError):
            self.make_aggregate([
                decision_item("a", d_a), decision_item("a", d_a)])
        with self.assertRaises(ValueError):
            self.make_aggregate([{"id": "a", "decision": d_a, "x": 1}])

    def test_decision_site_policy_faults(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        items = [decision_item("a", d_a)]
        with self.assertRaises(ValueError):
            self.make_aggregate(items, dsp={"sites": {SITE_A: {1}}})
        with self.assertRaises(ValueError):
            self.make_aggregate(items, dsp={"sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_aggregate(
                items, dsp={"sites": {SITE_A: [1]}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_aggregate(
                items, dsp={"sites": {SITE_A: {True}}, "threshold": 1})
        with self.assertRaises(ValueError):
            self.make_aggregate(
                items, dsp={"sites": {SITE_A: {0}}, "threshold": 1})
        with self.assertRaises(ValueError):
            self.make_aggregate(
                items, dsp={"sites": {SITE_A: set()}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_aggregate(
                items, dsp={"sites": {SITE_A: {1}}, "threshold": True})
        with self.assertRaises(ValueError):
            self.make_aggregate(
                items, dsp={"sites": {SITE_A: {1}}, "threshold": 0})
        with self.assertRaises(ValueError):
            self.make_aggregate(
                items, dsp={"sites": {SITE_A: {1}}, "threshold": 2})

    def test_prune_and_fork_policy_faults(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        items = [decision_item("a", d_a)]
        with self.assertRaises(ValueError):
            aggregate_prune_fork_decisions(
                items, {"batch": "x"}, self.dsp, self.sp, self.ring,
                self.m, JUDGE, 1)
        with self.assertRaises(TypeError):
            aggregate_prune_fork_decisions(
                items, self.policy, self.dsp, "x", self.ring,
                self.m, JUDGE, 1)

    def test_moment_issuer_version_rules(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        items = [decision_item("a", d_a)]
        with self.assertRaises(TypeError):
            self.make_aggregate(items, moment=True)
        with self.assertRaises(ValueError):
            self.make_aggregate(items, moment=-1)
        with self.assertRaises(TypeError):
            self.make_aggregate(items, issuer=7)
        with self.assertRaises(ValueError):
            self.make_aggregate(items, issuer="")
        with self.assertRaises(TypeError):
            self.make_aggregate(items, version=True)
        with self.assertRaises(ValueError):
            self.make_aggregate(items, version=0)

    def test_signing_credentials_have_no_fallback(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        items = [decision_item("a", d_a)]
        with self.assertRaises(AuthenticationError):
            self.make_aggregate(items, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.make_aggregate(items, issuer=JUDGE, version=2)
        revoked = dict(self.ring)
        revoked[JUDGE] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            self.make_aggregate(items, ring=revoked)
        future = dict(self.ring)
        future[JUDGE] = [entry(1, SECRET_COORD, not_before=self.m + 1)]
        with self.assertRaises(AuthenticationError):
            self.make_aggregate(items, ring=future)
        expired = dict(self.ring)
        expired[JUDGE] = [entry(1, SECRET_COORD, not_after=self.m - 1)]
        with self.assertRaises(AuthenticationError):
            self.make_aggregate(items, ring=expired)

    def test_inputs_are_not_modified(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        d_b = self.fdecision(self.items_ab, issuer=SITE_B)
        items = [decision_item("x", d_a), decision_item("y", d_b)]
        snapshot = copy.deepcopy(
            (items, self.policy, self.dsp, self.sp, self.ring))
        self.make_aggregate(items)
        self.assertEqual(
            (items, self.policy, self.dsp, self.sp, self.ring), snapshot)


class PerItemRulingTest(PruneForkDecisionAggregateFixtures):
    def rows(self, items, dsp=None):
        raw = self.make_aggregate(items, dsp=dsp)
        return self.verify_aggregate(raw, dsp=dsp)["items"]

    def row_by_id(self, items, dsp=None):
        return {row["id"]: row for row in self.rows(items, dsp=dsp)}

    def test_invalid_bytes_are_rejected_alone_and_processing_continues(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        d_b = self.fdecision(self.items_ab, issuer=SITE_B)
        rows = self.row_by_id([
            decision_item("good", d_a),
            decision_item("bad", b"{}"),
            decision_item("good2", d_b),
        ])
        bad = rows["bad"]
        self.assertEqual(bad["conclusion"], "invalid")
        self.assertEqual(bad["reason"], "invalid-proof")
        self.assertIsNone(bad["issuer"])
        self.assertIsNone(bad["keyVersion"])
        self.assertIsNone(bad["declaration"])
        self.assertEqual(rows["good"]["conclusion"], "valid")
        self.assertEqual(rows["good2"]["conclusion"], "valid")

    def test_foreign_fork_site_policy_is_invalid_without_identity(self):
        other_sp = site_policy(sites=(SITE_B, SITE_C), threshold=1)
        foreign = self.fdecision(
            [proof_item("x", self.proof(issuer=SITE_A))], sp=other_sp)
        rows = self.row_by_id([decision_item("x", foreign)])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])

    def test_unauthorized_adjudicator_keeps_identity(self):
        pol = site_policy(sites=(SITE_B, SITE_C), threshold=1)
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        d_b = self.fdecision(self.items_ab, issuer=SITE_B)
        rows = self.row_by_id([
            decision_item("x", d_a), decision_item("y", d_b)], dsp=pol)
        self.assertEqual(rows["x"]["reason"], "unauthorized-site")
        self.assertEqual(rows["x"]["issuer"], SITE_A)
        self.assertIsNotNone(rows["x"]["declaration"])
        self.assertEqual(rows["y"]["conclusion"], "valid")

    def test_unauthorized_version(self):
        pol = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        pol["sites"][SITE_A] = {2}
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        rows = self.row_by_id([decision_item("x", d_a)], dsp=pol)
        self.assertEqual(rows["x"]["reason"], "unauthorized-version")
        self.assertEqual(rows["x"]["keyVersion"], 1)

    def test_credential_states_and_bad_signature(self):
        pol = site_policy(sites=(SITE_A,), threshold=1)
        cases = [
            ({SITE_A: [entry(2, "77" * 32)]}, "credential-unavailable"),
            ({SITE_A: [entry(1, SECRET_COORD, revoked=True)]}, "revoked"),
            ({SITE_A: [entry(1, SECRET_COORD, not_before=self.m + 1)]},
             "not-yet-valid"),
            ({SITE_A: [entry(1, SECRET_COORD, not_after=self.m - 1)]},
             "expired"),
        ]
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        for overrides, reason in cases:
            ring = dict(self.ring)
            ring.update(overrides)
            raw = self.make_aggregate(
                [decision_item("x", d_a)], dsp=pol, ring=ring)
            rows = self.verify_aggregate(raw, dsp=pol, ring=ring)["items"]
            self.assertEqual(rows[0]["reason"], reason)

        forged = rewrap(parse(d_a)["payload"], secret="77" * 32)
        rows = self.row_by_id([decision_item("x", forged)], dsp=pol)
        self.assertEqual(rows["x"]["reason"], "bad-signature")
        self.assertEqual(rows["x"]["issuer"], SITE_A)
        self.assertIsNotNone(rows["x"]["declaration"])

    def test_identical_declaration_even_distinct_bytes_is_duplicate(self):
        d1 = self.fdecision(self.items_ab, issuer=SITE_A)
        d2 = self.fdecision(list(reversed(self.items_ab)), issuer=SITE_A)
        self.assertNotEqual(d1, d2)
        pol = site_policy(sites=(SITE_A,), threshold=1)
        raw = self.make_aggregate([
            decision_item("a", d1), decision_item("b", d2)], dsp=pol)
        result = self.verify_aggregate(raw, dsp=pol)
        rows = {row["id"]: row for row in result["items"]}
        self.assertEqual(rows["a"]["conclusion"], "valid")
        self.assertEqual(rows["b"]["conclusion"], "duplicate")
        self.assertEqual(rows["b"]["reason"], "duplicate")
        self.assertEqual(result["status"], "accepted")

    def test_duplicates_alone_cannot_meet_threshold_two(self):
        d1 = self.fdecision(self.items_ab, issuer=SITE_A)
        pol = site_policy(sites=(SITE_A, SITE_B), threshold=2)
        raw = self.make_aggregate([
            decision_item("a", d1), decision_item("b", d1)], dsp=pol)
        result = self.verify_aggregate(raw, dsp=pol)
        self.assertEqual(result["status"], "insufficient")

    def test_same_adjudicator_distinct_declarations_contradict(self):
        d1 = self.fdecision(self.items_ab, issuer=SITE_A)
        d2 = self.fdecision([
            proof_item("x", self.proof(self.items_one, issuer=SITE_A)),
            proof_item("y", b"{}"),
        ], issuer=SITE_A)
        pol = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        raw = self.make_aggregate([
            decision_item("a", d1), decision_item("b", d2)], dsp=pol)
        result = self.verify_aggregate(raw, dsp=pol)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])
        for row in result["items"]:
            self.assertEqual(row["conclusion"], "contradiction")
            self.assertEqual(row["reason"], "contradiction")
            self.assertEqual(row["issuer"], SITE_A)


class AggregationTest(PruneForkDecisionAggregateFixtures):
    def _two_accepted_items(self):
        return [
            decision_item("a", self.fdecision(self.items_ab, issuer=SITE_A)),
            decision_item("b", self.fdecision(self.items_ab, issuer=SITE_B)),
        ]

    def test_accepted_binds_the_common_declaration(self):
        raw = self.make_aggregate(self._two_accepted_items())
        result = self.verify_aggregate(raw)
        self.assertEqual(result["status"], "accepted")
        declaration = result["declaration"]
        self.assertEqual(list(declaration.keys()), DECLARATION_KEYS)
        self.assertEqual(declaration["status"], "accepted")
        self.assertEqual(len(declaration["common"]), 1)
        self.assertEqual(
            [c["id"] for c in declaration["conclusions"]], ["x", "y"])

    def test_below_threshold_is_insufficient_but_keeps_declaration(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        raw = self.make_aggregate([decision_item("x", d_a)])
        result = self.verify_aggregate(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declaration"])
        accepted = self.verify_aggregate(
            self.make_aggregate(self._two_accepted_items()))
        self.assertEqual(
            result["declaration"], accepted["declaration"])

    def test_no_valid_vote_binds_null_declaration(self):
        raw = self.make_aggregate([
            decision_item("x", b"{}"), decision_item("y", b"{"),
        ])
        result = self.verify_aggregate(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["declaration"])

    def test_cross_site_declaration_disagreement_is_conflicted(self):
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        d_b = self.fdecision([
            proof_item("x", self.proof(self.items_one, issuer=SITE_A)),
            proof_item("y", self.proof(self.items_two, issuer=SITE_B)),
        ], issuer=SITE_B)
        raw = self.make_aggregate([
            decision_item("a", d_a), decision_item("b", d_b)])
        result = self.verify_aggregate(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])
        self.assertTrue(
            all(row["conclusion"] == "valid" for row in result["items"]))

    def test_conflict_is_not_outvotable(self):
        # Two adjudicators back declaration one, one backs declaration two.
        d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        d_b = self.fdecision(self.items_ab, issuer=SITE_B)
        d_c = self.fdecision([
            proof_item("x", self.proof(self.items_one, issuer=SITE_A)),
            proof_item("y", self.proof(self.items_two, issuer=SITE_B)),
        ], issuer=SITE_C)
        raw = self.make_aggregate([
            decision_item("a", d_a), decision_item("b", d_b),
            decision_item("c", d_c)])
        result = self.verify_aggregate(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])

    def test_rows_sort_by_issuer_then_id_with_invalid_first(self):
        d_b = self.fdecision(self.items_ab, issuer=SITE_B)
        raw = self.make_aggregate([
            decision_item("z", d_b),
            decision_item("a", b"{}"),
        ])
        result = self.verify_aggregate(raw)
        keys = [
            (row["issuer"] is not None, row["issuer"], row["id"])
            for row in result["items"]
        ]
        self.assertEqual(keys, sorted(keys))
        self.assertIsNone(result["items"][0]["issuer"])


class PacketShapeTest(PruneForkDecisionAggregateFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.d_a = self.fdecision(self.items_ab, issuer=SITE_A)
        self.d_b = self.fdecision(self.items_ab, issuer=SITE_B)
        self.items = [
            decision_item("x", self.d_a), decision_item("y", self.d_b)]
        self.raw = self.make_aggregate(self.items)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(parse(self.raw)), self.raw)

    def test_top_and_payload_key_sets(self):
        data = parse(self.raw)
        self.assertEqual(set(data.keys()), set(AGGREGATE_KEYS))
        self.assertEqual(list(data["payload"].keys()), AGGREGATE_PAYLOAD_KEYS)

    def test_row_and_declaration_shapes(self):
        payload = parse(self.raw)["payload"]
        for row in payload["items"]:
            self.assertEqual(list(row.keys()), ROW_KEYS)
            self.assertEqual(
                row["decisionDigest"],
                hashlib.sha256(
                    self.d_a if row["id"] == "x" else self.d_b).hexdigest(),
            )
            self.assertEqual(list(row["declaration"].keys()),
                             DECLARATION_KEYS)
            for conclusion in row["declaration"]["conclusions"]:
                self.assertEqual(list(conclusion.keys()), CONCLUSION_KEYS)

    def test_decisions_bound_in_original_order(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(payload["decisions"], [
            hashlib.sha256(self.d_a).hexdigest(),
            hashlib.sha256(self.d_b).hexdigest(),
        ])
        reversed_raw = self.make_aggregate(list(reversed(self.items)))
        self.assertEqual(
            parse(reversed_raw)["payload"]["decisions"],
            list(reversed(payload["decisions"])),
        )

    def test_three_policy_digest_bindings(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(
            payload["prunePolicyDigest"],
            hashlib.sha256(compact({
                "batch": self.policy["batch"],
                "sites": {
                    site: sorted(self.policy["sites"][site])
                    for site in sorted(self.policy["sites"])
                },
                "threshold": self.policy["threshold"],
            })).hexdigest(),
        )
        for bound_name, policy in (
            ("sitePolicyDigest", self.sp),
            ("decisionSitePolicyDigest", self.dsp),
        ):
            self.assertEqual(
                payload[bound_name],
                hashlib.sha256(compact({
                    "sites": {
                        site: sorted(policy["sites"][site])
                        for site in sorted(policy["sites"])
                    },
                    "threshold": policy["threshold"],
                })).hexdigest(),
            )

    def test_identity_version_and_status_bindings(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["status"], "accepted")


class VerifySuccessTest(PacketShapeTest):
    def test_result_is_fresh_fixed_key_mapping(self):
        result = self.verify_aggregate(self.raw)
        self.assertEqual(list(result.keys()), AGGREGATE_RESULT_KEYS)
        self.assertEqual(result["aggregateDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["decisions"],
                         parse(self.raw)["payload"]["decisions"])

    def test_repeated_calls_share_no_mutable_structure(self):
        first = self.verify_aggregate(self.raw)
        second = self.verify_aggregate(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["declaration"], second["declaration"])
        first["items"][0]["id"] = "tampered"
        first["declaration"]["common"][0]["successors"].append("zz" * 32)
        first["declaration"]["conclusions"][0]["conclusion"] = "invalid"
        third = self.verify_aggregate(self.raw)
        self.assertEqual(third["items"][0]["id"], second["items"][0]["id"])
        self.assertEqual(len(third["declaration"]["common"][0]["successors"]),
                         2)
        self.assertEqual(
            third["declaration"]["conclusions"][0]["conclusion"], "valid")


class VerifyStructureTest(PacketShapeTest):
    def assert_invalid(self, raw):
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            self.verify_aggregate(raw)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            self.verify_aggregate("x")
        with self.assertRaises(TypeError):
            self.verify_aggregate(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.verify_aggregate(self.raw, moment=-1)
        with self.assertRaises(TypeError):
            verify_prune_fork_decision_aggregate(
                self.raw, "x", self.dsp, self.sp, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, "x", self.sp, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, self.dsp, "x", self.ring, self.m)

    def test_encoding_faults(self):
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(b"")
        self.assert_invalid(b"{")
        with self.assertRaises(TypeError):
            self.verify_aggregate(b"[]")

    def test_key_set_and_version_faults(self):
        data = parse(self.raw)
        del data["signature"]
        self.assert_invalid(compact(data))
        payload = parse(self.raw)["payload"]
        del payload["declaration"]
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["extra"] = 1
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["version"] = 2
        self.assert_invalid(rewrap(payload))

    def test_status_enum_and_field_types(self):
        payload = parse(self.raw)["payload"]
        payload["status"] = "nope"
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["issuer"] = 7
        with self.assertRaises(TypeError):
            self.verify_aggregate(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["items"][0]["keyVersion"] = True
        with self.assertRaises(TypeError):
            self.verify_aggregate(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["decisions"] = ["z" * 64, "y" * 64]
        self.assert_invalid(rewrap(payload))

    def test_duplicate_keys_and_non_canonical_form(self):
        text = self.raw.decode("utf-8")
        marker = '"version":1'
        duplicated = text.replace(marker, marker + "," + marker, 1).encode()
        self.assert_invalid(duplicated)
        pretty = json.dumps(parse(self.raw), indent=2)
        self.assert_invalid(pretty.encode())

    def test_declaration_conclusions_must_be_sorted(self):
        payload = parse(self.raw)["payload"]
        conclusions = payload["declaration"]["conclusions"]
        payload["declaration"]["conclusions"] = list(reversed(conclusions))
        self.assert_invalid(rewrap(payload))


class VerifyBindingTest(PacketShapeTest):
    def assert_invalid(self, payload):
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            self.verify_aggregate(rewrap(payload))

    def test_wrong_prune_policy(self):
        other = copy.deepcopy(self.policy)
        other["batch"] = "other-batch"
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_prune_fork_decision_aggregate(
                self.raw, other, self.dsp, self.sp, self.ring, self.m)

    def test_wrong_site_policies(self):
        other_fork = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, self.dsp, other_fork,
                self.ring, self.m)
        other_decision = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, other_decision, self.sp,
                self.ring, self.m)

    def test_tampered_status_and_declaration_cannot_be_resigned(self):
        payload = parse(self.raw)["payload"]
        payload["status"] = "insufficient"
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["status"] = "conflicted"
        payload["declaration"] = None
        self.assert_invalid(payload)

    def test_tampered_row_conclusion_cannot_be_resigned(self):
        payload = parse(self.raw)["payload"]
        payload["items"][0]["conclusion"] = "duplicate"
        payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid(payload)

    def test_decision_digest_bindings(self):
        payload = parse(self.raw)["payload"]
        payload["decisions"][0] = "cc" * 32
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["items"][0]["decisionDigest"] = "dd" * 32
        self.assert_invalid(payload)

    def test_rows_must_stay_sorted(self):
        payload = parse(self.raw)["payload"]
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(payload)

    def test_common_declaration_must_match_the_tallied_decisions(self):
        payload = parse(self.raw)["payload"]
        payload["declaration"] = None
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["declaration"]["common"][0]["successors"].append("ee" * 32)
        payload["declaration"]["common"][0]["successors"].sort()
        self.assert_invalid(payload)

    def test_bound_declaration_must_be_a_possible_decision_outcome(self):
        # A claimed accepted status needs the fork threshold of voting
        # sites; a single forgiving declaration cannot invent acceptance.
        payload = parse(self.raw)["payload"]
        for conclusion in payload["items"][0]["declaration"]["conclusions"]:
            conclusion["conclusion"] = "invalid"
            conclusion["issuer"] = None
        # Keep the per-row declaration and top status mutually impossible.
        payload["items"][0]["declaration"]["status"] = "accepted"
        payload["items"][1]["declaration"]["status"] = "accepted"
        self.assert_invalid(payload)


class VerifyAuthenticationTest(PacketShapeTest):
    def test_signature_mismatch(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.verify_aggregate(compact(data))

    def test_revoked_future_expired_aggregator(self):
        cases = [
            {JUDGE: [entry(1, SECRET_COORD, revoked=True)]},
            {JUDGE: [entry(1, SECRET_COORD, not_before=self.m + 1)]},
            {JUDGE: [entry(1, SECRET_COORD, not_after=self.m - 1)]},
        ]
        for overrides in cases:
            ring = dict(self.ring)
            ring.update(overrides)
            with self.assertRaises(AuthenticationError):
                verify_prune_fork_decision_aggregate(
                    self.raw, self.policy, self.dsp, self.sp, ring, self.m)

    def test_unknown_aggregator(self):
        ring = {k: v for k, v in self.ring.items() if k != JUDGE}
        with self.assertRaises(AuthenticationError):
            self.verify_aggregate(self.raw, ring=ring)

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        self.assertTrue(
            issubclass(InvalidAggregateForkDecisionAggregateError, ValueError))
        self.assertTrue(
            issubclass(InvalidAggregateForkDecisionError, ValueError))


if __name__ == "__main__":
    unittest.main()
