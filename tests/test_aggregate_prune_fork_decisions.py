"""Tests for batch verification and cross-site aggregation of fork decisions.

Covers :func:`verify_prune_aggregate_fork_decisions`,
:func:`aggregate_prune_fork_decisions` and
:func:`verify_prune_fork_decision_aggregate`: the decision batch
container and shared materials validated in full before any decision is
parsed, the per-decision verified/invalid/unauthenticated taxonomy with
input-order reports and no cross-decision interference, the
verify-then-authenticate-then-authorize per-decision aggregation
pipeline with its fixed invalid/unauthenticated/unauthorized reasons,
same-site duplicate/contradiction handling over the complete
declaration (the common fork edge set, the per-item conclusions sorted
by site then id, the original-order proof digest vector and the overall
status), cross-site declaration agreement with no majority override,
threshold acceptance with the common declaration kept on insufficient
tallies, the canonical signed aggregate packet and its three policy
digest bindings, the offline re-tally verification recomputing every
binding plus each counted declaration, the aggregate credential rules,
the InvalidAggregateForkDecisionAggregateError hierarchy,
equal-but-independent results, input immutability and the purely
offline guarantee.
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
    aggregate_prune_fork_decisions,
    verify_prune_aggregate_fork_decisions,
    verify_prune_fork_decision_aggregate,
)

from test_adjudicate_prune_aggregate_forks import (
    PruneAggregateForkAdjudicationFixtures,
    proof_item,
    rewrap,
    site_policy,
)
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C

JUDGE_B = SITE_C
BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
AGGREGATE_KEYS = ["payload", "signature"]
AGGREGATE_PAYLOAD_KEYS = [
    "decisionSitePolicyDigest", "declaration", "inputs", "issuer",
    "items", "keyVersion", "prunePolicyDigest", "sitePolicyDigest",
    "status", "version",
]
AGGREGATE_ROW_KEYS = [
    "conclusion", "declaration", "digest", "id", "issuer", "keyVersion",
    "reason",
]
DECLARATION_KEYS = ["common", "conclusions", "proofs", "status"]
DECLARATION_ENTRY_KEYS = [
    "conclusion", "digest", "edges", "id", "issuer", "reason",
]
AGGREGATE_RESULT_KEYS = [
    "aggregateDigest", "inputs", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "sitePolicyDigest", "decisionSitePolicyDigest",
    "declaration", "status", "version",
]


def decision_item(item_id, decision):
    """One batch item: a batch-unique id and decision bytes."""
    return {"id": item_id, "decision": decision}


def decision_site_policy(sites=(JUDGE, JUDGE_B), threshold=2):
    return {"sites": {site: {1} for site in sites}, "threshold": threshold}


class ForkDecisionAggregateFixtures(PruneAggregateForkAdjudicationFixtures):
    """Signed fork decisions from two decision sites and aggregate helpers."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.dsp = decision_site_policy()
        self.proofs = [
            proof_item("x", self.proof(issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]
        self.decision_a = self.make_decision(self.proofs, issuer=JUDGE)
        self.decision_b = self.make_decision(self.proofs, issuer=JUDGE_B)

    def decision_items(self):
        return [
            decision_item("one", self.decision_a),
            decision_item("two", self.decision_b),
        ]

    def batch_report(self, items, sp=None, ring=None, moment=None):
        return verify_prune_aggregate_fork_decisions(
            items, self.policy, self.sp if sp is None else sp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def make_aggregate(self, items, sp=None, dsp=None, ring=None,
                       moment=None, issuer=JUDGE, version=1):
        return aggregate_prune_fork_decisions(
            items, self.policy, self.sp if sp is None else sp,
            self.dsp if dsp is None else dsp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def verify_aggregate(self, raw, sp=None, dsp=None, ring=None,
                         moment=None):
        return verify_prune_fork_decision_aggregate(
            raw, self.policy, self.sp if sp is None else sp,
            self.dsp if dsp is None else dsp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def aggregate_payload(self, items, **kwargs):
        return parse(self.make_aggregate(items, **kwargs))["payload"]


class BatchVerificationTest(ForkDecisionAggregateFixtures):
    def test_verified_reports_in_input_order(self):
        report = self.batch_report([
            decision_item("a", self.decision_a),
            decision_item("b", b"{}"),
            decision_item("c", self.decision_b),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual([row["id"] for row in report["items"]],
                         ["a", "b", "c"])
        self.assertEqual([row["status"] for row in report["items"]],
                         ["verified", "invalid", "verified"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), ITEM_REPORT_KEYS)
        good = report["items"][0]
        self.assertIsNone(good["error"])
        self.assertEqual(good["result"]["proofDigest"],
                         hashlib.sha256(self.decision_a).hexdigest())
        self.assertEqual(good["result"]["issuer"], JUDGE)
        bad = report["items"][1]
        self.assertIsNone(bad["result"])
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")

    def test_unauthenticated_is_isolated(self):
        ring = {
            site: [entry(1, "77" * 32)]
            for site in (SITE_A, SITE_B, SITE_C, JUDGE)
        }
        report = self.batch_report([
            decision_item("a", self.decision_a),
            decision_item("b", self.decision_b),
        ], ring=ring)
        self.assertEqual([row["status"] for row in report["items"]],
                         ["unauthenticated", "unauthenticated"])
        self.assertTrue(all(row["error"] for row in report["items"]))
        self.assertTrue(all(row["result"] is None
                            for row in report["items"]))

    def test_structure_validated_upfront(self):
        with self.assertRaises(TypeError):
            self.batch_report("x")
        with self.assertRaises(TypeError):
            self.batch_report(["x"])
        with self.assertRaises(ValueError):
            self.batch_report([])
        with self.assertRaises(ValueError):
            self.batch_report([
                decision_item("a", self.decision_a),
                decision_item("a", self.decision_b),
            ])
        with self.assertRaises(ValueError):
            self.batch_report([
                {"id": "a", "decision": self.decision_a, "x": 1},
            ])
        with self.assertRaises(ValueError):
            self.batch_report([decision_item("", self.decision_a)])
        with self.assertRaises(TypeError):
            self.batch_report([decision_item(1, self.decision_a)])
        with self.assertRaises(TypeError):
            self.batch_report([decision_item("a", "x")])

    def test_shared_materials_validated_upfront(self):
        items = [decision_item("a", self.decision_a)]
        with self.assertRaises(ValueError):
            verify_prune_aggregate_fork_decisions(
                items, {"batch": "x"}, self.sp, self.ring, self.m)
        with self.assertRaises(ValueError):
            verify_prune_aggregate_fork_decisions(
                items, self.policy, {"sites": {}}, self.ring, self.m)
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
            self.batch_report([
                decision_item("a", b"{}"), decision_item("a", b"{"),
            ])

    def test_results_are_fresh_and_independent(self):
        items = [decision_item("a", self.decision_a)]
        first = self.batch_report(items)
        second = self.batch_report(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.batch_report(items)["items"][0]["result"]["issuer"],
            JUDGE,
        )

    def test_inputs_are_not_modified(self):
        items = [decision_item("a", self.decision_a)]
        snapshot = copy.deepcopy((items, self.policy, self.sp, self.ring))
        self.batch_report(items)
        self.assertEqual((items, self.policy, self.sp, self.ring), snapshot)


class AggregationValidationTest(ForkDecisionAggregateFixtures):
    def test_items_container_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.make_aggregate("x")
        with self.assertRaises(TypeError):
            self.make_aggregate(["x"])
        with self.assertRaises(TypeError):
            self.make_aggregate([decision_item(1, self.decision_a)])
        with self.assertRaises(TypeError):
            self.make_aggregate([decision_item("a", 1)])
        with self.assertRaises(ValueError):
            self.make_aggregate([])
        with self.assertRaises(ValueError):
            self.make_aggregate([decision_item("", self.decision_a)])
        with self.assertRaises(ValueError):
            self.make_aggregate([
                decision_item("a", self.decision_a),
                decision_item("a", self.decision_b),
            ])
        with self.assertRaises(ValueError):
            self.make_aggregate([
                {"id": "a", "decision": self.decision_a, "x": 1},
            ])

    def test_policy_faults(self):
        items = self.decision_items()
        with self.assertRaises(ValueError):
            aggregate_prune_fork_decisions(
                items, {"batch": "x"}, self.sp, self.dsp, self.ring,
                self.m, JUDGE, 1)
        with self.assertRaises(ValueError):
            self.make_aggregate(items, sp={"sites": {SITE_A: {1}}})
        with self.assertRaises(ValueError):
            self.make_aggregate(items, dsp={"sites": {JUDGE: {1}}})
        with self.assertRaises(ValueError):
            self.make_aggregate(items, dsp={"sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_aggregate(
                items, dsp={"sites": {JUDGE: [1]}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_aggregate(
                items, dsp={"sites": {JUDGE: {True}}, "threshold": 1})
        with self.assertRaises(ValueError):
            self.make_aggregate(
                items, dsp={"sites": {JUDGE: {0}}, "threshold": 1})
        with self.assertRaises(ValueError):
            self.make_aggregate(
                items, dsp={"sites": {JUDGE: set()}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_aggregate(
                items, dsp={"sites": {JUDGE: {1}}, "threshold": True})
        with self.assertRaises(ValueError):
            self.make_aggregate(
                items, dsp={"sites": {JUDGE: {1}}, "threshold": 0})
        with self.assertRaises(ValueError):
            self.make_aggregate(
                items, dsp={"sites": {JUDGE: {1}}, "threshold": 2})

    def test_moment_issuer_version_rules(self):
        items = self.decision_items()
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
        items = self.decision_items()
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
        items = self.decision_items()
        snapshot = copy.deepcopy(
            (items, self.policy, self.sp, self.dsp, self.ring))
        self.make_aggregate(items)
        self.assertEqual(
            (items, self.policy, self.sp, self.dsp, self.ring), snapshot)


class PerItemRulingTest(ForkDecisionAggregateFixtures):
    def rows_by_id(self, items, **kwargs):
        payload = self.aggregate_payload(items, **kwargs)
        return {row["id"]: row for row in payload["items"]}

    def test_invalid_decision_is_rejected_alone_and_processing_continues(self):
        rows = self.rows_by_id([
            decision_item("good", self.decision_a),
            decision_item("bad", b"{}"),
            decision_item("good2", self.decision_b),
        ])
        bad = rows["bad"]
        self.assertEqual(bad["conclusion"], "invalid")
        self.assertEqual(bad["reason"], "invalid")
        self.assertIsNone(bad["issuer"])
        self.assertIsNone(bad["keyVersion"])
        self.assertIsNone(bad["declaration"])
        self.assertEqual(rows["good"]["conclusion"], "valid")
        self.assertEqual(rows["good2"]["conclusion"], "valid")

    def test_tampered_decision_binding_is_invalid_without_identity(self):
        payload = parse(self.decision_a)["payload"]
        payload["status"] = "insufficient"
        forged = rewrap(payload)
        rows = self.rows_by_id([decision_item("x", forged)])
        self.assertEqual(rows["x"]["reason"], "invalid")
        self.assertIsNone(rows["x"]["issuer"])

    def test_unauthenticated_states_keep_identity(self):
        # The decision issuer (JUDGE_B) is sabotaged; the aggregate
        # itself is still signed by JUDGE.
        dsp = decision_site_policy(sites=(JUDGE_B,), threshold=1)
        cases = [
            {JUDGE_B: [entry(2, "77" * 32)]},
            {JUDGE_B: [entry(1, SECRET_COORD, revoked=True)]},
            {JUDGE_B: [entry(1, SECRET_COORD, not_before=self.m + 1)]},
            {JUDGE_B: [entry(1, SECRET_COORD, not_after=self.m - 1)]},
        ]
        for overrides in cases:
            ring = dict(self.ring)
            ring.update(overrides)
            rows = self.rows_by_id(
                [decision_item("x", self.decision_b)], dsp=dsp, ring=ring,
            )
            self.assertEqual(rows["x"]["conclusion"], "invalid")
            self.assertEqual(rows["x"]["reason"], "unauthenticated")
            self.assertEqual(rows["x"]["issuer"], JUDGE_B)
            self.assertEqual(rows["x"]["keyVersion"], 1)
            self.assertIsNone(rows["x"]["declaration"])

        # A wrong HMAC is unauthenticated too.
        forged = rewrap(parse(self.decision_b)["payload"], secret="77" * 32)
        rows = self.rows_by_id([decision_item("x", forged)], dsp=dsp)
        self.assertEqual(rows["x"]["reason"], "unauthenticated")
        self.assertEqual(rows["x"]["issuer"], JUDGE_B)

    def test_unauthorized_site_and_version_keep_identity(self):
        dsp = decision_site_policy(sites=(JUDGE_B,), threshold=1)
        rows = self.rows_by_id([decision_item("x", self.decision_a)],
                               dsp=dsp)
        self.assertEqual(rows["x"]["reason"], "unauthorized")
        self.assertEqual(rows["x"]["issuer"], JUDGE)
        self.assertIsNone(rows["x"]["declaration"])

        dsp = {"sites": {JUDGE: {2}}, "threshold": 1}
        rows = self.rows_by_id([decision_item("x", self.decision_a)],
                               dsp=dsp)
        self.assertEqual(rows["x"]["reason"], "unauthorized")
        self.assertEqual(rows["x"]["keyVersion"], 1)

    def test_identical_declarations_from_one_site_are_duplicates(self):
        dsp = decision_site_policy(sites=(JUDGE,), threshold=1)
        payload = self.aggregate_payload([
            decision_item("first", self.decision_a),
            decision_item("second", self.make_decision(
                self.proofs, issuer=JUDGE)),
        ], dsp=dsp)
        rows = {row["id"]: row for row in payload["items"]}
        self.assertEqual(rows["first"]["conclusion"], "valid")
        self.assertIsNone(rows["first"]["reason"])
        self.assertEqual(rows["second"]["conclusion"], "duplicate")
        self.assertEqual(rows["second"]["reason"], "duplicate")
        self.assertEqual(payload["status"], "accepted")

    def test_same_site_distinct_declarations_contradict(self):
        other_proofs = [
            proof_item("x", self.proof(self.items_two, issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]
        dsp = decision_site_policy(sites=(JUDGE,), threshold=1)
        payload = self.aggregate_payload([
            decision_item("a", self.decision_a),
            decision_item("b", self.make_decision(other_proofs,
                                                  issuer=JUDGE)),
        ], dsp=dsp)
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])
        for row in payload["items"]:
            self.assertEqual(row["conclusion"], "contradiction")
            self.assertEqual(row["reason"], "contradiction")
            self.assertEqual(row["issuer"], JUDGE)


class AggregationTallyTest(ForkDecisionAggregateFixtures):
    def test_accepted_binds_the_common_declaration(self):
        payload = self.aggregate_payload(self.decision_items())
        self.assertEqual(payload["status"], "accepted")
        declaration = payload["declaration"]
        self.assertEqual(list(declaration.keys()), DECLARATION_KEYS)
        self.assertEqual(declaration["status"], "accepted")
        self.assertIsNotNone(declaration["common"])
        self.assertEqual(
            declaration["proofs"],
            parse(self.decision_a)["payload"]["proofs"],
        )
        for item in declaration["conclusions"]:
            self.assertEqual(list(item.keys()), DECLARATION_ENTRY_KEYS)

    def test_below_threshold_is_insufficient_but_keeps_declaration(self):
        payload = self.aggregate_payload(
            [decision_item("one", self.decision_a)])
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNotNone(payload["declaration"])
        accepted = self.aggregate_payload(self.decision_items())
        self.assertEqual(payload["declaration"], accepted["declaration"])

    def test_no_valid_vote_binds_null_declaration(self):
        payload = self.aggregate_payload([
            decision_item("a", b"{}"), decision_item("b", b"{"),
        ])
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNone(payload["declaration"])

    def test_cross_site_disagreement_is_conflicted(self):
        other_proofs = [
            proof_item("x", self.proof(self.items_two, issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]
        payload = self.aggregate_payload([
            decision_item("a", self.decision_a),
            decision_item("b", self.make_decision(other_proofs,
                                                  issuer=JUDGE_B)),
        ])
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])
        self.assertTrue(
            all(row["conclusion"] == "valid" for row in payload["items"])
        )

    def test_conflict_is_not_outvotable(self):
        other_proofs = [
            proof_item("x", self.proof(self.items_two, issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]
        dsp = decision_site_policy(sites=(JUDGE, JUDGE_B, SITE_A),
                                   threshold=2)
        payload = self.aggregate_payload([
            decision_item("a", self.decision_a),
            decision_item("b", self.decision_b),
            decision_item("c", self.make_decision(other_proofs,
                                                  issuer=SITE_A)),
        ], dsp=dsp)
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])

    def test_only_valid_rows_count_toward_the_threshold(self):
        payload = self.aggregate_payload([
            decision_item("a", self.decision_a),
            decision_item("bad", b"{}"),
        ])
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNotNone(payload["declaration"])

    def test_rows_sort_by_issuer_then_id_with_invalid_first(self):
        payload = self.aggregate_payload([
            decision_item("z", self.decision_b),
            decision_item("a", self.decision_a),
            decision_item("m", b"{}"),
        ])
        keys = [
            (row["issuer"] is not None, row["issuer"], row["id"])
            for row in payload["items"]
        ]
        self.assertEqual(keys, sorted(keys))
        self.assertIsNone(payload["items"][0]["issuer"])


class AggregatePacketShapeTest(ForkDecisionAggregateFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = self.decision_items()
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

    def test_row_shapes(self):
        payload = parse(self.raw)["payload"]
        for row in payload["items"]:
            self.assertEqual(list(row.keys()), AGGREGATE_ROW_KEYS)
            self.assertEqual(
                row["digest"],
                hashlib.sha256(
                    self.decision_a if row["id"] == "one"
                    else self.decision_b
                ).hexdigest(),
            )

    def test_inputs_bound_in_original_order(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(payload["inputs"], [
            hashlib.sha256(self.decision_a).hexdigest(),
            hashlib.sha256(self.decision_b).hexdigest(),
        ])
        reversed_raw = self.make_aggregate(list(reversed(self.items)))
        self.assertEqual(
            parse(reversed_raw)["payload"]["inputs"],
            list(reversed(payload["inputs"])),
        )

    def test_policy_digest_bindings(self):
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
        self.assertEqual(
            payload["sitePolicyDigest"],
            hashlib.sha256(compact({
                "sites": {
                    site: sorted(self.sp["sites"][site])
                    for site in sorted(self.sp["sites"])
                },
                "threshold": self.sp["threshold"],
            })).hexdigest(),
        )
        self.assertEqual(
            payload["decisionSitePolicyDigest"],
            hashlib.sha256(compact({
                "sites": {
                    site: sorted(self.dsp["sites"][site])
                    for site in sorted(self.dsp["sites"])
                },
                "threshold": self.dsp["threshold"],
            })).hexdigest(),
        )

    def test_identity_version_and_declaration_bindings(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["status"], "accepted")
        declaration = payload["declaration"]
        self.assertEqual(declaration["status"], "accepted")
        decision_payload = parse(self.decision_a)["payload"]
        self.assertEqual(declaration["common"], decision_payload["common"])
        self.assertEqual(declaration["proofs"], decision_payload["proofs"])
        keys = [
            (entry["issuer"] is not None, entry["issuer"], entry["id"])
            for entry in declaration["conclusions"]
        ]
        self.assertEqual(keys, sorted(keys))


class AggregateVerifySuccessTest(AggregatePacketShapeTest):
    def test_result_is_fresh_fixed_key_mapping(self):
        result = self.verify_aggregate(self.raw)
        self.assertEqual(list(result.keys()), AGGREGATE_RESULT_KEYS)
        self.assertEqual(result["aggregateDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["inputs"],
                         parse(self.raw)["payload"]["inputs"])

    def test_repeated_calls_share_no_mutable_structure(self):
        first = self.verify_aggregate(self.raw)
        second = self.verify_aggregate(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["declaration"], second["declaration"])
        first["items"][0]["id"] = "tampered"
        first["declaration"]["conclusions"][0]["id"] = "tampered"
        third = self.verify_aggregate(self.raw)
        self.assertEqual(third["items"][0]["id"],
                         second["items"][0]["id"])
        self.assertEqual(third["declaration"]["conclusions"][0]["id"],
                         second["declaration"]["conclusions"][0]["id"])


class AggregateVerifyStructureTest(AggregatePacketShapeTest):
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
                self.raw, "x", self.sp, self.dsp, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, "x", self.dsp, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, self.sp, "x", self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, self.sp, self.dsp, "ring", self.m)

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
        payload["inputs"] = ["z" * 64]
        self.assert_invalid(rewrap(payload))

    def test_row_and_declaration_shape_faults(self):
        payload = parse(self.raw)["payload"]
        payload["items"][0]["extra"] = 1
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["items"][0]["declaration"] = None
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        del payload["items"][0]["declaration"]["proofs"]
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        entry = payload["items"][0]["declaration"]["conclusions"][0]
        entry["reason"] = "duplicate"
        self.assert_invalid(rewrap(payload))

    def test_duplicate_keys_and_non_canonical_form(self):
        text = self.raw.decode("utf-8")
        marker = '"version":1'
        duplicated = text.replace(marker, marker + "," + marker, 1).encode()
        self.assert_invalid(duplicated)
        pretty = json.dumps(parse(self.raw), indent=2)
        self.assert_invalid(pretty.encode())


class AggregateVerifyBindingTest(AggregatePacketShapeTest):
    def assert_invalid(self, payload):
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            self.verify_aggregate(rewrap(payload))

    def test_wrong_prune_policy(self):
        other = copy.deepcopy(self.policy)
        other["batch"] = "other-batch"
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_prune_fork_decision_aggregate(
                self.raw, other, self.sp, self.dsp, self.ring, self.m)

    def test_wrong_site_policies(self):
        other = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, other, self.dsp, self.ring, self.m)
        other_dsp = decision_site_policy(sites=(JUDGE,), threshold=1)
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_prune_fork_decision_aggregate(
                self.raw, self.policy, self.sp, other_dsp, self.ring,
                self.m)

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

    def test_input_digest_bindings(self):
        payload = parse(self.raw)["payload"]
        payload["inputs"][0] = "cc" * 32
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["items"][0]["digest"] = "dd" * 32
        self.assert_invalid(payload)

    def test_rows_must_stay_sorted(self):
        payload = parse(self.raw)["payload"]
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(payload)

    def test_declaration_must_re_tally_as_a_decision(self):
        payload = parse(self.raw)["payload"]
        declaration = payload["items"][0]["declaration"]
        declaration["status"] = "insufficient"
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        declaration = payload["items"][0]["declaration"]
        declaration["conclusions"][0]["conclusion"] = "duplicate"
        declaration["conclusions"][0]["reason"] = "duplicate"
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        declaration = payload["items"][0]["declaration"]
        declaration["proofs"][0] = "ee" * 32
        self.assert_invalid(payload)

    def test_common_declaration_must_match_the_tally(self):
        payload = parse(self.raw)["payload"]
        payload["declaration"]["status"] = "insufficient"
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["declaration"] = None
        self.assert_invalid(payload)


class AggregateVerifyAuthenticationTest(AggregatePacketShapeTest):
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
                    self.raw, self.policy, self.sp, self.dsp, ring, self.m)

    def test_unknown_aggregator(self):
        ring = {k: v for k, v in self.ring.items() if k != JUDGE}
        with self.assertRaises(AuthenticationError):
            self.verify_aggregate(self.raw, ring=ring)

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        self.assertTrue(issubclass(
            InvalidAggregateForkDecisionAggregateError, ValueError))


if __name__ == "__main__":
    unittest.main()
