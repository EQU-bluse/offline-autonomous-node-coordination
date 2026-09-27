"""Tests for multi-site adjudication over prune aggregate fork proofs.

Covers :func:`verify_prune_aggregate_fork_proofs`,
:func:`adjudicate_prune_aggregate_forks` and
:func:`verify_prune_aggregate_fork_decision`: the batch container and
shared materials validated in full before any proof is verified, the
per-proof verified/invalid-proof/unauthenticated taxonomy with
input-order reports and no cross-proof interference, the
verify-then-authorize-then-authenticate per-proof pipeline with its
fixed reasons, same-site duplicate/contradiction handling over the
complete fork edge set, cross-site edge-set agreement, threshold
acceptance with the common set kept on insufficient tallies, the
canonical signed decision and its bindings, the offline re-tally
verification and adjudicator credential rules, the error hierarchies,
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
    InvalidAggregateForkDecisionError,
    InvalidAggregateForkProofError,
    adjudicate_prune_aggregate_forks,
    verify_prune_aggregate_fork_decision,
    verify_prune_aggregate_fork_proofs,
)

from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_prune_aggregate_chains import PruneAggregateChainBatchFixtures

PROOF_ITEM_KEYS = {"id", "proof"}
BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
DECISION_KEYS = ["payload", "signature"]
DECISION_PAYLOAD_KEYS = [
    "common", "issuer", "items", "keyVersion", "proofs",
    "prunePolicyDigest", "sitePolicyDigest", "status", "version",
]
ROW_KEYS = ["conclusion", "digest", "edges", "id", "issuer",
            "keyVersion", "reason"]
EDGE_KEYS = ["predecessorDigest", "rootDigest", "successors"]
DECISION_RESULT_KEYS = [
    "common", "proofDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "proofs", "sitePolicyDigest", "status", "version",
]


def proof_item(item_id, proof):
    """One batch item: a batch-unique id and proof bytes."""
    return {"id": item_id, "proof": proof}


def site_policy(sites=(SITE_A, SITE_B, SITE_C), threshold=2):
    return {"sites": {site: {1} for site in sites}, "threshold": threshold}


def rewrap(payload, secret=SECRET_COORD):
    signature = __import__("hmac").new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


class PruneAggregateForkAdjudicationFixtures(PruneAggregateChainBatchFixtures):
    """Forking chain batches, signed fork proofs and adjudication helpers."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.m = self.moment + 20
        self.items_one = self.fork_items()
        # A second forking chain batch with a distinct successor pair.
        self.items_two = [
            self.citem("b", self.root_one, [self.first_a]),
            self.citem("c", self.root_one, [self.first_c]),
        ]
        self.sp = site_policy()

    def proof(self, items=None, issuer=SITE_A, moment=None):
        return self.sign_proof(
            self.items_one if items is None else items,
            moment=self.m if moment is None else moment,
            issuer=issuer,
        )

    def make_decision(self, items, sp=None, ring=None, moment=None,
               issuer=JUDGE, version=1):
        return adjudicate_prune_aggregate_forks(
            items, self.policy, self.sp if sp is None else sp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def verify_decision(self, raw, sp=None, ring=None, moment=None):
        return verify_prune_aggregate_fork_decision(
            raw, self.policy, self.sp if sp is None else sp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def proofs_report(self, items):
        return verify_prune_aggregate_fork_proofs(
            items, self.policy, self.ring, self.m
        )


class BatchVerificationTest(PruneAggregateForkAdjudicationFixtures):
    def test_verified_reports_in_input_order(self):
        p_a = self.proof(issuer=SITE_A)
        p_b = self.proof(issuer=SITE_B)
        report = self.proofs_report([
            proof_item("a", p_a), proof_item("b", b"{}"),
            proof_item("c", p_b),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual([row["id"] for row in report["items"]],
                         ["a", "b", "c"])
        statuses = [row["status"] for row in report["items"]]
        self.assertEqual(statuses,
                         ["verified", "invalid-proof", "verified"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), ITEM_REPORT_KEYS)
        self.assertIsNone(report["items"][0]["error"])
        self.assertEqual(
            report["items"][0]["result"]["proofDigest"],
            hashlib.sha256(p_a).hexdigest(),
        )
        bad = report["items"][1]
        self.assertIsNone(bad["result"])
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")

    def test_unauthenticated_is_isolated(self):
        ring = {
            site: [entry(1, "77" * 32)]
            for site in (SITE_A, SITE_B, SITE_C, JUDGE)
        }
        p_a = self.proof(issuer=SITE_A)
        p_b = self.proof(issuer=SITE_B)
        report = self.proofs_report  # bound materials first, then per item
        report = verify_prune_aggregate_fork_proofs(
            [proof_item("a", p_a), proof_item("b", p_b)],
            self.policy, ring, self.m,
        )
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["unauthenticated", "unauthenticated"],
        )
        self.assertTrue(all(row["error"] for row in report["items"]))

    def test_structure_validated_upfront(self):
        p_a = self.proof(issuer=SITE_A)
        with self.assertRaises(TypeError):
            self.proofs_report("x")
        with self.assertRaises(TypeError):
            self.proofs_report(["x"])
        with self.assertRaises(ValueError):
            self.proofs_report([])
        with self.assertRaises(ValueError):
            self.proofs_report([
                proof_item("a", p_a), proof_item("a", p_a),
            ])
        with self.assertRaises(ValueError):
            self.proofs_report([{"id": "a", "proof": p_a, "x": 1}])
        with self.assertRaises(ValueError):
            self.proofs_report([proof_item("", p_a)])
        with self.assertRaises(TypeError):
            self.proofs_report([proof_item(1, p_a)])
        with self.assertRaises(TypeError):
            self.proofs_report([proof_item("a", "x")])

    def test_shared_materials_validated_upfront(self):
        p_a = self.proof(issuer=SITE_A)
        items = [proof_item("a", p_a)]
        with self.assertRaises(ValueError):
            verify_prune_aggregate_fork_proofs(items, {"batch": "x"},
                                              self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_fork_proofs(items, self.policy,
                                              "ring", self.m)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_fork_proofs(items, self.policy,
                                              self.ring, True)
        with self.assertRaises(ValueError):
            verify_prune_aggregate_fork_proofs(items, self.policy,
                                              self.ring, -1)

    def test_batch_fault_surfaces_even_when_a_proof_is_bad(self):
        with self.assertRaises(ValueError):
            verify_prune_aggregate_fork_proofs(
                [proof_item("a", b"{}"), proof_item("a", b"{}")],
                self.policy, self.ring, self.m,
            )

    def test_results_are_fresh_and_independent(self):
        p_a = self.proof(issuer=SITE_A)
        first = self.proofs_report([proof_item("a", p_a)])
        second = self.proofs_report([proof_item("a", p_a)])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.proofs_report([proof_item("a", p_a)])["items"][0][
                "result"]["issuer"],
            SITE_A,
        )

    def test_inputs_are_not_modified(self):
        p_a = self.proof(issuer=SITE_A)
        items = [proof_item("a", p_a)]
        snapshot = copy.deepcopy((items, self.policy, self.ring))
        self.proofs_report(items)
        self.assertEqual((items, self.policy, self.ring), snapshot)


class AdjudicationValidationTest(PruneAggregateForkAdjudicationFixtures):
    def test_items_container_faults(self):
        p_a = self.proof(issuer=SITE_A)
        with self.assertRaises(TypeError):
            self.make_decision("x")
        with self.assertRaises(TypeError):
            self.make_decision(["x"])
        with self.assertRaises(TypeError):
            self.make_decision([proof_item(1, p_a)])
        with self.assertRaises(TypeError):
            self.make_decision([proof_item("a", 1)])

    def test_items_value_faults(self):
        p_a = self.proof(issuer=SITE_A)
        with self.assertRaises(ValueError):
            self.make_decision([])
        with self.assertRaises(ValueError):
            self.make_decision([proof_item("", p_a)])
        with self.assertRaises(ValueError):
            self.make_decision([proof_item("a", p_a), proof_item("a", p_a)])
        with self.assertRaises(ValueError):
            self.make_decision([{"id": "a", "proof": p_a, "x": 1}])

    def test_policy_faults(self):
        p_a = self.proof(issuer=SITE_A)
        items = [proof_item("a", p_a)]
        with self.assertRaises(ValueError):
            self.make_decision(items, sp={"sites": {SITE_A: {1}}})
        with self.assertRaises(ValueError):
            self.make_decision(items, sp={"sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_decision(items, sp={"sites": {SITE_A: [1]}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_decision(items, sp={"sites": {SITE_A: {True}},
                                   "threshold": 1})
        with self.assertRaises(ValueError):
            self.make_decision(items, sp={"sites": {SITE_A: {0}},
                                   "threshold": 1})
        with self.assertRaises(ValueError):
            self.make_decision(items, sp={"sites": {SITE_A: set()},
                                   "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_decision(items, sp={"sites": {SITE_A: {1}},
                                   "threshold": True})
        with self.assertRaises(ValueError):
            self.make_decision(items, sp={"sites": {SITE_A: {1}},
                                   "threshold": 0})
        with self.assertRaises(ValueError):
            self.make_decision(items, sp={"sites": {SITE_A: {1}},
                                   "threshold": 2})
    def test_prune_policy_faults(self):
        p_a = self.proof(issuer=SITE_A)
        items = [proof_item("a", p_a)]
        with self.assertRaises(ValueError):
            adjudicate_prune_aggregate_forks(
                items, {"batch": "x"}, self.sp, self.ring, self.m, JUDGE, 1)

    def test_moment_issuer_version_rules(self):
        p_a = self.proof(issuer=SITE_A)
        items = [proof_item("a", p_a)]
        with self.assertRaises(TypeError):
            self.make_decision(items, moment=True)
        with self.assertRaises(ValueError):
            self.make_decision(items, moment=-1)
        with self.assertRaises(TypeError):
            self.make_decision(items, issuer=7)
        with self.assertRaises(ValueError):
            self.make_decision(items, issuer="")
        with self.assertRaises(TypeError):
            self.make_decision(items, version=True)
        with self.assertRaises(ValueError):
            self.make_decision(items, version=0)

    def test_signing_credentials_have_no_fallback(self):
        p_a = self.proof(issuer=SITE_A)
        items = [proof_item("a", p_a)]
        with self.assertRaises(AuthenticationError):
            self.make_decision(items, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.make_decision(items, issuer=JUDGE, version=2)
        revoked = dict(self.ring)
        revoked[JUDGE] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            self.make_decision(items, ring=revoked)
        future = dict(self.ring)
        future[JUDGE] = [entry(1, SECRET_COORD, not_before=self.m + 1)]
        with self.assertRaises(AuthenticationError):
            self.make_decision(items, ring=future)
        expired = dict(self.ring)
        expired[JUDGE] = [entry(1, SECRET_COORD, not_after=self.m - 1)]
        with self.assertRaises(AuthenticationError):
            self.make_decision(items, ring=expired)

    def test_inputs_are_not_modified(self):
        p_a = self.proof(issuer=SITE_A)
        p_b = self.proof(issuer=SITE_B)
        items = [proof_item("x", p_a), proof_item("y", p_b)]
        snapshot = copy.deepcopy((items, self.policy, self.sp, self.ring))
        self.make_decision(items)
        self.assertEqual((items, self.policy, self.sp, self.ring), snapshot)


class PerItemRulingTest(PruneAggregateForkAdjudicationFixtures):
    def rows(self, items, sp=None):
        raw = self.make_decision(items, sp=sp)
        return self.verify_decision(raw, sp=sp)["items"]

    def row_by_id(self, items, sp=None):
        return {row["id"]: row for row in self.rows(items, sp)}

    def test_invalid_bytes_are_rejected_alone_and_processing_continues(self):
        p_b = self.proof(issuer=SITE_B)
        rows = self.row_by_id([
            proof_item("good", self.proof(issuer=SITE_A)),
            proof_item("bad", b"{}"),
            proof_item("good2", p_b),
        ])
        bad = rows["bad"]
        self.assertEqual(bad["conclusion"], "invalid")
        self.assertEqual(bad["reason"], "invalid-proof")
        self.assertIsNone(bad["issuer"])
        self.assertIsNone(bad["keyVersion"])
        self.assertIsNone(bad["edges"])
        self.assertEqual(rows["good"]["conclusion"], "valid")
        self.assertEqual(rows["good2"]["conclusion"], "valid")

    def test_empty_proof_bytes_are_invalid_proof_without_identity(self):
        rows = self.rows([proof_item("e", b"")])
        self.assertEqual(rows[0]["reason"], "invalid-proof")
        self.assertIsNone(rows[0]["issuer"])

    def test_unauthorized_site_keeps_identity_and_edges(self):
        pol = site_policy(sites=(SITE_B, SITE_C))
        rows = self.row_by_id([
            proof_item("x", self.proof(issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ], sp=pol)
        self.assertEqual(rows["x"]["reason"], "unauthorized-site")
        self.assertEqual(rows["x"]["issuer"], SITE_A)
        self.assertIsNotNone(rows["x"]["edges"])
        self.assertEqual(rows["y"]["conclusion"], "valid")

    def test_unauthorized_version(self):
        pol = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        pol["sites"][SITE_A] = {2}
        rows = self.row_by_id([
            proof_item("x", self.proof(issuer=SITE_A)),
        ], sp=pol)
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
        for overrides, reason in cases:
            ring = dict(self.ring)
            ring.update(overrides)
            raw = self.make_decision(
                [proof_item("x", self.proof(issuer=SITE_A))],
                sp=pol, ring=ring,
            )
            rows = self.verify_decision(raw, sp=pol, ring=ring)["items"]
            self.assertEqual(rows[0]["reason"], reason)

        # A wrong HMAC keeps identity and edges and is bad-signature.
        forged = rewrap(parse(self.proof(issuer=SITE_A))["payload"],
                        secret="77" * 32)
        rows = self.row_by_id([proof_item("x", forged)], sp=pol)
        self.assertEqual(rows["x"]["reason"], "bad-signature")
        self.assertEqual(rows["x"]["issuer"], SITE_A)
        self.assertIsNotNone(rows["x"]["edges"])

    def test_foreign_policy_and_future_proofs_are_invalid_without_identity(self):
        # A structurally fine proof whose bytes were rewrapped with a
        # foreign policy digest cannot be trusted to name a site.
        payload = parse(self.proof(issuer=SITE_A))["payload"]
        payload["policy"] = "bb" * 32
        forged = rewrap(payload)
        rows = self.row_by_id([proof_item("x", forged)])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])
        future = self.proof(issuer=SITE_A, moment=self.m + 10)
        rows = self.row_by_id([proof_item("x", future)])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])

    def test_identical_proof_digests_are_duplicates(self):
        p_a = self.proof(issuer=SITE_A)
        pol = site_policy(sites=(SITE_A,), threshold=1)
        raw = self.make_decision([
            proof_item("first", p_a), proof_item("second", p_a),
        ], sp=pol)
        result = self.verify_decision(raw, sp=pol)
        rows = {row["id"]: row for row in result["items"]}
        self.assertEqual(rows["first"]["conclusion"], "valid")
        self.assertIsNone(rows["first"]["reason"])
        self.assertEqual(rows["second"]["conclusion"], "duplicate")
        self.assertEqual(rows["second"]["reason"], "duplicate")
        self.assertEqual(result["status"], "accepted")

    def test_same_edge_set_distinct_proof_digests_still_duplicates(self):
        one = self.proof(issuer=SITE_A, moment=self.m)
        two = self.proof(issuer=SITE_A, moment=self.m - 5)
        self.assertNotEqual(one, two)
        pol = site_policy(sites=(SITE_A,), threshold=1)
        raw = self.make_decision([
            proof_item("x", one), proof_item("y", two),
        ], sp=pol)
        result = self.verify_decision(raw, sp=pol)
        rows = {row["id"]: row for row in result["items"]}
        self.assertEqual(rows["x"]["conclusion"], "valid")
        self.assertEqual(rows["y"]["conclusion"], "duplicate")
        self.assertEqual(result["status"], "accepted")

    def test_duplicates_alone_cannot_meet_threshold_two(self):
        p_a = self.proof(issuer=SITE_A)
        pol = site_policy(sites=(SITE_A, SITE_B), threshold=2)
        raw = self.make_decision([
            proof_item("a", p_a), proof_item("b", p_a),
        ], sp=pol)
        result = self.verify_decision(raw, sp=pol)
        self.assertEqual(result["status"], "insufficient")

    def test_same_site_distinct_edge_sets_contradict(self):
        pol = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        raw = self.make_decision([
            proof_item("a", self.proof(self.items_one, issuer=SITE_A)),
            proof_item("b", self.proof(self.items_two, issuer=SITE_A)),
        ], sp=pol)
        result = self.verify_decision(raw, sp=pol)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        for row in result["items"]:
            self.assertEqual(row["conclusion"], "contradiction")
            self.assertEqual(row["reason"], "contradiction")
            self.assertEqual(row["issuer"], SITE_A)


class AggregationTest(PruneAggregateForkAdjudicationFixtures):
    def test_accepted_binds_the_common_edge_set(self):
        raw = self.make_decision([
            proof_item("x", self.proof(issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ])
        result = self.verify_decision(raw)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(result["common"]), 1)
        edge = result["common"][0]
        self.assertEqual(list(edge.keys()), EDGE_KEYS)
        self.assertEqual(len(edge["successors"]), 2)
        self.assertEqual(edge["successors"], sorted(edge["successors"]))

    def test_below_threshold_is_insufficient_but_keeps_common(self):
        raw = self.make_decision([proof_item("x", self.proof(issuer=SITE_A))])
        result = self.verify_decision(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["common"])
        accepted = self.verify_decision(self.make_decision([
            proof_item("x", self.proof(issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]))
        self.assertEqual(result["common"], accepted["common"])

    def test_no_valid_vote_binds_null_common(self):
        raw = self.make_decision([
            proof_item("x", b"{}"), proof_item("y", b"{"),
        ])
        result = self.verify_decision(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["common"])

    def test_cross_site_edge_disagreement_is_conflicted(self):
        raw = self.make_decision([
            proof_item("x", self.proof(self.items_one, issuer=SITE_A)),
            proof_item("y", self.proof(self.items_two, issuer=SITE_B)),
        ])
        result = self.verify_decision(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        # Rows themselves stay valid -- the disagreement is between sites.
        self.assertTrue(
            all(row["conclusion"] == "valid" for row in result["items"])
        )

    def test_conflict_is_not_outvotable(self):
        pol = site_policy(threshold=2)
        # Two sites back edge set one, one site backs edge set two.
        raw = self.make_decision([
            proof_item("a", self.proof(self.items_one, issuer=SITE_A)),
            proof_item("b", self.proof(self.items_one, issuer=SITE_B)),
            proof_item("c", self.proof(self.items_two, issuer=SITE_C)),
        ], sp=pol)
        result = self.verify_decision(raw, sp=pol)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])

    def test_only_valid_rows_count_toward_the_threshold(self):
        raw = self.make_decision([
            proof_item("x", self.proof(issuer=SITE_A)),
            proof_item("bad", b"{}"),
        ])
        result = self.verify_decision(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["common"])

    def test_rows_sort_by_issuer_then_id_with_invalid_first(self):
        raw = self.make_decision([
            proof_item("z", self.proof(issuer=SITE_B)),
            proof_item("a", self.proof(issuer=SITE_A)),
            proof_item("m", b"{}"),
        ])
        result = self.verify_decision(raw)
        keys = [
            (row["issuer"] is not None, row["issuer"], row["id"])
            for row in result["items"]
        ]
        self.assertEqual(keys, sorted(keys))
        self.assertIsNone(result["items"][0]["issuer"])


class PacketShapeTest(PruneAggregateForkAdjudicationFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.p_a = self.proof(issuer=SITE_A)
        self.p_b = self.proof(issuer=SITE_B)
        self.items = [proof_item("x", self.p_a), proof_item("y", self.p_b)]
        self.raw = self.make_decision(self.items)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(parse(self.raw)), self.raw)

    def test_top_and_payload_key_sets(self):
        data = parse(self.raw)
        self.assertEqual(set(data.keys()), set(DECISION_KEYS))
        self.assertEqual(list(data["payload"].keys()), DECISION_PAYLOAD_KEYS)

    def test_row_and_edge_shapes(self):
        payload = parse(self.raw)["payload"]
        for row in payload["items"]:
            self.assertEqual(list(row.keys()), ROW_KEYS)
            self.assertEqual(
                row["digest"],
                hashlib.sha256(
                    self.p_a if row["id"] == "x" else self.p_b
                ).hexdigest(),
            )
            for edge in row["edges"]:
                self.assertEqual(list(edge.keys()), EDGE_KEYS)

    def test_proofs_bound_in_original_order(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(payload["proofs"], [
            hashlib.sha256(self.p_a).hexdigest(),
            hashlib.sha256(self.p_b).hexdigest(),
        ])
        reversed_raw = self.make_decision(list(reversed(self.items)))
        self.assertEqual(
            parse(reversed_raw)["payload"]["proofs"],
            list(reversed(payload["proofs"])),
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

    def test_identity_version_and_common_bindings(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["common"][0]["rootDigest"],
                         payload["items"][0]["edges"][0]["rootDigest"])


class VerifySuccessTest(PacketShapeTest):
    def test_result_is_fresh_fixed_key_mapping(self):
        result = self.verify_decision(self.raw)
        self.assertEqual(list(result.keys()), DECISION_RESULT_KEYS)
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["proofs"],
                         parse(self.raw)["payload"]["proofs"])

    def test_repeated_calls_share_no_mutable_structure(self):
        first = self.verify_decision(self.raw)
        second = self.verify_decision(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        first["items"][0]["id"] = "tampered"
        first["common"][0]["successors"].append("zz" * 32)
        third = self.verify_decision(self.raw)
        self.assertEqual(third["items"][0]["id"], second["items"][0]["id"])
        self.assertEqual(len(third["common"][0]["successors"]), 2)


class VerifyStructureTest(PacketShapeTest):
    def assert_invalid(self, raw):
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.verify_decision(raw)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            self.verify_decision("x")
        with self.assertRaises(TypeError):
            self.verify_decision(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.verify_decision(self.raw, moment=-1)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_fork_decision(
                self.raw, "x", self.sp, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_fork_decision(
                self.raw, self.policy, "x", self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_fork_decision(
                self.raw, self.policy, self.sp, "ring", self.m)

    def test_encoding_faults(self):
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(b"")
        self.assert_invalid(b"{")
        with self.assertRaises(TypeError):
            self.verify_decision(b"[]")

    def test_key_set_and_version_faults(self):
        data = parse(self.raw)
        del data["signature"]
        self.assert_invalid(compact(data))
        payload = parse(self.raw)["payload"]
        del payload["common"]
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
            self.verify_decision(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["items"][0]["keyVersion"] = True
        with self.assertRaises(TypeError):
            self.verify_decision(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["proofs"] = ["z" * 64]
        self.assert_invalid(rewrap(payload))

    def test_duplicate_keys_and_non_canonical_form(self):
        text = self.raw.decode("utf-8")
        marker = '"version":1'
        duplicated = text.replace(marker, marker + "," + marker, 1).encode()
        self.assert_invalid(duplicated)
        pretty = json.dumps(parse(self.raw), indent=2)
        self.assert_invalid(pretty.encode())


class VerifyBindingTest(PacketShapeTest):
    def assert_invalid(self, payload):
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.verify_decision(rewrap(payload))

    def test_wrong_prune_policy(self):
        other = copy.deepcopy(self.policy)
        other["batch"] = "other-batch"
        with self.assertRaises(InvalidAggregateForkDecisionError):
            verify_prune_aggregate_fork_decision(
                self.raw, other, self.sp, self.ring, self.m)

    def test_wrong_site_policy(self):
        other = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        with self.assertRaises(InvalidAggregateForkDecisionError):
            verify_prune_aggregate_fork_decision(
                self.raw, self.policy, other, self.ring, self.m)

    def test_tampered_status_and_common_cannot_be_resigned(self):
        payload = parse(self.raw)["payload"]
        payload["status"] = "insufficient"
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["status"] = "conflicted"
        payload["common"] = None
        self.assert_invalid(payload)

    def test_tampered_row_conclusion_cannot_be_resigned(self):
        payload = parse(self.raw)["payload"]
        payload["items"][0]["conclusion"] = "duplicate"
        payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid(payload)

    def test_proof_digest_bindings(self):
        payload = parse(self.raw)["payload"]
        payload["proofs"][0] = "cc" * 32
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["items"][0]["digest"] = "dd" * 32
        self.assert_invalid(payload)

    def test_rows_must_stay_sorted(self):
        payload = parse(self.raw)["payload"]
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(payload)

    def test_common_must_match_the_tallied_edges(self):
        payload = parse(self.raw)["payload"]
        payload["common"] = []
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["common"][0]["successors"].append("ee" * 32)
        payload["common"][0]["successors"].sort()
        self.assert_invalid(payload)


class VerifyAuthenticationTest(PacketShapeTest):
    def test_signature_mismatch(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.verify_decision(compact(data))

    def test_revoked_future_expired_adjudicator(self):
        cases = [
            {JUDGE: [entry(1, SECRET_COORD, revoked=True)]},
            {JUDGE: [entry(1, SECRET_COORD, not_before=self.m + 1)]},
            {JUDGE: [entry(1, SECRET_COORD, not_after=self.m - 1)]},
        ]
        for overrides in cases:
            ring = dict(self.ring)
            ring.update(overrides)
            with self.assertRaises(AuthenticationError):
                verify_prune_aggregate_fork_decision(
                    self.raw, self.policy, self.sp, ring, self.m)

    def test_unknown_adjudicator(self):
        ring = {k: v for k, v in self.ring.items() if k != JUDGE}
        with self.assertRaises(AuthenticationError):
            self.verify_decision(self.raw, ring=ring)

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        self.assertTrue(
            issubclass(InvalidAggregateForkDecisionError, ValueError))
        self.assertTrue(
            issubclass(InvalidAggregateForkProofError, ValueError))


if __name__ == "__main__":
    unittest.main()
