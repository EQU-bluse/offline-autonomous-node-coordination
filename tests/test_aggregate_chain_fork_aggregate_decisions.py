"""Tests for batch verification and cross-site aggregation of chain fork
aggregate decisions.

Covers :func:`verify_chain_fork_aggregate_decisions`,
:func:`aggregate_chain_fork_aggregate_decisions` and
:func:`verify_chain_fork_decision_aggregate` on the aggregate-decision
family: the decision batch container and shared materials validated in
full before any decision is parsed, the per-decision
verified/invalid/unauthenticated taxonomy with input-order reports and
no cross-decision interference, the verify-then-authenticate-then-
authorize per-decision aggregation pipeline with fixed
invalid/unauthenticated/unauthorized reasons, same-site
duplicate/contradiction handling over the complete declaration (the
common fork edge set, the per-item conclusions sorted by site then id,
the order-independent proof digest sequence and the overall status),
cross-site declaration agreement with no majority override, threshold
acceptance with the common declaration kept on insufficient tallies,
the canonical signed aggregate packet and its three policy digest
bindings (the middle digest is ``authorizationPolicyDigest``), the
offline re-tally verification recomputing every binding plus each
counted declaration, the family dispatch in
:func:`verify_chain_fork_decision_aggregate` (level-1 packets keep
their own taxonomy), the order-independent proof multiset rule that
distinguishes this family from the level-1 aggregate, the
InvalidChainForkDecisionAggregateError hierarchy, equal-but-independent
results, input immutability and the purely offline guarantee.
"""

import copy
import hashlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidChainDecisionAggregateError,
    InvalidChainDecisionError,
    InvalidChainForkDecisionAggregateError,
    adjudicate_chain_fork_aggregate_proofs,
    aggregate_chain_fork_aggregate_decisions,
    verify_chain_fork_aggregate_decision,
    verify_chain_fork_aggregate_decisions,
    verify_chain_fork_decision_aggregate,
)

from test_adjudicate_prune_aggregate_forks import proof_item
from test_aggregate_prune_fork_decisions import (
    decision_item,
    decision_site_policy,
)
from test_chain_fork_aggregate_proofs import ChainForkAggregateFixtures
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_fork_aggregate import rewrap

JUDGE_B = SITE_C
BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
AGGREGATE_KEYS = ["payload", "signature"]
AGGREGATE_PAYLOAD_KEYS = [
    "authorizationPolicyDigest", "decisionSitePolicyDigest", "declaration",
    "inputs", "issuer", "items", "keyVersion", "prunePolicyDigest",
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
    "prunePolicyDigest", "authorizationPolicyDigest",
    "decisionSitePolicyDigest", "declaration", "status", "version",
]
SINGLE_RESULT_KEYS = [
    "common", "proofDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "proofs", "authorizationPolicyDigest",
    "status", "version",
]


class ChainForkAggregateDecisionFixtures(ChainForkAggregateFixtures):
    """Signed chain fork aggregate decisions from two decision sites."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.auth = self.cauth()
        self.dsp = decision_site_policy(sites=(JUDGE, JUDGE_B))
        self.proofs = [
            proof_item("x", self.aproof(issuer=SITE_A)),
            proof_item("y", self.aproof(issuer=SITE_B)),
        ]
        self.decision_a = self.make_decision(self.proofs, issuer=JUDGE)
        self.decision_b = self.make_decision(self.proofs, issuer=JUDGE_B)

    def make_decision(self, items, auth=None, ring=None, moment=None,
                      issuer=JUDGE, version=1):
        # The base setUp chain reaches this override before this class's
        # own setUp assigns ``self.auth``; ``cauth()`` has no fixture
        # dependency, so fall back to it until then.
        auth_policy = auth if auth is not None else getattr(
            self, "auth", None) or self.cauth()
        return adjudicate_chain_fork_aggregate_proofs(
            items, self.policy, self.sp, auth_policy,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def other_proofs(self):
        return [
            proof_item("x", self.aproof(self.cf_items_two, issuer=SITE_A)),
            proof_item("y", self.aproof(issuer=SITE_B)),
        ]

    def decision_items(self):
        return [
            decision_item("one", self.decision_a),
            decision_item("two", self.decision_b),
        ]

    def batch_report(self, items, auth=None, ring=None, moment=None):
        return verify_chain_fork_aggregate_decisions(
            items, self.policy, self.auth if auth is None else auth,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def make_cfaa(self, items, auth=None, dsp=None, ring=None,
                       moment=None, issuer=JUDGE, version=1):
        return aggregate_chain_fork_aggregate_decisions(
            items, self.policy, self.auth if auth is None else auth,
            self.dsp if dsp is None else dsp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def verify_cfaa(self, raw, auth=None, dsp=None, ring=None,
                         moment=None):
        return verify_chain_fork_decision_aggregate(
            raw, self.policy, self.auth if auth is None else auth,
            self.dsp if dsp is None else dsp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def cfaa_payload(self, items, **kwargs):
        return parse(self.make_cfaa(items, **kwargs))["payload"]


class BatchVerificationTest(ChainForkAggregateDecisionFixtures):
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
        self.assertEqual(list(good["result"].keys()), SINGLE_RESULT_KEYS)
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
            verify_chain_fork_aggregate_decisions(
                items, {"batch": "x"}, self.auth, self.ring, self.m)
        with self.assertRaises(ValueError):
            verify_chain_fork_aggregate_decisions(
                items, self.policy, {"sites": {}}, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_chain_fork_aggregate_decisions(
                items, self.policy, self.auth, "ring", self.m)
        with self.assertRaises(TypeError):
            verify_chain_fork_aggregate_decisions(
                items, self.policy, self.auth, self.ring, True)
        with self.assertRaises(ValueError):
            verify_chain_fork_aggregate_decisions(
                items, self.policy, self.auth, self.ring, -1)

    def test_batch_fault_surfaces_even_when_a_decision_is_bad(self):
        with self.assertRaises(ValueError):
            self.batch_report([
                decision_item("a", b"{}"), decision_item("a", b"{"),
            ])

    def test_one_failure_matches_the_single_decision_result(self):
        report = self.batch_report([
            decision_item("ok", self.decision_a),
            decision_item("bad", b"{}"),
        ])
        single = verify_chain_fork_aggregate_decision(
            self.decision_a, self.policy, self.auth, self.ring, self.m)
        self.assertEqual(report["items"][0]["result"], single)

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
            self.batch_report(items)["items"][0]["result"]["issuer"], JUDGE)

    def test_inputs_are_not_modified(self):
        items = [decision_item("a", self.decision_a)]
        snapshot = copy.deepcopy((items, self.policy, self.auth, self.ring))
        self.batch_report(items)
        self.assertEqual((items, self.policy, self.auth, self.ring), snapshot)


class AggregationValidationTest(ChainForkAggregateDecisionFixtures):
    def test_items_container_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.make_cfaa("x")
        with self.assertRaises(TypeError):
            self.make_cfaa(["x"])
        with self.assertRaises(TypeError):
            self.make_cfaa([decision_item(1, self.decision_a)])
        with self.assertRaises(TypeError):
            self.make_cfaa([decision_item("a", 1)])
        with self.assertRaises(ValueError):
            self.make_cfaa([])
        with self.assertRaises(ValueError):
            self.make_cfaa([decision_item("", self.decision_a)])
        with self.assertRaises(ValueError):
            self.make_cfaa([
                decision_item("a", self.decision_a),
                decision_item("a", self.decision_b),
            ])
        with self.assertRaises(ValueError):
            self.make_cfaa([
                {"id": "a", "decision": self.decision_a, "x": 1},
            ])

    def test_policy_faults(self):
        items = self.decision_items()
        with self.assertRaises(ValueError):
            aggregate_chain_fork_aggregate_decisions(
                items, {"batch": "x"}, self.auth, self.dsp, self.ring,
                self.m, JUDGE, 1)
        with self.assertRaises(ValueError):
            self.make_cfaa(items, auth={"sites": {SITE_A: {1}}})
        with self.assertRaises(ValueError):
            self.make_cfaa(items, dsp={"sites": {JUDGE: {1}}})
        with self.assertRaises(ValueError):
            self.make_cfaa(items, dsp={"sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_cfaa(
                items, dsp={"sites": {JUDGE: [1]}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_cfaa(
                items, dsp={"sites": {JUDGE: {True}}, "threshold": 1})
        with self.assertRaises(ValueError):
            self.make_cfaa(
                items, dsp={"sites": {JUDGE: {0}}, "threshold": 1})
        with self.assertRaises(ValueError):
            self.make_cfaa(
                items, dsp={"sites": {JUDGE: set()}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.make_cfaa(
                items, dsp={"sites": {JUDGE: {1}}, "threshold": True})
        with self.assertRaises(ValueError):
            self.make_cfaa(
                items, dsp={"sites": {JUDGE: {1}}, "threshold": 0})
        with self.assertRaises(ValueError):
            self.make_cfaa(
                items, dsp={"sites": {JUDGE: {1}}, "threshold": 2})

    def test_moment_issuer_version_rules(self):
        items = self.decision_items()
        with self.assertRaises(TypeError):
            self.make_cfaa(items, moment=True)
        with self.assertRaises(ValueError):
            self.make_cfaa(items, moment=-1)
        with self.assertRaises(TypeError):
            self.make_cfaa(items, issuer=7)
        with self.assertRaises(ValueError):
            self.make_cfaa(items, issuer="")
        with self.assertRaises(TypeError):
            self.make_cfaa(items, version=True)
        with self.assertRaises(ValueError):
            self.make_cfaa(items, version=0)

    def test_signing_credentials_have_no_fallback(self):
        items = self.decision_items()
        with self.assertRaises(AuthenticationError):
            self.make_cfaa(items, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.make_cfaa(items, issuer=JUDGE, version=2)
        revoked = dict(self.ring)
        revoked[JUDGE] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            self.make_cfaa(items, ring=revoked)
        future = dict(self.ring)
        future[JUDGE] = [entry(1, SECRET_COORD, not_before=self.m + 1)]
        with self.assertRaises(AuthenticationError):
            self.make_cfaa(items, ring=future)
        expired = dict(self.ring)
        expired[JUDGE] = [entry(1, SECRET_COORD, not_after=self.m - 1)]
        with self.assertRaises(AuthenticationError):
            self.make_cfaa(items, ring=expired)

    def test_inputs_are_not_modified(self):
        items = self.decision_items()
        snapshot = copy.deepcopy(
            (items, self.policy, self.auth, self.dsp, self.ring))
        self.make_cfaa(items)
        self.assertEqual(
            (items, self.policy, self.auth, self.dsp, self.ring), snapshot)


class PerItemRulingTest(ChainForkAggregateDecisionFixtures):
    def rows_by_id(self, items, **kwargs):
        payload = self.cfaa_payload(items, **kwargs)
        return {row["id"]: row for row in payload["items"]}

    def test_invalid_decision_rejected_alone_processing_continues(self):
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
                [decision_item("x", self.decision_b)], dsp=dsp, ring=ring)
            self.assertEqual(rows["x"]["conclusion"], "invalid")
            self.assertEqual(rows["x"]["reason"], "unauthenticated")
            self.assertEqual(rows["x"]["issuer"], JUDGE_B)
            self.assertEqual(rows["x"]["keyVersion"], 1)
            self.assertIsNone(rows["x"]["declaration"])

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
        payload = self.cfaa_payload([
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
        other = self.make_decision(self.other_proofs(), issuer=JUDGE)
        dsp = decision_site_policy(sites=(JUDGE,), threshold=1)
        payload = self.cfaa_payload([
            decision_item("a", self.decision_a),
            decision_item("b", other),
        ], dsp=dsp)
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])
        for row in payload["items"]:
            self.assertEqual(row["conclusion"], "contradiction")
            self.assertEqual(row["reason"], "contradiction")
            self.assertEqual(row["issuer"], JUDGE)


class AggregationTallyTest(ChainForkAggregateDecisionFixtures):
    def test_accepted_binds_the_common_declaration(self):
        payload = self.cfaa_payload(self.decision_items())
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
        payload = self.cfaa_payload(
            [decision_item("one", self.decision_a)])
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNotNone(payload["declaration"])
        accepted = self.cfaa_payload(self.decision_items())
        self.assertEqual(payload["declaration"], accepted["declaration"])

    def test_no_valid_vote_binds_null_declaration(self):
        payload = self.cfaa_payload([
            decision_item("a", b"{}"), decision_item("b", b"{"),
        ])
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNone(payload["declaration"])

    def test_cross_site_disagreement_is_conflicted(self):
        other = self.make_decision(self.other_proofs(), issuer=JUDGE_B)
        payload = self.cfaa_payload([
            decision_item("a", self.decision_a),
            decision_item("b", other),
        ])
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])
        self.assertTrue(
            all(row["conclusion"] == "valid" for row in payload["items"])
        )

    def test_conflict_is_not_outvotable(self):
        other = self.make_decision(self.other_proofs(), issuer=SITE_A)
        dsp = decision_site_policy(sites=(JUDGE, JUDGE_B, SITE_A),
                                   threshold=2)
        payload = self.cfaa_payload([
            decision_item("a", self.decision_a),
            decision_item("b", self.decision_b),
            decision_item("c", other),
        ], dsp=dsp)
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])

    def test_only_valid_rows_count_toward_the_threshold(self):
        payload = self.cfaa_payload([
            decision_item("a", self.decision_a),
            decision_item("bad", b"{}"),
        ])
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNotNone(payload["declaration"])

    def test_rows_sort_by_issuer_then_id_with_invalid_first(self):
        payload = self.cfaa_payload([
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

    def test_two_identical_inputs_yield_duplicate_and_matching_inputs(self):
        payload = self.cfaa_payload([
            decision_item("a", self.decision_a),
            decision_item("b", self.decision_a),
        ], dsp=decision_site_policy(sites=(JUDGE,), threshold=1))
        self.assertEqual(payload["inputs"],
                         [hashlib.sha256(self.decision_a).hexdigest()] * 2)


class AggregatePacketShapeTest(ChainForkAggregateDecisionFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = self.decision_items()
        self.raw = self.make_cfaa(self.items)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(parse(self.raw)), self.raw)

    def test_top_and_payload_key_sets(self):
        data = parse(self.raw)
        self.assertEqual(set(data.keys()), set(AGGREGATE_KEYS))
        self.assertEqual(list(data["payload"].keys()),
                         AGGREGATE_PAYLOAD_KEYS)

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
        reversed_raw = self.make_cfaa(list(reversed(self.items)))
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
            payload["authorizationPolicyDigest"],
            hashlib.sha256(compact({
                "sites": {
                    site: sorted(self.auth["sites"][site])
                    for site in sorted(self.auth["sites"])
                },
                "threshold": self.auth["threshold"],
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

    def test_declaration_proofs_match_its_conclusions_as_a_multiset(self):
        declaration = parse(self.raw)["payload"]["declaration"]
        self.assertEqual(
            sorted(declaration["proofs"]),
            sorted(entry["digest"] for entry in declaration["conclusions"]),
        )


class AggregateVerifySuccessTest(AggregatePacketShapeTest):
    def test_result_is_fresh_fixed_key_mapping(self):
        result = self.verify_cfaa(self.raw)
        self.assertEqual(list(result.keys()), AGGREGATE_RESULT_KEYS)
        self.assertEqual(result["aggregateDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["inputs"],
                         parse(self.raw)["payload"]["inputs"])

    def test_repeated_calls_share_no_mutable_structure(self):
        first = self.verify_cfaa(self.raw)
        second = self.verify_cfaa(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["declaration"], second["declaration"])
        first["items"][0]["id"] = "tampered"
        first["declaration"]["conclusions"][0]["id"] = "tampered"
        third = self.verify_cfaa(self.raw)
        self.assertEqual(third["items"][0]["id"],
                         second["items"][0]["id"])
        self.assertEqual(third["declaration"]["conclusions"][0]["id"],
                         second["declaration"]["conclusions"][0]["id"])


class AggregateVerifyStructureTest(AggregatePacketShapeTest):
    def assert_invalid(self, raw):
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            self.verify_cfaa(raw)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            self.verify_cfaa("x")
        with self.assertRaises(TypeError):
            self.verify_cfaa(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.verify_cfaa(self.raw, moment=-1)
        with self.assertRaises(TypeError):
            verify_chain_fork_decision_aggregate(
                self.raw, "x", self.auth, self.dsp, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_chain_fork_decision_aggregate(
                self.raw, self.policy, "x", self.dsp, self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_chain_fork_decision_aggregate(
                self.raw, self.policy, self.auth, "x", self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_chain_fork_decision_aggregate(
                self.raw, self.policy, self.auth, self.dsp, "ring", self.m)

    def test_encoding_faults(self):
        self.assert_invalid(self.raw + b"\n")
        # Bytes that do not parse far enough to name a policy digest
        # cannot be classified by family and keep the level-1 parent
        # taxonomy; both error classes are ValueErrors.
        with self.assertRaises(InvalidChainDecisionAggregateError):
            self.verify_cfaa(b"")
        with self.assertRaises(InvalidChainDecisionAggregateError):
            self.verify_cfaa(b"{")
        with self.assertRaises(TypeError):
            self.verify_cfaa(b"[]")

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
            self.verify_cfaa(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["items"][0]["keyVersion"] = True
        with self.assertRaises(TypeError):
            self.verify_cfaa(rewrap(payload))
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
        pretty = __import__("json").dumps(parse(self.raw), indent=2)
        self.assert_invalid(pretty.encode())


class AggregateVerifyBindingTest(AggregatePacketShapeTest):
    def assert_invalid(self, payload):
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            self.verify_cfaa(rewrap(payload))

    def test_wrong_prune_policy(self):
        other = copy.deepcopy(self.policy)
        other["batch"] = "other-batch"
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            verify_chain_fork_decision_aggregate(
                self.raw, other, self.auth, self.dsp, self.ring, self.m)

    def test_wrong_site_policies(self):
        other_auth = {"sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 1}
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            verify_chain_fork_decision_aggregate(
                self.raw, self.policy, other_auth, self.dsp, self.ring,
                self.m)
        other_dsp = decision_site_policy(sites=(JUDGE,), threshold=1)
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            verify_chain_fork_decision_aggregate(
                self.raw, self.policy, self.auth, other_dsp, self.ring,
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

    def test_reordered_declaration_proofs_cannot_be_resigned(self):
        # The proof multiset must still agree; a pure reordering that
        # keeps the same digests is legal, but swapping in a foreign
        # digest breaks the multiset binding.
        payload = parse(self.raw)["payload"]
        declaration = payload["declaration"]
        declaration["proofs"] = ["ee" * 32] * len(declaration["proofs"])
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
            self.verify_cfaa(compact(data))

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
                verify_chain_fork_decision_aggregate(
                    self.raw, self.policy, self.auth, self.dsp, ring, self.m)

    def test_unknown_aggregator(self):
        ring = {k: v for k, v in self.ring.items() if k != JUDGE}
        with self.assertRaises(AuthenticationError):
            verify_chain_fork_decision_aggregate(
                self.raw, self.policy, self.auth, self.dsp, ring, self.m)

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        self.assertTrue(
            issubclass(InvalidChainForkDecisionAggregateError, ValueError))
        self.assertTrue(issubclass(
            InvalidChainForkDecisionAggregateError,
            InvalidChainDecisionAggregateError))
        self.assertIsNot(InvalidChainForkDecisionAggregateError,
                         InvalidChainDecisionAggregateError)
        self.assertIsNot(InvalidChainForkDecisionAggregateError,
                         InvalidChainDecisionError)


class FamilyDispatchTest(ChainForkAggregateDecisionFixtures):
    """The shared verifier name routes by the signed policy digest field."""

    def test_level_1_packet_uses_the_level_1_error_taxonomy(self):
        # Build a level-1 aggregate (adjudicate_chain_forks family).
        from test_chain_fork_proofs import ChainForkFixtures
        from offline_coordination.replication import (
            aggregate_chain_fork_decisions,
        )

        level1 = ChainForkFixtures()
        level1.setUp()
        dsp1 = decision_site_policy(sites=(JUDGE,), threshold=1)
        raw1 = aggregate_chain_fork_decisions(
            [decision_item("one", level1.decision_a)],
            level1.policy, level1.sp, dsp1, level1.ring, level1.m,
            JUDGE, 1,
        )
        payload = parse(raw1)["payload"]
        self.assertIn("sitePolicyDigest", payload)
        self.assertNotIn("authorizationPolicyDigest", payload)

        # It verifies under the level-1 argument order.
        result = verify_chain_fork_decision_aggregate(
            raw1, level1.policy, level1.sp, dsp1, level1.ring, level1.m)
        self.assertEqual(result["aggregateDigest"],
                         hashlib.sha256(raw1).hexdigest())

        # A broken level-1 packet keeps the level-1 error class, not the
        # level-2 subclass.
        payload["status"] = "insufficient"
        with self.assertRaises(InvalidChainDecisionAggregateError):
            verify_chain_fork_decision_aggregate(
                rewrap(payload), level1.policy, level1.sp, dsp1,
                level1.ring, level1.m)

    def test_level_2_packet_uses_the_level_2_error_taxonomy(self):
        raw = self.make_cfaa(self.decision_items())
        payload = parse(raw)["payload"]
        self.assertIn("authorizationPolicyDigest", payload)
        self.assertNotIn("sitePolicyDigest", payload)
        payload["status"] = "insufficient"
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            self.verify_cfaa(rewrap(payload))


class CrossEntryCompatibilityTest(ChainForkAggregateDecisionFixtures):
    """Legal aggregate decisions are accepted by every decision entry.

    Unlike the level-1 :func:`adjudicate_chain_forks` family, this
    family's proof summaries are bound as an order-independent
    multiset: reversing them after sealing and re-signing stays legal
    for the single decision, the batch verifier and the aggregator.
    """

    def _outcomes(self, raw):
        dsp = decision_site_policy(sites=(JUDGE, JUDGE_B), threshold=1)
        try:
            verify_chain_fork_aggregate_decision(
                raw, self.policy, self.auth, self.ring, self.m)
            single = "ok"
        except InvalidChainDecisionError:
            single = "invalid"
        except AuthenticationError:
            single = "unauth"
        batch = self.batch_report([decision_item("i", raw)])["items"][0][
            "status"]
        aggregate = self.make_cfaa([decision_item("i", raw)], dsp=dsp)
        row = parse(aggregate)["payload"]["items"][0]
        verifies = True
        try:
            self.verify_cfaa(aggregate, dsp=dsp)
        except Exception:  # pragma: no cover - any divergence fails below
            verifies = False
        return single, batch, (row["conclusion"], row["reason"]), verifies

    def test_legal_decisions_accepted_everywhere(self):
        for raw in (self.decision_a, self.decision_b):
            single, batch, row, verifies = self._outcomes(raw)
            self.assertEqual(single, "ok")
            self.assertEqual(batch, "verified")
            self.assertEqual(row, ("valid", None))
            self.assertTrue(verifies)

    def test_reordered_proof_summaries_stay_legal_in_this_family(self):
        payload = parse(self.decision_a)["payload"]
        payload["proofs"] = list(reversed(payload["proofs"]))
        forged = rewrap(payload)
        single, batch, row, verifies = self._outcomes(forged)
        self.assertEqual(single, "ok")
        self.assertEqual(batch, "verified")
        self.assertEqual(row, ("valid", None))
        self.assertTrue(verifies)

    def test_swapped_proof_digest_is_still_rejected(self):
        payload = parse(self.decision_a)["payload"]
        payload["proofs"][0] = "ff" * 32
        forged = rewrap(payload)
        single, batch, row, _verifies = self._outcomes(forged)
        self.assertEqual(single, "invalid")
        self.assertEqual(batch, "invalid")
        self.assertEqual(row, ("invalid", "invalid"))

    def test_bound_declaration_carries_the_decisions_multiset_order(self):
        # A decision whose proof summaries are merely reversed (the same
        # multiset) is legal in this family, and the aggregate embeds
        # that declaration verbatim: the proofs inside the bound common
        # declaration stay in the decision's order but re-tally through
        # the multiset rule.
        payload = parse(self.decision_a)["payload"]
        payload["proofs"] = list(reversed(payload["proofs"]))
        forged = rewrap(payload)
        dsp = decision_site_policy(sites=(JUDGE, JUDGE_B), threshold=1)
        raw = self.make_cfaa([decision_item("i", forged)], dsp=dsp)
        bound = parse(raw)["payload"]["declaration"]
        self.assertEqual(
            bound["proofs"], parse(forged)["payload"]["proofs"])
        result = self.verify_cfaa(raw, dsp=dsp)
        self.assertEqual(result["status"], "accepted")


class IndependenceTest(ChainForkAggregateDecisionFixtures):
    def test_no_file_is_read_or_written(self):
        raw = self.make_cfaa(self.decision_items())
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.make_cfaa(self.decision_items())
            self.batch_report(self.decision_items())
            self.verify_cfaa(raw)

    def test_inputs_are_not_modified(self):
        items = self.decision_items()
        raw = self.make_cfaa(items)
        snapshot = copy.deepcopy(
            (items, self.policy, self.auth, self.dsp, self.ring))
        self.make_cfaa(items)
        self.batch_report(items)
        self.verify_cfaa(raw)
        self.assertEqual(
            (items, self.policy, self.auth, self.dsp, self.ring), snapshot)


if __name__ == "__main__":
    unittest.main()
