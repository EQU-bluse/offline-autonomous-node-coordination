"""Tests for supersession chains over cross-site chain fork aggregate
decision aggregates.

Covers :func:`supersede_decision_aggregate`,
:func:`verify_decision_aggregate_chain`,
:func:`verify_decision_aggregate_chains`,
:func:`seal_decision_aggregate_head` and
:func:`verify_decision_aggregate_head`: the canonical signed successor
packet and every binding (root, predecessor, height, the full
recomputed conclusion, the raw decision increment as hex, the invariant
prune and site authorization policy digests, the old/new decision policy
digests, policy version and effective moment), the per-hop verdict state
machine (insufficient to accepted/conflicted, accepted only kept or
upgraded, conflicted never masked), the append-only decision prefix with
unchanged-policy growth and rotation-only re-sealing, versioned decision
site policy rotation with a single policyVersion step, dual-policy
sealer authorization and credential usability at both the effective and
verification moments, offline hop-by-hop verification, bare-root
verification, the fresh chain summary with the common declaration
digest, batch verification with cross-chain successor fork detection and
the conflicted reclassification, the stable head anchor seal/reverify
rules, the distinct InvalidChainForkDecisionAggregateError /
InvalidAggregateChainError / InvalidAggregateAnchorError hierarchy, and
every error classification (including a bool never posing as an int),
input immutability and the purely offline guarantee.
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
    InvalidAggregateAnchorError,
    InvalidAggregateChainError,
    InvalidChainForkDecisionAggregateError,
    aggregate_chain_fork_aggregate_decisions,
    seal_decision_aggregate_head,
    supersede_decision_aggregate,
    verify_decision_aggregate_chain,
    verify_decision_aggregate_chains,
    verify_decision_aggregate_head,
)

from test_chain_fork_aggregate_decision_aggregates import (
    ChainForkAggregateDecisionAggregateFixtures,
)
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_chain_fork_aggregate import chain_item, plain, vpol

JUDGE_B = SITE_C

PACKET_KEYS = ["payload", "signature"]
SUCCESSOR_PAYLOAD_KEYS = [
    "authorizationPolicyDigest", "decisions", "declaration",
    "effectiveAt", "height", "inputs", "issuer", "items", "keyVersion",
    "newPolicyDigest", "oldPolicyDigest", "policyVersion",
    "predecessorDigest", "prunePolicyDigest", "rootDigest", "status",
    "version",
]
INCREMENT_KEYS = ["decision", "id"]
CHAIN_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "commonDigest",
]
REPORT_KEYS = ["error", "id", "result", "status"]
BATCH_REPORT_KEYS = ["forks", "items", "version"]
FORK_KEYS = ["rootDigest", "predecessorDigest", "successors", "ids"]
ANCHOR_PAYLOAD_KEYS = [
    "headDigest", "height", "issuer", "keyVersion", "moment",
    "policyDigest", "policyVersion", "rootDigest", "version",
]
ANCHOR_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyDigest", "policyVersion",
    "anchorDigest",
]

FORKED_ERROR = "forked-decision-aggregate-chain"


def rewrap(payload, secret=SECRET_COORD):
    """Re-sign an envelope payload into canonical compact packet bytes."""
    signature = hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


class DecisionAggregateChainFixtures(
    ChainForkAggregateDecisionAggregateFixtures, unittest.TestCase
):
    """Shared chain-layer roots, decisions, policies and chain builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.auth = self.cauth()
        self.pv1 = vpol()
        self.pv2_t1 = vpol(2, threshold=1)
        self.pv1_3 = vpol(1, sites=(JUDGE, JUDGE_B, SITE_A), threshold=2)

        # A disagreeing decision carrying a distinct complete declaration.
        self.decision_other = self.make_cfa_decision(
            self.other_proofs(), issuer=SITE_A)

        # Chain-layer roots: one site (insufficient), two agreeing
        # (accepted) and two disagreeing declarations (conflicted).
        self.root_one = aggregate_chain_fork_aggregate_decisions(
            [decision_item("one", self.decision_a)],
            self.policy, self.auth, self.dsp, self.ring, self.m, JUDGE, 1,
        )
        self.root_two = aggregate_chain_fork_aggregate_decisions(
            self.cfa_decision_items(),
            self.policy, self.auth, self.dsp, self.ring, self.m, JUDGE, 1,
        )
        self.root_conf = aggregate_chain_fork_aggregate_decisions(
            [decision_item("a", self.decision_a),
             decision_item("b", self.make_cfa_decision(
                 self.other_proofs(), issuer=JUDGE_B))],
            self.policy, self.auth, plain(self.pv1_3), self.ring, self.m,
            JUDGE, 1,
        )

    def dsucc(self, predecessor, increment, old=None, new=None,
              moment=None, effective=None, issuer=JUDGE, version=1,
              auth=None):
        return supersede_decision_aggregate(
            predecessor, increment,
            self.policy, self.auth if auth is None else auth,
            self.pv1 if old is None else old,
            self.pv1 if new is None else new,
            self.ring,
            self.m + 10 if moment is None else moment,
            self.m if effective is None else effective,
            issuer, version,
        )

    def dvchain(self, root, successors, policies=None, moment=None,
                auth=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        if moment is None:
            moment = self.m + 10 * max(1, len(successors))
        return verify_decision_aggregate_chain(
            root, successors, self.policy,
            self.auth if auth is None else auth,
            policies, self.ring, moment,
        )

    def dcitem(self, item_id, root, successors, policies=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        return chain_item(item_id, root, successors, policies)

    def dvchains(self, items, moment=None, auth=None, ring=None):
        return verify_decision_aggregate_chains(
            items, self.policy,
            self.auth if auth is None else auth,
            self.ring if ring is None else ring,
            self.m + 20 if moment is None else moment,
        )


class SuccessorShapeTest(DecisionAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.dsucc(
            self.root_one, [decision_item("two", self.decision_b)])

    def test_canonical_compact_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(parse(self.raw)), self.raw)

    def test_top_and_payload_key_sets(self):
        data = parse(self.raw)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        self.assertEqual(list(data["payload"].keys()),
                         SUCCESSOR_PAYLOAD_KEYS)

    def test_increment_is_bound_as_hex(self):
        decisions = parse(self.raw)["payload"]["decisions"]
        self.assertEqual(len(decisions), 1)
        self.assertEqual(sorted(decisions[0].keys()), INCREMENT_KEYS)
        self.assertEqual(decisions[0]["id"], "two")
        self.assertEqual(
            bytes.fromhex(decisions[0]["decision"]), self.decision_b)

    def test_height_root_and_policy_bindings(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(payload["height"], 1)
        self.assertEqual(payload["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["predecessorDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(payload["effectiveAt"], self.m)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(
            payload["prunePolicyDigest"],
            parse(self.root_one)["payload"]["prunePolicyDigest"])
        self.assertEqual(
            payload["authorizationPolicyDigest"],
            parse(self.root_one)["payload"]["authorizationPolicyDigest"])


class BareRootVerifyTest(DecisionAggregateChainFixtures):
    def test_bare_root_verified_in_full(self):
        result = self.dvchain(self.root_two, [])
        self.assertEqual(list(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.root_two).hexdigest())
        self.assertEqual(result["headDigest"], result["rootDigest"])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["commonDigest"])

    def test_conflicted_bare_root_common_digest_is_null(self):
        result = self.dvchain(self.root_conf, [], policies=[self.pv1_3])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])

    def test_result_is_depth_independent_and_fresh(self):
        first = self.dvchain(self.root_two, [])
        second = self.dvchain(self.root_two, [])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)


class GrowthAndStateMachineTest(DecisionAggregateChainFixtures):
    def test_insufficient_grows_to_accepted(self):
        raw = self.dsucc(
            self.root_one, [decision_item("two", self.decision_b)])
        result = self.dvchain(self.root_one, [raw])
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["commonDigest"])

    def test_insufficient_stays_insufficient_below_threshold(self):
        # A decision that does not authenticate adds no valid distinct
        # site, so the tally stays insufficient but keeps the declaration.
        raw = self.dsucc(
            self.root_one, [decision_item("two", b"{}")])
        result = self.dvchain(self.root_one, [raw])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["commonDigest"])

    def test_conflicted_can_never_be_masked(self):
        raw = self.dsucc(
            self.root_conf,
            [decision_item("s", self.decision_b)],
            old=self.pv1_3, new=self.pv1_3,
        )
        self.assertEqual(parse(raw)["payload"]["status"], "conflicted")
        result = self.dvchain(
            self.root_conf, [raw], policies=[self.pv1_3, self.pv1_3])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])

    def test_accepted_may_advance_to_conflicted(self):
        rotated = vpol(2, sites=(JUDGE, JUDGE_B, SITE_A), threshold=2)
        raw = self.dsucc(
            self.root_two, [decision_item("c", self.decision_other)],
            old=self.pv1, new=rotated,
        )
        self.assertEqual(parse(raw)["payload"]["status"], "conflicted")
        self.assertEqual(
            self.dvchain(self.root_two, [raw],
                         policies=[self.pv1, rotated])["status"],
            "conflicted")

    def test_accepted_keeps_identical_declaration_under_rotation(self):
        raw = self.dsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(
            payload["declaration"],
            parse(self.root_two)["payload"]["declaration"])

    def test_two_hop_chain_recomputes_at_each_stage(self):
        first = self.dsucc(
            self.root_one, [decision_item("two", self.decision_b)])
        second = self.dsucc(
            first, [], old=self.pv1, new=self.pv2_t1,
            moment=self.m + 20, effective=self.m + 5)
        result = self.dvchain(
            self.root_one, [first, second],
            policies=[self.pv1, self.pv1, self.pv2_t1], moment=self.m + 30)
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(second).hexdigest())


class AppendOnlyTest(DecisionAggregateChainFixtures):
    def test_unchanged_policy_requires_non_empty_increment(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.dsucc(self.root_two, [], old=self.pv1, new=self.pv1)

    def test_repeated_packet_digest_rejected(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.dsucc(
                self.root_one,
                [decision_item("nine", self.decision_a)])

    def test_repeated_item_id_rejected(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.dsucc(
                self.root_one,
                [decision_item("one", self.decision_b)])

    def test_rotation_may_reseal_empty_sequence(self):
        raw = self.dsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1)
        self.assertEqual(parse(raw)["payload"]["decisions"], [])
        self.assertEqual(
            self.dvchain(self.root_two, [raw],
                         policies=[self.pv1, self.pv2_t1])["status"],
            "accepted")


class PolicyVersionTest(DecisionAggregateChainFixtures):
    def test_first_policy_must_match_root_and_carry_version_one(self):
        bad = vpol(1, sites=(JUDGE,), threshold=1)
        with self.assertRaises(InvalidAggregateChainError):
            self.dsucc(self.root_two, [], old=bad, new=self.pv2_t1)

    def test_changed_content_must_step_by_exactly_one(self):
        jump = vpol(3, threshold=1)
        with self.assertRaises(InvalidAggregateChainError):
            self.dsucc(self.root_two, [], old=self.pv1, new=jump)

    def test_unchanged_content_must_keep_version(self):
        mismatch = vpol(2)
        with self.assertRaises(InvalidAggregateChainError):
            self.dsucc(self.root_two, [], old=self.pv1, new=mismatch)

    def test_old_policy_must_equal_predecessor_policy(self):
        first = self.dsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1)
        with self.assertRaises(InvalidAggregateChainError):
            self.dsucc(first, [decision_item("c", self.decision_other)],
                       old=self.pv1, new=self.pv2_t1)


class AuthorizationAndMomentTest(DecisionAggregateChainFixtures):
    def test_sealer_must_be_authorized_under_both_policies(self):
        drop = vpol(2, sites=(JUDGE_B,), threshold=1)
        with self.assertRaises(InvalidAggregateChainError):
            self.dsucc(self.root_two, [], old=self.pv1, new=drop,
                       issuer=JUDGE)

    def test_credential_must_be_usable_at_both_moments(self):
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, SECRET_COORD, not_after=self.m + 5)]
        with self.assertRaises(AuthenticationError):
            supersede_decision_aggregate(
                self.root_one,
                [decision_item("two", self.decision_b)],
                self.policy, self.auth, self.pv1, self.pv1,
                ring, self.m + 10, self.m, JUDGE, 1)

    def test_effective_moment_must_not_move_backwards(self):
        first = self.dsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1,
            effective=self.m + 5)
        with self.assertRaises(ValueError):
            self.dsucc(
                first, [decision_item("c", self.decision_other)],
                old=self.pv2_t1, new=self.pv2_t1,
                effective=self.m + 4, moment=self.m + 10)

    def test_unknown_sealer_is_authentication_error(self):
        ring = {site: self.ring[site]
                for site in self.ring if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            supersede_decision_aggregate(
                self.root_two, [], self.policy, self.auth,
                self.pv1, self.pv2_t1, ring, self.m + 10, self.m, JUDGE, 1)

    def test_invariant_policies_must_match_the_root(self):
        other_auth = {"sites": {SITE_A: {1}}, "threshold": 1}
        with self.assertRaises(InvalidAggregateChainError):
            supersede_decision_aggregate(
                self.root_one, [decision_item("two", self.decision_b)],
                self.policy, other_auth, self.pv1, self.pv1,
                self.ring, self.m + 10, self.m, JUDGE, 1)


class ChainBindingTest(DecisionAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.dsucc(
            self.root_one, [decision_item("two", self.decision_b)])

    def assert_chain_invalid(self, raw):
        with self.assertRaises(InvalidAggregateChainError):
            self.dvchain(self.root_one, [raw])

    def test_tampered_height_binding(self):
        payload = parse(self.raw)["payload"]
        payload["height"] = 2
        self.assert_chain_invalid(rewrap(payload))

    def test_tampered_root_binding(self):
        payload = parse(self.raw)["payload"]
        payload["rootDigest"] = "0" * 64
        self.assert_chain_invalid(rewrap(payload))

    def test_tampered_predecessor_binding(self):
        payload = parse(self.raw)["payload"]
        payload["predecessorDigest"] = "1" * 64
        self.assert_chain_invalid(rewrap(payload))

    def test_tampered_status_cannot_be_resigned(self):
        payload = parse(self.raw)["payload"]
        payload["status"] = "insufficient"
        self.assert_chain_invalid(rewrap(payload))

    def test_tampered_increment_binding(self):
        payload = parse(self.raw)["payload"]
        payload["decisions"][0]["decision"] = self.decision_a.hex()
        self.assert_chain_invalid(rewrap(payload))

    def test_tampered_policy_version_binding(self):
        payload = parse(self.raw)["payload"]
        payload["policyVersion"] = 2
        self.assert_chain_invalid(rewrap(payload))

    def test_tampered_authorization_policy_binding(self):
        payload = parse(self.raw)["payload"]
        payload["authorizationPolicyDigest"] = "2" * 64
        self.assert_chain_invalid(rewrap(payload))

    def test_reordered_history_prefix_is_rejected(self):
        payload = parse(self.raw)["payload"]
        root_digest = hashlib.sha256(self.decision_a).hexdigest()
        new_digest = hashlib.sha256(self.decision_b).hexdigest()
        self.assertEqual(payload["inputs"], [root_digest, new_digest])
        payload["inputs"] = [new_digest, root_digest]
        self.assert_chain_invalid(rewrap(payload))

    def test_wrong_policy_history_count(self):
        with self.assertRaises(ValueError):
            verify_decision_aggregate_chain(
                self.root_one, [self.raw], self.policy, self.auth,
                [self.pv1], self.ring, self.m + 10)

    def test_root_stage_policy_must_be_version_one(self):
        first = vpol(2)
        with self.assertRaises(ValueError):
            verify_decision_aggregate_chain(
                self.root_one, [self.raw], self.policy, self.auth,
                [first, first], self.ring, self.m + 10)

    def test_bad_signature_is_authentication_error(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.dvchain(self.root_one, [compact(data)])

    def test_bad_root_raises_root_error(self):
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            self.dvchain(b"{}", [])

    def test_bad_root_is_distinct_from_chain_error(self):
        self.assertIsNot(InvalidChainForkDecisionAggregateError,
                         InvalidAggregateChainError)

    def test_non_canonical_encoding_rejected(self):
        pretty = json.dumps(parse(self.raw), indent=2)
        self.assert_chain_invalid(pretty.encode())
        self.assert_chain_invalid((self.raw.decode("utf-8") + "\n").encode())


class PublicArgumentTypeTest(DecisionAggregateChainFixtures):
    def test_supersede_type_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.dsucc(self.root_two, "x")
        with self.assertRaises(TypeError):
            self.dsucc(self.root_two, [decision_item(1, self.decision_b)])
        with self.assertRaises(TypeError):
            self.dsucc(
                self.root_two,
                [{"id": "x", "decision": 1}])
        with self.assertRaises(ValueError):
            self.dsucc(self.root_two, [decision_item("", self.decision_b)])
        with self.assertRaises(TypeError):
            supersede_decision_aggregate(
                self.root_two, [], self.policy, self.auth, self.pv1,
                self.pv2_t1, self.ring, True, self.m, JUDGE, 1)
        with self.assertRaises(ValueError):
            supersede_decision_aggregate(
                self.root_two, [], self.policy, self.auth, self.pv1,
                self.pv2_t1, self.ring, -1, self.m, JUDGE, 1)
        with self.assertRaises(TypeError):
            self.dsucc(self.root_two, [], issuer=7)
        with self.assertRaises(ValueError):
            self.dsucc(self.root_two, [], issuer="")
        with self.assertRaises(TypeError):
            self.dsucc(self.root_two, [], version=True)
        with self.assertRaises(ValueError):
            self.dsucc(self.root_two, [], version=0)
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            self.dsucc(b"not-a-packet", [])

    def test_verify_argument_faults(self):
        with self.assertRaises(TypeError):
            verify_decision_aggregate_chain(
                "x", [], self.policy, self.auth, [self.pv1], self.ring,
                self.m)
        with self.assertRaises(TypeError):
            verify_decision_aggregate_chain(
                self.root_two, "x", self.policy, self.auth, [self.pv1],
                self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_decision_aggregate_chain(
                self.root_two, ["x"],
                self.policy, self.auth, [self.pv1, self.pv1],
                self.ring, self.m)
        with self.assertRaises(ValueError):
            verify_decision_aggregate_chain(
                self.root_two, [], self.policy, self.auth, [],
                self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_decision_aggregate_chain(
                self.root_two, [], self.policy, self.auth, [self.pv1],
                self.ring, True)


class ChainBatchTest(DecisionAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.first_a = self.dsucc(
            self.root_one, [decision_item("two", self.decision_b)])
        self.first_b = self.dsucc(
            self.root_one, [], old=self.pv1, new=self.pv2_t1)
        self.second_a = self.dsucc(
            self.first_a,
            [decision_item("three", self.decision_other)],
            old=self.pv1, new=self.pv1,
            moment=self.m + 20, effective=self.m + 5)

    def test_batch_validated_upfront(self):
        with self.assertRaises(TypeError):
            self.dvchains("x")
        with self.assertRaises(ValueError):
            self.dvchains([])
        with self.assertRaises(ValueError):
            self.dvchains([
                self.dcitem("a", self.root_one, [self.first_a]),
                self.dcitem("a", self.root_one, [self.first_a]),
            ])
        with self.assertRaises(ValueError):
            self.dvchains([
                {"id": "a", "root": self.root_one,
                 "successors": [self.first_a], "policies": [self.pv1]},
            ])
        with self.assertRaises(TypeError):
            self.dvchains([self.dcitem(1, self.root_one, [self.first_a])])

    def test_verified_report_in_input_order(self):
        report = self.dvchains([
            self.dcitem("a", self.root_one, [self.first_a]),
            self.dcitem("bad", b"{}", []),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual([r["id"] for r in report["items"]], ["a", "bad"])
        self.assertEqual([r["status"] for r in report["items"]],
                         ["verified", "invalid-root"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), REPORT_KEYS)

    def test_invalid_chain_is_isolated_from_unauthenticated(self):
        payload = parse(self.first_a)["payload"]
        payload["height"] = 9
        tampered = rewrap(payload)
        noauth_succ = self.dsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1,
            issuer=JUDGE_B)
        ring = {site: self.ring[site] for site in self.ring
                if site != JUDGE_B}
        report = self.dvchains([
            self.dcitem("bad", self.root_one, [tampered]),
            chain_item("noauth", self.root_two, [noauth_succ],
                       [self.pv1, self.pv2_t1]),
        ], ring=ring)
        statuses = {r["id"]: r["status"] for r in report["items"]}
        self.assertEqual(statuses["bad"], "invalid-chain")
        self.assertEqual(statuses["noauth"], "unauthenticated")
        for row in report["items"]:
            self.assertTrue(row["error"])
            self.assertIsNone(row["result"])

    def test_same_predecessor_two_successors_is_a_fork(self):
        report = self.dvchains([
            self.dcitem("b", self.root_one, [self.first_b],
                       policies=[self.pv1, self.pv2_t1]),
            self.dcitem("a", self.root_one, [self.first_a]),
        ])
        statuses = {r["id"]: r["status"] for r in report["items"]}
        self.assertEqual(statuses["a"], "conflicted")
        self.assertEqual(statuses["b"], "conflicted")
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(list(fork.keys()), FORK_KEYS)
        self.assertEqual(fork["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(fork["ids"], ["a", "b"])
        self.assertEqual(
            fork["successors"],
            sorted([hashlib.sha256(self.first_a).hexdigest(),
                    hashlib.sha256(self.first_b).hexdigest()]))
        for row in report["items"]:
            if row["status"] == "conflicted":
                self.assertEqual(row["error"], FORKED_ERROR)
                self.assertIsNotNone(row["result"])

    def test_prefix_extension_is_not_a_fork(self):
        report = self.dvchains([
            self.dcitem("short", self.root_one, [self.first_a]),
            self.dcitem("long", self.root_one,
                       [self.first_a, self.second_a],
                       policies=[self.pv1, self.pv1, self.pv1]),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]], ["verified", "verified"])

    def test_conflicted_chain_keeps_verified_result(self):
        report = self.dvchains([
            self.dcitem("a", self.root_one, [self.first_a]),
            self.dcitem("b", self.root_one, [self.first_b],
                       policies=[self.pv1, self.pv2_t1]),
        ])
        row = report["items"][0]
        self.assertEqual(row["result"]["status"], "accepted")
        self.assertEqual(row["result"]["height"], 1)

    def test_different_roots_are_never_compared(self):
        report = self.dvchains([
            self.dcitem("a", self.root_one, [self.first_a]),
            self.dcitem("b", self.root_two, []),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]], ["verified", "verified"])

    def test_fork_summaries_are_stable_sorted(self):
        items = [
            self.dcitem("b", self.root_one, [self.first_b],
                       policies=[self.pv1, self.pv2_t1]),
            self.dcitem("a", self.root_one, [self.first_a]),
        ]
        report = self.dvchains(items)
        again = self.dvchains(copy.deepcopy(items))
        self.assertEqual(report["forks"], again["forks"])
        forks = report["forks"][0]
        self.assertEqual(forks["successors"], sorted(forks["successors"]))
        self.assertEqual(forks["ids"], sorted(forks["ids"]))


class AnchorTest(DecisionAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.first = self.dsucc(
            self.root_one, [decision_item("two", self.decision_b)])
        self.items = [self.dcitem("t", self.root_one, [self.first])]

    def dseal(self, items=None, target="t", moment=None, issuer=JUDGE,
              version=1):
        return seal_decision_aggregate_head(
            self.items if items is None else items, target,
            self.policy, self.auth, self.ring,
            self.m + 20 if moment is None else moment, issuer, version)

    def dverify(self, anchor, items=None, target="t", moment=None):
        return verify_decision_aggregate_head(
            anchor, self.items if items is None else items, target,
            self.policy, self.auth, self.ring,
            self.m + 20 if moment is None else moment)

    def test_seal_and_verify_accepted_unforked_head(self):
        anchor = self.dseal()
        self.assertEqual(list(parse(anchor).keys()), PACKET_KEYS)
        self.assertEqual(list(parse(anchor)["payload"].keys()),
                         ANCHOR_PAYLOAD_KEYS)
        result = self.dverify(anchor)
        self.assertEqual(list(result.keys()), ANCHOR_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(self.first).hexdigest())
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["policyVersion"], 1)
        from offline_coordination.replication import _pac_site_policy_bytes
        self.assertEqual(result["policyDigest"],
                         hashlib.sha256(
                             _pac_site_policy_bytes(self.pv1)).hexdigest())
        self.assertEqual(result["anchorDigest"],
                         hashlib.sha256(anchor).hexdigest())

    def test_conflicted_or_invalid_target_is_not_sealable(self):
        other = self.dsucc(
            self.root_one, [], old=self.pv1, new=self.pv2_t1)
        items = [
            self.dcitem("t", self.root_one, [self.first]),
            self.dcitem("f", self.root_one, [other],
                       policies=[self.pv1, self.pv2_t1]),
        ]
        with self.assertRaises(ValueError):
            self.dseal(items=items, target="t")
        with self.assertRaises(ValueError):
            self.dseal(items=items, target="f")
        with self.assertRaises(ValueError):
            self.dseal(items=items, target="missing")

    def test_insufficient_head_is_not_sealable(self):
        items = [self.dcitem("t", self.root_one, [])]
        with self.assertRaises(ValueError):
            self.dseal(items=items)

    def test_bare_root_accepted_head_can_be_anchored(self):
        items = [self.dcitem("t", self.root_two, [])]
        anchor = seal_decision_aggregate_head(
            items, "t", self.policy, self.auth, self.ring, self.m + 20,
            JUDGE, 1)
        result = verify_decision_aggregate_head(
            anchor, items, "t", self.policy, self.auth, self.ring,
            self.m + 20)
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(self.root_two).hexdigest())

    def test_bad_root_target_raises_root_error(self):
        items = [self.dcitem("t", b"{}", [])]
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            self.dseal(items=items)
        anchor = self.dseal()
        with self.assertRaises(InvalidChainForkDecisionAggregateError):
            self.dverify(anchor, items=items)

    def test_bad_successor_target_raises_chain_error(self):
        payload = parse(self.first)["payload"]
        payload["height"] = 9
        tampered = rewrap(payload)
        items = [self.dcitem("t", self.root_one, [tampered])]
        with self.assertRaises(InvalidAggregateChainError):
            self.dseal(items=items)
        anchor = self.dseal()
        with self.assertRaises(InvalidAggregateChainError):
            self.dverify(anchor, items=items)

    def test_tampered_anchor_binding_rejected(self):
        anchor = self.dseal()
        payload = parse(anchor)["payload"]
        payload["height"] = 2
        with self.assertRaises(InvalidAggregateAnchorError):
            self.dverify(rewrap(payload))

    def test_bad_anchor_signature_is_authentication_error(self):
        anchor = self.dseal()
        data = parse(anchor)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.dverify(compact(data))

    def test_future_sealing_moment_is_an_anchor_error(self):
        future_anchor = seal_decision_aggregate_head(
            self.items, "t", self.policy, self.auth, self.ring, self.m + 30,
            JUDGE, 1)
        with self.assertRaises(InvalidAggregateAnchorError):
            self.dverify(future_anchor, moment=self.m + 20)
        # The same anchor verifies once the verification moment catches up.
        self.assertEqual(
            self.dverify(future_anchor, moment=self.m + 30)["height"], 1)

    def test_anchor_signature_checked_against_current_key(self):
        anchor = self.dseal()
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            verify_decision_aggregate_head(
                anchor, self.items, "t", self.policy, self.auth, ring,
                self.m + 20)

    def test_anchor_rejected_when_chain_later_forks(self):
        anchor = self.dseal()
        other = self.dsucc(
            self.root_one, [], old=self.pv1, new=self.pv2_t1)
        items = [
            self.dcitem("t", self.root_one, [self.first]),
            self.dcitem("f", self.root_one, [other],
                       policies=[self.pv1, self.pv2_t1]),
        ]
        with self.assertRaises(InvalidAggregateAnchorError):
            self.dverify(anchor, items=items)

    def test_anchor_type_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.dseal(target=7)
        with self.assertRaises(ValueError):
            self.dseal(target="")
        with self.assertRaises(TypeError):
            self.dseal(version=True)
        with self.assertRaises(ValueError):
            self.dseal(version=0)
        with self.assertRaises(TypeError):
            verify_decision_aggregate_head(
                "x", self.items, "t", self.policy, self.auth, self.ring,
                self.m + 20)


class ImmutabilityAndOfflineTest(DecisionAggregateChainFixtures):
    def test_inputs_are_not_modified(self):
        increment = [decision_item("two", self.decision_b)]
        snapshot = copy.deepcopy(
            (increment, self.policy, self.auth, self.pv1, self.ring))
        self.dsucc(self.root_one, increment)
        self.assertEqual(
            (increment, self.policy, self.auth, self.pv1, self.ring),
            snapshot)

    def test_batch_inputs_are_not_modified(self):
        items = [self.dcitem("a", self.root_two, [])]
        snapshot = copy.deepcopy((items, self.policy, self.auth, self.ring))
        self.dvchains(items)
        self.assertEqual(
            (items, self.policy, self.auth, self.ring), snapshot)

    def test_repeated_batch_results_are_independent(self):
        items = [self.dcitem("a", self.root_two, [])]
        first = self.dvchains(items)
        second = self.dvchains(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0], second["items"][0])

    def test_no_file_is_read_or_written(self):
        items = [self.dcitem("a", self.root_two, [])]
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.dsucc(
                self.root_one, [decision_item("two", self.decision_b)])
            self.dvchain(self.root_one, [raw])
            self.dvchains(items)
            anchor = seal_decision_aggregate_head(
                items, "a", self.policy, self.auth, self.ring, self.m + 20,
                JUDGE, 1)
            verify_decision_aggregate_head(
                anchor, items, "a", self.policy, self.auth, self.ring,
                self.m + 20)


if __name__ == "__main__":
    unittest.main()
