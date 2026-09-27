"""Tests for supersession chains over cross-site fork decision aggregates.

Covers :func:`supersede_fork_aggregate`,
:func:`verify_fork_aggregate_chain`, :func:`seal_fork_aggregate_head`
and :func:`verify_fork_aggregate_head`: the canonical signed successor
packet and every binding (root, predecessor, height, the full
recomputed conclusion, the raw decision increment as hex, the
invariant pruning and fork-proof policy digests, the current decision
site policy digest, old/new versioned policy digests, policy version
and effective moment), the per-hop verdict state machine (insufficient
to accepted/conflicted, accepted only kept or upgraded, conflicted
never masked), the append-only decision prefix with unchanged-policy
growth and rotation-only re-sealing, versioned decision site policy
rotation with a single policyVersion step, dual-policy sealer
authorization and credential usability at both moments, offline
hop-by-hop verification from just the root, ordered successors, the
two invariant policies, the complete decision policy history, the
current keyring and moment, bare-root verification, the fresh chain
summary with the common declaration digest, the stable head anchor
seal/reverify rules, and every error classification (including a bool
never posing as an int), input immutability and the purely offline
guarantee.
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
    InvalidAggregateForkDecisionAggregateError,
    InvalidForkAggregateChainError,
    seal_fork_aggregate_head,
    supersede_fork_aggregate,
    verify_fork_aggregate_chain,
    verify_fork_aggregate_head,
)

from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_aggregate_prune_fork_decisions import (
    ForkDecisionAggregateFixtures,
    decision_item,
)
from test_adjudicate_prune_aggregate_forks import proof_item
from offline_coordination.replication import (
    _validated_adjudication_policy,
    _verdict_policy_bytes,
)

PACKET_KEYS = ["payload", "signature"]
SUCCESSOR_PAYLOAD_KEYS = [
    "decisionSitePolicyDigest", "decisions", "declaration", "effectiveAt",
    "height", "inputs", "issuer", "items", "keyVersion", "newPolicyDigest",
    "oldPolicyDigest", "policyVersion", "predecessorDigest",
    "prunePolicyDigest", "rootDigest", "sitePolicyDigest", "status",
    "version",
]
INCREMENT_KEYS = ["decision", "id"]
CHAIN_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "commonDigest",
]
ANCHOR_PAYLOAD_KEYS = [
    "headDigest", "height", "issuer", "keyVersion", "moment",
    "policyDigest", "policyVersion", "rootDigest", "version",
]
ANCHOR_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyDigest", "policyVersion",
    "anchorDigest",
]

# Three decision sites may hand decisions to the cross-site aggregate.
DECISION_SITES = (JUDGE, SITE_B, SITE_C)


def ditem(item_id, decision):
    """One supersession increment item: a unique id and a decision."""
    return {"id": item_id, "decision": decision}


def vpol(policy_version=1, sites=DECISION_SITES, threshold=2):
    """A versioned decision site policy: sites, threshold and policyVersion."""
    return {
        "sites": {site: {1} for site in sites},
        "threshold": threshold,
        "policyVersion": policy_version,
    }


def plain(policy):
    """Strip the version from a versioned decision site policy (root form)."""
    return {"sites": copy.deepcopy(policy["sites"]),
            "threshold": policy["threshold"]}


def policy_canon(policy):
    """Canonical compact bytes of a versioned site policy (sets -> arrays)."""
    return compact({
        "sites": {site: sorted(policy["sites"][site])
                  for site in sorted(policy["sites"])},
        "threshold": policy["threshold"],
        "policyVersion": policy["policyVersion"],
    })


class ForkAggregateChainFixtures(ForkDecisionAggregateFixtures,
                                 unittest.TestCase):
    """Shared roots, decisions, policies and chain builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.pol_v1 = vpol()
        self.pol_v2 = vpol(2, sites=(JUDGE, SITE_C))
        self.pol_v1_t3 = vpol(threshold=3)
        self.dsp3 = plain(self.pol_v1_t3)
        # Decisions: A (JUDGE), B (SITE_C), C (SITE_B) all carry the
        # same declaration; other carries a distinct fork edge set.
        self.decision_c = self.make_decision(self.proofs, issuer=SITE_B)
        self.other_proofs = [
            proof_item("x", self.proof(self.items_two, issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]
        self.decision_other = self.make_decision(
            self.other_proofs, issuer=SITE_B
        )
        # Roots are plain cross-site aggregates over the unversioned
        # decision site policy: one site (insufficient), two agreeing
        # (accepted), and two disagreeing sites (conflicted).
        self.root_one = self.make_aggregate(
            [ditem("one", self.decision_a)], dsp=plain(self.pol_v1)
        )
        self.root_two = self.make_aggregate(
            [ditem("one", self.decision_a), ditem("two", self.decision_b)],
            dsp=plain(self.pol_v1),
        )
        self.root_conf = self.make_aggregate(
            [ditem("one", self.decision_a),
             ditem("two", self.make_decision(self.other_proofs,
                                             issuer=SITE_C))],
            dsp=plain(self.pol_v1),
        )
        self.root_one_t3 = self.make_aggregate(
            [ditem("one", self.decision_a)], sp=self.sp, dsp=self.dsp3,
        )

    def fsucc(self, predecessor, increment, old=None, new=None,
             moment=None, effective=None, issuer=JUDGE, version=1):
        return supersede_fork_aggregate(
            predecessor, increment, self.policy, self.sp,
            self.pol_v1 if old is None else old,
            self.pol_v1 if new is None else new,
            self.ring,
            self.m + 10 if moment is None else moment,
            self.m if effective is None else effective,
            issuer, version,
        )

    def fvchain(self, root, successors, policies=None, moment=None,
               site_policy=None):
        if policies is None:
            policies = [self.pol_v1] * (len(successors) + 1)
        if moment is None:
            moment = self.m + 10 * max(1, len(successors))
        return verify_fork_aggregate_chain(
            root, successors, self.policy,
            self.sp if site_policy is None else site_policy,
            policies, self.ring, moment,
        )

    def fseal(self, root, successors, policies=None, moment=None,
                  issuer=JUDGE, version=1):
        if policies is None:
            policies = [self.pol_v1] * (len(successors) + 1)
        if moment is None:
            moment = self.m + 10 * max(1, len(successors))
        return seal_fork_aggregate_head(
            root, successors, self.policy, self.sp, policies, self.ring,
            moment, issuer, version,
        )

    def fvhead(self, anchor, root, successors, policies=None, moment=None):
        if policies is None:
            policies = [self.pol_v1] * (len(successors) + 1)
        if moment is None:
            moment = self.m + 10 * max(1, len(successors))
        return verify_fork_aggregate_head(
            anchor, root, successors, self.policy, self.sp, policies,
            self.ring, moment,
        )

    def resign(self, packet, secret=SECRET_COORD):
        data = parse(packet) if isinstance(packet, bytes) else packet
        data["signature"] = self._hmac(secret, compact(data["payload"]))
        return compact(data)

    @staticmethod
    def _hmac(secret_hex, raw):
        import hmac
        return hmac.new(bytes.fromhex(secret_hex), raw,
                        hashlib.sha256).hexdigest()


class SupersedeForkAggregateShapeTest(ForkAggregateChainFixtures):
    def test_packet_shape_and_canonical_encoding(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        self.assertTrue(raw.endswith(b"}"))
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), SUCCESSOR_PAYLOAD_KEYS)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(compact(data), raw)

    def test_root_predecessor_height_and_digests(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        payload = parse(raw)["payload"]
        self.assertEqual(payload["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["predecessorDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["height"], 1)

    def test_later_successor_links_and_height(self):
        first = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        second = self.fsucc(first, [ditem("four", self.decision_c)],
                           moment=self.m + 20, effective=self.m + 5)
        payload = parse(second)["payload"]
        self.assertEqual(payload["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["predecessorDigest"],
                         hashlib.sha256(first).hexdigest())
        self.assertEqual(payload["height"], 2)

    def test_increment_rides_as_hex_and_inputs_are_prefix_plus_new(self):
        increment = [ditem("three", self.decision_b)]
        raw = self.fsucc(self.root_one, increment)
        payload = parse(raw)["payload"]
        bound = payload["decisions"]
        self.assertEqual([list(item.keys()) for item in bound],
                         [INCREMENT_KEYS])
        self.assertEqual(bound[0]["id"], "three")
        self.assertEqual(bound[0]["decision"], self.decision_b.hex())
        self.assertEqual(payload["inputs"], [
            hashlib.sha256(self.decision_a).hexdigest(),
            hashlib.sha256(self.decision_b).hexdigest(),
        ])

    def test_bound_rows_are_the_full_recomputed_conclusion(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        payload = parse(raw)["payload"]
        sites = [(row["issuer"], row["id"]) for row in payload["items"]]
        self.assertEqual(sites, [(JUDGE, "one"), (SITE_C, "three")])
        for row in payload["items"]:
            self.assertIsNone(row["reason"])
            self.assertEqual(row["conclusion"], "valid")

    def test_policy_digests_bound(self):
        raw = self.fsucc(self.root_two, [ditem("three", self.decision_c)])
        payload = parse(raw)["payload"]
        expected_old = hashlib.sha256(policy_canon(self.pol_v1)).hexdigest()
        self.assertEqual(payload["oldPolicyDigest"], expected_old)
        self.assertEqual(payload["newPolicyDigest"], expected_old)
        # The current decision site policy is bound in its root form
        # (sites/threshold, no policyVersion); the version rides in the
        # old/new policy digests and policyVersion field.
        expected_current = hashlib.sha256(compact({
            "sites": {s: [1] for s in sorted(self.pol_v1["sites"])},
            "threshold": self.pol_v1["threshold"],
        })).hexdigest()
        self.assertEqual(payload["decisionSitePolicyDigest"], expected_current)
        expected_prune = hashlib.sha256(
            _verdict_policy_bytes(_validated_adjudication_policy(self.policy))
        ).hexdigest()
        self.assertEqual(payload["prunePolicyDigest"], expected_prune)
        self.assertEqual(
            payload["sitePolicyDigest"],
            hashlib.sha256(compact({
                "sites": {s: [1] for s in sorted(self.sp["sites"])},
                "threshold": self.sp["threshold"],
            })).hexdigest(),
        )


class ForkAggregateStateMachineTest(ForkAggregateChainFixtures):
    def test_insufficient_becomes_accepted_with_supplemental_evidence(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        result = self.fvchain(self.root_one, [raw])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["policyVersion"], 1)
        self.assertIsNotNone(result["commonDigest"])

    def test_insufficient_can_stay_insufficient_keeping_the_declaration(self):
        # Threshold three: a second agreeing site is still short of it.
        first = self.fsucc(
            self.root_one_t3, [ditem("three", self.decision_b)],
            old=self.pol_v1_t3, new=self.pol_v1_t3,
        )
        result = self.fvchain(
            self.root_one_t3, [first], policies=[self.pol_v1_t3] * 2,
            moment=self.m + 10,
        )
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["commonDigest"])
        second = self.fsucc(
            first, [ditem("four", self.decision_c)], old=self.pol_v1_t3,
            new=self.pol_v1_t3, moment=self.m + 20, effective=self.m + 5,
        )
        result = self.fvchain(
            self.root_one_t3, [first, second],
            policies=[self.pol_v1_t3] * 3, moment=self.m + 20,
        )
        self.assertEqual(result["status"], "accepted")

    def test_insufficient_becomes_conflicted(self):
        decision_other_c = self.make_decision(
            self.other_proofs, issuer=SITE_C
        )
        raw = self.fsucc(
            self.root_one, [ditem("three", decision_other_c)]
        )
        result = self.fvchain(self.root_one, [raw])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])

    def test_accepted_keeps_the_same_common_declaration(self):
        raw = self.fsucc(self.root_two, [ditem("three", self.decision_c)])
        result = self.fvchain(self.root_two, [raw])
        self.assertEqual(result["status"], "accepted")
        expected = hashlib.sha256(
            compact(parse(self.root_two)["payload"]["declaration"])
        ).hexdigest()
        self.assertEqual(result["commonDigest"], expected)

    def test_accepted_advances_to_conflicted_and_the_common_is_dropped(self):
        raw = self.fsucc(
            self.root_two, [ditem("three", self.decision_other)]
        )
        result = self.fvchain(self.root_two, [raw])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])

    def test_accepted_must_not_fall_back_to_insufficient(self):
        # Raising the threshold to three makes only two sites agree; the
        # accepted verdict would become insufficient, so the hop is
        # rejected rather than silently downgraded.
        raised = vpol(2, threshold=3)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.root_two, [], new=raised,
                      moment=self.m + 20, effective=self.m + 5)

    def test_conflicted_is_never_masked_by_a_later_majority(self):
        conflicted = self.fsucc(
            self.root_two, [ditem("three", self.decision_other)]
        )
        # A third site now agreeing with the original declaration would
        # outvote the disagreement under plain majority rules.
        masked = self.fsucc(
            conflicted, [ditem("four", self.decision_c)],
            moment=self.m + 20, effective=self.m + 5,
        )
        result = self.fvchain(
            self.root_two, [conflicted, masked],
            policies=[self.pol_v1] * 3, moment=self.m + 20,
        )
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])


class ForkAggregatePrefixTest(ForkAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.first = self.fsucc(
            self.root_one, [ditem("three", self.decision_b)]
        )

    def test_unchanged_policy_requires_a_new_decision(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.first, [], moment=self.m + 20,
                      effective=self.m + 5)

    def test_rotation_may_reseal_the_same_sequence(self):
        raw = self.fsucc(self.first, [], new=self.pol_v2,
                        moment=self.m + 20, effective=self.m + 5)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["decisions"], [])
        self.assertEqual(payload["policyVersion"], 2)
        result = self.fvchain(
            self.root_one, [self.first, raw],
            policies=[self.pol_v1, self.pol_v1, self.pol_v2],
            moment=self.m + 20,
        )
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["policyVersion"], 2)

    def test_existing_packet_cannot_be_appended_again(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.first, [ditem("nine", self.decision_b)],
                      moment=self.m + 20, effective=self.m + 5)

    def test_existing_id_cannot_be_reused(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.first, [ditem("one", self.decision_c)],
                      moment=self.m + 20, effective=self.m + 5)

    def test_duplicate_id_within_the_increment_is_rejected(self):
        with self.assertRaises(ValueError):
            self.fsucc(self.first, [
                ditem("nine", self.decision_c),
                ditem("nine", self.decision_a),
            ], moment=self.m + 20, effective=self.m + 5)

    def test_prefix_rows_keep_their_historical_marking(self):
        # A third agreeing site (site-b) extends the accepted two-site
        # head (judge, site-c); the rows stay site/id-sorted.
        raw = self.fsucc(self.root_two, [ditem("three", self.decision_c)])
        rows = parse(raw)["payload"]["items"]
        self.assertEqual(
            [(r["issuer"], r["id"], r["conclusion"]) for r in rows],
            [(JUDGE, "one", "valid"), (SITE_B, "three", "valid"),
             (SITE_C, "two", "valid")],
        )

    def test_a_smaller_id_joining_later_sorts_after_the_historical_rows(self):
        # A newly appended statement never rewrites a prefix row; here a
        # third agreeing site joins and the prefix valid rows survive.
        accepted = self.fsucc(
            self.root_one, [ditem("three", self.decision_b)]
        )
        raw = self.fsucc(
            accepted, [ditem("four", self.decision_c)],
            moment=self.m + 20, effective=self.m + 5,
        )
        rows = {row["id"]: row for row in parse(raw)["payload"]["items"]}
        self.assertEqual(rows["one"]["conclusion"], "valid")
        self.assertEqual(rows["three"]["conclusion"], "valid")
        self.assertEqual(rows["four"]["conclusion"], "valid")

    def test_increment_input_container_faults(self):
        with self.assertRaises(TypeError):
            self.fsucc(self.first, (ditem("nine", self.decision_c),))
        with self.assertRaises(TypeError):
            self.fsucc(self.first, [{"id": 9, "decision": self.decision_c}],
                      moment=self.m + 20, effective=self.m + 5)
        with self.assertRaises(TypeError):
            self.fsucc(self.first, [{"id": "nine", "decision": "raw"}],
                      moment=self.m + 20, effective=self.m + 5)
        with self.assertRaises(ValueError):
            self.fsucc(self.first, [ditem("", self.decision_c)],
                      moment=self.m + 20, effective=self.m + 5)
        with self.assertRaises(ValueError):
            self.fsucc(self.first, [{"id": "nine", "raw": self.decision_c}],
                      moment=self.m + 20, effective=self.m + 5)


class ForkAggregatePolicyRotationTest(ForkAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.head = self.fsucc(
            self.root_two, [ditem("three", self.decision_c)]
        )

    def test_unchanged_policy_keeps_the_version(self):
        # A third agreeing site lets the unchanged-policy chain grow; the
        # version stays 1 and the accepted head keeps its declaration.
        head = self.fsucc(
            self.root_one, [ditem("three", self.decision_b)]
        )
        same = vpol(1)
        raw = self.fsucc(
            head, [ditem("four", self.decision_c)], new=same,
            moment=self.m + 20, effective=self.m + 5,
        )
        payload = parse(raw)["payload"]
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(payload["status"], "accepted")
        rows = {row["id"]: row["conclusion"] for row in payload["items"]}
        self.assertEqual(rows["four"], "valid")

    def test_changed_policy_increments_by_exactly_one(self):
        raw = self.fsucc(self.head, [], new=self.pol_v2,
                        moment=self.m + 20, effective=self.m + 5)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["oldPolicyDigest"],
                         hashlib.sha256(policy_canon(self.pol_v1)).hexdigest())
        self.assertEqual(payload["newPolicyDigest"],
                         hashlib.sha256(policy_canon(self.pol_v2)).hexdigest())
        self.assertEqual(payload["policyVersion"], 2)

    def test_version_jump_is_rejected(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.head, [], new=vpol(3, sites=(JUDGE, SITE_C)),
                      moment=self.m + 20, effective=self.m + 5)

    def test_version_regression_is_rejected(self):
        rotated = self.fsucc(self.head, [], new=self.pol_v2,
                            moment=self.m + 20, effective=self.m + 5)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(rotated, [], old=self.pol_v2, new=self.pol_v1,
                      moment=self.m + 30, effective=self.m + 6)

    def test_changed_sites_without_version_step_is_rejected(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.head, [], new=vpol(1, sites=(JUDGE, SITE_C)),
                      moment=self.m + 20, effective=self.m + 5)

    def test_version_step_without_content_change_is_rejected(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.head, [], new=vpol(2),
                      moment=self.m + 20, effective=self.m + 5)

    def test_old_policy_must_match_the_predecessor(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.head, [], old=self.pol_v2, new=vpol(3),
                      moment=self.m + 20, effective=self.m + 5)

    def test_first_old_policy_must_match_the_root_site_policy(self):
        other = vpol(1, sites=(JUDGE, SITE_C))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.root_two, [ditem("four", self.decision_c)],
                      old=other, new=other)

    def test_rotation_never_changes_the_prune_policy(self):
        raw = self.fsucc(self.head, [], new=self.pol_v2,
                        moment=self.m + 20, effective=self.m + 5)
        other_prune = copy.deepcopy(self.policy)
        other_prune["threshold"] = 1
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_fork_aggregate_chain(
                self.root_two, [self.head, raw], other_prune, self.sp,
                [self.pol_v1, self.pol_v1, self.pol_v2], self.ring,
                self.m + 20,
            )

    def test_rotation_never_changes_the_fork_proof_site_policy(self):
        raw = self.fsucc(self.head, [], new=self.pol_v2,
                         moment=self.m + 20, effective=self.m + 5)
        other_site_policy = copy.deepcopy(self.sp)
        other_site_policy["threshold"] = 1
        # The root binds the fork-proof site policy digest, so changing
        # it fails the root, which binds that policy.
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_fork_aggregate_chain(
                self.root_two, [self.head, raw], self.policy,
                other_site_policy,
                [self.pol_v1, self.pol_v1, self.pol_v2], self.ring,
                self.m + 20,
            )

    def test_successor_bound_to_another_site_policy_is_a_chain_error(self):
        # Tamper only the successor's bound fork-proof site digest while
        # keeping the root valid: that is a chain fault.
        raw = self.fsucc(self.head, [], new=self.pol_v2,
                         moment=self.m + 20, effective=self.m + 5)
        data = parse(raw)
        data["payload"]["sitePolicyDigest"] = "00" * 32
        tampered = self.resign(data)
        with self.assertRaises(InvalidForkAggregateChainError):
            verify_fork_aggregate_chain(
                self.root_two, [self.head, tampered], self.policy, self.sp,
                [self.pol_v1, self.pol_v1, self.pol_v2], self.ring,
                self.m + 20,
            )

    def test_sealer_must_be_authorized_under_both_policies(self):
        # The rotation removes SITE_B; a SITE_B sealer is present in the
        # old policy but not the rotated one and can no longer seal.
        removes_b = vpol(2, sites=(JUDGE, SITE_C))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.head, [], new=removes_b, issuer=SITE_B,
                      moment=self.m + 20, effective=self.m + 5)
        # JUDGE survives the rotation and seals the hop.
        raw = self.fsucc(self.head, [], new=removes_b, issuer=JUDGE,
                        moment=self.m + 20, effective=self.m + 5)
        result = verify_fork_aggregate_chain(
            self.root_two, [self.head, raw], self.policy, self.sp,
            [self.pol_v1, self.pol_v1, removes_b], self.ring,
            self.m + 20,
        )
        self.assertEqual(result["status"], "accepted")

    def test_effective_moment_never_moves_backwards(self):
        rotated = self.fsucc(self.head, [], new=self.pol_v2,
                            moment=self.m + 20, effective=self.m + 5)
        with self.assertRaises(ValueError):
            self.fsucc(rotated, [], old=self.pol_v2,
                      new=vpol(3, sites=(JUDGE, SITE_C)),
                      moment=self.m + 30, effective=self.m + 4)


class ForkAggregateCredentialTest(ForkAggregateChainFixtures):
    def test_sealer_credential_must_be_usable_at_effective_moment(self):
        future_ring = copy.deepcopy(self.ring)
        future_ring[JUDGE][0]["notBefore"] = self.m + 5
        with self.assertRaises(AuthenticationError):
            supersede_fork_aggregate(
                self.root_one, [ditem("three", self.decision_b)],
                self.policy, self.sp, self.pol_v1, self.pol_v1, future_ring,
                self.m + 10, self.m, JUDGE, 1,
            )

    def test_sealer_credential_must_be_usable_at_issuance_moment(self):
        short_ring = copy.deepcopy(self.ring)
        short_ring[JUDGE][0]["notAfter"] = self.m + 5
        with self.assertRaises(AuthenticationError):
            supersede_fork_aggregate(
                self.root_one, [ditem("three", self.decision_b)],
                self.policy, self.sp, self.pol_v1, self.pol_v1, short_ring,
                self.m + 10, self.m, JUDGE, 1,
            )

    def test_later_revocation_rejects_the_successor_at_verify_time(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], revoked, self.m + 10,
            )

    def test_wrong_successor_signature_is_authentication_error(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        data = parse(raw)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            verify_fork_aggregate_chain(
                self.root_one, [compact(data)], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], self.ring, self.m + 10,
            )

    def test_exact_key_version_with_no_fallback(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        ring_v2 = copy.deepcopy(self.ring)
        ring_v2[JUDGE] = ring_v2[JUDGE] + [entry(2, "22" * 32)]
        result = verify_fork_aggregate_chain(
            self.root_one, [raw], self.policy, self.sp,
            [self.pol_v1, self.pol_v1], ring_v2, self.m + 10,
        )
        self.assertEqual(result["status"], "accepted")
        without_v1 = copy.deepcopy(ring_v2)
        without_v1[JUDGE] = [ring_v2[JUDGE][1]]
        with self.assertRaises(AuthenticationError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], without_v1, self.m + 10,
            )

    def test_unauthorized_sealer_is_a_chain_error(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.root_one, [ditem("three", self.decision_b)],
                      issuer="ghost-site")

    def test_authorized_but_unknown_credential_is_authentication_error(self):
        missing = {site: keys for site, keys in self.ring.items()
                   if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            supersede_fork_aggregate(
                self.root_one, [ditem("three", self.decision_b)],
                self.policy, self.sp, self.pol_v1, self.pol_v1, missing,
                self.m + 10, self.m, JUDGE, 1,
            )

    def test_new_decision_not_yet_valid_is_recomputed_as_invalid(self):
        # A decision signed with a key that is not yet valid at the hop's
        # moments carries no authority then; the statement is dropped and
        # the head stays insufficient with the original declaration.  A
        # fork decision packet binds no moment, so it is produced with a
        # currently-usable copy of the key and re-checked against a ring
        # where that same key only becomes valid later.
        late_secret = "33" * 32
        signing_ring = copy.deepcopy(self.ring)
        signing_ring[SITE_C] = [entry(1, late_secret)]
        late_ring = copy.deepcopy(signing_ring)
        late_ring[SITE_C][0]["notBefore"] = self.m + 50
        decision = self.make_decision(
            self.proofs, issuer=SITE_C, ring=signing_ring
        )
        raw = supersede_fork_aggregate(
            self.root_one, [ditem("three", decision)],
            self.policy, self.sp, self.pol_v1, self.pol_v1, late_ring,
            self.m + 10, self.m + 10, JUDGE, 1,
        )
        result = verify_fork_aggregate_chain(
            self.root_one, [raw], self.policy, self.sp,
            [self.pol_v1, self.pol_v1], late_ring, self.m + 10,
        )
        self.assertEqual(result["status"], "insufficient")
        rows = parse(raw)["payload"]["items"]
        new_row = next(row for row in rows if row["id"] == "three")
        self.assertEqual(new_row["conclusion"], "invalid")
        self.assertEqual(new_row["reason"], "unauthenticated")
        # A credential-time rejection keeps the claimed identity but
        # carries no declaration.
        self.assertEqual(new_row["issuer"], SITE_C)
        self.assertIsNone(new_row["declaration"])
        # With a now-valid keyring the historical verdict genuinely
        # differs at the effective moment too (the packet binds no
        # moment), so the chain no longer binds.
        with self.assertRaises(InvalidForkAggregateChainError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], signing_ring, self.m + 60,
            )

    def test_new_decision_that_expires_after_the_hop_is_an_auth_fault(self):
        # A decision credential usable at the effective moment but
        # expired by the verification moment changes the settled verdict
        # only at the latter, which is an authentication fault rather
        # than a rewrite of the bound effective-time conclusion.
        short_ring = copy.deepcopy(self.ring)
        short_ring[SITE_C][0]["notAfter"] = self.m + 15
        raw = supersede_fork_aggregate(
            self.root_one, [ditem("three", self.decision_b)],
            self.policy, self.sp, self.pol_v1, self.pol_v1, short_ring,
            self.m + 10, self.m + 10, JUDGE, 1,
        )
        result = verify_fork_aggregate_chain(
            self.root_one, [raw], self.policy, self.sp,
            [self.pol_v1, self.pol_v1], short_ring, self.m + 10,
        )
        self.assertEqual(result["status"], "accepted")
        with self.assertRaises(AuthenticationError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], short_ring, self.m + 60,
            )


class VerifyForkAggregateChainBindingTest(ForkAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.fsucc(
            self.root_one, [ditem("three", self.decision_b)]
        )

    def _tamper(self, mutate):
        data = parse(self.raw)
        mutate(data)
        return self.resign(data)

    def test_bare_root_is_verified_in_full_with_empty_successors(self):
        result = self.fvchain(self.root_two, [], policies=[self.pol_v1])
        self.assertEqual(list(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.root_two).hexdigest())
        self.assertEqual(result["headDigest"], result["rootDigest"])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")

    def test_bare_root_common_digest(self):
        result = self.fvchain(self.root_one, [])
        self.assertEqual(result["status"], "insufficient")
        declaration = parse(self.root_one)["payload"]["declaration"]
        self.assertEqual(
            result["commonDigest"],
            hashlib.sha256(compact(declaration)).hexdigest(),
        )
        root_null = self.make_aggregate(
            [ditem("junk", b"nope")], dsp=plain(self.pol_v1)
        )
        self.assertIsNone(self.fvchain(root_null, [])["commonDigest"])

    def test_bare_root_against_another_site_policy_is_a_bad_root(self):
        other = vpol(1, sites=(JUDGE,), threshold=1)
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            self.fvchain(self.root_two, [], policies=[other])

    def test_bad_root_raises_the_root_error(self):
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            self.fvchain(b"not-an-aggregate", [])

    def test_tampered_root_digest_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "rootDigest", "00" * 32))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_predecessor_digest_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "predecessorDigest", "00" * 32))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_height_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__("height", 5))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_status_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "status", "conflicted"))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_common_declaration_is_chain_error(self):
        def mutate(data):
            common = data["payload"]["declaration"]["common"]
            common[0]["rootDigest"] = "00" * 32
        raw = self._tamper(mutate)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_row_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"]["items"][0].__setitem__(
            "conclusion", "duplicate"))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_increment_decision_is_chain_error(self):
        def mutate(data):
            data["payload"]["decisions"][0]["decision"] = (
                self.decision_c.hex()
            )
        raw = self._tamper(mutate)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_policy_digests_are_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "newPolicyDigest", "00" * 32))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_decision_policy_digest_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "decisionSitePolicyDigest", "00" * 32))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_invariant_site_policy_digest_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "sitePolicyDigest", "00" * 32))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_policy_version_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "policyVersion", 2))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_effective_moment_regression_is_chain_error(self):
        first = self.fsucc(
            self.root_one, [ditem("three", self.decision_b)],
            moment=self.m + 10, effective=self.m,
        )
        second = self.fsucc(
            first, [ditem("four", self.decision_c)],
            moment=self.m + 20, effective=self.m + 5,
        )
        data = parse(second)
        data["payload"]["effectiveAt"] = self.m - 1
        tampered = self.resign(data)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(
                self.root_one, [first, tampered],
                policies=[self.pol_v1] * 3, moment=self.m + 20,
            )

    def test_negative_effective_moment_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "effectiveAt", -1))
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_trailing_byte_is_chain_error(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            verify_fork_aggregate_chain(
                self.root_one, [self.raw + b"\n"], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], self.ring, self.m + 10,
            )

    def test_duplicate_json_key_is_chain_error(self):
        text = self.raw.decode("utf-8").replace(
            '"height":1', '"height":1,"height":2', 1,
        )
        with self.assertRaises(InvalidForkAggregateChainError):
            verify_fork_aggregate_chain(
                self.root_one, [text.encode("utf-8")], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], self.ring, self.m + 10,
            )

    def test_non_canonical_encoding_is_chain_error(self):
        import json
        indented = json.dumps(parse(self.raw), indent=1, sort_keys=True)
        with self.assertRaises(InvalidForkAggregateChainError):
            verify_fork_aggregate_chain(
                self.root_one, [indented.encode("utf-8")], self.policy,
                self.sp, [self.pol_v1, self.pol_v1], self.ring,
                self.m + 10,
            )

    def test_prune_policy_mismatch_at_verify_fails_the_root(self):
        other = copy.deepcopy(self.policy)
        other["threshold"] = 1
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            verify_fork_aggregate_chain(
                self.root_one, [self.raw], other, self.sp,
                [self.pol_v1, self.pol_v1], self.ring, self.m + 10,
            )


class ForkAggregateChainArgumentTest(ForkAggregateChainFixtures):
    def test_policy_history_count_must_match_the_stages(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp, [self.pol_v1],
                self.ring, self.m + 10,
            )
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp,
                [self.pol_v1] * 3, self.ring, self.m + 10,
            )

    def test_root_stage_policy_must_be_version_one(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp,
                [vpol(2), self.pol_v1], self.ring, self.m + 10,
            )

    def test_policy_history_container_faults(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp, self.pol_v1,
                self.ring, self.m + 10,
            )
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp, [],
                self.ring, self.m + 10,
            )
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp,
                [{"sites": {}, "threshold": 2, "policyVersion": 1},
                 self.pol_v1],
                self.ring, self.m + 10,
            )

    def test_shared_material_faults(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], {"batch": "x", "sites": {},
                                       "threshold": 1}, self.sp,
                [self.pol_v1, self.pol_v1], self.ring, self.m + 10,
            )
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, {"sites": {}},
                [self.pol_v1, self.pol_v1], self.ring, self.m + 10,
            )
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                self.root_one, [raw], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], "ring", self.m + 10,
            )

    def test_public_argument_type_and_value_faults(self):
        good_inc = [ditem("three", self.decision_b)]
        with self.assertRaises(TypeError):
            self.fsucc("not-bytes", good_inc)
        with self.assertRaises(TypeError):
            supersede_fork_aggregate(
                self.root_one, good_inc, self.policy, self.sp,
                self.pol_v1, self.pol_v1, self.ring, True, self.m,
                JUDGE, 1,
            )
        with self.assertRaises(TypeError):
            supersede_fork_aggregate(
                self.root_one, good_inc, self.policy, self.sp,
                self.pol_v1, self.pol_v1, self.ring, self.m + 10, True,
                JUDGE, 1,
            )
        with self.assertRaises(ValueError):
            self.fsucc(self.root_one, good_inc, effective=-1,
                      moment=self.m + 10)
        with self.assertRaises(ValueError):
            self.fsucc(self.root_one, good_inc, moment=-1)
        with self.assertRaises(TypeError):
            self.fsucc(self.root_one, good_inc, issuer=7)
        with self.assertRaises(ValueError):
            self.fsucc(self.root_one, good_inc, issuer="")
        with self.assertRaises(TypeError):
            self.fsucc(self.root_one, good_inc, version=True)
        with self.assertRaises(ValueError):
            self.fsucc(self.root_one, good_inc, version=0)
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                "x", [], self.policy, self.sp, [self.pol_v1], self.ring,
                self.m,
            )
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                self.root_one, b"x", self.policy, self.sp, [self.pol_v1],
                self.ring, self.m,
            )
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                self.root_one, [b"x"], self.policy, self.sp,
                [self.pol_v1, self.pol_v1], self.ring, True,
            )

    def test_versioned_policy_faults(self):
        good_inc = [ditem("three", self.decision_b)]
        with self.assertRaises(ValueError):
            self.fsucc(self.root_one, good_inc,
                      new={"sites": {JUDGE: {1}, SITE_C: {1}},
                           "threshold": 2})
        with self.assertRaises(ValueError):
            self.fsucc(self.root_one, good_inc, new=vpol(0))
        with self.assertRaises(TypeError):
            self.fsucc(self.root_one, good_inc,
                      new={"sites": {JUDGE: {1}, SITE_C: {1}},
                           "threshold": 2, "policyVersion": True})
        with self.assertRaises(TypeError):
            self.fsucc(self.root_one, good_inc,
                      new={"sites": [], "threshold": 2, "policyVersion": 1})


class ForkAggregateHeadAnchorTest(ForkAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.first = self.fsucc(
            self.root_one, [ditem("three", self.decision_b)]
        )
        self.policies = [self.pol_v1, self.pol_v1]

    def test_anchor_shape_and_bindings(self):
        anchor = self.fseal(
            self.root_one, [self.first], self.policies,
            moment=self.m + 10,
        )
        self.assertTrue(anchor.endswith(b"}"))
        data = parse(anchor)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), ANCHOR_PAYLOAD_KEYS)
        self.assertEqual(payload["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["headDigest"],
                         hashlib.sha256(self.first).hexdigest())
        self.assertEqual(payload["height"], 1)
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(policy_canon(self.pol_v1)).hexdigest(),
        )
        self.assertEqual(payload["moment"], self.m + 10)
        self.assertEqual(compact(data), anchor)

    def test_anchor_over_a_rotation_binds_the_head_policy(self):
        rotated = self.fsucc(
            self.first, [], new=self.pol_v2,
            moment=self.m + 20, effective=self.m + 5,
        )
        anchor = self.fseal(
            self.root_one, [self.first, rotated],
            [self.pol_v1, self.pol_v1, self.pol_v2],
            moment=self.m + 20,
        )
        payload = parse(anchor)["payload"]
        self.assertEqual(payload["policyVersion"], 2)
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(policy_canon(self.pol_v2)).hexdigest(),
        )
        result = self.fvhead(
            anchor, self.root_one, [self.first, rotated],
            [self.pol_v1, self.pol_v1, self.pol_v2],
            moment=self.m + 20,
        )
        self.assertEqual(list(result.keys()), ANCHOR_RESULT_KEYS)
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["anchorDigest"],
                         hashlib.sha256(anchor).hexdigest())

    def test_bare_accepted_root_can_be_anchored_at_height_zero(self):
        anchor = self.fseal(self.root_two, [], [self.pol_v1])
        result = self.fvhead(anchor, self.root_two, [], [self.pol_v1])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(self.root_two).hexdigest())

    def test_insufficient_head_is_not_sealed(self):
        with self.assertRaises(ValueError):
            self.fseal(self.root_one, [], [self.pol_v1])

    def test_conflicted_head_is_not_sealed(self):
        with self.assertRaises(ValueError):
            self.fseal(self.root_conf, [], [self.pol_v1])

    def test_tampered_anchor_bindings_are_rejected(self):
        anchor = self.fseal(self.root_one, [self.first], self.policies,
                                moment=self.m + 10)
        for field, value in (
            ("height", 9),
            ("rootDigest", "00" * 32),
            ("headDigest", "00" * 32),
            ("policyVersion", 2),
        ):
            data = parse(anchor)
            data["payload"][field] = value
            with self.assertRaises(InvalidForkAggregateChainError):
                self.fvhead(self.resign(data),
                           self.root_one, [self.first], self.policies,
                           moment=self.m + 10)

    def test_anchor_over_another_chain_is_rejected(self):
        anchor = self.fseal(self.root_one, [self.first], self.policies,
                                moment=self.m + 10)
        other = self.fsucc(self.root_two, [ditem("four", self.decision_c)],
                          moment=self.m + 10, effective=self.m)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvhead(anchor, self.root_two, [other], self.policies,
                       moment=self.m + 10)

    def test_bad_anchor_signature_is_authentication_error(self):
        anchor = self.fseal(self.root_one, [self.first], self.policies,
                                moment=self.m + 10)
        data = parse(anchor)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.fvhead(compact(data), self.root_one, [self.first],
                       self.policies, moment=self.m + 10)

    def test_revoked_anchor_signer_is_authentication_error(self):
        anchor = self.fseal(self.root_one, [self.first], self.policies,
                                moment=self.m + 10)
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            verify_fork_aggregate_head(
                anchor, self.root_one, [self.first], self.policy, self.sp,
                self.policies, revoked, self.m + 10,
            )

    def test_malformed_anchor_is_a_chain_error(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvhead(b"not-an-anchor", self.root_one, [self.first],
                       self.policies, moment=self.m + 10)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvhead(self.fseal(
                self.root_one, [self.first], self.policies,
                moment=self.m + 10,
            ) + b"\n", self.root_one, [self.first], self.policies,
                moment=self.m + 10)

    def test_seal_argument_faults(self):
        with self.assertRaises(TypeError):
            self.fseal(self.root_one, [self.first], self.policies,
                           issuer=9)
        with self.assertRaises(ValueError):
            self.fseal(self.root_one, [self.first], self.policies,
                           issuer="")
        with self.assertRaises(TypeError):
            self.fseal(self.root_one, [self.first], self.policies,
                           version=True)
        with self.assertRaises(ValueError):
            self.fseal(self.root_one, [self.first], self.policies,
                           version=0)
        with self.assertRaises(AuthenticationError):
            self.fseal(self.root_one, [self.first], self.policies,
                           issuer="ghost", moment=self.m + 10)
        with self.assertRaises(ValueError):
            self.fseal(self.root_one, [self.first], [self.pol_v1],
                           moment=self.m + 10)


class ForkAggregateErrorHierarchyTest(ForkAggregateChainFixtures):
    def test_error_classes(self):
        self.assertTrue(
            issubclass(InvalidForkAggregateChainError, ValueError)
        )
        self.assertTrue(
            issubclass(InvalidAggregateForkDecisionAggregateError, ValueError)
        )
        self.assertIsNot(InvalidForkAggregateChainError,
                         InvalidAggregateForkDecisionAggregateError)
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class ForkAggregateIndependenceTest(ForkAggregateChainFixtures):
    def test_chain_results_are_equal_but_independent(self):
        raw = self.fsucc(self.root_one, [ditem("three", self.decision_b)])
        first = self.fvchain(self.root_one, [raw])
        second = self.fvchain(self.root_one, [raw])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["status"] = "conflicted"
        self.assertEqual(
            self.fvchain(self.root_one, [raw])["status"], "accepted"
        )

    def test_anchor_results_are_equal_but_independent(self):
        anchor = self.fseal(self.root_two, [], [self.pol_v1])
        first = self.fvhead(anchor, self.root_two, [], [self.pol_v1])
        second = self.fvhead(anchor, self.root_two, [], [self.pol_v1])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["height"] = 9
        self.assertEqual(
            self.fvhead(anchor, self.root_two, [], [self.pol_v1])["height"],
            0,
        )

    def test_inputs_are_not_modified(self):
        increment = [ditem("three", self.decision_b)]
        inc_snapshot = copy.deepcopy(increment)
        root_snapshot = copy.deepcopy(self.root_one)
        pol_snapshot = copy.deepcopy(self.pol_v1)
        ring_snapshot = copy.deepcopy(self.ring)
        self.fsucc(self.root_one, increment)
        self.assertEqual(increment, inc_snapshot)
        self.assertEqual(self.root_one, root_snapshot)
        self.assertEqual(self.pol_v1, pol_snapshot)
        self.assertEqual(self.ring, ring_snapshot)

    def test_no_file_is_read_or_written(self):
        raw = self.fsucc(
            self.root_one, [ditem("three", self.decision_b)]
        )
        anchor = self.fseal(
            self.root_one, [raw], [self.pol_v1, self.pol_v1],
            moment=self.m + 10,
        )
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.fvchain(self.root_one, [raw])
            self.fvhead(anchor, self.root_one, [raw],
                       [self.pol_v1, self.pol_v1], moment=self.m + 10)


if __name__ == "__main__":
    unittest.main()
