"""Tests for supersession chains over cross-site prune batch aggregates.

Covers :func:`supersede_prune_aggregate`,
:func:`verify_prune_aggregate_chain`, :func:`seal_prune_aggregate_head`
and :func:`verify_prune_aggregate_head`: the canonical signed
successor packet and every binding (root, predecessor, height, the full
recomputed conclusion, the raw handover increment as hex, the
invariant prune policy digest, old/new site policy digests, policy
version and effective moment), the per-hop verdict state machine
(insufficient to accepted/conflicted, accepted only kept or upgraded,
conflicted never masked), the append-only handover prefix with
unchanged-policy growth and rotation-only re-sealing, versioned site
policy rotation with a single policyVersion step, dual-policy sealer
authorization and credential usability at both moments, offline
hop-by-hop verification from just the root, ordered successors,
original prune policy, complete policy history, current keyring and
moment, bare-root verification, the fresh chain summary with the
common declaration digest, the stable head anchor seal/reverify rules,
and every error classification (including a bool never posing as an
int), input immutability and the purely offline guarantee.
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
    InvalidAggregateAnchorError,
    InvalidAggregateChainError,
    InvalidPruneBatchAggregateError,
    aggregate_prune_batches,
    seal_prune_aggregate_head,
    supersede_prune_aggregate,
    verify_prune_aggregate_chain,
    verify_prune_aggregate_head,
)

from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_aggregate_prune_batches import PruneBatchAggregateFixtures

PACKET_KEYS = ["payload", "signature"]
SUCCESSOR_PAYLOAD_KEYS = [
    "declaration", "effectiveAt", "handovers", "height", "inputs",
    "issuer", "items", "keyVersion", "newPolicyDigest", "oldPolicyDigest",
    "policyVersion", "predecessorDigest", "prunePolicyDigest", "rootDigest",
    "status", "version",
]
INCREMENT_KEYS = ["id", "packet"]
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


def pitem(item_id, packet):
    """One supersession increment item: a unique id and a handover packet."""
    return {"id": item_id, "packet": packet}


def vpol(policy_version=1, sites=(SITE_A, SITE_B, SITE_C), threshold=2):
    """A versioned site policy: sites, threshold and policyVersion."""
    return {
        "sites": {site: {1} for site in sites},
        "threshold": threshold,
        "policyVersion": policy_version,
    }


def plain(vpol_value):
    """Strip the version from a versioned site policy (root form)."""
    return {"sites": copy.deepcopy(vpol_value["sites"]),
            "threshold": vpol_value["threshold"]}


def policy_canon(policy):
    """Canonical compact bytes of a versioned site policy (sets -> arrays)."""
    return compact({
        "sites": {site: sorted(policy["sites"][site])
                  for site in sorted(policy["sites"])},
        "threshold": policy["threshold"],
        "policyVersion": policy["policyVersion"],
    })


class PruneAggregateChainFixtures(PruneBatchAggregateFixtures,
                                  unittest.TestCase):
    """Shared roots, handovers, policies and chain builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.pol_v1 = vpol()
        self.pol_v2 = vpol(2, sites=(SITE_A, SITE_B))
        self.pol_v1_t3 = vpol(threshold=3)
        # Roots are plain cross-site aggregates over the unversioned
        # site policy: one site (insufficient), two agreeing (accepted),
        # and two disagreeing sites (conflicted).
        self.root_one = self.aggregate([pitem("one", self.pkt_a)])
        self.root_two = self.aggregate([
            pitem("one", self.pkt_a), pitem("two", self.pkt_b),
        ])
        self.root_conf = self.aggregate([
            pitem("one", self.pkt_a), pitem("two", self.pkt_b_other),
        ])
        self.root_one_t3 = self.aggregate(
            [pitem("one", self.pkt_a)], sp=plain(self.pol_v1_t3)
        )

    def succ(self, predecessor, increment, old=None, new=None,
             moment=None, effective=None, issuer=SITE_A, version=1):
        return supersede_prune_aggregate(
            predecessor, increment, self.policy,
            self.pol_v1 if old is None else old,
            self.pol_v1 if new is None else new,
            self.ring,
            self.moment + 10 if moment is None else moment,
            self.moment if effective is None else effective,
            issuer, version,
        )

    def vchain(self, root, successors, policies=None, moment=None):
        if policies is None:
            policies = [self.pol_v1] * (len(successors) + 1)
        if moment is None:
            moment = self.moment + 10 * max(1, len(successors))
        return verify_prune_aggregate_chain(
            root, successors, self.policy, policies, self.ring, moment,
        )

    def seal_head(self, root, successors, policies=None, moment=None,
             issuer=JUDGE, version=1):
        if policies is None:
            policies = [self.pol_v1] * (len(successors) + 1)
        if moment is None:
            moment = self.moment + 10 * max(1, len(successors))
        return seal_prune_aggregate_head(
            root, successors, self.policy, policies, self.ring, moment,
            issuer, version,
        )

    def vhead(self, anchor, root, successors, policies=None, moment=None):
        if policies is None:
            policies = [self.pol_v1] * (len(successors) + 1)
        if moment is None:
            moment = self.moment + 10 * max(1, len(successors))
        return verify_prune_aggregate_head(
            anchor, root, successors, self.policy, policies, self.ring,
            moment,
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


class SupersedePruneAggregateShapeTest(PruneAggregateChainFixtures):
    def test_packet_shape_and_canonical_encoding(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), SUCCESSOR_PAYLOAD_KEYS)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["issuer"], SITE_A)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(compact(data), raw)

    def test_root_predecessor_height_and_digests(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        payload = parse(raw)["payload"]
        self.assertEqual(payload["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["predecessorDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["height"], 1)

    def test_later_successor_links_and_height(self):
        first = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        second = self.succ(first, [pitem("four", self.pkt_c)],
                           moment=self.moment + 20,
                           effective=self.moment + 5)
        payload = parse(second)["payload"]
        self.assertEqual(payload["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["predecessorDigest"],
                         hashlib.sha256(first).hexdigest())
        self.assertEqual(payload["height"], 2)

    def test_increment_rides_as_hex_and_inputs_are_prefix_plus_new(self):
        increment = [pitem("three", self.pkt_b)]
        raw = self.succ(self.root_one, increment)
        payload = parse(raw)["payload"]
        bound = payload["handovers"]
        self.assertEqual([list(item.keys()) for item in bound],
                         [INCREMENT_KEYS])
        self.assertEqual(bound[0]["id"], "three")
        self.assertEqual(bound[0]["packet"], self.pkt_b.hex())
        self.assertEqual(payload["inputs"], [
            hashlib.sha256(self.pkt_a).hexdigest(),
            hashlib.sha256(self.pkt_b).hexdigest(),
        ])

    def test_bound_rows_are_the_full_recomputed_conclusion(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        payload = parse(raw)["payload"]
        sites = [(row["issuer"], row["id"]) for row in payload["items"]]
        self.assertEqual(sites, [(SITE_A, "one"), (SITE_B, "three")])
        for row in payload["items"]:
            self.assertIsNone(row["reason"])
            self.assertEqual(row["conclusion"], "valid")

    def test_policy_digests_bound(self):
        raw = self.succ(self.root_two, [pitem("three", self.pkt_c)])
        payload = parse(raw)["payload"]
        expected_old = hashlib.sha256(policy_canon(self.pol_v1)).hexdigest()
        self.assertEqual(payload["oldPolicyDigest"], expected_old)
        self.assertEqual(payload["newPolicyDigest"], expected_old)
        self.assertEqual(
            payload["prunePolicyDigest"],
            hashlib.sha256(compact({
                "batch": self.policy["batch"],
                "sites": {s: [1] for s in sorted(self.policy["sites"])},
                "threshold": self.policy["threshold"],
            })).hexdigest(),
        )


class PruneAggregateStateMachineTest(PruneAggregateChainFixtures):
    def test_insufficient_becomes_accepted_with_supplemental_evidence(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        result = self.vchain(self.root_one, [raw])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["policyVersion"], 1)
        self.assertIsNotNone(result["commonDigest"])

    def test_insufficient_can_stay_insufficient_keeping_the_declaration(self):
        # Threshold three: a second agreeing site is still short of it.
        first = self.succ(
            self.root_one_t3, [pitem("three", self.pkt_b)],
            old=self.pol_v1_t3, new=self.pol_v1_t3,
        )
        result = self.vchain(
            self.root_one_t3, [first], policies=[self.pol_v1_t3] * 2,
            moment=self.moment + 10,
        )
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["commonDigest"])
        second = self.succ(
            first, [pitem("four", self.pkt_c)], old=self.pol_v1_t3,
            new=self.pol_v1_t3, moment=self.moment + 20,
            effective=self.moment + 5,
        )
        result = self.vchain(
            self.root_one_t3, [first, second],
            policies=[self.pol_v1_t3] * 3, moment=self.moment + 20,
        )
        self.assertEqual(result["status"], "accepted")

    def test_insufficient_becomes_conflicted(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b_other)])
        result = self.vchain(self.root_one, [raw])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])

    def test_accepted_keeps_the_same_common_declaration(self):
        raw = self.succ(self.root_two, [pitem("three", self.pkt_c)])
        result = self.vchain(self.root_two, [raw])
        self.assertEqual(result["status"], "accepted")
        expected = hashlib.sha256(
            compact(parse(self.root_two)["payload"]["declaration"])
        ).hexdigest()
        self.assertEqual(result["commonDigest"], expected)

    def test_accepted_advances_to_conflicted_and_the_common_is_dropped(self):
        raw = self.succ(self.root_two, [pitem("three", self.pkt_b_other)])
        result = self.vchain(self.root_two, [raw])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])

    def test_accepted_must_not_fall_back_to_insufficient(self):
        # Raising the threshold to three makes only two sites agree; the
        # accepted verdict would become insufficient, so the hop is
        # rejected rather than silently downgraded.
        raised = vpol(2, threshold=3)
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.root_two, [], new=raised,
                      moment=self.moment + 20, effective=self.moment + 5)

    def test_conflicted_is_never_masked_by_a_later_majority(self):
        conflicted = self.succ(
            self.root_two, [pitem("three", self.pkt_b_other)]
        )
        # A third site now agreeing with the original declaration would
        # outvote the disagreement under plain majority rules.
        masked = self.succ(
            conflicted, [pitem("four", self.pkt_c)],
            moment=self.moment + 20, effective=self.moment + 5,
        )
        result = self.vchain(
            self.root_two, [conflicted, masked],
            policies=[self.pol_v1] * 3, moment=self.moment + 20,
        )
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])


class PruneAggregatePrefixTest(PruneAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.first = self.succ(
            self.root_one, [pitem("three", self.pkt_b)]
        )

    def test_unchanged_policy_requires_a_new_handover(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.first, [], moment=self.moment + 20,
                      effective=self.moment + 5)

    def test_rotation_may_reseal_the_same_sequence(self):
        raw = self.succ(self.first, [], new=self.pol_v2,
                        moment=self.moment + 20, effective=self.moment + 5)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["handovers"], [])
        self.assertEqual(payload["policyVersion"], 2)
        result = self.vchain(
            self.root_one, [self.first, raw],
            policies=[self.pol_v1, self.pol_v1, self.pol_v2],
            moment=self.moment + 20,
        )
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["policyVersion"], 2)

    def test_existing_packet_cannot_be_appended_again(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.first, [pitem("nine", self.pkt_b)],
                      moment=self.moment + 20, effective=self.moment + 5)

    def test_existing_id_cannot_be_reused(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.first, [pitem("one", self.pkt_c)],
                      moment=self.moment + 20, effective=self.moment + 5)

    def test_duplicate_id_within_the_increment_is_rejected(self):
        with self.assertRaises(ValueError):
            self.succ(self.first, [
                pitem("nine", self.pkt_c), pitem("nine", self.pkt_a),
            ], moment=self.moment + 20, effective=self.moment + 5)

    def test_prefix_rows_keep_their_historical_marking(self):
        # A third agreeing site extends the accepted two-site head; the
        # two prefix statements stay valid and the new one joins them.
        raw = self.succ(self.root_two, [pitem("three", self.pkt_c)])
        rows = parse(raw)["payload"]["items"]
        self.assertEqual(
            [(r["issuer"], r["id"], r["conclusion"]) for r in rows],
            [(SITE_A, "one", "valid"), (SITE_B, "two", "valid"),
             (SITE_C, "three", "valid")],
        )

    def test_a_smaller_id_repeat_cannot_rewrite_the_historical_valid(self):
        # The prefix already settled site A's statement on "one".  A
        # later repeat carrying a lexicographically smaller id ("aaa")
        # is appended as a duplicate and must never replace the valid
        # historical row, regardless of the root's smallest-id election.
        accepted = self.succ(
            self.root_one, [pitem("three", self.pkt_b)]
        )
        repeat = self.handover(self.h1, issuer=SITE_A, moment=self.moment + 1)
        raw = self.succ(
            accepted, [pitem("aaa", repeat)],
            moment=self.moment + 20, effective=self.moment + 5,
        )
        rows = {row["id"]: row for row in parse(raw)["payload"]["items"]}
        self.assertEqual(rows["one"]["conclusion"], "valid")
        self.assertEqual(rows["aaa"]["conclusion"], "duplicate")
        self.assertEqual(rows["aaa"]["reason"], "duplicate")

    def test_increment_input_container_faults(self):
        with self.assertRaises(TypeError):
            self.succ(self.first, (pitem("nine", self.pkt_c),))
        with self.assertRaises(TypeError):
            self.succ(self.first, [{"id": 9, "packet": self.pkt_c}],
                      moment=self.moment + 20, effective=self.moment + 5)
        with self.assertRaises(TypeError):
            self.succ(self.first, [{"id": "nine", "packet": "raw"}],
                      moment=self.moment + 20, effective=self.moment + 5)
        with self.assertRaises(ValueError):
            self.succ(self.first, [pitem("", self.pkt_c)],
                      moment=self.moment + 20, effective=self.moment + 5)
        with self.assertRaises(ValueError):
            self.succ(self.first, [{"id": "nine", "raw": self.pkt_c}],
                      moment=self.moment + 20, effective=self.moment + 5)


class PruneAggregatePolicyRotationTest(PruneAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.head = self.succ(self.root_two, [pitem("three", self.pkt_c)])

    def test_unchanged_policy_keeps_the_version(self):
        # A second distinct handover packet carrying the identical
        # declaration lets the unchanged-policy chain grow; the version
        # stays 1 and the repeated same-site statement is a duplicate.
        same = vpol(1)
        repeat = self.handover(self.h1, issuer=SITE_A, moment=self.moment + 1)
        raw = self.succ(
            self.head, [pitem("four", repeat)], new=same,
            moment=self.moment + 20, effective=self.moment + 5,
        )
        payload = parse(raw)["payload"]
        self.assertEqual(payload["policyVersion"], 1)
        rows = {row["id"]: row["conclusion"] for row in payload["items"]}
        self.assertEqual(rows["four"], "duplicate")

    def test_changed_policy_increments_by_exactly_one(self):
        raw = self.succ(self.head, [], new=self.pol_v2,
                        moment=self.moment + 20, effective=self.moment + 5)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["oldPolicyDigest"],
                         hashlib.sha256(policy_canon(self.pol_v1)).hexdigest())
        self.assertEqual(payload["newPolicyDigest"],
                         hashlib.sha256(policy_canon(self.pol_v2)).hexdigest())
        self.assertEqual(payload["policyVersion"], 2)

    def test_version_jump_is_rejected(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.head, [], new=vpol(3, sites=(SITE_A, SITE_B)),
                      moment=self.moment + 20, effective=self.moment + 5)

    def test_version_regression_is_rejected(self):
        rotated = self.succ(self.head, [], new=self.pol_v2,
                            moment=self.moment + 20,
                            effective=self.moment + 5)
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(rotated, [], old=self.pol_v2, new=self.pol_v1,
                      moment=self.moment + 30, effective=self.moment + 6)

    def test_changed_sites_without_version_step_is_rejected(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.head, [], new=vpol(1, sites=(SITE_A, SITE_B)),
                      moment=self.moment + 20, effective=self.moment + 5)

    def test_version_step_without_content_change_is_rejected(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.head, [], new=vpol(2),
                      moment=self.moment + 20, effective=self.moment + 5)

    def test_old_policy_must_match_the_predecessor(self):
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.head, [], old=self.pol_v2, new=vpol(3),
                      moment=self.moment + 20, effective=self.moment + 5)

    def test_first_old_policy_must_match_the_root_site_policy(self):
        other = vpol(1, sites=(SITE_A, SITE_B))
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.root_two, [pitem("four", self.pkt_c)],
                      old=other, new=other)

    def test_rotation_never_changes_the_prune_policy(self):
        # Verifying the whole chain against a different original prune
        # policy fails at the root, which binds that policy's digest.
        raw = self.succ(self.head, [], new=self.pol_v2,
                        moment=self.moment + 20, effective=self.moment + 5)
        other_prune = copy.deepcopy(self.policy)
        other_prune["threshold"] = 1
        with self.assertRaises(InvalidPruneBatchAggregateError):
            verify_prune_aggregate_chain(
                self.root_two, [self.head, raw], other_prune,
                [self.pol_v1, self.pol_v1, self.pol_v2], self.ring,
                self.moment + 20,
            )

    def test_sealer_must_be_authorized_under_both_policies(self):
        # The rotation removes SITE_A, so SITE_A can no longer seal.
        removes_a = vpol(2, sites=(SITE_B, SITE_C))
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.head, [], new=removes_a,
                      moment=self.moment + 20, effective=self.moment + 5)
        # SITE_B survives the rotation and seals the hop.
        raw = self.succ(self.head, [], new=removes_a, issuer=SITE_B,
                        moment=self.moment + 20, effective=self.moment + 5)
        result = verify_prune_aggregate_chain(
            self.root_two, [self.head, raw], self.policy,
            [self.pol_v1, self.pol_v1, removes_a], self.ring,
            self.moment + 20,
        )
        self.assertEqual(result["status"], "accepted")

    def test_effective_moment_never_moves_backwards(self):
        rotated = self.succ(self.head, [], new=self.pol_v2,
                            moment=self.moment + 20,
                            effective=self.moment + 5)
        with self.assertRaises(ValueError):
            self.succ(rotated, [], old=self.pol_v2,
                      new=vpol(3, sites=(SITE_A, SITE_B)),
                      moment=self.moment + 30, effective=self.moment + 4)


class PruneAggregateCredentialTest(PruneAggregateChainFixtures):
    def test_sealer_credential_must_be_usable_at_effective_moment(self):
        future_ring = copy.deepcopy(self.ring)
        future_ring[SITE_A][0]["notBefore"] = self.moment + 5
        with self.assertRaises(AuthenticationError):
            supersede_prune_aggregate(
                self.root_one, [pitem("three", self.pkt_b)], self.policy,
                self.pol_v1, self.pol_v1, future_ring, self.moment + 10,
                self.moment, SITE_A, 1,
            )

    def test_sealer_credential_must_be_usable_at_issuance_moment(self):
        short_ring = copy.deepcopy(self.ring)
        short_ring[SITE_A][0]["notAfter"] = self.moment + 5
        with self.assertRaises(AuthenticationError):
            supersede_prune_aggregate(
                self.root_one, [pitem("three", self.pkt_b)], self.policy,
                self.pol_v1, self.pol_v1, short_ring, self.moment + 10,
                self.moment, SITE_A, 1,
            )

    def test_later_revocation_rejects_the_successor_at_verify_time(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        revoked = copy.deepcopy(self.ring)
        revoked[SITE_A][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy,
                [self.pol_v1, self.pol_v1], revoked, self.moment + 10,
            )

    def test_wrong_successor_signature_is_authentication_error(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        data = parse(raw)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            verify_prune_aggregate_chain(
                self.root_one, [compact(data)], self.policy,
                [self.pol_v1, self.pol_v1], self.ring, self.moment + 10,
            )

    def test_exact_key_version_with_no_fallback(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        ring_v2 = copy.deepcopy(self.ring)
        ring_v2[SITE_A] = ring_v2[SITE_A] + [entry(2, "22" * 32)]
        result = verify_prune_aggregate_chain(
            self.root_one, [raw], self.policy,
            [self.pol_v1, self.pol_v1], ring_v2, self.moment + 10,
        )
        self.assertEqual(result["status"], "accepted")
        without_v1 = copy.deepcopy(ring_v2)
        without_v1[SITE_A] = [ring_v2[SITE_A][1]]
        with self.assertRaises(AuthenticationError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy,
                [self.pol_v1, self.pol_v1], without_v1, self.moment + 10,
            )

    def test_unauthorized_sealer_is_a_chain_error(self):
        # An identity the policies do not authorize is a chain fault,
        # even when a key for it happens to exist or not.
        with self.assertRaises(InvalidAggregateChainError):
            self.succ(self.root_one, [pitem("three", self.pkt_b)],
                      issuer="ghost-site")

    def test_authorized_but_unknown_credential_is_authentication_error(self):
        missing = {site: keys for site, keys in self.ring.items()
                   if site != SITE_A}
        with self.assertRaises(AuthenticationError):
            supersede_prune_aggregate(
                self.root_one, [pitem("three", self.pkt_b)], self.policy,
                self.pol_v1, self.pol_v1, missing, self.moment + 10,
                self.moment, SITE_A, 1,
            )

    def test_new_handover_future_dated_is_recomputed_as_invalid(self):
        # A handover dated after the hop's effective/issuance moment
        # carries no authority then; the statement is dropped and the
        # head stays insufficient with the original declaration.
        future = self.handover(self.h1, issuer=SITE_B,
                               moment=self.moment + 50)
        raw = self.succ(self.root_one, [pitem("three", future)],
                        moment=self.moment + 10, effective=self.moment + 10)
        result = verify_prune_aggregate_chain(
            self.root_one, [raw], self.policy,
            [self.pol_v1, self.pol_v1], self.ring, self.moment + 10,
        )
        self.assertEqual(result["status"], "insufficient")
        rows = parse(raw)["payload"]["items"]
        new_row = next(row for row in rows if row["id"] == "three")
        self.assertEqual(new_row["conclusion"], "invalid")
        self.assertIsNone(new_row["issuer"])
        # Once the handover becomes valid the settled verdict differs,
        # so the historical chain no longer verifies at that moment.
        with self.assertRaises(AuthenticationError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy,
                [self.pol_v1, self.pol_v1], self.ring, self.moment + 60,
            )


class VerifyPruneAggregateChainBindingTest(PruneAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])

    def _tamper(self, mutate):
        data = parse(self.raw)
        mutate(data)
        return self.resign(data)

    def test_bare_root_is_verified_in_full_with_empty_successors(self):
        result = self.vchain(self.root_two, [], policies=[self.pol_v1])
        self.assertEqual(list(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.root_two).hexdigest())
        self.assertEqual(result["headDigest"], result["rootDigest"])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")

    def test_bare_root_common_digest(self):
        result = self.vchain(self.root_one, [])
        self.assertEqual(result["status"], "insufficient")
        declaration = parse(self.root_one)["payload"]["declaration"]
        self.assertEqual(
            result["commonDigest"],
            hashlib.sha256(compact(declaration)).hexdigest(),
        )
        self.assertIsNone(
            self.vchain(self.aggregate([pitem("junk", b"nope")]),
                        [])["commonDigest"]
        )

    def test_bare_root_against_another_site_policy_is_a_bad_root(self):
        other = vpol(1, threshold=1)
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.vchain(self.root_two, [], policies=[other])

    def test_bad_root_raises_the_root_error(self):
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.vchain(b"not-an-aggregate", [])

    def test_tampered_root_digest_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "rootDigest", "00" * 32))
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_tampered_predecessor_digest_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "predecessorDigest", "00" * 32))
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_tampered_height_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__("height", 5))
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_tampered_status_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "status", "conflicted"))
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_tampered_common_declaration_is_chain_error(self):
        def mutate(data):
            decl = data["payload"]["declaration"]
            decl.append(copy.deepcopy(decl[0]))
        raw = self._tamper(mutate)
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_tampered_row_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"]["items"][0].__setitem__(
            "conclusion", "duplicate"))
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_tampered_increment_packet_is_chain_error(self):
        def mutate(data):
            data["payload"]["handovers"][0]["packet"] = self.pkt_c.hex()
        raw = self._tamper(mutate)
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_tampered_policy_digests_are_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "newPolicyDigest", "00" * 32))
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_tampered_policy_version_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "policyVersion", 2))
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_effective_moment_regression_is_chain_error(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "effectiveAt", self.moment - 1))
        with self.assertRaises(InvalidAggregateChainError):
            self.vchain(self.root_one, [raw])

    def test_trailing_byte_is_chain_error(self):
        with self.assertRaises(InvalidAggregateChainError):
            verify_prune_aggregate_chain(
                self.root_one, [self.raw + b"\n"], self.policy,
                [self.pol_v1, self.pol_v1], self.ring, self.moment + 10,
            )

    def test_duplicate_json_key_is_chain_error(self):
        text = self.raw.decode("utf-8").replace(
            '"height":1', '"height":1,"height":2', 1,
        )
        with self.assertRaises(InvalidAggregateChainError):
            verify_prune_aggregate_chain(
                self.root_one, [text.encode("utf-8")], self.policy,
                [self.pol_v1, self.pol_v1], self.ring, self.moment + 10,
            )

    def test_non_canonical_encoding_is_chain_error(self):
        import json
        indented = json.dumps(parse(self.raw), indent=1, sort_keys=True)
        with self.assertRaises(InvalidAggregateChainError):
            verify_prune_aggregate_chain(
                self.root_one, [indented.encode("utf-8")], self.policy,
                [self.pol_v1, self.pol_v1], self.ring, self.moment + 10,
            )

    def test_prune_policy_mismatch_at_verify_fails_the_root(self):
        other = copy.deepcopy(self.policy)
        other["threshold"] = 1
        with self.assertRaises(InvalidPruneBatchAggregateError):
            verify_prune_aggregate_chain(
                self.root_one, [self.raw], other,
                [self.pol_v1, self.pol_v1], self.ring, self.moment + 10,
            )


class PruneAggregateChainArgumentTest(PruneAggregateChainFixtures):
    def test_policy_history_count_must_match_the_stages(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        with self.assertRaises(ValueError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy, [self.pol_v1],
                self.ring, self.moment + 10,
            )
        with self.assertRaises(ValueError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy,
                [self.pol_v1] * 3, self.ring, self.moment + 10,
            )

    def test_root_stage_policy_must_be_version_one(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        with self.assertRaises(ValueError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy,
                [vpol(2), self.pol_v1], self.ring, self.moment + 10,
            )

    def test_policy_history_container_faults(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        with self.assertRaises(TypeError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy, self.pol_v1,
                self.ring, self.moment + 10,
            )
        with self.assertRaises(ValueError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy, [],
                self.ring, self.moment + 10,
            )
        with self.assertRaises(ValueError):
            verify_prune_aggregate_chain(
                self.root_one, [raw], self.policy,
                [{"sites": {}, "threshold": 2, "policyVersion": 1},
                 self.pol_v1],
                self.ring, self.moment + 10,
            )

    def test_public_argument_type_and_value_faults(self):
        good_inc = [pitem("three", self.pkt_b)]
        with self.assertRaises(TypeError):
            self.succ("not-bytes", good_inc)
        with self.assertRaises(TypeError):
            supersede_prune_aggregate(
                self.root_one, good_inc, self.policy, self.pol_v1,
                self.pol_v1, self.ring, True, self.moment, SITE_A, 1,
            )
        with self.assertRaises(TypeError):
            supersede_prune_aggregate(
                self.root_one, good_inc, self.policy, self.pol_v1,
                self.pol_v1, self.ring, self.moment + 10, True, SITE_A, 1,
            )
        with self.assertRaises(ValueError):
            self.succ(self.root_one, good_inc, effective=-1,
                      moment=self.moment + 10)
        with self.assertRaises(ValueError):
            self.succ(self.root_one, good_inc, moment=-1)
        with self.assertRaises(TypeError):
            self.succ(self.root_one, good_inc, issuer=7)
        with self.assertRaises(ValueError):
            self.succ(self.root_one, good_inc, issuer="")
        with self.assertRaises(TypeError):
            self.succ(self.root_one, good_inc, version=True)
        with self.assertRaises(ValueError):
            self.succ(self.root_one, good_inc, version=0)
        with self.assertRaises(TypeError):
            verify_prune_aggregate_chain(
                "x", [], self.policy, [self.pol_v1], self.ring,
                self.moment,
            )
        with self.assertRaises(TypeError):
            verify_prune_aggregate_chain(
                self.root_one, b"x", self.policy, [self.pol_v1],
                self.ring, self.moment,
            )
        with self.assertRaises(TypeError):
            verify_prune_aggregate_chain(
                self.root_one, [b"x"], self.policy,
                [self.pol_v1, self.pol_v1], self.ring, True,
            )

    def test_versioned_policy_faults(self):
        good_inc = [pitem("three", self.pkt_b)]
        with self.assertRaises(ValueError):
            self.succ(self.root_one, good_inc,
                      new={"sites": {SITE_A: {1}, SITE_B: {1}},
                           "threshold": 2})
        with self.assertRaises(ValueError):
            self.succ(self.root_one, good_inc,
                      new=vpol(0))
        with self.assertRaises(TypeError):
            self.succ(self.root_one, good_inc,
                      new={"sites": {SITE_A: {1}, SITE_B: {1}},
                           "threshold": 2, "policyVersion": True})
        with self.assertRaises(TypeError):
            self.succ(self.root_one, good_inc,
                      new={"sites": [], "threshold": 2, "policyVersion": 1})


class PruneAggregateHeadAnchorTest(PruneAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.first = self.succ(
            self.root_one, [pitem("three", self.pkt_b)]
        )
        self.policies = [self.pol_v1, self.pol_v1]

    def test_anchor_shape_and_bindings(self):
        anchor = self.seal_head(
            self.root_one, [self.first], self.policies,
            moment=self.moment + 10,
        )
        self.assertFalse(anchor.endswith(b"\n"))
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
        self.assertEqual(payload["moment"], self.moment + 10)
        self.assertEqual(compact(data), anchor)

    def test_anchor_over_a_rotation_binds_the_head_policy(self):
        rotated = self.succ(
            self.first, [], new=self.pol_v2,
            moment=self.moment + 20, effective=self.moment + 5,
        )
        anchor = self.seal_head(
            self.root_one, [self.first, rotated],
            [self.pol_v1, self.pol_v1, self.pol_v2],
            moment=self.moment + 20,
        )
        payload = parse(anchor)["payload"]
        self.assertEqual(payload["policyVersion"], 2)
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(policy_canon(self.pol_v2)).hexdigest(),
        )
        result = self.vhead(
            anchor, self.root_one, [self.first, rotated],
            [self.pol_v1, self.pol_v1, self.pol_v2],
            moment=self.moment + 20,
        )
        self.assertEqual(list(result.keys()), ANCHOR_RESULT_KEYS)
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["anchorDigest"],
                         hashlib.sha256(anchor).hexdigest())

    def test_bare_accepted_root_can_be_anchored_at_height_zero(self):
        anchor = self.seal_head(self.root_two, [], [self.pol_v1])
        result = self.vhead(anchor, self.root_two, [], [self.pol_v1])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(self.root_two).hexdigest())

    def test_insufficient_head_is_not_sealed(self):
        with self.assertRaises(ValueError):
            self.seal_head(self.root_one, [], [self.pol_v1])

    def test_conflicted_head_is_not_sealed(self):
        with self.assertRaises(ValueError):
            self.seal_head(self.root_conf, [], [self.pol_v1])

    def test_tampered_anchor_bindings_are_rejected(self):
        anchor = self.seal_head(self.root_one, [self.first], self.policies,
                           moment=self.moment + 10)
        for field, value in (
            ("height", 9),
            ("rootDigest", "00" * 32),
            ("headDigest", "00" * 32),
            ("policyVersion", 2),
        ):
            data = parse(anchor)
            data["payload"][field] = value
            with self.assertRaises(InvalidAggregateAnchorError):
                self.vhead(self.resign(data),
                           self.root_one, [self.first], self.policies,
                           moment=self.moment + 10)

    def test_anchor_over_another_chain_is_rejected(self):
        anchor = self.seal_head(self.root_one, [self.first], self.policies,
                           moment=self.moment + 10)
        other = self.succ(self.root_two, [pitem("four", self.pkt_c)],
                          moment=self.moment + 10, effective=self.moment)
        with self.assertRaises(InvalidAggregateAnchorError):
            self.vhead(anchor, self.root_two, [other], self.policies,
                       moment=self.moment + 10)

    def test_bad_anchor_signature_is_authentication_error(self):
        anchor = self.seal_head(self.root_one, [self.first], self.policies,
                           moment=self.moment + 10)
        data = parse(anchor)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.vhead(compact(data), self.root_one, [self.first],
                       self.policies, moment=self.moment + 10)

    def test_revoked_anchor_signer_is_authentication_error(self):
        anchor = self.seal_head(self.root_one, [self.first], self.policies,
                           moment=self.moment + 10)
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            verify_prune_aggregate_head(
                anchor, self.root_one, [self.first], self.policy,
                self.policies, revoked, self.moment + 10,
            )

    def test_malformed_anchor_is_an_anchor_error(self):
        with self.assertRaises(InvalidAggregateAnchorError):
            self.vhead(b"not-an-anchor", self.root_one, [self.first],
                       self.policies, moment=self.moment + 10)
        with self.assertRaises(InvalidAggregateAnchorError):
            self.vhead(self.seal_head(
                self.root_one, [self.first], self.policies,
                moment=self.moment + 10,
            ) + b"\n", self.root_one, [self.first], self.policies,
                moment=self.moment + 10)

    def test_seal_argument_faults(self):
        with self.assertRaises(TypeError):
            self.seal_head(self.root_one, [self.first], self.policies,
                      issuer=9)
        with self.assertRaises(ValueError):
            self.seal_head(self.root_one, [self.first], self.policies,
                      issuer="")
        with self.assertRaises(TypeError):
            self.seal_head(self.root_one, [self.first], self.policies,
                      version=True)
        with self.assertRaises(ValueError):
            self.seal_head(self.root_one, [self.first], self.policies,
                      version=0)
        with self.assertRaises(AuthenticationError):
            self.seal_head(self.root_one, [self.first], self.policies,
                      issuer="ghost", moment=self.moment + 10)
        with self.assertRaises(ValueError):
            self.seal_head(self.root_one, [self.first], [self.pol_v1],
                      moment=self.moment + 10)


class PruneAggregateErrorHierarchyTest(PruneAggregateChainFixtures):
    def test_error_classes(self):
        self.assertTrue(issubclass(InvalidAggregateChainError, ValueError))
        self.assertTrue(issubclass(InvalidAggregateAnchorError, ValueError))
        self.assertTrue(issubclass(InvalidPruneBatchAggregateError, ValueError))
        self.assertIsNot(InvalidAggregateChainError,
                         InvalidPruneBatchAggregateError)
        self.assertIsNot(InvalidAggregateChainError,
                         InvalidAggregateAnchorError)
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class PruneAggregateIndependenceTest(PruneAggregateChainFixtures):
    def test_chain_results_are_equal_but_independent(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        first = self.vchain(self.root_one, [raw])
        second = self.vchain(self.root_one, [raw])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["status"] = "conflicted"
        self.assertEqual(
            self.vchain(self.root_one, [raw])["status"], "accepted"
        )

    def test_anchor_results_are_equal_but_independent(self):
        anchor = self.seal_head(self.root_two, [], [self.pol_v1])
        first = self.vhead(anchor, self.root_two, [], [self.pol_v1])
        second = self.vhead(anchor, self.root_two, [], [self.pol_v1])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["height"] = 9
        self.assertEqual(
            self.vhead(anchor, self.root_two, [], [self.pol_v1])["height"],
            0,
        )

    def test_inputs_are_not_modified(self):
        increment = [pitem("three", self.pkt_b)]
        inc_snapshot = copy.deepcopy(increment)
        root_snapshot = copy.deepcopy(self.root_one)
        pol_snapshot = copy.deepcopy(self.pol_v1)
        ring_snapshot = copy.deepcopy(self.ring)
        self.succ(self.root_one, increment)
        self.assertEqual(increment, inc_snapshot)
        self.assertEqual(self.root_one, root_snapshot)
        self.assertEqual(self.pol_v1, pol_snapshot)
        self.assertEqual(self.ring, ring_snapshot)

    def test_no_file_is_read_or_written(self):
        raw = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        anchor = self.seal_head(self.root_one, [raw], [self.pol_v1, self.pol_v1],
                           moment=self.moment + 10)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.vchain(self.root_one, [raw])
            self.vhead(anchor, self.root_one, [raw],
                       [self.pol_v1, self.pol_v1], moment=self.moment + 10)


if __name__ == "__main__":
    unittest.main()
