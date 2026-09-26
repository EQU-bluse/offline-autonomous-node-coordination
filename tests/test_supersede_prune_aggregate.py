"""Tests for supersession chains over cross-site prune batch aggregates.

Covers :func:`supersede_prune_aggregate`,
:func:`verify_prune_aggregate_chain`, :func:`seal_prune_aggregate_head`
and :func:`verify_prune_aggregate_head`: the canonical signed
successor packet and every binding (root, predecessor, height, the
full recomputed aggregate, the raw handover increment, old/new policy
digests, policy version and effective moment), the per-hop aggregate
state machine (insufficient to accepted/conflicted, accepted only kept
or upgraded, conflicted never masked), the append-only handover
prefix, unchanged-policy growth and policy rotation versioning, the
constant original prune policy, dual-policy sealer authorization and
credential usability at both moments, offline hop-by-hop chain
verification, and the stable head anchor seal/reverify rules and all
error classifications.
"""

import copy
import hashlib
import hmac
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
    seal_prune_aggregate_head,
    supersede_prune_aggregate,
    verify_prune_aggregate_chain,
    verify_prune_aggregate_head,
)

from test_fork_convergence import (
    SECRET_COORD,
    compact,
    entry,
    parse,
)
from test_prune_attestations import (
    JUDGE,
    SITE_A,
    SITE_B,
    SITE_C,
    hmac_hex,
    make_ring,
    sha256,
)
from test_aggregate_prune_batches import (
    PruneBatchAggregateFixtures,
    agg_item,
)

PACKET_KEYS = ["payload", "signature"]
SUCCESSOR_PAYLOAD_KEYS = {
    "rootDigest", "predecessorDigest", "height", "inputs", "items",
    "status", "declaration", "declarationDigest", "evidence",
    "oldPolicyDigest", "newPolicyDigest", "policyVersion",
    "effectiveAt", "issuer", "keyVersion", "version",
}
ANCHOR_PAYLOAD_KEYS = {
    "rootDigest", "headDigest", "height", "policyDigest",
    "policyVersion", "moment", "issuer", "keyVersion", "version",
}
CHAIN_RESULT_KEYS = {
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "declarationDigest",
}
HEAD_RESULT_KEYS = {
    "rootDigest", "headDigest", "height", "policyDigest",
    "policyVersion", "anchorDigest",
}


def versioned_site_policy(sites=(SITE_A, SITE_B, SITE_C), threshold=2,
                          policy_version=1):
    return {
        "sites": {site: {1} for site in sites},
        "threshold": threshold,
        "policyVersion": policy_version,
    }


def site_policy_digest(policy):
    return hashlib.sha256(compact({
        "policyVersion": policy["policyVersion"],
        "sites": {site: sorted(policy["sites"][site])
                  for site in policy["sites"]},
        "threshold": policy["threshold"],
    })).hexdigest()


class SupersedePruneAggregateFixtures(PruneBatchAggregateFixtures):
    """Shared roots, handover sequences and chain builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.pac_policy_v1 = versioned_site_policy()
        self.pac_policy_v2 = versioned_site_policy(
            (SITE_A, SITE_B, SITE_C), 3, 2
        )

    def insufficient_aggregate_root(self):
        return self.aggregate([agg_item("one", self.pkt_a)])

    def accepted_aggregate_root(self):
        return self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])

    def conflicted_aggregate_root(self):
        return self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b_other),
        ])

    def pac_supersede(self, predecessor, packets, old_policy=None,
                  new_policy=None, ring=None, moment=None, effective=None,
                  issuer=SITE_A, version=1):
        return supersede_prune_aggregate(
            predecessor, packets, self.policy,
            self.pac_policy_v1 if old_policy is None else old_policy,
            self.pac_policy_v1 if new_policy is None else new_policy,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
            self.moment if effective is None else effective,
            issuer, version,
        )

    def pac_verify_chain(self, root, successors, policies, ring=None,
                     moment=None):
        return verify_prune_aggregate_chain(
            root, successors, self.policy, policies,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
        )

    def pac_seal(self, root, successors, policies, ring=None, moment=None,
             issuer=JUDGE, version=1):
        return seal_prune_aggregate_head(
            root, successors, self.policy, policies,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
            issuer, version,
        )

    def pac_verify_head(self, anchor, root, successors, policies, ring=None,
                    moment=None):
        return verify_prune_aggregate_head(
            anchor, root, successors, self.policy, policies,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
        )

    def accepted_aggregate_chain(self):
        """A two-hop accepted chain; returns root, packets, policies."""
        root = self.insufficient_aggregate_root()
        successor_1 = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])
        successor_2 = self.pac_supersede(successor_1, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
            agg_item("three", self.pkt_c),
        ])
        policies = [self.pac_policy_v1, self.pac_policy_v1, self.pac_policy_v1]
        return root, [successor_1, successor_2], policies

    def pac_resign(self, payload, secret=SECRET_COORD):
        return compact({
            "payload": payload,
            "signature": hmac_hex(secret, compact(payload)),
        })


class SuccessorPacketShapeTest(SupersedePruneAggregateFixtures,
                               unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.root = self.insufficient_aggregate_root()
        self.packets = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        self.raw = self.pac_supersede(self.root, self.packets)
        self.data = parse(self.raw)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(self.data), self.raw)

    def test_top_and_payload_key_sets(self):
        self.assertEqual(set(self.data.keys()), {"payload", "signature"})
        self.assertEqual(set(self.data["payload"].keys()),
                         SUCCESSOR_PAYLOAD_KEYS)

    def test_link_and_policy_bindings(self):
        payload = self.data["payload"]
        self.assertEqual(payload["rootDigest"], sha256(self.root))
        self.assertEqual(payload["predecessorDigest"], sha256(self.root))
        self.assertEqual(payload["height"], 1)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(payload["effectiveAt"], self.moment)
        self.assertEqual(payload["issuer"], SITE_A)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        digest = site_policy_digest(self.pac_policy_v1)
        self.assertEqual(payload["oldPolicyDigest"], digest)
        self.assertEqual(payload["newPolicyDigest"], digest)

    def test_evidence_rides_as_lowercase_hex_bytes(self):
        evidence = self.data["payload"]["evidence"]
        self.assertEqual([item["id"] for item in evidence], ["one", "two"])
        self.assertEqual(bytes.fromhex(evidence[0]["packet"]), self.pkt_a)
        self.assertEqual(bytes.fromhex(evidence[1]["packet"]), self.pkt_b)

    def test_recomputed_aggregate_is_bound(self):
        payload = self.data["payload"]
        self.assertEqual(payload["inputs"],
                         [sha256(self.pkt_a), sha256(self.pkt_b)])
        self.assertEqual(
            [(row["issuer"], row["id"]) for row in payload["items"]],
            [(SITE_A, "one"), (SITE_B, "two")],
        )
        declaration = parse(self.pkt_a)["payload"]["items"]
        self.assertEqual(payload["declaration"], declaration)
        self.assertEqual(
            payload["declarationDigest"],
            hashlib.sha256(compact(declaration)).hexdigest(),
        )

    def test_signature_is_the_payload_hmac(self):
        self.assertEqual(
            self.data["signature"],
            hmac.new(
                bytes.fromhex(SECRET_COORD), compact(self.data["payload"]),
                hashlib.sha256,
            ).hexdigest(),
        )

    def test_inputs_are_not_modified(self):
        packets = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        snapshot = copy.deepcopy(
            (self.root, packets, self.policy, self.pac_policy_v1, self.ring)
        )
        self.pac_supersede(self.root, packets)
        self.assertEqual(
            (self.root, packets, self.policy, self.pac_policy_v1, self.ring),
            snapshot,
        )


class AggregateTransitionTest(SupersedePruneAggregateFixtures,
                              unittest.TestCase):
    def test_supplemental_packet_moves_insufficient_to_accepted(self):
        root = self.insufficient_aggregate_root()
        successor = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])
        payload = parse(successor)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertIsNotNone(payload["declaration"])

    def test_supplemental_packet_moves_insufficient_to_conflicted(self):
        root = self.insufficient_aggregate_root()
        successor = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b_other),
        ])
        payload = parse(successor)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])
        self.assertIsNone(payload["declarationDigest"])

    def test_accepted_keeps_the_identical_common_declaration(self):
        root = self.accepted_aggregate_root()
        successor = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
            agg_item("three", self.pkt_c),
        ])
        root_declaration = parse(root)["payload"]["declaration"]
        payload = parse(successor)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["declaration"], root_declaration)

    def test_accepted_advances_to_conflicted(self):
        root = self.accepted_aggregate_root()
        successor = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
            agg_item("three", self.pkt_b_other),
        ])
        payload = parse(successor)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])

    def test_accepted_never_falls_back_to_insufficient(self):
        root = self.accepted_aggregate_root()
        # A rotation raising the threshold above the vote count would
        # tally insufficient; the state machine forbids the fallback.
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(
                root,
                [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)],
                new_policy=self.pac_policy_v2,
            )

    def test_accepted_never_swaps_the_common_declaration(self):
        root = self.accepted_aggregate_root()
        # Forge a successor whose bound declaration differs from the
        # predecessor's while the recomputed aggregate keeps the root's.
        successor = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
            agg_item("three", self.pkt_c),
        ])
        payload = parse(successor)["payload"]
        payload["declaration"] = parse(self.pkt_b_other)["payload"]["items"]
        forged = self.pac_resign(payload)
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [forged],
                              [self.pac_policy_v1, self.pac_policy_v1])

    def test_conflicted_is_never_masked_by_a_majority(self):
        root = self.conflicted_aggregate_root()
        # Two further packets agreeing with site A's declaration still
        # cannot outvote the recorded contradiction.
        successor = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b_other),
            agg_item("three", self.pkt_c),
        ])
        payload = parse(successor)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["declaration"])

    def test_conflicted_never_returns_to_accepted(self):
        root = self.conflicted_aggregate_root()
        successor = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b_other),
            agg_item("three", self.pkt_c),
        ])
        payload = parse(successor)["payload"]
        payload["status"] = "accepted"
        forged = self.pac_resign(payload)
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [forged],
                              [self.pac_policy_v1, self.pac_policy_v1])


class HandoverPrefixTest(SupersedePruneAggregateFixtures,
                         unittest.TestCase):
    def test_first_successor_must_keep_the_root_packets(self):
        root = self.accepted_aggregate_root()
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(root, [agg_item("one", self.pkt_a)])

    def test_first_successor_must_keep_the_root_order(self):
        root = self.accepted_aggregate_root()
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(root, [
                agg_item("two", self.pkt_b), agg_item("one", self.pkt_a),
                agg_item("three", self.pkt_c),
            ])

    def test_first_successor_must_keep_the_root_ids(self):
        root = self.insufficient_aggregate_root()
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(root, [
                agg_item("uno", self.pkt_a), agg_item("two", self.pkt_b),
            ])

    def test_unchanged_policy_must_add_a_packet(self):
        root = self.insufficient_aggregate_root()
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(root, [agg_item("one", self.pkt_a)])

    def test_rotation_may_reseal_the_same_sequence(self):
        root, successors, _ = self.accepted_aggregate_chain()
        rotated = versioned_site_policy((SITE_A, SITE_B), 2, 2)
        packets = [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
            agg_item("three", self.pkt_c),
        ]
        successor = self.pac_supersede(
            successors[-1], packets,
            old_policy=self.pac_policy_v1, new_policy=rotated,
        )
        result = self.pac_verify_chain(
            root, successors + [successor],
            [self.pac_policy_v1, self.pac_policy_v1, self.pac_policy_v1, rotated],
        )
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["height"], 3)

    def test_later_successor_must_keep_the_predecessor_prefix(self):
        root = self.insufficient_aggregate_root()
        successor_1 = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(successor_1, [
                agg_item("one", self.pkt_a), agg_item("three", self.pkt_c),
            ])

    def test_later_successor_must_not_reorder_history(self):
        root = self.insufficient_aggregate_root()
        successor_1 = self.pac_supersede(root, [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(successor_1, [
                agg_item("two", self.pkt_b), agg_item("one", self.pkt_a),
                agg_item("three", self.pkt_c),
            ])


class PolicyVersionTest(SupersedePruneAggregateFixtures, unittest.TestCase):
    def test_changed_policy_must_increment_version_by_one(self):
        root = self.insufficient_aggregate_root()
        packets = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(
                root, packets,
                new_policy=versioned_site_policy((SITE_A, SITE_B), 2, 1),
            )
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(
                root, packets,
                new_policy=versioned_site_policy((SITE_A, SITE_B), 2, 3),
            )

    def test_unchanged_policy_must_keep_its_version(self):
        root = self.insufficient_aggregate_root()
        packets = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(
                root, packets,
                new_policy=versioned_site_policy(
                    (SITE_A, SITE_B, SITE_C), 2, 2
                ),
            )

    def test_old_policy_must_match_the_predecessor(self):
        root, successors, _ = self.accepted_aggregate_chain()
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(
                successors[-1],
                [
                    agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
                    agg_item("three", self.pkt_c),
                    agg_item("four", self.pkt_c),
                ],
                old_policy=versioned_site_policy((SITE_A, SITE_B), 2, 1),
            )

    def test_first_old_policy_must_match_the_root_policy(self):
        root = self.insufficient_aggregate_root()
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(
                root,
                [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)],
                old_policy=versioned_site_policy((SITE_A, SITE_B), 2, 1),
                new_policy=versioned_site_policy((SITE_A, SITE_B), 2, 1),
            )

    def test_rotation_binds_the_incremented_version(self):
        root = self.insufficient_aggregate_root()
        rotated = versioned_site_policy((SITE_A, SITE_B, SITE_C), 3, 2)
        successor = self.pac_supersede(
            root,
            [
                agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
                agg_item("three", self.pkt_c),
            ],
            new_policy=rotated,
        )
        payload = parse(successor)["payload"]
        self.assertEqual(payload["policyVersion"], 2)
        self.assertEqual(payload["newPolicyDigest"],
                         site_policy_digest(rotated))
        self.assertEqual(payload["oldPolicyDigest"],
                         site_policy_digest(self.pac_policy_v1))
        self.assertEqual(payload["status"], "accepted")

    def test_original_prune_policy_is_constant_across_the_chain(self):
        root, successors, policies = self.accepted_aggregate_chain()
        other_prune = {
            "batch": "other-batch",
            "sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
            "threshold": 2,
        }
        # Verifying against another prune policy rejects the root.
        with self.assertRaises(InvalidPruneBatchAggregateError):
            verify_prune_aggregate_chain(
                root, successors, other_prune, policies, self.ring,
                self.moment,
            )
        # A successor issued against another prune policy never
        # verifies under the original one.
        successor = supersede_prune_aggregate(
            root,
            [
                agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
                agg_item("three", self.pkt_c),
            ],
            other_prune, self.pac_policy_v1, self.pac_policy_v1, self.ring,
            self.moment, self.moment, SITE_A, 1,
        )
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [successor],
                              [self.pac_policy_v1, self.pac_policy_v1])


class EffectiveMomentTest(SupersedePruneAggregateFixtures,
                          unittest.TestCase):
    def test_effective_moment_must_not_move_backwards(self):
        root = self.insufficient_aggregate_root()
        successor = self.pac_supersede(
            root,
            [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)],
            effective=self.moment,
        )
        with self.assertRaises(ValueError):
            self.pac_supersede(
                successor,
                [
                    agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
                    agg_item("three", self.pkt_c),
                ],
                effective=self.moment - 1,
            )

    def test_verify_rejects_a_backwards_effective_moment(self):
        root = self.insufficient_aggregate_root()
        successor_1 = self.pac_supersede(
            root,
            [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)],
            effective=self.moment,
        )
        # A second hop bound to an earlier effective moment is rejected.
        successor_2 = self.pac_supersede(
            successor_1,
            [
                agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
                agg_item("three", self.pkt_c),
            ],
            effective=self.moment,
        )
        payload_2 = parse(successor_2)["payload"]
        payload_2["effectiveAt"] = self.moment - 1
        forged_2 = self.pac_resign(payload_2)
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [successor_1, forged_2],
                                  [self.pac_policy_v1] * 3)

    def test_negative_effective_moment_is_a_value_error(self):
        root = self.insufficient_aggregate_root()
        with self.assertRaises(ValueError):
            self.pac_supersede(
                root,
                [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)],
                effective=-1,
            )
        with self.assertRaises(TypeError):
            self.pac_supersede(
                root,
                [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)],
                effective=True,
            )


class SealerAuthorizationTest(SupersedePruneAggregateFixtures,
                              unittest.TestCase):
    def test_sealer_must_be_authorized_by_both_policies(self):
        root = self.insufficient_aggregate_root()
        packets = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(root, packets, issuer=JUDGE)
        rotated = versioned_site_policy((SITE_B, SITE_C), 2, 2)
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(
                root, packets, new_policy=rotated, issuer=SITE_A,
            )

    def test_unknown_sealer_credentials_raise_authentication_error(self):
        root = self.insufficient_aggregate_root()
        with self.assertRaises(AuthenticationError):
            self.pac_supersede(
                root,
                [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)],
                ring=make_ring(sites=(SITE_B, SITE_C, JUDGE)),
            )

    def test_verify_rejects_credentials_expired_since_effective(self):
        effective = self.moment - 10
        # Handovers signed no later than the hop's effective moment.
        pkt_a = self.handover(self.h1, issuer=SITE_A, moment=effective)
        pkt_b = self.handover(self.h1, issuer=SITE_B, moment=effective)
        root = self.aggregate([agg_item("one", pkt_a)], moment=effective)
        successor = self.pac_supersede(
            root,
            [agg_item("one", pkt_a), agg_item("two", pkt_b)],
            effective=effective,
        )
        # Usable at the effective moment, expired by verification time.
        ring = make_ring()
        ring[SITE_A] = [entry(1, SECRET_COORD, not_after=self.moment - 1)]
        with self.assertRaises(AuthenticationError):
            self.pac_verify_chain(
                root, [successor],
                [self.pac_policy_v1, self.pac_policy_v1], ring=ring,
            )


class VerifyChainTest(SupersedePruneAggregateFixtures, unittest.TestCase):
    def test_bare_root_chain_verifies_with_the_original_policies(self):
        root = self.accepted_aggregate_root()
        result = self.pac_verify_chain(root, [], [self.pac_policy_v1])
        self.assertEqual(set(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["rootDigest"], sha256(root))
        self.assertEqual(result["headDigest"], sha256(root))
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        declaration = parse(root)["payload"]["declaration"]
        self.assertEqual(
            result["declarationDigest"],
            hashlib.sha256(compact(declaration)).hexdigest(),
        )

    def test_full_chain_verifies_hop_by_hop(self):
        root, successors, policies = self.accepted_aggregate_chain()
        result = self.pac_verify_chain(root, successors, policies)
        self.assertEqual(result["rootDigest"], sha256(root))
        self.assertEqual(result["headDigest"], sha256(successors[-1]))
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")

    def test_conflicted_head_binds_no_declaration_digest(self):
        root = self.conflicted_aggregate_root()
        result = self.pac_verify_chain(root, [], [self.pac_policy_v1])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declarationDigest"])

    def test_bad_root_raises_aggregate_error(self):
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.pac_verify_chain(b"not-an-aggregate", [], [self.pac_policy_v1])
        root = self.accepted_aggregate_root()
        tampered = parse(root)
        tampered["payload"]["status"] = "conflicted"
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.pac_verify_chain(self.pac_resign(tampered["payload"]),
                              [], [self.pac_policy_v1])

    def test_bad_successor_raises_chain_error(self):
        root, successors, policies = self.accepted_aggregate_chain()
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [b"not-a-successor"], policies[:2])
        payload = parse(successors[0])["payload"]
        payload["height"] = 7
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [self.pac_resign(payload)], policies[:2])
        payload = parse(successors[0])["payload"]
        payload["rootDigest"] = "00" * 32
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [self.pac_resign(payload)], policies[:2])
        payload = parse(successors[0])["payload"]
        payload["predecessorDigest"] = "00" * 32
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [self.pac_resign(payload)], policies[:2])

    def test_tampered_successor_signature_raises_authentication_error(self):
        root, successors, policies = self.accepted_aggregate_chain()
        data = parse(successors[0])
        signature = data["signature"]
        data["signature"] = ("0" if signature[0] != "0" else "1") + (
            signature[1:]
        )
        with self.assertRaises(AuthenticationError):
            self.pac_verify_chain(root, [compact(data)], policies[:2])

    def test_successor_signed_by_an_unauthorized_sealer_is_rejected(self):
        root = self.insufficient_aggregate_root()
        successor = self.pac_supersede(
            root,
            [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)],
        )
        payload = parse(successor)["payload"]
        payload["issuer"] = JUDGE
        forged = self.pac_resign(payload)
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_verify_chain(root, [forged],
                              [self.pac_policy_v1, self.pac_policy_v1])

    def test_policy_count_must_match_the_chain_length(self):
        root, successors, policies = self.accepted_aggregate_chain()
        with self.assertRaises(ValueError):
            self.pac_verify_chain(root, successors, policies[:2])
        with self.assertRaises(ValueError):
            self.pac_verify_chain(root, [], [])
        with self.assertRaises(ValueError):
            self.pac_verify_chain(root, [],
                              [versioned_site_policy(policy_version=2)])

    def test_public_argument_type_faults(self):
        root, successors, policies = self.accepted_aggregate_chain()
        with self.assertRaises(TypeError):
            self.pac_verify_chain("not-bytes", [], [self.pac_policy_v1])
        with self.assertRaises(TypeError):
            self.pac_verify_chain(root, "not-a-list", policies)
        with self.assertRaises(TypeError):
            self.pac_verify_chain(root, ["not-bytes"], policies)
        with self.assertRaises(TypeError):
            self.pac_verify_chain(root, [], "not-a-list")
        with self.assertRaises(TypeError):
            self.pac_verify_chain(root, [], [self.pac_policy_v1], moment=True)
        with self.assertRaises(ValueError):
            self.pac_verify_chain(root, [], [self.pac_policy_v1], moment=-1)
        with self.assertRaises(ValueError):
            self.pac_verify_chain(root, [], [{"sites": {}, "threshold": 1,
                                          "policyVersion": 1}])
        with self.assertRaises(TypeError):
            self.pac_verify_chain(
                root, [],
                [versioned_site_policy(policy_version=True)],
            )

    def test_results_are_fresh_independent_mappings(self):
        root, successors, policies = self.accepted_aggregate_chain()
        first = self.pac_verify_chain(root, successors, policies)
        second = self.pac_verify_chain(root, successors, policies)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)


class SealHeadTest(SupersedePruneAggregateFixtures, unittest.TestCase):
    def test_anchor_shape_and_bindings(self):
        root, successors, policies = self.accepted_aggregate_chain()
        anchor = self.pac_seal(root, successors, policies)
        data = parse(anchor)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        self.assertEqual(set(data["payload"].keys()), ANCHOR_PAYLOAD_KEYS)
        payload = data["payload"]
        self.assertEqual(payload["rootDigest"], sha256(root))
        self.assertEqual(payload["headDigest"], sha256(successors[-1]))
        self.assertEqual(payload["height"], 2)
        self.assertEqual(payload["policyDigest"],
                         site_policy_digest(self.pac_policy_v1))
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(payload["moment"], self.moment)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(compact(data), anchor)

    def test_seal_requires_an_accepted_head(self):
        insufficient = self.insufficient_aggregate_root()
        with self.assertRaises(ValueError):
            self.pac_seal(insufficient, [], [self.pac_policy_v1])
        conflicted = self.conflicted_aggregate_root()
        with self.assertRaises(ValueError):
            self.pac_seal(conflicted, [], [self.pac_policy_v1])

    def test_verify_head_roundtrip(self):
        root, successors, policies = self.accepted_aggregate_chain()
        anchor = self.pac_seal(root, successors, policies)
        result = self.pac_verify_head(anchor, root, successors, policies)
        self.assertEqual(set(result.keys()), HEAD_RESULT_KEYS)
        self.assertEqual(result["rootDigest"], sha256(root))
        self.assertEqual(result["headDigest"], sha256(successors[-1]))
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["policyDigest"],
                         site_policy_digest(self.pac_policy_v1))
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["anchorDigest"], sha256(anchor))

    def test_verify_head_accepts_a_bare_accepted_root(self):
        root = self.accepted_aggregate_root()
        anchor = self.pac_seal(root, [], [self.pac_policy_v1])
        result = self.pac_verify_head(anchor, root, [], [self.pac_policy_v1])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["headDigest"], sha256(root))

    def test_anchor_against_another_chain_is_rejected(self):
        root, successors, policies = self.accepted_aggregate_chain()
        anchor = self.pac_seal(root, successors, policies)
        other_root = self.accepted_aggregate_root()
        with self.assertRaises(InvalidAggregateAnchorError):
            self.pac_verify_head(anchor, other_root, [], [self.pac_policy_v1])

    def test_tampered_anchor_raises_anchor_error(self):
        root, successors, policies = self.accepted_aggregate_chain()
        anchor = self.pac_seal(root, successors, policies)
        payload = parse(anchor)["payload"]
        payload["height"] = 9
        forged = self.pac_resign(payload)
        with self.assertRaises(InvalidAggregateAnchorError):
            self.pac_verify_head(forged, root, successors, policies)
        payload = parse(anchor)["payload"]
        payload["policyDigest"] = "00" * 32
        forged = self.pac_resign(payload)
        with self.assertRaises(InvalidAggregateAnchorError):
            self.pac_verify_head(forged, root, successors, policies)

    def test_bad_anchor_encoding_raises_anchor_error(self):
        root, successors, policies = self.accepted_aggregate_chain()
        with self.assertRaises(InvalidAggregateAnchorError):
            self.pac_verify_head(b"not-an-anchor", root, successors, policies)
        anchor = self.pac_seal(root, successors, policies)
        with self.assertRaises(InvalidAggregateAnchorError):
            self.pac_verify_head(anchor + b"\n", root, successors, policies)

    def test_anchor_signature_faults_raise_authentication_error(self):
        root, successors, policies = self.accepted_aggregate_chain()
        anchor = self.pac_seal(root, successors, policies)
        data = parse(anchor)
        data["payload"]["height"] = 1
        with self.assertRaises(AuthenticationError):
            self.pac_verify_head(compact(data), root, successors, policies)
        with self.assertRaises(AuthenticationError):
            self.pac_verify_head(anchor, root, successors, policies,
                             ring=make_ring(revoked=(JUDGE,)))

    def test_seal_public_argument_faults(self):
        root, successors, policies = self.accepted_aggregate_chain()
        with self.assertRaises(TypeError):
            self.pac_seal("not-bytes", successors, policies)
        with self.assertRaises(TypeError):
            self.pac_seal(root, successors, policies, issuer=7)
        with self.assertRaises(ValueError):
            self.pac_seal(root, successors, policies, issuer="")
        with self.assertRaises(TypeError):
            self.pac_seal(root, successors, policies, version=True)
        with self.assertRaises(ValueError):
            self.pac_seal(root, successors, policies, version=0)
        with self.assertRaises(AuthenticationError):
            self.pac_seal(root, successors, policies, issuer="unknown")
        with self.assertRaises(ValueError):
            self.pac_seal(root, successors, policies[:2])
        with self.assertRaises(TypeError):
            self.pac_verify_head("not-bytes", root, successors, policies)


class SupersedeArgumentFaultTest(SupersedePruneAggregateFixtures,
                                 unittest.TestCase):
    def test_packet_container_faults(self):
        root = self.insufficient_aggregate_root()
        with self.assertRaises(TypeError):
            self.pac_supersede(root, "not-a-list")
        with self.assertRaises(ValueError):
            self.pac_supersede(root, [])
        with self.assertRaises(TypeError):
            self.pac_supersede(root, ["not-a-dict"])
        with self.assertRaises(ValueError):
            self.pac_supersede(root, [{"id": "one"}])
        with self.assertRaises(ValueError):
            self.pac_supersede(root, [
                agg_item("one", self.pkt_a), agg_item("one", self.pkt_b),
            ])
        with self.assertRaises(TypeError):
            self.pac_supersede(root, [agg_item("one", "not-bytes")])

    def test_public_field_type_faults(self):
        root = self.insufficient_aggregate_root()
        packets = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        with self.assertRaises(TypeError):
            self.pac_supersede("not-bytes", packets)
        with self.assertRaises(TypeError):
            self.pac_supersede(root, packets, issuer=7)
        with self.assertRaises(ValueError):
            self.pac_supersede(root, packets, issuer="")
        with self.assertRaises(TypeError):
            self.pac_supersede(root, packets, version=True)
        with self.assertRaises(ValueError):
            self.pac_supersede(root, packets, version=0)
        with self.assertRaises(TypeError):
            self.pac_supersede(root, packets, moment=False)
        with self.assertRaises(ValueError):
            self.pac_supersede(root, packets, moment=-1)

    def test_policy_faults(self):
        root = self.insufficient_aggregate_root()
        packets = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        with self.assertRaises(ValueError):
            self.pac_supersede(
                root, packets,
                old_policy={"sites": {SITE_A: {1}}, "threshold": 1},
            )
        with self.assertRaises(TypeError):
            self.pac_supersede(
                root, packets,
                old_policy=versioned_site_policy(policy_version=True),
            )
        with self.assertRaises(ValueError):
            self.pac_supersede(
                root, packets,
                old_policy=versioned_site_policy(policy_version=0),
            )
        with self.assertRaises(TypeError):
            self.pac_supersede(root, packets, old_policy="not-a-dict")

    def test_malformed_predecessor_classification(self):
        packets = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.pac_supersede(b"not-an-aggregate", packets)
        root, successors, _ = self.accepted_aggregate_chain()
        with self.assertRaises(InvalidAggregateChainError):
            self.pac_supersede(successors[0] + b"\n", [
                agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
                agg_item("three", self.pkt_c),
            ])


class ErrorHierarchyTest(unittest.TestCase):
    def test_chain_errors_subclass_value_error(self):
        self.assertTrue(issubclass(InvalidAggregateChainError, ValueError))
        self.assertTrue(issubclass(InvalidAggregateAnchorError, ValueError))
        self.assertIsNot(InvalidAggregateChainError,
                         InvalidAggregateAnchorError)
        self.assertIsNot(InvalidAggregateChainError,
                         InvalidPruneBatchAggregateError)
        self.assertIsNot(InvalidAggregateAnchorError,
                         InvalidPruneBatchAggregateError)


class IndependenceAndOfflineTest(SupersedePruneAggregateFixtures,
                                 unittest.TestCase):
    def test_chain_inputs_are_not_modified(self):
        root, successors, policies = self.accepted_aggregate_chain()
        snapshot = copy.deepcopy((root, successors, self.policy, policies,
                                  self.ring))
        anchor = self.pac_seal(root, successors, policies)
        self.pac_verify_chain(root, successors, policies)
        self.pac_verify_head(anchor, root, successors, policies)
        self.assertEqual((root, successors, self.policy, policies,
                          self.ring), snapshot)

    def test_runs_entirely_offline(self):
        root, successors, policies = self.accepted_aggregate_chain()
        with mock.patch("builtins.open", side_effect=AssertionError("open")):
            anchor = self.pac_seal(root, successors, policies)
            self.pac_verify_chain(root, successors, policies)
            self.pac_verify_head(anchor, root, successors, policies)
            self.pac_supersede(successors[-1], [
                agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
                agg_item("three", self.pkt_c), agg_item("four", self.pkt_c),
            ])


if __name__ == "__main__":
    unittest.main()
