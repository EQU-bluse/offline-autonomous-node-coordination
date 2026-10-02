"""Tests for supersession chains over final cross-site aggregates.

Covers :func:`supersede_final_aggregate` and
:func:`verify_final_aggregate_chain`: the canonical signed successor
packet and every binding (root, predecessor, height, the full
recomputed conclusion, the raw decision increment as hex, the invariant
prune, site authorization, fork-proof signer and adjudication signer
site policy digests, the old/new decision policy digests, policy
version and effective moment), the per-hop verdict state machine
(insufficient to accepted/conflicted, accepted only kept or upgraded,
conflicted never masked, the empty fork edge set as a legal
declaration), the append-only decision prefix with unchanged-policy
growth and rotation-only re-sealing, versioned decision site policy
rotation with a single policyVersion step, dual-policy sealer
authorization and credential usability at both the effective and
verification moments, offline hop-by-hop verification, bare-root
verification, the fresh chain summary with the declaration digest, the
distinct InvalidAggregateDecisionChainForkDecisionAggregateError /
InvalidFinalAggregateChainError hierarchy, and every error
classification (including a bool never posing as an int), input
immutability and the purely offline guarantee.
"""

import copy
import hashlib
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidAggregateChainForkDecisionAggregateError,
    InvalidAggregateDecisionChainError,
    InvalidAggregateDecisionChainForkDecisionAggregateError,
    InvalidFinalAggregateChainError,
    supersede_final_aggregate,
    verify_final_aggregate_chain,
)

from test_aggregate_decision_chain_fork_decision_aggregates import (
    AggregateDecisionChainForkDecisionAggregateFixtures,
)
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_chain_fork_aggregate import vpol
from test_supersede_decision_aggregate import rewrap

JUDGE_B = SITE_C

PACKET_KEYS = ["payload", "signature"]
SUCCESSOR_PAYLOAD_KEYS = [
    "authorizationPolicyDigest", "decisions", "declaration",
    "effectiveAt", "height", "inputs", "issuer", "items", "keyVersion",
    "newPolicyDigest", "oldPolicyDigest", "policyVersion",
    "predecessorDigest", "prunePolicyDigest", "rootDigest",
    "signerSitePolicyDigest", "sitePolicyDigest", "status", "version",
]
INCREMENT_KEYS = ["decision", "id"]
CHAIN_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "declarationDigest",
]


class FinalAggregateChainFixtures(
    AggregateDecisionChainForkDecisionAggregateFixtures, unittest.TestCase
):
    """Shared final-layer roots, decisions, policies and chain builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.pv1 = vpol()
        self.pv2_t1 = vpol(2, threshold=1)
        self.pv1_3 = vpol(1, sites=(JUDGE, JUDGE_B, SITE_A), threshold=2)
        self.pv2_3 = vpol(2, sites=(JUDGE, JUDGE_B, SITE_A), threshold=2)

        # A fork-free decision from a third decision site, disagreeing
        # with the fork declarations of decision_a/decision_b.
        self.free_c = self.adcfd_rule(self.free_proofs, issuer=SITE_A)

        # Final aggregate roots: one site (insufficient), two agreeing
        # (accepted), two disagreeing declarations (conflicted) and a
        # fork-free accepted aggregate (the empty fork edge set is a
        # legal declaration).
        self.froot_one = self.adcfd_make_aggregate(
            [decision_item("one", self.decision_a)])
        self.froot_two = self.adcfd_make_aggregate(
            self.adcfd_decision_items())
        self.froot_conf = self.adcfd_make_aggregate(
            [decision_item("a", self.decision_a),
             decision_item("b", self.free_b)])
        self.froot_free = self.adcfd_make_aggregate(
            [decision_item("one", self.free_a),
             decision_item("two", self.free_b)])

    def fagsucc(self, root, predecessor, increment, old=None, new=None,
              moment=None, effective=None, issuer=JUDGE, version=1):
        return supersede_final_aggregate(
            root, predecessor, increment,
            self.policy, self.auth, self.ssp, self.signerp,
            self.pv1 if old is None else old,
            self.pv1 if new is None else new,
            self.ring,
            self.fm + 10 if moment is None else moment,
            self.fm if effective is None else effective,
            issuer, version,
        )

    def fagchain(self, root, successors, policies=None, moment=None,
               ring=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        if moment is None:
            moment = self.fm + 10 * max(1, len(successors))
        return verify_final_aggregate_chain(
            root, successors, self.policy, self.auth, self.ssp,
            self.signerp, policies,
            self.ring if ring is None else ring, moment,
        )


class SuccessorShapeTest(FinalAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.fagsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_b)])

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
        root_payload = parse(self.froot_one)["payload"]
        self.assertEqual(payload["height"], 1)
        self.assertEqual(payload["rootDigest"],
                         hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(payload["predecessorDigest"],
                         hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(payload["effectiveAt"], self.fm)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["issuer"], JUDGE)
        for field in ("prunePolicyDigest", "authorizationPolicyDigest",
                      "sitePolicyDigest", "signerSitePolicyDigest"):
            self.assertEqual(payload[field], root_payload[field])


class BareRootVerifyTest(FinalAggregateChainFixtures):
    def test_bare_root_verified_in_full(self):
        result = self.fagchain(self.froot_two, [])
        self.assertEqual(list(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.froot_two).hexdigest())
        self.assertEqual(result["headDigest"], result["rootDigest"])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["declarationDigest"])

    def test_conflicted_bare_root_declaration_digest_is_null(self):
        result = self.fagchain(self.froot_conf, [])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declarationDigest"])

    def test_fork_free_declaration_is_legal(self):
        root_payload = parse(self.froot_free)["payload"]
        self.assertEqual(root_payload["status"], "accepted")
        self.assertEqual(root_payload["declaration"]["common"], [])
        result = self.fagchain(self.froot_free, [])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(
            result["declarationDigest"],
            hashlib.sha256(
                compact(root_payload["declaration"])).hexdigest())

    def test_result_is_depth_independent_and_fresh(self):
        first = self.fagchain(self.froot_two, [])
        second = self.fagchain(self.froot_two, [])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)


class GrowthAndStateMachineTest(FinalAggregateChainFixtures):
    def test_insufficient_grows_to_accepted(self):
        raw = self.fagsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_b)])
        result = self.fagchain(self.froot_one, [raw])
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["declarationDigest"])

    def test_insufficient_stays_insufficient_below_threshold(self):
        # A decision that does not authenticate adds no valid distinct
        # site, so the tally stays insufficient but keeps the declaration.
        raw = self.fagsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", b"{}")])
        result = self.fagchain(self.froot_one, [raw])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declarationDigest"])

    def test_conflicted_can_never_be_masked(self):
        raw = self.fagsucc(
            self.froot_conf, self.froot_conf,
            [decision_item("s", self.decision_b)])
        self.assertEqual(parse(raw)["payload"]["status"], "conflicted")
        result = self.fagchain(self.froot_conf, [raw])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declarationDigest"])

    def test_accepted_may_advance_to_conflicted(self):
        raw = self.fagsucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.free_c)],
            old=self.pv1, new=self.pv2_3,
        )
        self.assertEqual(parse(raw)["payload"]["status"], "conflicted")
        self.assertEqual(
            self.fagchain(self.froot_two, [raw],
                        policies=[self.pv1, self.pv2_3])["status"],
            "conflicted")

    def test_accepted_keeps_identical_declaration_under_rotation(self):
        raw = self.fagsucc(
            self.froot_two, self.froot_two, [], old=self.pv1, new=self.pv2_t1)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(
            payload["declaration"],
            parse(self.froot_two)["payload"]["declaration"])

    def test_two_hop_chain_recomputes_at_each_stage(self):
        first = self.fagsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_b)])
        second = self.fagsucc(
            self.froot_one, first, [], old=self.pv1, new=self.pv2_t1,
            moment=self.fm + 20, effective=self.fm + 5)
        result = self.fagchain(
            self.froot_one, [first, second],
            policies=[self.pv1, self.pv1, self.pv2_t1], moment=self.fm + 30)
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(second).hexdigest())


class AppendOnlyTest(FinalAggregateChainFixtures):
    def test_unchanged_policy_requires_non_empty_increment(self):
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(self.froot_two, self.froot_two, [],
                       old=self.pv1, new=self.pv1)

    def test_repeated_packet_digest_rejected(self):
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(
                self.froot_one, self.froot_one,
                [decision_item("nine", self.decision_a)])

    def test_repeated_item_id_rejected(self):
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(
                self.froot_one, self.froot_one,
                [decision_item("one", self.decision_b)])

    def test_rotation_may_reseal_empty_sequence(self):
        raw = self.fagsucc(
            self.froot_two, self.froot_two, [], old=self.pv1, new=self.pv2_t1)
        self.assertEqual(parse(raw)["payload"]["decisions"], [])
        self.assertEqual(
            self.fagchain(self.froot_two, [raw],
                        policies=[self.pv1, self.pv2_t1])["status"],
            "accepted")


class PolicyVersionTest(FinalAggregateChainFixtures):
    def test_first_policy_must_match_root_and_carry_version_one(self):
        bad = vpol(1, sites=(JUDGE,), threshold=1)
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(self.froot_two, self.froot_two, [],
                       old=bad, new=self.pv2_t1)

    def test_changed_content_must_step_by_exactly_one(self):
        jump = vpol(3, threshold=1)
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(self.froot_two, self.froot_two, [],
                       old=self.pv1, new=jump)

    def test_unchanged_content_must_keep_version(self):
        mismatch = vpol(2)
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(self.froot_two, self.froot_two, [],
                       old=self.pv1, new=mismatch)

    def test_old_policy_must_equal_predecessor_policy(self):
        first = self.fagsucc(
            self.froot_two, self.froot_two, [], old=self.pv1, new=self.pv2_t1)
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(self.froot_two, first,
                       [decision_item("c", self.free_c)],
                       old=self.pv1, new=self.pv2_t1)


class AuthorizationAndMomentTest(FinalAggregateChainFixtures):
    def test_sealer_must_be_authorized_under_both_policies(self):
        drop = vpol(2, sites=(JUDGE_B,), threshold=1)
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(self.froot_two, self.froot_two, [],
                       old=self.pv1, new=drop, issuer=JUDGE)

    def test_credential_must_be_usable_at_both_moments(self):
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, SECRET_COORD, not_after=self.fm + 5)]
        with self.assertRaises(AuthenticationError):
            supersede_final_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_b)],
                self.policy, self.auth, self.ssp, self.signerp,
                self.pv1, self.pv1,
                ring, self.fm + 10, self.fm, JUDGE, 1)

    def test_effective_moment_must_not_move_backwards(self):
        first = self.fagsucc(
            self.froot_two, self.froot_two, [], old=self.pv1, new=self.pv2_t1,
            effective=self.fm + 5)
        with self.assertRaises(ValueError):
            self.fagsucc(
                self.froot_two, first,
                [decision_item("c", self.free_c)],
                old=self.pv2_t1, new=self.pv2_t1,
                effective=self.fm + 4, moment=self.fm + 10)

    def test_unknown_sealer_is_authentication_error(self):
        ring = {site: self.ring[site]
                for site in self.ring if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            supersede_final_aggregate(
                self.froot_two, self.froot_two, [],
                self.policy, self.auth, self.ssp, self.signerp,
                self.pv1, self.pv2_t1,
                ring, self.fm + 10, self.fm, JUDGE, 1)

    def test_invariant_policies_must_match_the_root(self):
        other_sp = {"sites": {SITE_A: {1}}, "threshold": 1}
        with self.assertRaises(InvalidFinalAggregateChainError):
            supersede_final_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_b)],
                self.policy, self.auth, other_sp, self.signerp,
                self.pv1, self.pv1,
                self.ring, self.fm + 10, self.fm, JUDGE, 1)
        with self.assertRaises(InvalidFinalAggregateChainError):
            supersede_final_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_b)],
                self.policy, self.auth, self.ssp, other_sp,
                self.pv1, self.pv1,
                self.ring, self.fm + 10, self.fm, JUDGE, 1)

    def test_predecessor_must_extend_the_given_root(self):
        other_root = self.adcfd_make_aggregate(
            [decision_item("zz", self.decision_a)])
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagsucc(
                other_root, self.froot_one,
                [decision_item("two", self.decision_b)])

    def test_root_argument_types(self):
        with self.assertRaises(TypeError):
            supersede_final_aggregate(
                "x", self.froot_one, [], self.policy, self.auth, self.ssp,
                self.signerp, self.pv1, self.pv2_t1, self.ring,
                self.fm + 10, self.fm, JUDGE, 1)
        with self.assertRaises(TypeError):
            supersede_final_aggregate(
                self.froot_two, "x", [], self.policy, self.auth, self.ssp,
                self.signerp, self.pv1, self.pv2_t1, self.ring,
                self.fm + 10, self.fm, JUDGE, 1)


class ChainBindingTest(FinalAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.fagsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_b)])

    def assert_chain_invalid(self, raw):
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fagchain(self.froot_one, [raw])

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

    def test_tampered_site_policy_binding(self):
        payload = parse(self.raw)["payload"]
        payload["sitePolicyDigest"] = "2" * 64
        self.assert_chain_invalid(rewrap(payload))

    def test_tampered_signer_site_policy_binding(self):
        payload = parse(self.raw)["payload"]
        payload["signerSitePolicyDigest"] = "3" * 64
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
            verify_final_aggregate_chain(
                self.froot_one, [self.raw], self.policy, self.auth,
                self.ssp, self.signerp, [self.pv1], self.ring, self.fm + 10)

    def test_root_stage_policy_must_be_version_one(self):
        first = vpol(2)
        with self.assertRaises(ValueError):
            verify_final_aggregate_chain(
                self.froot_one, [self.raw], self.policy, self.auth,
                self.ssp, self.signerp, [first, first], self.ring,
                self.fm + 10)

    def test_bad_signature_is_authentication_error(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.fagchain(self.froot_one, [compact(data)])

    def test_bad_root_raises_root_error(self):
        with self.assertRaises(
                InvalidAggregateDecisionChainForkDecisionAggregateError):
            self.fagchain(b"{}", [])

    def test_bad_root_is_distinct_from_chain_error(self):
        self.assertIsNot(
            InvalidAggregateDecisionChainForkDecisionAggregateError,
            InvalidFinalAggregateChainError)
        self.assertIsNot(InvalidFinalAggregateChainError,
                         InvalidAggregateDecisionChainError)
        self.assertIsNot(InvalidFinalAggregateChainError,
                         InvalidAggregateChainForkDecisionAggregateError)

    def test_non_canonical_encoding_rejected(self):
        pretty = json.dumps(parse(self.raw), indent=2)
        self.assert_chain_invalid(pretty.encode())
        self.assert_chain_invalid((self.raw.decode("utf-8") + "\n").encode())


class PublicArgumentTypeTest(FinalAggregateChainFixtures):
    def test_supersede_type_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.fagsucc(self.froot_two, self.froot_two, "x")
        with self.assertRaises(TypeError):
            self.fagsucc(self.froot_two, self.froot_two,
                       [decision_item(1, self.decision_b)])
        with self.assertRaises(TypeError):
            self.fagsucc(
                self.froot_two, self.froot_two,
                [{"id": "x", "decision": 1}])
        with self.assertRaises(ValueError):
            self.fagsucc(self.froot_two, self.froot_two,
                       [decision_item("", self.decision_b)])
        with self.assertRaises(ValueError):
            self.fagsucc(self.froot_two, self.froot_two,
                       [decision_item("a", self.decision_a),
                        decision_item("a", self.decision_b)])
        with self.assertRaises(TypeError):
            supersede_final_aggregate(
                self.froot_two, self.froot_two, [], self.policy, self.auth,
                self.ssp, self.signerp, self.pv1, self.pv2_t1, self.ring,
                True, self.fm, JUDGE, 1)
        with self.assertRaises(ValueError):
            supersede_final_aggregate(
                self.froot_two, self.froot_two, [], self.policy, self.auth,
                self.ssp, self.signerp, self.pv1, self.pv2_t1, self.ring,
                -1, self.fm, JUDGE, 1)
        with self.assertRaises(TypeError):
            self.fagsucc(self.froot_two, self.froot_two, [], issuer=7)
        with self.assertRaises(ValueError):
            self.fagsucc(self.froot_two, self.froot_two, [], issuer="")
        with self.assertRaises(TypeError):
            self.fagsucc(self.froot_two, self.froot_two, [], version=True)
        with self.assertRaises(ValueError):
            self.fagsucc(self.froot_two, self.froot_two, [], version=0)
        with self.assertRaises(
                InvalidAggregateDecisionChainForkDecisionAggregateError):
            self.fagsucc(b"not-a-packet", b"not-a-packet", [])

    def test_verify_argument_faults(self):
        with self.assertRaises(TypeError):
            verify_final_aggregate_chain(
                "x", [], self.policy, self.auth, self.ssp, self.signerp,
                [self.pv1], self.ring, self.fm)
        with self.assertRaises(TypeError):
            verify_final_aggregate_chain(
                self.froot_two, "x", self.policy, self.auth, self.ssp,
                self.signerp, [self.pv1], self.ring, self.fm)
        with self.assertRaises(TypeError):
            verify_final_aggregate_chain(
                self.froot_two, ["x"], self.policy, self.auth, self.ssp,
                self.signerp, [self.pv1, self.pv1], self.ring, self.fm)
        with self.assertRaises(ValueError):
            verify_final_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.signerp, [], self.ring, self.fm)
        with self.assertRaises(TypeError):
            verify_final_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.signerp, [self.pv1], self.ring, True)
        with self.assertRaises(ValueError):
            verify_final_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.signerp, [self.pv1], self.ring, -1)


class ImmutabilityAndOfflineTest(FinalAggregateChainFixtures):
    def test_inputs_are_not_modified(self):
        increment = [decision_item("two", self.decision_b)]
        snapshot = copy.deepcopy(
            (increment, self.policy, self.auth, self.ssp, self.signerp,
             self.pv1, self.ring))
        self.fagsucc(self.froot_one, self.froot_one, increment)
        self.assertEqual(
            (increment, self.policy, self.auth, self.ssp, self.signerp,
             self.pv1, self.ring),
            snapshot)

    def test_verify_inputs_are_not_modified(self):
        raw = self.fagsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_b)])
        successors = [raw]
        policies = [self.pv1, self.pv1]
        snapshot = copy.deepcopy(
            (successors, policies, self.policy, self.auth, self.ssp,
             self.signerp, self.ring))
        self.fagchain(self.froot_one, successors, policies=policies)
        self.assertEqual(
            (successors, policies, self.policy, self.auth, self.ssp,
             self.signerp, self.ring),
            snapshot)

    def test_repeated_results_are_independent(self):
        first = self.fagchain(self.froot_two, [])
        second = self.fagchain(self.froot_two, [])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_no_file_is_read_or_written(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.fagsucc(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_b)])
            self.fagchain(self.froot_one, [raw])
            self.fagchain(self.froot_two, [])


if __name__ == "__main__":
    unittest.main()
