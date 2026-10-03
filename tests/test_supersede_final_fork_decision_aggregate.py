"""Tests for supersession chains over final fork decision aggregates.

Covers :func:`supersede_final_fork_decision_aggregate` and
:func:`verify_final_fork_decision_aggregate_chain`: the canonical signed
successor packet and every binding (root, predecessor, height, the full
recomputed conclusion, the raw decision increment as hex, the five
invariant policy digests -- prune, site authorization, fork-proof
signer, adjudication signer and issuing adjudication site -- the
old/new decision policy digests, policy version and effective moment),
the per-hop full-stage re-verification (every prefix decision and every
increment decision is re-checked for authorization, credentials and
threshold at the hop's effective moment and again at the issuance /
verification moment, with no grandfathering), the verdict state machine
(insufficient to accepted/conflicted, accepted only kept or upgraded,
conflicted never masked, the empty fork edge set as a legal
declaration), the append-only decision prefix with unchanged-policy
growth and rotation-only re-sealing, versioned decision site policy
rotation with a single policyVersion step, dual-policy sealer
authorization, offline hop-by-hop verification, bare-root verification,
the fresh depth-independent chain summary with the declaration digest,
the distinct InvalidFinalAggregateChainForkDecisionAggregateError /
InvalidFinalForkDecisionAggregateChainError hierarchy, and every error
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
    InvalidFinalAggregateChainForkDecisionAggregateError,
    InvalidFinalAggregateChainForkDecisionError,
    InvalidFinalForkDecisionAggregateChainError,
    supersede_final_fork_decision_aggregate,
    verify_final_fork_decision_aggregate_chain,
)

from test_final_aggregate_chain_fork_decision_aggregates import (
    FinalFinalFixtures,
    compact,
)
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import SECRET_COORD, entry
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_chain_fork_aggregate import vpol

JUDGE_B = SITE_C

PACKET_KEYS = ["payload", "signature"]
SUCCESSOR_PAYLOAD_KEYS = [
    "adjudicationSitePolicyDigest", "authorizationPolicyDigest",
    "decisions", "declaration", "effectiveAt", "height", "inputs",
    "issuer", "items", "keyVersion", "newPolicyDigest", "oldPolicyDigest",
    "policyVersion", "predecessorDigest", "prunePolicyDigest",
    "rootDigest", "signerSitePolicyDigest", "sitePolicyDigest", "status",
    "version",
]
INCREMENT_KEYS = ["decision", "id"]
CHAIN_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "declarationDigest",
]


class FinalForkDecisionAggregateChainFixtures(FinalFinalFixtures):
    """Root final decision aggregates, versioned policies and builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.pv1 = vpol()
        self.pv2_t1 = vpol(2, threshold=1)
        self.pv2_3 = vpol(2, sites=(JUDGE, JUDGE_B, SITE_A), threshold=2)

        # A fork-free decision from a third decision site, disagreeing
        # with the fork declarations of decision_ja/decision_jb.
        self.free_c = self.facf_decision(self.ffree_proofs, SITE_A)

        self.froot_one = self.fmake_aggregate(
            [decision_item("one", self.decision_ja)])
        self.froot_two = self.fmake_aggregate(self.fdecision_items())
        self.froot_conf = self.fmake_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.free_jb)])
        self.froot_free = self.fmake_aggregate([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb)])

    def ffdsucc(self, root, predecessor, increment, old=None, new=None,
             moment=None, effective=None, issuer=JUDGE, version=1):
        return supersede_final_fork_decision_aggregate(
            root, predecessor, increment,
            self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
            self.pv1 if old is None else old,
            self.pv1 if new is None else new,
            self.ring,
            self.fm + 10 if moment is None else moment,
            self.fm if effective is None else effective,
            issuer, version,
        )

    def ffdchain(self, root, successors, policies=None, moment=None,
              ring=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        if moment is None:
            moment = self.fm + 10 * max(1, len(successors))
        return verify_final_fork_decision_aggregate_chain(
            root, successors, self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, policies,
            self.ring if ring is None else ring, moment,
        )


class SuccessorShapeTest(FinalForkDecisionAggregateChainFixtures,
                         unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])

    def test_canonical_compact_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(json.loads(self.raw.decode())), self.raw)

    def test_top_and_payload_key_sets(self):
        data = json.loads(self.raw.decode())
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        self.assertEqual(sorted(data["payload"].keys()),
                         SUCCESSOR_PAYLOAD_KEYS)

    def test_increment_is_bound_as_hex(self):
        decisions = json.loads(self.raw.decode())["payload"]["decisions"]
        self.assertEqual(len(decisions), 1)
        self.assertEqual(sorted(decisions[0].keys()), INCREMENT_KEYS)
        self.assertEqual(decisions[0]["id"], "two")
        self.assertEqual(
            bytes.fromhex(decisions[0]["decision"]), self.decision_jb)

    def test_height_root_and_policy_bindings(self):
        payload = json.loads(self.raw.decode())["payload"]
        root_payload = json.loads(self.froot_one.decode())["payload"]
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
                      "sitePolicyDigest", "signerSitePolicyDigest",
                      "adjudicationSitePolicyDigest"):
            self.assertEqual(payload[field], root_payload[field], field)

    def test_signed_with_exact_issuer_version_key(self):
        import hmac as _hmac
        from offline_coordination.replication import (
            _prune_compact, _usable_checkpoint_key, _validated_keyring,
        )
        data = json.loads(self.raw.decode())
        key_entry = _usable_checkpoint_key(
            _validated_keyring(self.ring), JUDGE, 1, self.fm + 10)
        expected = _hmac.new(
            bytes.fromhex(key_entry["secret"]),
            _prune_compact(data["payload"]),
            hashlib.sha256).hexdigest()
        self.assertEqual(data["signature"], expected)


class BareRootVerifyTest(FinalForkDecisionAggregateChainFixtures,
                        unittest.TestCase):
    def test_bare_root_verified_in_full(self):
        result = self.ffdchain(self.froot_two, [])
        self.assertEqual(list(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.froot_two).hexdigest())
        self.assertEqual(result["headDigest"], result["rootDigest"])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["declarationDigest"])

    def test_conflicted_bare_root_declaration_digest_is_null(self):
        result = self.ffdchain(self.froot_conf, [])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declarationDigest"])

    def test_insufficient_bare_root_keeps_declaration_digest(self):
        result = self.ffdchain(self.froot_one, [])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declarationDigest"])

    def test_fork_free_declaration_is_legal(self):
        root_payload = json.loads(self.froot_free.decode())["payload"]
        self.assertEqual(root_payload["status"], "accepted")
        self.assertEqual(root_payload["declaration"]["common"], [])
        result = self.ffdchain(self.froot_free, [])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(
            result["declarationDigest"],
            hashlib.sha256(compact(root_payload["declaration"])).hexdigest())

    def test_result_is_depth_independent_and_fresh(self):
        first = self.ffdchain(self.froot_two, [])
        second = self.ffdchain(self.froot_two, [])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)


class GrowthAndStateMachineTest(FinalForkDecisionAggregateChainFixtures,
                                unittest.TestCase):
    def test_insufficient_grows_to_accepted(self):
        raw = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        result = self.ffdchain(self.froot_one, [raw])
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["declarationDigest"])

    def test_invalid_increment_stays_insufficient_but_keeps_declaration(self):
        raw = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("bad", b"{}")])
        payload = json.loads(raw.decode())["payload"]
        self.assertEqual(payload["status"], "insufficient")
        bad = next(row for row in payload["items"] if row["id"] == "bad")
        self.assertEqual(bad["conclusion"], "invalid")
        self.assertEqual(bad["reason"], "invalid")
        self.assertIsNone(bad["issuer"])
        result = self.ffdchain(self.froot_one, [raw])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declarationDigest"])

    def test_conflicted_can_never_be_masked(self):
        raw = self.ffdsucc(
            self.froot_conf, self.froot_conf,
            [decision_item("s", self.decision_jb)])
        self.assertEqual(
            json.loads(raw.decode())["payload"]["status"], "conflicted")
        result = self.ffdchain(self.froot_conf, [raw])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declarationDigest"])

    def test_accepted_may_advance_to_conflicted(self):
        raw = self.ffdsucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.free_c)],
            old=self.pv1, new=self.pv2_3)
        self.assertEqual(
            json.loads(raw.decode())["payload"]["status"], "conflicted")
        self.assertEqual(
            self.ffdchain(self.froot_two, [raw],
                      policies=[self.pv1, self.pv2_3])["status"],
            "conflicted")

    def test_accepted_keeps_identical_declaration_under_rotation(self):
        raw = self.ffdsucc(
            self.froot_two, self.froot_two, [],
            old=self.pv1, new=self.pv2_t1)
        payload = json.loads(raw.decode())["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(
            payload["declaration"],
            json.loads(self.froot_two.decode())["payload"]["declaration"])

    def test_two_hop_chain_recomputes_at_each_stage(self):
        first = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        second = self.ffdsucc(
            self.froot_one, first, [], old=self.pv1, new=self.pv2_t1,
            moment=self.fm + 20, effective=self.fm + 5)
        result = self.ffdchain(
            self.froot_one, [first, second],
            policies=[self.pv1, self.pv1, self.pv2_t1],
            moment=self.fm + 30)
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(second).hexdigest())


class PerHopReverificationTest(FinalForkDecisionAggregateChainFixtures,
                               unittest.TestCase):
    """Every hop re-verifies ALL decisions of the stage, prefix included."""

    def _seal(self, predecessor, ring, moment, effective,
              old=None, new=None, increment=()):
        return supersede_final_fork_decision_aggregate(
            self.froot_one, predecessor, list(increment),
            self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
            self.pv1 if old is None else old,
            self.pv2_t1 if new is None else new,
            ring, moment, effective, JUDGE, 1)

    def test_revoked_prefix_credential_rejects_later_hop(self):
        first = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE_B][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self._seal(first, revoked, self.fm + 20, self.fm + 5)

    def test_expired_prefix_credential_at_effective_rejects_hop(self):
        first = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        expired = copy.deepcopy(self.ring)
        expired[JUDGE_B][0]["notAfter"] = self.fm + 3
        with self.assertRaises(AuthenticationError):
            self._seal(first, expired, self.fm + 20, self.fm + 10)

    def test_rotated_policy_dropping_counted_site_rejects_hop(self):
        first = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        drop = vpol(2, sites=(JUDGE,), threshold=1)
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self._seal(first, self.ring, self.fm + 20, self.fm + 5,
                       new=drop)

    def test_prefix_credential_expired_at_verify_moment_rejects_chain(self):
        first = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        expired = copy.deepcopy(self.ring)
        expired[JUDGE_B][0]["notAfter"] = self.fm + 15
        with self.assertRaises(AuthenticationError):
            self.ffdchain(self.froot_one, [first], ring=expired,
                       moment=self.fm + 100)

    def test_increment_credential_unusable_at_effective_rejected(self):
        # The new decision's key is valid at issuance but not yet valid
        # at the earlier effective moment.
        future_ring = copy.deepcopy(self.ring)
        future_ring[JUDGE_B] = [
            entry(1, SECRET_COORD, not_before=self.fm + 5,
                  not_after=self.fm + 100)]
        decision = self.facf_decision(self.ffork_proofs, JUDGE_B)
        with self.assertRaises(AuthenticationError):
            supersede_final_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", decision)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.pv1, self.pv1, future_ring,
                self.fm + 20, self.fm, JUDGE, 1)

    def test_increment_credential_rejected_by_new_policy(self):
        # A rotation authorizing only JUDGE makes an increment decision
        # from JUDGE_B non-counted even though its signature is valid.
        only_judge = vpol(2, sites=(JUDGE,), threshold=1)
        raw = self._seal(
            self.froot_one, self.ring, self.fm + 20, self.fm + 5,
            new=only_judge,
            increment=[decision_item("two", self.decision_jb)])
        payload = json.loads(raw.decode())["payload"]
        new_row = next(
            row for row in payload["items"] if row["id"] == "two")
        self.assertEqual(new_row["reason"], "unauthorized")
        # The JUDGE prefix vote alone is below threshold 1... it equals
        # it, so the stage stays accepted on JUDGE's declaration.
        self.assertEqual(payload["status"], "accepted")


class AppendOnlyTest(FinalForkDecisionAggregateChainFixtures,
                     unittest.TestCase):
    def test_unchanged_policy_requires_non_empty_increment(self):
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(self.froot_two, self.froot_two, [],
                      old=self.pv1, new=self.pv1)

    def test_repeated_packet_digest_rejected(self):
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(
                self.froot_one, self.froot_one,
                [decision_item("nine", self.decision_ja)])

    def test_repeated_item_id_rejected(self):
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(
                self.froot_one, self.froot_one,
                [decision_item("one", self.decision_jb)])

    def test_rotation_may_reseal_empty_sequence(self):
        raw = self.ffdsucc(
            self.froot_two, self.froot_two, [],
            old=self.pv1, new=self.pv2_t1)
        self.assertEqual(
            json.loads(raw.decode())["payload"]["decisions"], [])
        self.assertEqual(
            self.ffdchain(self.froot_two, [raw],
                      policies=[self.pv1, self.pv2_t1])["status"],
            "accepted")


class PolicyVersionTest(FinalForkDecisionAggregateChainFixtures,
                        unittest.TestCase):
    def test_first_policy_must_match_root_and_carry_version_one(self):
        bad = vpol(1, sites=(JUDGE,), threshold=1)
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(self.froot_two, self.froot_two, [],
                      old=bad, new=self.pv2_t1)

    def test_changed_content_must_step_by_exactly_one(self):
        jump = vpol(3, threshold=1)
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(self.froot_two, self.froot_two, [],
                      old=self.pv1, new=jump)

    def test_unchanged_content_must_keep_version(self):
        mismatch = vpol(2)
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(self.froot_two, self.froot_two, [],
                      old=self.pv1, new=mismatch)

    def test_old_policy_must_equal_predecessor_policy(self):
        first = self.ffdsucc(
            self.froot_two, self.froot_two, [],
            old=self.pv1, new=self.pv2_t1)
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(
                self.froot_two, first,
                [decision_item("c", self.free_c)],
                old=self.pv1, new=self.pv2_t1)


class AuthorizationAndMomentTest(FinalForkDecisionAggregateChainFixtures,
                                 unittest.TestCase):
    def test_sealer_must_be_authorized_under_both_policies(self):
        drop = vpol(2, sites=(JUDGE_B,), threshold=1)
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(self.froot_two, self.froot_two, [],
                      old=self.pv1, new=drop, issuer=JUDGE)

    def test_credential_must_be_usable_at_both_moments(self):
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, SECRET_COORD, not_after=self.fm + 5)]
        with self.assertRaises(AuthenticationError):
            supersede_final_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_jb)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.pv1, self.pv1,
                ring, self.fm + 10, self.fm, JUDGE, 1)

    def test_effective_moment_must_not_move_backwards(self):
        first = self.ffdsucc(
            self.froot_two, self.froot_two, [],
            old=self.pv1, new=self.pv2_t1, effective=self.fm + 5)
        with self.assertRaises(ValueError):
            self.ffdsucc(
                self.froot_two, first,
                [decision_item("c", self.free_c)],
                old=self.pv2_t1, new=self.pv2_t1,
                effective=self.fm + 4, moment=self.fm + 10)

    def test_unknown_sealer_is_authentication_error(self):
        ring = {site: self.ring[site]
                for site in self.ring if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            supersede_final_fork_decision_aggregate(
                self.froot_two, self.froot_two, [],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.pv1, self.pv2_t1,
                ring, self.fm + 10, self.fm, JUDGE, 1)

    def test_invariant_policies_must_match_the_root(self):
        other_fsignerp = {"sites": {SITE_A: {1}, SITE_B: {1}},
                          "threshold": 1}
        other_adjp = {"sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
                      "threshold": 1}
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            supersede_final_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_jb)],
                self.policy, self.auth, self.ssp, other_fsignerp,
                self.adjp, self.pv1, self.pv1,
                self.ring, self.fm + 10, self.fm, JUDGE, 1)
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            supersede_final_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_jb)],
                self.policy, self.auth, self.ssp, self.fsignerp,
                other_adjp, self.pv1, self.pv1,
                self.ring, self.fm + 10, self.fm, JUDGE, 1)

    def test_predecessor_must_extend_the_given_root(self):
        other_root = self.fmake_aggregate(
            [decision_item("zz", self.decision_ja)])
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(
                other_root, self.froot_one,
                [decision_item("two", self.decision_jb)])

    def test_root_argument_types(self):
        with self.assertRaises(TypeError):
            supersede_final_fork_decision_aggregate(
                "x", self.froot_one, [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.pv1, self.pv2_t1,
                self.ring, self.fm + 10, self.fm, JUDGE, 1)
        with self.assertRaises(TypeError):
            supersede_final_fork_decision_aggregate(
                self.froot_two, "x", [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.pv1, self.pv2_t1,
                self.ring, self.fm + 10, self.fm, JUDGE, 1)


class ChainBindingTest(FinalForkDecisionAggregateChainFixtures,
                       unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])

    def assert_chain_invalid(self, raw):
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainError):
            self.ffdchain(self.froot_one, [raw])

    def test_tampered_height_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["height"] = 2
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_root_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["rootDigest"] = "0" * 64
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_predecessor_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["predecessorDigest"] = "1" * 64
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_status_cannot_be_resigned(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["status"] = "insufficient"
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_increment_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["decisions"][0]["decision"] = self.decision_ja.hex()
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_policy_version_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["policyVersion"] = 2
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_adjudication_site_policy_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["adjudicationSitePolicyDigest"] = "9" * 64
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_signer_site_policy_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["signerSitePolicyDigest"] = "3" * 64
        self.assert_chain_invalid(self.rewrap(payload))

    def test_reordered_history_prefix_is_rejected(self):
        payload = json.loads(self.raw.decode())["payload"]
        root_digest = hashlib.sha256(self.decision_ja).hexdigest()
        new_digest = hashlib.sha256(self.decision_jb).hexdigest()
        self.assertEqual(payload["inputs"], [root_digest, new_digest])
        payload["inputs"] = [new_digest, root_digest]
        self.assert_chain_invalid(self.rewrap(payload))

    def test_wrong_policy_history_count(self):
        with self.assertRaises(ValueError):
            verify_final_fork_decision_aggregate_chain(
                self.froot_one, [self.raw], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp,
                [self.pv1], self.ring, self.fm + 10)

    def test_root_stage_policy_must_be_version_one(self):
        first = vpol(2)
        with self.assertRaises(ValueError):
            verify_final_fork_decision_aggregate_chain(
                self.froot_one, [self.raw], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp,
                [first, first], self.ring, self.fm + 10)

    def test_bad_signature_is_authentication_error(self):
        data = json.loads(self.raw.decode())
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.ffdchain(self.froot_one, [compact(data)])

    def test_bad_root_raises_root_error(self):
        with self.assertRaises(
                InvalidFinalAggregateChainForkDecisionAggregateError):
            self.ffdchain(b"{}", [])

    def test_bad_root_is_distinct_from_chain_error(self):
        self.assertIsNot(
            InvalidFinalAggregateChainForkDecisionAggregateError,
            InvalidFinalForkDecisionAggregateChainError)
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateChainError,
            InvalidFinalAggregateChainForkDecisionError)
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateChainError, ValueError))

    def test_non_canonical_encoding_rejected(self):
        pretty = json.dumps(json.loads(self.raw.decode()), indent=2)
        self.assert_chain_invalid(pretty.encode())
        self.assert_chain_invalid(
            (self.raw.decode("utf-8") + "\n").encode())


class PublicArgumentTypeTest(FinalForkDecisionAggregateChainFixtures,
                            unittest.TestCase):
    def test_supersede_type_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.ffdsucc(self.froot_two, self.froot_two, "x")
        with self.assertRaises(TypeError):
            self.ffdsucc(self.froot_two, self.froot_two,
                      [decision_item(1, self.decision_jb)])
        with self.assertRaises(TypeError):
            self.ffdsucc(
                self.froot_two, self.froot_two,
                [{"id": "x", "decision": 1}])
        with self.assertRaises(ValueError):
            self.ffdsucc(self.froot_two, self.froot_two,
                      [decision_item("", self.decision_jb)])
        with self.assertRaises(ValueError):
            self.ffdsucc(self.froot_two, self.froot_two,
                      [decision_item("a", self.decision_ja),
                       decision_item("a", self.decision_jb)])
        with self.assertRaises(TypeError):
            supersede_final_fork_decision_aggregate(
                self.froot_two, self.froot_two, [], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp, self.pv1, self.pv2_t1,
                self.ring, True, self.fm, JUDGE, 1)
        with self.assertRaises(ValueError):
            supersede_final_fork_decision_aggregate(
                self.froot_two, self.froot_two, [], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp, self.pv1, self.pv2_t1,
                self.ring, -1, self.fm, JUDGE, 1)
        with self.assertRaises(TypeError):
            self.ffdsucc(self.froot_two, self.froot_two, [], issuer=7)
        with self.assertRaises(ValueError):
            self.ffdsucc(self.froot_two, self.froot_two, [], issuer="")
        with self.assertRaises(TypeError):
            self.ffdsucc(self.froot_two, self.froot_two, [], version=True)
        with self.assertRaises(ValueError):
            self.ffdsucc(self.froot_two, self.froot_two, [], version=0)
        with self.assertRaises(
                InvalidFinalAggregateChainForkDecisionAggregateError):
            self.ffdsucc(b"not-a-packet", b"not-a-packet", [])

    def test_verify_argument_faults(self):
        with self.assertRaises(TypeError):
            verify_final_fork_decision_aggregate_chain(
                "x", [], self.policy, self.auth, self.ssp, self.fsignerp,
                self.adjp, [self.pv1], self.ring, self.fm)
        with self.assertRaises(TypeError):
            verify_final_fork_decision_aggregate_chain(
                self.froot_two, "x", self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, [self.pv1], self.ring, self.fm)
        with self.assertRaises(TypeError):
            verify_final_fork_decision_aggregate_chain(
                self.froot_two, ["x"], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, [self.pv1, self.pv1],
                self.ring, self.fm)
        with self.assertRaises(ValueError):
            verify_final_fork_decision_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, [], self.ring, self.fm)
        with self.assertRaises(TypeError):
            verify_final_fork_decision_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, [self.pv1], self.ring, True)
        with self.assertRaises(ValueError):
            verify_final_fork_decision_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, [self.pv1], self.ring, -1)


class ImmutabilityAndOfflineTest(FinalForkDecisionAggregateChainFixtures,
                                 unittest.TestCase):
    def test_inputs_are_not_modified(self):
        increment = [decision_item("two", self.decision_jb)]
        snapshot = copy.deepcopy(
            (increment, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.pv1, self.ring))
        self.ffdsucc(self.froot_one, self.froot_one, increment)
        self.assertEqual(
            (increment, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.pv1, self.ring),
            snapshot)

    def test_verify_inputs_are_not_modified(self):
        raw = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        successors = [raw]
        policies = [self.pv1, self.pv1]
        snapshot = copy.deepcopy(
            (successors, policies, self.policy, self.auth, self.ssp,
             self.fsignerp, self.adjp, self.ring))
        self.ffdchain(self.froot_one, successors, policies=policies)
        self.assertEqual(
            (successors, policies, self.policy, self.auth, self.ssp,
             self.fsignerp, self.adjp, self.ring),
            snapshot)

    def test_repeated_results_are_independent(self):
        first = self.ffdchain(self.froot_two, [])
        second = self.ffdchain(self.froot_two, [])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_no_file_is_read_or_written(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.ffdsucc(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_jb)])
            self.ffdchain(self.froot_one, [raw])
            self.ffdchain(self.froot_two, [])


if __name__ == "__main__":
    unittest.main()
