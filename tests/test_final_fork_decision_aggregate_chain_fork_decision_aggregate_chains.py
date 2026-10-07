"""Tests for successor sealing and whole-chain verification over final
fork decision aggregate chain fork decision aggregates.

Covers
:func:`supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate`
and
:func:`verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain`:
the canonical signed successor packet and every binding (root,
predecessor, continuous height, the predecessor decision digest prefix
plus the raw non-empty decision increment as hex, the recomputed items,
common declaration and status, the six invariant policy digests --
prune, site authorization, fork-proof signer, adjudication signer,
issuing adjudication site and proof site -- the old/new decision policy
digests, the increasing policy version, the effective moment and the
sealing identity), the per-hop full-stage re-verification (every prefix
decision and every increment decision is re-checked for authorization,
credentials and threshold at the hop's effective moment and again at the
sealing / verification moment, with no grandfathering), the aggregate
tally (same-site identical declaration counted once, differing
same-site declarations a contradiction, cross-site disagreement
conflicted with no majority override), the verdict state machine
(insufficient kept or advanced, accepted only kept or conflicted,
conflicted never masked, the empty fork edge set as a legal
declaration), the append-only decision prefix (the increment is always
non-empty and adds only new digests and ids), versioned decision site
policy rotation with a single policyVersion step, dual-policy sealer
authorization, offline hop-by-hop verification, bare-root verification
returning height zero, the fresh depth-independent chain summary with
the declaration digest, the distinct root / chain error hierarchy, and
every error classification (including a bool never posing as an int),
input immutability and the purely offline guarantee.
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
    InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError,
    InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
    InvalidFinalForkDecisionAggregateChainForkDecisionError,
    supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate,
    verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain,
)

from test_final_fork_decision_aggregate_chain_fork_decision_aggregates import (
    FinalForkDecisionAggregateChainForkDecisionFixtures,
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
    "policyVersion", "predecessorDigest", "proofSitePolicyDigest",
    "prunePolicyDigest", "rootDigest", "signerSitePolicyDigest",
    "sitePolicyDigest", "status", "version",
]
INCREMENT_KEYS = ["decision", "id"]
CHAIN_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "declarationDigest",
]


class FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures(
    FinalForkDecisionAggregateChainForkDecisionFixtures
):
    """Root aggregates, versioned decision policies and chain builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.pv1 = vpol()
        self.pv2_t1 = vpol(2, threshold=1)
        self.pv2_3 = vpol(2, sites=(JUDGE, JUDGE_B, SITE_A), threshold=2)

        # A fork decision from a third decision site; adjudicating the
        # same fork proofs yields the same complete declaration.
        self.decision_ac = self.ffdacf_judge(
            self.fork_proof_items, issuer=SITE_A)
        # A fork-free decision from the third site, a different
        # declaration from the fork decisions of JUDGE/JUDGE_B.
        self.free_c = self.ffdacf_judge(
            self.free_proof_items, issuer=SITE_A)

        self.froot_one = self.cfd_make_aggregate(
            [decision_item("one", self.decision_ja)])
        self.froot_two = self.cfd_make_aggregate(self.fdecision_items())
        self.froot_conf = self.cfd_make_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.free_jb)])
        self.froot_free = self.cfd_make_aggregate([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb)])

    def ffdasucc(self, root, predecessor, increment, old=None, new=None,
             moment=None, effective=None, issuer=JUDGE, version=1):
        return (
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                root, predecessor, increment,
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp,
                self.pv1 if old is None else old,
                self.pv1 if new is None else new,
                self.ring,
                self.m + 10 if moment is None else moment,
                self.m if effective is None else effective,
                issuer, version,
            )
        )

    def ffdachain(self, root, successors, policies=None, moment=None,
              ring=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        if moment is None:
            moment = self.m + 10 * max(1, len(successors))
        return (
            verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain(
                root, successors, self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.proofp, policies,
                self.ring if ring is None else ring, moment,
            )
        )


class SuccessorShapeTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])

    def test_canonical_compact_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(json.loads(self.raw.decode())), self.raw)
        self.raw.decode("utf-8")
        self.assertNotIn(b" ", self.raw)

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
        self.assertEqual(payload["effectiveAt"], self.m)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["status"], "accepted")
        for field in ("prunePolicyDigest", "authorizationPolicyDigest",
                      "sitePolicyDigest", "signerSitePolicyDigest",
                      "adjudicationSitePolicyDigest",
                      "proofSitePolicyDigest"):
            self.assertEqual(payload[field], root_payload[field], field)

    def test_bound_prefix_plus_increment_inputs(self):
        payload = json.loads(self.raw.decode())["payload"]
        self.assertEqual(payload["inputs"], [
            hashlib.sha256(self.decision_ja).hexdigest(),
            hashlib.sha256(self.decision_jb).hexdigest(),
        ])

    def test_signed_with_exact_issuer_version_key(self):
        import hmac as _hmac
        from offline_coordination.replication import (
            _prune_compact, _usable_checkpoint_key, _validated_keyring,
            SECRET,
        )
        data = json.loads(self.raw.decode())
        key_entry = _usable_checkpoint_key(
            _validated_keyring(self.ring), JUDGE, 1, self.m + 10)
        expected = _hmac.new(
            bytes.fromhex(key_entry[SECRET]),
            _prune_compact(data["payload"]),
            hashlib.sha256).hexdigest()
        self.assertEqual(data["signature"], expected)


class BareRootVerifyTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def test_bare_root_verified_in_full(self):
        result = self.ffdachain(self.froot_two, [])
        self.assertEqual(list(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.froot_two).hexdigest())
        self.assertEqual(result["headDigest"], result["rootDigest"])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["declarationDigest"])

    def test_conflicted_bare_root_declaration_digest_is_null(self):
        result = self.ffdachain(self.froot_conf, [])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declarationDigest"])

    def test_insufficient_bare_root_keeps_declaration_digest(self):
        result = self.ffdachain(self.froot_one, [])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declarationDigest"])

    def test_fork_free_declaration_is_legal(self):
        root_payload = json.loads(self.froot_free.decode())["payload"]
        self.assertEqual(root_payload["status"], "accepted")
        self.assertEqual(root_payload["declaration"]["common"], [])
        result = self.ffdachain(self.froot_free, [])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(
            result["declarationDigest"],
            hashlib.sha256(compact(root_payload["declaration"])).hexdigest())

    def test_result_is_depth_independent_and_fresh(self):
        first = self.ffdachain(self.froot_two, [])
        second = self.ffdachain(self.froot_two, [])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)


class GrowthAndStateMachineTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def test_insufficient_grows_to_accepted(self):
        raw = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        result = self.ffdachain(self.froot_one, [raw])
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["declarationDigest"])

    def test_invalid_increment_stays_insufficient_but_keeps_declaration(self):
        raw = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("bad", b"{}")])
        payload = json.loads(raw.decode())["payload"]
        self.assertEqual(payload["status"], "insufficient")
        bad = next(row for row in payload["items"] if row["id"] == "bad")
        self.assertEqual(bad["conclusion"], "invalid")
        self.assertEqual(bad["reason"], "invalid")
        self.assertIsNone(bad["issuer"])
        result = self.ffdachain(self.froot_one, [raw])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declarationDigest"])

    def test_conflicted_can_never_be_masked(self):
        raw = self.ffdasucc(
            self.froot_conf, self.froot_conf,
            [decision_item("s", self.decision_jb)])
        self.assertEqual(
            json.loads(raw.decode())["payload"]["status"], "conflicted")
        result = self.ffdachain(self.froot_conf, [raw])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declarationDigest"])

    def test_accepted_may_advance_to_conflicted_under_rotation(self):
        raw = self.ffdasucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.free_c)],
            old=self.pv1, new=self.pv2_3)
        self.assertEqual(
            json.loads(raw.decode())["payload"]["status"], "conflicted")
        self.assertEqual(
            self.ffdachain(self.froot_two, [raw],
                       policies=[self.pv1, self.pv2_3])["status"],
            "conflicted")

    def test_accepted_keeps_identical_declaration_under_rotation(self):
        # A third site adjudicating the same fork proofs casts the exact
        # same complete declaration, so acceptance is preserved.
        raw = self.ffdasucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.decision_ac)],
            old=self.pv1, new=self.pv2_3)
        payload = json.loads(raw.decode())["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(
            payload["declaration"],
            json.loads(self.froot_two.decode())["payload"]["declaration"])

    def test_insufficient_may_stay_insufficient(self):
        raw = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("bad", b"{}")])
        self.assertEqual(
            self.ffdachain(self.froot_one, [raw])["status"], "insufficient")

    def test_two_hop_chain_recomputes_at_each_stage(self):
        first = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        second = self.ffdasucc(
            self.froot_one, first,
            [decision_item("three", self.decision_ac)],
            old=self.pv1, new=self.pv2_3,
            moment=self.m + 20, effective=self.m + 5)
        result = self.ffdachain(
            self.froot_one, [first, second],
            policies=[self.pv1, self.pv1, self.pv2_3],
            moment=self.m + 30)
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(second).hexdigest())


class PerHopReverificationTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    """Every hop re-verifies ALL decisions of the stage, prefix included."""

    def _seal(self, predecessor, ring, moment, effective,
              old=None, new=None, increment=()):
        return supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
            self.froot_one, predecessor, list(increment),
            self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
            self.proofp,
            self.pv1 if old is None else old,
            self.pv2_3 if new is None else new,
            ring, moment, effective, JUDGE, 1)

    def test_revoked_prefix_credential_rejects_later_hop(self):
        first = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE_B][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self._seal(first, revoked, self.m + 20, self.m + 5,
                       increment=[decision_item("three", self.decision_ac)])

    def test_expired_prefix_credential_at_effective_rejects_hop(self):
        first = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        expired = copy.deepcopy(self.ring)
        expired[JUDGE_B][0]["notAfter"] = self.m + 3
        with self.assertRaises(AuthenticationError):
            self._seal(first, expired, self.m + 20, self.m + 10,
                       increment=[decision_item("three", self.decision_ac)])

    def test_rotated_policy_dropping_counted_site_rejects_hop(self):
        first = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        drop = vpol(2, sites=(JUDGE, SITE_A), threshold=1)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self._seal(first, self.ring, self.m + 20, self.m + 5,
                       new=drop,
                       increment=[decision_item("three", self.decision_ac)])

    def test_prefix_credential_expired_at_verify_moment_rejects_chain(self):
        first = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        expired = copy.deepcopy(self.ring)
        expired[JUDGE_B][0]["notAfter"] = self.m + 15
        with self.assertRaises(AuthenticationError):
            self.ffdachain(self.froot_one, [first], ring=expired,
                       moment=self.m + 100)

    def test_increment_credential_unusable_at_effective_rejected(self):
        future_ring = copy.deepcopy(self.ring)
        future_ring[JUDGE_B] = [
            entry(1, SECRET_COORD, not_before=self.m + 5,
                  not_after=self.m + 100)]
        # The decision bytes are signed normally; only the credential
        # window in the sealing keyring makes it unusable at effectiveAt.
        decision = self.ffdacf_judge(
            self.fork_proof_items, issuer=JUDGE_B)
        with self.assertRaises(AuthenticationError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", decision)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv1, future_ring,
                self.m + 20, self.m, JUDGE, 1)

    def test_increment_credential_rejected_by_new_policy(self):
        # A rotation to threshold 1 keeps JUDGE/JUDGE_B; a third-site
        # increment is authenticated but unauthorized, so it casts no
        # vote while the accepted prefix declaration is preserved.
        raw = self.ffdasucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.decision_ac)],
            old=self.pv1, new=self.pv2_t1)
        payload = json.loads(raw.decode())["payload"]
        new_row = next(
            row for row in payload["items"] if row["id"] == "c")
        self.assertEqual(new_row["conclusion"], "invalid")
        self.assertEqual(new_row["reason"], "unauthorized")
        self.assertEqual(payload["status"], "accepted")

    def test_same_site_different_declaration_is_a_contradiction(self):
        raw = self.ffdasucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.free_ja)],
            old=self.pv1, new=self.pv2_t1)
        payload = json.loads(raw.decode())["payload"]
        self.assertEqual(payload["status"], "conflicted")


class AppendOnlyTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def test_empty_increment_is_value_error_even_on_rotation(self):
        with self.assertRaises(ValueError):
            self.ffdasucc(self.froot_two, self.froot_two, [],
                      old=self.pv1, new=self.pv2_t1)

    def test_repeated_packet_digest_rejected(self):
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdasucc(
                self.froot_one, self.froot_one,
                [decision_item("nine", self.decision_ja)])

    def test_repeated_item_id_rejected(self):
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdasucc(
                self.froot_one, self.froot_one,
                [decision_item("one", self.decision_jb)])

    def test_duplicate_increment_id_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffdasucc(
                self.froot_one, self.froot_one,
                [decision_item("x", self.decision_jb),
                 decision_item("x", self.free_jb)])


class PolicyVersionTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def test_first_policy_must_match_root_and_carry_version_one(self):
        bad = vpol(1, sites=(JUDGE,), threshold=1)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdasucc(self.froot_two, self.froot_two,
                      [decision_item("c", self.decision_ac)],
                      old=bad, new=self.pv2_3)

    def test_changed_content_must_step_by_exactly_one(self):
        jump = vpol(3, sites=(JUDGE, JUDGE_B, SITE_A), threshold=2)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdasucc(self.froot_two, self.froot_two,
                      [decision_item("c", self.decision_ac)],
                      old=self.pv1, new=jump)

    def test_unchanged_content_must_keep_version(self):
        mismatch = vpol(2)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdasucc(self.froot_two, self.froot_two,
                      [decision_item("c", self.decision_ac)],
                      old=self.pv1, new=mismatch)

    def test_old_policy_must_equal_predecessor_policy(self):
        first = self.ffdasucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.decision_ac)],
            old=self.pv1, new=self.pv2_3)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdasucc(
                self.froot_two, first,
                [decision_item("d", self.free_c)],
                old=self.pv1, new=self.pv2_3)


class AuthorizationAndMomentTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def test_sealer_must_be_authorized_under_both_policies(self):
        drop = vpol(2, sites=(JUDGE_B, SITE_A), threshold=1)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdasucc(self.froot_two, self.froot_two,
                      [decision_item("c", self.decision_ac)],
                      old=self.pv1, new=drop, issuer=JUDGE)

    def test_credential_must_be_usable_at_both_moments(self):
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, SECRET_COORD, not_after=self.m + 5)]
        with self.assertRaises(AuthenticationError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_jb)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv1,
                ring, self.m + 10, self.m, JUDGE, 1)

    def test_effective_moment_must_not_move_backwards(self):
        first = self.ffdasucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.decision_ac)],
            old=self.pv1, new=self.pv2_3, effective=self.m + 5)
        with self.assertRaises(ValueError):
            self.ffdasucc(
                self.froot_two, first,
                [decision_item("d", self.free_c)],
                old=self.pv2_3, new=self.pv2_3,
                effective=self.m + 4, moment=self.m + 10)

    def test_unknown_sealer_is_authentication_error(self):
        ring = {site: self.ring[site]
                for site in self.ring if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_two, self.froot_two,
                [decision_item("c", self.decision_ac)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv2_3,
                ring, self.m + 10, self.m, JUDGE, 1)

    def test_invariant_policies_must_match_the_root(self):
        other_proofp = {"sites": {SITE_A: {1}, SITE_B: {1}},
                        "threshold": 1}
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_jb)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                other_proofp, self.pv1, self.pv1,
                self.ring, self.m + 10, self.m, JUDGE, 1)
        other_adjp = {"sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
                      "threshold": 1}
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_jb)],
                self.policy, self.auth, self.ssp, self.fsignerp,
                other_adjp, self.proofp, self.pv1, self.pv1,
                self.ring, self.m + 10, self.m, JUDGE, 1)

    def test_predecessor_must_extend_the_given_root(self):
        other_root = self.cfd_make_aggregate(
            [decision_item("zz", self.decision_ja)])
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdasucc(
                other_root, self.froot_one,
                [decision_item("two", self.decision_jb)])

    def test_root_argument_types(self):
        with self.assertRaises(TypeError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                "x", self.froot_one,
                [decision_item("two", self.decision_jb)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv1,
                self.ring, self.m + 10, self.m, JUDGE, 1)
        with self.assertRaises(TypeError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_two, "x",
                [decision_item("two", self.decision_jb)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv1,
                self.ring, self.m + 10, self.m, JUDGE, 1)


class ChainBindingTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])

    def rewrap(self, payload):
        import hmac as _hmac
        from offline_coordination.replication import (
            _prune_compact, _usable_checkpoint_key, _validated_keyring,
            SECRET,
        )
        entry = _usable_checkpoint_key(
            _validated_keyring(self.ring), JUDGE, 1, self.m + 10)
        signature = _hmac.new(
            bytes.fromhex(entry[SECRET]), _prune_compact(payload),
            hashlib.sha256).hexdigest()
        return _prune_compact({"payload": payload, "signature": signature})

    def assert_chain_invalid(self, raw):
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
        ):
            self.ffdachain(self.froot_one, [raw])

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

    def test_tampered_policy_digest_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["newPolicyDigest"] = "9" * 64
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_invariant_policy_binding(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["proofSitePolicyDigest"] = "3" * 64
        self.assert_chain_invalid(self.rewrap(payload))

    def test_reordered_history_prefix_is_rejected(self):
        payload = json.loads(self.raw.decode())["payload"]
        root_digest = hashlib.sha256(self.decision_ja).hexdigest()
        new_digest = hashlib.sha256(self.decision_jb).hexdigest()
        self.assertEqual(payload["inputs"], [root_digest, new_digest])
        payload["inputs"] = [new_digest, root_digest]
        self.assert_chain_invalid(self.rewrap(payload))

    def test_tampered_row_conclusion_is_rejected(self):
        payload = json.loads(self.raw.decode())["payload"]
        row = next(r for r in payload["items"] if r["id"] == "two")
        row["conclusion"] = "duplicate"
        row["reason"] = "duplicate"
        self.assert_chain_invalid(self.rewrap(payload))

    def test_wrong_policy_history_count(self):
        with self.assertRaises(ValueError):
            verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain(
                self.froot_one, [self.raw], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp, self.proofp,
                [self.pv1], self.ring, self.m + 10)

    def test_root_stage_policy_must_be_version_one(self):
        first = vpol(2)
        with self.assertRaises(ValueError):
            verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain(
                self.froot_one, [self.raw], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp, self.proofp,
                [first, first], self.ring, self.m + 10)

    def test_bad_signature_is_authentication_error(self):
        data = json.loads(self.raw.decode())
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.ffdachain(self.froot_one, [compact(data)])

    def test_bad_root_raises_root_error(self):
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError
        ):
            self.ffdachain(b"{}", [])

    def test_foreign_decision_site_policy_raises_root_error(self):
        # A root whose aggregate threshold-2 policy is verified against a
        # different version-1 decision policy fails as a root fault.
        foreign = vpol(1, sites=(JUDGE, SITE_A), threshold=1)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError
        ):
            verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain(
                self.froot_one, [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.proofp,
                [foreign], self.ring, self.m + 10)

    def test_error_classes_are_distinct(self):
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError,
            ValueError))
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError,
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError)
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
            InvalidFinalForkDecisionAggregateChainForkDecisionError)

    def test_non_canonical_encoding_rejected(self):
        import json as _json
        pretty = _json.dumps(json.loads(self.raw.decode()), indent=2)
        self.assert_chain_invalid(pretty.encode())
        self.assert_chain_invalid(
            (self.raw.decode("utf-8") + "\n").encode())

    def test_garbage_successor_bytes_are_chain_error(self):
        for raw in (b"", b"\xff", b"{", b'{"payload":{}}',
                    b'{"payload":1,"signature":""}'):
            with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError
            ):
                self.ffdachain(self.froot_one, [raw])


class PublicArgumentTypeTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def test_supersede_type_and_value_faults(self):
        good = [decision_item("two", self.decision_jb)]
        with self.assertRaises(TypeError):
            self.ffdasucc(self.froot_two, self.froot_two, "x")
        with self.assertRaises(TypeError):
            self.ffdasucc(self.froot_two, self.froot_two,
                      [decision_item(1, self.decision_jb)])
        with self.assertRaises(TypeError):
            self.ffdasucc(
                self.froot_two, self.froot_two,
                [{"id": "x", "decision": 1}])
        with self.assertRaises(ValueError):
            self.ffdasucc(self.froot_two, self.froot_two,
                      [decision_item("", self.decision_jb)])
        with self.assertRaises(ValueError):
            self.ffdasucc(self.froot_one, self.froot_one, [])
        with self.assertRaises(TypeError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_two, self.froot_two, good,
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv1,
                self.ring, True, self.m, JUDGE, 1)
        with self.assertRaises(ValueError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_two, self.froot_two, good,
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv1,
                self.ring, -1, self.m, JUDGE, 1)
        with self.assertRaises(TypeError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_two, self.froot_two, good,
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv1,
                self.ring, self.m + 10, True, JUDGE, 1)
        with self.assertRaises(ValueError):
            supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
                self.froot_two, self.froot_two, good,
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.proofp, self.pv1, self.pv1,
                self.ring, self.m + 10, -1, JUDGE, 1)
        with self.assertRaises(TypeError):
            self.ffdasucc(self.froot_two, self.froot_two, good, issuer=7)
        with self.assertRaises(ValueError):
            self.ffdasucc(self.froot_two, self.froot_two, good, issuer="")
        with self.assertRaises(TypeError):
            self.ffdasucc(self.froot_two, self.froot_two, good, version=True)
        with self.assertRaises(ValueError):
            self.ffdasucc(self.froot_two, self.froot_two, good, version=0)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError
        ):
            self.ffdasucc(b"not-a-packet", b"not-a-packet", good)

    def test_verify_argument_faults(self):
        with self.assertRaises(TypeError):
            self.ffdachain("x", [])
        with self.assertRaises(TypeError):
            self.ffdachain(self.froot_two, "x")
        with self.assertRaises(TypeError):
            verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain(
                self.froot_two, ["x"], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.proofp, [self.pv1, self.pv1],
                self.ring, self.m)
        with self.assertRaises(ValueError):
            self.ffdachain(self.froot_two, [], policies=[])
        with self.assertRaises(TypeError):
            verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.proofp, [self.pv1],
                self.ring, True)
        with self.assertRaises(ValueError):
            verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.proofp, [self.pv1],
                self.ring, -1)


class ImmutabilityAndOfflineTest(
    FinalForkDecisionAggregateChainForkDecisionAggregateChainFixtures,
    unittest.TestCase,
):
    def test_inputs_are_not_modified(self):
        increment = [decision_item("two", self.decision_jb)]
        snapshot = copy.deepcopy(
            (increment, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.proofp, self.pv1, self.ring))
        self.ffdasucc(self.froot_one, self.froot_one, increment)
        self.assertEqual(
            (increment, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.proofp, self.pv1, self.ring),
            snapshot)

    def test_verify_inputs_are_not_modified(self):
        raw = self.ffdasucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        successors = [raw]
        policies = [self.pv1, self.pv1]
        snapshot = copy.deepcopy(
            (successors, policies, self.policy, self.auth, self.ssp,
             self.fsignerp, self.adjp, self.proofp, self.ring))
        self.ffdachain(self.froot_one, successors, policies=policies)
        self.assertEqual(
            (successors, policies, self.policy, self.auth, self.ssp,
             self.fsignerp, self.adjp, self.proofp, self.ring),
            snapshot)

    def test_repeated_results_are_independent(self):
        first = self.ffdachain(self.froot_two, [])
        second = self.ffdachain(self.froot_two, [])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_no_file_is_read_or_written(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.ffdasucc(
                self.froot_one, self.froot_one,
                [decision_item("two", self.decision_jb)])
            self.ffdachain(self.froot_one, [raw])
            self.ffdachain(self.froot_two, [])


if __name__ == "__main__":
    unittest.main()
