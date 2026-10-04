"""Equivalence regression tests for the refactored final fork decision
aggregate supersession chain boundary.

These tests pin the *public* behavior shared by the five entry points --
:func:`supersede_final_fork_decision_aggregate`,
:func:`verify_final_fork_decision_aggregate_chain`,
:func:`verify_final_fork_decision_aggregate_chains`,
:func:`seal_final_fork_decision_aggregate_head` and
:func:`verify_final_fork_decision_aggregate_head` -- across the five
dimensions the internal refactor had to preserve:

* success: identical canonical UTF-8 bytes, digests, signature coverage,
  height, policy version, status, declaration and anchor summaries across
  repeated calls and across the single-chain, batch and anchor paths;
* tampering: every rebound field is rejected with the same dedicated
  error class, and a bare signature fault stays an authentication fault;
* forks: only the same predecessor under one root pointing at distinct
  successors is a fork, a plain prefix extension is never one, and only
  chains crossing a forking edge are reclassified;
* policy rotation: unchanged content keeps its version and needs an
  increment, a content change steps by exactly one, and an anchor over a
  rotated head binds the final stage policy;
* credential boundaries: unknown, revoked, not-yet-valid and expired
  keys are authentication faults at exactly the moment they stop working,
  both for decision hops and for head anchors;

plus input immutability and equal-but-deep-independent results.
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
    InvalidFinalAggregateChainForkDecisionAggregateError,
    InvalidFinalForkDecisionAggregateAnchorError,
    InvalidFinalForkDecisionAggregateChainError,
    SECRET,
    _pac_policy_digest,
    _prune_compact,
    _usable_checkpoint_key,
    _validated_keyring,
    seal_final_fork_decision_aggregate_head,
    supersede_final_fork_decision_aggregate,
    verify_final_fork_decision_aggregate_chain,
    verify_final_fork_decision_aggregate_chains,
    verify_final_fork_decision_aggregate_head,
)

from test_final_fork_decision_aggregate_chains import (
    FinalForkDecisionAggregateChainsFixtures,
    chain_item,
)
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import entry
from test_prune_attestations import JUDGE, SITE_C
from test_supersede_chain_fork_aggregate import vpol

JUDGE_B = SITE_C


SUCCESSOR_INVARIANT_FIELDS = (
    "prunePolicyDigest",
    "authorizationPolicyDigest",
    "sitePolicyDigest",
    "signerSitePolicyDigest",
    "adjudicationSitePolicyDigest",
)


class SuccessEquivalenceTest(FinalForkDecisionAggregateChainsFixtures,
                            unittest.TestCase):
    """One chain, verified through every entry point, one summary."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # A two-hop chain: growth then a policy rotation.
        self.first = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        self.second = self.ffdsucc(
            self.froot_one, self.first, [],
            old=self.pv1, new=self.pv2_t1,
            moment=self.fm + 20, effective=self.fm + 5)
        self.item = chain_item(
            "chain", self.froot_one, [self.first, self.second],
            [self.pv1, self.pv1, self.pv2_t1])

    def test_sealing_is_byte_for_byte_deterministic(self):
        again = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        self.assertEqual(again, self.first)
        rotated_again = self.ffdsucc(
            self.froot_one, self.first, [],
            old=self.pv1, new=self.pv2_t1,
            moment=self.fm + 20, effective=self.fm + 5)
        self.assertEqual(rotated_again, self.second)

    def test_single_chain_batch_and_anchor_summaries_agree(self):
        single = verify_final_fork_decision_aggregate_chain(
            self.item["root"], self.item["successors"],
            self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
            self.item["policies"], self.ring, self.vmoment)
        batch = self.ffreport([self.item])["items"][0]
        self.assertEqual(batch["status"], "verified")
        self.assertEqual(batch["result"], single)
        anchor = self.ffseal([self.item], "chain")
        anchored = self.ffverify(anchor, [self.item], "chain")
        payload = json.loads(anchor.decode())["payload"]
        self.assertEqual(payload["rootDigest"], single["rootDigest"])
        self.assertEqual(payload["headDigest"], single["headDigest"])
        self.assertEqual(payload["height"], single["height"])
        self.assertEqual(payload["policyVersion"], single["policyVersion"])
        self.assertEqual(
            payload["declarationDigest"], single["declarationDigest"])
        self.assertEqual(anchored["rootDigest"], single["rootDigest"])
        self.assertEqual(anchored["headDigest"], single["headDigest"])
        self.assertEqual(anchored["height"], single["height"])
        self.assertEqual(anchored["policyVersion"], single["policyVersion"])
        self.assertEqual(
            anchored["declarationDigest"], single["declarationDigest"])
        self.assertEqual(anchored["anchorDigest"],
                         hashlib.sha256(anchor).hexdigest())

    def test_rotated_head_binds_the_final_stage_policy(self):
        anchor = self.ffseal([self.item], "chain")
        payload = json.loads(anchor.decode())["payload"]
        self.assertEqual(payload["policyVersion"], 2)
        self.assertEqual(
            payload["policyDigest"], _pac_policy_digest(self.pv2_t1))
        self.assertEqual(payload["height"], 2)

    def test_results_are_equal_but_deeply_independent(self):
        a = verify_final_fork_decision_aggregate_chain(
            self.froot_two, [], self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, [self.pv1], self.ring, self.vmoment)
        b = verify_final_fork_decision_aggregate_chain(
            self.froot_two, [], self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, [self.pv1], self.ring, self.vmoment)
        self.assertEqual(a, b)
        self.assertIsNot(a, b)
        a["status"] = "tampered"
        c = verify_final_fork_decision_aggregate_chain(
            self.froot_two, [], self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, [self.pv1], self.ring, self.vmoment)
        self.assertEqual(c["status"], "accepted")

    def test_inputs_are_never_modified(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        snapshot = copy.deepcopy(items)
        policies_snapshot = copy.deepcopy(
            [self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
             self.pv1, self.ring])
        self.ffreport(items)
        self.ffseal(items, "a")
        verify_final_fork_decision_aggregate_chain(
            self.froot_two, [], self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, [self.pv1], self.ring, self.vmoment)
        self.assertEqual(items, snapshot)
        self.assertEqual(
            [self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
             self.pv1, self.ring],
            policies_snapshot)
        anchor = self.ffseal(items, "a")
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file access")):
            self.ffreport(items)
            self.ffverify(anchor, items, "a")


class TamperEquivalenceTest(FinalForkDecisionAggregateChainsFixtures,
                           unittest.TestCase):
    """A re-signed tampered successor or anchor is still structurally
    bound by the shared verifier; a bare bad signature is an auth fault."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])

    def resign_successor(self, payload, moment=None):
        """Re-seal an edited successor payload with the JUDGE hop key."""
        at = self.fm + 10 if moment is None else moment
        entry = _usable_checkpoint_key(
            _validated_keyring(self.ring),
            payload["issuer"], payload["keyVersion"], at)
        signature = hmac.new(
            bytes.fromhex(entry[SECRET]), _prune_compact(payload),
            hashlib.sha256).hexdigest()
        return _prune_compact({"payload": payload, "signature": signature})

    def assert_chain_invalid(self, packet):
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self.ffdchain(self.froot_one, [packet],
                          policies=[self.pv1, self.pv1])

    def test_each_invariant_digest_tamper_is_a_chain_error(self):
        for field in SUCCESSOR_INVARIANT_FIELDS:
            payload = json.loads(self.raw.decode())["payload"]
            payload[field] = "9" * 64
            self.assert_chain_invalid(self.resign_successor(payload))

    def test_each_link_tamper_is_a_chain_error(self):
        edits = {
            "rootDigest": "0" * 64,
            "predecessorDigest": "1" * 64,
            "height": 9,
        }
        for field, value in edits.items():
            payload = json.loads(self.raw.decode())["payload"]
            payload[field] = value
            self.assert_chain_invalid(self.resign_successor(payload))

    def test_backwards_effective_moment_over_a_successor_is_rejected(self):
        # Build a two-hop chain, then re-seal the second hop with an
        # effective moment before the first hop's effective moment.
        first = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        second = self.ffdsucc(
            self.froot_one, first, [], old=self.pv1, new=self.pv2_t1,
            moment=self.fm + 20, effective=self.fm + 5)
        payload = json.loads(second.decode())["payload"]
        payload["effectiveAt"] = self.fm - 1
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self.ffdchain(
                self.froot_one,
                [first, self.resign_successor(payload, self.fm + 20)],
                policies=[self.pv1, self.pv1, self.pv2_t1])

    def test_conclusion_tamper_cannot_be_resigned(self):
        for field in ("status",):
            payload = json.loads(self.raw.decode())["payload"]
            payload[field] = "insufficient"
            self.assert_chain_invalid(self.resign_successor(payload))
        payload = json.loads(self.raw.decode())["payload"]
        payload["policyVersion"] = 2
        self.assert_chain_invalid(self.resign_successor(payload))

    def test_bare_signature_fault_is_authentication_error(self):
        data = json.loads(self.raw.decode())
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.ffdchain(self.froot_one, [_prune_compact(data)],
                          policies=[self.pv1, self.pv1])

    def test_root_bytes_fault_keeps_the_root_error_class(self):
        with self.assertRaises(
                InvalidFinalAggregateChainForkDecisionAggregateError):
            self.ffdchain(b"\xff", [])

    def test_anchor_binding_tamper_is_an_anchor_error(self):
        items = [self.bare_one("a")]
        anchor = self.ffseal(items, "a")
        for field, value in (("height", 5), ("rootDigest", "2" * 64),
                             ("headDigest", "3" * 64),
                             ("policyDigest", "4" * 64),
                             ("policyVersion", 2),
                             ("declarationDigest", "5" * 64)):
            payload = json.loads(anchor.decode())["payload"]
            payload[field] = value
            with self.assertRaises(InvalidFinalForkDecisionAggregateAnchorError):
                self.ffverify(self.ffrewrap(payload), items, "a")

    def test_anchor_bare_signature_fault_is_authentication_error(self):
        items = [self.bare_one("a")]
        anchor = self.ffseal(items, "a")
        data = json.loads(anchor.decode())
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.ffverify(_prune_compact(data), items, "a")


class ForkClassificationTest(FinalForkDecisionAggregateChainsFixtures,
                            unittest.TestCase):
    def test_divergence_is_a_fork_but_prefix_extension_is_not(self):
        forked = self.ffreport([
            self.ffitem("b", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("a", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1])])
        self.assertEqual(len(forked["forks"]), 1)
        self.assertEqual(
            [i["status"] for i in forked["items"]],
            ["conflicted", "conflicted"])
        extended = self.ffreport([
            self.ffitem("long", self.froot_one,
                       [self.s_grow, self.sec_t1],
                       [self.pv1, self.pv1, self.pv2_t1]),
            self.ffitem("short", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("bare", self.froot_one)])
        self.assertEqual(extended["forks"], [])
        self.assertEqual(
            [i["status"] for i in extended["items"]],
            ["verified", "verified", "verified"])

    def test_fork_detection_is_scoped_to_one_root(self):
        report = self.ffreport([
            self.ffitem("a", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_two, [self.t_rot],
                       [self.pv1, self.pv2_t1])])
        self.assertEqual(report["forks"], [])

    def test_failed_chains_are_never_reclassified(self):
        report = self.ffreport([
            self.ffitem("ok", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("bad", self.froot_one, [b"{}"],
                       [self.pv1, self.pv1])])
        statuses = {i["id"]: i["status"] for i in report["items"]}
        self.assertEqual(statuses, {"ok": "verified", "bad": "invalid-chain"})
        self.assertEqual(report["forks"], [])

    def test_a_forked_target_cannot_be_sealed(self):
        items = [
            self.ffitem("a", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1])]
        with self.assertRaises(ValueError):
            self.ffseal(items, "a")


class PolicyRotationTest(FinalForkDecisionAggregateChainsFixtures,
                        unittest.TestCase):
    def test_rotation_rules_hold_through_seal_and_verify(self):
        # A content rotation may re-seal an empty increment...
        rotated = self.ffdsucc(
            self.froot_two, self.froot_two, [],
            old=self.pv1, new=self.pv2_t1)
        payload = json.loads(rotated.decode())["payload"]
        self.assertEqual(payload["policyVersion"], 2)
        self.assertEqual(payload["decisions"], [])
        result = self.ffdchain(
            self.froot_two, [rotated], policies=[self.pv1, self.pv2_t1])
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["status"], "accepted")
        # ...while an unchanged policy without a decision is rejected.
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(self.froot_two, self.froot_two, [],
                         old=self.pv1, new=self.pv1)
        # A rotation skipping a version is rejected.
        skip = vpol(3, threshold=1)
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self.ffdsucc(self.froot_two, self.froot_two, [],
                         old=self.pv1, new=skip)

    def test_rotation_keeps_the_accepted_common_declaration(self):
        rotated = self.ffdsucc(
            self.froot_two, self.froot_two, [],
            old=self.pv1, new=self.pv2_t1)
        payload = json.loads(rotated.decode())["payload"]
        root_declaration = json.loads(
            self.froot_two.decode())["payload"]["declaration"]
        self.assertEqual(payload["declaration"], root_declaration)

    def test_anchor_over_rotated_head_round_trips(self):
        item = self.ffitem(
            "h", self.froot_one, [self.s_grow, self.sec_t1],
            [self.pv1, self.pv1, self.pv2_t1])
        anchor = self.ffseal([item], "h")
        result = self.ffverify(anchor, [item], "h")
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(
            result["policyDigest"], _pac_policy_digest(self.pv2_t1))
        # A second, different sealing moment yields a distinct but still
        # verifiable anchor with the same chain bindings.
        later = self.ffseal([item], "h", moment=self.vmoment + 10)
        self.assertNotEqual(later, anchor)
        later_payload = json.loads(later.decode())["payload"]
        payload = json.loads(anchor.decode())["payload"]
        for field in ("rootDigest", "headDigest", "height", "policyDigest",
                      "policyVersion", "declarationDigest"):
            self.assertEqual(later_payload[field], payload[field], field)
        self.assertEqual(later_payload["sealedAt"], self.vmoment + 10)
        self.assertEqual(
            self.ffverify(later, [item], "h",
                          moment=self.vmoment + 10)["anchorDigest"],
            hashlib.sha256(later).hexdigest())


class CredentialBoundaryTest(FinalForkDecisionAggregateChainsFixtures,
                             unittest.TestCase):
    def ring_with(self, site, version, **changes):
        ring = copy.deepcopy(self.ring)
        ring[site] = [dict(ring[site][0], **changes)]
        return ring

    def test_unknown_issuer_is_an_authentication_fault(self):
        with self.assertRaises(AuthenticationError):
            self.ffdchain(self.froot_two, [], ring={"else": [
                entry(1, "22" * 32)]})

    def seal_anchor(self, items, target, ring=None, moment=None,
                    issuer=JUDGE, version=1):
        return seal_final_fork_decision_aggregate_head(
            items, target, self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp,
            self.ring if ring is None else ring,
            self.vmoment if moment is None else moment, issuer, version)

    def test_revoked_decision_key_rejects_hop_and_anchor(self):
        revoked = self.ring_with(JUDGE, 1, revoked=True)
        with self.assertRaises(AuthenticationError):
            self.ffdchain(self.froot_two, [], ring=revoked)
        with self.assertRaises(AuthenticationError):
            self.seal_anchor([self.bare_one("a")], "a", ring=revoked)

    def test_not_yet_valid_and_expired_keys_are_boundary_faults(self):
        future = self.ring_with(
            JUDGE, 1, notBefore=self.vmoment + 1,
            notAfter=10 ** 9)
        with self.assertRaises(AuthenticationError):
            self.ffdchain(self.froot_two, [], ring=future,
                          moment=self.vmoment)
        expired = self.ring_with(
            JUDGE, 1, notBefore=0, notAfter=self.vmoment - 1)
        with self.assertRaises(AuthenticationError):
            self.ffdchain(self.froot_two, [], ring=expired,
                          moment=self.vmoment)

    def test_increment_key_unusable_only_at_effective_is_rejected(self):
        future_ring = copy.deepcopy(self.ring)
        future_ring[JUDGE_B] = [
            entry(1, self.ring[JUDGE_B][0]["secret"],
                  not_before=self.fm + 5, not_after=10 ** 9)]
        decision = self.facf_decision(self.ffork_proofs, JUDGE_B)
        with self.assertRaises(AuthenticationError):
            supersede_final_fork_decision_aggregate(
                self.froot_one, self.froot_one,
                [decision_item("two", decision)],
                self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
                self.pv1, self.pv1, future_ring,
                self.fm + 20, self.fm, JUDGE, 1)

    def test_anchor_sealed_in_the_future_is_rejected_now(self):
        items = [self.bare_one("a")]
        anchor = self.ffseal(items, "a", moment=self.vmoment + 10)
        with self.assertRaises(InvalidFinalForkDecisionAggregateAnchorError):
            self.ffverify(anchor, items, "a", moment=self.vmoment)
        # Once the verification moment reaches the sealing moment it is
        # valid again.
        self.assertEqual(
            self.ffverify(anchor, items, "a",
                          moment=self.vmoment + 10)["anchorDigest"],
            hashlib.sha256(anchor).hexdigest())

    def test_anchor_signer_window_is_enforced(self):
        items = [self.bare_one("a")]
        not_yet = self.ring_with(
            JUDGE, 1, notBefore=self.vmoment + 1, notAfter=10 ** 9)
        with self.assertRaises(AuthenticationError):
            self.seal_anchor(items, "a", ring=not_yet)
        expired = self.ring_with(
            JUDGE, 1, notBefore=0, notAfter=self.vmoment - 1)
        with self.assertRaises(AuthenticationError):
            self.seal_anchor(items, "a", ring=expired)


class ErrorTaxonomyTest(FinalForkDecisionAggregateChainsFixtures,
                        unittest.TestCase):
    def test_the_three_value_error_families_are_distinct(self):
        self.assertTrue(issubclass(
            InvalidFinalAggregateChainForkDecisionAggregateError, ValueError))
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateChainError, ValueError))
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateAnchorError, ValueError))
        self.assertIsNot(
            InvalidFinalAggregateChainForkDecisionAggregateError,
            InvalidFinalForkDecisionAggregateChainError)
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateChainError,
            InvalidFinalForkDecisionAggregateAnchorError)
        self.assertTrue(issubclass(AuthenticationError, Exception))

    def test_bool_never_poses_as_an_int_on_every_path(self):
        with self.assertRaises(TypeError):
            self.ffreport([self.bare_one()], moment=True)
        with self.assertRaises(TypeError):
            self.ffseal([self.bare_one("a")], "a", version=True)
        with self.assertRaises(TypeError):
            verify_final_fork_decision_aggregate_chain(
                self.froot_two, [], self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, [self.pv1], self.ring, True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
