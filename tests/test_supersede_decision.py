"""Tests for supersession chains over multi-site convergence decisions.

Covers :func:`supersede_decision`, :func:`verify_decision_chain`,
:func:`verify_decision_chains`, :func:`seal_decision_head` and
:func:`verify_decision_head`: the canonical signed successor packet
and every binding (root, predecessor, height, recomputed verdict, raw
evidence increment, old/new policy digests, policy version and
effective moment), the per-hop verdict state machine (insufficient to
accepted/conflicted, accepted only kept or upgraded, conflicted never
masked), the append-only evidence prefix, unchanged-policy growth and
policy rotation versioning, dual-policy sealer authorization and
credential usability at both moments, offline hop-by-hop verification,
batch pre-checks with input-order isolation, fork detection with the
prefix-extension exception, and the stable head anchor seal/reverify
rules and all error classifications.
"""

import copy
import hashlib
import hmac
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidAnchorError,
    InvalidChainError,
    InvalidConvergenceDecisionError,
    adjudicate_convergence,
    certify_fork_convergence,
    seal_decision_head,
    supersede_decision,
    verify_decision_chain,
    verify_decision_chains,
    verify_decision_head,
)

from test_fork_convergence import (
    ALPHA,
    BETA,
    CERTIFIED_AT,
    COORD,
    ConvergenceFixtures,
    GAMMA,
    RING,
    SECRET_COORD,
    compact,
    parse,
)

SIGN_MOMENT = 290
EFFECTIVE_MOMENT = 288
VERIFY_MOMENT = 300


def versioned_policy(sites, threshold=2, policy_version=1):
    return {
        "sites": {site: {1} for site in sites},
        "threshold": threshold,
        "policyVersion": policy_version,
    }


class SupersedeFixtures(ConvergenceFixtures):
    """Shared accepted/insufficient roots, evidence and chain builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        confirmation = self.confirm([
            self.execution_receipt(BETA, moment=220, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=225, post_digest="e2" * 32),
        ])
        self.rounds = self.chain(confirmation)
        self.cert_coord = self.certify(self.rounds)
        self.cert_alpha = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, CERTIFIED_AT,
            ALPHA, 1,
        )
        self.cert_gamma = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, CERTIFIED_AT,
            GAMMA, 1,
        )
        # Extra same-result coord certificates only grow the history.
        self.cert_coord_2 = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, 271, COORD, 1
        )
        self.cert_coord_3 = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, 272, COORD, 1
        )
        other_confirmation = self.confirm([
            self.execution_receipt(BETA, moment=220, post_digest="f9" * 32),
            self.execution_receipt(GAMMA, moment=225, post_digest="e2" * 32),
        ])
        self.rounds_conflict = self.chain(other_confirmation)
        self.cert_coord_conflict = certify_fork_convergence(
            self.rounds_conflict, self.decision, self.pol, RING,
            CERTIFIED_AT, COORD, 1,
        )
        self.site_policy = {
            "sites": {COORD: {1}, ALPHA: {1}, GAMMA: {1}},
            "threshold": 2,
        }
        self.policy_v1 = versioned_policy((COORD, ALPHA, GAMMA), 2, 1)

    def item(self, certificate, item_id, rounds=None):
        return {
            "id": item_id,
            "certificate": certificate,
            "rounds": self.rounds if rounds is None else rounds,
        }

    @property
    def item_coord(self):
        return self.item(self.cert_coord, "c")

    @property
    def item_alpha(self):
        return self.item(self.cert_alpha, "a")

    @property
    def item_gamma(self):
        return self.item(self.cert_gamma, "g")

    @property
    def item_coord_conflict(self):
        return self.item(self.cert_coord_conflict, "cx", self.rounds_conflict)

    def adjudicate(self, items, site_policy=None):
        return adjudicate_convergence(
            items, self.decision, self.pol,
            self.site_policy if site_policy is None else site_policy,
            RING, 280, COORD, 1,
        )

    def insufficient_root(self):
        return self.adjudicate([copy.deepcopy(self.item_coord)])

    def accepted_root(self, site_policy=None):
        return self.adjudicate([
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ], site_policy=site_policy)

    def supersede(self, predecessor, evidence, old_policy=None,
                  new_policy=None, ring=RING, moment=SIGN_MOMENT,
                  effective=EFFECTIVE_MOMENT, issuer=COORD, version=1):
        return supersede_decision(
            predecessor, evidence, self.decision, self.pol,
            self.policy_v1 if old_policy is None else old_policy,
            self.policy_v1 if new_policy is None else new_policy,
            ring, moment, effective, issuer, version,
        )

    def verify_chain(self, root, successors, policies, ring=RING,
                     moment=VERIFY_MOMENT):
        return verify_decision_chain(
            root, successors, self.decision, self.pol, policies, ring, moment
        )

    def verify_chains(self, items, ring=RING, moment=VERIFY_MOMENT):
        return verify_decision_chains(
            items, self.decision, self.pol, ring, moment
        )

    def chain_item(self, chain_id, root, successors, policies):
        return {
            "id": chain_id,
            "roots": root,
            "successors": successors,
            "policies": policies,
        }

    def accepted_chain(self):
        """A two-hop accepted chain; returns root, packets, policies."""
        root = self.accepted_root()
        first_evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ]
        successor_1 = self.supersede(root, first_evidence)
        second_evidence = first_evidence + [
            self.item(self.cert_coord_3, "c3")
        ]
        successor_2 = self.supersede(successor_1, second_evidence)
        policies = [self.policy_v1, self.policy_v1, self.policy_v1]
        return root, [successor_1, successor_2], policies


class SuccessorPacketShapeTest(SupersedeFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.root = self.insufficient_root()
        self.evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ]
        self.raw = self.supersede(self.root, self.evidence)
        self.data = parse(self.raw)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(self.data), self.raw)

    def test_top_and_payload_key_sets(self):
        self.assertEqual(set(self.data.keys()), {"payload", "signature"})
        self.assertEqual(
            set(self.data["payload"].keys()),
            {"rootDigest", "predecessorDigest", "height", "certificates",
             "common", "commonDigest", "planDigest", "items", "status",
             "evidence", "oldPolicyDigest", "newPolicyDigest",
             "policyVersion", "effectiveAt", "issuer", "keyVersion",
             "version"},
        )

    def test_link_and_policy_bindings(self):
        payload = self.data["payload"]
        self.assertEqual(
            payload["rootDigest"],
            hashlib.sha256(self.root).hexdigest(),
        )
        self.assertEqual(
            payload["predecessorDigest"],
            hashlib.sha256(self.root).hexdigest(),
        )
        self.assertEqual(payload["height"], 1)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(payload["effectiveAt"], EFFECTIVE_MOMENT)
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        policy_digest = hashlib.sha256(
            compact({
                "sites": {site: [1] for site in (ALPHA, COORD, GAMMA)},
                "threshold": 2,
                "policyVersion": 1,
            })
        ).hexdigest()
        self.assertEqual(payload["oldPolicyDigest"], policy_digest)
        self.assertEqual(payload["newPolicyDigest"], policy_digest)

    def test_evidence_rides_as_lowercase_hex_bytes(self):
        evidence = self.data["payload"]["evidence"]
        self.assertEqual([item["id"] for item in evidence], ["c", "a"])
        self.assertEqual(
            bytes.fromhex(evidence[0]["certificate"]), self.cert_coord
        )
        self.assertEqual(
            bytes.fromhex(evidence[0]["rounds"][0]["confirmation"]),
            self.rounds[0]["confirmation"],
        )
        self.assertEqual(evidence[0]["rounds"][0]["seq"], 1)
        self.assertIsNone(evidence[0]["rounds"][0]["previous"])

    def test_recomputed_verdict_aggregates_are_bound(self):
        payload = self.data["payload"]
        self.assertEqual(
            payload["certificates"],
            [hashlib.sha256(self.cert_coord).hexdigest(),
             hashlib.sha256(self.cert_alpha).hexdigest()],
        )
        self.assertEqual(
            [(row["site"], row["id"]) for row in payload["items"]],
            [(ALPHA, "a"), (COORD, "c")],
        )
        self.assertEqual(payload["planDigest"], payload["common"]["planDigest"])
        self.assertEqual(
            payload["commonDigest"],
            hashlib.sha256(compact(payload["common"])).hexdigest(),
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
        evidence = copy.deepcopy(self.evidence)
        snapshot = copy.deepcopy(
            (self.root, evidence, self.decision, self.pol,
             self.policy_v1, self.policy_v1, RING)
        )
        self.supersede(self.root, evidence)
        self.assertEqual(
            (self.root, evidence, self.decision, self.pol,
             self.policy_v1, self.policy_v1, RING),
            snapshot,
        )


class VerdictTransitionTest(SupersedeFixtures, unittest.TestCase):
    def test_supplemental_evidence_moves_insufficient_to_accepted(self):
        root = self.insufficient_root()
        successor = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ])
        payload = parse(successor)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertIsNotNone(payload["common"])

    def test_accepted_keeps_the_identical_common_result(self):
        root = self.accepted_root()
        successor = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ])
        root_common = parse(root)["payload"]["common"]
        payload = parse(successor)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["common"], root_common)

    def test_accepted_advances_to_conflicted(self):
        root = self.accepted_root()
        successor = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            copy.deepcopy(self.item_coord_conflict),
        ])
        self.assertEqual(parse(successor)["payload"]["status"], "conflicted")

    def test_conflicted_is_never_masked_by_a_later_majority(self):
        root = self.accepted_root()
        conflicted = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            copy.deepcopy(self.item_coord_conflict),
        ])
        # A third distinct site agreeing on the original result cannot
        # outvote the persistent self-contradiction in the prefix: the
        # recomputed verdict stays conflicted on every later hop.
        still = self.supersede(conflicted, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            copy.deepcopy(self.item_coord_conflict),
            copy.deepcopy(self.item_gamma),
        ])
        self.assertEqual(parse(still)["payload"]["status"], "conflicted")
        result = self.verify_chain(root, [conflicted, still], [
            self.policy_v1, self.policy_v1, self.policy_v1,
        ])
        self.assertEqual(result["status"], "conflicted")

    def test_a_changed_common_result_becomes_conflicted_not_swapped(self):
        root = self.accepted_root()
        original_common = parse(root)["payload"]["common"]
        # Alpha attesting a different beta post-state is a cross-site
        # disagreement: the verdict upgrades to conflicted rather than
        # silently swapping the accepted common result.
        other_alpha = certify_fork_convergence(
            self.rounds_conflict, self.decision, self.pol, RING,
            CERTIFIED_AT, ALPHA, 1,
        )
        successor = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(other_alpha, "a2", self.rounds_conflict),
        ])
        payload = parse(successor)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertNotEqual(payload["common"], original_common)
        self.assertIsNone(payload["common"])


class EvidencePrefixTest(SupersedeFixtures, unittest.TestCase):
    def test_first_hop_must_keep_root_certificates_in_order(self):
        root = self.insufficient_root()
        with self.assertRaises(InvalidChainError):
            self.supersede(root, [copy.deepcopy(self.item_alpha)])
        with self.assertRaises(InvalidChainError):
            self.supersede(root, [
                copy.deepcopy(self.item_alpha),
                copy.deepcopy(self.item_coord),
            ])

    def test_later_hop_prefix_must_not_be_deleted_or_reordered(self):
        root = self.insufficient_root()
        first = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ])
        with self.assertRaises(InvalidChainError):
            self.supersede(first, [copy.deepcopy(self.item_coord)])
        with self.assertRaises(InvalidChainError):
            self.supersede(first, [
                copy.deepcopy(self.item_alpha),
                copy.deepcopy(self.item_coord),
                self.item(self.cert_coord_2, "c2"),
            ])

    def test_unchanged_policy_must_add_an_item(self):
        root = self.accepted_root()
        with self.assertRaises(InvalidChainError):
            self.supersede(root, [
                copy.deepcopy(self.item_coord),
                copy.deepcopy(self.item_alpha),
            ])

    def test_history_is_append_only_across_hops(self):
        root, successors, policies = self.accepted_chain()
        result = self.verify_chain(root, successors, policies)
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["status"], "accepted")


class PolicyRotationTest(SupersedeFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.root = self.accepted_root()
        self.evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ]

    def test_unchanged_policy_keeps_its_version(self):
        successor = self.supersede(
            self.root, self.evidence, self.policy_v1, self.policy_v1
        )
        self.assertEqual(
            parse(successor)["payload"]["policyVersion"], 1
        )

    def test_changed_threshold_increments_the_version_by_one(self):
        rotated = versioned_policy((COORD, ALPHA, GAMMA), 1, 2)
        successor = self.supersede(
            self.root, self.evidence, self.policy_v1, rotated
        )
        payload = parse(successor)["payload"]
        self.assertEqual(payload["policyVersion"], 2)
        self.assertNotEqual(
            payload["oldPolicyDigest"], payload["newPolicyDigest"]
        )

    def test_a_version_jump_or_held_version_on_change_is_invalid(self):
        jumped = versioned_policy((COORD, ALPHA, GAMMA), 1, 3)
        with self.assertRaises(InvalidChainError):
            self.supersede(self.root, self.evidence, self.policy_v1, jumped)
        held = versioned_policy((COORD, ALPHA, GAMMA), 1, 1)
        with self.assertRaises(InvalidChainError):
            self.supersede(self.root, self.evidence, self.policy_v1, held)

    def test_old_policy_must_match_the_predecessor_policy(self):
        rotated = versioned_policy((COORD, ALPHA, GAMMA), 1, 2)
        successor = self.supersede(
            self.root, self.evidence, self.policy_v1, rotated
        )
        mismatched = versioned_policy((COORD, ALPHA, GAMMA), 1, 4)
        with self.assertRaises(InvalidChainError):
            self.supersede(successor, self.evidence, self.policy_v1,
                           mismatched)

    def test_rotation_may_reseal_the_same_evidence_sequence(self):
        rotated = versioned_policy((COORD, ALPHA, GAMMA), 1, 2)
        same_evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ]
        root = self.accepted_root()
        successor = self.supersede(root, same_evidence, self.policy_v1,
                                   rotated)
        result = self.verify_chain(
            root, [successor], [self.policy_v1, rotated]
        )
        self.assertEqual(result["policyVersion"], 2)

    def test_the_sealer_must_be_authorized_under_both_policies(self):
        removes_coord = versioned_policy((ALPHA, GAMMA), 2, 2)
        with self.assertRaises(InvalidChainError):
            self.supersede(self.root, self.evidence, self.policy_v1,
                           removes_coord)
        only_version_two = versioned_policy((COORD, ALPHA, GAMMA), 1, 2)
        only_version_two = {
            "sites": {COORD: {2}, ALPHA: {1}, GAMMA: {1}},
            "threshold": 1,
            "policyVersion": 2,
        }
        with self.assertRaises(InvalidChainError):
            self.supersede(self.root, self.evidence, self.policy_v1,
                           only_version_two)

    def test_effective_moment_must_not_move_backwards(self):
        successor = self.supersede(
            self.root, self.evidence, effective=EFFECTIVE_MOMENT
        )
        with self.assertRaises(ValueError):
            self.supersede(
                successor,
                self.evidence + [self.item(self.cert_coord_3, "c3")],
                effective=EFFECTIVE_MOMENT - 1,
            )


class SupersedeUpfrontValidationTest(SupersedeFixtures, unittest.TestCase):
    def test_argument_type_faults(self):
        evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ]
        root = self.insufficient_root()
        with self.assertRaises(TypeError):
            self.supersede("x", evidence)
        with self.assertRaises(TypeError):
            supersede_decision(
                root, evidence, "x", self.pol, self.policy_v1,
                self.policy_v1, RING, SIGN_MOMENT, EFFECTIVE_MOMENT, COORD, 1,
            )
        with self.assertRaises(TypeError):
            self.supersede(root, evidence, moment=True)
        with self.assertRaises(TypeError):
            self.supersede(root, evidence, effective=True)
        with self.assertRaises(TypeError):
            self.supersede(root, evidence, issuer=7)
        with self.assertRaises(TypeError):
            self.supersede(root, evidence, version=True)

    def test_value_faults(self):
        root = self.insufficient_root()
        with self.assertRaises(ValueError):
            self.supersede(root, [])
        with self.assertRaises(ValueError):
            self.supersede(root, [
                copy.deepcopy(self.item_coord),
                copy.deepcopy(self.item_coord),
            ])
        with self.assertRaises(ValueError):
            self.supersede(root, [copy.deepcopy(self.item_coord)],
                           issuer="")
        with self.assertRaises(ValueError):
            self.supersede(root, [copy.deepcopy(self.item_coord)],
                           version=0)
        with self.assertRaises(ValueError):
            self.supersede(root, [copy.deepcopy(self.item_coord)],
                           effective=-1)
        bad_policy = dict(self.policy_v1, policyVersion=0)
        with self.assertRaises(ValueError):
            self.supersede(root, [
                copy.deepcopy(self.item_coord),
                copy.deepcopy(self.item_alpha),
            ], old_policy=bad_policy, new_policy=bad_policy)

    def test_nested_round_faults_preempt_the_whole_batch(self):
        root = self.insufficient_root()
        broken = copy.deepcopy(self.item_coord)
        broken["rounds"] = [{"seq": True, "previous": None,
                             "confirmation": self.rounds[0]["confirmation"]}]
        with self.assertRaises(TypeError):
            self.supersede(root, [broken, copy.deepcopy(self.item_alpha)])


class CredentialTest(SupersedeFixtures, unittest.TestCase):
    def _sealer_setup(self):
        # DELTA seals the successor but signs no evidence, so revoking
        # its key changes the credential check without re-tallying the
        # verdict.  The root is accepted under a policy listing DELTA.
        from test_fork_convergence import DELTA
        site_policy = {
            "sites": {COORD: {1}, ALPHA: {1}, GAMMA: {1}, DELTA: {1}},
            "threshold": 2,
        }
        root = adjudicate_convergence(
            [copy.deepcopy(self.item_coord), copy.deepcopy(self.item_alpha)],
            self.decision, self.pol, site_policy, RING, 280, COORD, 1,
        )
        policy = versioned_policy((COORD, ALPHA, GAMMA, DELTA), 2, 1)
        evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ]
        return DELTA, root, policy, evidence

    def test_unauthorized_identity_is_a_chain_fault(self):
        delta, root, policy, evidence = self._sealer_setup()
        # An identity the policies do not authorize is a chain fault;
        # the key is never looked up.
        with self.assertRaises(InvalidChainError):
            self.supersede(root, evidence, old_policy=policy,
                           new_policy=policy, issuer="nobody")

    def test_unknown_or_revoked_sealer_raises_authentication_error(self):
        from test_fork_convergence import SECRET_DELTA, entry
        delta, root, policy, evidence = self._sealer_setup()
        # An authorized identity missing from the keyring is a
        # credential fault.
        missing = {name: entries for name, entries in RING.items()
                   if name != delta}
        with self.assertRaises(AuthenticationError):
            self.supersede(root, evidence, old_policy=policy,
                           new_policy=policy, ring=missing, issuer=delta)
        revoked = {**RING, delta: [entry(1, SECRET_DELTA, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            self.supersede(root, evidence, old_policy=policy,
                           new_policy=policy, ring=revoked, issuer=delta)

    def test_sealer_must_be_usable_at_the_effective_moment(self):
        from test_fork_convergence import SECRET_DELTA, entry
        delta, root, policy, evidence = self._sealer_setup()
        future_key = {
            **RING,
            delta: [entry(1, SECRET_DELTA, not_before=EFFECTIVE_MOMENT + 1)],
        }
        with self.assertRaises(AuthenticationError):
            self.supersede(root, evidence, old_policy=policy,
                           new_policy=policy, ring=future_key, issuer=delta)

    def test_a_revoked_credential_at_verify_time_is_unauthenticated(self):
        from test_fork_convergence import SECRET_COORD as SC, entry
        root, successors, policies = self.accepted_chain()
        revoked = {**RING, COORD: [entry(1, SC, revoked=True)]}
        report = self.verify_chains([
            self.chain_item("x", root, successors, policies)
        ], ring=revoked)
        self.assertEqual(report["items"][0]["status"], "unauthenticated")


class VerifyDecisionChainTest(SupersedeFixtures, unittest.TestCase):
    def test_bare_root_has_height_zero(self):
        root = self.insufficient_root()
        result = self.verify_chain(root, [], [self.policy_v1])
        self.assertEqual(
            set(result.keys()),
            {"rootDigest", "headDigest", "height", "policyVersion", "status"},
        )
        self.assertEqual(result["rootDigest"], result["headDigest"])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "insufficient")

    def test_multi_hop_chain_summary(self):
        root, successors, policies = self.accepted_chain()
        result = self.verify_chain(root, successors, policies)
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(
            result["headDigest"], hashlib.sha256(successors[-1]).hexdigest()
        )

    def test_result_is_a_fresh_mapping(self):
        root, successors, policies = self.accepted_chain()
        first = self.verify_chain(root, successors, policies)
        second = self.verify_chain(root, successors, policies)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["status"] = "tampered"
        self.assertEqual(
            self.verify_chain(root, successors, policies)["status"],
            "accepted",
        )

    def test_bad_root_raises_convergence_decision_error(self):
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify_chain(b"{}", [], [self.policy_v1])

    def test_bad_successor_raises_chain_error(self):
        root = self.insufficient_root()
        with self.assertRaises(InvalidChainError):
            self.verify_chain(root, [b"{}"], [self.policy_v1, self.policy_v1])

    def test_policy_sequence_length_must_match_the_stages(self):
        root, successors, _policies = self.accepted_chain()
        with self.assertRaises(ValueError):
            self.verify_chain(root, successors, [self.policy_v1])

    def test_root_stage_policy_must_be_version_one(self):
        root = self.insufficient_root()
        wrong = versioned_policy((COORD, ALPHA, GAMMA), 2, 2)
        with self.assertRaises(ValueError):
            self.verify_chain(root, [], [wrong])

    def test_each_tampered_binding_is_rejected(self):
        root = self.insufficient_root()
        successor = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ])

        def resign(field, value):
            data = parse(successor)
            data["payload"][field] = value
            data["signature"] = hmac.new(
                bytes.fromhex(SECRET_COORD), compact(data["payload"]),
                hashlib.sha256,
            ).hexdigest()
            return compact(data)

        for field, value in (
            ("rootDigest", "ab" * 32),
            ("predecessorDigest", "ab" * 32),
            ("height", 9),
            ("policyVersion", 9),
            ("status", "insufficient"),
            ("effectiveAt", 1),
        ):
            with self.assertRaises(InvalidChainError, msg=field):
                self.verify_chain(
                    root, [resign(field, value)],
                    [self.policy_v1, self.policy_v1],
                )

    def test_wrong_signature_is_authentication_error(self):
        root = self.insufficient_root()
        successor = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ])
        data = parse(successor)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.verify_chain(
                root, [compact(data)], [self.policy_v1, self.policy_v1]
            )


class VerifyDecisionChainsBatchTest(SupersedeFixtures, unittest.TestCase):
    def test_batch_container_type_faults(self):
        root = self.insufficient_root()
        with self.assertRaises(TypeError):
            self.verify_chains("x")
        with self.assertRaises(TypeError):
            self.verify_chains([{"id": 1, "roots": root, "successors": [],
                                 "policies": [self.policy_v1]}])
        with self.assertRaises(TypeError):
            self.verify_chains([{"id": "x", "roots": "y", "successors": [],
                                 "policies": [self.policy_v1]}])
        with self.assertRaises(TypeError):
            self.verify_chains([{"id": "x", "roots": root, "successors": [1],
                                 "policies": [self.policy_v1]}])

    def test_batch_value_faults(self):
        root = self.insufficient_root()
        good = {"id": "x", "roots": root, "successors": [],
                "policies": [self.policy_v1]}
        with self.assertRaises(ValueError):
            self.verify_chains([])
        with self.assertRaises(ValueError):
            self.verify_chains([dict(good, id="")])
        with self.assertRaises(ValueError):
            self.verify_chains([good, dict(good)])
        with self.assertRaises(ValueError):
            self.verify_chains([dict(good, policies=[])])
        with self.assertRaises(ValueError):
            self.verify_chains([{"id": "x", "roots": root,
                                  "successors": []}])

    def test_reports_in_input_order_with_isolation(self):
        root, successors, policies = self.accepted_chain()
        report = self.verify_chains([
            self.chain_item("ok", root, successors, policies),
            {"id": "bad", "roots": b"{}", "successors": [],
             "policies": [self.policy_v1]},
            {"id": "ok2", "roots": root, "successors": [b"{}"],
             "policies": [self.policy_v1, self.policy_v1]},
        ])
        self.assertEqual(
            [item["id"] for item in report["items"]],
            ["ok", "bad", "ok2"],
        )
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(
            statuses, {"ok": "verified", "bad": "invalid", "ok2": "invalid"}
        )

    def test_report_shape_and_version(self):
        root = self.insufficient_root()
        report = self.verify_chains([
            self.chain_item("x", root, [], [self.policy_v1])
        ])
        self.assertEqual(set(report.keys()), {"items", "version"})
        self.assertEqual(report["version"], 1)
        item = report["items"][0]
        self.assertEqual(list(item.keys()), ["error", "id", "result", "status"])
        self.assertIsNone(item["error"])
        self.assertIsNotNone(item["result"])

    def test_prefix_extension_is_not_a_fork(self):
        root = self.insufficient_root()
        first = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ])
        second = self.supersede(first, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ])
        report = self.verify_chains([
            self.chain_item("long", root, [first, second],
                            [self.policy_v1] * 3),
            self.chain_item("short", root, [first],
                            [self.policy_v1] * 2),
        ])
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses, {"long": "verified", "short": "verified"})

    def test_one_predecessor_with_distinct_successors_is_a_fork(self):
        root = self.insufficient_root()
        first = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ])
        branch_a = self.supersede(first, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ], effective=EFFECTIVE_MOMENT + 4)
        branch_b = self.supersede(first, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_3, "c3"),
        ], effective=EFFECTIVE_MOMENT + 5)
        report = self.verify_chains([
            self.chain_item("A", root, [first, branch_a],
                            [self.policy_v1] * 3),
            self.chain_item("B", root, [first, branch_b],
                            [self.policy_v1] * 3),
        ])
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses, {"A": "conflicted", "B": "conflicted"})
        # The verified results are retained on a conflicted chain.
        for item in report["items"]:
            self.assertIsNotNone(item["result"])
            self.assertTrue(item["error"])

    def test_repeated_calls_are_independent(self):
        root, successors, policies = self.accepted_chain()
        items = [self.chain_item("x", root, successors, policies)]
        first = self.verify_chains(items)
        second = self.verify_chains(items)
        self.assertEqual(first, second)
        self.assertIsNot(
            first["items"][0]["result"], second["items"][0]["result"]
        )
        first["items"][0]["result"]["status"] = "tampered"
        self.assertEqual(
            self.verify_chains(items)["items"][0]["result"]["status"],
            "accepted",
        )


class DecisionHeadAnchorTest(SupersedeFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.root, self.successors, self.policies = self.accepted_chain()
        self.items = [self.chain_item(
            "x", self.root, self.successors, self.policies
        )]
        self.anchor = seal_decision_head(
            self.items, "x", self.decision, self.pol, RING, SIGN_MOMENT,
            COORD, 1,
        )

    def test_seal_and_reverify_an_accepted_head(self):
        self.assertTrue(self.anchor.endswith(b"}"))
        result = verify_decision_head(
            self.anchor, self.items, "x", self.decision, self.pol, RING,
            VERIFY_MOMENT,
        )
        self.assertEqual(
            set(result.keys()),
            {"rootDigest", "headDigest", "height", "policyDigest",
             "policyVersion", "anchorDigest"},
        )
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(
            result["anchorDigest"],
            hashlib.sha256(self.anchor).hexdigest(),
        )

    def test_anchor_only_seals_a_verified_accepted_target(self):
        insufficient = self.insufficient_root()
        items = [self.chain_item(
            "z", insufficient, [], [self.policy_v1]
        )]
        with self.assertRaises(ValueError):
            seal_decision_head(
                items, "z", self.decision, self.pol, RING, SIGN_MOMENT,
                COORD, 1,
            )
        # A forked target is conflicted and cannot be anchored.
        first = self.supersede(self.insufficient_root(), [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ])
        branch_a = self.supersede(first, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ], effective=EFFECTIVE_MOMENT + 4)
        branch_b = self.supersede(first, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_3, "c3"),
        ], effective=EFFECTIVE_MOMENT + 5)
        forked = [
            self.chain_item("A", self.insufficient_root(), [first, branch_a],
                            [self.policy_v1] * 3),
            self.chain_item("B", self.insufficient_root(), [first, branch_b],
                            [self.policy_v1] * 3),
        ]
        with self.assertRaises(ValueError):
            seal_decision_head(
                forked, "A", self.decision, self.pol, RING, SIGN_MOMENT,
                COORD, 1,
            )

    def test_unknown_target_is_a_value_error(self):
        with self.assertRaises(ValueError):
            seal_decision_head(
                self.items, "missing", self.decision, self.pol, RING,
                SIGN_MOMENT, COORD, 1,
            )
        with self.assertRaises(ValueError):
            verify_decision_head(
                self.anchor, self.items, "missing", self.decision, self.pol,
                RING, VERIFY_MOMENT,
            )

    def test_tampered_anchor_is_invalid(self):
        # A structural key-set/encoding fault is an InvalidAnchorError
        # even before the HMAC is consulted.
        data = parse(self.anchor)
        del data["payload"]["height"]
        with self.assertRaises(InvalidAnchorError):
            verify_decision_head(
                compact(data), self.items, "x", self.decision, self.pol,
                RING, VERIFY_MOMENT,
            )
        with self.assertRaises(InvalidAnchorError):
            verify_decision_head(
                self.anchor + b"\n", self.items, "x", self.decision,
                self.pol, RING, VERIFY_MOMENT,
            )

    def test_a_rebound_anchor_value_is_an_authentication_error(self):
        # Changing a bound value while keeping the old signature fails
        # the HMAC check rather than the structural check.
        data = parse(self.anchor)
        data["payload"]["height"] = 9
        with self.assertRaises(AuthenticationError):
            verify_decision_head(
                compact(data), self.items, "x", self.decision, self.pol,
                RING, VERIFY_MOMENT,
            )

    def test_wrong_anchor_signature_is_authentication_error(self):
        data = parse(self.anchor)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            verify_decision_head(
                compact(data), self.items, "x", self.decision, self.pol,
                RING, VERIFY_MOMENT,
            )

    def test_current_credential_state_is_checked(self):
        from test_fork_convergence import SECRET_COORD as SC, entry
        revoked = {**RING, COORD: [entry(1, SC, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            verify_decision_head(
                self.anchor, self.items, "x", self.decision, self.pol,
                revoked, VERIFY_MOMENT,
            )

    def test_a_moved_head_no_longer_matches_the_anchor(self):
        # Extending the chain moves the head digest and height.
        moved_successor = self.supersede(self.successors[-1], [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
            self.item(self.cert_coord_3, "c3"),
            self.item(certify_fork_convergence(
                self.rounds, self.decision, self.pol, RING, 273, COORD, 1
            ), "c4"),
        ], effective=EFFECTIVE_MOMENT + 8)
        moved_items = [self.chain_item(
            "x", self.root, self.successors + [moved_successor],
            self.policies + [self.policy_v1],
        )]
        with self.assertRaises(InvalidAnchorError):
            verify_decision_head(
                self.anchor, moved_items, "x", self.decision, self.pol,
                RING, VERIFY_MOMENT,
            )

    def test_inputs_are_not_modified(self):
        items = copy.deepcopy(self.items)
        snapshot = copy.deepcopy(
            (self.anchor, items, self.decision, self.pol, RING)
        )
        verify_decision_head(
            self.anchor, items, "x", self.decision, self.pol, RING,
            VERIFY_MOMENT,
        )
        self.assertEqual(
            (self.anchor, items, self.decision, self.pol, RING), snapshot
        )


if __name__ == "__main__":
    unittest.main()
