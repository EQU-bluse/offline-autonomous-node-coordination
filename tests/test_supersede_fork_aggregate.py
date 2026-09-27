"""Tests for supersession chains over cross-site fork decision aggregates.

Covers :func:`supersede_fork_aggregate`,
:func:`verify_fork_aggregate_chain`, :func:`verify_fork_aggregate_chains`,
:func:`seal_fork_aggregate_head` and :func:`verify_fork_aggregate_head`:
the canonical signed successor packet and every binding (root,
predecessor, height, the full recomputed conclusion, the raw decision
increment as hex, the invariant prune and fork-proof site policy
digests, the old/new decision policy digests, policy version and
effective moment), the per-hop verdict state machine (insufficient to
accepted/conflicted, accepted only kept or upgraded, conflicted never
masked), the append-only decision prefix with unchanged-policy growth
and rotation-only re-sealing, versioned decision site policy rotation
with a single policyVersion step, dual-policy sealer authorization and
credential usability at both moments, offline hop-by-hop verification,
bare-root verification, the fresh chain summary with the common
declaration digest, batch verification with cross-chain successor fork
detection and the conflicted reclassification, the stable head anchor
seal/reverify rules, and every error classification (including a bool
never posing as an int), input immutability and the purely offline
guarantee.
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
    InvalidAggregateForkDecisionAggregateError,
    InvalidForkAggregateChainError,
    aggregate_prune_fork_decisions,
    seal_fork_aggregate_head,
    supersede_fork_aggregate,
    verify_fork_aggregate_chain,
    verify_fork_aggregate_chains,
    verify_fork_aggregate_head,
)

from test_aggregate_prune_fork_decisions import (
    ForkDecisionAggregateFixtures,
    decision_item,
)
from test_adjudicate_prune_aggregate_forks import proof_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C

JUDGE_B = SITE_C

PACKET_KEYS = ["payload", "signature"]
SUCCESSOR_PAYLOAD_KEYS = [
    "decisions", "declaration", "effectiveAt", "height", "inputs",
    "issuer", "items", "keyVersion", "newPolicyDigest", "oldPolicyDigest",
    "policyVersion", "predecessorDigest", "prunePolicyDigest", "rootDigest",
    "sitePolicyDigest", "status", "version",
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


def vpol(policy_version=1, sites=(JUDGE, JUDGE_B), threshold=2):
    """A versioned decision site policy: sites, threshold, policyVersion."""
    return {
        "sites": {site: {1} for site in sites},
        "threshold": threshold,
        "policyVersion": policy_version,
    }


def plain(policy):
    """Strip the version from a versioned decision site policy (root form)."""
    return {"sites": copy.deepcopy(policy["sites"]),
            "threshold": policy["threshold"]}


def rewrap(payload, secret=SECRET_COORD):
    """Re-sign an envelope payload into canonical compact packet bytes."""
    signature = hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


def chain_item(item_id, root, successors, policies):
    """One batch item: a unique id, a root, successors and policies."""
    return {"id": item_id, "root": root, "successors": successors,
            "policies": policies}


class ForkAggregateChainFixtures(ForkDecisionAggregateFixtures,
                                unittest.TestCase):
    """Shared roots, decisions, policies and chain builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.pv1 = vpol()
        self.pv2_t1 = vpol(2, threshold=1)
        self.pv1_3 = vpol(1, sites=(JUDGE, SITE_A, SITE_B), threshold=2)

        # An agreeing decision over the same fork edge set, each distinct
        # only in its issuing decision site.
        agreeing_proofs = [
            proof_item("x", self.proof(issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]
        self.decision_sa = self.make_decision(agreeing_proofs, issuer=SITE_A)
        self.decision_sb = self.make_decision(agreeing_proofs, issuer=SITE_B)
        # A distinct decision from SITE_A over a different fork edge set.
        other_proofs = [
            proof_item("x", self.proof(self.items_two, issuer=SITE_A)),
            proof_item("y", self.proof(issuer=SITE_B)),
        ]
        self.decision_c = self.make_decision(other_proofs, issuer=SITE_A)

        # Roots: one site (insufficient), two agreeing (accepted) and
        # two disagreeing sites (conflicted under a three-site policy).
        self.root_one = self.make_aggregate(
            [decision_item("one", self.decision_a)])
        self.root_two = self.make_aggregate(self.decision_items())
        self.root_conf = aggregate_prune_fork_decisions(
            [decision_item("a", self.decision_a),
             decision_item("c", self.decision_c)],
            self.policy, self.sp, plain(self.pv1_3),
            self.ring, self.m, JUDGE, 1,
        )

    def fsucc(self, predecessor, increment, old=None, new=None,
             moment=None, effective=None, issuer=JUDGE, version=1,
             site_policy=None):
        return supersede_fork_aggregate(
            predecessor, increment,
            self.policy, self.sp if site_policy is None else site_policy,
            self.pv1 if old is None else old,
            self.pv1 if new is None else new,
            self.ring,
            self.m + 10 if moment is None else moment,
            self.m if effective is None else effective,
            issuer, version,
        )

    def fvchain(self, root, successors, policies=None, moment=None,
               site_policy=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        if moment is None:
            moment = self.m + 10 * max(1, len(successors))
        return verify_fork_aggregate_chain(
            root, successors, self.policy,
            self.sp if site_policy is None else site_policy,
            policies, self.ring, moment,
        )

    def fcitem(self, item_id, root, successors, policies=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        return chain_item(item_id, root, successors, policies)

    def fvchains(self, items, moment=None, site_policy=None, ring=None):
        return verify_fork_aggregate_chains(
            items, self.policy,
            self.sp if site_policy is None else site_policy,
            self.ring if ring is None else ring,
            self.m + 20 if moment is None else moment,
        )


class SuccessorShapeTest(ForkAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.fsucc(
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


class BareRootVerifyTest(ForkAggregateChainFixtures):
    def test_bare_root_verified_in_full(self):
        result = self.fvchain(self.root_two, [])
        self.assertEqual(list(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.root_two).hexdigest())
        self.assertEqual(result["headDigest"], result["rootDigest"])
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["commonDigest"])

    def test_conflicted_bare_root_common_digest_is_null(self):
        result = self.fvchain(self.root_conf, [], policies=[self.pv1_3])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])

    def test_result_is_depth_independent_and_fresh(self):
        first = self.fvchain(self.root_two, [])
        second = self.fvchain(self.root_two, [])
        self.assertEqual(first, second)
        self.assertIsNot(first, second)


class GrowthAndStateMachineTest(ForkAggregateChainFixtures):
    def test_insufficient_grows_to_accepted(self):
        raw = self.fsucc(
            self.root_one, [decision_item("two", self.decision_b)])
        result = self.fvchain(self.root_one, [raw])
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["commonDigest"])

    def test_insufficient_stays_insufficient_below_threshold(self):
        # An appended decision that cannot authenticate adds no valid
        # distinct site, so the tally stays insufficient but keeps the
        # one common declaration.
        raw = self.fsucc(
            self.root_one, [decision_item("two", b"{}")])
        result = self.fvchain(self.root_one, [raw])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["commonDigest"])

    def test_conflicted_can_never_be_masked(self):
        raw = self.fsucc(
            self.root_conf,
            [decision_item("s", self.decision_sb)],
            old=self.pv1_3, new=self.pv1_3,
        )
        self.assertEqual(parse(raw)["payload"]["status"], "conflicted")
        result = self.fvchain(
            self.root_conf, [raw], policies=[self.pv1_3, self.pv1_3])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["commonDigest"])

    def test_accepted_may_advance_to_conflicted(self):
        rotated = vpol(2, sites=(JUDGE, JUDGE_B, SITE_A), threshold=2)
        raw = self.fsucc(
            self.root_two, [decision_item("c", self.decision_c)],
            old=self.pv1, new=rotated,
        )
        self.assertEqual(parse(raw)["payload"]["status"], "conflicted")
        self.assertEqual(
            self.fvchain(self.root_two, [raw],
                         policies=[self.pv1, rotated])["status"],
            "conflicted")

    def test_accepted_keeps_identical_declaration_under_rotation(self):
        raw = self.fsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(
            payload["declaration"],
            parse(self.root_two)["payload"]["declaration"])


class AppendOnlyTest(ForkAggregateChainFixtures):
    def test_unchanged_policy_requires_non_empty_increment(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.root_two, [], old=self.pv1, new=self.pv1)

    def test_repeated_packet_digest_rejected(self):
        # decision_a is already the root's one/decision.
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(
                self.root_one,
                [decision_item("nine", self.decision_a)])

    def test_repeated_item_id_rejected(self):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(
                self.root_one,
                [decision_item("one", self.decision_b)])

    def test_rotation_may_reseal_empty_sequence(self):
        raw = self.fsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1)
        self.assertEqual(parse(raw)["payload"]["decisions"], [])
        self.assertEqual(
            self.fvchain(self.root_two, [raw],
                        policies=[self.pv1, self.pv2_t1])["status"],
            "accepted")


class PolicyVersionTest(ForkAggregateChainFixtures):
    def test_first_policy_must_match_root_and_carry_version_one(self):
        bad = vpol(1, sites=(JUDGE,), threshold=1)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.root_two, [], old=bad, new=self.pv2_t1)

    def test_changed_content_must_step_by_exactly_one(self):
        jump = vpol(3, threshold=1)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.root_two, [], old=self.pv1, new=jump)

    def test_unchanged_content_must_keep_version(self):
        mismatch = vpol(2)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.root_two, [], old=self.pv1, new=mismatch)

    def test_old_policy_must_equal_predecessor_policy(self):
        first = self.fsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(first, [decision_item("c", self.decision_c)],
                      old=self.pv1, new=self.pv2_t1)


class AuthorizationAndMomentTest(ForkAggregateChainFixtures):
    def test_sealer_must_be_authorized_under_both_policies(self):
        # Rotation drops JUDGE from the new policy; JUDGE_B is sealer
        # but JUDGE_B cannot seal under the root policy sealer name...
        drop = vpol(2, sites=(JUDGE_B,), threshold=1)
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fsucc(self.root_two, [], old=self.pv1, new=drop,
                      issuer=JUDGE)

    def test_credential_must_be_usable_at_both_moments(self):
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, SECRET_COORD, not_after=self.m + 5)]
        with self.assertRaises(AuthenticationError):
            supersede_fork_aggregate(
                self.root_one,
                [decision_item("two", self.decision_b)],
                self.policy, self.sp, self.pv1, self.pv1,
                ring, self.m + 10, self.m, JUDGE, 1)

    def test_effective_moment_must_not_move_backwards(self):
        first = self.fsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1,
            effective=self.m + 5)
        with self.assertRaises(ValueError):
            self.fsucc(
                first, [decision_item("c", self.decision_c)],
                old=self.pv2_t1, new=self.pv2_t1,
                effective=self.m + 4, moment=self.m + 10)

    def test_unknown_sealer_is_authentication_error(self):
        # JUDGE is authorized by both policies but absent from the
        # keyring, so authorization passes while credential lookup fails.
        ring = {site: self.ring[site]
                for site in self.ring if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            supersede_fork_aggregate(
                self.root_two, [], self.policy, self.sp,
                self.pv1, self.pv2_t1, ring, self.m + 10, self.m, JUDGE, 1)


class ChainBindingTest(ForkAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.fsucc(
            self.root_one, [decision_item("two", self.decision_b)])

    def assert_chain_invalid(self, raw):
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fvchain(self.root_one, [raw])

    def test_tampered_height_binding(self):
        payload = parse(self.raw)["payload"]
        payload["height"] = 2
        self.assert_chain_invalid(rewrap(payload))

    def test_tampered_root_binding(self):
        payload = parse(self.raw)["payload"]
        payload["rootDigest"] = "0" * 64
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

    def test_wrong_policy_history_count(self):
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [self.raw], self.policy, self.sp,
                [self.pv1], self.ring, self.m + 10)

    def test_root_stage_policy_must_be_version_one(self):
        # Same sites/threshold as the root, but policyVersion 2 first.
        first = vpol(2)
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_one, [self.raw], self.policy, self.sp,
                [first, first], self.ring, self.m + 10)

    def test_bad_signature_is_authentication_error(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        raw = compact(data)
        with self.assertRaises(AuthenticationError):
            self.fvchain(self.root_one, [raw])

    def test_bad_root_raises_root_error(self):
        with self.assertRaises(InvalidAggregateForkDecisionAggregateError):
            self.fvchain(b"{}", [])

    def test_non_canonical_encoding_rejected(self):
        text = self.raw.decode("utf-8")
        pretty = json.dumps(parse(self.raw), indent=2)
        self.assert_chain_invalid(pretty.encode())
        self.assert_chain_invalid((text + "\n").encode())


class PublicArgumentTypeTest(ForkAggregateChainFixtures):
    def test_supersede_type_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.fsucc(self.root_two, "x")
        with self.assertRaises(TypeError):
            self.fsucc(self.root_two, [decision_item(1, self.decision_b)])
        with self.assertRaises(TypeError):
            self.fsucc(
                self.root_two,
                [{"id": "x", "decision": 1}])
        with self.assertRaises(ValueError):
            self.fsucc(self.root_two, [decision_item("", self.decision_b)])
        with self.assertRaises(TypeError):
            supersede_fork_aggregate(
                self.root_two, [], self.policy, self.sp, self.pv1, self.pv2_t1,
                self.ring, True, self.m, JUDGE, 1)
        with self.assertRaises(ValueError):
            supersede_fork_aggregate(
                self.root_two, [], self.policy, self.sp, self.pv1, self.pv2_t1,
                self.ring, -1, self.m, JUDGE, 1)
        with self.assertRaises(TypeError):
            self.fsucc(self.root_two, [], issuer=7)
        with self.assertRaises(ValueError):
            self.fsucc(self.root_two, [], issuer="")
        with self.assertRaises(TypeError):
            self.fsucc(self.root_two, [], version=True)
        with self.assertRaises(ValueError):
            self.fsucc(self.root_two, [], version=0)

    def test_verify_argument_faults(self):
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                "x", [], self.policy, self.sp, [self.pv1], self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                self.root_two, "x", self.policy, self.sp, [self.pv1],
                self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                self.root_two, ["x"],
                self.policy, self.sp, [self.pv1, self.pv1],
                self.ring, self.m)
        with self.assertRaises(ValueError):
            verify_fork_aggregate_chain(
                self.root_two, [], self.policy, self.sp, [],
                self.ring, self.m)
        with self.assertRaises(TypeError):
            verify_fork_aggregate_chain(
                self.root_two, [], self.policy, self.sp, [self.pv1],
                self.ring, True)


class ChainBatchTest(ForkAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.first_a = self.fsucc(
            self.root_one, [decision_item("two", self.decision_b)])
        # A genuinely different first successor: a pure policy rotation.
        self.first_b = self.fsucc(
            self.root_one, [], old=self.pv1, new=self.pv2_t1)
        # A plain one-hop extension of first_a (prefix, not a fork): a
        # new decision digest not already in the prefix; it is not
        # authorized by pv1, so the accepted verdict is simply kept.
        self.second_a = self.fsucc(
            self.first_a,
            [decision_item("three", self.decision_sa)],
            old=self.pv1, new=self.pv1,
            moment=self.m + 20, effective=self.m + 5)

    def test_batch_validated_upfront(self):
        with self.assertRaises(TypeError):
            self.fvchains("x")
        with self.assertRaises(ValueError):
            self.fvchains([])
        with self.assertRaises(ValueError):
            self.fvchains([
                self.fcitem("a", self.root_one, [self.first_a]),
                self.fcitem("a", self.root_one, [self.first_a]),
            ])
        with self.assertRaises(ValueError):
            self.fvchains([
                {"id": "a", "root": self.root_one,
                 "successors": [self.first_a], "policies": [self.pv1]},
            ])
        with self.assertRaises(TypeError):
            self.fvchains([self.fcitem(1, self.root_one, [self.first_a])])

    def test_verified_report_in_input_order(self):
        report = self.fvchains([
            self.fcitem("a", self.root_one, [self.first_a]),
            self.fcitem("bad", b"{}", []),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual([r["id"] for r in report["items"]], ["a", "bad"])
        self.assertEqual([r["status"] for r in report["items"]],
                         ["verified", "invalid-root"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), REPORT_KEYS)

    def test_invalid_chain_is_isolated_from_unauthenticated(self):
        # Tampered successor (sealed by JUDGE) -> invalid-chain.
        payload = parse(self.first_a)["payload"]
        payload["height"] = 9
        tampered = rewrap(payload)
        # A rotation-only successor (empty increment, so the verdict is
        # unaffected by the missing key) sealed by JUDGE_B; a ring lacking
        # JUDGE_B still verifies the JUDGE-signed root and the unchanged
        # verdict, but cannot authenticate the successor HMAC.
        noauth_succ = self.fsucc(
            self.root_two, [], old=self.pv1, new=self.pv2_t1,
            issuer=JUDGE_B)
        ring = {site: self.ring[site] for site in self.ring
                if site != JUDGE_B}
        report = self.fvchains([
            self.fcitem("bad", self.root_one, [tampered]),
            self.fcitem("noauth", self.root_two, [noauth_succ],
                        policies=[self.pv1, self.pv2_t1]),
        ], ring=ring)
        statuses = {r["id"]: r["status"] for r in report["items"]}
        self.assertEqual(statuses["bad"], "invalid-chain")
        self.assertEqual(statuses["noauth"], "unauthenticated")
        for row in report["items"]:
            self.assertTrue(row["error"])
            self.assertIsNone(row["result"])

    def test_same_predecessor_two_successors_is_a_fork(self):
        report = self.fvchains([
            self.fcitem("b", self.root_one, [self.first_b],
                       policies=[self.pv1, self.pv2_t1]),
            self.fcitem("a", self.root_one, [self.first_a]),
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
                self.assertEqual(row["error"],
                                 "forked-fork-aggregate-chain")
                self.assertIsNotNone(row["result"])

    def test_prefix_extension_is_not_a_fork(self):
        report = self.fvchains([
            self.fcitem("short", self.root_one, [self.first_a]),
            self.fcitem("long", self.root_one,
                       [self.first_a, self.second_a],
                       policies=[self.pv1, self.pv1, self.pv1]),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]], ["verified", "verified"])

    def test_conflicted_chain_keeps_verified_result(self):
        report = self.fvchains([
            self.fcitem("a", self.root_one, [self.first_a]),
            self.fcitem("b", self.root_one, [self.first_b],
                       policies=[self.pv1, self.pv2_t1]),
        ])
        row = report["items"][0]
        self.assertEqual(row["result"]["status"], "accepted")
        self.assertEqual(row["result"]["height"], 1)

    def test_different_roots_are_never_compared(self):
        # Two roots that each have one successor never fork against each
        # other even though the "predecessor" (height-0) role repeats.
        report = self.fvchains([
            self.fcitem("a", self.root_one, [self.first_a]),
            self.fcitem("b", self.root_two, []),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]], ["verified", "verified"])


class AnchorTest(ForkAggregateChainFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.first = self.fsucc(
            self.root_one, [decision_item("two", self.decision_b)])
        self.items = [self.fcitem("t", self.root_one, [self.first])]

    def fseal(self, items=None, target="t", moment=None, issuer=JUDGE,
             version=1):
        return seal_fork_aggregate_head(
            self.items if items is None else items, target,
            self.policy, self.sp, self.ring,
            self.m + 20 if moment is None else moment, issuer, version)

    def fverify(self, anchor, items=None, target="t", moment=None):
        return verify_fork_aggregate_head(
            anchor, self.items if items is None else items, target,
            self.policy, self.sp, self.ring,
            self.m + 20 if moment is None else moment)

    def test_seal_and_verify_accepted_unforked_head(self):
        anchor = self.fseal()
        self.assertEqual(list(parse(anchor).keys()), PACKET_KEYS)
        self.assertEqual(list(parse(anchor)["payload"].keys()),
                         ANCHOR_PAYLOAD_KEYS)
        result = self.fverify(anchor)
        self.assertEqual(list(result.keys()), ANCHOR_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(self.first).hexdigest())
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["anchorDigest"],
                         hashlib.sha256(anchor).hexdigest())

    def test_conflicted_or_invalid_target_is_not_sealable(self):
        other = self.fsucc(
            self.root_one, [], old=self.pv1, new=self.pv2_t1)
        items = [
            self.fcitem("t", self.root_one, [self.first]),
            self.fcitem("f", self.root_one, [other],
                       policies=[self.pv1, self.pv2_t1]),
        ]
        with self.assertRaises(ValueError):
            self.fseal(items=items, target="t")
        with self.assertRaises(ValueError):
            self.fseal(items=items, target="f")
        with self.assertRaises(ValueError):
            self.fseal(items=items, target="missing")

    def test_insufficient_head_is_not_sealable(self):
        items = [self.fcitem("t", self.root_one, [])]
        with self.assertRaises(ValueError):
            self.fseal(items=items)

    def test_bare_root_accepted_head_can_be_anchored(self):
        items = [self.fcitem("t", self.root_two, [])]
        anchor = seal_fork_aggregate_head(
            items, "t", self.policy, self.sp, self.ring, self.m + 20,
            JUDGE, 1)
        result = verify_fork_aggregate_head(
            anchor, items, "t", self.policy, self.sp, self.ring, self.m + 20)
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(self.root_two).hexdigest())

    def test_tampered_anchor_binding_rejected(self):
        anchor = self.fseal()
        payload = parse(anchor)["payload"]
        payload["height"] = 2
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fverify(rewrap(payload))

    def test_anchor_signature_checked_against_current_key(self):
        anchor = self.fseal()
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            verify_fork_aggregate_head(
                anchor, self.items, "t", self.policy, self.sp, ring,
                self.m + 20)

    def test_anchor_rejected_when_chain_later_forks(self):
        anchor = self.fseal()
        other = self.fsucc(
            self.root_one, [], old=self.pv1, new=self.pv2_t1)
        items = [
            self.fcitem("t", self.root_one, [self.first]),
            self.fcitem("f", self.root_one, [other],
                       policies=[self.pv1, self.pv2_t1]),
        ]
        with self.assertRaises(InvalidForkAggregateChainError):
            self.fverify(anchor, items=items)

    def test_anchor_type_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.fseal(target=7)
        with self.assertRaises(ValueError):
            self.fseal(target="")
        with self.assertRaises(TypeError):
            self.fseal(version=True)
        with self.assertRaises(ValueError):
            self.fseal(version=0)


class ImmutabilityAndOfflineTest(ForkAggregateChainFixtures):
    def test_inputs_are_not_modified(self):
        increment = [decision_item("two", self.decision_b)]
        snapshot = copy.deepcopy(
            (increment, self.policy, self.sp, self.pv1, self.ring))
        self.fsucc(self.root_one, increment)
        self.assertEqual(
            (increment, self.policy, self.sp, self.pv1, self.ring), snapshot)

    def test_batch_inputs_are_not_modified(self):
        items = [self.fcitem("a", self.root_two, [])]
        snapshot = copy.deepcopy((items, self.policy, self.sp, self.ring))
        self.fvchains(items)
        self.assertEqual((items, self.policy, self.sp, self.ring), snapshot)

    def test_repeated_batch_results_are_independent(self):
        items = [self.fcitem("a", self.root_two, [])]
        first = self.fvchains(items)
        second = self.fvchains(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0], second["items"][0])


if __name__ == "__main__":
    unittest.main()
