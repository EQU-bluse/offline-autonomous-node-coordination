"""Tests for convergence decision supersession chains.

Covers :func:`supersede_decision`, :func:`verify_decision_chain`,
:func:`verify_decision_chains`, :func:`seal_decision_head` and
:func:`verify_decision_head`: the predecessor dispatch (root decision
or previous successor), the versioned chain policy and its history
rules, the evidence prefix and delta bindings, the per-hop decision
recomputation with its monotone status relation, the dual-policy
issuer authorization and credential usability, the canonical signed
successor packet and every bound field, the single-chain and batch
verification with isolated input-order reports, successor fork
detection (prefix extensions excepted), and the sealed head anchor
with its batch-bound re-verification.
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
    certify_fork_convergence,
    seal_decision_head,
    supersede_decision,
    verify_decision_chain,
    verify_decision_chains,
    verify_decision_head,
)

from test_adjudicate_convergence import (
    AdjudicationFixtures,
    site_policy,
)
from test_fork_convergence import (
    ALPHA,
    CERTIFIED_AT,
    COORD,
    DELTA,
    GAMMA,
    RING,
    SECRET_COORD,
    compact,
    parse,
)

HOP_ONE_MOMENT = 290
HOP_TWO_MOMENT = 295
SEAL_MOMENT = 300
VERIFY_CHAIN_MOMENT = 310


def chain_policy(sites=None, threshold=2, version=1):
    policy = site_policy(sites, threshold)
    policy["version"] = version
    return policy


def canonical_chain_policy(sites=None, threshold=2, version=1):
    if sites is None:
        sites = (COORD, ALPHA, GAMMA)
    return {
        "sites": {site: [1] for site in sorted(sites)},
        "threshold": threshold,
        "version": version,
    }


class ChainFixtures(AdjudicationFixtures):
    """Shared root decision, evidence items and chain policy builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.cp1 = chain_policy(version=1)
        self.cert_gamma = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, CERTIFIED_AT,
            GAMMA, 1,
        )
        self.root_items = [
            self.item(self.cert_coord, "c"),
            self.item(self.cert_alpha, "a"),
        ]
        self.root = self.adjudicate(self.root_items)
        self.full_items = self.root_items + [self.item(self.cert_gamma, "g")]

    def supersede(self, predecessor=None, items=None, previous=None,
                  new=None, moment=HOP_ONE_MOMENT, issuer=COORD, version=1):
        return supersede_decision(
            self.root if predecessor is None else predecessor,
            self.full_items if items is None else items,
            self.decision, self.pol,
            self.cp1 if previous is None else previous,
            self.cp1 if new is None else new,
            RING, moment, issuer, version,
        )

    def verify_chain(self, root=None, successors=(), policies=None,
                     ring=RING, moment=VERIFY_CHAIN_MOMENT, decision=None):
        return verify_decision_chain(
            self.root if root is None else root,
            list(successors),
            [self.cp1] * (len(successors) + 1) if policies is None
            else policies,
            decision or self.decision, ring, moment,
        )

    def verify_batch(self, items, ring=RING, moment=VERIFY_CHAIN_MOMENT,
                     decision=None):
        return verify_decision_chains(
            items, decision or self.decision, ring, moment
        )

    def chain_item(self, item_id, root=None, successors=(), policies=None):
        return {
            "id": item_id,
            "root": self.root if root is None else root,
            "successors": list(successors),
            "policies": [self.cp1] * (len(successors) + 1)
            if policies is None else policies,
        }


class SuccessorPacketTest(ChainFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.supersede()
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
            {"decision", "evidenceDelta", "height", "issuer", "keyVersion",
             "moment", "policyDigest", "predecessorDigest",
             "previousPolicyDigest", "rootDigest", "version"},
        )

    def test_chain_bindings(self):
        payload = self.data["payload"]
        root_digest = hashlib.sha256(self.root).hexdigest()
        self.assertEqual(payload["rootDigest"], root_digest)
        self.assertEqual(payload["predecessorDigest"], root_digest)
        self.assertEqual(payload["height"], 1)
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], HOP_ONE_MOMENT)
        self.assertEqual(payload["version"], 1)
        self.assertIsInstance(payload["version"], int)
        self.assertNotIsInstance(payload["version"], bool)
        expected_policy_digest = hashlib.sha256(
            compact(canonical_chain_policy())
        ).hexdigest()
        self.assertEqual(payload["policyDigest"], expected_policy_digest)
        self.assertEqual(
            payload["previousPolicyDigest"], expected_policy_digest
        )

    def test_evidence_delta_and_embedded_decision(self):
        payload = self.data["payload"]
        self.assertEqual(
            payload["evidenceDelta"],
            [hashlib.sha256(self.cert_gamma).hexdigest()],
        )
        embedded = compact(payload["decision"])
        decision_payload = parse(embedded)["payload"]
        self.assertEqual(
            decision_payload["certificates"],
            [hashlib.sha256(item["certificate"]).hexdigest()
             for item in self.full_items],
        )
        self.assertEqual(decision_payload["status"], "accepted")
        self.assertEqual(
            decision_payload["decisionDigest"],
            hashlib.sha256(self.decision).hexdigest(),
        )

    def test_signature_is_the_payload_hmac(self):
        payload = self.data["payload"]
        self.assertEqual(
            self.data["signature"],
            hmac.new(
                bytes.fromhex(SECRET_COORD), compact(payload),
                hashlib.sha256,
            ).hexdigest(),
        )

    def test_second_hop_binds_the_first_as_predecessor(self):
        first = self.supersede()
        second = self.supersede(
            predecessor=first, moment=HOP_TWO_MOMENT
        )
        payload = parse(second)["payload"]
        self.assertEqual(payload["height"], 2)
        self.assertEqual(
            payload["predecessorDigest"], hashlib.sha256(first).hexdigest()
        )
        self.assertEqual(
            payload["rootDigest"], hashlib.sha256(self.root).hexdigest()
        )
        # No new evidence: the delta is empty.
        self.assertEqual(payload["evidenceDelta"], [])

    def test_inputs_are_not_modified(self):
        items = copy.deepcopy(self.full_items)
        snapshot = copy.deepcopy(
            (items, self.root, self.decision, self.pol, self.cp1, RING)
        )
        self.supersede(items=items)
        self.assertEqual(
            (items, self.root, self.decision, self.pol, self.cp1, RING),
            snapshot,
        )


class SupersedeSemanticsTest(ChainFixtures, unittest.TestCase):
    def test_insufficient_advances_to_accepted_with_more_evidence(self):
        root = self.adjudicate([self.item(self.cert_coord, "c")])
        self.assertEqual(parse(root)["payload"]["status"], "insufficient")
        succ = self.supersede(predecessor=root)
        result = self.verify_chain(root=root, successors=[succ])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["height"], 1)

    def test_accepted_escalates_to_conflicted(self):
        conflicting, rounds = self.reshape_cert(GAMMA)
        items = self.full_items + [
            self.item(conflicting, "g2", rounds=rounds)
        ]
        succ = self.supersede(items=items)
        result = self.verify_chain(successors=[succ])
        self.assertEqual(result["status"], "conflicted")

    def test_conflicted_stays_conflicted(self):
        conflicting, rounds = self.reshape_cert(ALPHA)
        root = self.adjudicate([
            self.item(self.cert_coord, "c"),
            self.item(conflicting, "a", rounds=rounds),
        ])
        self.assertEqual(parse(root)["payload"]["status"], "conflicted")
        items = [
            self.item(self.cert_coord, "c"),
            self.item(conflicting, "a", rounds=rounds),
            self.item(self.cert_alpha, "a2"),
            self.item(self.cert_gamma, "g"),
        ]
        succ = self.supersede(predecessor=root, items=items)
        result = self.verify_chain(root=root, successors=[succ])
        self.assertEqual(result["status"], "conflicted")

    def test_accepted_must_not_regress_to_insufficient(self):
        rotated = chain_policy(threshold=3, version=2)
        with self.assertRaises(ValueError):
            self.supersede(items=self.root_items, new=rotated)

    def test_policy_rotation_keeps_root_plan_and_settled_operations(self):
        rotated = chain_policy(threshold=3, version=2)
        succ = self.supersede(new=rotated, previous=self.cp1)
        result = self.verify_chain(
            successors=[succ], policies=[self.cp1, rotated]
        )
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["policyVersion"], 2)
        common = parse(succ)["payload"]["decision"]["payload"]["common"]
        self.assertEqual(common, parse(self.root)["payload"]["common"])

    def test_policy_content_change_must_increment_version_by_one(self):
        with self.assertRaises(ValueError):
            self.supersede(new=chain_policy(threshold=3, version=1))
        with self.assertRaises(ValueError):
            self.supersede(new=chain_policy(threshold=3, version=3))
        with self.assertRaises(ValueError):
            # Unchanged content must keep the version.
            self.supersede(new=chain_policy(version=2))

    def test_unchanged_policy_keeps_version(self):
        succ = self.supersede(new=chain_policy(version=1))
        payload = parse(succ)["payload"]
        self.assertEqual(
            payload["policyDigest"], payload["previousPolicyDigest"]
        )

    def test_issuer_must_be_authorized_by_both_policies(self):
        with self.assertRaises(ValueError):
            self.supersede(issuer=DELTA)
        narrowed = chain_policy(sites=(COORD, ALPHA), threshold=2, version=2)
        with self.assertRaises(ValueError):
            self.supersede(new=narrowed, issuer=GAMMA)

    def test_moment_must_not_regress(self):
        first = self.supersede(moment=HOP_TWO_MOMENT)
        with self.assertRaises(ValueError):
            self.supersede(predecessor=first, moment=HOP_ONE_MOMENT)

    def test_evidence_sequence_must_extend_the_predecessor(self):
        reordered = [
            self.item(self.cert_gamma, "g"),
            self.item(self.cert_coord, "c"),
            self.item(self.cert_alpha, "a"),
        ]
        with self.assertRaises(ValueError):
            self.supersede(items=reordered)
        shortened = [self.item(self.cert_coord, "c")]
        with self.assertRaises(ValueError):
            self.supersede(items=shortened)

    def test_batch_precheck_classification(self):
        with self.assertRaises(TypeError):
            self.supersede(predecessor="not-bytes")
        with self.assertRaises(TypeError):
            self.supersede(items="not-a-list")
        with self.assertRaises(ValueError):
            self.supersede(items=[])
        with self.assertRaises(ValueError):
            self.supersede(items=[self.item(self.cert_coord, "c"),
                                  self.item(self.cert_alpha, "c")])
        with self.assertRaises(TypeError):
            self.supersede(moment=True)
        with self.assertRaises(ValueError):
            self.supersede(moment=-1)
        with self.assertRaises(TypeError):
            self.supersede(new={"sites": site_policy()["sites"],
                                "threshold": 2, "version": True})
        with self.assertRaises(ValueError):
            self.supersede(new=chain_policy(version=0))
        with self.assertRaises(ValueError):
            self.supersede(new={"sites": site_policy()["sites"],
                                "threshold": 2})
        with self.assertRaises(TypeError):
            self.supersede(version=True)
        with self.assertRaises(ValueError):
            self.supersede(version=0)
        with self.assertRaises(ValueError):
            self.supersede(issuer="")

    def test_bad_root_raises_decision_error(self):
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.supersede(predecessor=b"{}")
        other = self.adjudicate([self.item(self.cert_coord, "c")])
        with self.assertRaises(InvalidConvergenceDecisionError):
            # The root policy must match the offered previous policy.
            self.supersede(
                predecessor=other,
                previous=chain_policy(threshold=1, version=1),
                new=chain_policy(threshold=1, version=1),
                items=self.full_items,
            )

    def test_bad_predecessor_successor_raises_chain_error(self):
        first = self.supersede()
        with self.assertRaises(InvalidChainError):
            # The offered previous policy is not the one the
            # predecessor binds.
            self.supersede(
                predecessor=first,
                previous=chain_policy(version=2),
                new=chain_policy(version=2),
            )
        with self.assertRaises(InvalidChainError):
            self.supersede(predecessor=b'{"payload":{"rootDigest":'
                                       b'"' + b"0" * 64 + b'"},'
                                       b'"signature":"' + b"0" * 64
                                       + b'"}')

    def test_predecessor_signature_is_checked(self):
        first = parse(self.supersede())
        first["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.supersede(predecessor=compact(first),
                           moment=HOP_TWO_MOMENT)


class VerifyChainTest(ChainFixtures, unittest.TestCase):
    def test_empty_chain_verifies_the_root_alone(self):
        result = self.verify_chain()
        self.assertEqual(result["height"], 0)
        self.assertEqual(
            result["rootDigest"], hashlib.sha256(self.root).hexdigest()
        )
        self.assertEqual(result["headDigest"], result["rootDigest"])
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["version"], 1)
        self.assertEqual(
            list(result.keys()),
            ["height", "headDigest", "policyVersion", "rootDigest",
             "status", "version"],
        )

    def test_multi_hop_chain(self):
        rotated = chain_policy(threshold=3, version=2)
        first = self.supersede()
        second = self.supersede(
            predecessor=first, new=rotated, moment=HOP_TWO_MOMENT
        )
        result = self.verify_chain(
            successors=[first, second], policies=[self.cp1, self.cp1,
                                                  rotated]
        )
        self.assertEqual(result["height"], 2)
        self.assertEqual(
            result["headDigest"], hashlib.sha256(second).hexdigest()
        )
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["status"], "accepted")

    def test_repeated_calls_return_independent_equal_results(self):
        first = self.supersede()
        one = self.verify_chain(successors=[first])
        two = self.verify_chain(successors=[first])
        self.assertEqual(one, two)
        self.assertIsNot(one, two)

    def test_argument_validation(self):
        with self.assertRaises(TypeError):
            self.verify_chain(root="not-bytes")
        with self.assertRaises(TypeError):
            self.verify_chain(successors="not-a-list")
        with self.assertRaises(TypeError):
            self.verify_chain(successors=["not-bytes"])
        with self.assertRaises(ValueError):
            self.verify_chain(policies=[])
        with self.assertRaises(ValueError):
            self.verify_chain(successors=[self.supersede()],
                              policies=[self.cp1])
        with self.assertRaises(ValueError):
            self.verify_chain(policies=[self.cp1, self.cp1])
        with self.assertRaises(TypeError):
            self.verify_chain(moment=True)
        with self.assertRaises(ValueError):
            self.verify_chain(moment=-1)

    def test_bad_root_raises_decision_error(self):
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify_chain(root=b"{}")

    def test_successor_faults_raise_chain_error(self):
        first = self.supersede()
        second = self.supersede(predecessor=first, moment=HOP_TWO_MOMENT)
        with self.assertRaises(InvalidChainError):
            self.verify_chain(successors=[b"{}"])
        with self.assertRaises(InvalidChainError):
            # Out of order: the second hop does not chain to the root.
            self.verify_chain(
                successors=[second, first],
                policies=[self.cp1, self.cp1, self.cp1],
            )
        with self.assertRaises(InvalidChainError):
            # A skipped version step breaks the policy history.
            self.verify_chain(
                successors=[first],
                policies=[self.cp1, chain_policy(threshold=3, version=1)],
            )
        tampered = parse(first)
        tampered["payload"]["height"] = 7
        tampered["signature"] = hmac.new(
            bytes.fromhex(SECRET_COORD), compact(tampered["payload"]),
            hashlib.sha256,
        ).hexdigest()
        with self.assertRaises(InvalidChainError):
            self.verify_chain(successors=[compact(tampered)])

    def test_hop_moment_must_not_exceed_the_verification_moment(self):
        first = self.supersede(moment=HOP_TWO_MOMENT)
        with self.assertRaises(InvalidChainError):
            self.verify_chain(successors=[first], moment=HOP_ONE_MOMENT)

    def test_signature_and_credential_faults(self):
        first = self.supersede()
        tampered = parse(first)
        tampered["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.verify_chain(successors=[compact(tampered)])
        ring = {site: keys for site, keys in RING.items() if site != COORD}
        with self.assertRaises(AuthenticationError):
            self.verify_chain(successors=[first], ring=ring)


class VerifyChainsBatchTest(ChainFixtures, unittest.TestCase):
    def test_batch_precheck(self):
        with self.assertRaises(TypeError):
            self.verify_batch("not-a-list")
        with self.assertRaises(ValueError):
            self.verify_batch([])
        with self.assertRaises(ValueError):
            self.verify_batch([self.chain_item("x"), self.chain_item("x")])
        with self.assertRaises(ValueError):
            self.verify_batch([{"id": "x", "root": self.root,
                                "successors": []}])
        with self.assertRaises(TypeError):
            self.verify_batch([self.chain_item(1)])
        with self.assertRaises(ValueError):
            self.verify_batch([self.chain_item("")])
        with self.assertRaises(TypeError):
            self.verify_batch([self.chain_item("x", root="not-bytes")])
        with self.assertRaises(TypeError):
            self.verify_batch([self.chain_item("x", successors="no")])
        with self.assertRaises(ValueError):
            self.verify_batch([self.chain_item("x", policies=[])])

    def test_isolated_input_order_reports(self):
        good = self.supersede()
        items = [
            self.chain_item("bad", root=b"{}"),
            self.chain_item("good", successors=[good]),
            self.chain_item("root-only"),
        ]
        report = self.verify_batch(items)
        self.assertEqual(set(report.keys()), {"forks", "items", "version"})
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [item["id"] for item in report["items"]],
            ["bad", "good", "root-only"],
        )
        bad, good_report, root_only = report["items"]
        self.assertEqual(bad["status"], "invalid")
        self.assertTrue(bad["error"])
        self.assertIsNone(bad["result"])
        self.assertEqual(
            list(bad.keys()), ["error", "id", "result", "status"]
        )
        self.assertEqual(good_report["status"], "verified")
        self.assertIsNone(good_report["error"])
        self.assertEqual(good_report["result"]["height"], 1)
        self.assertEqual(root_only["status"], "verified")
        self.assertEqual(root_only["result"]["height"], 0)

    def test_unauthenticated_item(self):
        good = self.supersede()
        ring = {site: keys for site, keys in RING.items() if site != COORD}
        report = self.verify_batch(
            [self.chain_item("x", successors=[good])], ring=ring
        )
        (item,) = report["items"]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertTrue(item["error"])
        self.assertIsNone(item["result"])

    def test_fork_between_two_successors_of_one_predecessor(self):
        first = self.supersede(moment=HOP_ONE_MOMENT)
        rival = self.supersede(moment=HOP_TWO_MOMENT)
        items = [
            self.chain_item("a", successors=[first]),
            self.chain_item("b", successors=[rival]),
        ]
        report = self.verify_batch(items)
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["conflicted", "conflicted"],
        )
        for item in report["items"]:
            self.assertEqual(item["error"], "forked-chain")
            self.assertIsNotNone(item["result"])
        (fork,) = report["forks"]
        self.assertEqual(
            set(fork.keys()),
            {"ids", "predecessor", "rootDigest", "successors"},
        )
        self.assertEqual(
            fork["predecessor"], hashlib.sha256(self.root).hexdigest()
        )
        self.assertEqual(
            fork["rootDigest"], hashlib.sha256(self.root).hexdigest()
        )
        self.assertEqual(
            fork["successors"],
            sorted(hashlib.sha256(packet).hexdigest()
                   for packet in (first, rival)),
        )
        self.assertEqual(fork["ids"], ["a", "b"])

    def test_prefix_extension_is_not_a_fork(self):
        first = self.supersede()
        second = self.supersede(predecessor=first, moment=HOP_TWO_MOMENT)
        items = [
            self.chain_item("short", successors=[first]),
            self.chain_item("long", successors=[first, second]),
        ]
        report = self.verify_batch(items)
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["verified", "verified"],
        )

    def test_chains_under_different_roots_are_never_compared(self):
        other_root = self.adjudicate([self.item(self.cert_coord, "c")])
        other_succ = self.supersede(predecessor=other_root)
        own_succ = self.supersede()
        items = [
            self.chain_item("one", successors=[own_succ]),
            self.chain_item("two", root=other_root,
                            successors=[other_succ]),
        ]
        report = self.verify_batch(items)
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["verified", "verified"],
        )

    def test_repeated_calls_return_independent_results(self):
        items = [self.chain_item("x", successors=[self.supersede()])]
        one = self.verify_batch(items)
        two = self.verify_batch(items)
        self.assertEqual(one, two)
        self.assertIsNot(one, two)
        self.assertIsNot(one["items"][0]["result"],
                         two["items"][0]["result"])


class SealHeadTest(ChainFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.succ = self.supersede()
        self.items = [self.chain_item("x", successors=[self.succ])]
        self.anchor = seal_decision_head(
            self.items, self.decision, RING, SEAL_MOMENT, COORD, 1, "x"
        )

    def test_anchor_packet_shape_and_bindings(self):
        data = parse(self.anchor)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        payload = data["payload"]
        self.assertEqual(
            set(payload.keys()),
            {"headDigest", "height", "issuer", "keyVersion", "moment",
             "policyDigest", "policyVersion", "rootDigest", "version"},
        )
        self.assertEqual(
            payload["headDigest"], hashlib.sha256(self.succ).hexdigest()
        )
        self.assertEqual(
            payload["rootDigest"], hashlib.sha256(self.root).hexdigest()
        )
        self.assertEqual(payload["height"], 1)
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], SEAL_MOMENT)
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(
                compact(canonical_chain_policy())
            ).hexdigest(),
        )
        self.assertEqual(
            data["signature"],
            hmac.new(
                bytes.fromhex(SECRET_COORD), compact(payload),
                hashlib.sha256,
            ).hexdigest(),
        )
        self.assertEqual(compact(data), self.anchor)

    def test_verify_head_returns_the_bound_fields(self):
        result = verify_decision_head(
            self.anchor, self.items, self.decision, RING,
            VERIFY_CHAIN_MOMENT,
        )
        self.assertEqual(
            result,
            {
                "headDigest": hashlib.sha256(self.succ).hexdigest(),
                "height": 1,
                "issuer": COORD,
                "keyVersion": 1,
                "moment": SEAL_MOMENT,
                "policyDigest": hashlib.sha256(
                    compact(canonical_chain_policy())
                ).hexdigest(),
                "policyVersion": 1,
                "rootDigest": hashlib.sha256(self.root).hexdigest(),
                "status": "accepted",
                "version": 1,
            },
        )

    def test_seal_requires_a_verified_accepted_fork_free_target(self):
        with self.assertRaises(ValueError):
            seal_decision_head(
                self.items, self.decision, RING, SEAL_MOMENT, COORD, 1,
                "unknown",
            )
        insufficient_root = self.adjudicate([self.item(self.cert_coord,
                                                       "c")])
        insufficient = [self.chain_item("s", root=insufficient_root)]
        with self.assertRaises(ValueError):
            seal_decision_head(
                insufficient, self.decision, RING, SEAL_MOMENT, COORD, 1,
                "s",
            )
        rival = self.supersede(moment=HOP_TWO_MOMENT)
        forked = [
            self.chain_item("a", successors=[self.succ]),
            self.chain_item("b", successors=[rival]),
        ]
        with self.assertRaises(ValueError):
            seal_decision_head(
                forked, self.decision, RING, SEAL_MOMENT, COORD, 1, "a"
            )
        invalid = [self.chain_item("i", root=b"{}")]
        with self.assertRaises(ValueError):
            seal_decision_head(
                invalid, self.decision, RING, SEAL_MOMENT, COORD, 1, "i"
            )

    def test_seal_argument_validation(self):
        with self.assertRaises(TypeError):
            seal_decision_head(
                self.items, self.decision, RING, True, COORD, 1, "x"
            )
        with self.assertRaises(ValueError):
            seal_decision_head(
                self.items, self.decision, RING, SEAL_MOMENT, "", 1, "x"
            )
        with self.assertRaises(ValueError):
            seal_decision_head(
                self.items, self.decision, RING, SEAL_MOMENT, COORD, 0,
                "x",
            )
        with self.assertRaises(TypeError):
            seal_decision_head(
                self.items, self.decision, RING, SEAL_MOMENT, COORD, 1, 7
            )
        with self.assertRaises(ValueError):
            seal_decision_head(
                self.items, self.decision, RING, SEAL_MOMENT, COORD, 1, ""
            )

    def test_verify_head_anchor_faults(self):
        with self.assertRaises(TypeError):
            verify_decision_head(
                "not-bytes", self.items, self.decision, RING,
                VERIFY_CHAIN_MOMENT,
            )
        with self.assertRaises(InvalidAnchorError):
            verify_decision_head(
                b"{}", self.items, self.decision, RING,
                VERIFY_CHAIN_MOMENT,
            )
        with self.assertRaises(InvalidAnchorError):
            # The anchor moment must not lie in the future.
            verify_decision_head(
                self.anchor, self.items, self.decision, RING,
                SEAL_MOMENT - 1,
            )

    def test_verify_head_requires_the_original_batch(self):
        other_root = self.adjudicate([self.item(self.cert_coord, "c")])
        other_items = [self.chain_item("y", root=other_root)]
        with self.assertRaises(InvalidAnchorError):
            verify_decision_head(
                self.anchor, other_items, self.decision, RING,
                VERIFY_CHAIN_MOMENT,
            )
        tampered = parse(self.anchor)
        tampered["payload"]["height"] = 2
        tampered["signature"] = hmac.new(
            bytes.fromhex(SECRET_COORD), compact(tampered["payload"]),
            hashlib.sha256,
        ).hexdigest()
        with self.assertRaises(InvalidAnchorError):
            verify_decision_head(
                compact(tampered), self.items, self.decision, RING,
                VERIFY_CHAIN_MOMENT,
            )

    def test_verify_head_authentication(self):
        tampered = parse(self.anchor)
        tampered["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            verify_decision_head(
                compact(tampered), self.items, self.decision, RING,
                VERIFY_CHAIN_MOMENT,
            )
        # The anchor issuer's own credential is checked against the
        # current keyring; seal with a second identity so the batch
        # itself still verifies.
        anchor = seal_decision_head(
            self.items, self.decision, RING, SEAL_MOMENT, ALPHA, 1, "x"
        )
        ring = {site: keys for site, keys in RING.items() if site != ALPHA}
        with self.assertRaises(AuthenticationError):
            verify_decision_head(
                anchor, self.items, self.decision, ring,
                VERIFY_CHAIN_MOMENT,
            )

    def test_seal_and_verify_do_not_modify_inputs(self):
        items = copy.deepcopy(self.items)
        snapshot = copy.deepcopy(items)
        anchor = seal_decision_head(
            items, self.decision, RING, SEAL_MOMENT, COORD, 1, "x"
        )
        verify_decision_head(
            anchor, items, self.decision, RING, VERIFY_CHAIN_MOMENT
        )
        self.assertEqual(items, snapshot)


if __name__ == "__main__":
    unittest.main()
