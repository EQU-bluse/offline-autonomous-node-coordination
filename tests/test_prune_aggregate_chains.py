"""Tests for batch verification of prune aggregate chains and fork proofs.

Covers :func:`verify_prune_aggregate_chains`,
:func:`sign_prune_aggregate_fork_proof` and
:func:`verify_prune_aggregate_fork_proof`: the batch container and
shared materials validated in full before any chain is verified, the
per-chain verified/invalid-root/invalid-chain/unauthenticated taxonomy
with input-order reports and no cross-chain interference, fork
detection grouped by the aggregate root digest (the same predecessor
digest pointing at two distinct successor digests, prefix extensions
excluded), the conflicted reclassification keeping the verified result
with the fixed ``forked-aggregate-chain`` error, the sorted fork
entries with ascending successor digests and crossing ids, the signed
fork proof binding the prune policy digest, the original-order chain
material digests, the complete report, the signing moment and the
exact issuer/key version, offline proof re-verification recomputing
the forks, digests and ordering from the bound materials alone, the
InvalidAggregateForkProofError hierarchy, equal-but-independent
results, input immutability and the purely offline guarantee.
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
    InvalidAggregateChainError,
    InvalidAggregateForkProofError,
    InvalidPruneBatchAggregateError,
    sign_prune_aggregate_fork_proof,
    verify_prune_aggregate_chains,
    verify_prune_aggregate_fork_proof,
)

from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import BATCH, JUDGE, SITE_A, hmac_hex, sha256
from test_supersede_prune_aggregate import (
    PruneAggregateChainFixtures,
    pitem,
    policy_canon,
    vpol,
)

REPORT_KEYS = ["error", "id", "result", "status"]
BATCH_REPORT_KEYS = ["forks", "items", "version"]
FORK_KEYS = ["rootDigest", "predecessorDigest", "successors", "ids"]
CHAIN_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "commonDigest",
]
PROOF_KEYS = ["payload", "signature"]
PROOF_PAYLOAD_KEYS = [
    "chains", "issuer", "keyVersion", "moment", "policy", "report",
    "version",
]
PROOF_CHAIN_KEYS = ["id", "policies", "root", "successors"]
PROOF_RESULT_KEYS = [
    "chains", "issuer", "keyVersion", "moment", "policyDigest",
    "proofDigest", "report", "version",
]


def chain_item(item_id, root, successors, policies):
    """One batch item: a unique id, a root, successors and policies."""
    return {
        "id": item_id,
        "root": root,
        "successors": successors,
        "policies": policies,
    }


class PruneAggregateChainBatchFixtures(PruneAggregateChainFixtures):
    """Chains over one shared root, plus batch and proof helpers."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Two distinct valid first successors over the same root.
        self.first_a = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        self.first_b = self.succ(self.root_one, [pitem("four", self.pkt_c)])
        self.first_c = self.succ(
            self.root_one, [pitem("five", self.pkt_b_other)]
        )
        # Two distinct valid second successors over one shared first hop.
        self.second_a = self.succ(
            self.first_a, [pitem("four", self.pkt_c)],
            moment=self.moment + 20, effective=self.moment + 5,
        )
        self.second_b = self.succ(
            self.first_a, [pitem("five", self.pkt_b_other)],
            moment=self.moment + 20, effective=self.moment + 5,
        )

    def citem(self, item_id, root, successors, policies=None):
        if policies is None:
            policies = [self.pol_v1] * (len(successors) + 1)
        return chain_item(item_id, root, successors, policies)

    def fork_items(self):
        return [
            self.citem("b", self.root_one, [self.first_a]),
            self.citem("a", self.root_one, [self.first_b]),
        ]

    def vchains(self, items, moment=None, policy=None, ring=None):
        return verify_prune_aggregate_chains(
            items,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment + 20 if moment is None else moment,
        )

    def sign_proof(self, items, moment=None, issuer=JUDGE, version=1,
                   policy=None, ring=None):
        return sign_prune_aggregate_fork_proof(
            items,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment + 20 if moment is None else moment,
            issuer, version,
        )

    def vproof(self, proof, moment=None, policy=None, ring=None):
        return verify_prune_aggregate_fork_proof(
            proof,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment + 20 if moment is None else moment,
        )

    def tamper_proof(self, proof, mutate):
        """Mutate the payload and re-sign with the same key."""
        data = parse(proof)
        mutate(data["payload"])
        data["signature"] = hmac_hex(SECRET_COORD, compact(data["payload"]))
        return compact(data)


class PruneAggregateChainBatchShapeTest(PruneAggregateChainBatchFixtures):
    def test_all_verified_report_shape_and_input_order(self):
        items = [
            self.citem("x", self.root_one, [self.first_a]),
            self.citem("y", self.root_two, []),
            self.citem("z", self.root_one, [self.first_a, self.second_a]),
        ]
        report = self.vchains(items)
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["forks"], [])
        self.assertEqual([item["id"] for item in report["items"]],
                         ["x", "y", "z"])
        for entry_report in report["items"]:
            self.assertEqual(list(entry_report.keys()), REPORT_KEYS)
            self.assertEqual(entry_report["status"], "verified")
            self.assertIsNone(entry_report["error"])
            self.assertEqual(list(entry_report["result"].keys()),
                             CHAIN_RESULT_KEYS)
        self.assertEqual(report["items"][0]["result"]["height"], 1)
        self.assertEqual(report["items"][1]["result"]["height"], 0)
        self.assertEqual(report["items"][2]["result"]["height"], 2)
        self.assertEqual(report["items"][1]["result"]["status"], "accepted")

    def test_results_match_single_chain_verification(self):
        items = [self.citem("x", self.root_one, [self.first_a])]
        report = self.vchains(items)
        single = self.vchain(self.root_one, [self.first_a],
                             moment=self.moment + 20)
        self.assertEqual(report["items"][0]["result"], single)

    def test_results_are_equal_but_independent(self):
        items = [self.citem("x", self.root_one, [self.first_a])]
        first = self.vchains(items)
        second = self.vchains(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["items"][0]["result"]["status"] = "conflicted"
        self.assertEqual(
            self.vchains(items)["items"][0]["result"]["status"], "accepted"
        )


class PruneAggregateChainBatchArgumentTest(PruneAggregateChainBatchFixtures):
    def test_container_faults(self):
        with self.assertRaises(TypeError):
            self.vchains("not-a-list")
        with self.assertRaises(ValueError):
            self.vchains([])
        with self.assertRaises(TypeError):
            self.vchains(["not-a-dict"])
        with self.assertRaises(ValueError):
            self.vchains([{"id": "x", "root": self.root_one}])

    def test_id_faults(self):
        with self.assertRaises(TypeError):
            self.vchains([self.citem(9, self.root_two, [])])
        with self.assertRaises(ValueError):
            self.vchains([self.citem("", self.root_two, [])])
        with self.assertRaises(ValueError):
            self.vchains([
                self.citem("x", self.root_two, []),
                self.citem("x", self.root_one, []),
            ])

    def test_packet_type_faults(self):
        with self.assertRaises(TypeError):
            self.vchains([self.citem("x", "not-bytes", [])])
        with self.assertRaises(TypeError):
            self.vchains([self.citem("x", self.root_one, "not-a-list")])
        with self.assertRaises(TypeError):
            self.vchains([self.citem("x", self.root_one, ["not-bytes"])])

    def test_policy_faults_are_batch_level(self):
        with self.assertRaises(TypeError):
            self.vchains([self.citem("x", self.root_one, [self.first_a],
                                     policies="not-a-list")])
        with self.assertRaises(ValueError):
            self.vchains([self.citem("x", self.root_one, [self.first_a],
                                     policies=[])])
        # The policy count must match the stages, checked up front.
        with self.assertRaises(ValueError):
            self.vchains([self.citem("x", self.root_one, [self.first_a],
                                     policies=[self.pol_v1])])
        with self.assertRaises(ValueError):
            self.vchains([self.citem("x", self.root_one, [],
                                     policies=[self.pol_v1, self.pol_v1])])
        # The root stage policy must carry policyVersion 1.
        with self.assertRaises(ValueError):
            self.vchains([self.citem(
                "x", self.root_one, [self.first_a],
                policies=[vpol(2), self.pol_v1],
            )])
        with self.assertRaises(TypeError):
            self.vchains([self.citem("x", self.root_one, [self.first_a],
                                     policies=[self.pol_v1, "not-a-dict"])])

    def test_shared_material_faults(self):
        items = [self.citem("x", self.root_two, [])]
        with self.assertRaises(ValueError):
            self.vchains(items, policy={"batch": BATCH, "sites": {},
                                        "threshold": 1})
        with self.assertRaises(TypeError):
            self.vchains(items, policy="not-a-dict")
        with self.assertRaises(TypeError):
            self.vchains(items, ring="not-a-dict")
        with self.assertRaises(TypeError):
            self.vchains(items, moment=True)
        with self.assertRaises(TypeError):
            self.vchains(items, moment="10")
        with self.assertRaises(ValueError):
            self.vchains(items, moment=-1)

    def test_precheck_failure_verifies_no_chain(self):
        # One bad item anywhere fails the whole batch before any chain
        # runs: the fault raises instead of reporting per-chain results.
        items = [
            self.citem("good", self.root_one, [self.first_a]),
            self.citem("bad", self.root_one, [self.first_b],
                       policies=[self.pol_v1]),
        ]
        with self.assertRaises(ValueError):
            self.vchains(items)


class PruneAggregateChainBatchIsolationTest(PruneAggregateChainBatchFixtures):
    def test_invalid_root_is_isolated(self):
        items = [
            self.citem("bad", b"not-an-aggregate", []),
            self.citem("good", self.root_one, [self.first_a]),
        ]
        report = self.vchains(items)
        bad, good = report["items"]
        self.assertEqual(bad["status"], "invalid-root")
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")
        self.assertIsNone(bad["result"])
        self.assertEqual(good["status"], "verified")
        self.assertEqual(report["forks"], [])

    def test_invalid_chain_is_isolated(self):
        data = parse(self.first_a)
        data["payload"]["height"] = 9
        tampered = self.resign(data)
        items = [
            self.citem("bad", self.root_one, [tampered]),
            self.citem("good", self.root_one, [self.first_a]),
        ]
        report = self.vchains(items)
        bad, good = report["items"]
        self.assertEqual(bad["status"], "invalid-chain")
        self.assertIsNone(bad["result"])
        self.assertEqual(good["status"], "verified")

    def test_unauthenticated_chain_is_isolated(self):
        data = parse(self.first_a)
        data["signature"] = "00" * 32
        items = [
            self.citem("bad", self.root_one, [compact(data)]),
            self.citem("good", self.root_one, [self.first_a]),
        ]
        report = self.vchains(items)
        bad, good = report["items"]
        self.assertEqual(bad["status"], "unauthenticated")
        self.assertIsNone(bad["result"])
        self.assertEqual(good["status"], "verified")

    def test_unauthenticated_root_credential(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        items = [self.citem("x", self.root_two, [])]
        report = self.vchains(items, ring=revoked)
        self.assertEqual(report["items"][0]["status"], "unauthenticated")

    def test_failure_kinds_do_not_interfere(self):
        data = parse(self.first_a)
        data["payload"]["height"] = 9
        items = [
            self.citem("bad-root", b"junk", []),
            self.citem("bad-chain", self.root_one, [self.resign(data)]),
            self.citem("good", self.root_one, [self.first_a]),
        ]
        report = self.vchains(items)
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["invalid-root", "invalid-chain", "verified"],
        )


class PruneAggregateChainBatchForkTest(PruneAggregateChainBatchFixtures):
    def test_two_successors_over_one_root_are_a_fork(self):
        report = self.vchains(self.fork_items())
        # Input order is preserved in the reports.
        self.assertEqual([item["id"] for item in report["items"]],
                         ["b", "a"])
        for item in report["items"]:
            self.assertEqual(item["status"], "conflicted")
            self.assertEqual(item["error"], "forked-aggregate-chain")
            # The verified result is kept.
            self.assertIsNotNone(item["result"])
            self.assertEqual(item["result"]["status"], "accepted")
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(list(fork.keys()), FORK_KEYS)
        root_digest = sha256(self.root_one)
        self.assertEqual(fork["rootDigest"], root_digest)
        self.assertEqual(fork["predecessorDigest"], root_digest)
        self.assertEqual(
            fork["successors"],
            sorted([sha256(self.first_a), sha256(self.first_b)]),
        )
        # The crossing ids are ascending, not in input order.
        self.assertEqual(fork["ids"], ["a", "b"])

    def test_three_way_fork_lists_every_successor_and_id(self):
        items = [
            self.citem("c", self.root_one, [self.first_c]),
            self.citem("a", self.root_one, [self.first_a]),
            self.citem("b", self.root_one, [self.first_b]),
        ]
        report = self.vchains(items)
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(
            fork["successors"],
            sorted([sha256(self.first_a), sha256(self.first_b),
                    sha256(self.first_c)]),
        )
        self.assertEqual(fork["ids"], ["a", "b", "c"])
        self.assertEqual([item["status"] for item in report["items"]],
                         ["conflicted"] * 3)

    def test_fork_at_a_later_hop(self):
        items = [
            self.citem("a", self.root_one, [self.first_a, self.second_a]),
            self.citem("b", self.root_one, [self.first_a, self.second_b]),
        ]
        report = self.vchains(items)
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(fork["predecessorDigest"], sha256(self.first_a))
        self.assertEqual(
            fork["successors"],
            sorted([sha256(self.second_a), sha256(self.second_b)]),
        )
        self.assertEqual(fork["ids"], ["a", "b"])

    def test_prefix_extension_is_not_a_fork(self):
        items = [
            self.citem("short", self.root_one, [self.first_a]),
            self.citem("long", self.root_one, [self.first_a, self.second_a]),
            self.citem("bare", self.root_one, []),
        ]
        report = self.vchains(items)
        self.assertEqual(report["forks"], [])
        self.assertEqual([item["status"] for item in report["items"]],
                         ["verified"] * 3)

    def test_identical_chains_are_not_a_fork(self):
        items = [
            self.citem("a", self.root_one, [self.first_a]),
            self.citem("b", self.root_one, [self.first_a]),
        ]
        report = self.vchains(items)
        self.assertEqual(report["forks"], [])
        self.assertEqual([item["status"] for item in report["items"]],
                         ["verified"] * 2)

    def test_forks_under_different_roots_are_distinct(self):
        other_a = self.succ(self.root_two, [pitem("three", self.pkt_c)])
        other_b = self.succ(self.root_two, [pitem("four", self.pkt_b_other)])
        items = [
            self.citem("one-a", self.root_one, [self.first_a]),
            self.citem("two-a", self.root_two, [other_a]),
            self.citem("one-b", self.root_one, [self.first_b]),
            self.citem("two-b", self.root_two, [other_b]),
        ]
        report = self.vchains(items)
        self.assertEqual(len(report["forks"]), 2)
        by_root = {fork["rootDigest"]: fork for fork in report["forks"]}
        self.assertEqual(set(by_root),
                         {sha256(self.root_one), sha256(self.root_two)})
        self.assertEqual(by_root[sha256(self.root_one)]["ids"],
                         ["one-a", "one-b"])
        self.assertEqual(by_root[sha256(self.root_two)]["ids"],
                         ["two-a", "two-b"])
        # The forks are sorted stably on their first two fields.
        self.assertEqual(
            [(fork["rootDigest"], fork["predecessorDigest"])
             for fork in report["forks"]],
            sorted((fork["rootDigest"], fork["predecessorDigest"])
                   for fork in report["forks"]),
        )
        self.assertEqual([item["status"] for item in report["items"]],
                         ["conflicted"] * 4)

    def test_failed_chains_never_create_or_cross_forks(self):
        data = parse(self.first_b)
        data["payload"]["height"] = 9
        items = [
            self.citem("good", self.root_one, [self.first_a]),
            self.citem("bad", self.root_one, [self.resign(data)]),
        ]
        report = self.vchains(items)
        self.assertEqual(report["forks"], [])
        self.assertEqual([item["status"] for item in report["items"]],
                         ["verified", "invalid-chain"])


class PruneAggregateForkProofSignTest(PruneAggregateChainBatchFixtures):
    def test_proof_shape_and_canonical_encoding(self):
        proof = self.sign_proof(self.fork_items())
        self.assertFalse(proof.endswith(b"\n"))
        self.assertFalse(proof.endswith(b" "))
        data = parse(proof)
        self.assertEqual(list(data.keys()), PROOF_KEYS)
        self.assertEqual(list(data["payload"].keys()), PROOF_PAYLOAD_KEYS)
        self.assertEqual(compact(data), proof)
        payload = data["payload"]
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.moment + 20)

    def test_proof_binds_the_policy_digest(self):
        payload = parse(self.sign_proof(self.fork_items()))["payload"]
        expected = hashlib.sha256(compact({
            "batch": BATCH,
            "sites": {site: [1] for site in sorted([SITE_A, "site-b",
                                                    "site-c"])},
            "threshold": 2,
        })).hexdigest()
        self.assertEqual(payload["policy"], expected)

    def test_proof_chains_bind_root_successor_and_policy_digests(self):
        items = self.fork_items()
        payload = parse(self.sign_proof(items))["payload"]
        chains = payload["chains"]
        self.assertEqual([chain["id"] for chain in chains], ["b", "a"])
        pol_digest = sha256(policy_canon(self.pol_v1))
        for chain, successor in zip(chains, [self.first_a, self.first_b]):
            self.assertEqual(list(chain.keys()), PROOF_CHAIN_KEYS)
            self.assertEqual(chain["root"], sha256(self.root_one))
            self.assertEqual(chain["successors"], [sha256(successor)])
            self.assertEqual(chain["policies"], [pol_digest, pol_digest])

    def test_proof_binds_the_complete_report(self):
        items = self.fork_items()
        payload = parse(self.sign_proof(items))["payload"]
        self.assertEqual(payload["report"], self.vchains(items))

    def test_no_fork_is_a_value_error(self):
        items = [self.citem("x", self.root_one, [self.first_a])]
        with self.assertRaises(ValueError):
            self.sign_proof(items)

    def test_sign_argument_faults(self):
        items = self.fork_items()
        with self.assertRaises(ValueError):
            self.sign_proof([])
        with self.assertRaises(ValueError):
            self.sign_proof(items + items)
        with self.assertRaises(TypeError):
            self.sign_proof(items, issuer=9)
        with self.assertRaises(ValueError):
            self.sign_proof(items, issuer="")
        with self.assertRaises(TypeError):
            self.sign_proof(items, version=True)
        with self.assertRaises(ValueError):
            self.sign_proof(items, version=0)
        with self.assertRaises(TypeError):
            self.sign_proof(items, moment=True)
        with self.assertRaises(ValueError):
            self.sign_proof(items, moment=-1)

    def test_sign_credential_faults(self):
        items = self.fork_items()
        with self.assertRaises(AuthenticationError):
            self.sign_proof(items, issuer="ghost")
        # A revoked signing key version rejects even though the chain
        # materials still verify under the signer's other version.
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE] = revoked[JUDGE] + [entry(2, "22" * 32, revoked=True)]
        with self.assertRaises(AuthenticationError):
            self.sign_proof(items, ring=revoked, version=2)


class PruneAggregateForkProofVerifyTest(PruneAggregateChainBatchFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = self.fork_items()
        self.proof = self.sign_proof(self.items)

    def test_verify_result_shape_and_bindings(self):
        result = self.vproof(self.proof)
        self.assertEqual(list(result.keys()), PROOF_RESULT_KEYS)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["moment"], self.moment + 20)
        self.assertEqual(result["proofDigest"], sha256(self.proof))
        payload = parse(self.proof)["payload"]
        self.assertEqual(result["policyDigest"], payload["policy"])
        self.assertEqual(result["report"], payload["report"])
        self.assertEqual(result["chains"], payload["chains"])

    def test_verify_results_are_equal_but_independent(self):
        first = self.vproof(self.proof)
        second = self.vproof(self.proof)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["report"]["items"][0]["status"] = "verified"
        first["chains"][0]["root"] = "00" * 32
        again = self.vproof(self.proof)
        self.assertEqual(again["report"]["items"][0]["status"], "conflicted")
        self.assertNotEqual(again["chains"][0]["root"], "00" * 32)

    def test_verify_argument_faults(self):
        with self.assertRaises(TypeError):
            self.vproof("not-bytes")
        with self.assertRaises(TypeError):
            self.vproof(self.proof, policy="not-a-dict")
        with self.assertRaises(ValueError):
            self.vproof(self.proof, policy={"batch": BATCH, "sites": {},
                                            "threshold": 1})
        with self.assertRaises(TypeError):
            self.vproof(self.proof, moment=True)
        with self.assertRaises(ValueError):
            self.vproof(self.proof, moment=-1)

    def test_wrong_prune_policy_is_a_proof_error(self):
        other = {"batch": "batch-other",
                 "sites": {SITE_A: {1}, "site-b": {1}, "site-c": {1}},
                 "threshold": 2}
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.proof, policy=other)

    def test_verification_before_the_signing_moment_is_a_proof_error(self):
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.proof, moment=self.moment + 19)

    def test_bad_signature_is_authentication_error(self):
        data = parse(self.proof)
        data["payload"]["moment"] = self.moment + 19
        with self.assertRaises(AuthenticationError):
            self.vproof(compact(data))

    def test_unknown_or_revoked_signer_is_authentication_error(self):
        missing = {site: keys for site, keys in self.ring.items()
                   if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            self.vproof(self.proof, ring=missing)
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.vproof(self.proof, ring=revoked)

    def test_proof_encoding_faults(self):
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.proof + b"\n")
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(b"not-json")
        data = parse(self.proof)
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(json.dumps(data, indent=2).encode("utf-8"))
        raw = self.proof.decode("utf-8")
        duplicated = raw.replace(
            '"version":1', '"version":1,"version":1', 1
        )
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(duplicated.encode("utf-8"))

    def test_payload_field_faults(self):
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(
                self.proof, lambda p: p.__setitem__("version", 2)))
        with self.assertRaises(TypeError):
            self.vproof(self.tamper_proof(
                self.proof, lambda p: p.__setitem__("version", True)))
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(
                self.proof, lambda p: p.__setitem__("issuer", "")))
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(
                self.proof, lambda p: p.__setitem__("keyVersion", 0)))
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(
                self.proof, lambda p: p.__setitem__("policy", "00" * 32)))

    def test_chain_material_binding_faults(self):
        # A dropped chain breaks the report item count binding.
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(
                self.proof, lambda p: p["chains"].pop(0)))
        # A reordered chain breaks the positional id binding.
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(
                self.proof, lambda p: p["chains"].reverse()))
        # A tampered successor digest breaks the fork recomputation.
        def swap_successor(payload):
            payload["chains"][0]["successors"][0] = "00" * 32
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(self.proof, swap_successor))
        # A wrong policy history count breaks the chain material.
        def drop_policy(payload):
            payload["chains"][0]["policies"].pop(0)
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(self.proof, drop_policy))

    def test_report_binding_faults(self):
        # A proof without a fork is structurally illegal.
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(
                self.proof, lambda p: p["report"].__setitem__("forks", [])))
        # A tampered fork id list breaks the crossing recomputation.
        def tamper_ids(payload):
            payload["report"]["forks"][0]["ids"] = ["a"]
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(self.proof, tamper_ids))
        # A tampered fork successor list breaks the edge recomputation.
        def tamper_successors(payload):
            payload["report"]["forks"][0]["successors"] = ["00" * 32] * 2
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(self.proof, tamper_successors))
        # A tampered item status breaks the conflicted-set equality.
        def tamper_status(payload):
            payload["report"]["items"][0]["status"] = "verified"
            payload["report"]["items"][0]["error"] = None
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(self.proof, tamper_status))
        # A tampered result binding breaks the chain material match.
        def tamper_head(payload):
            payload["report"]["items"][0]["result"]["headDigest"] = "00" * 32
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(self.proof, tamper_head))
        # A tampered item error breaks the fixed conflicted error.
        def tamper_error(payload):
            payload["report"]["items"][0]["error"] = "something-else"
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(self.tamper_proof(self.proof, tamper_error))


class PruneAggregateForkProofErrorHierarchyTest(
        PruneAggregateChainBatchFixtures):
    def test_error_classes(self):
        self.assertTrue(issubclass(InvalidAggregateForkProofError, ValueError))
        self.assertIsNot(InvalidAggregateForkProofError,
                         InvalidAggregateChainError)
        self.assertIsNot(InvalidAggregateForkProofError,
                         InvalidPruneBatchAggregateError)
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class PruneAggregateChainBatchIndependenceTest(
        PruneAggregateChainBatchFixtures):
    def test_inputs_are_not_modified(self):
        items = self.fork_items()
        snapshot = copy.deepcopy(items)
        policy_snapshot = copy.deepcopy(self.policy)
        ring_snapshot = copy.deepcopy(self.ring)
        proof = self.sign_proof(items)
        self.vchains(items)
        self.vproof(proof)
        self.assertEqual(items, snapshot)
        self.assertEqual(self.policy, policy_snapshot)
        self.assertEqual(self.ring, ring_snapshot)

    def test_no_file_is_read_or_written(self):
        items = self.fork_items()
        proof = self.sign_proof(items)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.vchains(items)
            self.sign_proof(items)
            self.vproof(proof)


if __name__ == "__main__":
    unittest.main()
