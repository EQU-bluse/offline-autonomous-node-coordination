"""Tests for batch verification and fork proofs of prune aggregate chains.

Covers :func:`verify_prune_aggregate_chains`,
:func:`sign_prune_aggregate_fork_proof` and
:func:`verify_prune_aggregate_fork_proof`: the whole-batch upfront
validation and exception taxonomy (no chain is verified when a
batch-level fault exists), the strict input-order per-chain reports
and the ``invalid-root``/``invalid-chain``/``unauthenticated``
failure classes, cross-chain fork detection by
``rootDigest``/``predecessorDigest`` successor digests with
prefix-extension non-forks and cross-root isolation, the
``conflicted`` reclassification with the fixed
``forked-aggregate-chain`` error, the signed fork proof binding the
prune policy digest, the original-order chain material summary (root,
successor and policy-history byte digests), the complete report, the
signing moment, the exact issuer/version credentials and ``version``
1, offline proof re-verification recomputing the forks, digests and
ordering from the bound materials alone, the
``InvalidAggregateForkProofError`` hierarchy, input immutability and
the purely offline guarantee.
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
    InvalidAggregateForkProofError,
    verify_prune_aggregate_chain,
    verify_prune_aggregate_chains,
    sign_prune_aggregate_fork_proof,
    verify_prune_aggregate_fork_proof,
)

from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C, hmac_hex, sha256
from test_supersede_prune_aggregate import (
    PruneAggregateChainFixtures,
    pitem,
    policy_canon,
    vpol,
)

REPORT_KEYS = ["error", "id", "result", "status"]
TOP_KEYS = ["forks", "items", "version"]
FORK_KEYS = ["rootDigest", "predecessorDigest", "successors", "ids"]
RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "commonDigest",
]
MATERIAL_KEYS = ["id", "policies", "root", "successors"]
PROOF_PACKET_KEYS = ["payload", "signature"]
PROOF_PAYLOAD_KEYS = [
    "chains", "issuer", "keyVersion", "materialsDigest", "moment",
    "prunePolicyDigest", "report", "version",
]
PROOF_RESULT_KEYS = [
    "chains", "issuer", "keyVersion", "materialsDigest", "moment",
    "prunePolicyDigest", "proofDigest", "report", "version",
]


class PruneAggregateChainBatchFixtures(PruneAggregateChainFixtures):
    """Divergent chains over shared roots plus batch/proof helpers."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Two divergent first successors over the one-vote root: one
        # reaches acceptance, the other conflicts the declaration.
        self.fork_a = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        self.fork_b = self.succ(
            self.root_one, [pitem("four", self.pkt_b_other)]
        )
        # A shared first hop with two divergent continuations.
        self.shared = self.succ(self.root_one, [pitem("three", self.pkt_b)])
        self.deeper_a = self.succ(
            self.shared, [pitem("five", self.pkt_c)],
            moment=self.moment + 20, effective=self.moment + 5,
        )
        self.deeper_b = self.succ(
            self.shared, [pitem("six", self.pkt_a_short)],
            moment=self.moment + 20, effective=self.moment + 5,
        )
        self.verify_moment = self.moment + 100

    def mkchain(self, item_id, root, successors, policies=None):
        if policies is None:
            policies = [self.pol_v1] * (len(successors) + 1)
        return {
            "id": item_id,
            "root": root,
            "successors": (
                list(successors) if isinstance(successors, list)
                else successors
            ),
            "policies": (
                list(policies) if isinstance(policies, list) else policies
            ),
        }

    def forked_batch(self):
        """Two chains forking at the root edge plus one clean chain."""
        return [
            self.mkchain("b-chain", self.root_one, [self.fork_a]),
            self.mkchain("a-chain", self.root_one, [self.fork_b]),
            self.mkchain("c-chain", self.root_two, []),
        ]

    def deeper_batch(self):
        """Two chains sharing one hop and forking at the second."""
        return [
            self.mkchain("deep-a", self.root_one,
                       [self.shared, self.deeper_a]),
            self.mkchain("deep-b", self.root_one,
                       [self.shared, self.deeper_b]),
        ]

    def vchains(self, chains, moment=None, ring=None):
        return verify_prune_aggregate_chains(
            chains, self.policy, self.ring if ring is None else ring,
            self.verify_moment if moment is None else moment,
        )

    def sign_proof(self, chains, issuer=JUDGE, version=1, moment=None,
                   ring=None):
        return sign_prune_aggregate_fork_proof(
            chains, self.policy, self.ring if ring is None else ring,
            self.verify_moment if moment is None else moment,
            issuer, version,
        )

    def vproof(self, proof, moment=None, ring=None, policy=None):
        return verify_prune_aggregate_fork_proof(
            proof, self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.verify_moment if moment is None else moment,
        )


class ChainBatchValidationTest(PruneAggregateChainBatchFixtures):
    """The whole batch is validated before any chain is verified."""

    def test_chains_must_be_a_non_empty_list(self):
        with self.assertRaises(TypeError):
            self.vchains("not-a-list")
        with self.assertRaises(ValueError):
            self.vchains([])

    def test_item_must_be_a_dict_with_the_exact_keys(self):
        with self.assertRaises(TypeError):
            self.vchains(["not-a-dict"])
        good = self.mkchain("c", self.root_two, [])
        for bad_keys in (
            {"id": "c", "root": self.root_two, "successors": []},
            {"id": "c", "root": self.root_two, "successors": [],
             "policies": [self.pol_v1], "extra": 1},
        ):
            with self.assertRaises(ValueError):
                self.vchains([bad_keys])
        self.assertEqual(
            self.vchains([good])["items"][0]["status"], "verified"
        )

    def test_id_must_be_a_unique_non_empty_str(self):
        with self.assertRaises(TypeError):
            self.vchains([self.mkchain(7, self.root_two, [])])
        with self.assertRaises(ValueError):
            self.vchains([self.mkchain("", self.root_two, [])])
        with self.assertRaises(ValueError):
            self.vchains([
                self.mkchain("dup", self.root_two, []),
                self.mkchain("dup", self.root_one, []),
            ])

    def test_root_and_successors_must_be_bytes(self):
        with self.assertRaises(TypeError):
            self.vchains([self.mkchain("c", "not-bytes", [])])
        with self.assertRaises(TypeError):
            self.vchains([self.mkchain("c", self.root_two, "not-a-list")])
        with self.assertRaises(TypeError):
            self.vchains([self.mkchain("c", self.root_two, ["not-bytes"])])

    def test_policies_must_match_the_stage_count(self):
        with self.assertRaises(TypeError):
            self.vchains([self.mkchain("c", self.root_two, [],
                                     policies="not-a-list")])
        with self.assertRaises(ValueError):
            self.vchains([self.mkchain("c", self.root_two, [], policies=[])])
        with self.assertRaises(ValueError):
            self.vchains([self.mkchain(
                "c", self.root_one, [self.fork_a], policies=[self.pol_v1]
            )])
        with self.assertRaises(ValueError):
            self.vchains([self.mkchain(
                "c", self.root_two, [],
                policies=[self.pol_v1, self.pol_v1],
            )])

    def test_shared_material_and_moment_faults(self):
        batch = [self.mkchain("c", self.root_two, [])]
        with self.assertRaises(ValueError):
            verify_prune_aggregate_chains(
                batch, {"batch": "b"}, self.ring, self.verify_moment
            )
        with self.assertRaises(TypeError):
            verify_prune_aggregate_chains(
                batch, self.policy, "not-a-dict", self.verify_moment
            )
        with self.assertRaises(TypeError):
            self.vchains(batch, moment=True)
        with self.assertRaises(ValueError):
            self.vchains(batch, moment=-1)

    def test_batch_fault_verifies_no_chain(self):
        # The first chain would fail verification (a garbage root) but
        # the duplicate id is a batch-level fault: the call raises
        # instead of reporting anything.
        with self.assertRaises(ValueError):
            self.vchains([
                self.mkchain("dup", b"garbage", []),
                self.mkchain("dup", self.root_two, []),
            ])
        with self.assertRaises(TypeError):
            self.vchains([
                self.mkchain("ok", self.root_two, []),
                self.mkchain("bad", self.root_two, [], policies="nope"),
            ])


class ChainBatchVerifyTest(PruneAggregateChainBatchFixtures):
    def test_top_level_shape_and_input_order(self):
        report = self.vchains([
            self.mkchain("one", self.root_two, []),
            self.mkchain("two", self.root_one, [self.fork_a]),
            self.mkchain("three", self.root_conf, []),
        ])
        self.assertEqual(list(report.keys()), TOP_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertNotIsInstance(report["version"], bool)
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [item["id"] for item in report["items"]],
            ["one", "two", "three"],
        )
        for item in report["items"]:
            self.assertEqual(list(item.keys()), REPORT_KEYS)
            self.assertEqual(item["status"], "verified")
            self.assertIsNone(item["error"])
            self.assertEqual(
                list(item["result"].keys()), RESULT_KEYS
            )

    def test_result_matches_the_single_chain_summary(self):
        successors = [self.shared, self.deeper_a]
        policies = [self.pol_v1] * 3
        single = verify_prune_aggregate_chain(
            self.root_one, successors, self.policy, policies, self.ring,
            self.verify_moment,
        )
        report = self.vchains([
            self.mkchain("x", self.root_one, successors, policies=policies)
        ])
        self.assertEqual(report["items"][0]["result"], single)

    def test_bare_root_chain_reports_the_root_stage(self):
        report = self.vchains([self.mkchain("bare", self.root_two, [])])
        result = report["items"][0]["result"]
        self.assertEqual(result["rootDigest"], sha256(self.root_two))
        self.assertEqual(result["headDigest"], sha256(self.root_two))
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertIsNotNone(result["commonDigest"])

    def test_invalid_root_is_isolated(self):
        report = self.vchains([
            self.mkchain("bad", b"not-a-root", []),
            self.mkchain("good", self.root_two, []),
        ])
        bad, good = report["items"]
        self.assertEqual(bad["status"], "invalid-root")
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")
        self.assertIsNone(bad["result"])
        self.assertEqual(good["status"], "verified")
        self.assertEqual(report["forks"], [])

    def test_root_site_policy_mismatch_is_invalid_root(self):
        report = self.vchains([
            self.mkchain("mismatch", self.root_two, [],
                       policies=[vpol(1, sites=(SITE_A, SITE_B))]),
        ])
        self.assertEqual(report["items"][0]["status"], "invalid-root")

    def test_root_stage_policy_version_is_invalid_root(self):
        report = self.vchains([
            self.mkchain("v2", self.root_two, [], policies=[self.pol_v2]),
        ])
        self.assertEqual(report["items"][0]["status"], "invalid-root")

    def test_invalid_chain_is_isolated(self):
        report = self.vchains([
            self.mkchain("bad", self.root_one, [b"not-a-successor"]),
            self.mkchain("good", self.root_two, []),
        ])
        bad, good = report["items"]
        self.assertEqual(bad["status"], "invalid-chain")
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")
        self.assertIsNone(bad["result"])
        self.assertEqual(good["status"], "verified")

    def test_successor_over_another_root_is_invalid_chain(self):
        report = self.vchains([
            self.mkchain("bad", self.root_two, [self.fork_a],
                       policies=[self.pol_v1, self.pol_v1]),
        ])
        self.assertEqual(report["items"][0]["status"], "invalid-chain")

    def test_later_policy_fault_is_invalid_chain(self):
        report = self.vchains([
            self.mkchain("bad", self.root_one, [self.fork_a],
                       policies=[self.pol_v1, {"sites": {}, "threshold": 1,
                                               "policyVersion": 1}]),
        ])
        self.assertEqual(report["items"][0]["status"], "invalid-chain")

    def test_unauthenticated_root_and_successor(self):
        revoked_judge = {
            **self.ring, JUDGE: [entry(1, SECRET_COORD, revoked=True)]
        }
        report = self.vchains(
            [self.mkchain("root-auth", self.root_two, [])], ring=revoked_judge
        )
        self.assertEqual(report["items"][0]["status"], "unauthenticated")
        self.assertIsNone(report["items"][0]["result"])

        revoked_site = {
            **self.ring, SITE_A: [entry(1, SECRET_COORD, revoked=True)]
        }
        report = self.vchains(
            [self.mkchain("succ-auth", self.root_one, [self.fork_a])],
            ring=revoked_site,
        )
        self.assertEqual(report["items"][0]["status"], "unauthenticated")

    def test_one_failure_never_stops_a_later_chain(self):
        report = self.vchains([
            self.mkchain("bad-root", b"junk", []),
            self.mkchain("bad-chain", self.root_one, [b"junk"]),
            self.mkchain("good", self.root_two, []),
        ])
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["invalid-root", "invalid-chain", "verified"],
        )

    def test_results_are_equal_but_independent(self):
        batch = [self.mkchain("x", self.root_one, [self.shared, self.deeper_a])]
        first = self.vchains(batch)
        second = self.vchains(batch)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(
            first["items"][0]["result"], second["items"][0]["result"]
        )

    def test_inputs_are_not_modified(self):
        batch = self.forked_batch()
        snapshot = copy.deepcopy(batch)
        policy = copy.deepcopy(self.policy)
        self.vchains(batch)
        self.assertEqual(batch, snapshot)
        self.assertEqual(self.policy, policy)

    def test_no_file_is_read_or_written(self):
        with mock.patch("builtins.open", side_effect=AssertionError("io")):
            self.vchains(self.forked_batch())


class ChainBatchForkTest(PruneAggregateChainBatchFixtures):
    def test_fork_at_the_root_edge(self):
        report = self.vchains(self.forked_batch())
        first, second, third = report["items"]
        self.assertEqual(first["status"], "conflicted")
        self.assertEqual(second["status"], "conflicted")
        self.assertEqual(third["status"], "verified")
        for item in (first, second):
            self.assertEqual(item["error"], "forked-aggregate-chain")
            # The verified single-chain result is kept.
            self.assertIsNotNone(item["result"])
            self.assertEqual(
                list(item["result"].keys()), RESULT_KEYS
            )
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(list(fork.keys()), FORK_KEYS)
        self.assertEqual(fork["rootDigest"], sha256(self.root_one))
        self.assertEqual(fork["predecessorDigest"], sha256(self.root_one))
        self.assertEqual(
            fork["successors"],
            sorted([sha256(self.fork_a), sha256(self.fork_b)]),
        )
        self.assertEqual(fork["ids"], ["a-chain", "b-chain"])

    def test_fork_after_a_shared_prefix(self):
        report = self.vchains(self.deeper_batch())
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["conflicted", "conflicted"],
        )
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(fork["predecessorDigest"], sha256(self.shared))
        self.assertEqual(
            fork["successors"],
            sorted([sha256(self.deeper_a), sha256(self.deeper_b)]),
        )
        self.assertEqual(fork["ids"], ["deep-a", "deep-b"])

    def test_prefix_extension_is_not_a_fork(self):
        report = self.vchains([
            self.mkchain("short", self.root_one, [self.shared]),
            self.mkchain("long", self.root_one, [self.shared, self.deeper_a]),
        ])
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["verified", "verified"],
        )
        self.assertEqual(report["forks"], [])

    def test_identical_chains_are_not_a_fork(self):
        report = self.vchains([
            self.mkchain("one", self.root_one, [self.shared]),
            self.mkchain("two", self.root_one, [self.shared]),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["verified", "verified"],
        )

    def test_bare_roots_share_no_edges(self):
        report = self.vchains([
            self.mkchain("one", self.root_one, []),
            self.mkchain("two", self.root_one, []),
        ])
        self.assertEqual(report["forks"], [])

    def test_different_roots_are_never_compared(self):
        other_root = self.aggregate([pitem("one", self.pkt_a_short)])
        other_succ = self.succ(other_root, [pitem("two", self.pkt_a)])
        report = self.vchains([
            self.mkchain("one", self.root_one, [self.fork_a]),
            self.mkchain("two", other_root, [other_succ]),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["verified", "verified"],
        )

    def test_failed_chains_do_not_participate(self):
        report = self.vchains([
            self.mkchain("good", self.root_one, [self.fork_a]),
            self.mkchain("broken", self.root_one, [b"junk"]),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["verified", "invalid-chain"],
        )

    def test_three_chains_share_one_fork_edge(self):
        report = self.vchains([
            self.mkchain("c", self.root_one, [self.fork_a]),
            self.mkchain("a", self.root_one, [self.fork_b]),
            self.mkchain("b", self.root_one, [self.fork_a]),
        ])
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(fork["ids"], ["a", "b", "c"])
        self.assertEqual(
            fork["successors"],
            sorted([sha256(self.fork_a), sha256(self.fork_b)]),
        )
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["conflicted"] * 3,
        )

    def test_forks_sorted_by_root_then_predecessor(self):
        # Two independent fork groups under different roots.
        other_root = self.aggregate([pitem("one", self.pkt_a_short)])
        other_a = self.succ(other_root, [pitem("two", self.pkt_b)])
        other_b = self.succ(other_root, [pitem("three", self.pkt_c)])
        other_policies = [self.pol_v1, self.pol_v1]
        report = self.vchains([
            self.mkchain("r1-a", self.root_one, [self.fork_a]),
            self.mkchain("r2-a", other_root, [other_a],
                       policies=other_policies),
            self.mkchain("r1-b", self.root_one, [self.fork_b]),
            self.mkchain("r2-b", other_root, [other_b],
                       policies=other_policies),
        ])
        self.assertEqual(len(report["forks"]), 2)
        roots = [fork["rootDigest"] for fork in report["forks"]]
        self.assertEqual(roots, sorted(roots))
        self.assertEqual(
            {fork["rootDigest"] for fork in report["forks"]},
            {sha256(self.root_one), sha256(other_root)},
        )
        for fork in report["forks"]:
            self.assertEqual(len(fork["ids"]), 2)
            self.assertEqual(fork["ids"], sorted(fork["ids"]))

    def test_two_fork_edges_share_a_root_group(self):
        # Two chains diverge below a shared first hop while a third
        # chain forks right at the root edge: two fork edges, one root.
        report = self.vchains([
            self.mkchain("a", self.root_one, [self.shared, self.deeper_a]),
            self.mkchain("b", self.root_one, [self.shared, self.deeper_b]),
            self.mkchain("c", self.root_one, [self.fork_b]),
        ])
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["conflicted"] * 3,
        )
        self.assertEqual(len(report["forks"]), 2)
        edges = [
            (fork["rootDigest"], fork["predecessorDigest"])
            for fork in report["forks"]
        ]
        self.assertEqual(edges, sorted(edges))
        self.assertEqual(
            {fork["predecessorDigest"] for fork in report["forks"]},
            {sha256(self.root_one), sha256(self.shared)},
        )
        for fork in report["forks"]:
            self.assertEqual(fork["rootDigest"], sha256(self.root_one))
            if fork["predecessorDigest"] == sha256(self.root_one):
                self.assertEqual(fork["ids"], ["a", "b", "c"])
                self.assertEqual(
                    fork["successors"],
                    sorted([sha256(self.shared), sha256(self.fork_b)]),
                )
            else:
                self.assertEqual(fork["ids"], ["a", "b"])
                self.assertEqual(
                    fork["successors"],
                    sorted([sha256(self.deeper_a), sha256(self.deeper_b)]),
                )


class SignPruneAggregateForkProofTest(PruneAggregateChainBatchFixtures):
    def test_proof_shape_and_canonical_encoding(self):
        raw = self.sign_proof(self.forked_batch())
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), PROOF_PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), PROOF_PAYLOAD_KEYS)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.verify_moment)
        self.assertEqual(compact(data), raw)

    def test_payload_binds_policy_report_and_materials(self):
        batch = self.forked_batch()
        raw = self.sign_proof(batch)
        payload = parse(raw)["payload"]
        self.assertEqual(
            payload["prunePolicyDigest"],
            sha256(compact({
                "batch": self.policy["batch"],
                "sites": {site: [1] for site in sorted(self.policy["sites"])},
                "threshold": self.policy["threshold"],
            })),
        )
        report = self.vchains(batch)
        self.assertEqual(payload["report"], report)
        materials = payload["chains"]
        self.assertEqual(
            payload["materialsDigest"], sha256(compact(materials))
        )
        self.assertEqual([m["id"] for m in materials],
                         ["b-chain", "a-chain", "c-chain"])
        for material in materials:
            self.assertEqual(list(material.keys()), MATERIAL_KEYS)
        self.assertEqual(materials[0]["root"], sha256(self.root_one))
        self.assertEqual(materials[0]["successors"], [sha256(self.fork_a)])
        self.assertEqual(materials[2]["successors"], [])
        self.assertEqual(
            materials[0]["policies"],
            [sha256(policy_canon(self.pol_v1))] * 2,
        )
        self.assertEqual(
            materials[2]["policies"], [sha256(policy_canon(self.pol_v1))]
        )

    def test_materials_keep_the_original_order_and_every_chain(self):
        batch = [
            self.mkchain("bad", b"junk", []),
            self.mkchain("a", self.root_one, [self.fork_a]),
            self.mkchain("b", self.root_one, [self.fork_b]),
        ]
        payload = parse(self.sign_proof(batch))["payload"]
        materials = payload["chains"]
        # The failed chain is summarized too, none omitted or reordered.
        self.assertEqual([m["id"] for m in materials], ["bad", "a", "b"])
        self.assertEqual(materials[0]["root"], sha256(b"junk"))
        self.assertEqual(payload["report"]["items"][0]["status"],
                         "invalid-root")

    def test_signature_uses_the_exact_issuer_version_key(self):
        raw = self.sign_proof(self.forked_batch())
        data = parse(raw)
        self.assertEqual(
            data["signature"],
            hmac_hex(SECRET_COORD, compact(data["payload"])),
        )

    def test_no_fork_is_a_value_error(self):
        with self.assertRaises(ValueError):
            self.sign_proof([self.mkchain("x", self.root_two, [])])
        with self.assertRaises(ValueError):
            self.sign_proof([
                self.mkchain("short", self.root_one, [self.shared]),
                self.mkchain("long", self.root_one,
                           [self.shared, self.deeper_a]),
            ])

    def test_signing_argument_faults(self):
        batch = self.forked_batch()
        with self.assertRaises(TypeError):
            self.sign_proof(batch, issuer=7)
        with self.assertRaises(ValueError):
            self.sign_proof(batch, issuer="")
        with self.assertRaises(TypeError):
            self.sign_proof(batch, version=True)
        with self.assertRaises(ValueError):
            self.sign_proof(batch, version=0)
        with self.assertRaises(TypeError):
            self.sign_proof(batch, moment=True)
        with self.assertRaises(ValueError):
            self.sign_proof(batch, moment=-1)
        with self.assertRaises(ValueError):
            self.sign_proof([
                self.mkchain("dup", self.root_one, [self.fork_a]),
                self.mkchain("dup", self.root_one, [self.fork_b]),
            ])

    def test_unknown_or_revoked_signer_is_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.sign_proof(self.forked_batch(), issuer="nobody")
        revoked = {
            **self.ring, SITE_C: [entry(1, SECRET_COORD, revoked=True)]
        }
        with self.assertRaises(AuthenticationError):
            self.sign_proof(
                self.forked_batch(), issuer=SITE_C, ring=revoked
            )

    def test_inputs_are_not_modified(self):
        batch = self.forked_batch()
        snapshot = copy.deepcopy(batch)
        self.sign_proof(batch)
        self.assertEqual(batch, snapshot)

    def test_no_file_is_read_or_written(self):
        with mock.patch("builtins.open", side_effect=AssertionError("io")):
            self.sign_proof(self.forked_batch())


class VerifyPruneAggregateForkProofTest(PruneAggregateChainBatchFixtures):
    def test_round_trip_result(self):
        batch = self.forked_batch()
        raw = self.sign_proof(batch)
        result = self.vproof(raw)
        self.assertEqual(list(result.keys()), PROOF_RESULT_KEYS)
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["moment"], self.verify_moment)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["proofDigest"], sha256(raw))
        self.assertEqual(result["report"], self.vchains(batch))
        payload = parse(raw)["payload"]
        self.assertEqual(result["chains"], payload["chains"])
        self.assertEqual(
            result["materialsDigest"], payload["materialsDigest"]
        )
        self.assertEqual(
            result["prunePolicyDigest"], payload["prunePolicyDigest"]
        )

    def test_results_are_equal_but_independent(self):
        raw = self.sign_proof(self.forked_batch())
        first = self.vproof(raw)
        second = self.vproof(raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["report"], second["report"])
        self.assertIsNot(first["chains"], second["chains"])

    def test_proof_must_be_bytes(self):
        with self.assertRaises(TypeError):
            self.vproof("not-bytes")

    def test_trailing_byte_and_bad_encodings(self):
        raw = self.sign_proof(self.forked_batch())
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(raw + b"\n")
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(b"not-json")
        data = parse(raw)
        reserialized = json.dumps(data).encode("utf-8")
        if reserialized != raw:
            with self.assertRaises(InvalidAggregateForkProofError):
                self.vproof(reserialized)

    def test_duplicate_json_key_is_a_proof_error(self):
        raw = self.sign_proof(self.forked_batch())
        data = parse(raw)
        payload_text = json.dumps(
            data["payload"], ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        )
        duplicated = (
            b'{"payload":' + payload_text.encode("utf-8")
            + b',"payload":' + payload_text.encode("utf-8")
            + b',"signature":"' + data["signature"].encode("utf-8") + b'"}'
        )
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(duplicated)

    def _resigned(self, raw, mutate, secret=SECRET_COORD):
        data = parse(raw)
        mutate(data["payload"])
        data["signature"] = hmac_hex(secret, compact(data["payload"]))
        return compact(data)

    def test_report_without_a_fork_is_a_value_error(self):
        raw = self.sign_proof(self.forked_batch())

        def drop_fork(payload):
            payload["report"]["forks"] = []

        with self.assertRaises(ValueError):
            self.vproof(self._resigned(raw, drop_fork))

    def test_tampered_report_is_a_proof_error(self):
        raw = self.sign_proof(self.forked_batch())

        def flip_status(payload):
            payload["report"]["items"][0]["status"] = "verified"
            payload["report"]["items"][0]["error"] = None

        def wrong_ids(payload):
            payload["report"]["forks"][0]["ids"] = ["a-chain"]

        def wrong_successors(payload):
            payload["report"]["forks"][0]["successors"] = [
                sha256(self.fork_a)
            ]

        def wrong_height(payload):
            payload["report"]["items"][0]["result"]["height"] = 9

        def wrong_head(payload):
            payload["report"]["items"][0]["result"]["headDigest"] = (
                sha256(b"other")
            )

        for mutate in (
            flip_status, wrong_ids, wrong_successors,
            wrong_height, wrong_head,
        ):
            with self.assertRaises(
                InvalidAggregateForkProofError, msg=mutate.__name__
            ):
                self.vproof(self._resigned(raw, mutate))

    def test_tampered_materials_are_a_proof_error(self):
        raw = self.sign_proof(self.forked_batch())

        def swap_successor(payload):
            payload["chains"][0]["successors"] = [sha256(b"other")]

        def swap_root(payload):
            payload["chains"][0]["root"] = sha256(b"other")

        def drop_material(payload):
            payload["chains"] = payload["chains"][1:]

        def reorder_materials(payload):
            payload["chains"] = list(reversed(payload["chains"]))

        def fix_materials_digest(payload):
            swap_successor(payload)
            payload["materialsDigest"] = sha256(compact(payload["chains"]))

        for mutate in (
            swap_successor, swap_root, drop_material, reorder_materials,
            fix_materials_digest,
        ):
            with self.assertRaises(
                InvalidAggregateForkProofError, msg=mutate.__name__
            ):
                self.vproof(self._resigned(raw, mutate))

    def test_tampered_payload_fields_are_proof_errors(self):
        raw = self.sign_proof(self.forked_batch())

        def bad_version(payload):
            payload["version"] = 2

        def bad_materials_digest(payload):
            payload["materialsDigest"] = sha256(b"other")

        for mutate in (bad_version, bad_materials_digest):
            with self.assertRaises(
                InvalidAggregateForkProofError, msg=mutate.__name__
            ):
                self.vproof(self._resigned(raw, mutate))

    def test_empty_issuer_and_non_positive_key_version_are_value_errors(self):
        raw = self.sign_proof(self.forked_batch())

        def empty_issuer(payload):
            payload["issuer"] = ""

        def zero_key_version(payload):
            payload["keyVersion"] = 0

        for mutate in (empty_issuer, zero_key_version):
            with self.assertRaises(ValueError, msg=mutate.__name__):
                self.vproof(self._resigned(raw, mutate))

    def test_wrong_prune_policy_is_a_proof_error(self):
        raw = self.sign_proof(self.forked_batch())
        other_policy = {
            "batch": "other-batch",
            "sites": {SITE_A: {1}, SITE_B: {1}},
            "threshold": 2,
        }
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(raw, policy=other_policy)

    def test_future_proof_moment_is_a_proof_error(self):
        raw = self.sign_proof(self.forked_batch())
        with self.assertRaises(InvalidAggregateForkProofError):
            self.vproof(raw, moment=self.verify_moment - 1)

    def test_bad_signature_is_authentication_error(self):
        raw = self.sign_proof(self.forked_batch())
        data = parse(raw)
        data["signature"] = hmac_hex("22" * 32, compact(data["payload"]))
        with self.assertRaises(AuthenticationError):
            self.vproof(compact(data))

    def test_revoked_or_unknown_signer_is_authentication_error(self):
        raw = self.sign_proof(self.forked_batch())
        revoked = {
            **self.ring, JUDGE: [entry(1, SECRET_COORD, revoked=True)]
        }
        with self.assertRaises(AuthenticationError):
            self.vproof(raw, ring=revoked)
        unknown = {SITE_A: self.ring[SITE_A]}
        with self.assertRaises(AuthenticationError):
            self.vproof(raw, ring=unknown)

    def test_exact_key_version_with_no_fallback(self):
        ring = {
            **self.ring,
            JUDGE: [entry(2, SECRET_COORD)],
        }
        raw = self.sign_proof(self.forked_batch())
        with self.assertRaises(AuthenticationError):
            self.vproof(raw, ring=ring)

    def test_verify_argument_faults(self):
        raw = self.sign_proof(self.forked_batch())
        with self.assertRaises(ValueError):
            verify_prune_aggregate_fork_proof(
                raw, {"batch": "b"}, self.ring, self.verify_moment
            )
        with self.assertRaises(TypeError):
            self.vproof(raw, moment=True)
        with self.assertRaises(ValueError):
            self.vproof(raw, moment=-1)

    def test_error_class_hierarchy(self):
        self.assertTrue(issubclass(InvalidAggregateForkProofError, ValueError))

    def test_inputs_are_not_modified(self):
        raw = self.sign_proof(self.forked_batch())
        snapshot = bytes(raw)
        policy = copy.deepcopy(self.policy)
        self.vproof(raw)
        self.assertEqual(raw, snapshot)
        self.assertEqual(self.policy, policy)

    def test_no_file_is_read_or_written(self):
        raw = self.sign_proof(self.forked_batch())
        with mock.patch("builtins.open", side_effect=AssertionError("io")):
            self.vproof(raw)


if __name__ == "__main__":
    unittest.main()
