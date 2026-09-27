"""Tests for batch verification of fork aggregate supersession chains.

Covers :func:`verify_fork_aggregate_chains`: the batch container and
shared materials (the invariant pruning and fork-proof site policies)
validated in full before any chain is verified, the per-chain
verified/invalid-root/invalid-chain/unauthenticated taxonomy with
input-order reports and no cross-chain interference, fork detection
grouped by the aggregate root digest (the same predecessor digest
pointing at two distinct successor digests, prefix extensions
excluded), the conflicted reclassification keeping the verified result
with the fixed ``forked-fork-aggregate-chain`` error, the sorted fork
entries with ascending successor digests and crossing ids, the error
hierarchy, equal-but-independent results, input immutability and the
purely offline guarantee.
"""

import copy
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidAggregateForkDecisionAggregateError,
    InvalidForkAggregateChainError,
    verify_fork_aggregate_chains,
)

from test_prune_attestations import JUDGE, SITE_B, SITE_C, sha256
from test_supersede_fork_aggregate import (
    ForkAggregateChainFixtures,
    ditem,
)

REPORT_KEYS = ["error", "id", "result", "status"]
BATCH_REPORT_KEYS = ["forks", "items", "version"]
FORK_KEYS = ["rootDigest", "predecessorDigest", "successors", "ids"]
CHAIN_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "commonDigest",
]


def chain_item(item_id, root, successors, policies):
    """One batch item: a unique id, a root, successors and policies."""
    return {
        "id": item_id,
        "root": root,
        "successors": successors,
        "policies": policies,
    }


class ForkAggregateChainBatchFixtures(ForkAggregateChainFixtures):
    """Chains over shared roots, plus batch helpers."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Two distinct agreeing first successors over the same root.
        self.first_a = self.fsucc(
            self.root_one, [ditem("three", self.decision_b)]
        )
        self.first_b = self.fsucc(
            self.root_one, [ditem("four", self.decision_c)]
        )
        # A distinct first successor that conflicts with the root.
        self.first_c = self.fsucc(
            self.root_one, [ditem("five", self.decision_other)]
        )
        # Two distinct valid second successors over one shared first hop.
        self.second_a = self.fsucc(
            self.first_a, [ditem("six", self.decision_c)],
            moment=self.m + 20, effective=self.m + 5,
        )
        self.second_b = self.fsucc(
            self.first_a, [ditem("seven", self.decision_other)],
            moment=self.m + 20, effective=self.m + 5,
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

    def vchains(self, items, moment=None, prune_policy=None,
                site_policy=None, ring=None):
        return verify_fork_aggregate_chains(
            items,
            self.policy if prune_policy is None else prune_policy,
            self.sp if site_policy is None else site_policy,
            self.ring if ring is None else ring,
            self.m + 20 if moment is None else moment,
        )


class ForkAggregateChainBatchShapeTest(ForkAggregateChainBatchFixtures):
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
        for item_report in report["items"]:
            self.assertEqual(list(item_report.keys()), REPORT_KEYS)
            self.assertEqual(item_report["status"], "verified")
            self.assertIsNone(item_report["error"])
            self.assertEqual(list(item_report["result"].keys()),
                             CHAIN_RESULT_KEYS)
        self.assertEqual(report["items"][0]["result"]["height"], 1)
        self.assertEqual(report["items"][1]["result"]["height"], 0)
        self.assertEqual(report["items"][2]["result"]["height"], 2)
        self.assertEqual(report["items"][1]["result"]["status"], "accepted")

    def test_results_match_single_chain_verification(self):
        items = [self.citem("x", self.root_one, [self.first_a])]
        report = self.vchains(items)
        single = self.fvchain(self.root_one, [self.first_a],
                              moment=self.m + 20)
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


class ForkAggregateChainBatchArgumentTest(ForkAggregateChainBatchFixtures):
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
        with self.assertRaises(ValueError):
            self.vchains([self.citem("x", self.root_one, [self.first_a],
                                     policies=[self.pol_v1])])
        with self.assertRaises(ValueError):
            self.vchains([self.citem("x", self.root_one, [],
                                     policies=[self.pol_v1, self.pol_v1])])
        with self.assertRaises(ValueError):
            self.vchains([self.citem(
                "x", self.root_one, [self.first_a],
                policies=[
                    {"sites": {JUDGE: {1}, SITE_C: {1}}, "threshold": 2,
                     "policyVersion": 2},
                    self.pol_v1,
                ],
            )])
        with self.assertRaises(TypeError):
            self.vchains([self.citem("x", self.root_one, [self.first_a],
                                     policies=[self.pol_v1, "not-a-dict"])])

    def test_shared_material_faults(self):
        items = [self.citem("x", self.root_two, [])]
        with self.assertRaises(ValueError):
            self.vchains(items, prune_policy={
                "batch": "x", "sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.vchains(items, prune_policy="not-a-dict")
        other_site_policy = copy.deepcopy(self.sp)
        other_site_policy["threshold"] = 0
        with self.assertRaises(ValueError):
            self.vchains(items, site_policy=other_site_policy)
        with self.assertRaises(TypeError):
            self.vchains(items, site_policy="not-a-dict")
        with self.assertRaises(TypeError):
            self.vchains(items, ring="not-a-dict")
        with self.assertRaises(TypeError):
            self.vchains(items, moment=True)
        with self.assertRaises(TypeError):
            self.vchains(items, moment="10")
        with self.assertRaises(ValueError):
            self.vchains(items, moment=-1)

    def test_precheck_failure_verifies_no_chain(self):
        items = [
            self.citem("good", self.root_one, [self.first_a]),
            self.citem("bad", self.root_one, [self.first_b],
                       policies=[self.pol_v1]),
        ]
        with self.assertRaises(ValueError):
            self.vchains(items)


class ForkAggregateChainBatchIsolationTest(ForkAggregateChainBatchFixtures):
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
        from test_fork_convergence import compact, parse
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
        from test_fork_convergence import compact, parse
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
        from test_fork_convergence import compact, parse
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


class ForkAggregateChainBatchForkTest(ForkAggregateChainBatchFixtures):
    def test_two_successors_over_one_root_are_a_fork(self):
        report = self.vchains(self.fork_items())
        self.assertEqual([item["id"] for item in report["items"]],
                         ["b", "a"])
        for item in report["items"]:
            self.assertEqual(item["status"], "conflicted")
            self.assertEqual(item["error"], "forked-fork-aggregate-chain")
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
        # A chain whose own head conflicts still keeps that verified
        # conflicted result across the fork edge.
        c_report = next(item for item in report["items"] if item["id"] == "c")
        self.assertEqual(c_report["result"]["status"], "conflicted")

    def test_fork_at_a_later_hop(self):
        items = [
            self.citem("a", self.root_one, [self.first_a, self.second_a]),
            self.citem("b", self.root_one, [self.first_a, self.second_b]),
        ]
        report = self.vchains(items)
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(fork["predecessorDigest"],
                         sha256(self.first_a))
        self.assertEqual(
            fork["successors"],
            sorted([sha256(self.second_a), sha256(self.second_b)]),
        )
        self.assertEqual(fork["ids"], ["a", "b"])

    def test_prefix_extension_is_not_a_fork(self):
        items = [
            self.citem("short", self.root_one, [self.first_a]),
            self.citem("long", self.root_one,
                       [self.first_a, self.second_a]),
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
        other_a = self.fsucc(
            self.root_two, [ditem("three", self.decision_c)])
        other_b = self.fsucc(
            self.root_two, [ditem("four", self.decision_other)])
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
        self.assertEqual(
            [(fork["rootDigest"], fork["predecessorDigest"])
             for fork in report["forks"]],
            sorted((fork["rootDigest"], fork["predecessorDigest"])
                   for fork in report["forks"]),
        )
        self.assertEqual([item["status"] for item in report["items"]],
                         ["conflicted"] * 4)

    def test_failed_chains_never_create_or_cross_forks(self):
        from test_fork_convergence import compact, parse
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


class ForkAggregateChainErrorHierarchyTest(ForkAggregateChainBatchFixtures):
    def test_error_classes(self):
        self.assertTrue(issubclass(InvalidForkAggregateChainError, ValueError))
        self.assertIsNot(InvalidForkAggregateChainError,
                         InvalidAggregateForkDecisionAggregateError)
        self.assertTrue(issubclass(
            InvalidAggregateForkDecisionAggregateError, ValueError))
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class ForkAggregateChainBatchIndependenceTest(ForkAggregateChainBatchFixtures):
    def test_inputs_are_not_modified(self):
        items = self.fork_items()
        snapshot = copy.deepcopy(items)
        prune_snapshot = copy.deepcopy(self.policy)
        site_snapshot = copy.deepcopy(self.sp)
        ring_snapshot = copy.deepcopy(self.ring)
        self.vchains(items)
        self.assertEqual(items, snapshot)
        self.assertEqual(self.policy, prune_snapshot)
        self.assertEqual(self.sp, site_snapshot)
        self.assertEqual(self.ring, ring_snapshot)

    def test_no_file_is_read_or_written(self):
        items = self.fork_items()
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.vchains(items)


if __name__ == "__main__":
    unittest.main()
