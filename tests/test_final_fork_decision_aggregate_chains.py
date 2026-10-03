"""Tests for batch verification and sealed head anchors over final fork
decision aggregate supersession chains.

Covers :func:`verify_final_fork_decision_aggregate_chains`,
:func:`seal_final_fork_decision_aggregate_head` and
:func:`verify_final_fork_decision_aggregate_head`: the batch container
(id/root/successors/policies, unique non-empty ids, one policy per
stage) and the six shared materials validated in full before any chain
runs, the per-chain verified/invalid-root/invalid-chain/unauthenticated
taxonomy in input order with no cross-chain interference, fork
detection scoped to one root digest (a predecessor pointing at
distinct successors is a fork, a prefix extension is not) with forks
sorted by root then predecessor, ascending successor digests and ids,
verified chains crossing a fork reclassified conflicted with their
results kept while failed chains never move, the canonical head anchor
with root/head/height/final-stage policy digest/policy version/
declaration digest/sealedAt/issuer/keyVersion bindings, sealing only a
verified accepted unforked target, offline recomputation and binding
comparison, the sealing-moment ceiling, signature and credential
classification, the distinct anchor error hierarchy, equal-but-
independent results, input immutability and the purely offline
guarantee.
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
    verify_final_fork_decision_aggregate_chain,
    verify_final_fork_decision_aggregate_chains,
    verify_final_fork_decision_aggregate_head,
)

from test_supersede_final_fork_decision_aggregate import (
    FinalForkDecisionAggregateChainFixtures,
)
from test_aggregate_prune_fork_decisions import decision_item
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_chain_fork_aggregate import vpol

JUDGE_B = SITE_C

REPORT_KEYS = ["forks", "items", "version"]
ITEM_KEYS = ["error", "id", "result", "status"]
FORK_KEYS = ["rootDigest", "predecessorDigest", "successors", "ids"]
CHAIN_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "declarationDigest",
]
PACKET_KEYS = ["payload", "signature"]
ANCHOR_PAYLOAD_KEYS = [
    "rootDigest", "headDigest", "height", "policyDigest",
    "policyVersion", "declarationDigest", "sealedAt", "issuer",
    "keyVersion", "version",
]
ANCHOR_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyDigest",
    "policyVersion", "declarationDigest", "anchorDigest",
]

FORKED_ERROR = "forked-final-fork-decision-aggregate-chain"


def chain_item(item_id, root, successors=(), policies=None):
    """One batch item: a unique id, root bytes, successors and policies."""
    return {
        "id": item_id,
        "root": root,
        "successors": list(successors),
        "policies": policies,
    }


class FinalForkDecisionAggregateChainsFixtures(
    FinalForkDecisionAggregateChainFixtures
):
    """Accepted and divergent chains over the insufficient/accepted roots."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.vmoment = self.fm + 20
        self.pv2_3t1 = vpol(
            2, sites=(JUDGE, JUDGE_B, SITE_A), threshold=1)

        # Two distinct accepted first successors over the insufficient
        # one-site root froot_one.
        self.s_grow = self.ffdsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_jb)])
        self.s_t1 = self.ffdsucc(
            self.froot_one, self.froot_one, [],
            old=self.pv1, new=self.pv2_t1)
        self.s_3t1 = self.ffdsucc(
            self.froot_one, self.froot_one, [],
            old=self.pv1, new=self.pv2_3t1)

        # Two distinct accepted second successors over s_grow.
        self.sec_t1 = self.ffdsucc(
            self.froot_one, self.s_grow, [],
            old=self.pv1, new=self.pv2_t1,
            moment=self.fm + 20, effective=self.fm + 5)
        self.sec_3 = self.ffdsucc(
            self.froot_one, self.s_grow, [],
            old=self.pv1, new=self.pv2_3,
            moment=self.fm + 20, effective=self.fm + 5)

        # Two distinct first successors over the accepted froot_two:
        # an accepted rotation and a conflicted declaration extension.
        self.t_rot = self.ffdsucc(
            self.froot_two, self.froot_two, [],
            old=self.pv1, new=self.pv2_t1)
        self.t_conf = self.ffdsucc(
            self.froot_two, self.froot_two,
            [decision_item("c", self.free_c)],
            old=self.pv1, new=self.pv2_3)

    def ffitem(self, item_id, root, successors=(), policies=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        return chain_item(item_id, root, successors, policies)

    def ffreport(self, items, moment=None, ring=None, adjp=None):
        return verify_final_fork_decision_aggregate_chains(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp if adjp is None else adjp,
            self.ring if ring is None else ring,
            self.vmoment if moment is None else moment,
        )

    def bare_one(self, item_id="a"):
        return self.ffitem(item_id, self.froot_two, [])

    def grow_item(self, item_id="b"):
        return self.ffitem(item_id, self.froot_one, [self.s_grow],
                          [self.pv1, self.pv1])

    def ffseal(self, items, target, moment=None, issuer=JUDGE, version=1):
        return seal_final_fork_decision_aggregate_head(
            items, target, self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, self.ring,
            self.vmoment if moment is None else moment, issuer, version,
        )

    def ffverify(self, anchor, items, target, moment=None, ring=None):
        return verify_final_fork_decision_aggregate_head(
            anchor, items, target, self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp,
            self.ring if ring is None else ring,
            self.vmoment if moment is None else moment,
        )

    def ffrewrap(self, payload, moment=None, issuer=None, version=None):
        """Re-seal an edited anchor payload (default JUDGE key)."""
        sign_issuer = payload.get("issuer") if issuer is None else issuer
        sign_version = (
            payload.get("keyVersion") if version is None else version)
        at = self.vmoment if moment is None else moment
        entry = _usable_checkpoint_key(
            _validated_keyring(self.ring), sign_issuer, sign_version, at)
        payload_bytes = _prune_compact(payload)
        signature = hmac.new(
            bytes.fromhex(entry[SECRET]), payload_bytes,
            hashlib.sha256).hexdigest()
        return _prune_compact(
            {"payload": payload, "signature": signature})


class BatchValidationTest(FinalForkDecisionAggregateChainsFixtures,
                         unittest.TestCase):
    def test_non_list_items_is_type_error(self):
        with self.assertRaises(TypeError):
            self.ffreport((self.bare_one(),))

    def test_empty_list_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffreport([])

    def test_non_dict_item_is_type_error(self):
        with self.assertRaises(TypeError):
            self.ffreport(["nope"])

    def test_wrong_item_key_set(self):
        with self.assertRaises(ValueError):
            self.ffreport([{"id": "a", "root": self.froot_two,
                           "successors": [], "policies": [self.pv1],
                           "extra": 1}])

    def test_missing_item_key(self):
        with self.assertRaises(ValueError):
            self.ffreport([{"id": "a", "root": self.froot_two,
                           "successors": []}])

    def test_non_str_id(self):
        with self.assertRaises(TypeError):
            self.ffreport([self.ffitem(1, self.froot_two)])

    def test_empty_id(self):
        with self.assertRaises(ValueError):
            self.ffreport([self.ffitem("", self.froot_two)])

    def test_duplicate_id(self):
        with self.assertRaises(ValueError):
            self.ffreport([self.bare_one("a"), self.grow_item("a")])

    def test_root_must_be_bytes(self):
        with self.assertRaises(TypeError):
            self.ffreport([self.ffitem("a", self.froot_two.hex())])

    def test_successors_must_be_a_list(self):
        item = self.bare_one()
        item["successors"] = (self.s_grow,)
        with self.assertRaises(TypeError):
            self.ffreport([item])

    def test_successor_element_must_be_bytes(self):
        with self.assertRaises(TypeError):
            self.ffreport([self.ffitem(
                "a", self.froot_one, [self.s_grow.hex()],
                [self.pv1, self.pv1])])

    def test_policy_count_must_match_stages(self):
        with self.assertRaises(ValueError):
            self.ffreport([self.ffitem(
                "a", self.froot_one, [self.s_grow], [self.pv1])])

    def test_root_stage_policy_must_be_version_one(self):
        bad = vpol(2)
        with self.assertRaises(ValueError):
            self.ffreport([self.ffitem("a", self.froot_two, [], [bad])])

    def test_bool_moment_never_poses_as_int(self):
        with self.assertRaises(TypeError):
            self.ffreport([self.bare_one()], moment=True)

    def test_negative_moment_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffreport([self.bare_one()], moment=-1)

    def test_illegal_shared_policy_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffreport(
                [self.bare_one()],
                adjp={"sites": {}, "threshold": 1})

    def test_keyring_fault_is_type_error(self):
        with self.assertRaises(TypeError):
            self.ffreport([self.bare_one()], ring={"x": "nope"})


class BatchReportTest(FinalForkDecisionAggregateChainsFixtures,
                      unittest.TestCase):
    def test_report_and_item_key_order(self):
        report = self.ffreport([self.bare_one("a"), self.grow_item("b")])
        self.assertEqual(list(report.keys()), REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["forks"], [])
        for item in report["items"]:
            self.assertEqual(list(item.keys()), ITEM_KEYS)
            self.assertEqual(item["status"], "verified")
            self.assertIsNone(item["error"])
            self.assertIsInstance(item["result"], dict)
            self.assertEqual(
                list(item["result"].keys()), CHAIN_RESULT_KEYS)

    def test_input_order_preserved(self):
        report = self.ffreport([self.grow_item("b"), self.bare_one("a")])
        self.assertEqual([i["id"] for i in report["items"]], ["b", "a"])

    def test_results_match_single_chain_verification(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        report = self.ffreport(items)
        for item, raw in zip(report["items"], items):
            single = verify_final_fork_decision_aggregate_chain(
                raw["root"], raw["successors"], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp, raw["policies"],
                self.ring, self.vmoment)
            self.assertEqual(item["result"], single)

    def test_invalid_root_is_isolated(self):
        report = self.ffreport([
            self.ffitem("bad", b"not-a-packet"),
            self.bare_one("ok")])
        bad, ok = report["items"]
        self.assertEqual(bad["status"], "invalid-root")
        self.assertTrue(bad["error"])
        self.assertIsNone(bad["result"])
        self.assertEqual(ok["status"], "verified")
        self.assertIsNone(ok["error"])

    def test_invalid_chain_is_isolated(self):
        report = self.ffreport([
            self.bare_one("ok"),
            self.ffitem("bad", self.froot_two, [b"{}"],
                       [self.pv1, self.pv1])])
        ok, bad = report["items"]
        self.assertEqual(ok["status"], "verified")
        self.assertEqual(bad["status"], "invalid-chain")
        self.assertTrue(bad["error"])
        self.assertIsNone(bad["result"])

    def test_garbage_root_bytes_are_invalid_root(self):
        for raw in (b"", b"\xff", b"{", b"[]", b'{"payload":{}}'):
            report = self.ffreport([self.ffitem("bad", raw)])
            self.assertEqual(
                report["items"][0]["status"], "invalid-root", raw)

    def test_foreign_policy_digest_is_invalid_root(self):
        foreign = {
            "sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
            "threshold": 1}
        report = self.ffreport([self.bare_one()], adjp=foreign)
        self.assertEqual(report["items"][0]["status"], "invalid-root")

    def test_wrong_keyring_is_unauthenticated(self):
        wrong_ring = copy.deepcopy(self.ring)
        wrong_ring[JUDGE] = [
            dict(wrong_ring[JUDGE][0], secret="00" * 32)]
        report = self.ffreport([self.bare_one()], ring=wrong_ring)
        item = report["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertIsNone(item["result"])
        self.assertIn("signature", item["error"])

    def test_revoked_key_is_unauthenticated(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        report = self.ffreport([self.bare_one()], ring=revoked)
        self.assertEqual(
            report["items"][0]["status"], "unauthenticated")

    def test_failure_kinds_do_not_interfere(self):
        # A signature-tampered root is unauthenticated without a
        # keyring-wide change that would also affect the good chain.
        tampered = json.loads(self.froot_two.decode())
        tampered["signature"] = "00" * 32
        bad_sig_root = _prune_compact(tampered)
        report = self.ffreport([
            self.ffitem("root", b"{}", [], [self.pv1]),
            self.ffitem("chain", self.froot_two, [b"{}"],
                        [self.pv1, self.pv1]),
            self.ffitem("auth", bad_sig_root, [], [self.pv1]),
            self.grow_item("ok")])
        statuses = {i["id"]: i["status"] for i in report["items"]}
        self.assertEqual(statuses, {
            "root": "invalid-root",
            "chain": "invalid-chain",
            "auth": "unauthenticated",
            "ok": "verified",
        })

    def test_equal_but_independent_results(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        first = self.ffreport(items)
        second = self.ffreport(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        first["items"][0]["result"]["status"] = "tampered"
        self.assertEqual(
            self.ffreport(items)["items"][0]["result"]["status"],
            "accepted")

    def test_inputs_are_not_modified(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        snapshot = copy.deepcopy(items)
        self.ffreport(items)
        self.assertEqual(items, snapshot)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file access")):
            self.ffreport(items)


class ForkDetectionTest(FinalForkDecisionAggregateChainsFixtures,
                        unittest.TestCase):
    def test_two_successors_over_one_root_are_a_fork(self):
        report = self.ffreport([
            self.ffitem("b", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("a", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1])])
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["conflicted", "conflicted"])
        fork, = report["forks"]
        self.assertEqual(list(fork.keys()), FORK_KEYS)
        self.assertEqual(
            fork["rootDigest"],
            hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(
            fork["predecessorDigest"],
            hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(fork["successors"], sorted([
            hashlib.sha256(self.s_grow).hexdigest(),
            hashlib.sha256(self.s_t1).hexdigest()]))
        self.assertEqual(fork["ids"], ["a", "b"])
        for item in report["items"]:
            self.assertEqual(item["error"], FORKED_ERROR)
            self.assertIsNotNone(item["result"])

    def test_conflicted_result_keeps_the_verified_chain_summary(self):
        item = self.ffitem("a", self.froot_two, [self.t_conf],
                          [self.pv1, self.pv2_3])
        report = self.ffreport([
            item,
            self.ffitem("b", self.froot_two, [self.t_rot],
                       [self.pv1, self.pv2_t1])])
        target = report["items"][0]
        single = verify_final_fork_decision_aggregate_chain(
            item["root"], item["successors"], self.policy, self.auth,
            self.ssp, self.fsignerp, self.adjp, item["policies"],
            self.ring, self.vmoment)
        self.assertEqual(target["status"], "conflicted")
        self.assertEqual(target["result"], single)
        self.assertEqual(target["result"]["status"], "conflicted")

    def test_three_way_fork_lists_every_successor_and_id(self):
        report = self.ffreport([
            self.ffitem("c", self.froot_one, [self.s_3t1],
                       [self.pv1, self.pv2_3t1]),
            self.ffitem("a", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1])])
        fork, = report["forks"]
        self.assertEqual(len(fork["successors"]), 3)
        self.assertEqual(fork["successors"], sorted(fork["successors"]))
        self.assertEqual(fork["ids"], ["a", "b", "c"])

    def test_fork_at_a_later_hop(self):
        report = self.ffreport([
            self.ffitem("a", self.froot_one,
                       [self.s_grow, self.sec_t1],
                       [self.pv1, self.pv1, self.pv2_t1]),
            self.ffitem("b", self.froot_one,
                       [self.s_grow, self.sec_3],
                       [self.pv1, self.pv1, self.pv2_3])])
        fork, = report["forks"]
        self.assertEqual(
            fork["predecessorDigest"],
            hashlib.sha256(self.s_grow).hexdigest())
        self.assertEqual(fork["ids"], ["a", "b"])

    def test_prefix_extension_is_not_a_fork(self):
        report = self.ffreport([
            self.ffitem("long", self.froot_one,
                       [self.s_grow, self.sec_t1],
                       [self.pv1, self.pv1, self.pv2_t1]),
            self.ffitem("short", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("bare", self.froot_one)])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["verified", "verified", "verified"])

    def test_identical_chains_are_not_a_fork(self):
        report = self.ffreport([
            self.ffitem("a", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1])])
        self.assertEqual(report["forks"], [])

    def test_forks_under_different_roots_are_distinct_and_sorted(self):
        report = self.ffreport([
            self.ffitem("a", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1]),
            self.ffitem("c", self.froot_two, [self.t_rot],
                       [self.pv1, self.pv2_t1]),
            self.ffitem("d", self.froot_two, [self.t_conf],
                       [self.pv1, self.pv2_3])])
        self.assertEqual(len(report["forks"]), 2)
        roots = [f["rootDigest"] for f in report["forks"]]
        self.assertEqual(roots, sorted(roots))
        by_root = {f["rootDigest"]: f["ids"] for f in report["forks"]}
        self.assertEqual(
            by_root[hashlib.sha256(self.froot_one).hexdigest()],
            ["a", "b"])
        self.assertEqual(
            by_root[hashlib.sha256(self.froot_two).hexdigest()],
            ["c", "d"])

    def test_failed_chains_never_create_or_cross_forks(self):
        # A failed chain carrying the same successor as a verified one
        # neither hides nor creates a fork; with only one *verified*
        # successor per predecessor there is no fork at all.
        report = self.ffreport([
            self.ffitem("ok", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("bad", self.froot_one, [self.s_t1, b"{}"],
                       [self.pv1, self.pv2_t1, self.pv2_t1])])
        self.assertEqual(report["forks"], [])
        statuses = {i["id"]: i["status"] for i in report["items"]}
        self.assertEqual(statuses, {"ok": "verified", "bad": "invalid-chain"})


class SealAnchorShapeTest(FinalForkDecisionAggregateChainsFixtures,
                          unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = [self.bare_one("a"), self.grow_item("b")]
        self.raw = self.ffseal(self.items, "a")
        self.data = json.loads(self.raw.decode())

    def test_envelope_and_payload_keys(self):
        self.assertEqual(list(self.data.keys()), PACKET_KEYS)
        self.assertEqual(
            set(self.data["payload"]), set(ANCHOR_PAYLOAD_KEYS))

    def test_canonical_compact_encoding(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertFalse(self.raw.endswith(b"\n"))
        self.assertEqual(
            _prune_compact(json.loads(self.raw.decode())), self.raw)
        self.assertNotIn(b" ", self.raw)

    def test_payload_bindings(self):
        payload = self.data["payload"]
        result = self.ffreport(self.items)["items"][0]["result"]
        self.assertEqual(payload["rootDigest"], result["rootDigest"])
        self.assertEqual(payload["headDigest"], result["headDigest"])
        self.assertEqual(payload["height"], 0)
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(
            payload["policyDigest"], _pac_policy_digest(self.pv1))
        self.assertEqual(
            payload["declarationDigest"], result["declarationDigest"])
        self.assertEqual(payload["sealedAt"], self.vmoment)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)

    def test_signed_with_exact_issuer_version_key(self):
        entry = _usable_checkpoint_key(
            _validated_keyring(self.ring), JUDGE, 1, self.vmoment)
        expected = hmac.new(
            bytes.fromhex(entry[SECRET]),
            _prune_compact(self.data["payload"]),
            hashlib.sha256).hexdigest()
        self.assertEqual(self.data["signature"], expected)

    def test_sealing_is_deterministic(self):
        self.assertEqual(
            self.ffseal(self.items, "a"), self.ffseal(self.items, "a"))

    def test_multi_hop_head_binds_the_final_stage_policy(self):
        item = self.ffitem(
            "h", self.froot_one, [self.s_grow, self.sec_t1],
            [self.pv1, self.pv1, self.pv2_t1])
        raw = self.ffseal([item], "h")
        payload = json.loads(raw.decode())["payload"]
        result = self.ffreport([item])["items"][0]["result"]
        self.assertEqual(payload["height"], 2)
        self.assertEqual(payload["policyVersion"], 2)
        self.assertEqual(
            payload["policyDigest"], _pac_policy_digest(self.pv2_t1))
        self.assertEqual(payload["headDigest"], result["headDigest"])
        self.assertEqual(
            payload["headDigest"],
            hashlib.sha256(self.sec_t1).hexdigest())


class SealGuardTest(FinalForkDecisionAggregateChainsFixtures,
                    unittest.TestCase):
    def test_other_chains_failures_do_not_block_target(self):
        raw = self.ffseal([
            self.bare_one("a"),
            self.ffitem("bad", b"{}")], "a")
        self.assertIsInstance(raw, bytes)

    def test_conflicted_target_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffseal([
                self.ffitem("a", self.froot_one, [self.s_grow],
                           [self.pv1, self.pv1]),
                self.ffitem("b", self.froot_one, [self.s_t1],
                           [self.pv1, self.pv2_t1])], "a")

    def test_insufficient_head_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffseal([self.ffitem("a", self.froot_one)], "a")

    def test_conflicted_head_status_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffseal([
                self.ffitem("a", self.froot_two, [self.t_conf],
                           [self.pv1, self.pv2_3])], "a")

    def test_invalid_root_target_raises_root_error(self):
        with self.assertRaises(
            InvalidFinalAggregateChainForkDecisionAggregateError
        ):
            self.ffseal([self.ffitem("a", b"{}")], "a")

    def test_invalid_chain_target_raises_chain_error(self):
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self.ffseal([
                self.ffitem("a", self.froot_two, [b"{}"],
                           [self.pv1, self.pv1])], "a")

    def test_unauthenticated_target_raises_authentication_error(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.seal_with_ring(revoked)

    def seal_with_ring(self, ring):
        return seal_final_fork_decision_aggregate_head(
            [self.bare_one("a")], "a", self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, ring, self.vmoment, JUDGE, 1)

    def test_unknown_target(self):
        with self.assertRaises(ValueError):
            self.ffseal([self.bare_one("a")], "missing")

    def test_target_validation(self):
        with self.assertRaises(TypeError):
            self.ffseal([self.bare_one("a")], 7)
        with self.assertRaises(ValueError):
            self.ffseal([self.bare_one("a")], "")

    def test_signer_validation(self):
        items = [self.bare_one("a")]
        with self.assertRaises(TypeError):
            self.ffseal(items, "a", issuer=7)
        with self.assertRaises(ValueError):
            self.ffseal(items, "a", issuer="")
        with self.assertRaises(TypeError):
            self.ffseal(items, "a", version=True)
        with self.assertRaises(ValueError):
            self.ffseal(items, "a", version=0)

    def test_unknown_signer_credential_is_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.ffseal([self.bare_one("a")], "a", issuer="nobody", version=1)

    def test_moment_validation(self):
        with self.assertRaises(TypeError):
            self.ffseal([self.bare_one("a")], "a", moment=True)
        with self.assertRaises(ValueError):
            self.ffseal([self.bare_one("a")], "a", moment=-1)


class VerifyAnchorTest(FinalForkDecisionAggregateChainsFixtures,
                       unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = [self.bare_one("a"), self.grow_item("b")]
        self.raw = self.ffseal(self.items, "a")

    def test_success_result(self):
        result = self.ffverify(self.raw, self.items, "a")
        self.assertEqual(list(result.keys()), ANCHOR_RESULT_KEYS)
        single = self.ffreport(self.items)["items"][0]["result"]
        self.assertEqual(result["rootDigest"], single["rootDigest"])
        self.assertEqual(result["headDigest"], single["headDigest"])
        self.assertEqual(result["height"], single["height"])
        self.assertEqual(result["policyVersion"], single["policyVersion"])
        self.assertEqual(
            result["declarationDigest"], single["declarationDigest"])
        self.assertEqual(
            result["policyDigest"], _pac_policy_digest(self.pv1))
        self.assertEqual(
            result["anchorDigest"], hashlib.sha256(self.raw).hexdigest())

    def test_equal_but_independent_results(self):
        first = self.ffverify(self.raw, self.items, "a")
        second = self.ffverify(self.raw, self.items, "a")
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["height"] = 99
        self.assertEqual(
            self.ffverify(self.raw, self.items, "a")["height"], 0)

    def test_bad_signature_is_authentication_error(self):
        data = json.loads(self.raw.decode())
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.ffverify(_prune_compact(data), self.items, "a")

    def test_unknown_or_revoked_signer_is_authentication_error(self):
        dropped = {site: self.ring[site]
                   for site in self.ring if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            self.ffverify(self.raw, self.items, "a", ring=dropped)
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.ffverify(self.raw, self.items, "a", ring=revoked)

    def test_expired_signer_at_verify_moment_is_authentication_error(self):
        expired = copy.deepcopy(self.ring)
        expired[JUDGE][0]["notAfter"] = self.vmoment - 1
        with self.assertRaises(AuthenticationError):
            self.ffverify(self.raw, self.items, "a", ring=expired)

    def test_sealed_at_later_than_moment_is_anchor_error(self):
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.raw, self.items, "a", moment=self.vmoment - 1)

    def test_height_binding_tamper_is_anchor_error(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["height"] = 5
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.ffrewrap(payload), self.items, "a")

    def test_root_binding_tamper_is_anchor_error(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["rootDigest"] = "0" * 64
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.ffrewrap(payload), self.items, "a")

    def test_head_binding_tamper_is_anchor_error(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["headDigest"] = "1" * 64
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.ffrewrap(payload), self.items, "a")

    def test_policy_digest_binding_tamper_is_anchor_error(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["policyDigest"] = "2" * 64
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.ffrewrap(payload), self.items, "a")

    def test_declaration_digest_binding_tamper_is_anchor_error(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["declarationDigest"] = None
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.ffrewrap(payload), self.items, "a")

    def test_wrong_version_is_anchor_error(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["version"] = 2
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.ffrewrap(payload), self.items, "a")

    def test_extra_payload_key_is_anchor_error(self):
        payload = json.loads(self.raw.decode())["payload"]
        payload["extra"] = 1
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.ffrewrap(payload), self.items, "a")

    def test_non_canonical_encoding_is_anchor_error(self):
        raw = self.raw.replace(b":", b": ", 1)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(raw, self.items, "a")

    def test_trailing_byte_is_anchor_error(self):
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.raw + b"\n", self.items, "a")

    def test_garbage_bytes_are_anchor_error(self):
        for raw in (b"", b"\xff", b"{", b'{"payload":{}}'):
            with self.assertRaises(
                InvalidFinalForkDecisionAggregateAnchorError
            ):
                self.ffverify(raw, self.items, "a")

    def test_json_array_is_type_error(self):
        with self.assertRaises(TypeError):
            self.ffverify(b"[]", self.items, "a")

    def test_target_head_drifted_is_anchor_error(self):
        # Same id and root, but the chain now extends by one accepted
        # hop, so the head digest and height drift off the anchor.
        extended = [self.ffitem("a", self.froot_two, [self.t_rot],
                               [self.pv1, self.pv2_t1])]
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.raw, extended, "a")

    def test_target_became_conflicted_is_anchor_error(self):
        # The same id now walks a forking successor edge, so it no
        # longer verifies without a fork (its head drifts as well).
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateAnchorError
        ):
            self.ffverify(self.raw, [
                self.ffitem("a", self.froot_two, [self.t_rot],
                           [self.pv1, self.pv2_t1]),
                self.ffitem("z", self.froot_two, [self.t_conf],
                           [self.pv1, self.pv2_3])], "a")

    def test_target_root_error_still_classified_as_root_error(self):
        with self.assertRaises(
            InvalidFinalAggregateChainForkDecisionAggregateError
        ):
            self.ffverify(self.raw, [self.ffitem("a", b"{}")], "a")

    def test_target_chain_error_still_classified_as_chain_error(self):
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self.ffverify(self.raw, [
                self.ffitem("a", self.froot_two, [b"{}"],
                           [self.pv1, self.pv1])], "a")

    def test_anchor_argument_faults(self):
        with self.assertRaises(TypeError):
            self.ffverify("bytes", self.items, "a")
        with self.assertRaises(TypeError):
            self.ffverify(self.raw, self.items, 7)
        with self.assertRaises(ValueError):
            self.ffverify(self.raw, self.items, "")
        with self.assertRaises(ValueError):
            self.ffverify(self.raw, self.items, "missing")
        with self.assertRaises(TypeError):
            self.ffverify(self.raw, self.items, "a", moment=True)
        with self.assertRaises(ValueError):
            self.ffverify(self.raw, self.items, "a", moment=-1)

    def test_error_classes_are_distinct(self):
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateAnchorError, ValueError))
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateAnchorError,
            InvalidFinalForkDecisionAggregateChainError)
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateAnchorError,
            InvalidFinalAggregateChainForkDecisionAggregateError)

    def test_inputs_are_not_modified(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        snapshot = copy.deepcopy((items, self.raw))
        self.ffverify(self.raw, items, "a")
        self.assertEqual((items, self.raw), snapshot)

    def test_no_file_is_read_or_written(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.ffreport(self.items)
            self.ffseal(self.items, "a")
            self.ffverify(self.raw, self.items, "a")


if __name__ == "__main__":
    unittest.main()
