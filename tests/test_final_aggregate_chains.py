"""Tests for final aggregate chain batches and sealed head anchors.

Covers :func:`verify_final_aggregate_chains`,
:func:`seal_final_aggregate_head` and
:func:`verify_final_aggregate_head`: the upfront whole-batch validation
(container, element and field types, empty or duplicate ids, wrong key
sets and policy counts), the isolated per-chain verdicts (``verified``,
``invalid-root``, ``invalid-chain``, ``unauthenticated``) in strict
input order, same-root successor fork detection (a shared predecessor
digest pointing at two distinct successor digests, while a plain prefix
extension is not a fork), the ``conflicted`` reclassification keeping
the verified result with the ``forked-final-aggregate-chain`` error,
the stably sorted fork summaries, the sealed head anchor over a
verified, accepted, unforked target (binding the root and head digests,
the height, the head policy digest and version, the declaration digest,
the sealing moment and the issuer/key version under HMAC-SHA256), the
offline anchor re-verification (signature, sealing moment, batch
conclusion and every binding), the distinct
:class:`InvalidFinalAggregateAnchorError` /
:class:`InvalidFinalAggregateChainError` /
:class:`InvalidAggregateDecisionChainForkDecisionAggregateError`
hierarchy, and the input immutability and purely offline guarantees.
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
    InvalidAggregateDecisionChainForkDecisionAggregateError,
    InvalidFinalAggregateAnchorError,
    InvalidFinalAggregateChainError,
    seal_final_aggregate_head,
    verify_final_aggregate_chains,
    verify_final_aggregate_head,
)

from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_chain_fork_aggregate import chain_item, vpol
from test_supersede_decision_aggregate import rewrap
from test_supersede_final_aggregate import FinalAggregateChainFixtures

JUDGE_B = SITE_C

PACKET_KEYS = ["payload", "signature"]
REPORT_KEYS = ["error", "id", "result", "status"]
BATCH_REPORT_KEYS = ["forks", "items", "version"]
FORK_KEYS = ["rootDigest", "predecessorDigest", "successors", "ids"]
ANCHOR_PAYLOAD_KEYS = [
    "declarationDigest", "headDigest", "height", "issuer", "keyVersion",
    "moment", "policyDigest", "policyVersion", "rootDigest", "version",
]
ANCHOR_RESULT_KEYS = [
    "rootDigest", "headDigest", "height", "policyDigest", "policyVersion",
    "declarationDigest", "anchorDigest",
]

FORKED_ERROR = "forked-final-aggregate-chain"


class FinalAggregateBatchFixtures(FinalAggregateChainFixtures):
    """Batch and anchor builders over the final-layer chain fixtures."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Two successors growing the same root predecessor along
        # different packets, plus a second hop extending the first.
        self.first_a = self.fagsucc(
            self.froot_one, self.froot_one,
            [decision_item("two", self.decision_b)])
        self.first_b = self.fagsucc(
            self.froot_one, self.froot_one, [],
            old=self.pv1, new=self.pv2_t1)
        self.second_a = self.fagsucc(
            self.froot_one, self.first_a,
            [decision_item("three", self.free_c)],
            old=self.pv1, new=self.pv1,
            moment=self.fm + 20, effective=self.fm + 5)

    def fgitem(self, item_id, root, successors, policies=None):
        if policies is None:
            policies = [self.pv1] * (len(successors) + 1)
        return chain_item(item_id, root, successors, policies)

    def fagchains(self, items, moment=None, ring=None):
        return verify_final_aggregate_chains(
            items, self.policy, self.auth, self.ssp, self.signerp,
            self.ring if ring is None else ring,
            self.fm + 20 if moment is None else moment)


class ChainBatchTest(FinalAggregateBatchFixtures):
    def test_batch_validated_upfront(self):
        with self.assertRaises(TypeError):
            self.fagchains("x")
        with self.assertRaises(ValueError):
            self.fagchains([])
        with self.assertRaises(ValueError):
            self.fagchains([
                self.fgitem("a", self.froot_one, [self.first_a]),
                self.fgitem("a", self.froot_one, [self.first_a]),
            ])
        with self.assertRaises(ValueError):
            self.fagchains([
                {"id": "a", "root": self.froot_one,
                 "successors": [self.first_a]},
            ])
        with self.assertRaises(ValueError):
            self.fagchains([
                {"id": "a", "root": self.froot_one,
                 "successors": [self.first_a], "policies": [self.pv1]},
            ])
        with self.assertRaises(TypeError):
            self.fagchains([self.fgitem(1, self.froot_one, [self.first_a])])
        with self.assertRaises(ValueError):
            self.fagchains([self.fgitem("", self.froot_one, [self.first_a])])

    def test_verified_report_in_input_order(self):
        report = self.fagchains([
            self.fgitem("a", self.froot_one, [self.first_a]),
            self.fgitem("bad", b"{}", []),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual([r["id"] for r in report["items"]], ["a", "bad"])
        self.assertEqual([r["status"] for r in report["items"]],
                         ["verified", "invalid-root"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), REPORT_KEYS)
        self.assertIsNone(report["items"][0]["error"])
        self.assertIsNotNone(report["items"][1]["error"])
        self.assertIsNone(report["items"][1]["result"])

    def test_invalid_chain_is_isolated_from_unauthenticated(self):
        payload = parse(self.first_a)["payload"]
        payload["height"] = 9
        tampered = rewrap(payload)
        noauth_succ = self.fagsucc(
            self.froot_two, self.froot_two, [],
            old=self.pv1, new=self.pv2_t1, issuer=JUDGE_B)
        ring = {site: self.ring[site] for site in self.ring
                if site != JUDGE_B}
        report = self.fagchains([
            self.fgitem("bad", self.froot_one, [tampered]),
            self.fgitem("noauth", self.froot_two, [noauth_succ],
                        policies=[self.pv1, self.pv2_t1]),
        ], ring=ring)
        statuses = {r["id"]: r["status"] for r in report["items"]}
        self.assertEqual(statuses["bad"], "invalid-chain")
        self.assertEqual(statuses["noauth"], "unauthenticated")
        for row in report["items"]:
            self.assertTrue(row["error"])
            self.assertIsNone(row["result"])

    def test_same_predecessor_two_successors_is_a_fork(self):
        report = self.fagchains([
            self.fgitem("b", self.froot_one, [self.first_b],
                        policies=[self.pv1, self.pv2_t1]),
            self.fgitem("a", self.froot_one, [self.first_a]),
        ])
        statuses = {r["id"]: r["status"] for r in report["items"]}
        self.assertEqual(statuses["a"], "conflicted")
        self.assertEqual(statuses["b"], "conflicted")
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(list(fork.keys()), FORK_KEYS)
        self.assertEqual(fork["rootDigest"],
                         hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(fork["predecessorDigest"],
                         hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(fork["ids"], ["a", "b"])
        self.assertEqual(
            fork["successors"],
            sorted([hashlib.sha256(self.first_a).hexdigest(),
                    hashlib.sha256(self.first_b).hexdigest()]))
        for row in report["items"]:
            if row["status"] == "conflicted":
                self.assertEqual(row["error"], FORKED_ERROR)
                self.assertIsNotNone(row["result"])

    def test_prefix_extension_is_not_a_fork(self):
        report = self.fagchains([
            self.fgitem("short", self.froot_one, [self.first_a]),
            self.fgitem("long", self.froot_one,
                        [self.first_a, self.second_a],
                        policies=[self.pv1, self.pv1, self.pv1]),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]], ["verified", "verified"])

    def test_conflicted_chain_keeps_verified_result(self):
        report = self.fagchains([
            self.fgitem("a", self.froot_one, [self.first_a]),
            self.fgitem("b", self.froot_one, [self.first_b],
                        policies=[self.pv1, self.pv2_t1]),
        ])
        row = report["items"][0]
        self.assertEqual(row["result"]["status"], "accepted")
        self.assertEqual(row["result"]["height"], 1)

    def test_different_roots_are_never_compared(self):
        report = self.fagchains([
            self.fgitem("a", self.froot_one, [self.first_a]),
            self.fgitem("b", self.froot_two, []),
        ])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]], ["verified", "verified"])

    def test_fork_summaries_are_stable_sorted(self):
        items = [
            self.fgitem("b", self.froot_one, [self.first_b],
                        policies=[self.pv1, self.pv2_t1]),
            self.fgitem("a", self.froot_one, [self.first_a]),
        ]
        report = self.fagchains(items)
        again = self.fagchains(copy.deepcopy(items))
        self.assertEqual(report["forks"], again["forks"])
        forks = report["forks"][0]
        self.assertEqual(forks["successors"], sorted(forks["successors"]))
        self.assertEqual(forks["ids"], sorted(forks["ids"]))


class AnchorTest(FinalAggregateBatchFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = [self.fgitem("t", self.froot_one, [self.first_a])]

    def fgseal(self, items=None, target="t", moment=None, issuer=JUDGE,
               version=1):
        return seal_final_aggregate_head(
            self.items if items is None else items, target,
            self.policy, self.auth, self.ssp, self.signerp, self.ring,
            self.fm + 20 if moment is None else moment, issuer, version)

    def fgverify(self, anchor, items=None, target="t", moment=None):
        return verify_final_aggregate_head(
            anchor, self.items if items is None else items, target,
            self.policy, self.auth, self.ssp, self.signerp, self.ring,
            self.fm + 20 if moment is None else moment)

    def test_seal_and_verify_accepted_unforked_head(self):
        anchor = self.fgseal()
        self.assertEqual(list(parse(anchor).keys()), PACKET_KEYS)
        self.assertEqual(list(parse(anchor)["payload"].keys()),
                         ANCHOR_PAYLOAD_KEYS)
        result = self.fgverify(anchor)
        self.assertEqual(list(result.keys()), ANCHOR_RESULT_KEYS)
        self.assertEqual(result["rootDigest"],
                         hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(self.first_a).hexdigest())
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["policyVersion"], 1)
        from offline_coordination.replication import _pac_site_policy_bytes
        self.assertEqual(result["policyDigest"],
                         hashlib.sha256(
                             _pac_site_policy_bytes(self.pv1)).hexdigest())
        self.assertEqual(
            result["declarationDigest"],
            hashlib.sha256(compact(
                parse(self.first_a)["payload"]["declaration"])).hexdigest())
        self.assertEqual(result["anchorDigest"],
                         hashlib.sha256(anchor).hexdigest())

    def test_conflicted_or_invalid_target_is_not_sealable(self):
        items = [
            self.fgitem("t", self.froot_one, [self.first_a]),
            self.fgitem("f", self.froot_one, [self.first_b],
                        policies=[self.pv1, self.pv2_t1]),
        ]
        with self.assertRaises(ValueError):
            self.fgseal(items=items, target="t")
        with self.assertRaises(ValueError):
            self.fgseal(items=items, target="f")
        with self.assertRaises(ValueError):
            self.fgseal(items=items, target="missing")

    def test_insufficient_head_is_not_sealable(self):
        items = [self.fgitem("t", self.froot_one, [])]
        with self.assertRaises(ValueError):
            self.fgseal(items=items)

    def test_conflicted_head_is_not_sealable(self):
        items = [self.fgitem("t", self.froot_conf, [])]
        with self.assertRaises(ValueError):
            self.fgseal(items=items)

    def test_bare_root_accepted_head_can_be_anchored(self):
        items = [self.fgitem("t", self.froot_two, [])]
        anchor = seal_final_aggregate_head(
            items, "t", self.policy, self.auth, self.ssp, self.signerp,
            self.ring, self.fm + 20, JUDGE, 1)
        result = verify_final_aggregate_head(
            anchor, items, "t", self.policy, self.auth, self.ssp,
            self.signerp, self.ring, self.fm + 20)
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["headDigest"],
                         hashlib.sha256(self.froot_two).hexdigest())
        self.assertIsNotNone(result["declarationDigest"])

    def test_bad_root_target_raises_root_error(self):
        items = [self.fgitem("t", b"{}", [])]
        with self.assertRaises(
                InvalidAggregateDecisionChainForkDecisionAggregateError):
            self.fgseal(items=items)
        anchor = self.fgseal()
        with self.assertRaises(
                InvalidAggregateDecisionChainForkDecisionAggregateError):
            self.fgverify(anchor, items=items)

    def test_bad_successor_target_raises_chain_error(self):
        payload = parse(self.first_a)["payload"]
        payload["height"] = 9
        tampered = rewrap(payload)
        items = [self.fgitem("t", self.froot_one, [tampered])]
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fgseal(items=items)
        anchor = self.fgseal()
        with self.assertRaises(InvalidFinalAggregateChainError):
            self.fgverify(anchor, items=items)

    def test_tampered_anchor_binding_rejected(self):
        anchor = self.fgseal()
        payload = parse(anchor)["payload"]
        payload["height"] = 2
        with self.assertRaises(InvalidFinalAggregateAnchorError):
            self.fgverify(rewrap(payload))

    def test_tampered_anchor_declaration_binding_rejected(self):
        anchor = self.fgseal()
        payload = parse(anchor)["payload"]
        payload["declarationDigest"] = "0" * 64
        with self.assertRaises(InvalidFinalAggregateAnchorError):
            self.fgverify(rewrap(payload))

    def test_bad_anchor_signature_is_authentication_error(self):
        anchor = self.fgseal()
        data = parse(anchor)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.fgverify(compact(data))

    def test_future_sealing_moment_is_an_anchor_error(self):
        future_anchor = self.fgseal(moment=self.fm + 30)
        with self.assertRaises(InvalidFinalAggregateAnchorError):
            self.fgverify(future_anchor, moment=self.fm + 20)
        # The same anchor verifies once the verification moment catches up.
        self.assertEqual(
            self.fgverify(future_anchor, moment=self.fm + 30)["height"], 1)

    def test_anchor_signature_checked_against_current_key(self):
        anchor = self.fgseal()
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            verify_final_aggregate_head(
                anchor, self.items, "t", self.policy, self.auth, self.ssp,
                self.signerp, ring, self.fm + 20)

    def test_anchor_rejected_when_chain_later_forks(self):
        anchor = self.fgseal()
        items = [
            self.fgitem("t", self.froot_one, [self.first_a]),
            self.fgitem("f", self.froot_one, [self.first_b],
                        policies=[self.pv1, self.pv2_t1]),
        ]
        with self.assertRaises(InvalidFinalAggregateAnchorError):
            self.fgverify(anchor, items=items)

    def test_anchor_structural_faults(self):
        anchor = self.fgseal()
        pretty = json.dumps(parse(anchor), indent=2).encode()
        with self.assertRaises(InvalidFinalAggregateAnchorError):
            self.fgverify(pretty)
        with self.assertRaises(InvalidFinalAggregateAnchorError):
            self.fgverify(anchor + b"\n")
        data = parse(anchor)
        del data["payload"]["declarationDigest"]
        with self.assertRaises(InvalidFinalAggregateAnchorError):
            self.fgverify(compact(data))
        data = parse(anchor)
        data["payload"]["declarationDigest"] = 7
        with self.assertRaises(TypeError):
            self.fgverify(compact(data))
        data = parse(anchor)
        data["payload"]["version"] = 2
        with self.assertRaises(InvalidFinalAggregateAnchorError):
            self.fgverify(compact(data))

    def test_anchor_error_is_distinct_from_chain_error(self):
        self.assertIsNot(InvalidFinalAggregateAnchorError,
                         InvalidFinalAggregateChainError)
        self.assertTrue(
            issubclass(InvalidFinalAggregateAnchorError, ValueError))

    def test_anchor_type_and_value_faults(self):
        with self.assertRaises(TypeError):
            self.fgseal(target=7)
        with self.assertRaises(ValueError):
            self.fgseal(target="")
        with self.assertRaises(TypeError):
            self.fgseal(issuer=9)
        with self.assertRaises(ValueError):
            self.fgseal(issuer="")
        with self.assertRaises(TypeError):
            self.fgseal(version=True)
        with self.assertRaises(ValueError):
            self.fgseal(version=0)
        with self.assertRaises(TypeError):
            verify_final_aggregate_head(
                "x", self.items, "t", self.policy, self.auth, self.ssp,
                self.signerp, self.ring, self.fm + 20)


class ImmutabilityAndOfflineTest(FinalAggregateBatchFixtures):
    def test_batch_inputs_are_not_modified(self):
        items = [
            self.fgitem("a", self.froot_one, [self.first_a]),
            self.fgitem("b", self.froot_one, [self.first_b],
                        policies=[self.pv1, self.pv2_t1]),
        ]
        snapshot = copy.deepcopy(
            (items, self.policy, self.auth, self.ssp, self.signerp,
             self.ring))
        self.fagchains(items)
        self.assertEqual(
            (items, self.policy, self.auth, self.ssp, self.signerp,
             self.ring), snapshot)

    def test_repeated_batch_results_are_independent(self):
        items = [self.fgitem("a", self.froot_two, [])]
        first = self.fagchains(items)
        second = self.fagchains(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0], second["items"][0])

    def test_anchor_inputs_are_not_modified(self):
        items = [self.fgitem("t", self.froot_one, [self.first_a])]
        snapshot = copy.deepcopy(
            (items, self.policy, self.auth, self.ssp, self.signerp,
             self.ring))
        anchor = seal_final_aggregate_head(
            items, "t", self.policy, self.auth, self.ssp, self.signerp,
            self.ring, self.fm + 20, JUDGE, 1)
        verify_final_aggregate_head(
            anchor, items, "t", self.policy, self.auth, self.ssp,
            self.signerp, self.ring, self.fm + 20)
        self.assertEqual(
            (items, self.policy, self.auth, self.ssp, self.signerp,
             self.ring), snapshot)

    def test_no_file_is_read_or_written(self):
        items = [self.fgitem("t", self.froot_one, [self.first_a])]
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.fagchains(items)
            anchor = seal_final_aggregate_head(
                items, "t", self.policy, self.auth, self.ssp, self.signerp,
                self.ring, self.fm + 20, JUDGE, 1)
            verify_final_aggregate_head(
                anchor, items, "t", self.policy, self.auth, self.ssp,
                self.signerp, self.ring, self.fm + 20)


if __name__ == "__main__":
    unittest.main()
