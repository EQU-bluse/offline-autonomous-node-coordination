"""End-to-end regression boundary for the final fork decision aggregate
chain fork pipeline.

Exercises the complete path across the five public entry points as one
integrated flow: batch chain verification
(:func:`verify_final_fork_decision_aggregate_chains`), fork proof
issuance (:func:`sign_final_fork_decision_aggregate_chain_fork_proof`),
multi-proof verification
(:func:`verify_final_fork_decision_aggregate_chain_fork_proofs`),
cross-site threshold adjudication
(:func:`adjudicate_final_fork_decision_aggregate_chain_forks`) and
decision review
(:func:`verify_final_fork_decision_aggregate_chain_fork_decision`).

Covered end to end: legitimate same-root fork-free batches attested
with the empty fork edge set still signing, verifying and adjudicating;
one predecessor gaining distinct successors producing the complete
stably sorted edge set; the accepted/insufficient/conflicted/duplicate
multi-site rulings; input-order independence of the sealed decision
bytes, equal-but-independent repeated results and input immutability;
reordered bound digests or rows rejected even when re-signed; per-item
batch isolation (invalid-proof vs unauthenticated) with later items
unaffected; batch container and shared-policy faults raising TypeError
or ValueError; every fixed adjudication rejection reason; the six
policy digests, per-row proof digests, common edge set, status and
signature of a legitimate decision all re-checkable offline; and the
purely offline guarantee of every entry point.  Standard library only;
no runtime code is touched.
"""

import copy
import hashlib
import hmac
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidFinalForkDecisionAggregateChainForkDecisionError,
    InvalidFinalForkDecisionAggregateChainForkProofError,
    _prune_batch_site_policy_bytes,
    _verdict_policy_bytes,
    adjudicate_final_fork_decision_aggregate_chain_forks,
    sign_final_fork_decision_aggregate_chain_fork_proof,
    verify_final_fork_decision_aggregate_chain_fork_decision,
    verify_final_fork_decision_aggregate_chain_fork_proofs,
    verify_final_fork_decision_aggregate_chains,
)

from test_final_fork_decision_aggregate_chain_fork_proofs import (
    FinalForkDecisionAggregateChainForkFixtures,
)
from test_adjudicate_prune_aggregate_forks import proof_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_supersede_decision_aggregate import rewrap
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C

EDGE_KEYS = ["predecessorDigest", "rootDigest", "successors"]
SIX_DIGEST_FIELDS = [
    "prunePolicyDigest", "authorizationPolicyDigest", "sitePolicyDigest",
    "signerSitePolicyDigest", "adjudicationSitePolicyDigest",
    "proofSitePolicyDigest",
]


def sha256_hex(raw):
    return hashlib.sha256(raw).hexdigest()


class ForkPipelineEndToEndFixtures(
    FinalForkDecisionAggregateChainForkFixtures
):
    """End-to-end batches: fork-free, single-fork and deep-fork."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Three same-root chains forking twice: at the root edge (s_t1
        # vs s_grow) and one level down at the shared predecessor
        # s_grow (sec_t1 vs sec_3).
        self.deep_items = [
            self.ffitem("c", self.froot_one, [self.s_grow, self.sec_3],
                        [self.pv1, self.pv1, self.pv2_3]),
            self.ffitem("a", self.froot_one, [self.s_t1],
                        [self.pv1, self.pv2_t1]),
            self.ffitem("b", self.froot_one, [self.s_grow, self.sec_t1],
                        [self.pv1, self.pv1, self.pv2_t1]),
        ]

    def chain_batch_report(self, items):
        return verify_final_fork_decision_aggregate_chains(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring, self.m)

    def site_pair(self, items):
        """The same declaration attested by both authorized sites."""
        return [
            proof_item("x", self.ffdacf_proof(items, issuer=SITE_A)),
            proof_item("y", self.ffdacf_proof(items, issuer=SITE_B)),
        ]

    def expected_common(self, items):
        """The common edge set a ruling over ``items`` must bind."""
        return [
            {key: fork[key] for key in EDGE_KEYS}
            for fork in self.chain_batch_report(items)["forks"]
        ]


class FullPathTest(ForkPipelineEndToEndFixtures, unittest.TestCase):
    """Batch verification -> proof -> multi-proof -> ruling -> review."""

    def test_fork_free_batch_flows_end_to_end_with_empty_edges(self):
        report = self.chain_batch_report(self.clean_items)
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [item["status"] for item in report["items"]], ["verified"])

        raw = self.ffdacf_proof(self.clean_items)
        self.assertEqual(parse(raw)["payload"]["report"], report)

        proof_report = self.ffdacf_report([proof_item("p", raw)])
        item = proof_report["items"][0]
        self.assertEqual(item["status"], "verified")
        self.assertEqual(item["result"]["proofDigest"], sha256_hex(raw))
        self.assertEqual(item["result"]["report"]["forks"], [])

        decision = self.ffdacf_judge(self.site_pair(self.clean_items))
        result = self.ffdacf_verify(decision)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["common"], [])
        self.assertEqual(result["proofDigest"], sha256_hex(decision))

    def test_fork_batch_flows_end_to_end_with_the_common_edge(self):
        report = self.chain_batch_report(self.fork_items)
        self.assertEqual(len(report["forks"]), 1)

        raw = self.ffdacf_proof()
        self.assertEqual(parse(raw)["payload"]["report"], report)
        proof_report = self.ffdacf_report([proof_item("p", raw)])
        self.assertEqual(proof_report["items"][0]["status"], "verified")

        decision = self.ffdacf_judge(self.site_pair(self.fork_items))
        result = self.ffdacf_verify(decision)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["common"],
                         self.expected_common(self.fork_items))
        edge = result["common"][0]
        self.assertEqual(list(edge.keys()), EDGE_KEYS)
        self.assertEqual(edge["rootDigest"], sha256_hex(self.froot_one))
        self.assertEqual(edge["successors"], sorted(edge["successors"]))

    def test_shared_predecessor_forks_keep_complete_sorted_edges(self):
        report = self.chain_batch_report(self.deep_items)
        forks = report["forks"]
        self.assertEqual(len(forks), 2)
        # Stably sorted by root then predecessor digest; every edge
        # carries the complete ascending successor set and id list.
        self.assertEqual(
            [(f["rootDigest"], f["predecessorDigest"]) for f in forks],
            sorted((f["rootDigest"], f["predecessorDigest"])
                   for f in forks))
        self.assertEqual(
            {f["predecessorDigest"] for f in forks},
            {sha256_hex(self.froot_one), sha256_hex(self.s_grow)})
        for fork in forks:
            self.assertEqual(fork["successors"],
                             sorted(fork["successors"]))
            self.assertEqual(fork["ids"], sorted(fork["ids"]))
        # Every chain crosses a fork and is reclassified conflicted.
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["conflicted"] * 3)

        raw = self.ffdacf_proof(self.deep_items)
        self.assertEqual(parse(raw)["payload"]["report"], report)
        proof_report = self.ffdacf_report([proof_item("p", raw)])
        self.assertEqual(proof_report["items"][0]["status"], "verified")

        result = self.ffdacf_verify(
            self.ffdacf_judge(self.site_pair(self.deep_items)))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["common"],
                         self.expected_common(self.deep_items))
        self.assertEqual(len(result["common"]), 2)


class MultiSiteRulingTest(ForkPipelineEndToEndFixtures,
                          unittest.TestCase):
    def test_identical_declarations_reaching_threshold_are_accepted(self):
        result = self.ffdacf_verify(
            self.ffdacf_judge(self.site_pair(self.fork_items)))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["common"],
                         self.expected_common(self.fork_items))
        self.assertTrue(all(row["conclusion"] == "valid"
                            for row in result["items"]))

    def test_below_threshold_is_insufficient_but_keeps_the_common(self):
        result = self.ffdacf_verify(self.ffdacf_judge([
            proof_item("x", self.ffdacf_proof(issuer=SITE_A))]))
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["common"],
                         self.expected_common(self.fork_items))

    def test_cross_site_disagreement_is_conflicted(self):
        result = self.ffdacf_verify(self.ffdacf_judge([
            proof_item("x", self.ffdacf_proof(self.fork_items,
                                              issuer=SITE_A)),
            proof_item("y", self.ffdacf_proof(self.clean_items,
                                              issuer=SITE_B)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])

    def test_same_site_contradiction_is_conflicted(self):
        result = self.ffdacf_verify(self.ffdacf_judge([
            proof_item("fork", self.ffdacf_proof(self.fork_items,
                                                 issuer=SITE_A)),
            proof_item("clean", self.ffdacf_proof(self.clean_items,
                                                  issuer=SITE_A)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        self.assertTrue(all(row["conclusion"] == "contradiction"
                            for row in result["items"]))

    def test_identical_valid_declarations_from_one_site_duplicate(self):
        proof = self.ffdacf_proof(issuer=SITE_A)
        result = self.ffdacf_verify(self.ffdacf_judge([
            proof_item("first", proof), proof_item("second", proof)]))
        self.assertEqual(result["status"], "insufficient")
        rows = {row["id"]: row for row in result["items"]}
        self.assertEqual(rows["first"]["conclusion"], "valid")
        self.assertEqual(rows["second"]["conclusion"], "duplicate")
        self.assertEqual(rows["second"]["reason"], "duplicate")


class DeterminismAndIndependenceTest(ForkPipelineEndToEndFixtures,
                                     unittest.TestCase):
    def test_input_order_never_changes_the_decision_bytes(self):
        items = self.site_pair(self.deep_items)
        items.append(proof_item("bad", b"{}"))
        forward = self.ffdacf_judge(items)
        self.assertEqual(self.ffdacf_judge(list(reversed(items))),
                         forward)
        self.assertEqual(self.ffdacf_judge([items[1], items[2],
                                            items[0]]), forward)

    def test_repeated_calls_are_identical_or_equal_and_independent(self):
        items = self.site_pair(self.fork_items)
        self.assertEqual(self.ffdacf_judge(items),
                         self.ffdacf_judge(items))
        first = self.ffdacf_report(items)
        second = self.ffdacf_report(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.ffdacf_report(items)["items"][0]["result"]["issuer"],
            SITE_A)
        verified = self.ffdacf_verify(self.ffdacf_judge(items))
        again = self.ffdacf_verify(self.ffdacf_judge(items))
        self.assertEqual(verified, again)
        self.assertIsNot(verified["items"], again["items"])

    def test_inputs_policies_and_keyring_are_not_modified(self):
        items = self.site_pair(self.deep_items)
        snapshot = copy.deepcopy(
            (items, self.deep_items, self.fork_items, self.clean_items,
             self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
             self.proofp, self.ring))
        decision = self.ffdacf_judge(items)
        self.chain_batch_report(self.deep_items)
        self.ffdacf_proof()
        self.ffdacf_report(items)
        self.ffdacf_verify(decision)
        self.assertEqual(
            (items, self.deep_items, self.fork_items, self.clean_items,
             self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
             self.proofp, self.ring),
            snapshot)


class RebindingRejectionTest(ForkPipelineEndToEndFixtures,
                             unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = self.site_pair(self.fork_items)
        self.decision = self.ffdacf_judge(self.items)

    def test_reordered_proof_digests_cannot_be_resigned(self):
        payload = copy.deepcopy(parse(self.decision)["payload"])
        payload["proofs"] = list(reversed(payload["proofs"]))
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainForkDecisionError):
            self.ffdacf_verify(rewrap(payload))

    def test_reordered_rows_cannot_be_resigned(self):
        payload = copy.deepcopy(parse(self.decision)["payload"])
        payload["items"] = list(reversed(payload["items"]))
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainForkDecisionError):
            self.ffdacf_verify(rewrap(payload))

    def test_reordered_bound_chains_are_isolated_as_invalid_proof(self):
        raw = self.ffdacf_proof(self.deep_items)
        payload = copy.deepcopy(parse(raw)["payload"])
        payload["chains"] = list(reversed(payload["chains"]))
        report = self.ffdacf_report([
            proof_item("reordered", rewrap(payload)),
            proof_item("ok", self.ffdacf_proof(issuer=SITE_B)),
        ])
        rows = {row["id"]: row for row in report["items"]}
        self.assertEqual(rows["reordered"]["status"], "invalid-proof")
        self.assertIsNone(rows["reordered"]["result"])
        self.assertTrue(rows["reordered"]["error"])
        self.assertEqual(rows["ok"]["status"], "verified")

    def test_reordered_bound_report_rows_are_invalid_proof(self):
        raw = self.ffdacf_proof(self.deep_items)
        payload = copy.deepcopy(parse(raw)["payload"])
        payload["report"]["items"] = list(
            reversed(payload["report"]["items"]))
        report = self.ffdacf_report([proof_item("x", rewrap(payload))])
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_dedicated_error_hierarchy(self):
        self.assertTrue(
            issubclass(InvalidFinalForkDecisionAggregateChainForkProofError,
                       ValueError))
        self.assertTrue(
            issubclass(
                InvalidFinalForkDecisionAggregateChainForkDecisionError,
                ValueError))
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateChainForkProofError,
            InvalidFinalForkDecisionAggregateChainForkDecisionError)


class BatchIsolationTest(ForkPipelineEndToEndFixtures,
                         unittest.TestCase):
    """One failing item never changes its own class or a later item."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.extra_ring = {
            **self.ring,
            "ghost": [entry(1, SECRET_COORD)],
            "site-d": [entry(1, SECRET_COORD)],
        }
        # The verify-time ring: one revoked, one not yet valid, one
        # expired credential; the ghost site is absent entirely.
        self.verify_ring = {
            SITE_A: [entry(1, SECRET_COORD, revoked=True)],
            SITE_B: [entry(1, SECRET_COORD, not_before=self.m + 1)],
            SITE_C: [entry(1, SECRET_COORD, not_after=self.m - 1)],
            JUDGE: [entry(1, SECRET_COORD)],
            "site-d": [entry(1, SECRET_COORD)],
        }

    def tamper(self, raw, mutate):
        payload = copy.deepcopy(parse(raw)["payload"])
        mutate(payload)
        return rewrap(payload)

    def test_invalid_proof_and_unauthenticated_items_are_isolated(self):
        valid = self.ffdacf_sign(issuer="site-d", ring=self.extra_ring)
        bad_key_set = self.tamper(
            valid, lambda p: p.__setitem__("extra", 1))
        future = self.ffdacf_sign(issuer="site-d", ring=self.extra_ring,
                                  moment=self.m + 10)
        bad_digest = self.tamper(
            valid, lambda p: p.__setitem__("prunePolicy", "ab" * 32))
        bad_report = self.tamper(
            valid,
            lambda p: p["report"]["items"][0].__setitem__("id", "zz"))
        unknown = self.ffdacf_sign(issuer="ghost", ring=self.extra_ring)
        revoked = self.ffdacf_sign(issuer=SITE_A)
        not_yet = self.ffdacf_sign(issuer=SITE_B)
        expired = self.ffdacf_sign(issuer=SITE_C)
        forged = parse(self.ffdacf_sign(issuer=JUDGE))
        forged["signature"] = "0" * 64

        items = [
            proof_item("non-canonical", valid + b"\n"),
            proof_item("unknown", unknown),
            proof_item("revoked", revoked),
            proof_item("key-set", bad_key_set),
            proof_item("future", future),
            proof_item("not-yet-valid", not_yet),
            proof_item("expired", expired),
            proof_item("digest", bad_digest),
            proof_item("report", bad_report),
            proof_item("bad-signature", compact(forged)),
            proof_item("valid", valid),
        ]
        report = verify_final_fork_decision_aggregate_chain_fork_proofs(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.verify_ring, self.m)
        self.assertEqual([row["id"] for row in report["items"]],
                         [item["id"] for item in items])
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["invalid-proof", "unauthenticated", "unauthenticated",
             "invalid-proof", "invalid-proof", "unauthenticated",
             "unauthenticated", "invalid-proof", "invalid-proof",
             "unauthenticated", "verified"])
        for row in report["items"][:-1]:
            self.assertIsNone(row["result"], row["id"])
            self.assertTrue(row["error"], row["id"])
        last = report["items"][-1]
        self.assertIsNone(last["error"])
        self.assertEqual(last["result"]["proofDigest"], sha256_hex(valid))
        self.assertEqual(last["result"]["issuer"], "site-d")

    def test_batch_container_and_shared_policy_faults_raise(self):
        proof = self.ffdacf_proof()
        with self.assertRaises(TypeError):
            self.ffdacf_report("x")
        with self.assertRaises(TypeError):
            self.ffdacf_report([proof_item(1, proof)])
        with self.assertRaises(TypeError):
            self.ffdacf_report([proof_item("a", "x")])
        with self.assertRaises(TypeError):
            self.ffdacf_report([proof_item("a", proof)], moment=True)
        with self.assertRaises(ValueError):
            self.ffdacf_report([])
        with self.assertRaises(ValueError):
            self.ffdacf_report([proof_item("", proof)])
        with self.assertRaises(ValueError):
            self.ffdacf_report(
                [proof_item("a", proof), proof_item("a", proof)])
        with self.assertRaises(ValueError):
            self.ffdacf_report([{"id": "a", "proof": proof, "x": 1}])
        other = {"sites": {SITE_A: {1}}, "threshold": 2}
        for field in ("auth", "sp", "ssp", "adjp"):
            with self.assertRaises(ValueError, msg=field):
                self.ffdacf_report([proof_item("a", proof)],
                                   **{field: other})
        with self.assertRaises(ValueError):
            self.ffdacf_report([proof_item("a", proof)],
                               prune_policy={"batch": "x"})

    def test_sign_and_adjudicate_argument_faults_raise(self):
        proof = self.ffdacf_proof()
        with self.assertRaises(ValueError):
            self.ffdacf_sign([])
        with self.assertRaises(ValueError):
            self.ffdacf_sign(self.fork_items + self.fork_items)
        with self.assertRaises(TypeError):
            self.ffdacf_sign(moment=True)
        with self.assertRaises(AuthenticationError):
            self.ffdacf_sign(issuer="ghost")
        items = [proof_item("a", proof)]
        with self.assertRaises(TypeError):
            self.ffdacf_judge("x")
        with self.assertRaises(ValueError):
            self.ffdacf_judge([])
        with self.assertRaises(ValueError):
            self.ffdacf_judge(items, proofp={"sites": {SITE_A: {1}},
                                             "threshold": 2})
        with self.assertRaises(TypeError):
            self.ffdacf_judge(items, version=True)
        with self.assertRaises(AuthenticationError):
            self.ffdacf_judge(items, issuer="nobody")

    def test_decision_review_container_faults_raise(self):
        decision = self.ffdacf_judge(self.site_pair(self.fork_items))
        with self.assertRaises(TypeError):
            self.ffdacf_verify("x")
        with self.assertRaises(TypeError):
            self.ffdacf_verify(b"[]")
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainForkDecisionError):
            self.ffdacf_verify(decision + b"\n")


class AdjudicationReasonTest(ForkPipelineEndToEndFixtures,
                             unittest.TestCase):
    """Every fixed per-row rejection reason, isolated from valid rows."""

    def reasons(self, bad, **kwargs):
        items = [proof_item("bad", bad),
                 proof_item("ok", self.ffdacf_proof(issuer=SITE_B))]
        result = self.ffdacf_verify(self.ffdacf_judge(items, **kwargs),
                                    **kwargs)
        rows = {row["id"]: row for row in result["items"]}
        self.assertEqual(rows["ok"]["conclusion"], "valid")
        return rows["bad"]

    def test_unauthorized_site(self):
        ring = {**self.ring, "ghost": [entry(1, SECRET_COORD)]}
        bad = self.ffdacf_sign(issuer="ghost", ring=ring)
        row = self.reasons(bad, ring=ring)
        self.assertEqual(row["reason"], "unauthorized-site")
        self.assertEqual(row["issuer"], "ghost")

    def test_unauthorized_version(self):
        ring = dict(self.ring)
        ring[SITE_A] = ring[SITE_A] + [entry(2, SECRET_COORD)]
        bad = self.ffdacf_sign(issuer=SITE_A, version=2, ring=ring)
        row = self.reasons(bad, ring=ring)
        self.assertEqual(row["reason"], "unauthorized-version")

    def test_credential_unavailable(self):
        ring = {s: keys for s, keys in self.ring.items() if s != SITE_A}
        row = self.reasons(self.ffdacf_sign(issuer=SITE_A), ring=ring)
        self.assertEqual(row["reason"], "credential-unavailable")

    def test_revoked_not_yet_valid_and_expired(self):
        for override, reason in [
            (entry(1, SECRET_COORD, revoked=True), "revoked"),
            (entry(1, SECRET_COORD, not_before=self.m + 1),
             "not-yet-valid"),
            (entry(1, SECRET_COORD, not_after=self.m - 1), "expired"),
        ]:
            ring = {**self.ring, SITE_A: [override]}
            row = self.reasons(self.ffdacf_sign(issuer=SITE_A), ring=ring)
            self.assertEqual(row["reason"], reason)

    def test_bad_signature(self):
        forged = rewrap(parse(self.ffdacf_sign(issuer=SITE_A))["payload"],
                        secret="77" * 32)
        row = self.reasons(forged)
        self.assertEqual(row["reason"], "bad-signature")


class LegitimateDecisionReviewTest(ForkPipelineEndToEndFixtures,
                                   unittest.TestCase):
    """A legitimate decision is fully re-checkable offline."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.p_a = self.ffdacf_proof(issuer=SITE_A)
        self.p_b = self.ffdacf_proof(issuer=SITE_B)
        self.decision = self.ffdacf_judge(
            [proof_item("x", self.p_a), proof_item("y", self.p_b)])
        self.payload = parse(self.decision)["payload"]
        self.result = self.ffdacf_verify(self.decision)

    def test_all_six_policy_digests_are_recomputable(self):
        expected = {
            "prunePolicyDigest": hashlib.sha256(
                _verdict_policy_bytes(self.policy)).hexdigest(),
            "authorizationPolicyDigest": hashlib.sha256(
                _prune_batch_site_policy_bytes(self.auth)).hexdigest(),
            "sitePolicyDigest": hashlib.sha256(
                _prune_batch_site_policy_bytes(self.ssp)).hexdigest(),
            "signerSitePolicyDigest": hashlib.sha256(
                _prune_batch_site_policy_bytes(self.fsignerp)).hexdigest(),
            "adjudicationSitePolicyDigest": hashlib.sha256(
                _prune_batch_site_policy_bytes(self.adjp)).hexdigest(),
            "proofSitePolicyDigest": hashlib.sha256(
                _prune_batch_site_policy_bytes(self.proofp)).hexdigest(),
        }
        for field in SIX_DIGEST_FIELDS:
            self.assertEqual(self.payload[field], expected[field], field)
            self.assertEqual(self.result[field], expected[field], field)

    def test_per_row_proof_digests_follow_the_sorted_rows(self):
        rows = self.payload["items"]
        self.assertEqual(self.payload["proofs"],
                         [row["digest"] for row in rows])
        keyed = [(row["issuer"], row["id"], row["digest"]) for row in rows]
        self.assertEqual(keyed, sorted(keyed))
        self.assertEqual(
            {row["digest"] for row in rows},
            {sha256_hex(self.p_a), sha256_hex(self.p_b)})
        self.assertEqual(self.result["proofs"], self.payload["proofs"])
        self.assertEqual(self.result["items"], rows)

    def test_status_common_and_signature_are_recomputable(self):
        self.assertEqual(self.payload["status"], "accepted")
        self.assertEqual(self.result["status"], "accepted")
        self.assertEqual(self.result["common"],
                         self.expected_common(self.fork_items))
        self.assertEqual(self.payload["common"], self.result["common"])
        self.assertEqual(self.result["proofDigest"],
                         sha256_hex(self.decision))
        self.assertEqual(
            parse(self.decision)["signature"],
            hmac.new(bytes.fromhex(SECRET_COORD), compact(self.payload),
                     hashlib.sha256).hexdigest())


class NoFileSystemTest(ForkPipelineEndToEndFixtures, unittest.TestCase):
    def test_no_entry_point_reads_or_writes_a_file(self):
        items = self.site_pair(self.fork_items)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.chain_batch_report(self.deep_items)
            self.ffdacf_proof()
            self.ffdacf_proof(self.clean_items)
            self.ffdacf_report(items)
            decision = self.ffdacf_judge(items)
            self.ffdacf_verify(decision)


if __name__ == "__main__":
    unittest.main()
