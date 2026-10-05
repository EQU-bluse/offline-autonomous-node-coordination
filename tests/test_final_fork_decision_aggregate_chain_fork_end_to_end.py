"""End-to-end regression boundary for the final fork decision aggregate
chain fork proof pipeline.

This suite pins the complete path across the batch chain validator and
the four public fork-ruling entry points as one regression boundary:
:func:`verify_final_fork_decision_aggregate_chains` batches the chains,
:func:`sign_final_fork_decision_aggregate_chain_fork_proof` issues the
fork proof over the batch report,
:func:`verify_final_fork_decision_aggregate_chain_fork_proofs`
re-checks proof batches item by item,
:func:`adjudicate_final_fork_decision_aggregate_chain_forks` tallies
the multi-site threshold ruling and
:func:`verify_final_fork_decision_aggregate_chain_fork_decision`
re-verifies the signed ruling offline.

Covered end to end: proofs built from legal same-root chain batches and
forked chain batches -- a fork-free batch still issues, verifies and
adjudicates with the empty edge set, while one predecessor pointing at
distinct successors keeps the complete, stably sorted edge set from
issuance through the ruling; the accepted/insufficient/conflicted/
duplicate tally states; input-order independence of the adjudication
bytes, repeated-call determinism with equal-but-depth-independent
results and input/policy/keyring immutability; re-signed reorderings of
the bound digests and rows rejected by the dedicated proof/decision
exceptions; per-item isolation of invalid-proof and unauthenticated
faults with later items still verified; the batch-level
TypeError/ValueError boundary; every fixed adjudication rejection
reason; full offline recheckability of a legal ruling (six policy
digests, per-row proof digests, common edge set, status and
signature); the purely offline guarantee of every entry; and the
unchanged behaviour of the command-line, storage, recovery and state
replication interfaces.
"""

import copy
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination import merge, storage
from offline_coordination.replication import (
    AuthenticationError,
    InvalidFinalForkDecisionAggregateChainForkDecisionError,
    InvalidFinalForkDecisionAggregateChainForkProofError,
    _prune_batch_site_policy_bytes,
    _verdict_policy_bytes,
    adjudicate_final_fork_decision_aggregate_chain_forks,
    export_recovery_audit,
    export_recovery_checkpoint,
    recover_authorized,
    sign_final_fork_decision_aggregate_chain_fork_proof,
    verify_final_fork_decision_aggregate_chain,
    verify_final_fork_decision_aggregate_chain_fork_decision,
    verify_final_fork_decision_aggregate_chain_fork_proofs,
    verify_final_fork_decision_aggregate_chains,
    verify_recovery_page,
)

from test_final_fork_decision_aggregate_chain_fork_proofs import (
    FinalForkDecisionAggregateChainForkFixtures,
)
from test_adjudicate_prune_aggregate_forks import proof_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B
from test_recovery_checkpoint import make_keyring, make_ticket
from test_supersede_decision_aggregate import rewrap

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EDGE_KEYS = ["predecessorDigest", "rootDigest", "successors"]
REASONS = [
    "unauthorized-site", "unauthorized-version",
    "credential-unavailable", "revoked", "not-yet-valid", "expired",
    "bad-signature",
]


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


class EndToEndPathTest(FinalForkDecisionAggregateChainForkFixtures,
                       unittest.TestCase):
    """The full sign -> verify -> adjudicate -> re-verify walk."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.fork_p_a = self.ffdacf_proof(issuer=SITE_A)
        self.fork_p_b = self.ffdacf_proof(issuer=SITE_B)
        self.clean_p_a = self.ffdacf_proof(self.clean_items, issuer=SITE_A)
        self.clean_p_b = self.ffdacf_proof(self.clean_items, issuer=SITE_B)

    def walk(self, items):
        """Run the whole pipeline and return every intermediate."""
        report = self.ffdacf_report(items)
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["verified"] * len(items))
        raw = self.ffdacf_judge(items)
        result = self.ffdacf_verify(raw)
        return report, raw, result

    def test_fork_free_batch_walks_the_whole_pipeline(self):
        items = [proof_item("x", self.clean_p_a),
                 proof_item("y", self.clean_p_b)]
        report, raw, result = self.walk(items)
        # The issued proofs attest the empty fork edge set...
        for item in items:
            payload = parse(item["proof"])["payload"]
            self.assertEqual(payload["report"]["forks"], [])
        # ...the per-item review binds the same empty collection...
        for row in report["items"]:
            self.assertEqual(row["result"]["report"]["forks"], [])
        # ...and the ruling is accepted with an empty common declaration.
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["common"], [])
        self.assertEqual(result["proofDigest"], sha256(raw))

    def test_forked_batch_walks_the_whole_pipeline(self):
        items = [proof_item("x", self.fork_p_a),
                 proof_item("y", self.fork_p_b)]
        report, raw, result = self.walk(items)
        expected_successors = sorted(
            [sha256(self.s_grow), sha256(self.s_t1)])
        # The issued proofs bind the complete fork collection.
        for item in items:
            forks = parse(item["proof"])["payload"]["report"]["forks"]
            fork, = forks
            self.assertEqual(fork["rootDigest"], sha256(self.froot_one))
            self.assertEqual(fork["predecessorDigest"],
                             sha256(self.froot_one))
            self.assertEqual(fork["successors"], expected_successors)
            self.assertEqual(fork["ids"], ["a", "b"])
        # The per-item review keeps the same collection.
        for row in report["items"]:
            self.assertEqual(row["result"]["report"]["forks"], forks)
        # The ruling is accepted and binds the one stable-sorted edge.
        self.assertEqual(result["status"], "accepted")
        edge, = result["common"]
        self.assertEqual(list(edge.keys()), EDGE_KEYS)
        self.assertEqual(edge["rootDigest"], sha256(self.froot_one))
        self.assertEqual(edge["predecessorDigest"], sha256(self.froot_one))
        self.assertEqual(edge["successors"], expected_successors)
        # Every authenticated row declares exactly that edge set.
        for row in result["items"]:
            self.assertEqual(row["conclusion"], "valid")
            self.assertEqual(row["edges"], [edge])

    def test_complete_sorted_edge_set_for_a_three_way_fork(self):
        three = [
            self.ffitem("c", self.froot_one, [self.s_3t1],
                        [self.pv1, self.pv2_3t1]),
            self.ffitem("a", self.froot_one, [self.s_grow],
                        [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_one, [self.s_t1],
                        [self.pv1, self.pv2_t1]),
        ]
        items = [
            proof_item("x", self.ffdacf_proof(three, issuer=SITE_A)),
            proof_item("y", self.ffdacf_proof(three, issuer=SITE_B)),
        ]
        _report, _raw, result = self.walk(items)
        self.assertEqual(result["status"], "accepted")
        edge, = result["common"]
        self.assertEqual(edge["successors"], sorted([
            sha256(self.s_grow), sha256(self.s_t1), sha256(self.s_3t1)]))
        self.assertEqual(len(edge["successors"]), 3)

    def test_batch_chain_report_matches_single_chain_verification(self):
        items = [self.ffitem("b", self.froot_one, [self.s_grow],
                             [self.pv1, self.pv1]),
                 self.ffitem("a", self.froot_two, [])]
        report = verify_final_fork_decision_aggregate_chains(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring, self.m)
        for row, item in zip(report["items"], items):
            single = verify_final_fork_decision_aggregate_chain(
                item["root"], item["successors"], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp, item["policies"],
                self.ring, self.m)
            self.assertEqual(row["status"], "verified")
            self.assertEqual(row["result"], single)


class TallyRegressionTest(FinalForkDecisionAggregateChainForkFixtures,
                          unittest.TestCase):
    """The accepted/insufficient/conflicted/duplicate tally states."""

    def tally(self, items, proofp=None):
        return self.ffdacf_verify(
            self.ffdacf_judge(items, proofp=proofp), proofp=proofp)

    def test_identical_claims_at_threshold_are_accepted(self):
        result = self.tally([
            proof_item("x", self.ffdacf_proof(issuer=SITE_A)),
            proof_item("y", self.ffdacf_proof(issuer=SITE_B)),
        ])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(result["common"]), 1)

    def test_below_threshold_is_insufficient_but_binds_the_declaration(
            self):
        result = self.tally(
            [proof_item("x", self.ffdacf_proof(issuer=SITE_A))])
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(len(result["common"]), 1)
        # A fork-free single vote binds the empty declaration as well.
        result = self.tally([proof_item(
            "x", self.ffdacf_proof(self.clean_items, issuer=SITE_A))])
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["common"], [])

    def test_cross_site_disagreement_is_conflicted(self):
        result = self.tally([
            proof_item("x", self.ffdacf_proof(issuer=SITE_A)),
            proof_item("y", self.ffdacf_proof(self.clean_items,
                                              issuer=SITE_B)),
        ])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])

    def test_same_site_contradiction_is_conflicted(self):
        result = self.tally([
            proof_item("fork", self.ffdacf_proof(issuer=SITE_A)),
            proof_item("clean",
                       self.ffdacf_proof(self.clean_items, issuer=SITE_A)),
        ])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        self.assertTrue(all(
            row["conclusion"] == "contradiction"
            for row in result["items"]))

    def test_identical_valid_claims_from_one_site_are_duplicates(self):
        proof = self.ffdacf_proof(issuer=SITE_A)
        result = self.tally(
            [proof_item("first", proof), proof_item("second", proof)])
        rows = {row["id"]: row for row in result["items"]}
        self.assertEqual(rows["first"]["conclusion"], "valid")
        self.assertEqual(rows["second"]["conclusion"], "duplicate")
        self.assertEqual(rows["second"]["reason"], "duplicate")
        # Duplicates count once, so one site never reaches threshold 2.
        self.assertEqual(result["status"], "insufficient")


class DeterminismAndImmutabilityTest(
    FinalForkDecisionAggregateChainForkFixtures, unittest.TestCase
):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.p_a = self.ffdacf_proof(issuer=SITE_A)
        self.p_b = self.ffdacf_proof(issuer=SITE_B)
        self.items = [proof_item("x", self.p_a), proof_item("y", self.p_b)]
        self.raw = self.ffdacf_judge(self.items)

    def test_input_order_never_changes_the_adjudication_bytes(self):
        self.assertEqual(
            self.ffdacf_judge(list(reversed(self.items))), self.raw)
        with_bad = [proof_item("g", b"{}"), proof_item("x", self.p_a)]
        self.assertEqual(
            self.ffdacf_judge(with_bad),
            self.ffdacf_judge(list(reversed(with_bad))))

    def test_repeated_calls_produce_identical_bytes(self):
        self.assertEqual(self.ffdacf_judge(self.items), self.raw)
        self.assertEqual(
            self.ffdacf_proof(issuer=SITE_A),
            self.ffdacf_proof(issuer=SITE_A))

    def test_repeated_verification_is_equal_but_depth_independent(self):
        first = self.ffdacf_verify(self.raw)
        second = self.ffdacf_verify(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(first["common"], second["common"])
        first["items"][0]["edges"][0]["successors"].append("ff" * 32)
        first["common"][0]["successors"].clear()
        again = self.ffdacf_verify(self.raw)
        self.assertEqual(again, second)
        self.assertEqual(len(again["common"][0]["successors"]), 2)

    def test_inputs_policies_and_keyring_are_not_modified(self):
        chain_items = copy.deepcopy(self.fork_items)
        snapshot = copy.deepcopy(
            (self.items, chain_items, self.policy, self.auth, self.ssp,
             self.fsignerp, self.adjp, self.proofp, self.ring))
        sign_final_fork_decision_aggregate_chain_fork_proof(
            chain_items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring, self.m, SITE_A, 1)
        verify_final_fork_decision_aggregate_chains(
            chain_items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring, self.m)
        verify_final_fork_decision_aggregate_chain_fork_proofs(
            self.items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring, self.m)
        raw = adjudicate_final_fork_decision_aggregate_chain_forks(
            self.items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.proofp, self.ring, self.m, JUDGE, 1)
        verify_final_fork_decision_aggregate_chain_fork_decision(
            raw, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.proofp, self.ring, self.m)
        self.assertEqual(
            (self.items, chain_items, self.policy, self.auth, self.ssp,
             self.fsignerp, self.adjp, self.proofp, self.ring),
            snapshot)

    def test_rearranged_bound_rows_are_rejected_even_when_resigned(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["items"] = list(reversed(payload["items"]))
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainForkDecisionError):
            self.ffdacf_verify(rewrap(payload))

    def test_rearranged_proof_digests_are_rejected_even_when_resigned(
            self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["proofs"] = list(reversed(payload["proofs"]))
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainForkDecisionError):
            self.ffdacf_verify(rewrap(payload))
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["proofs"][0] = "dd" * 32
        with self.assertRaises(
                InvalidFinalForkDecisionAggregateChainForkDecisionError):
            self.ffdacf_verify(rewrap(payload))

    def test_rearranged_bound_chains_are_an_invalid_proof(self):
        payload = copy.deepcopy(parse(self.p_a)["payload"])
        payload["chains"] = list(reversed(payload["chains"]))
        report = self.ffdacf_report([proof_item("a", rewrap(payload))])
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_tampered_report_binding_is_an_invalid_proof(self):
        payload = copy.deepcopy(parse(self.p_a)["payload"])
        payload["report"]["items"][0]["id"] = "zz"
        report = self.ffdacf_report([proof_item("a", rewrap(payload))])
        self.assertEqual(report["items"][0]["status"], "invalid-proof")


class BatchIsolationRegressionTest(
    FinalForkDecisionAggregateChainForkFixtures, unittest.TestCase
):
    """Per-item fault isolation inside the proof batch verifier."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.ffdacf_proof(issuer=SITE_A)
        self.good = self.ffdacf_proof(issuer=SITE_B)

    def statuses(self, bad, ring=None, moment=None):
        report = verify_final_fork_decision_aggregate_chain_fork_proofs(
            [proof_item("bad", bad), proof_item("good", self.good)],
            self.policy, self.auth, self.ssp, self.fsignerp, self.adjp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment)
        bad_row, good_row = report["items"]
        self.assertEqual(good_row["status"], "verified")
        self.assertIsNotNone(good_row["result"])
        self.assertIsNone(bad_row["result"])
        self.assertTrue(bad_row["error"])
        return bad_row["status"]

    def test_non_canonical_encoding_is_only_invalid_proof(self):
        self.assertEqual(self.statuses(self.raw + b"\n"), "invalid-proof")
        self.assertEqual(self.statuses(b"not-json"), "invalid-proof")

    def test_wrong_key_set_is_only_invalid_proof(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["extra"] = 1
        self.assertEqual(
            self.statuses(rewrap(payload)), "invalid-proof")
        payload = copy.deepcopy(parse(self.raw)["payload"])
        del payload["chains"]
        self.assertEqual(
            self.statuses(rewrap(payload)), "invalid-proof")

    def test_future_moment_is_only_invalid_proof(self):
        future = self.ffdacf_proof(moment=self.m + 10)
        self.assertEqual(
            self.statuses(future, moment=self.m), "invalid-proof")

    def test_policy_digest_mismatch_is_only_invalid_proof(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["prunePolicy"] = "ab" * 32
        self.assertEqual(
            self.statuses(rewrap(payload)), "invalid-proof")

    def test_report_binding_tamper_is_only_invalid_proof(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["report"]["version"] = 2
        self.assertEqual(
            self.statuses(rewrap(payload)), "invalid-proof")

    def test_unknown_credential_is_only_unauthenticated(self):
        ring = dict(self.ring)
        ring["ghost"] = [entry(1, SECRET_COORD)]
        ghost = self.ffdacf_sign(issuer="ghost", ring=ring)
        # The verifying keyring simply does not know the issuer.
        self.assertEqual(self.statuses(ghost), "unauthenticated")

    def test_revoked_credential_is_only_unauthenticated(self):
        ring = dict(self.ring)
        ring[SITE_A] = [entry(1, SECRET_COORD, revoked=True)]
        self.assertEqual(
            self.statuses(self.raw, ring=ring), "unauthenticated")

    def test_not_yet_valid_credential_is_only_unauthenticated(self):
        ring = dict(self.ring)
        ring[SITE_A] = [entry(1, SECRET_COORD, not_before=self.m + 1)]
        self.assertEqual(
            self.statuses(self.raw, ring=ring), "unauthenticated")

    def test_expired_credential_is_only_unauthenticated(self):
        ring = dict(self.ring)
        ring[SITE_A] = [entry(1, SECRET_COORD, not_after=self.m - 1)]
        self.assertEqual(
            self.statuses(self.raw, ring=ring), "unauthenticated")

    def test_bad_signature_is_only_unauthenticated(self):
        forged = compact(
            {"payload": parse(self.raw)["payload"],
             "signature": "0" * 64})
        self.assertEqual(self.statuses(forged), "unauthenticated")

    def test_batch_container_and_field_faults_raise(self):
        with self.assertRaises(TypeError):
            self.ffdacf_report("x")
        with self.assertRaises(TypeError):
            self.ffdacf_report([proof_item("a", "not-bytes")])
        with self.assertRaises(TypeError):
            self.ffdacf_report([proof_item(1, self.raw)])
        with self.assertRaises(ValueError):
            self.ffdacf_report([])
        with self.assertRaises(ValueError):
            self.ffdacf_report([proof_item("a", self.raw),
                                proof_item("a", self.raw)])
        with self.assertRaises(ValueError):
            self.ffdacf_report([{"id": "a", "proof": self.raw, "x": 1}])
        with self.assertRaises(ValueError):
            self.ffdacf_report([proof_item("a", self.raw)],
                               prune_policy={"batch": "x"})
        with self.assertRaises(TypeError):
            self.ffdacf_report([proof_item("a", self.raw)], moment=True)


class AdjudicationRejectionRegressionTest(
    FinalForkDecisionAggregateChainForkFixtures, unittest.TestCase
):
    """Every fixed per-proof rejection reason, isolated from good rows."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.ffdacf_proof(issuer=SITE_A)

    def reason_of(self, bad, ring=None, proofp=None):
        ring = self.ring if ring is None else ring
        items = [proof_item("bad", bad),
                 proof_item("good", self.ffdacf_proof(issuer=SITE_B))]
        raw = adjudicate_final_fork_decision_aggregate_chain_forks(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.proofp if proofp is None else proofp,
            ring, self.m, JUDGE, 1)
        result = verify_final_fork_decision_aggregate_chain_fork_decision(
            raw, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.proofp if proofp is None else proofp,
            ring, self.m)
        rows = {row["id"]: row for row in result["items"]}
        # The rejection never blocks the later valid row.
        self.assertEqual(rows["good"]["conclusion"], "valid")
        self.assertIsNone(rows["good"]["reason"])
        self.assertEqual(rows["bad"]["conclusion"], "invalid")
        return rows["bad"]["reason"]

    def test_each_fixed_rejection_reason(self):
        reasons = set()
        # unauthorized-site: the signer is unknown to the proof policy.
        ring = dict(self.ring)
        ring["ghost"] = [entry(1, SECRET_COORD)]
        reasons.add(self.reason_of(
            self.ffdacf_sign(issuer="ghost", ring=ring), ring=ring))
        # unauthorized-version: the site is known, the key version not.
        ring = dict(self.ring)
        ring[SITE_A] = ring[SITE_A] + [entry(2, SECRET_COORD)]
        reasons.add(self.reason_of(
            self.ffdacf_sign(issuer=SITE_A, version=2, ring=ring),
            ring=ring))
        # credential-unavailable: the keyring lost the site.
        ring = {site: keys for site, keys in self.ring.items()
                if site != SITE_A}
        reasons.add(self.reason_of(self.raw, ring=ring))
        # revoked / not-yet-valid / expired credentials.
        for overridden, expected in [
            (entry(1, SECRET_COORD, revoked=True), "revoked"),
            (entry(1, SECRET_COORD, not_before=self.m + 1),
             "not-yet-valid"),
            (entry(1, SECRET_COORD, not_after=self.m - 1), "expired"),
        ]:
            ring = dict(self.ring)
            ring[SITE_A] = [overridden]
            reasons.add(self.reason_of(self.raw, ring=ring))
        # bad-signature: a forged envelope under a foreign secret.
        forged = rewrap(parse(self.raw)["payload"], secret="77" * 32)
        reasons.add(self.reason_of(forged))
        self.assertEqual(reasons, set(REASONS))

    def test_legal_decision_is_fully_recheckable(self):
        items = [proof_item("x", self.ffdacf_proof(issuer=SITE_A)),
                 proof_item("y", self.ffdacf_proof(issuer=SITE_B))]
        raw = self.ffdacf_judge(items)
        data = parse(raw)
        payload = data["payload"]
        # All six policy digests recompute from the shared materials.
        self.assertEqual(
            payload["prunePolicyDigest"],
            hashlib.sha256(_verdict_policy_bytes(self.policy)).hexdigest())
        for field, policy in [
            ("authorizationPolicyDigest", self.auth),
            ("sitePolicyDigest", self.ssp),
            ("signerSitePolicyDigest", self.fsignerp),
            ("adjudicationSitePolicyDigest", self.adjp),
            ("proofSitePolicyDigest", self.proofp),
        ]:
            self.assertEqual(
                payload[field],
                hashlib.sha256(
                    _prune_batch_site_policy_bytes(policy)).hexdigest(),
                field)
        # Rows are stably sorted by site then id and each row's proof
        # digest recomputes from the submitted proof bytes.
        rows = payload["items"]
        self.assertEqual([(row["issuer"], row["id"]) for row in rows],
                         [(SITE_A, "x"), (SITE_B, "y")])
        by_id = {"x": items[0]["proof"], "y": items[1]["proof"]}
        for row in rows:
            self.assertEqual(row["digest"], sha256(by_id[row["id"]]))
        self.assertEqual(payload["proofs"],
                         [row["digest"] for row in rows])
        # The common edge set and the status survive re-verification.
        self.assertEqual(payload["status"], "accepted")
        edge, = payload["common"]
        self.assertEqual(edge["successors"],
                         sorted([sha256(self.s_grow), sha256(self.s_t1)]))
        # The signature is the exact HMAC of the canonical payload.
        secret = self.ring[JUDGE][0]["secret"]
        expected = hmac.new(bytes.fromhex(secret), compact(payload),
                            hashlib.sha256).hexdigest()
        self.assertEqual(data["signature"], expected)
        result = self.ffdacf_verify(raw)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["common"], payload["common"])
        self.assertEqual(result["items"], rows)
        self.assertEqual(result["proofDigest"], sha256(raw))


class OfflineAndCoexistenceTest(
    FinalForkDecisionAggregateChainForkFixtures, unittest.TestCase
):
    """The entries stay purely offline and the other interfaces keep
    their existing behaviour."""

    def test_no_entry_reads_or_writes_a_file(self):
        items = [proof_item("x", self.ffdacf_proof(issuer=SITE_A)),
                 proof_item("y", self.ffdacf_proof(issuer=SITE_B))]
        raw = self.ffdacf_judge(items)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            verify_final_fork_decision_aggregate_chains(
                self.fork_items, self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.ring, self.m)
            self.ffdacf_proof()
            self.ffdacf_proof(self.clean_items)
            self.ffdacf_report(items)
            self.ffdacf_judge(items)
            self.ffdacf_verify(raw)

    def test_command_line_interface_is_unchanged(self):
        proc = subprocess.run(
            [sys.executable, "-m", "offline_coordination", "status"],
            capture_output=True, text=True, cwd=REPO_ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = json.loads(proc.stdout)
        self.assertEqual(line, {
            "connectivity": "offline",
            "nodeId": "local-node",
            "pendingChanges": 0,
            "revision": 0,
        })

    def test_storage_round_trip_is_unchanged(self):
        state = {"clock": {"writer-a": 1},
                 "records": {"key": ["value", False, {"writer-a": 1},
                                     "writer-a"]}}
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "state.json")
            storage.save_state(path, state)
            self.assertEqual(storage.load_state(path), state)

    def test_recovery_interfaces_are_unchanged(self):
        keyring = make_keyring()
        with tempfile.TemporaryDirectory() as directory:
            ledger = os.path.join(directory, "ledger-0")
            with open(ledger, "wb") as handle:
                handle.write(b"ledger-0")
            audit = os.path.join(directory, "audit.jsonl")
            recover_authorized(
                [ledger], keyring, make_ticket([ledger]), 7, audit)
            checkpoint = export_recovery_checkpoint(
                audit, keyring, "issuer-a", 1, 7)
            page = export_recovery_audit(audit)
            result = verify_recovery_page(checkpoint, page, keyring, 7)
            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["lastSeq"], 3)
            self.assertEqual(result["digest"], sha256(checkpoint))

    def test_state_merge_interface_is_unchanged(self):
        left = {"clock": {"a": 1},
                "records": {"k": ["v", False, {"a": 1}, "a"]}}
        merged = merge.merge_states(left, {"clock": {}, "records": {}})
        self.assertEqual(merged["records"]["k"][0], "v")
        self.assertEqual(merged["clock"], {"a": 1})


class ErrorHierarchyRegressionTest(
    FinalForkDecisionAggregateChainForkFixtures, unittest.TestCase
):
    def test_dedicated_exceptions_keep_their_taxonomy(self):
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
        self.assertTrue(issubclass(AuthenticationError, ValueError))


if __name__ == "__main__":
    unittest.main()
