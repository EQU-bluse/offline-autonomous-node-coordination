"""Tests for batch verification and multi-site threshold adjudication of
prune aggregate fork proofs.

Covers :func:`verify_prune_aggregate_fork_proofs`,
:func:`adjudicate_prune_aggregate_forks` and
:func:`verify_prune_aggregate_fork_decision`: the batch container and
shared materials validated in full before any proof is parsed, the
per-proof verified/invalid-proof/unauthenticated taxonomy with strict
input-order reports and no cross-item interference, the fixed reasons
for invalid, unauthorized and unauthenticated proofs with later items
still processed, same-site duplicate and contradiction handling on the
complete fork edge set, cross-site edge agreement that no majority can
outvote, accepted/insufficient/conflicted outcomes with the unique
common edge set kept below threshold and null only with no valid vote
or a conflict, the signed decision binding both policy digests, the
original-order proof digests, the stably site/id-sorted decisions and
the common edge set, offline re-tally and current-key signature
verification, the InvalidAggregateForkDecisionError hierarchy,
equal-but-independent results, input immutability and the purely
offline guarantee.
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
    InvalidAggregateForkDecisionError,
    InvalidAggregateForkProofError,
    adjudicate_prune_aggregate_forks,
    sign_prune_aggregate_fork_proof,
    verify_prune_aggregate_fork_decision,
    verify_prune_aggregate_fork_proofs,
)

from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C, hmac_hex
from test_supersede_prune_aggregate import pitem
from test_prune_aggregate_chains import PruneAggregateChainBatchFixtures

REPORT_KEYS = ["error", "id", "result", "status"]
BATCH_REPORT_KEYS = ["items", "version"]
SINGLE_PROOF_RESULT_KEYS = [
    "chains", "issuer", "keyVersion", "moment", "policyDigest",
    "proofDigest", "report", "version",
]
DECISION_KEYS = ["payload", "signature"]
DECISION_PAYLOAD_KEYS = [
    "common", "decisions", "issuer", "keyVersion", "proofs",
    "prunePolicyDigest", "sitePolicyDigest", "status", "version",
]
ROW_KEYS = [
    "conclusion", "digest", "edges", "id", "keyVersion", "reason", "site",
]
EDGE_KEYS = ["predecessorDigest", "rootDigest", "successors"]
DECISION_RESULT_KEYS = [
    "common", "decisions", "decisionDigest", "issuer", "keyVersion",
    "prunePolicyDigest", "proofs", "sitePolicyDigest", "status", "version",
]


def fp_item(item_id, proof):
    """One batch item: a unique id and fork proof bytes."""
    return {"id": item_id, "proof": proof}


def fork_site_policy(sites=(SITE_A, SITE_B, SITE_C), threshold=2,
                     versions=None):
    """A ``{sites, threshold}`` site policy for fork proof signers."""
    if versions is None:
        versions = {site: {1} for site in sites}
    return {"sites": versions, "threshold": threshold}


class PruneAggregateForkAdjudicationFixtures(PruneAggregateChainBatchFixtures):
    """Fork proofs signed by several sites plus adjudication helpers."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.fsp = fork_site_policy()
        self.verify_moment = self.moment + 20
        # The base fork: root_one splits into first_a/first_b.
        self.fork1 = self.fork_items()
        # A different fork: first_a splits into second_a/second_b.
        self.fork2 = [
            self.citem("a", self.root_one, [self.first_a, self.second_a]),
            self.citem("b", self.root_one, [self.first_a, self.second_b]),
        ]

    def mkproof(self, chains=None, issuer=SITE_A, version=1, moment=None,
              policy=None, ring=None):
        return sign_prune_aggregate_fork_proof(
            self.fork1 if chains is None else chains,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.verify_moment if moment is None else moment,
            issuer, version,
        )

    def proofs_batch(self):
        return [
            fp_item("a", self.mkproof(issuer=SITE_A)),
            fp_item("b", self.mkproof(issuer=SITE_B)),
        ]

    def bverify_proofs(self, items, policy=None, ring=None, moment=None):
        return verify_prune_aggregate_fork_proofs(
            items,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.verify_moment if moment is None else moment,
        )

    def madjudicate(self, items, prune_policy=None, sp=None, ring=None,
                   moment=None, issuer=JUDGE, version=1):
        return adjudicate_prune_aggregate_forks(
            items,
            self.policy if prune_policy is None else prune_policy,
            self.fsp if sp is None else sp,
            self.ring if ring is None else ring,
            self.verify_moment if moment is None else moment,
            issuer, version,
        )

    def vdecision(self, decision, prune_policy=None, sp=None,
                        ring=None, moment=None):
        return verify_prune_aggregate_fork_decision(
            decision,
            self.policy if prune_policy is None else prune_policy,
            self.fsp if sp is None else sp,
            self.ring if ring is None else ring,
            self.verify_moment if moment is None else moment,
        )

    def resign_proof(self, proof, mutate, secret=SECRET_COORD):
        """Mutate a proof payload and re-sign with an arbitrary secret."""
        data = parse(proof)
        mutate(data["payload"])
        data["signature"] = hmac_hex(secret, compact(data["payload"]))
        return compact(data)

    def resign_decision(self, decision, mutate, secret=SECRET_COORD):
        """Mutate the decision payload and re-sign with an arbitrary secret."""
        data = parse(decision)
        mutate(data["payload"])
        data["signature"] = hmac_hex(secret, compact(data["payload"]))
        return compact(data)


# ---------------------------------------------------------------------------
# Batch verification
# ---------------------------------------------------------------------------


class VerifyPruneAggregateForkProofsShapeTest(
        PruneAggregateForkAdjudicationFixtures):
    def test_verified_report_shape_and_input_order(self):
        items = [
            fp_item("x", self.mkproof(issuer=SITE_A)),
            fp_item("y", self.mkproof(issuer=SITE_B)),
        ]
        report = self.bverify_proofs(items)
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertNotIsInstance(report["version"], bool)
        self.assertEqual([r["id"] for r in report["items"]], ["x", "y"])
        for item_report in report["items"]:
            self.assertEqual(list(item_report.keys()), REPORT_KEYS)
            self.assertEqual(item_report["status"], "verified")
            self.assertIsNone(item_report["error"])
            self.assertEqual(
                list(item_report["result"].keys()), SINGLE_PROOF_RESULT_KEYS
            )

    def test_result_matches_the_single_proof_verifier(self):
        proof = self.mkproof(issuer=SITE_A)
        report = self.bverify_proofs([fp_item("x", proof)])
        single = self.vproof(proof)
        self.assertEqual(report["items"][0]["result"], single)

    def test_results_are_equal_but_independent(self):
        items = [fp_item("x", self.mkproof(issuer=SITE_A))]
        first = self.bverify_proofs(items)
        second = self.bverify_proofs(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.bverify_proofs(items)["items"][0]["result"]["issuer"], SITE_A
        )


class VerifyPruneAggregateForkProofsArgumentTest(
        PruneAggregateForkAdjudicationFixtures):
    def test_container_faults(self):
        with self.assertRaises(TypeError):
            self.bverify_proofs("not-a-list")
        with self.assertRaises(ValueError):
            self.bverify_proofs([])
        with self.assertRaises(TypeError):
            self.bverify_proofs(["not-a-dict"])
        with self.assertRaises(ValueError):
            self.bverify_proofs([{"id": "x"}])
        with self.assertRaises(ValueError):
            self.bverify_proofs([{"proof": self.mkproof()}])

    def test_id_faults(self):
        with self.assertRaises(TypeError):
            self.bverify_proofs([fp_item(9, self.mkproof())])
        with self.assertRaises(ValueError):
            self.bverify_proofs([fp_item("", self.mkproof())])
        with self.assertRaises(ValueError):
            self.bverify_proofs([
                fp_item("x", self.mkproof(issuer=SITE_A)),
                fp_item("x", self.mkproof(issuer=SITE_B)),
            ])

    def test_proof_type_fault(self):
        with self.assertRaises(TypeError):
            self.bverify_proofs([fp_item("x", "not-bytes")])

    def test_shared_material_faults(self):
        items = [fp_item("x", self.mkproof())]
        with self.assertRaises(TypeError):
            self.bverify_proofs(items, policy="not-a-dict")
        with self.assertRaises(ValueError):
            self.bverify_proofs(items, policy={
                "batch": "b", "sites": {}, "threshold": 1,
            })
        with self.assertRaises(TypeError):
            self.bverify_proofs(items, ring="not-a-dict")
        with self.assertRaises(TypeError):
            self.bverify_proofs(items, moment=True)
        with self.assertRaises(ValueError):
            self.bverify_proofs(items, moment=-1)

    def test_precheck_failure_parses_no_proof(self):
        # A structurally bad item anywhere fails the batch before any
        # proof is verified; the fault raises rather than reporting.
        good = fp_item("good", self.mkproof(issuer=SITE_A))
        with self.assertRaises(ValueError):
            self.bverify_proofs([good, {"id": "", "proof": self.mkproof()}])
        with self.assertRaises(TypeError):
            self.bverify_proofs([good, fp_item("bad", 123)])


class VerifyPruneAggregateForkProofsIsolationTest(
        PruneAggregateForkAdjudicationFixtures):
    def test_invalid_proof_is_isolated(self):
        items = [
            fp_item("bad", b"not-a-proof"),
            fp_item("good", self.mkproof(issuer=SITE_A)),
        ]
        report = self.bverify_proofs(items)
        bad, good = report["items"]
        self.assertEqual(bad["status"], "invalid-proof")
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")
        self.assertIsNone(bad["result"])
        self.assertEqual(good["status"], "verified")

    def test_tampered_proof_is_invalid_proof(self):
        tampered = self.resign_proof(
            self.mkproof(), lambda p: p.__setitem__("version", 2)
        )
        report = self.bverify_proofs([
            fp_item("bad", tampered), fp_item("good", self.mkproof(issuer=SITE_B))
        ])
        self.assertEqual([r["status"] for r in report["items"]],
                         ["invalid-proof", "verified"])

    def test_wrong_policy_proof_is_invalid_proof(self):
        # A structurally intact proof bound to a different prune policy
        # digest cannot verify against this policy.
        proof = self.resign_proof(
            self.mkproof(), lambda p: p.__setitem__("policy", "11" * 32)
        )
        report = self.bverify_proofs([fp_item("x", proof)])
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_future_signed_proof_is_invalid_proof(self):
        future = self.mkproof(moment=self.verify_moment + 10)
        report = self.bverify_proofs([fp_item("x", future)])
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_bad_signature_is_unauthenticated(self):
        data = parse(self.mkproof())
        data["signature"] = "00" * 32
        report = self.bverify_proofs([fp_item("x", compact(data))])
        self.assertEqual(report["items"][0]["status"], "unauthenticated")
        self.assertIsNone(report["items"][0]["result"])

    def test_unknown_or_revoked_signer_is_unauthenticated(self):
        missing = {site: keys for site, keys in self.ring.items()
                   if site != SITE_A}
        report = self.bverify_proofs(
            [fp_item("x", self.mkproof(issuer=SITE_A))], ring=missing
        )
        self.assertEqual(report["items"][0]["status"], "unauthenticated")
        revoked = copy.deepcopy(self.ring)
        revoked[SITE_A][0]["revoked"] = True
        report = self.bverify_proofs(
            [fp_item("x", self.mkproof(issuer=SITE_A))], ring=revoked
        )
        self.assertEqual(report["items"][0]["status"], "unauthenticated")

    def test_exact_key_version_with_no_fallback(self):
        proof = self.mkproof(issuer=SITE_A)
        ring_v2 = copy.deepcopy(self.ring)
        ring_v2[SITE_A] = ring_v2[SITE_A] + [entry(2, "22" * 32)]
        self.assertEqual(
            self.bverify_proofs([fp_item("x", proof)], ring=ring_v2)
            ["items"][0]["status"],
            "verified",
        )
        without_v1 = copy.deepcopy(ring_v2)
        without_v1[SITE_A] = [ring_v2[SITE_A][1]]
        self.assertEqual(
            self.bverify_proofs([fp_item("x", proof)], ring=without_v1)
            ["items"][0]["status"],
            "unauthenticated",
        )

    def test_failure_kinds_do_not_interfere(self):
        data = parse(self.mkproof(issuer=SITE_B))
        data["signature"] = "00" * 32
        items = [
            fp_item("junk", b"junk"),
            fp_item("bad-sig", compact(data)),
            fp_item("good", self.mkproof(issuer=SITE_A)),
        ]
        report = self.bverify_proofs(items)
        self.assertEqual([r["status"] for r in report["items"]],
                         ["invalid-proof", "unauthenticated", "verified"])

    def test_later_revocation_changes_only_the_verifying_result(self):
        proof = self.mkproof(issuer=SITE_A)
        self.assertEqual(
            self.bverify_proofs([fp_item("x", proof)])["items"][0]["status"],
            "verified",
        )
        revoked = copy.deepcopy(self.ring)
        revoked[SITE_A][0]["revoked"] = True
        self.assertEqual(
            self.bverify_proofs([fp_item("x", proof)], ring=revoked)
            ["items"][0]["status"],
            "unauthenticated",
        )


# ---------------------------------------------------------------------------
# Adjudication shape and outcomes
# ---------------------------------------------------------------------------


class AdjudicatePruneAggregateForksShapeTest(
        PruneAggregateForkAdjudicationFixtures):
    def test_decision_shape_and_canonical_encoding(self):
        raw = self.madjudicate(self.proofs_batch())
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), DECISION_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), DECISION_PAYLOAD_KEYS)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(compact(data), raw)

    def test_proofs_bound_in_original_order(self):
        items = [
            fp_item("one", self.mkproof(issuer=SITE_A)),
            fp_item("two", self.mkproof(issuer=SITE_B)),
        ]
        raw = self.madjudicate(items)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["proofs"], [
            hashlib.sha256(items[0]["proof"]).hexdigest(),
            hashlib.sha256(items[1]["proof"]).hexdigest(),
        ])
        swapped = self.madjudicate(list(reversed(items)))
        self.assertNotEqual(raw, swapped)
        self.assertEqual(parse(swapped)["payload"]["proofs"],
                         list(reversed(payload["proofs"])))

    def test_decisions_sorted_by_site_then_id_with_fixed_keys(self):
        raw = self.madjudicate([
            fp_item("junk", b"nope"),
            fp_item("b-row", self.mkproof(issuer=SITE_B)),
            fp_item("a-row", self.mkproof(issuer=SITE_A)),
        ])
        rows = parse(raw)["payload"]["decisions"]
        self.assertEqual([(r["site"], r["id"]) for r in rows], [
            (None, "junk"), (SITE_A, "a-row"), (SITE_B, "b-row"),
        ])
        for row in rows:
            self.assertEqual(list(row.keys()), ROW_KEYS)

    def test_common_edge_shape(self):
        result = self.vdecision(self.madjudicate(self.proofs_batch()))
        self.assertEqual(result["status"], "accepted")
        (edge,) = result["common"]
        self.assertEqual(list(edge.keys()), EDGE_KEYS)
        self.assertEqual(edge["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(edge["predecessorDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(
            edge["successors"],
            sorted([hashlib.sha256(self.first_a).hexdigest(),
                    hashlib.sha256(self.first_b).hexdigest()]),
        )

    def test_policy_digests_are_bound(self):
        raw = self.madjudicate(self.proofs_batch())
        payload = parse(raw)["payload"]
        canonical_prune = compact({
            "batch": self.policy["batch"],
            "sites": {site: [1] for site in sorted(self.policy["sites"])},
            "threshold": self.policy["threshold"],
        })
        canonical_site = compact({
            "sites": {site: [1] for site in sorted(self.fsp["sites"])},
            "threshold": self.fsp["threshold"],
        })
        self.assertEqual(payload["prunePolicyDigest"],
                         hashlib.sha256(canonical_prune).hexdigest())
        self.assertEqual(payload["sitePolicyDigest"],
                         hashlib.sha256(canonical_site).hexdigest())


class AdjudicatePruneAggregateForksOutcomeTest(
        PruneAggregateForkAdjudicationFixtures):
    def test_accepted_at_threshold(self):
        result = self.vdecision(self.madjudicate(self.proofs_batch()))
        self.assertEqual(result["status"], "accepted")
        for row in result["decisions"]:
            if row["site"] is not None:
                self.assertEqual(row["conclusion"], "valid")
                self.assertIsNone(row["reason"])

    def test_insufficient_below_threshold_keeps_the_common_set(self):
        sp = fork_site_policy(threshold=3)
        raw = self.madjudicate(self.proofs_batch(), sp=sp)
        result = self.vdecision(raw, sp=sp)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["common"])
        self.assertEqual(len(result["common"]), 1)

    def test_no_valid_vote_binds_null_common(self):
        raw = self.madjudicate([fp_item("junk", b"nope")])
        result = self.vdecision(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["common"])
        (row,) = result["decisions"]
        self.assertEqual(row["conclusion"], "invalid")
        self.assertEqual(row["reason"], "invalid-proof")
        self.assertIsNone(row["site"])
        self.assertIsNone(row["keyVersion"])
        self.assertIsNone(row["edges"])

    def test_same_site_identical_proof_is_duplicate(self):
        proof = self.mkproof(issuer=SITE_A)
        raw = self.madjudicate([fp_item("one", proof), fp_item("two", proof)])
        result = self.vdecision(raw)
        self.assertEqual(result["status"], "insufficient")
        rows = {row["id"]: row for row in result["decisions"]}
        self.assertEqual(rows["one"]["conclusion"], "valid")
        self.assertIsNone(rows["one"]["reason"])
        self.assertEqual(rows["two"]["conclusion"], "duplicate")
        self.assertEqual(rows["two"]["reason"], "duplicate")
        # The duplicate keeps the site identity and edge set.
        self.assertEqual(rows["two"]["site"], SITE_A)
        self.assertEqual(rows["two"]["edges"], rows["one"]["edges"])

    def test_same_site_different_bytes_with_the_same_edges_are_duplicates(self):
        # The edge set, not the proof bytes, is the site's identity: two
        # separately signed proofs (different signing moment -> different
        # bytes) that attest the identical complete edge set count once.
        proof_one = self.mkproof(
            issuer=SITE_A, moment=self.verify_moment - 1
        )
        proof_two = self.mkproof(issuer=SITE_A)
        self.assertNotEqual(proof_one, proof_two)
        raw = self.madjudicate([
            fp_item("one", proof_one), fp_item("two", proof_two),
        ])
        result = self.vdecision(raw)
        rows = {row["id"]: row for row in result["decisions"]}
        self.assertEqual(rows["one"]["conclusion"], "valid")
        self.assertEqual(rows["two"]["conclusion"], "duplicate")
        self.assertEqual(rows["two"]["reason"], "duplicate")
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["common"])

    def test_same_site_different_proofs_are_a_contradiction(self):
        raw = self.madjudicate([
            fp_item("one", self.mkproof(self.fork1, issuer=SITE_A)),
            fp_item("two", self.mkproof(self.fork2, issuer=SITE_A)),
        ])
        result = self.vdecision(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        self.assertTrue(all(
            row["conclusion"] == "contradiction"
            and row["reason"] == "contradiction"
            for row in result["decisions"]
        ))

    def test_cross_site_disagreement_conflicts_with_no_majority_override(self):
        # Two sites attest edge set 1, one site attests edge set 2: a raw
        # count of two would accept, but any disagreement conflicts.
        items = [
            fp_item("a", self.mkproof(self.fork1, issuer=SITE_A)),
            fp_item("b", self.mkproof(self.fork1, issuer=SITE_C)),
            fp_item("c", self.mkproof(self.fork2, issuer=SITE_B)),
        ]
        result = self.vdecision(self.madjudicate(items))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])

    def test_cross_site_agreement_accepts_with_different_proof_bytes(self):
        # The proofs are separately signed but bind the same complete
        # fork edge set; that is the cross-site agreement that counts.
        items = [
            fp_item("a", self.mkproof(self.fork1, issuer=SITE_A)),
            fp_item("b", self.mkproof(self.fork1, issuer=SITE_B)),
        ]
        self.assertNotEqual(items[0]["proof"], items[1]["proof"])
        result = self.vdecision(self.madjudicate(items))
        self.assertEqual(result["status"], "accepted")

    def test_conflict_is_never_outvoted_by_later_sites(self):
        items = [
            fp_item("a", self.mkproof(self.fork1, issuer=SITE_A)),
            fp_item("b", self.mkproof(self.fork2, issuer=SITE_A)),
            fp_item("c", self.mkproof(self.fork1, issuer=SITE_B)),
            fp_item("d", self.mkproof(self.fork1, issuer=SITE_C)),
        ]
        result = self.vdecision(self.madjudicate(items))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])


class AdjudicatePruneAggregateForksItemFailureTest(
        PruneAggregateForkAdjudicationFixtures):
    def _reasons(self, result):
        return {row["id"]: (row["conclusion"], row["reason"])
                for row in result["decisions"]}

    def test_invalid_proof_is_isolated_and_keeps_no_identity(self):
        result = self.vdecision(self.madjudicate([
            fp_item("good", self.mkproof(issuer=SITE_A)),
            fp_item("junk", b"nope"),
        ]))
        reasons = self._reasons(result)
        self.assertEqual(reasons["junk"], ("invalid", "invalid-proof"))
        self.assertEqual(reasons["good"], ("valid", None))
        junk = next(row for row in result["decisions"] if row["id"] == "junk")
        self.assertIsNone(junk["site"])
        self.assertIsNone(junk["edges"])

    def test_wrong_prune_policy_proof_is_invalid_with_no_identity(self):
        proof = self.resign_proof(
            self.mkproof(), lambda p: p.__setitem__("policy", "11" * 32)
        )
        result = self.vdecision(
            self.madjudicate([fp_item("x", proof)])
        )
        (row,) = result["decisions"]
        self.assertEqual(row["reason"], "invalid-proof")
        self.assertIsNone(row["site"])

    def test_unauthorized_site(self):
        sp = fork_site_policy(sites=(SITE_A, SITE_C), threshold=1)
        result = self.vdecision(
            self.madjudicate([fp_item("b", self.mkproof(issuer=SITE_B))], sp=sp),
            sp=sp,
        )
        self.assertEqual(self._reasons(result)["b"],
                         ("invalid", "unauthorized-site"))

    def test_unauthorized_version(self):
        sp = fork_site_policy(
            versions={SITE_A: {2}, SITE_B: {2}, SITE_C: {1}}
        )
        result = self.vdecision(
            self.madjudicate([fp_item("a", self.mkproof(issuer=SITE_A))], sp=sp),
            sp=sp,
        )
        self.assertEqual(self._reasons(result)["a"],
                         ("invalid", "unauthorized-version"))

    def test_credential_unavailable(self):
        missing = {site: keys for site, keys in self.ring.items()
                   if site != SITE_B}
        result = self.vdecision(
            self.madjudicate([fp_item("b", self.mkproof(issuer=SITE_B))],
                            ring=missing),
            ring=missing,
        )
        self.assertEqual(self._reasons(result)["b"],
                         ("invalid", "credential-unavailable"))

    def test_revoked_not_yet_valid_and_expired(self):
        proof = self.mkproof(issuer=SITE_B)
        revoked = copy.deepcopy(self.ring)
        revoked[SITE_B][0]["revoked"] = True
        result = self.vdecision(
            self.madjudicate([fp_item("b", proof)], ring=revoked),
            ring=revoked,
        )
        self.assertEqual(self._reasons(result)["b"], ("invalid", "revoked"))

        future = copy.deepcopy(self.ring)
        future[SITE_B][0]["notBefore"] = self.verify_moment + 1
        result = self.vdecision(
            self.madjudicate([fp_item("b", proof)], ring=future),
            ring=future,
        )
        self.assertEqual(self._reasons(result)["b"],
                         ("invalid", "not-yet-valid"))

        past = copy.deepcopy(self.ring)
        past[SITE_B][0]["notAfter"] = self.verify_moment - 1
        result = self.vdecision(
            self.madjudicate([fp_item("b", proof)], ring=past), ring=past
        )
        self.assertEqual(self._reasons(result)["b"],
                         ("invalid", "expired"))

    def test_bad_signature(self):
        data = parse(self.mkproof(issuer=SITE_B))
        data["signature"] = "00" * 32
        result = self.vdecision(
            self.madjudicate([fp_item("b", compact(data))])
        )
        self.assertEqual(self._reasons(result)["b"],
                         ("invalid", "bad-signature"))

    def test_rejected_authenticated_proof_keeps_its_identity_and_edges(self):
        sp = fork_site_policy(sites=(SITE_A, SITE_C), threshold=1)
        result = self.vdecision(
            self.madjudicate([fp_item("b", self.mkproof(issuer=SITE_B))], sp=sp),
            sp=sp,
        )
        (row,) = result["decisions"]
        self.assertEqual(row["site"], SITE_B)
        self.assertEqual(row["keyVersion"], 1)
        self.assertIsNotNone(row["edges"])

    def test_one_item_failure_never_stops_the_others(self):
        items = [
            fp_item("junk", b"nope"),
            fp_item("a", self.mkproof(issuer=SITE_A)),
            fp_item("b", self.mkproof(issuer=SITE_B)),
        ]
        result = self.vdecision(self.madjudicate(items))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(result["decisions"]), 3)


class AdjudicatePruneAggregateForksArgumentTest(
        PruneAggregateForkAdjudicationFixtures):
    def test_item_container_faults(self):
        with self.assertRaises(TypeError):
            self.madjudicate("nope")
        with self.assertRaises(TypeError):
            self.madjudicate([fp_item(1, self.mkproof())])
        with self.assertRaises(ValueError):
            self.madjudicate([])
        with self.assertRaises(ValueError):
            self.madjudicate([fp_item("", self.mkproof())])
        with self.assertRaises(ValueError):
            self.madjudicate([
                fp_item("same", self.mkproof(issuer=SITE_A)),
                fp_item("same", self.mkproof(issuer=SITE_B)),
            ])
        with self.assertRaises(ValueError):
            self.madjudicate([{"id": "x", "raw": self.mkproof()}])

    def test_site_policy_faults(self):
        good = self.proofs_batch()
        with self.assertRaises(TypeError):
            self.madjudicate(good, sp={"sites": [], "threshold": 1})
        with self.assertRaises(ValueError):
            self.madjudicate(good, sp={"sites": self.fsp["sites"]})
        with self.assertRaises(ValueError):
            self.madjudicate(good, sp=fork_site_policy(threshold=0))
        with self.assertRaises(ValueError):
            self.madjudicate(good, sp=fork_site_policy(threshold=4))
        with self.assertRaises(ValueError):
            self.madjudicate(good, sp=fork_site_policy(
                sites=("", SITE_B), threshold=1))
        with self.assertRaises(TypeError):
            self.madjudicate(good, sp=fork_site_policy(
                versions={SITE_A: [1], SITE_B: {1}, SITE_C: {1}}))
        with self.assertRaises(TypeError):
            self.madjudicate(good, sp=fork_site_policy(
                versions={SITE_A: {True}, SITE_B: {1}, SITE_C: {1}}))

    def test_prune_policy_moment_issuer_and_version_faults(self):
        good = self.proofs_batch()
        with self.assertRaises(TypeError):
            self.madjudicate(good, prune_policy="not-a-dict")
        with self.assertRaises(ValueError):
            self.madjudicate(good, prune_policy={
                "batch": "b", "sites": {}, "threshold": 1,
            })
        with self.assertRaises(TypeError):
            self.madjudicate(good, moment=True)
        with self.assertRaises(ValueError):
            self.madjudicate(good, moment=-1)
        with self.assertRaises(TypeError):
            self.madjudicate(good, issuer=7)
        with self.assertRaises(ValueError):
            self.madjudicate(good, issuer="")
        with self.assertRaises(TypeError):
            self.madjudicate(good, version=True)
        with self.assertRaises(ValueError):
            self.madjudicate(good, version=0)

    def test_unknown_adjudicator_credentials_raise(self):
        with self.assertRaises(AuthenticationError):
            self.madjudicate(self.proofs_batch(), issuer="ghost")


# ---------------------------------------------------------------------------
# Decision verification and bindings
# ---------------------------------------------------------------------------


class VerifyPruneAggregateForkDecisionBindingTest(
        PruneAggregateForkAdjudicationFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.madjudicate(self.proofs_batch())

    def test_verify_result_shape_and_digest(self):
        result = self.vdecision(self.raw)
        self.assertEqual(list(result.keys()), DECISION_RESULT_KEYS)
        self.assertEqual(result["decisionDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["proofs"], parse(self.raw)["payload"]["proofs"])

    def test_results_are_equal_but_independent(self):
        first = self.vdecision(self.raw)
        second = self.vdecision(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["decisions"], second["decisions"])
        self.assertIsNot(first["common"], second["common"])
        first["status"] = "conflicted"
        first["decisions"][0]["conclusion"] = "duplicate"
        self.assertEqual(self.vdecision(self.raw)["status"], "accepted")

    def test_tampered_status_is_rejected(self):
        raw = self.resign_decision(
            self.raw, lambda p: p.__setitem__("status", "insufficient")
        )
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(raw)

    def test_tampered_common_is_rejected(self):
        raw = self.resign_decision(
            self.raw, lambda p: p.__setitem__("common", None)
        )
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(raw)

        def add_successor(payload):
            payload["common"][0]["successors"].append("ff" * 32)
            payload["common"][0]["successors"].sort()
        raw = self.resign_decision(self.raw, add_successor)
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(raw)

    def test_tampered_row_conclusion_is_rejected(self):
        def mutate(payload):
            row = payload["decisions"][1]
            row["conclusion"] = "duplicate"
            row["reason"] = "duplicate"
        raw = self.resign_decision(self.raw, mutate)
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(raw)

    def test_row_reorder_is_rejected(self):
        raw = self.resign_decision(
            self.raw,
            lambda p: p.__setitem__("decisions", list(reversed(p["decisions"]))),
        )
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(raw)

    def test_unknown_proof_digest_is_rejected(self):
        raw = self.resign_decision(
            self.raw,
            lambda p: p.__setitem__("proofs", ["00" * 32] * len(p["proofs"])),
        )
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(raw)

    def test_wrong_policy_digests_are_rejected(self):
        other_prune = copy.deepcopy(self.policy)
        other_prune["threshold"] = 1
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(self.raw, prune_policy=other_prune)
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(self.raw, sp=fork_site_policy(threshold=1))

    def test_threshold_change_retallies_the_status(self):
        # The packet was accepted at threshold 2; a threshold-3 policy
        # with the same digest content differs, and the re-tally forces
        # the mismatch to surface (different site policy digest).
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(self.raw, sp=fork_site_policy(threshold=3))

    def test_encoding_faults(self):
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(self.raw + b"\n")
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(b"not-json")
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(
                json.dumps(parse(self.raw), indent=2).encode("utf-8")
            )
        text = self.raw.decode("utf-8")
        duplicated = text.replace(
            '"version":1', '"version":1,"version":1', 1
        )
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(duplicated.encode("utf-8"))

    def test_bad_outer_signature_is_authentication_error(self):
        data = parse(self.raw)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.vdecision(compact(data))

    def test_later_revocation_or_expiry_rejects_the_decision(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.vdecision(self.raw, ring=revoked)
        expired = copy.deepcopy(self.ring)
        expired[JUDGE][0]["notAfter"] = self.verify_moment - 1
        with self.assertRaises(AuthenticationError):
            self.vdecision(self.raw, ring=expired)

    def test_exact_adjudicator_version_only(self):
        ring_v2 = copy.deepcopy(self.ring)
        ring_v2[JUDGE] = ring_v2[JUDGE] + [entry(2, "22" * 32)]
        self.assertEqual(
            self.vdecision(self.raw, ring=ring_v2)["status"], "accepted"
        )
        without_v1 = copy.deepcopy(ring_v2)
        without_v1[JUDGE] = [ring_v2[JUDGE][1]]
        with self.assertRaises(AuthenticationError):
            self.vdecision(self.raw, ring=without_v1)

    def test_canonical_reserialization_keeps_the_signature(self):
        self.assertEqual(compact(parse(self.raw)), self.raw)
        self.assertEqual(
            self.vdecision(compact(parse(self.raw)))["status"],
            "accepted",
        )


class VerifyPruneAggregateForkDecisionArgumentTest(
        PruneAggregateForkAdjudicationFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.madjudicate(self.proofs_batch())

    def test_public_argument_faults(self):
        with self.assertRaises(TypeError):
            self.vdecision("not-bytes")
        with self.assertRaises(TypeError):
            self.vdecision(self.raw, prune_policy=9)
        with self.assertRaises(ValueError):
            self.vdecision(self.raw, prune_policy={
                "batch": "b", "sites": {}, "threshold": 1,
            })
        with self.assertRaises(TypeError):
            self.vdecision(self.raw, sp={"sites": [], "threshold": 1})
        with self.assertRaises(ValueError):
            self.vdecision(self.raw, sp={"sites": self.fsp["sites"]})
        with self.assertRaises(TypeError):
            self.vdecision(self.raw, ring="not-a-dict")
        with self.assertRaises(TypeError):
            self.vdecision(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.vdecision(self.raw, moment=-1)


class VerifyPruneAggregateForkDecisionExtraBindingTest(
        PruneAggregateForkAdjudicationFixtures):
    def _multi_fork_chains(self):
        other_a = self.succ(self.root_two, [pitem("three", self.pkt_c)])
        other_b = self.succ(
            self.root_two, [pitem("four", self.pkt_b_other)]
        )
        return [
            self.citem("one-a", self.root_one, [self.first_a]),
            self.citem("two-a", self.root_two, [other_a]),
            self.citem("one-b", self.root_one, [self.first_b]),
            self.citem("two-b", self.root_two, [other_b]),
        ]

    def test_multi_fork_edge_sets_must_agree_completely(self):
        chains = self._multi_fork_chains()
        proof_a = self.mkproof(chains, issuer=SITE_A)
        proof_b = self.mkproof(chains, issuer=SITE_B)
        result = self.vdecision(self.madjudicate([
            fp_item("a", proof_a), fp_item("b", proof_b),
        ]))
        self.assertEqual(result["status"], "accepted")
        # One fork per root, two edges total.
        roots = {edge["rootDigest"] for edge in result["common"]}
        self.assertEqual(len(roots), 2)
        self.assertEqual(len(result["common"]), 2)

        # Dropping one crossing chain changes one edge's successor set:
        # the two sites then disagree and the aggregate is conflicted.
        fewer = chains[:3]
        proof_fewer = self.mkproof(fewer, issuer=SITE_C)
        result = self.vdecision(self.madjudicate([
            fp_item("a", proof_a), fp_item("c", proof_fewer),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])

    def test_duplicate_row_with_changed_edges_is_rejected(self):
        proof = self.mkproof(issuer=SITE_A)
        raw = self.madjudicate([fp_item("one", proof), fp_item("two", proof)])

        def mutate(payload):
            dup = next(
                row for row in payload["decisions"] if row["id"] == "two"
            )
            dup["edges"][0]["successors"] = ["ff" * 32, "ee" * 32]
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(self.resign_decision(raw, mutate))

    def test_invalid_row_with_identity_is_rejected(self):
        raw = self.madjudicate([fp_item("junk", b"nope")])

        def mutate(payload):
            row = payload["decisions"][0]
            row["site"] = SITE_A
            row["keyVersion"] = 1
            row["edges"] = []
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(self.resign_decision(raw, mutate))

    def test_authenticated_rejection_row_without_identity_is_rejected(self):
        sp = fork_site_policy(sites=(SITE_A, SITE_C), threshold=1)
        raw = self.madjudicate(
            [fp_item("b", self.mkproof(issuer=SITE_B))], sp=sp
        )

        def mutate(payload):
            row = payload["decisions"][0]
            row["site"] = None
            row["keyVersion"] = None
            row["edges"] = None
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(self.resign_decision(raw, mutate), sp=sp)

    def test_conflicted_status_with_a_common_set_is_rejected(self):
        # A self-contradiction legitimately conflicts with null common;
        # claiming both a conflict and a common set is a binding fault.
        raw = self.madjudicate([
            fp_item("one", self.mkproof(self.fork1, issuer=SITE_A)),
            fp_item("two", self.mkproof(self.fork2, issuer=SITE_A)),
        ])

        def mutate(payload):
            payload["common"] = payload["decisions"][0]["edges"]
        with self.assertRaises(InvalidAggregateForkDecisionError):
            self.vdecision(self.resign_decision(raw, mutate))

    def test_empty_proof_bytes_is_invalid_proof_in_the_batch(self):
        report = self.bverify_proofs([fp_item("x", b"")])
        self.assertEqual(report["items"][0]["status"], "invalid-proof")
        result = self.vdecision(
            self.madjudicate([fp_item("x", b"")])
        )
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["decisions"][0]["reason"], "invalid-proof")


class PruneAggregateForkErrorHierarchyTest(
        PruneAggregateForkAdjudicationFixtures):
    def test_error_classes(self):
        self.assertTrue(
            issubclass(InvalidAggregateForkDecisionError, ValueError)
        )
        self.assertIsNot(InvalidAggregateForkDecisionError,
                         InvalidAggregateForkProofError)
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class PruneAggregateForkIndependenceTest(
        PruneAggregateForkAdjudicationFixtures):
    def test_inputs_are_not_modified(self):
        items = self.proofs_batch() + [fp_item("junk", b"nope")]
        snapshot = copy.deepcopy(items)
        prune_snapshot = copy.deepcopy(self.policy)
        sp_snapshot = copy.deepcopy(self.fsp)
        ring_snapshot = copy.deepcopy(self.ring)
        raw = self.madjudicate(items)
        self.bverify_proofs(items)
        self.vdecision(raw)
        self.assertEqual(items, snapshot)
        self.assertEqual(self.policy, prune_snapshot)
        self.assertEqual(self.fsp, sp_snapshot)
        self.assertEqual(self.ring, ring_snapshot)

    def test_no_file_is_read_or_written(self):
        items = self.proofs_batch()
        raw = self.madjudicate(items)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.bverify_proofs(items)
            self.madjudicate(items)
            self.vdecision(raw)


if __name__ == "__main__":
    unittest.main()
