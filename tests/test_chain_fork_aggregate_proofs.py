"""Tests for signed chain fork aggregate proofs and cross-site ruling.

Covers :func:`sign_chain_fork_aggregate_proof`,
:func:`verify_chain_fork_aggregate_proofs`,
:func:`adjudicate_chain_fork_aggregate_proofs` and
:func:`verify_chain_fork_aggregate_decision`: the signed proof binding
both shared policy digests, the original-order chain materials (id,
root, every successor and the complete versioned policy history), the
complete chain fork aggregate chain-batch report and the signing
moment; offline re-verification recomputing the chain material digests,
fork edges, crossing chains, conflicted set and report status from the
bound materials alone; the verified/invalid-proof/unauthenticated batch
taxonomy with input-order reports; the separate site authorization
policy and the verify-then-authorize-then-authenticate per-proof
pipeline with fixed reasons; same-site duplicate/contradiction handling
over the complete fork edge set; cross-site edge-set agreement and
threshold acceptance with the common set kept on insufficient tallies;
the original-order proof digest vector; the canonical signed decision
binding three policy digests and its offline re-tally verification; the
distinct InvalidChainProofError/InvalidChainDecisionError hierarchies;
equal-but-independent results, input immutability and the purely
offline guarantee.
"""

import copy
import hashlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidChainDecisionError,
    InvalidChainProofError,
    adjudicate_chain_fork_aggregate_proofs,
    sign_chain_fork_aggregate_proof,
    verify_chain_fork_aggregate_decision,
    verify_chain_fork_aggregate_proofs,
)

from test_adjudicate_prune_aggregate_forks import proof_item, site_policy
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_fork_aggregate import rewrap
from test_chain_fork_proofs import ChainForkFixtures

BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
PROOF_KEYS = ["payload", "signature"]
PROOF_PAYLOAD_KEYS = [
    "chains", "issuer", "keyVersion", "moment", "prunePolicy", "report",
    "sitePolicy", "version",
]
PROOF_RESULT_KEYS = [
    "chains", "issuer", "keyVersion", "moment", "prunePolicyDigest",
    "sitePolicyDigest", "proofDigest", "report", "version",
]
DECISION_PAYLOAD_KEYS = [
    "authorizationPolicyDigest", "common", "issuer", "items", "keyVersion",
    "proofs", "prunePolicyDigest", "status", "version",
]
ROW_KEYS = ["conclusion", "digest", "edges", "id", "issuer",
            "keyVersion", "reason"]
EDGE_KEYS = ["predecessorDigest", "rootDigest", "successors"]
DECISION_RESULT_KEYS = [
    "common", "proofDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "proofs", "authorizationPolicyDigest",
    "status", "version",
]


class ChainForkAggregateFixtures(ChainForkFixtures):
    """Chain fork aggregate proofs over the forking chain batches."""

    def cauth(self, sites=(SITE_A, SITE_B, SITE_C), threshold=2):
        return site_policy(sites=sites, threshold=threshold)

    def asign_proof(self, items=None, issuer=SITE_A, moment=None, version=1,
                    prune_policy=None, site_policy_=None, ring=None):
        return sign_chain_fork_aggregate_proof(
            self.cf_items_one if items is None else items,
            self.policy if prune_policy is None else prune_policy,
            self.sp if site_policy_ is None else site_policy_,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def aproof(self, items=None, issuer=SITE_A, moment=None):
        return self.asign_proof(items=items, issuer=issuer, moment=moment)

    def caproofs_report(self, items, **kwargs):
        return verify_chain_fork_aggregate_proofs(
            items, self.policy, self.sp, self.ring, self.m, **kwargs)

    def cadjudicate(self, items, auth=None, ring=None, moment=None,
                   issuer=JUDGE, version=1):
        return adjudicate_chain_fork_aggregate_proofs(
            items, self.policy, self.sp,
            self.cauth() if auth is None else auth,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def caverify_decision(self, raw, auth=None, ring=None, moment=None):
        return verify_chain_fork_aggregate_decision(
            raw, self.policy,
            self.cauth() if auth is None else auth,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def catamper_proof(self, proof, mutate):
        """Mutate the payload and re-sign with the same signer secret."""
        data = parse(proof)
        mutate(data["payload"])
        return rewrap(data["payload"])


class ProofSignTest(ChainForkAggregateFixtures):
    def test_canonical_compact_encoding_without_trailing_byte(self):
        raw = self.aproof()
        self.assertIsInstance(raw, bytes)
        self.assertTrue(raw.endswith(b"}"))
        self.assertNotIn(b"\n", raw)
        self.assertEqual(compact(parse(raw)), raw)
        self.assertEqual(list(parse(raw).keys()), PROOF_KEYS)
        self.assertEqual(list(parse(raw)["payload"].keys()),
                         PROOF_PAYLOAD_KEYS)

    def test_identity_moment_and_version_bindings(self):
        payload = parse(self.aproof())["payload"]
        self.assertEqual(payload["issuer"], SITE_A)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.m)
        self.assertEqual(payload["version"], 1)

    def test_chains_bind_materials_in_input_order(self):
        payload = parse(self.aproof())["payload"]
        self.assertEqual([c["id"] for c in payload["chains"]], ["b", "a"])
        self.assertEqual(payload["chains"][0]["root"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["chains"][0]["successors"],
                         [hashlib.sha256(self.first_b).hexdigest()])

    def test_the_complete_chain_batch_report_is_bound(self):
        from offline_coordination.replication import (
            verify_chain_fork_aggregate_chains,
        )
        raw = self.aproof()
        self.assertEqual(
            parse(raw)["payload"]["report"],
            verify_chain_fork_aggregate_chains(
                self.cf_items_one, self.policy, self.sp, self.ring, self.m),
        )

    def test_conflicted_report_uses_the_cfca_fixed_error(self):
        for item in parse(self.aproof())["payload"]["report"]["items"]:
            self.assertEqual(item["error"], "forked-chain-fork-aggregate")

    def test_fork_free_batch_is_a_value_error(self):
        no_fork = [self.fcitem("x", self.root_one, [self.first_a])]
        with self.assertRaises(ValueError):
            self.asign_proof(no_fork)

    def test_sign_argument_faults(self):
        with self.assertRaises(ValueError):
            self.asign_proof([])
        with self.assertRaises(ValueError):
            self.asign_proof(self.cf_items_one + self.cf_items_one)
        with self.assertRaises(TypeError):
            self.asign_proof(issuer=9)
        with self.assertRaises(ValueError):
            self.asign_proof(issuer="")
        with self.assertRaises(TypeError):
            self.asign_proof(version=True)
        with self.assertRaises(ValueError):
            self.asign_proof(version=0)
        with self.assertRaises(TypeError):
            self.asign_proof(moment=True)
        with self.assertRaises(ValueError):
            self.asign_proof(moment=-1)

    def test_sign_credential_faults(self):
        with self.assertRaises(AuthenticationError):
            self.asign_proof(issuer="ghost")

    def test_shared_policy_faults(self):
        with self.assertRaises(ValueError):
            self.asign_proof(prune_policy={"batch": "x"})
        with self.assertRaises(ValueError):
            self.asign_proof(
                site_policy_=site_policy(sites=(SITE_A,), threshold=2))


class ProofVerifyTest(ChainForkAggregateFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.aproof()

    def test_result_shape_and_bindings(self):
        result = verify_chain_fork_aggregate_proofs(
            [proof_item("a", self.raw)], self.policy, self.sp, self.ring,
            self.m,
        )["items"][0]["result"]
        self.assertEqual(list(result.keys()), PROOF_RESULT_KEYS)
        self.assertEqual(result["issuer"], SITE_A)
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        payload = parse(self.raw)["payload"]
        self.assertEqual(result["prunePolicyDigest"], payload["prunePolicy"])
        self.assertEqual(result["sitePolicyDigest"], payload["sitePolicy"])
        self.assertEqual(result["report"], payload["report"])

    def test_wrong_policies_are_proof_errors(self):
        other = {"batch": "other",
                 "sites": {s: {1} for s in self.policy["sites"]},
                 "threshold": self.policy["threshold"]}
        report = verify_chain_fork_aggregate_proofs(
            [proof_item("a", self.raw)], other, self.sp, self.ring, self.m)
        self.assertEqual(report["items"][0]["status"], "invalid-proof")
        other_site = site_policy(sites=tuple(self.sp["sites"]), threshold=1)
        report = verify_chain_fork_aggregate_proofs(
            [proof_item("a", self.raw)], self.policy, other_site,
            self.ring, self.m)
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_encoding_and_binding_faults(self):
        def status_of(raw):
            return self.caproofs_report([proof_item("a", raw)])["items"][0]
        self.assertEqual(status_of(self.raw + b"\n")["status"], "invalid-proof")
        self.assertEqual(status_of(b"not-json")["status"], "invalid-proof")
        self.assertEqual(status_of(b"")["status"], "invalid-proof")
        bad_version = self.catamper_proof(
            self.raw, lambda p: p.__setitem__("version", 2))
        self.assertEqual(status_of(bad_version)["status"], "invalid-proof")
        bad = self.catamper_proof(
            self.raw, lambda p: p["report"].__setitem__("forks", []))
        self.assertEqual(status_of(bad)["status"], "invalid-proof")

    def test_credentials_are_unauthenticated(self):
        missing = {s: keys for s, keys in self.ring.items() if s != SITE_A}
        report = self.caproofs_report([proof_item("a", self.raw)])
        self.assertEqual(report["items"][0]["status"], "verified")
        report = verify_chain_fork_aggregate_proofs(
            [proof_item("a", self.raw)], self.policy, self.sp, missing,
            self.m)
        self.assertEqual(report["items"][0]["status"], "unauthenticated")
        data = parse(self.raw)
        data["signature"] = "0" * 64
        report = self.caproofs_report([proof_item("a", compact(data))])
        self.assertEqual(report["items"][0]["status"], "unauthenticated")


class BatchVerifyTest(ChainForkAggregateFixtures):
    def test_reports_in_input_order_and_isolation(self):
        p_a = self.aproof(issuer=SITE_A)
        p_b = self.aproof(issuer=SITE_B)
        report = self.caproofs_report([
            proof_item("a", p_a), proof_item("b", b"{}"),
            proof_item("c", p_b),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual([r["id"] for r in report["items"]], ["a", "b", "c"])
        self.assertEqual([r["status"] for r in report["items"]],
                         ["verified", "invalid-proof", "verified"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), ITEM_REPORT_KEYS)
        self.assertIsNone(report["items"][1]["result"])
        self.assertTrue(report["items"][1]["error"])

    def test_structure_validated_upfront(self):
        p = self.aproof()
        with self.assertRaises(TypeError):
            self.caproofs_report("x")
        with self.assertRaises(ValueError):
            self.caproofs_report([])
        with self.assertRaises(ValueError):
            self.caproofs_report([proof_item("a", p), proof_item("a", p)])
        with self.assertRaises(ValueError):
            self.caproofs_report([{"id": "a", "proof": p, "x": 1}])
        with self.assertRaises(TypeError):
            self.caproofs_report([proof_item(1, p)])
        with self.assertRaises(TypeError):
            self.caproofs_report([proof_item("a", "x")])

    def test_results_are_fresh_and_independent(self):
        items = [proof_item("a", self.aproof())]
        first = self.caproofs_report(items)
        second = self.caproofs_report(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.caproofs_report(items)["items"][0]["result"]["issuer"], SITE_A)


class AdjudicationValidationTest(ChainForkAggregateFixtures):
    def test_items_and_material_faults(self):
        p = self.aproof()
        items = [proof_item("a", p)]
        with self.assertRaises(TypeError):
            self.cadjudicate("x")
        with self.assertRaises(ValueError):
            self.cadjudicate([])
        with self.assertRaises(ValueError):
            self.cadjudicate([proof_item("", p)])
        with self.assertRaises(ValueError):
            self.cadjudicate([proof_item("a", p), proof_item("a", p)])
        with self.assertRaises(ValueError):
            self.cadjudicate(items, auth={"sites": {SITE_A: {1}}, "threshold": 2})
        with self.assertRaises(TypeError):
            self.cadjudicate(items, moment=True)
        with self.assertRaises(ValueError):
            self.cadjudicate(items, moment=-1)
        with self.assertRaises(TypeError):
            self.cadjudicate(items, issuer=7)
        with self.assertRaises(ValueError):
            self.cadjudicate(items, issuer="")
        with self.assertRaises(TypeError):
            self.cadjudicate(items, version=True)
        with self.assertRaises(ValueError):
            self.cadjudicate(items, version=0)

    def test_signing_credentials_have_no_fallback(self):
        items = [proof_item("a", self.aproof())]
        with self.assertRaises(AuthenticationError):
            self.cadjudicate(items, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.cadjudicate(items, issuer=JUDGE, version=2)


class PerItemRulingTest(ChainForkAggregateFixtures):
    def rows(self, items, **kwargs):
        return self.caverify_decision(
            self.cadjudicate(items, **kwargs), **kwargs)["items"]

    def row_by_id(self, items, **kwargs):
        return {r["id"]: r for r in self.rows(items, **kwargs)}

    def test_invalid_bytes_rejected_alone(self):
        rows = self.row_by_id([
            proof_item("good", self.aproof(issuer=SITE_A)),
            proof_item("bad", b"{}"),
            proof_item("good2", self.aproof(issuer=SITE_B)),
        ])
        self.assertEqual(rows["bad"]["reason"], "invalid-proof")
        self.assertIsNone(rows["bad"]["issuer"])
        self.assertIsNone(rows["bad"]["edges"])
        self.assertEqual(rows["good"]["conclusion"], "valid")

    def test_unauthorized_site_is_governed_by_the_separate_policy(self):
        # The proof is valid under the fork-proof site policy but the
        # separate adjudication authorization policy omits the site.
        ring = dict(self.ring)
        ring["ghost"] = [entry(1, SECRET_COORD)]
        p = self.asign_proof(issuer="ghost", ring=ring)
        rows = self.row_by_id([proof_item("x", p)], ring=ring)
        self.assertEqual(rows["x"]["reason"], "unauthorized-site")
        self.assertEqual(rows["x"]["issuer"], "ghost")
        self.assertIsNotNone(rows["x"]["edges"])
        # Authorizing the site in the separate policy flips it to valid,
        # independently of the bound fork-proof site policy digest.
        auth = self.cauth(sites=(SITE_A, SITE_B, SITE_C, "ghost"), threshold=1)
        rows = self.row_by_id([proof_item("x", p)], auth=auth, ring=ring)
        self.assertIsNone(rows["x"]["reason"])

    def test_unauthorized_version(self):
        ring = dict(self.ring)
        ring[SITE_A] = ring[SITE_A] + [entry(2, SECRET_COORD)]
        p = self.asign_proof(issuer=SITE_A, version=2, ring=ring)
        rows = self.row_by_id([proof_item("x", p)], ring=ring)
        self.assertEqual(rows["x"]["reason"], "unauthorized-version")

    def test_credential_states_and_bad_signature(self):
        p = self.aproof(issuer=SITE_A)
        for modified, reason in [
            ({k: v for k, v in self.ring.items() if k != SITE_A},
             "credential-unavailable"),
            ({**self.ring, SITE_A: [entry(1, SECRET_COORD, revoked=True)]},
             "revoked"),
            ({**self.ring, SITE_A: [entry(1, SECRET_COORD,
                                         not_before=self.m + 1)]},
             "not-yet-valid"),
            ({**self.ring, SITE_A: [entry(1, SECRET_COORD,
                                         not_after=self.m - 1)]},
             "expired"),
        ]:
            rows = self.row_by_id([proof_item("x", p)], ring=modified)
            self.assertEqual(rows["x"]["reason"], reason)
        forged = rewrap(parse(p)["payload"], secret="77" * 32)
        rows = self.row_by_id([proof_item("x", forged)])
        self.assertEqual(rows["x"]["reason"], "bad-signature")

    def test_foreign_policy_and_future_proofs_have_no_identity(self):
        def foreign(field, digest):
            payload = copy.deepcopy(parse(self.aproof())["payload"])
            payload[field] = digest
            return rewrap(payload)
        rows = self.row_by_id(
            [proof_item("x", foreign("prunePolicy", "bb" * 32))])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])
        rows = self.row_by_id(
            [proof_item("x", foreign("sitePolicy", "cc" * 32))])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        rows = self.row_by_id(
            [proof_item("x", self.aproof(moment=self.m + 10))])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])

    def test_identical_edge_sets_are_duplicates(self):
        p = self.aproof(issuer=SITE_A)
        result = self.caverify_decision(self.cadjudicate([
            proof_item("first", p), proof_item("second", p)]))
        self.assertEqual(result["status"], "insufficient")
        rows = {r["id"]: r for r in result["items"]}
        self.assertEqual(rows["first"]["conclusion"], "valid")
        self.assertEqual(rows["second"]["conclusion"], "duplicate")
        self.assertEqual(rows["second"]["reason"], "duplicate")

    def test_same_site_distinct_edge_sets_contradict(self):
        result = self.caverify_decision(self.cadjudicate([
            proof_item("a", self.aproof(self.cf_items_one, issuer=SITE_A)),
            proof_item("b", self.aproof(self.cf_items_two, issuer=SITE_A)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        self.assertTrue(
            all(r["conclusion"] == "contradiction" for r in result["items"]))


class AggregationTest(ChainForkAggregateFixtures):
    def test_accepted_binds_the_common_edge_set(self):
        result = self.caverify_decision(self.cadjudicate([
            proof_item("x", self.aproof(issuer=SITE_A)),
            proof_item("y", self.aproof(issuer=SITE_B)),
        ]))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(result["common"]), 1)
        self.assertEqual(result["common"][0]["successors"],
                         sorted(result["common"][0]["successors"]))

    def test_below_threshold_keeps_common(self):
        result = self.caverify_decision(self.cadjudicate([
            proof_item("x", self.aproof(issuer=SITE_A))]))
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["common"])

    def test_no_valid_vote_binds_null_common(self):
        result = self.caverify_decision(self.cadjudicate([
            proof_item("x", b"{}"), proof_item("y", b"{")]))
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["common"])

    def test_cross_site_disagreement_is_conflicted_and_unoutvotable(self):
        result = self.caverify_decision(self.cadjudicate([
            proof_item("x", self.aproof(self.cf_items_one, issuer=SITE_A)),
            proof_item("y", self.aproof(self.cf_items_two, issuer=SITE_B)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        result = self.caverify_decision(self.cadjudicate([
            proof_item("a", self.aproof(self.cf_items_one, issuer=SITE_A)),
            proof_item("b", self.aproof(self.cf_items_one, issuer=SITE_B)),
            proof_item("c", self.aproof(self.cf_items_two, issuer=SITE_C)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])


class DecisionPacketShapeTest(ChainForkAggregateFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.p_a = self.aproof(issuer=SITE_A)
        self.p_b = self.aproof(issuer=SITE_B)
        self.items = [proof_item("x", self.p_a), proof_item("y", self.p_b)]
        self.raw = self.cadjudicate(self.items)

    def test_canonical_shape_and_two_policy_bindings(self):
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(parse(self.raw)), self.raw)
        payload = parse(self.raw)["payload"]
        self.assertEqual(list(payload.keys()), DECISION_PAYLOAD_KEYS)
        # Exactly two policy digests: the prune policy and the separate
        # site authorization policy.  The fork-proof site policy is
        # already digested inside each signed proof.
        self.assertNotIn("sitePolicyDigest", payload)
        auth = self.cauth()
        self.assertEqual(payload["authorizationPolicyDigest"],
                         hashlib.sha256(compact({
                             "sites": {s: sorted(auth["sites"][s])
                                       for s in sorted(auth["sites"])},
                             "threshold": 2,
                         })).hexdigest())
        self.assertEqual(payload["prunePolicyDigest"],
                         hashlib.sha256(compact({
                             "batch": self.policy["batch"],
                             "sites": {s: sorted(self.policy["sites"][s])
                                       for s in sorted(self.policy["sites"])},
                             "threshold": self.policy["threshold"],
                         })).hexdigest())
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["status"], "accepted")
        for row in payload["items"]:
            self.assertEqual(list(row.keys()), ROW_KEYS)

    def test_proofs_keep_the_original_input_order(self):
        # Rows are sorted by site then id, but the proofs vector records
        # the raw input order: reversing the inputs reverses the vector.
        payload = parse(self.raw)["payload"]
        self.assertEqual(
            payload["proofs"],
            [hashlib.sha256(self.p_a).hexdigest(),
             hashlib.sha256(self.p_b).hexdigest()],
        )
        reversed_raw = self.cadjudicate(list(reversed(self.items)))
        reversed_payload = parse(reversed_raw)["payload"]
        self.assertEqual(reversed_payload["proofs"],
                         list(reversed(payload["proofs"])))
        # The rows themselves stay in the same canonical order.
        self.assertEqual(
            [r["id"] for r in reversed_payload["items"]],
            [r["id"] for r in payload["items"]],
        )

    def test_result_is_a_fresh_fixed_key_mapping(self):
        result = self.caverify_decision(self.raw)
        self.assertEqual(list(result.keys()), DECISION_RESULT_KEYS)
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        again = self.caverify_decision(self.raw)
        self.assertEqual(result, again)
        self.assertIsNot(result, again)
        self.assertIsNot(result["items"], again["items"])
        result["items"][0]["id"] = "tampered"
        self.assertEqual(
            self.caverify_decision(self.raw)["items"][0]["id"],
            again["items"][0]["id"])


class VerifyDecisionBindingTest(DecisionPacketShapeTest):
    def assert_invalid(self, packet):
        with self.assertRaises(InvalidChainDecisionError):
            self.caverify_decision(packet)

    def test_wrong_authorization_policy(self):
        with self.assertRaises(InvalidChainDecisionError):
            self.caverify_decision(self.raw, auth=self.cauth(threshold=1))

    def test_tampered_status_and_common_cannot_be_resigned(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["status"] = "insufficient"
        self.assert_invalid(rewrap(payload))
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["status"] = "conflicted"
        payload["common"] = None
        self.assert_invalid(rewrap(payload))

    def test_tampered_row_cannot_be_resigned(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["items"][0]["conclusion"] = "duplicate"
        payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid(rewrap(payload))

    def test_proof_digest_multiset_must_agree_but_order_is_free(self):
        # A digest absent from the rows breaks the multiset binding...
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["proofs"][0] = "dd" * 32
        self.assert_invalid(rewrap(payload))
        # ...while a pure reordering of the same multiset still tallies,
        # because the vector follows the original input order, not the
        # canonical row order.
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["proofs"] = list(reversed(payload["proofs"]))
        result = self.caverify_decision(rewrap(payload))
        self.assertEqual(result["status"], "accepted")

    def test_rows_must_stay_sorted(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(rewrap(payload))

    def test_encoding_faults(self):
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(b"")
        with self.assertRaises(TypeError):
            self.caverify_decision(b"[]")


class VerifyDecisionAuthenticationTest(DecisionPacketShapeTest):
    def test_signature_and_credential_faults(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.caverify_decision(compact(data))
        for overrides in [
            {JUDGE: [entry(1, SECRET_COORD, revoked=True)]},
            {JUDGE: [entry(1, SECRET_COORD, not_before=self.m + 1)]},
            {JUDGE: [entry(1, SECRET_COORD, not_after=self.m - 1)]},
        ]:
            ring = dict(self.ring)
            ring.update(overrides)
            with self.assertRaises(AuthenticationError):
                self.caverify_decision(self.raw, ring=ring)


class ErrorHierarchyTest(ChainForkAggregateFixtures):
    def test_hierarchy(self):
        self.assertTrue(issubclass(InvalidChainProofError, ValueError))
        self.assertTrue(issubclass(InvalidChainDecisionError, ValueError))
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        self.assertIsNot(InvalidChainProofError, InvalidChainDecisionError)


class IndependenceTest(ChainForkAggregateFixtures):
    def test_inputs_are_not_modified(self):
        items = [proof_item("a", self.aproof(issuer=SITE_A)),
                 proof_item("b", self.aproof(issuer=SITE_B))]
        auth = self.cauth()
        snapshot = copy.deepcopy((items, self.policy, self.sp, auth,
                                  self.ring))
        raw = self.cadjudicate(items, auth=auth)
        self.caproofs_report(items)
        self.caverify_decision(raw, auth=auth)
        self.assertEqual((items, self.policy, self.sp, auth, self.ring),
                         snapshot)

    def test_no_file_is_read_or_written(self):
        items = [proof_item("a", self.aproof(issuer=SITE_A)),
                 proof_item("b", self.aproof(issuer=SITE_B))]
        raw = self.cadjudicate(items)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.aproof()
            self.caproofs_report(items)
            self.cadjudicate(items)
            self.caverify_decision(raw)


if __name__ == "__main__":
    unittest.main()
