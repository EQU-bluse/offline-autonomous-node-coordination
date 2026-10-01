"""Tests for signed aggregate decision chain fork proofs and the
multi-site threshold ruling.

Covers :func:`sign_aggregate_decision_chain_fork_proof`,
:func:`verify_aggregate_decision_chain_fork_proofs`,
:func:`adjudicate_aggregate_decision_chain_forks` and
:func:`verify_aggregate_decision_chain_fork_decision`: the signed proof
binding all three shared policy digests (the prune policy, the site
authorization policy and the fork-proof signer site policy), the
original-order chain materials (id, root, every successor and the
complete versioned decision site policy history), the complete chain
batch report including a possibly empty fork collection, and the
signing moment; offline re-verification recomputing every binding from
the bound materials; fork-free batches attested with the empty fork
edge set, and invalid or unauthenticated chains never contributing a
fork; the verified/invalid-proof/unauthenticated batch taxonomy with
input-order isolation and ``proofDigest`` on success; the separate
adjudication signer site policy and the
verify-then-authorize-then-authenticate per-proof pipeline with fixed
reasons; same-site duplicate/contradiction handling over the complete
declaration (the fork edge set, empty for a fork-free batch);
cross-site declaration agreement and threshold acceptance with the
common declaration kept on insufficient tallies; the canonical signed
decision binding four policy digests and term-by-term proof digest
bindings over the canonical site/id-sorted rows, so the result bytes
are independent of the input order; the distinct
InvalidAggregateDecisionChainForkProofError /
InvalidAggregateDecisionChainForkDecisionError hierarchies (a bool
never posing as an int); equal-but-independent results, input
immutability and the purely offline guarantee.
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
    InvalidAggregateDecisionChainForkDecisionError,
    InvalidAggregateDecisionChainForkProofError,
    adjudicate_aggregate_decision_chain_forks,
    sign_aggregate_decision_chain_fork_proof,
    verify_aggregate_decision_chain_fork_decision,
    verify_aggregate_decision_chain_fork_proofs,
)

from test_supersede_aggregate_decision import AggregateDecisionChainFixtures
from test_adjudicate_prune_aggregate_forks import proof_item
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_supersede_decision_aggregate import rewrap
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C

BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
PROOF_KEYS = ["payload", "signature"]
PROOF_PAYLOAD_KEYS = [
    "authorizationPolicy", "chains", "issuer", "keyVersion", "moment",
    "prunePolicy", "report", "sitePolicy", "version",
]
PROOF_RESULT_KEYS = [
    "chains", "issuer", "keyVersion", "moment", "prunePolicyDigest",
    "authorizationPolicyDigest", "sitePolicyDigest", "proofDigest",
    "report", "version",
]
DECISION_PAYLOAD_KEYS = [
    "authorizationPolicyDigest", "common", "issuer", "items", "keyVersion",
    "proofs", "prunePolicyDigest", "signerSitePolicyDigest",
    "sitePolicyDigest", "status", "version",
]
ROW_KEYS = ["conclusion", "digest", "edges", "id", "issuer",
            "keyVersion", "reason"]
EDGE_KEYS = ["predecessorDigest", "rootDigest", "successors"]
DECISION_RESULT_KEYS = [
    "common", "proofDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "proofs", "authorizationPolicyDigest",
    "signerSitePolicyDigest", "sitePolicyDigest", "status", "version",
]

FORKED_ERROR = "forked-aggregate-decision-chain"


class AggregateDecisionChainForkFixtures(AggregateDecisionChainFixtures):
    """Fork proofs over aggregate decision chain batches."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Two distinct successors over the same root_one predecessor:
        # one grows the chain with a second decision, one rotates the
        # decision site policy.  Together they fork at the root edge.
        self.succ_a = self.adsucc(
            self.root_one, self.root_one,
            [decision_item("two", self.decision_b)])
        self.succ_b = self.adsucc(
            self.root_one, self.root_one, [],
            old=self.pv1, new=self.pv2_t1)
        self.fork_items = [
            self.dcitem("b", self.root_one, [self.succ_b],
                        policies=[self.pv1, self.pv2_t1]),
            self.dcitem("a", self.root_one, [self.succ_a]),
        ]
        # A fork-free batch of one bare accepted chain.
        self.clean_items = [self.dcitem("a", self.root_two, [])]
        # A batch whose only chain does not verify: it must not
        # contribute a fork.
        self.bad_items = [self.dcitem("bad", b"{}", [])]
        # The separate adjudication signer site policy authorizes the
        # proof signing sites; it is distinct from the invariant
        # fork-proof signer site policy already digested in the chains.
        self.signerp = {
            "sites": {SITE_A: {1}, SITE_B: {1}},
            "threshold": 2,
        }
        self.m = self.fm + 20

    def adcf_sign(self, items=None, issuer=SITE_A, moment=None, version=1,
                    prune_policy=None, auth=None, sp=None, ring=None):
        return sign_aggregate_decision_chain_fork_proof(
            self.fork_items if items is None else items,
            self.policy if prune_policy is None else prune_policy,
            self.auth if auth is None else auth,
            self.ssp if sp is None else sp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def adcf_proof(self, items=None, issuer=SITE_A, moment=None):
        return self.adcf_sign(items=items, issuer=issuer, moment=moment)

    def adcf_report(self, items, prune_policy=None, auth=None, sp=None,
                       ring=None, moment=None):
        return verify_aggregate_decision_chain_fork_proofs(
            items,
            self.policy if prune_policy is None else prune_policy,
            self.auth if auth is None else auth,
            self.ssp if sp is None else sp,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def adcf_judge(self, items, signer=None, ring=None, moment=None,
                    issuer=JUDGE, version=1):
        return adjudicate_aggregate_decision_chain_forks(
            items, self.policy, self.auth, self.ssp,
            self.signerp if signer is None else signer,
            self.ring if ring is None else ring,
            self.m if moment is None else moment, issuer, version,
        )

    def adcf_verify(self, raw, signer=None, ring=None, moment=None,
                 prune_policy=None, auth=None, sp=None):
        return verify_aggregate_decision_chain_fork_decision(
            raw,
            self.policy if prune_policy is None else prune_policy,
            self.auth if auth is None else auth,
            self.ssp if sp is None else sp,
            self.signerp if signer is None else signer,
            self.ring if ring is None else ring,
            self.m if moment is None else moment,
        )

    def adcf_tamper(self, proof, mutate):
        """Mutate the payload and re-sign with the same signer secret."""
        data = parse(proof)
        mutate(data["payload"])
        return rewrap(data["payload"])


class ProofSignTest(AggregateDecisionChainForkFixtures):
    def test_canonical_compact_encoding_without_trailing_byte(self):
        raw = self.adcf_proof()
        self.assertIsInstance(raw, bytes)
        self.assertTrue(raw.endswith(b"}"))
        self.assertNotIn(b"\n", raw)
        self.assertEqual(compact(parse(raw)), raw)
        self.assertEqual(list(parse(raw).keys()), PROOF_KEYS)
        self.assertEqual(list(parse(raw)["payload"].keys()),
                         PROOF_PAYLOAD_KEYS)

    def test_identity_moment_and_version_bindings(self):
        payload = parse(self.adcf_proof())["payload"]
        self.assertEqual(payload["issuer"], SITE_A)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.m)
        self.assertEqual(payload["version"], 1)

    def test_chains_bind_materials_in_input_order(self):
        payload = parse(self.adcf_proof())["payload"]
        self.assertEqual([c["id"] for c in payload["chains"]], ["b", "a"])
        self.assertEqual(payload["chains"][0]["root"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(payload["chains"][0]["successors"],
                         [hashlib.sha256(self.succ_b).hexdigest()])
        self.assertEqual(
            payload["chains"][1]["successors"],
            [hashlib.sha256(self.succ_a).hexdigest()])

    def test_the_complete_chain_batch_report_is_bound(self):
        raw = self.adcf_proof()
        self.assertEqual(
            parse(raw)["payload"]["report"],
            verify_aggregate_decision_chains_report(self.fork_items, self),
        )

    def test_three_policy_digests_are_bound(self):
        from offline_coordination.replication import (
            _verdict_policy_bytes,
            _prune_batch_site_policy_bytes,
        )
        payload = parse(self.adcf_proof())["payload"]
        self.assertEqual(
            payload["prunePolicy"],
            hashlib.sha256(
                _verdict_policy_bytes(self.policy)).hexdigest())
        self.assertEqual(
            payload["authorizationPolicy"],
            hashlib.sha256(
                _prune_batch_site_policy_bytes(self.auth)).hexdigest())
        self.assertEqual(
            payload["sitePolicy"],
            hashlib.sha256(
                _prune_batch_site_policy_bytes(self.ssp)).hexdigest())

    def test_conflicted_report_uses_the_adc_fixed_error(self):
        for item in parse(self.adcf_proof())["payload"]["report"]["items"]:
            self.assertEqual(item["error"], FORKED_ERROR)

    def test_fork_free_batch_is_attested_with_an_empty_fork_collection(self):
        # Unlike the earlier fork proof layers, no fork is allowed and
        # the proof binds the empty fork collection.
        raw = self.adcf_proof(self.clean_items)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["report"]["forks"], [])
        self.assertEqual(
            payload["report"]["items"][0]["status"], "verified")

    def test_invalid_chains_never_contribute_a_fork(self):
        raw = self.adcf_proof(self.bad_items)
        report = parse(raw)["payload"]["report"]
        self.assertEqual(report["forks"], [])
        self.assertEqual(report["items"][0]["status"], "invalid-root")

    def test_sign_argument_faults(self):
        with self.assertRaises(ValueError):
            self.adcf_sign([])
        with self.assertRaises(ValueError):
            self.adcf_sign(self.fork_items + self.fork_items)
        with self.assertRaises(TypeError):
            self.adcf_sign(issuer=9)
        with self.assertRaises(ValueError):
            self.adcf_sign(issuer="")
        with self.assertRaises(TypeError):
            self.adcf_sign(version=True)
        with self.assertRaises(ValueError):
            self.adcf_sign(version=0)
        with self.assertRaises(TypeError):
            self.adcf_sign(moment=True)
        with self.assertRaises(ValueError):
            self.adcf_sign(moment=-1)

    def test_bool_never_poses_as_an_int(self):
        with self.assertRaises(TypeError):
            sign_aggregate_decision_chain_fork_proof(
                self.fork_items, self.policy, self.auth, self.ssp,
                self.ring, False, SITE_A, 1)
        with self.assertRaises(TypeError):
            verify_aggregate_decision_chain_fork_proofs(
                [proof_item("a", self.adcf_proof())], self.policy, self.auth,
                self.ssp, self.ring, True)

    def test_sign_credential_faults(self):
        with self.assertRaises(AuthenticationError):
            self.adcf_sign(issuer="ghost")

    def test_shared_policy_faults(self):
        with self.assertRaises(ValueError):
            self.adcf_sign(prune_policy={"batch": "x"})
        other = {"sites": {SITE_A: {1}}, "threshold": 2}
        with self.assertRaises(ValueError):
            self.adcf_sign(auth=other)
        with self.assertRaises(ValueError):
            self.adcf_sign(sp=other)


def verify_aggregate_decision_chains_report(items, fixtures):
    """Run the exact aggregate decision chain batch verifier."""
    from offline_coordination.replication import (
        verify_aggregate_decision_chains,
    )
    return verify_aggregate_decision_chains(
        items, fixtures.policy, fixtures.auth, fixtures.ssp, fixtures.ring,
        fixtures.m,
    )


class ProofVerifyTest(AggregateDecisionChainForkFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.adcf_proof()

    def test_result_shape_and_bindings(self):
        result = self.adcf_report([proof_item("a", self.raw)])[
            "items"][0]["result"]
        self.assertEqual(list(result.keys()), PROOF_RESULT_KEYS)
        self.assertEqual(result["issuer"], SITE_A)
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        payload = parse(self.raw)["payload"]
        self.assertEqual(result["prunePolicyDigest"],
                         payload["prunePolicy"])
        self.assertEqual(result["authorizationPolicyDigest"],
                         payload["authorizationPolicy"])
        self.assertEqual(result["sitePolicyDigest"], payload["sitePolicy"])
        self.assertEqual(result["report"], payload["report"])

    def test_fork_free_proof_verifies_with_empty_edges(self):
        raw = self.adcf_proof(self.clean_items)
        result = self.adcf_report([proof_item("a", raw)])[
            "items"][0]["result"]
        self.assertEqual(result["report"]["forks"], [])

    def test_wrong_policies_are_proof_errors(self):
        other_prune = {"batch": "other",
                       "sites": {s: {1} for s in self.policy["sites"]},
                       "threshold": self.policy["threshold"]}
        report = self.adcf_report(
            [proof_item("a", self.raw)], prune_policy=other_prune)
        self.assertEqual(report["items"][0]["status"], "invalid-proof")
        other_sp = {"sites": {SITE_A: {1}}, "threshold": 1}
        report = self.adcf_report(
            [proof_item("a", self.raw)], auth=other_sp)
        self.assertEqual(report["items"][0]["status"], "invalid-proof")
        report = self.adcf_report(
            [proof_item("a", self.raw)], sp=other_sp)
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_encoding_and_binding_faults(self):
        def status_of(raw):
            return self.adcf_report([proof_item("a", raw)])[
                "items"][0]
        self.assertEqual(status_of(self.raw + b"\n")["status"],
                         "invalid-proof")
        self.assertEqual(status_of(b"not-json")["status"], "invalid-proof")
        self.assertEqual(status_of(b"")["status"], "invalid-proof")
        bad_version = self.adcf_tamper(
            self.raw, lambda p: p.__setitem__("version", 2))
        self.assertEqual(status_of(bad_version)["status"], "invalid-proof")
        # A tampered report item breaks the report binding even though
        # the fork collection itself is unchanged.
        bad_report = self.adcf_tamper(
            self.raw,
            lambda p: p["report"]["items"][0].__setitem__("id", "zz"))
        self.assertEqual(status_of(bad_report)["status"], "invalid-proof")
        # A claimed fork that the materials do not produce is rejected.
        bad_fork = self.adcf_tamper(
            self.raw,
            lambda p: p["report"]["forks"].append(
                copy.deepcopy(p["report"]["forks"][0])))
        self.assertEqual(status_of(bad_fork)["status"], "invalid-proof")

    def test_future_moment_is_an_invalid_proof(self):
        raw = self.adcf_proof(moment=self.m + 10)
        report = self.adcf_report([proof_item("a", raw)],
                                     moment=self.m)
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_credentials_are_unauthenticated(self):
        missing = {s: keys for s, keys in self.ring.items() if s != SITE_A}
        report = verify_aggregate_decision_chain_fork_proofs(
            [proof_item("a", self.raw)], self.policy, self.auth, self.ssp,
            missing, self.m)
        self.assertEqual(report["items"][0]["status"], "unauthenticated")
        data = parse(self.raw)
        data["signature"] = "0" * 64
        report = self.adcf_report([proof_item("a", compact(data))])
        self.assertEqual(report["items"][0]["status"], "unauthenticated")

    def test_every_proof_binding_mismatch_is_isolated(self):
        # The batch verifier surfaces binding faults as invalid-proof
        # reports instead of raising, and never lets one stop another.
        bad_moment = self.adcf_tamper(
            self.raw, lambda p: p.__setitem__("moment", self.m - 1))
        report = self.adcf_report(
            [proof_item("a", bad_moment)], moment=self.m - 5)
        self.assertEqual(report["items"][0]["status"], "invalid-proof")
        bad_version = self.adcf_tamper(
            self.raw,
            lambda p: p["report"].__setitem__("version", 2))
        report = self.adcf_report([
            proof_item("a", bad_version),
            proof_item("b", self.adcf_proof(issuer=SITE_B)),
        ])
        self.assertEqual([r["status"] for r in report["items"]],
                         ["invalid-proof", "verified"])


class BatchVerifyTest(AggregateDecisionChainForkFixtures):
    def test_reports_in_input_order_and_isolation(self):
        p_a = self.adcf_proof(issuer=SITE_A)
        p_b = self.adcf_proof(issuer=SITE_B)
        report = self.adcf_report([
            proof_item("a", p_a), proof_item("b", b"{}"),
            proof_item("c", p_b),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual([r["id"] for r in report["items"]],
                         ["a", "b", "c"])
        self.assertEqual([r["status"] for r in report["items"]],
                         ["verified", "invalid-proof", "verified"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), ITEM_REPORT_KEYS)
        self.assertIsNone(report["items"][1]["result"])
        self.assertTrue(report["items"][1]["error"])

    def test_structure_validated_upfront(self):
        p = self.adcf_proof()
        with self.assertRaises(TypeError):
            self.adcf_report("x")
        with self.assertRaises(ValueError):
            self.adcf_report([])
        with self.assertRaises(ValueError):
            self.adcf_report([proof_item("a", p), proof_item("a", p)])
        with self.assertRaises(ValueError):
            self.adcf_report([{"id": "a", "proof": p, "x": 1}])
        with self.assertRaises(TypeError):
            self.adcf_report([proof_item(1, p)])
        with self.assertRaises(TypeError):
            self.adcf_report([proof_item("a", "x")])

    def test_results_are_fresh_and_independent(self):
        items = [proof_item("a", self.adcf_proof())]
        first = self.adcf_report(items)
        second = self.adcf_report(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.adcf_report(items)["items"][0]["result"]["issuer"],
            SITE_A)


class AdjudicationValidationTest(AggregateDecisionChainForkFixtures):
    def test_items_and_material_faults(self):
        p = self.adcf_proof()
        items = [proof_item("a", p)]
        with self.assertRaises(TypeError):
            self.adcf_judge("x")
        with self.assertRaises(ValueError):
            self.adcf_judge([])
        with self.assertRaises(ValueError):
            self.adcf_judge([proof_item("", p)])
        with self.assertRaises(ValueError):
            self.adcf_judge([proof_item("a", p), proof_item("a", p)])
        with self.assertRaises(ValueError):
            self.adcf_judge(
                items, signer={"sites": {SITE_A: {1}}, "threshold": 2})
        with self.assertRaises(TypeError):
            self.adcf_judge(items, moment=True)
        with self.assertRaises(ValueError):
            self.adcf_judge(items, moment=-1)
        with self.assertRaises(TypeError):
            self.adcf_judge(items, issuer=7)
        with self.assertRaises(ValueError):
            self.adcf_judge(items, issuer="")
        with self.assertRaises(TypeError):
            self.adcf_judge(items, version=True)
        with self.assertRaises(ValueError):
            self.adcf_judge(items, version=0)

    def test_shared_policies_are_validated(self):
        items = [proof_item("a", self.adcf_proof())]
        with self.assertRaises(ValueError):
            adjudicate_aggregate_decision_chain_forks(
                items, {"batch": "x"}, self.auth, self.ssp, self.signerp,
                self.ring, self.m, JUDGE, 1)
        with self.assertRaises(ValueError):
            adjudicate_aggregate_decision_chain_forks(
                items, self.policy, {"sites": {}}, self.ssp, self.signerp,
                self.ring, self.m, JUDGE, 1)

    def test_signing_credentials_have_no_fallback(self):
        items = [proof_item("a", self.adcf_proof())]
        with self.assertRaises(AuthenticationError):
            self.adcf_judge(items, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.adcf_judge(items, issuer=JUDGE, version=2)


class PerItemRulingTest(AggregateDecisionChainForkFixtures):
    def rows(self, items, **kwargs):
        return self.adcf_verify(self.adcf_judge(items, **kwargs), **kwargs)[
            "items"]

    def row_by_id(self, items, **kwargs):
        return {r["id"]: r for r in self.rows(items, **kwargs)}

    def test_invalid_bytes_rejected_alone(self):
        rows = self.row_by_id([
            proof_item("good", self.adcf_proof(issuer=SITE_A)),
            proof_item("bad", b"{}"),
            proof_item("good2", self.adcf_proof(self.clean_items,
                                            issuer=SITE_B)),
        ])
        self.assertEqual(rows["bad"]["reason"], "invalid-proof")
        self.assertIsNone(rows["bad"]["issuer"])
        self.assertIsNone(rows["bad"]["edges"])
        self.assertEqual(rows["good"]["conclusion"], "valid")
        self.assertEqual(rows["good2"]["conclusion"], "valid")
        # The fork-free vote declares the empty edge set.
        self.assertEqual(rows["good2"]["edges"], [])

    def test_unauthorized_site_is_governed_by_the_separate_policy(self):
        ring = dict(self.ring)
        ring["ghost"] = [entry(1, SECRET_COORD)]
        p = self.adcf_sign(issuer="ghost", ring=ring)
        rows = self.row_by_id([proof_item("x", p)], ring=ring)
        self.assertEqual(rows["x"]["reason"], "unauthorized-site")
        self.assertEqual(rows["x"]["issuer"], "ghost")
        self.assertIsNotNone(rows["x"]["edges"])
        signer = {"sites": {**self.signerp["sites"], "ghost": {1}},
                  "threshold": 1}
        rows = self.row_by_id([proof_item("x", p)], signer=signer,
                              ring=ring)
        self.assertIsNone(rows["x"]["reason"])

    def test_unauthorized_version(self):
        ring = dict(self.ring)
        ring[SITE_A] = ring[SITE_A] + [entry(2, SECRET_COORD)]
        p = self.adcf_sign(issuer=SITE_A, version=2, ring=ring)
        rows = self.row_by_id([proof_item("x", p)], ring=ring)
        self.assertEqual(rows["x"]["reason"], "unauthorized-version")

    def test_credential_states_and_bad_signature(self):
        p = self.adcf_proof(issuer=SITE_A)
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

    def test_foreign_policies_and_future_proofs_have_no_identity(self):
        def foreign(field, digest):
            payload = copy.deepcopy(parse(self.adcf_proof())["payload"])
            payload[field] = digest
            return rewrap(payload)
        rows = self.row_by_id(
            [proof_item("x", foreign("prunePolicy", "bb" * 32))])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])
        rows = self.row_by_id(
            [proof_item("x", foreign("authorizationPolicy", "aa" * 32))])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])
        rows = self.row_by_id(
            [proof_item("x", foreign("sitePolicy", "cc" * 32))])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])
        rows = self.row_by_id(
            [proof_item("x", self.adcf_proof(moment=self.m + 10))],
            moment=self.m)
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])

    def test_identical_declarations_are_duplicates(self):
        p = self.adcf_proof(issuer=SITE_A)
        result = self.adcf_verify(self.adcf_judge([
            proof_item("first", p), proof_item("second", p)]))
        self.assertEqual(result["status"], "insufficient")
        rows = {r["id"]: r for r in result["items"]}
        self.assertEqual(rows["first"]["conclusion"], "valid")
        self.assertEqual(rows["second"]["conclusion"], "duplicate")
        self.assertEqual(rows["second"]["reason"], "duplicate")

    def test_empty_declaration_duplicates_match_across_fork_free_batches(self):
        # Two fork-free batches (different ids, same empty edge set) from
        # one site are the same empty declaration, hence a duplicate.
        other_clean = [self.dcitem("z", self.root_one, [])]
        p_one = self.adcf_proof(self.clean_items, issuer=SITE_A)
        p_two = self.adcf_proof(other_clean, issuer=SITE_A)
        result = self.adcf_verify(self.adcf_judge([
            proof_item("one", p_one), proof_item("two", p_two)]))
        rows = {r["id"]: r for r in result["items"]}
        self.assertEqual(rows["two"]["conclusion"], "duplicate")

    def test_same_site_distinct_declarations_contradict(self):
        result = self.adcf_verify(self.adcf_judge([
            proof_item("fork", self.adcf_proof(self.fork_items, issuer=SITE_A)),
            proof_item("clean", self.adcf_proof(self.clean_items,
                                            issuer=SITE_A)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        self.assertTrue(
            all(r["conclusion"] == "contradiction" for r in result["items"]))


class ThresholdTallyTest(AggregateDecisionChainForkFixtures):
    def test_accepted_binds_the_common_fork_edges(self):
        result = self.adcf_verify(self.adcf_judge([
            proof_item("x", self.adcf_proof(issuer=SITE_A)),
            proof_item("y", self.adcf_proof(issuer=SITE_B)),
        ]))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(result["common"]), 1)
        edge = result["common"][0]
        self.assertEqual(list(edge.keys()), EDGE_KEYS)
        self.assertEqual(edge["rootDigest"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(edge["successors"], sorted(edge["successors"]))

    def test_fork_free_consensus_is_accepted_with_empty_common(self):
        result = self.adcf_verify(self.adcf_judge([
            proof_item("x", self.adcf_proof(self.clean_items, issuer=SITE_A)),
            proof_item("y", self.adcf_proof(self.clean_items, issuer=SITE_B)),
        ]))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["common"], [])

    def test_below_threshold_keeps_the_common_declaration(self):
        result = self.adcf_verify(self.adcf_judge([
            proof_item("x", self.adcf_proof(issuer=SITE_A))]))
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(len(result["common"]), 1)
        result_empty = self.adcf_verify(self.adcf_judge([
            proof_item("x", self.adcf_proof(self.clean_items, issuer=SITE_A))]))
        self.assertEqual(result_empty["status"], "insufficient")
        self.assertEqual(result_empty["common"], [])

    def test_no_valid_vote_binds_null_common(self):
        result = self.adcf_verify(self.adcf_judge([
            proof_item("x", b"{}"), proof_item("y", b"{")]))
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["common"])

    def test_only_invalid_unauthorized_rows_never_vote(self):
        # An unauthorized site carries no vote even though its proof is
        # structurally sound.
        result = self.adcf_verify(self.adcf_judge([
            proof_item("x", self.adcf_proof(issuer=SITE_C))]))
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["common"])

    def test_cross_site_disagreement_is_conflicted_and_unoutvotable(self):
        result = self.adcf_verify(self.adcf_judge([
            proof_item("x", self.adcf_proof(self.fork_items, issuer=SITE_A)),
            proof_item("y", self.adcf_proof(self.clean_items, issuer=SITE_B)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        # A third agreeing site cannot outvote the disagreement.
        three = {"sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
                 "threshold": 2}
        result = self.adcf_verify(self.adcf_judge([
            proof_item("a", self.adcf_proof(self.fork_items, issuer=SITE_A)),
            proof_item("b", self.adcf_proof(self.fork_items, issuer=SITE_B)),
            proof_item("c", self.adcf_proof(self.clean_items,
                                            issuer=SITE_C)),
        ], signer=three), signer=three)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])


class DecisionPacketShapeTest(AggregateDecisionChainForkFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.p_a = self.adcf_proof(issuer=SITE_A)
        self.p_b = self.adcf_proof(issuer=SITE_B)
        self.items = [proof_item("x", self.p_a), proof_item("y", self.p_b)]
        self.raw = self.adcf_judge(self.items)

    def test_canonical_shape_and_four_policy_bindings(self):
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(parse(self.raw)), self.raw)
        payload = parse(self.raw)["payload"]
        self.assertEqual(list(payload.keys()), DECISION_PAYLOAD_KEYS)
        from offline_coordination.replication import (
            _verdict_policy_bytes,
            _prune_batch_site_policy_bytes,
        )
        self.assertEqual(
            payload["prunePolicyDigest"],
            hashlib.sha256(
                _verdict_policy_bytes(self.policy)).hexdigest())
        self.assertEqual(
            payload["authorizationPolicyDigest"],
            hashlib.sha256(
                _prune_batch_site_policy_bytes(self.auth)).hexdigest())
        self.assertEqual(
            payload["sitePolicyDigest"],
            hashlib.sha256(
                _prune_batch_site_policy_bytes(self.ssp)).hexdigest())
        self.assertEqual(
            payload["signerSitePolicyDigest"],
            hashlib.sha256(
                _prune_batch_site_policy_bytes(self.signerp)).hexdigest())
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["status"], "accepted")
        for row in payload["items"]:
            self.assertEqual(list(row.keys()), ROW_KEYS)

    def test_proofs_are_bound_term_by_term_to_the_sorted_rows(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(
            payload["proofs"],
            [row["digest"] for row in payload["items"]],
        )
        # Rows are sorted by site then id.
        ids = [(r["issuer"], r["id"]) for r in payload["items"]]
        self.assertEqual(ids, sorted(ids))

    def test_result_bytes_are_independent_of_input_order(self):
        reversed_raw = self.adcf_judge(list(reversed(self.items)))
        self.assertEqual(reversed_raw, self.raw)
        # Invalid rows sort first by id; their position also never
        # changes the sealed bytes.
        with_bad = [proof_item("g", b"{}"), proof_item("x", self.p_a)]
        self.assertEqual(
            self.adcf_judge(with_bad),
            self.adcf_judge(list(reversed(with_bad))))

    def test_result_is_a_fresh_fixed_key_mapping(self):
        result = self.adcf_verify(self.raw)
        self.assertEqual(list(result.keys()), DECISION_RESULT_KEYS)
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        again = self.adcf_verify(self.raw)
        self.assertEqual(result, again)
        self.assertIsNot(result, again)
        self.assertIsNot(result["items"], again["items"])
        result["items"][0]["id"] = "tampered"
        self.assertEqual(
            self.adcf_verify(self.raw)["items"][0]["id"],
            again["items"][0]["id"])


class VerifyDecisionBindingTest(DecisionPacketShapeTest):
    def assert_invalid(self, packet, **kwargs):
        with self.assertRaises(
                InvalidAggregateDecisionChainForkDecisionError):
            self.adcf_verify(packet, **kwargs)

    def test_wrong_policies(self):
        self.assert_invalid(self.raw,
                            signer={"sites": {SITE_A: {1}}, "threshold": 1})
        other_sp = {"sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 1}
        self.assert_invalid(self.raw, sp=other_sp)
        other_auth = {"sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 1}
        self.assert_invalid(self.raw, auth=other_auth)
        other_prune = {"batch": "other",
                       "sites": {s: {1} for s in self.policy["sites"]},
                       "threshold": self.policy["threshold"]}
        self.assert_invalid(self.raw, prune_policy=other_prune)

    def test_tampered_status_and_common_cannot_be_resigned(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["status"] = "insufficient"
        self.assert_invalid(rewrap(payload))
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["status"] = "conflicted"
        payload["common"] = None
        self.assert_invalid(rewrap(payload))
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["common"] = []
        self.assert_invalid(rewrap(payload))

    def test_tampered_row_cannot_be_resigned(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["items"][0]["conclusion"] = "duplicate"
        payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid(rewrap(payload))

    def test_proof_digests_are_positional(self):
        # A foreign digest breaks the term-by-term binding...
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["proofs"][0] = "dd" * 32
        self.assert_invalid(rewrap(payload))
        # ...and a pure reordering of the same digests is rejected too,
        # because the vector must follow the canonical sorted rows.
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["proofs"] = list(reversed(payload["proofs"]))
        self.assert_invalid(rewrap(payload))

    def test_rows_must_stay_sorted(self):
        payload = copy.deepcopy(parse(self.raw)["payload"])
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(rewrap(payload))

    def test_encoding_faults(self):
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(b"")
        with self.assertRaises(TypeError):
            self.adcf_verify(b"[]")

    def test_argument_faults(self):
        with self.assertRaises(TypeError):
            verify_aggregate_decision_chain_fork_decision(
                "x", self.policy, self.auth, self.ssp, self.signerp,
                self.ring, self.m)
        with self.assertRaises(ValueError):
            self.adcf_verify(
                self.raw,
                signer={"sites": {SITE_A: {1}, SITE_B: {1}},
                        "threshold": 3})
        with self.assertRaises(TypeError):
            verify_aggregate_decision_chain_fork_decision(
                self.raw, self.policy, self.auth, self.ssp, self.signerp,
                self.ring, True)


class VerifyDecisionAuthenticationTest(DecisionPacketShapeTest):
    def test_signature_and_credential_faults(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.adcf_verify(compact(data))
        for overrides in [
            {JUDGE: [entry(1, SECRET_COORD, revoked=True)]},
            {JUDGE: [entry(1, SECRET_COORD, not_before=self.m + 1)]},
            {JUDGE: [entry(1, SECRET_COORD, not_after=self.m - 1)]},
        ]:
            ring = dict(self.ring)
            ring.update(overrides)
            with self.assertRaises(AuthenticationError):
                self.adcf_verify(self.raw, ring=ring)


class ErrorHierarchyTest(AggregateDecisionChainForkFixtures):
    def test_hierarchy(self):
        self.assertTrue(
            issubclass(InvalidAggregateDecisionChainForkProofError,
                       ValueError))
        self.assertTrue(
            issubclass(InvalidAggregateDecisionChainForkDecisionError,
                       ValueError))
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        self.assertIsNot(InvalidAggregateDecisionChainForkProofError,
                         InvalidAggregateDecisionChainForkDecisionError)

    def test_distinct_from_the_other_aggregate_error_classes(self):
        from offline_coordination.replication import (
            InvalidAggregateDecisionChainError,
        )
        self.assertIsNot(InvalidAggregateDecisionChainForkProofError,
                         InvalidAggregateDecisionChainError)
        self.assertIsNot(InvalidAggregateDecisionChainForkDecisionError,
                         InvalidAggregateDecisionChainError)


class IndependenceTest(AggregateDecisionChainForkFixtures):
    def test_inputs_are_not_modified(self):
        items = [proof_item("a", self.adcf_proof(issuer=SITE_A)),
                 proof_item("b", self.adcf_proof(issuer=SITE_B))]
        snapshot = copy.deepcopy(
            (items, self.fork_items, self.policy, self.auth, self.ssp,
             self.signerp, self.ring))
        raw = self.adcf_judge(items)
        self.adcf_report(items)
        self.adcf_verify(raw)
        self.adcf_sign()
        self.assertEqual(
            (items, self.fork_items, self.policy, self.auth, self.ssp,
             self.signerp, self.ring),
            snapshot)

    def test_no_file_is_read_or_written(self):
        items = [proof_item("a", self.adcf_proof(issuer=SITE_A)),
                 proof_item("b", self.adcf_proof(issuer=SITE_B))]
        raw = self.adcf_judge(items)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.adcf_proof()
            self.adcf_proof(self.clean_items)
            self.adcf_report(items)
            self.adcf_judge(items)
            self.adcf_verify(raw)


if __name__ == "__main__":
    unittest.main()
