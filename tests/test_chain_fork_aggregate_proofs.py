"""Tests for signed chain fork aggregate proofs and cross-site adjudication.

Covers :func:`sign_chain_fork_aggregate_proof`,
:func:`verify_chain_fork_aggregate_proof`,
:func:`verify_chain_fork_aggregate_proofs`,
:func:`adjudicate_chain_fork_aggregate_proofs` and
:func:`verify_chain_fork_aggregate_decision`: the signed proof binding
both shared policy digests, the original-order chain materials (id,
root, every successor and the complete versioned decision site policy
history), the complete fork-chain batch report and the signing moment;
offline re-verification recomputing the chain material digests, fork
edges, crossing chains, conflicted set and report status from the bound
materials alone; the verified/invalid-proof/unauthenticated batch
taxonomy with input-order reports; the verify-then-authorize-then-
authenticate per-proof pipeline with fixed reasons; same-site
duplicate/contradiction handling over the complete fork edge set;
cross-site edge-set agreement and threshold acceptance with the common
set kept on insufficient tallies; the canonical signed decision and
its offline re-tally verification; the distinct
InvalidChainProofError/InvalidChainDecisionError
hierarchies; equal-but-independent results, input immutability and the
purely offline guarantee.
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
    InvalidChainDecisionError,
    InvalidChainForkAggregateError,
    InvalidChainProofError,
    adjudicate_chain_fork_aggregate_proofs,
    sign_chain_fork_aggregate_proof,
    verify_chain_fork_aggregate_decision,
    verify_chain_fork_aggregate_proof,
    verify_chain_fork_aggregate_proofs,
)

from test_adjudicate_prune_aggregate_forks import proof_item, site_policy
from test_aggregate_chain_fork_decisions import decision_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_chain_fork_aggregate import (
    ChainForkAggregateChainFixtures,
    rewrap,
)

BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
PROOF_KEYS = ["payload", "signature"]
PROOF_PAYLOAD_KEYS = [
    "chains", "issuer", "keyVersion", "moment", "prunePolicy", "report",
    "sitePolicy", "version",
]
PROOF_CHAIN_KEYS = ["id", "policies", "root", "successors"]
PROOF_RESULT_KEYS = [
    "chains", "issuer", "keyVersion", "moment", "prunePolicyDigest",
    "sitePolicyDigest", "proofDigest", "report", "version",
]
DECISION_PAYLOAD_KEYS = [
    "common", "issuer", "items", "keyVersion", "proofs",
    "prunePolicyDigest", "sitePolicyDigest", "status", "version",
]
ROW_KEYS = ["conclusion", "digest", "edges", "id", "issuer",
            "keyVersion", "reason"]
EDGE_KEYS = ["predecessorDigest", "rootDigest", "successors"]
DECISION_RESULT_KEYS = [
    "common", "proofDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "proofs", "sitePolicyDigest", "status", "version",
]


def versioned_policy_bytes(policy):
    """Canonical compact bytes of a versioned decision site policy."""
    return compact({
        "policyVersion": policy["policyVersion"],
        "sites": {site: sorted(policy["sites"][site])
                  for site in sorted(policy["sites"])},
        "threshold": policy["threshold"],
    })


class ChainForkAggregateProofFixtures(ChainForkAggregateChainFixtures):
    """Forking chain fork aggregate batches and proof helpers."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Sign/adjudicate after every hop's issuance moment.
        self.t = self.m + 20
        self.first_a = self.csucc(
            self.root_one, [decision_item("two", self.decision_b)])
        # A genuinely different first successor: a pure policy rotation.
        self.first_b = self.csucc(
            self.root_one, [], old=self.pv1, new=self.pv2_t1)
        # A third distinct first successor carrying a different decision.
        self.first_c = self.csucc(
            self.root_one,
            [decision_item("three", self.decision_sa)],
            old=self.pv1, new=self.pv1,
            moment=self.t, effective=self.m,
        )
        self.items_one = [
            self.ccitem("b", self.root_one, [self.first_b],
                        policies=[self.pv1, self.pv2_t1]),
            self.ccitem("a", self.root_one, [self.first_a]),
        ]
        self.items_two = [
            self.ccitem("b", self.root_one, [self.first_c]),
            self.ccitem("a", self.root_one, [self.first_a]),
        ]

    def cap_sign(self, items=None, issuer=SITE_A, moment=None, version=1,
                   prune_policy=None, site_policy_=None, ring=None):
        return sign_chain_fork_aggregate_proof(
            self.items_one if items is None else items,
            self.policy if prune_policy is None else prune_policy,
            self.sp if site_policy_ is None else site_policy_,
            self.ring if ring is None else ring,
            self.t if moment is None else moment, issuer, version,
        )

    def cap_proof(self, items=None, issuer=SITE_A, moment=None):
        return self.cap_sign(items=items, issuer=issuer, moment=moment)

    def cap_verify(self, raw, moment=None, prune_policy=None,
               site_policy_=None, ring=None):
        return verify_chain_fork_aggregate_proof(
            raw,
            self.policy if prune_policy is None else prune_policy,
            self.sp if site_policy_ is None else site_policy_,
            self.ring if ring is None else ring,
            self.t if moment is None else moment,
        )

    def cap_report(self, items, **kwargs):
        return verify_chain_fork_aggregate_proofs(
            items, self.policy, self.sp, self.ring, self.t, **kwargs)

    def cap_adjudicate(self, items, sp=None, ring=None, moment=None,
                      issuer=JUDGE, version=1):
        return adjudicate_chain_fork_aggregate_proofs(
            items, self.policy, self.sp if sp is None else sp,
            self.ring if ring is None else ring,
            self.t if moment is None else moment, issuer, version,
        )

    def cap_verify_decision(self, raw, sp=None, ring=None, moment=None):
        return verify_chain_fork_aggregate_decision(
            raw, self.policy, self.sp if sp is None else sp,
            self.ring if ring is None else ring,
            self.t if moment is None else moment,
        )

    def cap_tamper(self, cap_proof, mutate):
        """Mutate the payload and re-sign with the same signer secret."""
        data = parse(cap_proof)
        mutate(data["payload"])
        data["signature"] = hmac.new(
            bytes.fromhex(SECRET_COORD), compact(data["payload"]),
            hashlib.sha256,
        ).hexdigest()
        return compact(data)


class ProofSignTest(ChainForkAggregateProofFixtures):
    def test_canonical_compact_encoding_without_trailing_byte(self):
        raw = self.cap_proof()
        self.assertIsInstance(raw, bytes)
        self.assertTrue(raw.endswith(b"}"))
        self.assertNotIn(b"\n", raw)
        self.assertEqual(compact(parse(raw)), raw)
        data = parse(raw)
        self.assertEqual(list(data.keys()), PROOF_KEYS)
        self.assertEqual(list(data["payload"].keys()), PROOF_PAYLOAD_KEYS)

    def test_identity_moment_and_version_bindings(self):
        payload = parse(self.cap_proof())["payload"]
        self.assertEqual(payload["issuer"], SITE_A)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.t)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)

    def test_chains_bind_every_material_digest_in_input_order(self):
        payload = parse(self.cap_proof())["payload"]
        chains = payload["chains"]
        self.assertEqual([chain["id"] for chain in chains], ["b", "a"])
        self.assertEqual(chains[0]["root"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(chains[0]["successors"],
                         [hashlib.sha256(self.first_b).hexdigest()])
        self.assertEqual(chains[1]["successors"],
                         [hashlib.sha256(self.first_a).hexdigest()])
        for chain in chains:
            self.assertEqual(list(chain.keys()), PROOF_CHAIN_KEYS)
        # The complete versioned decision site policy history is bound
        # per stage.
        self.assertEqual(
            chains[0]["policies"],
            [hashlib.sha256(versioned_policy_bytes(pol)).hexdigest()
             for pol in (self.pv1, self.pv2_t1)],
        )
        self.assertEqual(
            chains[1]["policies"],
            [hashlib.sha256(versioned_policy_bytes(self.pv1)).hexdigest()] * 2,
        )

    def test_both_policy_digests_are_bound(self):
        payload = parse(self.cap_proof())["payload"]
        self.assertEqual(
            payload["prunePolicy"],
            hashlib.sha256(compact({
                "batch": self.policy["batch"],
                "sites": {
                    site: sorted(self.policy["sites"][site])
                    for site in sorted(self.policy["sites"])
                },
                "threshold": self.policy["threshold"],
            })).hexdigest(),
        )
        self.assertEqual(
            payload["sitePolicy"],
            hashlib.sha256(compact({
                "sites": {
                    site: sorted(self.sp["sites"][site])
                    for site in sorted(self.sp["sites"])
                },
                "threshold": self.sp["threshold"],
            })).hexdigest(),
        )

    def test_the_complete_report_is_bound(self):
        raw = self.cap_proof()
        from offline_coordination.replication import (
            verify_chain_fork_aggregate_chains,
        )
        self.assertEqual(
            parse(raw)["payload"]["report"],
            verify_chain_fork_aggregate_chains(
                self.items_one, self.policy, self.sp, self.ring, self.t),
        )

    def test_a_fork_free_batch_is_a_value_error(self):
        no_fork = [self.ccitem("x", self.root_one, [self.first_a])]
        with self.assertRaises(ValueError):
            self.cap_sign(no_fork)

    def test_sign_argument_faults(self):
        with self.assertRaises(ValueError):
            self.cap_sign([])
        with self.assertRaises(ValueError):
            self.cap_sign(self.items_one + self.items_one)
        with self.assertRaises(TypeError):
            self.cap_sign(self.items_one, issuer=9)
        with self.assertRaises(ValueError):
            self.cap_sign(self.items_one, issuer="")
        with self.assertRaises(TypeError):
            self.cap_sign(self.items_one, version=True)
        with self.assertRaises(ValueError):
            self.cap_sign(self.items_one, version=0)
        with self.assertRaises(TypeError):
            self.cap_sign(self.items_one, moment=True)
        with self.assertRaises(ValueError):
            self.cap_sign(self.items_one, moment=-1)

    def test_sign_credential_faults(self):
        with self.assertRaises(AuthenticationError):
            self.cap_sign(self.items_one, issuer="ghost")
        revoked = dict(self.ring)
        revoked[SITE_A] = revoked[SITE_A] + [
            entry(2, "22" * 32, revoked=True)]
        with self.assertRaises(AuthenticationError):
            self.cap_sign(self.items_one, ring=revoked, version=2)

    def test_shared_policy_faults(self):
        with self.assertRaises(ValueError):
            self.cap_sign(
                self.items_one,
                prune_policy={"batch": "x"},
            )
        with self.assertRaises(ValueError):
            self.cap_sign(
                self.items_one,
                site_policy_=site_policy(sites=(SITE_A,), threshold=2),
            )


class ProofVerifyTest(ChainForkAggregateProofFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.cap_proof()

    def test_result_shape_and_bindings(self):
        result = self.cap_verify(self.raw)
        self.assertEqual(list(result.keys()), PROOF_RESULT_KEYS)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["issuer"], SITE_A)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["moment"], self.t)
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        payload = parse(self.raw)["payload"]
        self.assertEqual(result["prunePolicyDigest"], payload["prunePolicy"])
        self.assertEqual(result["sitePolicyDigest"], payload["sitePolicy"])
        self.assertEqual(result["report"], payload["report"])
        self.assertEqual(result["chains"], payload["chains"])

    def test_results_are_equal_but_independent(self):
        first = self.cap_verify(self.raw)
        second = self.cap_verify(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["report"], second["report"])
        first["report"]["items"][0]["status"] = "verified"
        first["chains"][0]["root"] = "00" * 32
        again = self.cap_verify(self.raw)
        self.assertEqual(again["report"]["items"][0]["status"], "conflicted")
        self.assertNotEqual(again["chains"][0]["root"], "00" * 32)

    def test_public_argument_faults(self):
        with self.assertRaises(TypeError):
            self.cap_verify("not-bytes")
        with self.assertRaises(TypeError):
            self.cap_verify(self.raw, prune_policy="not-a-dict")
        with self.assertRaises(TypeError):
            self.cap_verify(self.raw, site_policy_="not-a-dict")
        with self.assertRaises(ValueError):
            self.cap_verify(self.raw,
                        prune_policy={"batch": "b", "sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.cap_verify(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.cap_verify(self.raw, moment=-1)

    def test_wrong_prune_policy_is_a_proof_error(self):
        other = {"batch": "other",
                 "sites": {site: {1} for site in self.policy["sites"]},
                 "threshold": self.policy["threshold"]}
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.raw, prune_policy=other)

    def test_wrong_site_policy_is_a_proof_error(self):
        other = site_policy(
            sites=tuple(self.sp["sites"]),
            threshold=1,
        )
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.raw, site_policy_=other)

    def test_verification_before_signing_moment_is_a_proof_error(self):
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.raw, moment=self.t - 1)

    def test_encoding_faults(self):
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.raw + b"\n")
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(b"not-json")
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(json.dumps(parse(self.raw), indent=2).encode())
        duplicated = self.raw.decode("utf-8").replace(
            '"version":1', '"version":1,"version":1', 1).encode()
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(duplicated)
        with self.assertRaises(TypeError):
            self.cap_verify(b"[]")
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(b"")

    def test_payload_field_faults(self):
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p.__setitem__("version", 2)))
        with self.assertRaises(TypeError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p.__setitem__("version", True)))
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p.__setitem__("issuer", "")))
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p.__setitem__("keyVersion", 0)))
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p.__setitem__("prunePolicy", "00" * 32)))
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p.__setitem__("sitePolicy", "00" * 32)))

    def test_chain_material_binding_faults(self):
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p["chains"].pop(0)))
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p["chains"].reverse()))

        def swap_successor(payload):
            payload["chains"][0]["successors"][0] = "00" * 32
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(self.raw, swap_successor))

        def drop_policy(payload):
            payload["chains"][0]["policies"].pop(0)
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(self.raw, drop_policy))

    def test_report_binding_faults(self):
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(
                self.raw, lambda p: p["report"].__setitem__("forks", [])))

        def tamper_ids(payload):
            payload["report"]["forks"][0]["ids"] = ["a"]
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(self.raw, tamper_ids))

        def tamper_successors(payload):
            payload["report"]["forks"][0]["successors"] = ["00" * 32] * 2
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(self.raw, tamper_successors))

        def tamper_status(payload):
            payload["report"]["items"][0]["status"] = "verified"
            payload["report"]["items"][0]["error"] = None
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(self.raw, tamper_status))

        def tamper_error(payload):
            payload["report"]["items"][0]["error"] = "something-else"
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(self.raw, tamper_error))

        def tamper_head(payload):
            payload["report"]["items"][0]["result"]["headDigest"] = "00" * 32
        with self.assertRaises(InvalidChainProofError):
            self.cap_verify(self.cap_tamper(self.raw, tamper_head))

    def test_conflicted_report_uses_the_cfca_fixed_error(self):
        for item in parse(self.raw)["payload"]["report"]["items"]:
            self.assertEqual(item["error"], "forked-chain-fork-aggregate")

    def test_unknown_revoked_future_expired_credentials_are_authentication(self):
        missing = {site: keys for site, keys in self.ring.items()
                   if site != SITE_A}
        with self.assertRaises(AuthenticationError):
            self.cap_verify(self.raw, ring=missing)
        revoked = dict(self.ring)
        revoked[SITE_A] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            self.cap_verify(self.raw, ring=revoked)
        future = dict(self.ring)
        future[SITE_A] = [entry(1, SECRET_COORD, not_before=self.t + 1)]
        with self.assertRaises(AuthenticationError):
            self.cap_verify(self.raw, ring=future)
        expired = dict(self.ring)
        expired[SITE_A] = [entry(1, SECRET_COORD, not_after=self.t - 1)]
        with self.assertRaises(AuthenticationError):
            self.cap_verify(self.raw, ring=expired)

    def test_bad_signature_is_authentication(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.cap_verify(compact(data))

    def test_error_hierarchy(self):
        # Structure/binding faults reuse the existing chain proof and
        # chain decision error classes rather than introducing new ones.
        self.assertTrue(issubclass(InvalidChainProofError, ValueError))
        self.assertTrue(issubclass(InvalidChainDecisionError, ValueError))
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        self.assertIsNot(InvalidChainProofError, InvalidChainDecisionError)
        self.assertIsNot(InvalidChainProofError,
                         InvalidChainForkAggregateError)
        self.assertIsNot(InvalidChainDecisionError,
                         InvalidChainForkAggregateError)
        # A bad aggregate proof is caught by exactly InvalidChainProofError.
        try:
            self.cap_verify(self.raw + b"\n")
        except InvalidChainProofError:
            pass
        else:  # pragma: no cover - asserted by other tests, kept explicit
            self.fail("expected InvalidChainProofError")


class BatchVerifyTest(ChainForkAggregateProofFixtures):
    def test_reports_in_input_order(self):
        p_a = self.cap_proof(issuer=SITE_A)
        p_b = self.cap_proof(issuer=SITE_B)
        report = self.cap_report([
            proof_item("a", p_a), proof_item("b", b"{}"),
            proof_item("c", p_b),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual([row["id"] for row in report["items"]],
                         ["a", "b", "c"])
        self.assertEqual([row["status"] for row in report["items"]],
                         ["verified", "invalid-proof", "verified"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), ITEM_REPORT_KEYS)
        self.assertIsNone(report["items"][0]["error"])
        self.assertEqual(
            report["items"][0]["result"]["proofDigest"],
            hashlib.sha256(p_a).hexdigest(),
        )
        bad = report["items"][1]
        self.assertIsNone(bad["result"])
        self.assertTrue(bad["error"])

    def test_unauthenticated_is_isolated(self):
        ring = {site: [entry(1, "77" * 32)]
                for site in (SITE_A, SITE_B, SITE_C, JUDGE)}
        report = verify_chain_fork_aggregate_proofs(
            [proof_item("a", self.cap_proof(issuer=SITE_A)),
             proof_item("b", self.cap_proof(issuer=SITE_B))],
            self.policy, self.sp, ring, self.t,
        )
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["unauthenticated", "unauthenticated"],
        )
        self.assertTrue(all(row["error"] for row in report["items"]))
        self.assertTrue(all(row["result"] is None
                            for row in report["items"]))

    def test_structure_validated_upfront(self):
        p_a = self.cap_proof()
        with self.assertRaises(TypeError):
            self.cap_report("x")
        with self.assertRaises(TypeError):
            self.cap_report(["x"])
        with self.assertRaises(ValueError):
            self.cap_report([])
        with self.assertRaises(ValueError):
            self.cap_report([proof_item("a", p_a), proof_item("a", p_a)])
        with self.assertRaises(ValueError):
            self.cap_report([{"id": "a", "proof": p_a, "x": 1}])
        with self.assertRaises(ValueError):
            self.cap_report([proof_item("", p_a)])
        with self.assertRaises(TypeError):
            self.cap_report([proof_item(1, p_a)])
        with self.assertRaises(TypeError):
            self.cap_report([proof_item("a", "x")])

    def test_shared_materials_validated_upfront(self):
        items = [proof_item("a", self.cap_proof())]
        with self.assertRaises(ValueError):
            verify_chain_fork_aggregate_proofs(items, {"batch": "x"}, self.sp,
                                               self.ring, self.t)
        with self.assertRaises(ValueError):
            verify_chain_fork_aggregate_proofs(items, self.policy,
                                               site_policy(sites=(SITE_A,),
                                                           threshold=2),
                                               self.ring, self.t)
        with self.assertRaises(TypeError):
            verify_chain_fork_aggregate_proofs(items, self.policy, self.sp,
                                               "ring", self.t)
        with self.assertRaises(TypeError):
            verify_chain_fork_aggregate_proofs(items, self.policy, self.sp,
                                               self.ring, True)
        with self.assertRaises(ValueError):
            verify_chain_fork_aggregate_proofs(items, self.policy, self.sp,
                                               self.ring, -1)

    def test_results_are_fresh_and_independent(self):
        items = [proof_item("a", self.cap_proof())]
        first = self.cap_report(items)
        second = self.cap_report(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.cap_report(items)["items"][0]["result"]["issuer"], SITE_A)

    def test_inputs_are_not_modified(self):
        items = [proof_item("a", self.cap_proof())]
        snapshot = copy.deepcopy((items, self.policy, self.sp, self.ring))
        self.cap_report(items)
        self.assertEqual((items, self.policy, self.sp, self.ring), snapshot)


class AdjudicationValidationTest(ChainForkAggregateProofFixtures):
    def test_items_container_faults(self):
        p = self.cap_proof()
        with self.assertRaises(TypeError):
            self.cap_adjudicate("x")
        with self.assertRaises(TypeError):
            self.cap_adjudicate(["x"])
        with self.assertRaises(TypeError):
            self.cap_adjudicate([proof_item(1, p)])
        with self.assertRaises(TypeError):
            self.cap_adjudicate([proof_item("a", 1)])

    def test_items_value_faults(self):
        p = self.cap_proof()
        with self.assertRaises(ValueError):
            self.cap_adjudicate([])
        with self.assertRaises(ValueError):
            self.cap_adjudicate([proof_item("", p)])
        with self.assertRaises(ValueError):
            self.cap_adjudicate([proof_item("a", p), proof_item("a", p)])
        with self.assertRaises(ValueError):
            self.cap_adjudicate([{"id": "a", "proof": p, "x": 1}])

    def test_policy_threshold_moment_issuer_version_rules(self):
        p = self.cap_proof()
        items = [proof_item("a", p)]
        with self.assertRaises(ValueError):
            self.cap_adjudicate(
                items, sp=site_policy(sites=(SITE_A,), threshold=2))
        with self.assertRaises(ValueError):
            adjudicate_chain_fork_aggregate_proofs(
                items, {"batch": "x"}, self.sp, self.ring, self.t, JUDGE, 1)
        with self.assertRaises(TypeError):
            self.cap_adjudicate(items, moment=True)
        with self.assertRaises(ValueError):
            self.cap_adjudicate(items, moment=-1)
        with self.assertRaises(TypeError):
            self.cap_adjudicate(items, issuer=7)
        with self.assertRaises(ValueError):
            self.cap_adjudicate(items, issuer="")
        with self.assertRaises(TypeError):
            self.cap_adjudicate(items, version=True)
        with self.assertRaises(ValueError):
            self.cap_adjudicate(items, version=0)

    def test_signing_credentials_have_no_fallback(self):
        items = [proof_item("a", self.cap_proof())]
        with self.assertRaises(AuthenticationError):
            self.cap_adjudicate(items, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.cap_adjudicate(items, issuer=JUDGE, version=2)
        revoked = dict(self.ring)
        revoked[JUDGE] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            self.cap_adjudicate(items, ring=revoked)
        future = dict(self.ring)
        future[JUDGE] = [entry(1, SECRET_COORD, not_before=self.t + 1)]
        with self.assertRaises(AuthenticationError):
            self.cap_adjudicate(items, ring=future)
        expired = dict(self.ring)
        expired[JUDGE] = [entry(1, SECRET_COORD, not_after=self.t - 1)]
        with self.assertRaises(AuthenticationError):
            self.cap_adjudicate(items, ring=expired)

    def test_inputs_are_not_modified(self):
        items = [proof_item("x", self.cap_proof(issuer=SITE_A)),
                 proof_item("y", self.cap_proof(issuer=SITE_B))]
        snapshot = copy.deepcopy((items, self.policy, self.sp, self.ring))
        self.cap_adjudicate(items)
        self.assertEqual((items, self.policy, self.sp, self.ring), snapshot)


class PerItemRulingTest(ChainForkAggregateProofFixtures):
    def rows(self, items, sp=None, ring=None):
        return self.cap_verify_decision(
            self.cap_adjudicate(items, sp=sp, ring=ring),
            sp=sp, ring=ring)["items"]

    def row_by_id(self, items, sp=None, ring=None):
        return {row["id"]: row
                for row in self.rows(items, sp=sp, ring=ring)}

    def test_invalid_bytes_rejected_alone_processing_continues(self):
        rows = self.row_by_id([
            proof_item("good", self.cap_proof(issuer=SITE_A)),
            proof_item("bad", b"{}"),
            proof_item("good2", self.cap_proof(issuer=SITE_B)),
        ])
        bad = rows["bad"]
        self.assertEqual(bad["conclusion"], "invalid")
        self.assertEqual(bad["reason"], "invalid-proof")
        self.assertIsNone(bad["issuer"])
        self.assertIsNone(bad["keyVersion"])
        self.assertIsNone(bad["edges"])
        self.assertEqual(rows["good"]["conclusion"], "valid")
        self.assertEqual(rows["good2"]["conclusion"], "valid")

    def test_unauthorized_site_keeps_identity_and_edges(self):
        ring = dict(self.ring)
        ring["ghost"] = [entry(1, SECRET_COORD)]
        p = self.cap_sign(issuer="ghost", ring=ring)
        rows = self.row_by_id([proof_item("x", p)], ring=ring)
        self.assertEqual(rows["x"]["reason"], "unauthorized-site")
        self.assertEqual(rows["x"]["issuer"], "ghost")
        self.assertIsNotNone(rows["x"]["edges"])

    def test_unauthorized_version(self):
        ring = dict(self.ring)
        ring[SITE_A] = ring[SITE_A] + [entry(2, SECRET_COORD)]
        p = self.cap_sign(issuer=SITE_A, version=2, ring=ring)
        rows = self.row_by_id([proof_item("x", p)], ring=ring)
        self.assertEqual(rows["x"]["reason"], "unauthorized-version")
        self.assertEqual(rows["x"]["keyVersion"], 2)

    def test_credential_states_and_bad_signature(self):
        p = self.cap_proof(issuer=SITE_A)
        for modified, reason in [
            ({k: v for k, v in self.ring.items() if k != SITE_A},
             "credential-unavailable"),
            (self._ring_with(
                SITE_A, entry(1, SECRET_COORD, revoked=True)), "revoked"),
            (self._ring_with(
                SITE_A, entry(1, SECRET_COORD, not_before=self.t + 1)),
             "not-yet-valid"),
            (self._ring_with(
                SITE_A, entry(1, SECRET_COORD, not_after=self.t - 1)),
             "expired"),
        ]:
            rows = self.row_by_id([proof_item("x", p)], ring=modified)
            self.assertEqual(rows["x"]["reason"], reason)
        forged = rewrap(parse(p)["payload"], secret="77" * 32)
        rows = self.row_by_id([proof_item("x", forged)])
        self.assertEqual(rows["x"]["reason"], "bad-signature")
        self.assertEqual(rows["x"]["issuer"], SITE_A)
        self.assertIsNotNone(rows["x"]["edges"])

    def _ring_with(self, site, key_entry):
        ring = dict(self.ring)
        ring[site] = [key_entry]
        return ring

    def test_foreign_policies_and_future_proofs_have_no_identity(self):
        payload = parse(self.cap_proof(issuer=SITE_A))["payload"]
        payload["prunePolicy"] = "bb" * 32
        rows = self.row_by_id([proof_item("x", rewrap(payload))])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])

        payload = parse(self.cap_proof(issuer=SITE_A))["payload"]
        payload["sitePolicy"] = "cc" * 32
        rows = self.row_by_id([proof_item("x", rewrap(payload))])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])

        future = self.cap_proof(issuer=SITE_A, moment=self.t + 10)
        rows = self.row_by_id([proof_item("x", future)])
        self.assertEqual(rows["x"]["reason"], "invalid-proof")
        self.assertIsNone(rows["x"]["issuer"])

    def test_identical_proof_digests_are_duplicates(self):
        p = self.cap_proof(issuer=SITE_A)
        result = self.cap_verify_decision(self.cap_adjudicate(
            [proof_item("first", p), proof_item("second", p)]))
        self.assertEqual(result["status"], "insufficient")
        rows = {row["id"]: row for row in result["items"]}
        self.assertEqual(rows["first"]["conclusion"], "valid")
        self.assertIsNone(rows["first"]["reason"])
        self.assertEqual(rows["second"]["conclusion"], "duplicate")
        self.assertEqual(rows["second"]["reason"], "duplicate")

    def test_same_edge_set_distinct_digests_still_duplicates(self):
        one = self.cap_proof(issuer=SITE_A, moment=self.t)
        two = self.cap_proof(issuer=SITE_A, moment=self.t - 5)
        self.assertNotEqual(one, two)
        result = self.cap_verify_decision(self.cap_adjudicate(
            [proof_item("x", one), proof_item("y", two)]))
        rows = {row["id"]: row for row in result["items"]}
        self.assertEqual(rows["x"]["conclusion"], "valid")
        self.assertEqual(rows["y"]["conclusion"], "duplicate")
        self.assertEqual(result["status"], "insufficient")

    def test_duplicates_alone_cannot_meet_threshold_two(self):
        p = self.cap_proof(issuer=SITE_A)
        result = self.cap_verify_decision(self.cap_adjudicate(
            [proof_item("a", p), proof_item("b", p)]))
        self.assertEqual(result["status"], "insufficient")

    def test_same_site_distinct_edge_sets_contradict(self):
        result = self.cap_verify_decision(self.cap_adjudicate([
            proof_item("a", self.cap_proof(self.items_one, issuer=SITE_A)),
            proof_item("b", self.cap_proof(self.items_two, issuer=SITE_A)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        for row in result["items"]:
            self.assertEqual(row["conclusion"], "contradiction")
            self.assertEqual(row["reason"], "contradiction")
            self.assertEqual(row["issuer"], SITE_A)


class AggregationTest(ChainForkAggregateProofFixtures):
    def test_accepted_binds_the_common_edge_set(self):
        result = self.cap_verify_decision(self.cap_adjudicate([
            proof_item("x", self.cap_proof(issuer=SITE_A)),
            proof_item("y", self.cap_proof(issuer=SITE_B)),
        ]))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(result["common"]), 1)
        edge = result["common"][0]
        self.assertEqual(list(edge.keys()), EDGE_KEYS)
        self.assertEqual(len(edge["successors"]), 2)
        self.assertEqual(edge["successors"], sorted(edge["successors"]))

    def test_below_threshold_keeps_common(self):
        result = self.cap_verify_decision(self.cap_adjudicate(
            [proof_item("x", self.cap_proof(issuer=SITE_A))]))
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["common"])
        accepted = self.cap_verify_decision(self.cap_adjudicate([
            proof_item("x", self.cap_proof(issuer=SITE_A)),
            proof_item("y", self.cap_proof(issuer=SITE_B)),
        ]))
        self.assertEqual(result["common"], accepted["common"])

    def test_no_valid_vote_binds_null_common(self):
        result = self.cap_verify_decision(self.cap_adjudicate([
            proof_item("x", b"{}"), proof_item("y", b"{"),
        ]))
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["common"])

    def test_cross_site_edge_disagreement_is_conflicted(self):
        result = self.cap_verify_decision(self.cap_adjudicate([
            proof_item("x", self.cap_proof(self.items_one, issuer=SITE_A)),
            proof_item("y", self.cap_proof(self.items_two, issuer=SITE_B)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])
        self.assertTrue(
            all(row["conclusion"] == "valid" for row in result["items"]))

    def test_conflict_is_not_outvotable(self):
        result = self.cap_verify_decision(self.cap_adjudicate([
            proof_item("a", self.cap_proof(self.items_one, issuer=SITE_A)),
            proof_item("b", self.cap_proof(self.items_one, issuer=SITE_B)),
            proof_item("c", self.cap_proof(self.items_two, issuer=SITE_C)),
        ]))
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["common"])

    def test_only_valid_rows_count_toward_the_threshold(self):
        result = self.cap_verify_decision(self.cap_adjudicate([
            proof_item("x", self.cap_proof(issuer=SITE_A)),
            proof_item("bad", b"{}"),
        ]))
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["common"])

    def test_rows_sort_by_issuer_then_id_with_invalid_first(self):
        result = self.cap_verify_decision(self.cap_adjudicate([
            proof_item("z", self.cap_proof(issuer=SITE_B)),
            proof_item("a", self.cap_proof(issuer=SITE_A)),
            proof_item("m", b"{}"),
        ]))
        keys = [(row["issuer"] is not None, row["issuer"], row["id"])
                for row in result["items"]]
        self.assertEqual(keys, sorted(keys))
        self.assertIsNone(result["items"][0]["issuer"])


class DecisionPacketShapeTest(ChainForkAggregateProofFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.p_a = self.cap_proof(issuer=SITE_A)
        self.p_b = self.cap_proof(issuer=SITE_B)
        self.items = [proof_item("x", self.p_a), proof_item("y", self.p_b)]
        self.raw = self.cap_adjudicate(self.items)

    def test_canonical_compact_without_trailing_byte(self):
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(parse(self.raw)), self.raw)
        self.assertEqual(list(parse(self.raw).keys()), ["payload", "signature"])
        self.assertEqual(list(parse(self.raw)["payload"].keys()),
                         DECISION_PAYLOAD_KEYS)

    def test_row_shapes_and_proof_digests(self):
        payload = parse(self.raw)["payload"]
        for row in payload["items"]:
            self.assertEqual(list(row.keys()), ROW_KEYS)
            expected = self.p_a if row["id"] == "x" else self.p_b
            self.assertEqual(row["digest"],
                             hashlib.sha256(expected).hexdigest())
            for edge in row["edges"]:
                self.assertEqual(list(edge.keys()), EDGE_KEYS)

    def test_proofs_bound_in_original_input_order(self):
        payload = parse(self.raw)["payload"]
        # The summaries cover every row exactly, but keep the original
        # input order rather than the canonical row order.
        self.assertEqual(
            sorted(payload["proofs"]),
            sorted(row["digest"] for row in payload["items"]),
        )
        self.assertEqual(payload["proofs"], [
            hashlib.sha256(self.p_a).hexdigest(),
            hashlib.sha256(self.p_b).hexdigest(),
        ])
        # Reversing the inputs independently reverses the summary vector
        # while the sorted rows are unchanged.
        reversed_raw = self.cap_adjudicate(list(reversed(self.items)))
        reversed_payload = parse(reversed_raw)["payload"]
        self.assertEqual(
            reversed_payload["proofs"], list(reversed(payload["proofs"])))
        self.assertEqual(
            [row["id"] for row in reversed_payload["items"]],
            [row["id"] for row in payload["items"]],
        )

    def test_reordered_summaries_cover_the_same_multiset(self):
        payload = parse(self.raw)["payload"]
        tampered = dict(payload)
        tampered["proofs"] = list(reversed(payload["proofs"]))
        # Same digest multiset, merely reordered: the rows still cover
        # every summary exactly, so the binding holds.
        self.assertIsNotNone(self.cap_verify_decision(rewrap(tampered)))
        tampered["proofs"] = ["cc" * 32, payload["proofs"][1]]
        with self.assertRaises(InvalidChainDecisionError):
            self.cap_verify_decision(rewrap(tampered))

    def test_policy_digest_and_identity_bindings(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(
            payload["prunePolicyDigest"],
            hashlib.sha256(compact({
                "batch": self.policy["batch"],
                "sites": {
                    site: sorted(self.policy["sites"][site])
                    for site in sorted(self.policy["sites"])
                },
                "threshold": self.policy["threshold"],
            })).hexdigest(),
        )
        self.assertEqual(
            payload["sitePolicyDigest"],
            hashlib.sha256(compact({
                "sites": {
                    site: sorted(self.sp["sites"][site])
                    for site in sorted(self.sp["sites"])
                },
                "threshold": self.sp["threshold"],
            })).hexdigest(),
        )
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["status"], "accepted")


class VerifyDecisionSuccessTest(DecisionPacketShapeTest):
    def test_result_is_fresh_fixed_key_mapping(self):
        result = self.cap_verify_decision(self.raw)
        self.assertEqual(list(result.keys()), DECISION_RESULT_KEYS)
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["proofs"],
                         parse(self.raw)["payload"]["proofs"])

    def test_repeated_calls_share_no_mutable_structure(self):
        first = self.cap_verify_decision(self.raw)
        second = self.cap_verify_decision(self.raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        first["items"][0]["id"] = "tampered"
        first["common"][0]["successors"].append("zz" * 32)
        third = self.cap_verify_decision(self.raw)
        self.assertEqual(third["items"][0]["id"], second["items"][0]["id"])
        self.assertEqual(len(third["common"][0]["successors"]), 2)

    def test_verifier_uses_the_current_keyring(self):
        revoked = dict(self.ring)
        revoked[JUDGE] = [entry(1, SECRET_COORD, revoked=True)]
        with self.assertRaises(AuthenticationError):
            self.cap_verify_decision(self.raw, ring=revoked)
        # A later key rotation does not verify the old signature.
        rotated = dict(self.ring)
        rotated[JUDGE] = [entry(2, SECRET_COORD)]
        with self.assertRaises(AuthenticationError):
            self.cap_verify_decision(self.raw, ring=rotated)


class VerifyDecisionStructureTest(DecisionPacketShapeTest):
    def assert_invalid(self, raw):
        with self.assertRaises(InvalidChainDecisionError):
            self.cap_verify_decision(raw)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            self.cap_verify_decision("x")
        with self.assertRaises(TypeError):
            verify_chain_fork_aggregate_decision(
                self.raw, "x", self.sp, self.ring, self.t)
        with self.assertRaises(TypeError):
            verify_chain_fork_aggregate_decision(
                self.raw, self.policy, "x", self.ring, self.t)
        with self.assertRaises(TypeError):
            verify_chain_fork_aggregate_decision(
                self.raw, self.policy, self.sp, "ring", self.t)
        with self.assertRaises(TypeError):
            self.cap_verify_decision(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.cap_verify_decision(self.raw, moment=-1)

    def test_encoding_faults(self):
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(b"")
        self.assert_invalid(b"{")
        with self.assertRaises(TypeError):
            self.cap_verify_decision(b"[]")

    def test_key_set_and_version_faults(self):
        data = parse(self.raw)
        del data["signature"]
        self.assert_invalid(compact(data))
        payload = parse(self.raw)["payload"]
        del payload["common"]
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["extra"] = 1
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["version"] = 2
        self.assert_invalid(rewrap(payload))

    def test_status_enum_and_field_types(self):
        payload = parse(self.raw)["payload"]
        payload["status"] = "nope"
        self.assert_invalid(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["issuer"] = 7
        with self.assertRaises(TypeError):
            self.cap_verify_decision(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["items"][0]["keyVersion"] = True
        with self.assertRaises(TypeError):
            self.cap_verify_decision(rewrap(payload))
        payload = parse(self.raw)["payload"]
        payload["proofs"] = ["z" * 64]
        self.assert_invalid(rewrap(payload))

    def test_duplicate_keys_and_non_canonical_form(self):
        text = self.raw.decode("utf-8")
        duplicated = text.replace(
            '"version":1', '"version":1,"version":1', 1).encode()
        self.assert_invalid(duplicated)
        self.assert_invalid(json.dumps(parse(self.raw), indent=2).encode())


class VerifyDecisionBindingTest(DecisionPacketShapeTest):
    def assert_invalid(self, payload):
        with self.assertRaises(InvalidChainDecisionError):
            self.cap_verify_decision(rewrap(payload))

    def test_wrong_prune_policy(self):
        other = copy.deepcopy(self.policy)
        other["batch"] = "other-batch"
        with self.assertRaises(InvalidChainDecisionError):
            verify_chain_fork_aggregate_decision(
                self.raw, other, self.sp, self.ring, self.t)

    def test_wrong_site_policy(self):
        other = site_policy(
            sites=tuple(self.sp["sites"]), threshold=1)
        with self.assertRaises(InvalidChainDecisionError):
            verify_chain_fork_aggregate_decision(
                self.raw, self.policy, other, self.ring, self.t)

    def test_tampered_status_and_common_cannot_be_resigned(self):
        payload = parse(self.raw)["payload"]
        payload["status"] = "insufficient"
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["status"] = "conflicted"
        payload["common"] = None
        self.assert_invalid(payload)

    def test_tampered_row_conclusion_cannot_be_resigned(self):
        payload = parse(self.raw)["payload"]
        payload["items"][0]["conclusion"] = "duplicate"
        payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid(payload)

    def test_proof_digest_bindings(self):
        payload = parse(self.raw)["payload"]
        payload["proofs"][0] = "cc" * 32
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["items"][0]["digest"] = "dd" * 32
        self.assert_invalid(payload)

    def test_rows_must_stay_sorted(self):
        payload = parse(self.raw)["payload"]
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(payload)

    def test_common_must_match_the_tallied_edges(self):
        payload = parse(self.raw)["payload"]
        payload["common"] = []
        self.assert_invalid(payload)
        payload = parse(self.raw)["payload"]
        payload["common"][0]["successors"].append("ee" * 32)
        payload["common"][0]["successors"].sort()
        self.assert_invalid(payload)


class VerifyDecisionAuthenticationTest(DecisionPacketShapeTest):
    def test_signature_mismatch(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.cap_verify_decision(compact(data))

    def test_revoked_future_expired_adjudicator(self):
        cases = [
            {JUDGE: [entry(1, SECRET_COORD, revoked=True)]},
            {JUDGE: [entry(1, SECRET_COORD, not_before=self.t + 1)]},
            {JUDGE: [entry(1, SECRET_COORD, not_after=self.t - 1)]},
        ]
        for overrides in cases:
            ring = dict(self.ring)
            ring.update(overrides)
            with self.assertRaises(AuthenticationError):
                verify_chain_fork_aggregate_decision(
                    self.raw, self.policy, self.sp, ring, self.t)

    def test_unknown_adjudicator(self):
        ring = {k: v for k, v in self.ring.items() if k != JUDGE}
        with self.assertRaises(AuthenticationError):
            verify_chain_fork_aggregate_decision(
                self.raw, self.policy, self.sp, ring, self.t)


class IndependenceTest(ChainForkAggregateProofFixtures):
    def test_inputs_are_not_modified(self):
        items = [proof_item("a", self.cap_proof(issuer=SITE_A)),
                 proof_item("b", self.cap_proof(issuer=SITE_B))]
        items_snapshot = copy.deepcopy(items)
        policy_snapshot = copy.deepcopy(self.policy)
        sp_snapshot = copy.deepcopy(self.sp)
        ring_snapshot = copy.deepcopy(self.ring)
        raw = self.cap_adjudicate(items)
        self.cap_report(items)
        self.cap_verify(items[0]["proof"])
        self.cap_verify_decision(raw)
        self.assertEqual(items, items_snapshot)
        self.assertEqual(self.policy, policy_snapshot)
        self.assertEqual(self.sp, sp_snapshot)
        self.assertEqual(self.ring, ring_snapshot)

    def test_no_file_is_read_or_written(self):
        items = [proof_item("a", self.cap_proof(issuer=SITE_A)),
                 proof_item("b", self.cap_proof(issuer=SITE_B))]
        raw = self.cap_adjudicate(items)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.cap_proof()
            self.cap_report(items)
            self.cap_verify(items[0]["proof"])
            self.cap_adjudicate(items)
            self.cap_verify_decision(raw)


if __name__ == "__main__":
    unittest.main()
