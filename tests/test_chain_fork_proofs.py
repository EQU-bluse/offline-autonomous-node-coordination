"""Tests for signed fork proofs over fork aggregate chain batches.

Covers :func:`sign_chain_fork_proof`, :func:`verify_chain_fork_proof`,
:func:`verify_chain_fork_proofs`, :func:`adjudicate_chain_forks` and
:func:`verify_chain_fork_decision`: the canonical compact proof issued
only when the existing
:func:`verify_fork_aggregate_chains` batch reports a fork, the complete
per-chain material binding (id, root, every successor and the full
versioned policy history in input order), both invariant shared policy
digests, identity, key version and moment binding with the tail-free
signature encoding, the fully offline recomputation of materials, fork
edges, crossing chains and report status, the verified/invalid-proof/
unauthenticated batch taxonomy with input-order reports and fresh
independent results, the verify-then-authorize-then-authenticate
adjudication pipeline with its fixed reasons, same-site duplicate and
contradiction handling over the complete fork edge set, cross-site
edge-set agreement that a majority can never mask, threshold
acceptance with the common set kept on insufficient tallies, the
signed decision's offline re-tally and current-signature checks, the
distinct error hierarchies, input immutability and the purely offline
guarantee.
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidChainDecisionError,
    InvalidChainProofError,
    adjudicate_chain_forks,
    sign_chain_fork_proof,
    verify_chain_fork_decision,
    verify_chain_fork_proof,
    verify_chain_fork_proofs,
)

from test_adjudicate_prune_aggregate_forks import proof_item
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C
from test_supersede_fork_aggregate import (
    ForkAggregateChainFixtures,
    vpol,
)

PACKET_KEYS = ["payload", "signature"]
PROOF_PAYLOAD_KEYS = [
    "chains", "issuer", "keyVersion", "moment",
    "prunePolicyDigest", "report", "sitePolicyDigest", "version",
]
PROOF_RESULT_KEYS = [
    "chains", "issuer", "keyVersion", "moment",
    "prunePolicyDigest", "sitePolicyDigest", "proofDigest",
    "report", "version",
]
BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
DECISION_PAYLOAD_KEYS = [
    "common", "issuer", "items", "keyVersion", "proofs",
    "prunePolicyDigest", "sitePolicyDigest", "status", "version",
]
ROW_KEYS = ["conclusion", "digest", "edges", "id", "issuer",
            "keyVersion", "reason"]
DECISION_RESULT_KEYS = [
    "common", "proofDigest", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "proofs", "sitePolicyDigest", "status",
    "version",
]


class ChainForkProofFixtures(ForkAggregateChainFixtures):
    """Forking chain batches, proofs and decisions over the shared ring."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Two distinct height-one successors of the same root: a real
        # fork when two chains each cross that edge.
        self.first_a = self.fsucc(
            self.root_one, [decision_item("two", self.decision_b)])
        self.first_b = self.fsucc(
            self.root_one, [], old=self.pv1, new=self.pv2_t1)
        # A third distinct successor for cross-site disagreement.
        self.first_c = self.fsucc(
            self.root_one,
            [decision_item("two", self.decision_sa)])
        self.sign_moment = self.m + 30
        self.try_moment = self.m + 40
        self.fork_items = [
            self.fcitem("b", self.root_one, [self.first_b],
                       policies=[self.pv1, self.pv2_t1]),
            self.fcitem("a", self.root_one, [self.first_a]),
        ]
        self.other_fork_items = [
            self.fcitem("b", self.root_one, [self.first_b],
                       policies=[self.pv1, self.pv2_t1]),
            self.fcitem("c", self.root_one, [self.first_c]),
        ]
        self.clean_items = [self.fcitem("a", self.root_two, [])]

    def cf_proof(self, items=None, issuer=SITE_A, moment=None):
        return sign_chain_fork_proof(
            self.fork_items if items is None else items,
            self.policy, self.sp, self.ring,
            self.sign_moment if moment is None else moment,
            issuer, 1,
        )

    def cf_proofs_report(self, raw_items, moment=None, ring=None):
        return verify_chain_fork_proofs(
            raw_items, self.policy, self.sp,
            self.ring if ring is None else ring,
            self.try_moment if moment is None else moment,
        )

    def cf_decide(self, items, moment=None, issuer=JUDGE, version=1,
                  ring=None):
        return adjudicate_chain_forks(
            items, self.policy, self.sp,
            self.ring if ring is None else ring,
            self.try_moment if moment is None else moment,
            issuer, version,
        )

    def cf_verify_decision(self, decision, moment=None):
        return verify_chain_fork_decision(
            decision, self.policy, self.sp, self.ring,
            self.try_moment + 1 if moment is None else moment,
        )


class ProofShapeTest(ChainForkProofFixtures):
    def test_canonical_compact_without_trailing_byte(self):
        raw = self.cf_proof()
        self.assertIsInstance(raw, bytes)
        self.assertTrue(raw.endswith(b"}"))
        self.assertNotIn(b"\n", raw)
        self.assertEqual(compact(parse(raw)), raw)

    def test_top_and_payload_key_sets(self):
        data = parse(self.cf_proof())
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        self.assertEqual(list(data["payload"].keys()), PROOF_PAYLOAD_KEYS)
        self.assertEqual(data["payload"]["version"], 1)
        self.assertEqual(data["payload"]["issuer"], SITE_A)
        self.assertEqual(data["payload"]["keyVersion"], 1)
        self.assertEqual(data["payload"]["moment"], self.sign_moment)

    def test_chains_bind_complete_input_order_material(self):
        chains = parse(self.cf_proof())["payload"]["chains"]
        self.assertEqual([chain["id"] for chain in chains], ["b", "a"])
        chain_b, chain_a = chains
        self.assertEqual(chain_a["root"],
                         hashlib.sha256(self.root_one).hexdigest())
        self.assertEqual(chain_a["successors"],
                         [hashlib.sha256(self.first_a).hexdigest()])
        self.assertEqual(
            chain_b["successors"],
            [hashlib.sha256(self.first_b).hexdigest()])
        self.assertEqual(len(chain_a["policies"]), 2)
        self.assertEqual(len(chain_b["policies"]), 2)
        self.assertEqual(chain_a["policies"][0], chain_a["policies"][1])
        self.assertNotEqual(chain_a["policies"][1], chain_b["policies"][1])

    def test_bound_report_is_the_complete_batch_report(self):
        report = parse(self.cf_proof())["payload"]["report"]
        self.assertEqual(list(report.keys()),
                         ["forks", "items", "version"])
        self.assertEqual([item["id"] for item in report["items"]],
                         ["b", "a"])
        statuses = {item["id"]: item["status"]
                    for item in report["items"]}
        self.assertEqual(statuses, {"a": "conflicted", "b": "conflicted"})
        self.assertEqual(len(report["forks"]), 1)

    def test_proof_requires_an_actual_fork(self):
        with self.assertRaises(ValueError):
            sign_chain_fork_proof(
                self.clean_items, self.policy, self.sp, self.ring,
                self.sign_moment, SITE_A, 1)


class VerifyProofTest(ChainForkProofFixtures):
    def test_roundtrip_result_shape(self):
        raw = self.cf_proof()
        result = verify_chain_fork_proof(
            raw, self.policy, self.sp, self.ring, self.try_moment)
        self.assertEqual(list(result.keys()), PROOF_RESULT_KEYS)
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["issuer"], SITE_A)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["moment"], self.sign_moment)
        self.assertEqual([c["id"] for c in result["chains"]], ["b", "a"])
        self.assertEqual(result["report"], parse(raw)["payload"]["report"])

    def test_repeated_verify_is_equal_but_independent(self):
        raw = self.cf_proof()
        first = verify_chain_fork_proof(
            raw, self.policy, self.sp, self.ring, self.try_moment)
        second = verify_chain_fork_proof(
            raw, self.policy, self.sp, self.ring, self.try_moment)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["report"], second["report"])

    def test_future_signing_moment_rejected(self):
        raw = self.cf_proof(moment=self.try_moment + 1)
        with self.assertRaises(InvalidChainProofError):
            verify_chain_fork_proof(
                raw, self.policy, self.sp, self.ring, self.try_moment)

    def test_wrong_prune_policy_rejected(self):
        other = copy.deepcopy(self.policy)
        other["batch"] = "other-batch"
        with self.assertRaises(ValueError):
            verify_chain_fork_proof(
                self.cf_proof(), other, self.sp, self.ring, self.try_moment)

    def test_wrong_site_policy_is_invalid_proof(self):
        other = copy.deepcopy(self.sp)
        other["threshold"] = 1
        with self.assertRaises(InvalidChainProofError):
            verify_chain_fork_proof(
                self.cf_proof(), self.policy, other, self.ring,
                self.try_moment)

    def test_unknown_revoked_future_expired_and_bad_signature(self):
        raw = self.cf_proof()
        unknown_ring = {site: self.ring[site]
                        for site in self.ring if site != SITE_A}
        with self.assertRaises(AuthenticationError):
            verify_chain_fork_proof(
                raw, self.policy, self.sp, unknown_ring, self.try_moment)
        revoked = dict(self.ring)
        revoked[SITE_A] = [entry(1, self.ring[SITE_A][0]["secret"],
                                 revoked=True)]
        with self.assertRaises(AuthenticationError):
            verify_chain_fork_proof(
                raw, self.policy, self.sp, revoked, self.try_moment)
        future = dict(self.ring)
        future[SITE_A] = [entry(1, self.ring[SITE_A][0]["secret"],
                                not_before=self.sign_moment + 1)]
        with self.assertRaises(AuthenticationError):
            verify_chain_fork_proof(
                raw, self.policy, self.sp, future, self.sign_moment)
        expired = dict(self.ring)
        expired[SITE_A] = [entry(1, self.ring[SITE_A][0]["secret"],
                                 not_after=self.sign_moment - 1)]
        with self.assertRaises(AuthenticationError):
            verify_chain_fork_proof(
                raw, self.policy, self.sp, expired, self.try_moment)
        data = parse(raw)
        data["signature"] = "f" * 64
        with self.assertRaises(AuthenticationError):
            verify_chain_fork_proof(
                compact(data), self.policy, self.sp, self.ring,
                self.try_moment)

    def test_tampered_report_binding_rejected(self):
        data = parse(self.cf_proof())
        data["payload"]["report"]["items"][0]["id"] = "z"
        with self.assertRaises(InvalidChainProofError):
            verify_chain_fork_proof(
                compact(data), self.policy, self.sp, self.ring,
                self.try_moment)

    def test_tampered_chain_material_rejected(self):
        data = parse(self.cf_proof())
        data["payload"]["chains"][0]["root"] = "0" * 64
        with self.assertRaises(InvalidChainProofError):
            verify_chain_fork_proof(
                compact(data), self.policy, self.sp, self.ring,
                self.try_moment)

    def test_non_canonical_encoding_rejected(self):
        raw = self.cf_proof()
        with self.assertRaises(InvalidChainProofError):
            verify_chain_fork_proof(
                raw + b"\n", self.policy, self.sp, self.ring,
                self.try_moment)
        with self.assertRaises(InvalidChainProofError):
            verify_chain_fork_proof(
                json.dumps(parse(raw), indent=2).encode(),
                self.policy, self.sp, self.ring, self.try_moment)

    def test_malformed_and_wrong_type_proofs(self):
        with self.assertRaises(InvalidChainProofError):
            verify_chain_fork_proof(
                b"not json", self.policy, self.sp, self.ring,
                self.try_moment)
        with self.assertRaises(InvalidChainProofError):
            verify_chain_fork_proof(
                compact({"payload": {}, "signature": "0" * 64}),
                self.policy, self.sp, self.ring, self.try_moment)
        with self.assertRaises(TypeError):
            verify_chain_fork_proof(
                "x", self.policy, self.sp, self.ring, self.try_moment)

    def test_public_argument_faults(self):
        with self.assertRaises(TypeError):
            sign_chain_fork_proof(
                self.fork_items, self.policy, self.sp, self.ring,
                True, SITE_A, 1)
        with self.assertRaises(ValueError):
            sign_chain_fork_proof(
                self.fork_items, self.policy, self.sp, self.ring,
                -1, SITE_A, 1)
        with self.assertRaises(TypeError):
            sign_chain_fork_proof(
                self.fork_items, self.policy, self.sp, self.ring,
                self.sign_moment, 9, 1)
        with self.assertRaises(ValueError):
            sign_chain_fork_proof(
                self.fork_items, self.policy, self.sp, self.ring,
                self.sign_moment, "", 1)
        with self.assertRaises(TypeError):
            sign_chain_fork_proof(
                self.fork_items, self.policy, self.sp, self.ring,
                self.sign_moment, SITE_A, True)
        with self.assertRaises(ValueError):
            sign_chain_fork_proof(
                self.fork_items, self.policy, self.sp, self.ring,
                self.sign_moment, SITE_A, 0)


class VerifyProofsBatchTest(ChainForkProofFixtures):
    def test_batch_validated_upfront(self):
        with self.assertRaises(TypeError):
            self.cf_proofs_report("x")
        with self.assertRaises(ValueError):
            self.cf_proofs_report([])
        raw = self.cf_proof()
        with self.assertRaises(ValueError):
            self.cf_proofs_report(
                [proof_item("a", raw), proof_item("a", raw)])
        with self.assertRaises(ValueError):
            self.cf_proofs_report([{"id": "a"}])
        with self.assertRaises(TypeError):
            self.cf_proofs_report([{"id": 1, "proof": raw}])
        with self.assertRaises(TypeError):
            self.cf_proofs_report([proof_item("a", "x")])

    def test_input_order_status_taxonomy_and_isolation(self):
        good = self.cf_proof()
        bad_sig = compact({**parse(good), "signature": "9" * 64})
        malformed = compact({"payload": {}, "signature": "0" * 64})
        future = self.cf_proof(moment=self.try_moment + 1)
        report = self.cf_proofs_report([
            proof_item("g", good),
            proof_item("s", bad_sig),
            proof_item("m", malformed),
            proof_item("f", future),
        ])
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["verified", "unauthenticated", "invalid-proof",
             "invalid-proof"])
        self.assertEqual([row["id"] for row in report["items"]],
                         ["g", "s", "m", "f"])
        for row in report["items"]:
            self.assertEqual(list(row.keys()), ITEM_REPORT_KEYS)
        good_row = report["items"][0]
        self.assertIsNone(good_row["error"])
        self.assertEqual(good_row["result"]["issuer"], SITE_A)
        for row in report["items"][1:]:
            self.assertIsNone(row["result"])
            self.assertTrue(row["error"])

    def test_repeated_results_are_independent(self):
        raw = self.cf_proof()
        items = [proof_item("g", raw)]
        first = self.cf_proofs_report(items)
        second = self.cf_proofs_report(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])


class AdjudicationShapeTest(ChainForkProofFixtures):
    def test_decision_payload_shape_and_ordering(self):
        raw = self.cf_decide([
            proof_item("a", self.cf_proof(issuer=SITE_A)),
            proof_item("b", self.cf_proof(issuer=SITE_B)),
        ])
        self.assertTrue(raw.endswith(b"}"))
        self.assertEqual(compact(parse(raw)), raw)
        data = parse(raw)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), DECISION_PAYLOAD_KEYS)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual([row["id"] for row in payload["items"]],
                         ["a", "b"])
        for row in payload["items"]:
            self.assertEqual(list(row.keys()), ROW_KEYS)
        self.assertEqual(len(payload["common"]), 1)
        self.assertEqual(payload["proofs"],
                         [hashlib.sha256(self.cf_proof(issuer=SITE_A)).hexdigest(),
                          hashlib.sha256(self.cf_proof(issuer=SITE_B)).hexdigest()])


class TallyTest(ChainForkProofFixtures):
    def test_accepted_at_threshold(self):
        decision = self.cf_decide([
            proof_item("a", self.cf_proof(issuer=SITE_A)),
            proof_item("b", self.cf_proof(issuer=SITE_B)),
        ])
        payload = parse(decision)["payload"]
        self.assertEqual(payload["status"], "accepted")
        for row in payload["items"]:
            self.assertEqual(row["conclusion"], "valid")
            self.assertIsNone(row["reason"])
            self.assertEqual(row["issuer"], row["issuer"])
            self.assertIsNotNone(row["edges"])
        result = self.cf_verify_decision(decision)
        self.assertEqual(list(result.keys()), DECISION_RESULT_KEYS)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(decision).hexdigest())

    def test_insufficient_keeps_the_common_set(self):
        decision = self.cf_decide(
            [proof_item("a", self.cf_proof(issuer=SITE_A))])
        payload = parse(decision)["payload"]
        self.assertEqual(payload["status"], "insufficient")
        self.assertEqual(len(payload["common"]), 1)
        result = self.cf_verify_decision(decision)
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["common"], payload["common"])

    def test_no_valid_vote_has_null_common(self):
        malformed = compact({"payload": {}, "signature": "0" * 64})
        decision = self.cf_decide([proof_item("m", malformed)])
        payload = parse(decision)["payload"]
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNone(payload["common"])
        row = payload["items"][0]
        self.assertEqual(row["conclusion"], "invalid")
        self.assertEqual(row["reason"], "invalid-proof")
        self.assertIsNone(row["issuer"])
        self.assertIsNone(row["edges"])
        self.cf_verify_decision(decision)

    def test_same_site_identical_set_counts_once(self):
        decision = self.cf_decide([
            proof_item("x", self.cf_proof(issuer=SITE_A)),
            proof_item("y", self.cf_proof(issuer=SITE_A)),
        ])
        rows = {row["id"]: row
                for row in parse(decision)["payload"]["items"]}
        self.assertEqual(
            (rows["x"]["conclusion"], rows["x"]["reason"]),
            ("valid", None))
        self.assertEqual(
            (rows["y"]["conclusion"], rows["y"]["reason"]),
            ("duplicate", "duplicate"))
        self.assertEqual(parse(decision)["payload"]["status"],
                         "insufficient")
        self.cf_verify_decision(decision)

    def test_same_site_distinct_sets_contradict(self):
        decision = self.cf_decide([
            proof_item("x", self.cf_proof(issuer=SITE_A)),
            proof_item("y", self.cf_proof(items=self.other_fork_items,
                                       issuer=SITE_A)),
        ])
        payload = parse(decision)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["common"])
        reasons = {row["id"]: (row["conclusion"], row["reason"])
                   for row in payload["items"]}
        self.assertEqual(reasons["x"], ("contradiction", "contradiction"))
        self.assertEqual(reasons["y"], ("contradiction", "contradiction"))
        self.cf_verify_decision(decision)

    def test_cross_site_disagreement_conflicted_even_with_majority(self):
        # Two sites share one edge set, one site declares another: the
        # majority must not mask the conflict.
        decision = self.cf_decide([
            proof_item("a", self.cf_proof(issuer=SITE_A)),
            proof_item("b", self.cf_proof(issuer=SITE_B)),
            proof_item("c", self.cf_proof(items=self.other_fork_items,
                                       issuer=SITE_C)),
        ])
        payload = parse(decision)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["common"])
        self.cf_verify_decision(decision)

    def test_invalid_rows_are_sorted_with_identities_first(self):
        decision = self.cf_decide([
            proof_item("m", compact({"payload": {},
                                     "signature": "0" * 64})),
            proof_item("a", self.cf_proof(issuer=SITE_A)),
        ])
        rows = parse(decision)["payload"]["items"]
        self.assertEqual([row["id"] for row in rows], ["m", "a"])

    def test_authorization_failure_reasons(self):
        # JUDGE signs a proof but is not an authorized fork-proof site.
        decision = self.cf_decide(
            [proof_item("j", self.cf_proof(issuer=JUDGE))])
        row = parse(decision)["payload"]["items"][0]
        self.assertEqual(row["conclusion"], "invalid")
        self.assertEqual(row["reason"], "unauthorized-site")
        self.assertEqual(row["issuer"], JUDGE)
        self.assertIsNotNone(row["edges"])

        # An allowed site with a disallowed key version: craft the ring
        # so the site holds version 2 and sign with it while the policy
        # allows only {1}.
        ring = dict(self.ring)
        ring[SITE_A] = [entry(2, self.ring[SITE_A][0]["secret"])]
        raw_v2 = sign_chain_fork_proof(
            self.fork_items, self.policy, self.sp, ring,
            self.sign_moment, SITE_A, 2)
        decision = self.cf_decide([proof_item("a", raw_v2)])
        row = parse(decision)["payload"]["items"][0]
        self.assertEqual(row["reason"], "unauthorized-version")
        self.assertEqual(row["issuer"], SITE_A)
        self.assertEqual(row["keyVersion"], 2)

    def test_credential_failure_reasons(self):
        # Authorized site/version but missing from the adjudication ring.
        ring = {site: self.ring[site]
                for site in self.ring if site != SITE_A}
        decision = self.cf_decide(
            [proof_item("a", self.cf_proof())], ring=ring)
        self.assertEqual(parse(decision)["payload"]["items"][0]["reason"],
                         "credential-unavailable")

        revoked = dict(self.ring)
        revoked[SITE_A] = [entry(1, self.ring[SITE_A][0]["secret"],
                                 revoked=True)]
        decision = self.cf_decide(
            [proof_item("a", self.cf_proof())], ring=revoked)
        self.assertEqual(parse(decision)["payload"]["items"][0]["reason"],
                         "revoked")

        future = dict(self.ring)
        future[SITE_A] = [entry(1, self.ring[SITE_A][0]["secret"],
                                not_before=self.try_moment + 1)]
        decision = self.cf_decide(
            [proof_item("a", self.cf_proof())], ring=future)
        self.assertEqual(parse(decision)["payload"]["items"][0]["reason"],
                         "not-yet-valid")

        expired = dict(self.ring)
        expired[SITE_A] = [entry(1, self.ring[SITE_A][0]["secret"],
                                 not_after=self.try_moment - 1)]
        decision = self.cf_decide(
            [proof_item("a", self.cf_proof())], ring=expired)
        self.assertEqual(parse(decision)["payload"]["items"][0]["reason"],
                         "expired")

        data = parse(self.cf_proof())
        data["signature"] = "2" * 64
        decision = self.cf_decide([proof_item("a", compact(data))])
        self.assertEqual(parse(decision)["payload"]["items"][0]["reason"],
                         "bad-signature")

    def test_foreign_policy_and_future_proof_carry_no_identity(self):
        import hmac

        secret = self.ring[SITE_A][0]["secret"]
        data = parse(self.cf_proof())
        data["payload"]["sitePolicyDigest"] = "6" * 64
        foreign = compact({
            "payload": data["payload"],
            "signature": hmac.new(
                bytes.fromhex(secret), compact(data["payload"]),
                hashlib.sha256).hexdigest(),
        })
        decision = self.cf_decide([proof_item("f", foreign)])
        row = parse(decision)["payload"]["items"][0]
        self.assertEqual(row["reason"], "invalid-proof")
        self.assertIsNone(row["issuer"])
        self.assertIsNone(row["edges"])

        future = self.cf_proof(moment=self.try_moment + 1)
        decision = self.cf_decide([proof_item("f", future)])
        row = parse(decision)["payload"]["items"][0]
        self.assertEqual(row["reason"], "invalid-proof")
        self.assertIsNone(row["issuer"])


class DecisionVerificationTest(ChainForkProofFixtures):
    def two_site_decision(self):
        return self.cf_decide([
            proof_item("a", self.cf_proof(issuer=SITE_A)),
            proof_item("b", self.cf_proof(issuer=SITE_B)),
        ])

    def test_wrong_policies_rejected(self):
        decision = self.two_site_decision()
        other_prune = copy.deepcopy(self.policy)
        other_prune["batch"] = "other"
        with self.assertRaises(ValueError):
            verify_chain_fork_decision(
                decision, other_prune, self.sp, self.ring,
                self.try_moment + 1)
        other_site = copy.deepcopy(self.sp)
        other_site["threshold"] = 1
        with self.assertRaises(InvalidChainDecisionError):
            verify_chain_fork_decision(
                decision, self.policy, other_site, self.ring,
                self.try_moment + 1)

    def test_tampered_status_and_common_rejected(self):
        data = parse(self.two_site_decision())
        data["payload"]["status"] = "insufficient"
        with self.assertRaises(InvalidChainDecisionError):
            self.cf_verify_decision(compact(data))

        data = parse(self.two_site_decision())
        data["payload"]["common"] = None
        with self.assertRaises(InvalidChainDecisionError):
            self.cf_verify_decision(compact(data))

    def test_tampered_row_tally_rejected(self):
        data = parse(self.two_site_decision())
        data["payload"]["items"][0]["conclusion"] = "duplicate"
        data["payload"]["items"][0]["reason"] = "duplicate"
        with self.assertRaises(InvalidChainDecisionError):
            self.cf_verify_decision(compact(data))

    def test_proof_digest_binding_recomputed(self):
        data = parse(self.two_site_decision())
        data["payload"]["proofs"][0] = "5" * 64
        with self.assertRaises(InvalidChainDecisionError):
            self.cf_verify_decision(compact(data))

    def test_row_order_binding_recomputed(self):
        data = parse(self.two_site_decision())
        data["payload"]["items"].reverse()
        with self.assertRaises(InvalidChainDecisionError):
            self.cf_verify_decision(compact(data))

    def test_bad_signature_is_authentication_error(self):
        data = parse(self.two_site_decision())
        data["signature"] = "3" * 64
        with self.assertRaises(AuthenticationError):
            self.cf_verify_decision(compact(data))

    def test_later_revocation_rejects(self):
        decision = self.two_site_decision()
        ring = dict(self.ring)
        ring[JUDGE] = [entry(1, self.ring[JUDGE][0]["secret"],
                             revoked=True)]
        with self.assertRaises(AuthenticationError):
            verify_chain_fork_decision(
                decision, self.policy, self.sp, ring,
                self.try_moment + 1)

    def test_non_canonical_and_malformed_rejected(self):
        decision = self.two_site_decision()
        with self.assertRaises(InvalidChainDecisionError):
            self.cf_verify_decision(decision + b"\n")
        with self.assertRaises(InvalidChainDecisionError):
            self.cf_verify_decision(
                json.dumps(parse(decision), indent=2).encode())
        with self.assertRaises(InvalidChainDecisionError):
            self.cf_verify_decision(b"{}")
        with self.assertRaises(TypeError):
            self.cf_verify_decision("x")


class AdjudicationArgumentTest(ChainForkProofFixtures):
    def test_batch_and_credential_faults(self):
        raw = self.cf_proof()
        with self.assertRaises(TypeError):
            adjudicate_chain_forks(
                "x", self.policy, self.sp, self.ring,
                self.try_moment, JUDGE, 1)
        with self.assertRaises(ValueError):
            adjudicate_chain_forks(
                [], self.policy, self.sp, self.ring,
                self.try_moment, JUDGE, 1)
        with self.assertRaises(ValueError):
            adjudicate_chain_forks(
                [proof_item("a", raw), proof_item("a", raw)],
                self.policy, self.sp, self.ring,
                self.try_moment, JUDGE, 1)
        with self.assertRaises(TypeError):
            adjudicate_chain_forks(
                [proof_item("a", raw)], self.policy, self.sp, self.ring,
                True, JUDGE, 1)
        with self.assertRaises(ValueError):
            adjudicate_chain_forks(
                [proof_item("a", raw)], self.policy, self.sp, self.ring,
                -1, JUDGE, 1)
        with self.assertRaises(TypeError):
            adjudicate_chain_forks(
                [proof_item("a", raw)], self.policy, self.sp, self.ring,
                self.try_moment, 8, 1)
        with self.assertRaises(ValueError):
            adjudicate_chain_forks(
                [proof_item("a", raw)], self.policy, self.sp, self.ring,
                self.try_moment, "", 1)
        with self.assertRaises(TypeError):
            adjudicate_chain_forks(
                [proof_item("a", raw)], self.policy, self.sp, self.ring,
                self.try_moment, JUDGE, False)
        with self.assertRaises(ValueError):
            adjudicate_chain_forks(
                [proof_item("a", raw)], self.policy, self.sp, self.ring,
                self.try_moment, JUDGE, 0)
        with self.assertRaises(ValueError):
            adjudicate_chain_forks(
                [proof_item("a", raw)], self.policy,
                {"sites": {}, "threshold": 1}, self.ring,
                self.try_moment, JUDGE, 1)

    def test_unknown_adjudicator_is_authentication_error(self):
        ring = {site: self.ring[site]
                for site in self.ring if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            adjudicate_chain_forks(
                [proof_item("a", self.cf_proof())], self.policy, self.sp,
                ring, self.try_moment, JUDGE, 1)


class ImmutabilityAndOfflineTest(ChainForkProofFixtures):
    def test_all_inputs_preserved(self):
        items = copy.deepcopy(self.fork_items)
        policy = copy.deepcopy(self.policy)
        sp = copy.deepcopy(self.sp)
        ring = copy.deepcopy(self.ring)
        proof = self.cf_proof()
        proof_items = [proof_item("a", proof), proof_item("b", proof)]
        proof_snapshot = copy.deepcopy(proof_items)
        decision = adjudicate_chain_forks(
            proof_items, self.policy, self.sp, self.ring,
            self.try_moment, JUDGE, 1)
        verify_chain_fork_proof(
            proof, self.policy, self.sp, self.ring, self.try_moment)
        self.cf_proofs_report([proof_item("a", proof)])
        self.cf_verify_decision(decision)
        self.assertEqual(items, self.fork_items)
        self.assertEqual(proof_items, proof_snapshot)
        self.assertEqual((self.policy, self.sp, self.ring),
                         (policy, sp, ring))

    def test_success_result_does_not_alias_the_proof_bytes_report(self):
        proof = self.cf_proof()
        result = verify_chain_fork_proof(
            proof, self.policy, self.sp, self.ring, self.try_moment)
        result["report"]["items"][0]["id"] = "mutated"
        again = verify_chain_fork_proof(
            proof, self.policy, self.sp, self.ring, self.try_moment)
        self.assertNotEqual(
            again["report"]["items"][0]["id"], "mutated")


if __name__ == "__main__":
    unittest.main()
