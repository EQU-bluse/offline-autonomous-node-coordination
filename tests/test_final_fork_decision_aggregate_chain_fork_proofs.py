"""Tests for signed fork proofs, multi-site threshold adjudication and
offline decision verification over final fork decision aggregate chain
batches.

Covers :func:`sign_final_fork_decision_aggregate_chain_fork_proof`,
:func:`verify_final_fork_decision_aggregate_chain_fork_proofs`,
:func:`adjudicate_final_fork_decision_aggregate_chain_forks` and
:func:`verify_final_fork_decision_aggregate_chain_fork_decision`: the
canonical proof packet binding every chain root, successor and stage
policy digest together with the complete batch report and its possibly
empty fork edge collection (failed chains never contribute an edge),
the five invariant policy digest bindings, the batch proof verifier
with its verified/invalid-proof/unauthenticated taxonomy in input
order, the adjudication pipeline (structural re-verification, exact
site/key-version authorization against the proof site policy, keyring
authentication), same-site duplicate/contradiction handling, cross-site
declaration agreement with no majority override, threshold acceptance
with the common declaration kept on insufficient tallies, the signed
decision binding six policy digests and the term-by-term proof digest
vector independent of the input order, the offline decision re-tally
recomputing every binding, the credential rules, the distinct error
hierarchy, equal-but-independent results, input immutability and the
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
    InvalidFinalForkDecisionAggregateChainForkDecisionError,
    InvalidFinalForkDecisionAggregateChainForkProofError,
    SECRET,
    _prune_batch_site_policy_bytes,
    _prune_compact,
    _usable_checkpoint_key,
    _validated_keyring,
    _verdict_policy_bytes,
    adjudicate_final_fork_decision_aggregate_chain_forks,
    sign_final_fork_decision_aggregate_chain_fork_proof,
    verify_final_fork_decision_aggregate_chain_fork_decision,
    verify_final_fork_decision_aggregate_chain_fork_proofs,
    verify_final_fork_decision_aggregate_chains,
)

from test_final_fork_decision_aggregate_chains import (
    FinalForkDecisionAggregateChainsFixtures,
)
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C

PACKET_KEYS = ["payload", "signature"]
PROOF_PAYLOAD_KEYS = [
    "adjudicationSitePolicy", "authorizationPolicy", "chains", "issuer",
    "keyVersion", "moment", "prunePolicy", "report", "signerSitePolicy",
    "sitePolicy", "version",
]
PROOF_RESULT_KEYS = [
    "adjudicationSitePolicyDigest", "authorizationPolicyDigest", "chains",
    "issuer", "keyVersion", "moment", "proofDigest", "prunePolicyDigest",
    "report", "signerSitePolicyDigest", "sitePolicyDigest", "version",
]
BATCH_REPORT_KEYS = ["items", "version"]
ITEM_REPORT_KEYS = ["error", "id", "result", "status"]
DECISION_PAYLOAD_KEYS = [
    "adjudicationSitePolicyDigest", "authorizationPolicyDigest", "common",
    "issuer", "items", "keyVersion", "proofSitePolicyDigest", "proofs",
    "prunePolicyDigest", "signerSitePolicyDigest", "sitePolicyDigest",
    "status", "version",
]
DECISION_ROW_KEYS = [
    "conclusion", "digest", "edges", "id", "issuer", "keyVersion",
    "reason",
]
DECISION_RESULT_KEYS = [
    "adjudicationSitePolicyDigest", "authorizationPolicyDigest", "common",
    "issuer", "items", "keyVersion", "proofDigest",
    "proofSitePolicyDigest", "proofs", "prunePolicyDigest",
    "signerSitePolicyDigest", "sitePolicyDigest", "status", "version",
]
EDGE_KEYS = ["rootDigest", "predecessorDigest", "successors"]


def compact(obj):
    """One canonical compact envelope, matching the production encoding."""
    return _prune_compact(obj)


def parse(raw):
    return json.loads(raw.decode("utf-8"))


def proof_item(item_id, proof):
    """One proof batch item: a unique id and the proof bytes."""
    return {"id": item_id, "proof": proof}


class FinalForkDecisionAggregateChainForkProofsFixtures(
    FinalForkDecisionAggregateChainsFixtures
):
    """Signed fork proofs and adjudication decisions over the chains."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # The proof site policy authorizes the exact proof signer
        # identity and key version at adjudication time; it is the sixth
        # policy digest bound inside every decision.
        self.psp = {"sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 2}
        # Two verified chains forking under one root, and the same
        # trajectories extended identically (no fork).
        self.fork_items = [
            self.ffitem("a", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1]),
        ]
        self.clean_items = [
            self.ffitem("a", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
        ]
        self.fork_proofs = [
            proof_item("x", self.ffproof(self.fork_items, SITE_A)),
            proof_item("y", self.ffproof(self.fork_items, SITE_B)),
        ]
        self.free_proofs = [
            proof_item("x", self.ffproof(self.clean_items, SITE_A)),
            proof_item("y", self.ffproof(self.clean_items, SITE_B)),
        ]
        self.decision = self.ffdecision(self.fork_proofs)

    def ffproof(self, items, issuer=SITE_A, moment=None, ring=None):
        return sign_final_fork_decision_aggregate_chain_fork_proof(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring if ring is None else ring,
            self.vmoment if moment is None else moment, issuer, 1)

    def ffbatch(self, items, ring=None, moment=None):
        return verify_final_fork_decision_aggregate_chain_fork_proofs(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.ring if ring is None else ring,
            self.vmoment if moment is None else moment)

    def ffdecision(self, items, issuer=JUDGE, moment=None, ring=None,
                   psp=None):
        return adjudicate_final_fork_decision_aggregate_chain_forks(
            items, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.psp if psp is None else psp,
            self.ring if ring is None else ring,
            self.vmoment if moment is None else moment, issuer, 1)

    def ffverify_decision(self, raw, ring=None, moment=None, psp=None):
        return verify_final_fork_decision_aggregate_chain_fork_decision(
            raw, self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, self.psp if psp is None else psp,
            self.ring if ring is None else ring,
            self.vmoment if moment is None else moment)

    def ffrewrap(self, payload, moment=None, issuer=None, version=None):
        """Re-seal an edited decision payload (default JUDGE key)."""
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

    def assert_invalid_decision(self, raw, ring=None, moment=None, psp=None):
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionError
        ):
            self.ffverify_decision(raw, ring=ring, moment=moment, psp=psp)


class ProofShapeTest(FinalForkDecisionAggregateChainForkProofsFixtures,
                     unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.ffproof(self.fork_items)
        self.payload = parse(self.raw)

    def test_envelope_and_payload_keys(self):
        self.assertEqual(list(self.payload.keys()), PACKET_KEYS)
        self.assertEqual(
            sorted(self.payload["payload"].keys()), PROOF_PAYLOAD_KEYS)

    def test_canonical_compact_encoding(self):
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertFalse(self.raw.endswith(b"\n"))
        self.assertEqual(compact(self.payload), self.raw)
        self.assertNotIn(" ", self.raw.decode("utf-8"))

    def test_chain_materials_bound_in_input_order(self):
        chains = self.payload["payload"]["chains"]
        self.assertEqual([c["id"] for c in chains], ["a", "b"])
        for chain, item in zip(chains, self.fork_items):
            self.assertEqual(
                chain["root"], hashlib.sha256(item["root"]).hexdigest())
            self.assertEqual(
                chain["successors"],
                [hashlib.sha256(s).hexdigest()
                 for s in item["successors"]])
            self.assertEqual(len(chain["policies"]), len(item["policies"]))

    def test_report_is_the_chain_batch_report(self):
        report = verify_final_fork_decision_aggregate_chains(
            self.fork_items, self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, self.ring, self.vmoment)
        self.assertEqual(self.payload["payload"]["report"], report)
        fork, = report["forks"]
        self.assertEqual(fork["ids"], ["a", "b"])

    def test_five_policy_digest_bindings(self):
        payload = self.payload["payload"]
        self.assertEqual(
            payload["prunePolicy"],
            hashlib.sha256(_verdict_policy_bytes(self.policy)).hexdigest())
        for name, policy in (
            ("authorizationPolicy", self.auth),
            ("sitePolicy", self.ssp),
            ("signerSitePolicy", self.fsignerp),
            ("adjudicationSitePolicy", self.adjp),
        ):
            self.assertEqual(
                payload[name],
                hashlib.sha256(
                    _prune_batch_site_policy_bytes(policy)).hexdigest(),
                name)

    def test_identity_moment_and_version(self):
        payload = self.payload["payload"]
        self.assertEqual(payload["issuer"], SITE_A)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.vmoment)
        self.assertEqual(payload["version"], 1)

    def test_fork_free_batch_still_signs_with_empty_edges(self):
        raw = self.ffproof(self.clean_items)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["report"]["forks"], [])
        self.assertEqual(compact(parse(raw)), raw)

    def test_failed_chains_contribute_no_edges(self):
        items = [
            self.ffitem("ok", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("bad", self.froot_one, [self.s_t1, b"{}"],
                       [self.pv1, self.pv2_t1, self.pv1]),
        ]
        payload = parse(self.ffproof(items))["payload"]
        self.assertEqual(payload["report"]["forks"], [])
        statuses = [i["status"] for i in payload["report"]["items"]]
        self.assertEqual(statuses, ["verified", "invalid-chain"])


class ProofSignValidationTest(
    FinalForkDecisionAggregateChainForkProofsFixtures, unittest.TestCase
):
    def test_non_list_items_is_type_error(self):
        with self.assertRaises(TypeError):
            self.ffproof((self.fork_items[0],))

    def test_empty_list_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffproof([])

    def test_wrong_item_key_set(self):
        with self.assertRaises(ValueError):
            self.ffproof([{"id": "a", "root": self.froot_one}])

    def test_duplicate_id_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffproof([
                self.ffitem("a", self.froot_one),
                self.ffitem("a", self.froot_two),
            ])

    def test_wrong_policy_count_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffproof([
                self.ffitem("a", self.froot_one, [self.s_grow],
                           [self.pv1]),
            ])

    def test_illegal_shared_policy_is_value_error(self):
        with self.assertRaises(ValueError):
            sign_final_fork_decision_aggregate_chain_fork_proof(
                self.fork_items, self.policy, self.auth, self.ssp,
                self.fsignerp, {"sites": {}, "threshold": 1},
                self.ring, self.vmoment, SITE_A, 1)

    def test_bool_moment_never_poses_as_int(self):
        with self.assertRaises(TypeError):
            self.ffproof(self.fork_items, moment=True)

    def test_negative_moment_is_value_error(self):
        with self.assertRaises(ValueError):
            self.ffproof(self.fork_items, moment=-1)

    def test_issuer_and_version_validation(self):
        for issuer, version, error in (
            (1, 1, TypeError),
            ("", 1, ValueError),
            (SITE_A, True, TypeError),
            (SITE_A, 0, ValueError),
        ):
            with self.assertRaises(error):
                sign_final_fork_decision_aggregate_chain_fork_proof(
                    self.fork_items, self.policy, self.auth, self.ssp,
                    self.fsignerp, self.adjp, self.ring, self.vmoment,
                    issuer, version)

    def test_unknown_issuer_is_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.ffproof(self.fork_items, issuer="nobody")

    def test_revoked_key_is_authentication_error(self):
        revoked = copy.deepcopy(self.ring)
        revoked[SITE_A][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.ffproof(self.fork_items, ring=revoked)

    def test_inputs_are_not_modified(self):
        items = copy.deepcopy(self.fork_items)
        snapshot = copy.deepcopy(items)
        self.ffproof(items)
        self.assertEqual(items, snapshot)
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.ffproof(self.fork_items)


class ProofsBatchTest(FinalForkDecisionAggregateChainForkProofsFixtures,
                      unittest.TestCase):
    def test_batch_container_validation(self):
        with self.assertRaises(TypeError):
            self.ffbatch((self.fork_proofs[0],))
        with self.assertRaises(ValueError):
            self.ffbatch([])
        with self.assertRaises(TypeError):
            self.ffbatch(["nope"])
        with self.assertRaises(ValueError):
            self.ffbatch([{"id": "x", "proof": b"{}", "extra": 1}])
        with self.assertRaises(TypeError):
            self.ffbatch([{"id": 1, "proof": b"{}"}])
        with self.assertRaises(ValueError):
            self.ffbatch([{"id": "", "proof": b"{}"}])
        with self.assertRaises(ValueError):
            self.ffbatch([
                proof_item("x", self.fork_proofs[0]["proof"]),
                proof_item("x", self.fork_proofs[1]["proof"]),
            ])
        with self.assertRaises(TypeError):
            self.ffbatch([{"id": "x", "proof": "bytes"}])

    def test_shared_material_validation(self):
        with self.assertRaises(TypeError):
            self.ffbatch(self.fork_proofs, moment=True)
        with self.assertRaises(ValueError):
            self.ffbatch(self.fork_proofs, moment=-1)
        with self.assertRaises(ValueError):
            verify_final_fork_decision_aggregate_chain_fork_proofs(
                self.fork_proofs, self.policy, self.auth, self.ssp,
                self.fsignerp, {"sites": {}, "threshold": 1},
                self.ring, self.vmoment)
        with self.assertRaises(TypeError):
            self.ffbatch(self.fork_proofs, ring={"x": "nope"})

    def test_two_verified_proofs(self):
        report = self.ffbatch(self.fork_proofs)
        self.assertEqual(list(report.keys()), BATCH_REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual(len(report["items"]), 2)
        for item, proof in zip(report["items"], self.fork_proofs):
            self.assertEqual(list(item.keys()), ITEM_REPORT_KEYS)
            self.assertEqual(item["status"], "verified")
            self.assertIsNone(item["error"])
            result = item["result"]
            self.assertEqual(sorted(result), PROOF_RESULT_KEYS)
            self.assertEqual(
                result["proofDigest"],
                hashlib.sha256(proof["proof"]).hexdigest())
            self.assertEqual(result["version"], 1)

    def test_input_order_preserved(self):
        report = self.ffbatch(list(reversed(self.fork_proofs)))
        self.assertEqual([i["id"] for i in report["items"]], ["y", "x"])

    def test_invalid_proof_does_not_block_later(self):
        report = self.ffbatch([
            proof_item("bad", b"not a proof"),
            proof_item("ok", self.fork_proofs[1]["proof"]),
        ])
        bad, ok = report["items"]
        self.assertEqual(bad["status"], "invalid-proof")
        self.assertTrue(bad["error"])
        self.assertIsNone(bad["result"])
        self.assertEqual(ok["status"], "verified")
        self.assertEqual(ok["result"]["issuer"], SITE_B)

    def test_garbage_bytes_and_json_are_invalid(self):
        for raw in (b"", b"\xff", b"{", b"[]", b'{"payload":{}}'):
            report = self.ffbatch([proof_item("bad", raw)])
            self.assertEqual(
                report["items"][0]["status"], "invalid-proof", raw)

    def test_foreign_policy_digest_is_invalid_proof(self):
        foreign = {"sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 1}
        report = verify_final_fork_decision_aggregate_chain_fork_proofs(
            self.fork_proofs, self.policy, self.auth, self.ssp,
            self.fsignerp, foreign, self.ring, self.vmoment)
        for item in report["items"]:
            self.assertEqual(item["status"], "invalid-proof")

    def test_wrong_keyring_is_unauthenticated(self):
        wrong_ring = copy.deepcopy(self.ring)
        wrong_ring[SITE_A] = [
            dict(wrong_ring[SITE_A][0], secret="00" * 32)]
        item = self.ffbatch(
            [proof_item("x", self.fork_proofs[0]["proof"])],
            ring=wrong_ring)["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertIsNone(item["result"])
        self.assertIn("signature", item["error"])
        # The unauthenticated identity never enters the report.
        self.assertNotIn(SITE_A, str(item["result"]))

    def test_revoked_key_is_unauthenticated(self):
        revoked = copy.deepcopy(self.ring)
        revoked[SITE_B][0]["revoked"] = True
        item = self.ffbatch(
            [proof_item("y", self.fork_proofs[1]["proof"])],
            ring=revoked)["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertIn("revoked", item["error"])

    def test_equal_but_independent_results(self):
        first = self.ffbatch(self.fork_proofs)
        second = self.ffbatch(self.fork_proofs)
        self.assertEqual(first, second)
        first["items"][0]["result"]["issuer"] = "tampered"
        self.assertEqual(
            self.ffbatch(self.fork_proofs)["items"][0]["result"]["issuer"],
            SITE_A)

    def test_inputs_are_not_modified(self):
        items = copy.deepcopy(self.fork_proofs)
        snapshot = copy.deepcopy(items)
        self.ffbatch(items)
        self.assertEqual(items, snapshot)
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.ffbatch(self.fork_proofs)


class AdjudicationTest(FinalForkDecisionAggregateChainForkProofsFixtures,
                       unittest.TestCase):
    def test_two_agreeing_sites_are_accepted(self):
        payload = parse(self.decision)["payload"]
        self.assertEqual(payload["status"], "accepted")
        edge, = payload["common"]
        self.assertEqual(sorted(edge), sorted(EDGE_KEYS))
        self.assertEqual(
            edge["rootDigest"], hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(
            edge["predecessorDigest"],
            hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(
            edge["successors"],
            sorted([hashlib.sha256(self.s_grow).hexdigest(),
                    hashlib.sha256(self.s_t1).hexdigest()]))

    def test_envelope_payload_and_row_shapes(self):
        packet = parse(self.decision)
        self.assertEqual(list(packet.keys()), PACKET_KEYS)
        payload = packet["payload"]
        self.assertEqual(sorted(payload), DECISION_PAYLOAD_KEYS)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        rows = payload["items"]
        self.assertEqual([r["issuer"] for r in rows], [SITE_A, SITE_B])
        for row, proof in zip(rows, self.fork_proofs):
            self.assertEqual(sorted(row), sorted(DECISION_ROW_KEYS))
            self.assertEqual(row["conclusion"], "valid")
            self.assertIsNone(row["reason"])
            self.assertEqual(row["keyVersion"], 1)
            self.assertEqual(
                row["digest"],
                hashlib.sha256(proof["proof"]).hexdigest())
            self.assertEqual(len(row["edges"]), 1)
        # The proof vector is bound term by term to the sorted rows.
        self.assertEqual(
            payload["proofs"], [row["digest"] for row in rows])

    def test_six_policy_digest_bindings(self):
        payload = parse(self.decision)["payload"]
        self.assertEqual(
            payload["prunePolicyDigest"],
            hashlib.sha256(_verdict_policy_bytes(self.policy)).hexdigest())
        for name, policy in (
            ("authorizationPolicyDigest", self.auth),
            ("sitePolicyDigest", self.ssp),
            ("signerSitePolicyDigest", self.fsignerp),
            ("adjudicationSitePolicyDigest", self.adjp),
            ("proofSitePolicyDigest", self.psp),
        ):
            self.assertEqual(
                payload[name],
                hashlib.sha256(
                    _prune_batch_site_policy_bytes(policy)).hexdigest(),
                name)

    def test_fork_free_consensus_accepted_with_empty_common(self):
        payload = parse(self.ffdecision(self.free_proofs))["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["common"], [])

    def test_one_site_is_insufficient_but_keeps_common(self):
        payload = parse(self.ffdecision(self.fork_proofs[:1]))["payload"]
        self.assertEqual(payload["status"], "insufficient")
        self.assertEqual(len(payload["common"]), 1)

    def test_no_valid_vote_is_insufficient_with_null_common(self):
        payload = parse(self.ffdecision(
            [proof_item("bad", b"{}")]))["payload"]
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNone(payload["common"])
        row = payload["items"][0]
        self.assertEqual(row["conclusion"], "invalid")
        self.assertEqual(row["reason"], "invalid-proof")
        self.assertIsNone(row["issuer"])
        self.assertIsNone(row["keyVersion"])
        self.assertIsNone(row["edges"])

    def test_identical_same_site_proofs_are_duplicate(self):
        proof = self.ffproof(self.fork_items, SITE_A)
        payload = parse(self.ffdecision(
            [proof_item("a", proof), proof_item("b", proof)]))["payload"]
        by_id = {r["id"]: r for r in payload["items"]}
        self.assertEqual(by_id["a"]["conclusion"], "valid")
        self.assertEqual(by_id["b"]["conclusion"], "duplicate")
        self.assertEqual(by_id["b"]["reason"], "duplicate")
        self.assertEqual(payload["status"], "insufficient")

    def test_different_same_site_declarations_contradict(self):
        payload = parse(self.ffdecision([
            proof_item("a", self.ffproof(self.fork_items, SITE_A)),
            proof_item("b", self.ffproof(self.clean_items, SITE_A)),
        ]))["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["common"])
        for row in payload["items"]:
            self.assertEqual(row["conclusion"], "contradiction")
            self.assertEqual(row["reason"], "contradiction")

    def test_cross_site_disagreement_is_conflicted(self):
        payload = parse(self.ffdecision([
            proof_item("a", self.ffproof(self.fork_items, SITE_A)),
            proof_item("b", self.ffproof(self.clean_items, SITE_B)),
        ]))["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["common"])

    def test_unauthorized_site_does_not_count(self):
        psp = {"sites": {SITE_B: {1}}, "threshold": 1}
        payload = parse(self.ffdecision(
            [proof_item("x", self.fork_proofs[0]["proof"])],
            psp=psp))["payload"]
        row = payload["items"][0]
        self.assertEqual(row["conclusion"], "invalid")
        self.assertEqual(row["reason"], "unauthorized-site")
        self.assertEqual(row["issuer"], SITE_A)
        self.assertIsNotNone(row["edges"])
        self.assertEqual(payload["status"], "insufficient")

    def test_unauthorized_version_does_not_count(self):
        psp = {"sites": {SITE_A: {2}}, "threshold": 1}
        payload = parse(self.ffdecision(
            [proof_item("x", self.fork_proofs[0]["proof"])],
            psp=psp))["payload"]
        self.assertEqual(
            payload["items"][0]["reason"], "unauthorized-version")

    def test_credential_unavailable_row(self):
        ring = copy.deepcopy(self.ring)
        del ring[SITE_A]
        payload = parse(self.ffdecision(
            [proof_item("x", self.fork_proofs[0]["proof"])],
            ring=ring))["payload"]
        self.assertEqual(
            payload["items"][0]["reason"], "credential-unavailable")

    def test_revoked_and_bad_signature_rows(self):
        revoked = copy.deepcopy(self.ring)
        revoked[SITE_A][0]["revoked"] = True
        payload = parse(self.ffdecision(
            [proof_item("x", self.fork_proofs[0]["proof"])],
            ring=revoked))["payload"]
        self.assertEqual(payload["items"][0]["reason"], "revoked")
        wrong = copy.deepcopy(self.ring)
        wrong[SITE_A] = [dict(wrong[SITE_A][0], secret="00" * 32)]
        payload = parse(self.ffdecision(
            [proof_item("x", self.fork_proofs[0]["proof"])],
            ring=wrong))["payload"]
        self.assertEqual(payload["items"][0]["reason"], "bad-signature")

    def test_input_order_does_not_change_the_bytes(self):
        first = self.ffdecision(self.fork_proofs)
        second = self.ffdecision(list(reversed(self.fork_proofs)))
        self.assertEqual(first, second)

    def test_adjudicator_credential_rules(self):
        with self.assertRaises(AuthenticationError):
            self.ffdecision(self.fork_proofs, issuer="nobody")
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.ffdecision(self.fork_proofs, ring=revoked)

    def test_batch_and_identity_validation(self):
        with self.assertRaises(TypeError):
            self.ffdecision((self.fork_proofs[0],))
        with self.assertRaises(ValueError):
            self.ffdecision([])
        with self.assertRaises(ValueError):
            self.ffdecision([
                proof_item("x", self.fork_proofs[0]["proof"]),
                proof_item("x", self.fork_proofs[1]["proof"]),
            ])
        with self.assertRaises(ValueError):
            self.ffdecision(self.fork_proofs,
                            psp={"sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.ffdecision(self.fork_proofs, moment=True)
        with self.assertRaises(ValueError):
            self.ffdecision(self.fork_proofs, moment=-1)
        with self.assertRaises(TypeError):
            self.ffdecision(self.fork_proofs, issuer=1)
        with self.assertRaises(ValueError):
            self.ffdecision(self.fork_proofs, issuer="")
        with self.assertRaises(TypeError):
            adjudicate_final_fork_decision_aggregate_chain_forks(
                self.fork_proofs, self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.psp, self.ring,
                self.vmoment, JUDGE, True)
        with self.assertRaises(ValueError):
            adjudicate_final_fork_decision_aggregate_chain_forks(
                self.fork_proofs, self.policy, self.auth, self.ssp,
                self.fsignerp, self.adjp, self.psp, self.ring,
                self.vmoment, JUDGE, 0)

    def test_inputs_are_not_modified(self):
        items = copy.deepcopy(self.fork_proofs)
        snapshot = copy.deepcopy(items)
        self.ffdecision(items)
        self.assertEqual(items, snapshot)
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.ffdecision(self.fork_proofs)


class DecisionVerifyTest(FinalForkDecisionAggregateChainForkProofsFixtures,
                         unittest.TestCase):
    def test_result_keys_status_and_digest(self):
        result = self.ffverify_decision(self.decision)
        self.assertEqual(sorted(result), DECISION_RESULT_KEYS)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(
            result["proofDigest"],
            hashlib.sha256(self.decision).hexdigest())
        self.assertEqual(result["issuer"], JUDGE)
        self.assertEqual(result["version"], 1)
        self.assertEqual(len(result["common"]), 1)
        self.assertEqual(len(result["proofs"]), 2)

    def test_non_bytes_is_type_error(self):
        with self.assertRaises(TypeError):
            self.ffverify_decision("bytes")

    def test_equal_but_independent_results(self):
        first = self.ffverify_decision(self.decision)
        second = self.ffverify_decision(self.decision)
        self.assertEqual(first, second)
        first["items"][0]["conclusion"] = "tampered"
        self.assertEqual(
            self.ffverify_decision(self.decision)["items"][0]["conclusion"],
            "valid")

    def test_bad_signature_is_authentication_error(self):
        tampered = parse(self.decision)
        tampered["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.ffverify_decision(compact(tampered))

    def test_later_revocation_rejects(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.ffverify_decision(self.decision, ring=revoked)

    def test_expired_at_verify_moment_rejects(self):
        expired = copy.deepcopy(self.ring)
        expired[JUDGE][0]["notAfter"] = self.vmoment - 1
        with self.assertRaises(AuthenticationError):
            self.ffverify_decision(self.decision, ring=expired)

    def test_foreign_policies_are_invalid(self):
        foreign = {"sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 1}
        self.assert_invalid_decision(self.decision, psp=foreign)
        with self.assertRaises(
            InvalidFinalForkDecisionAggregateChainForkDecisionError
        ):
            verify_final_fork_decision_aggregate_chain_fork_decision(
                self.decision, self.policy, self.auth, self.ssp,
                self.fsignerp, foreign, self.psp, self.ring, self.vmoment)

    def test_status_tamper_is_invalid(self):
        payload = parse(self.decision)["payload"]
        payload["status"] = "insufficient"
        self.assert_invalid_decision(self.ffrewrap(payload))

    def test_common_tamper_is_invalid(self):
        payload = parse(self.decision)["payload"]
        payload["common"] = []
        self.assert_invalid_decision(self.ffrewrap(payload))

    def test_row_conclusion_tamper_is_invalid(self):
        payload = parse(self.decision)["payload"]
        payload["items"][0]["conclusion"] = "duplicate"
        payload["items"][0]["reason"] = "duplicate"
        self.assert_invalid_decision(self.ffrewrap(payload))

    def test_proof_vector_reorder_is_invalid(self):
        payload = parse(self.decision)["payload"]
        payload["proofs"] = list(reversed(payload["proofs"]))
        self.assert_invalid_decision(self.ffrewrap(payload))

    def test_rows_must_stay_sorted(self):
        payload = parse(self.decision)["payload"]
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid_decision(self.ffrewrap(payload))

    def test_policy_digest_tamper_is_invalid(self):
        payload = parse(self.decision)["payload"]
        payload["proofSitePolicyDigest"] = "ab" * 32
        self.assert_invalid_decision(self.ffrewrap(payload))

    def test_wrong_version_is_invalid(self):
        payload = parse(self.decision)["payload"]
        payload["version"] = 2
        self.assert_invalid_decision(self.ffrewrap(payload))

    def test_extra_row_key_is_invalid(self):
        payload = parse(self.decision)["payload"]
        payload["items"][0]["extra"] = 1
        self.assert_invalid_decision(self.ffrewrap(payload))

    def test_non_canonical_encoding_is_invalid(self):
        raw = self.decision.replace(b":", b": ", 1)
        self.assert_invalid_decision(raw)

    def test_trailing_byte_is_invalid(self):
        self.assert_invalid_decision(self.decision + b"\n")

    def test_garbage_bytes_are_invalid(self):
        for raw in (b"", b"\xff", b"{", b'{"payload":{}}'):
            self.assert_invalid_decision(raw)

    def test_non_object_json_is_type_error(self):
        with self.assertRaises(TypeError):
            self.ffverify_decision(b"[]")

    def test_error_classes_are_distinct(self):
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateChainForkProofError,
            ValueError))
        self.assertTrue(issubclass(
            InvalidFinalForkDecisionAggregateChainForkDecisionError,
            ValueError))
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateChainForkProofError,
            InvalidFinalForkDecisionAggregateChainForkDecisionError)

    def test_inputs_are_not_modified(self):
        snapshot = copy.deepcopy(self.decision)
        self.ffverify_decision(self.decision)
        self.assertEqual(self.decision, snapshot)
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.ffverify_decision(self.decision)


if __name__ == "__main__":
    unittest.main()
