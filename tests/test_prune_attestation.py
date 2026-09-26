"""Tests for the signed prune attestation handover and adjudication.

Covers :func:`sign_prune_attestation`,
:func:`adjudicate_prune_attestations` and
:func:`verify_prune_adjudication`: the canonical attestation envelope
and its batch/site/keyVersion/moment/version-1 bindings, the
original-order receipt/checkpoint digests and the complete embedded
batch report with failed items preserved as they are, the exact
site/version HMAC-SHA256 signing with no fallback, the policy-driven
multi-site adjudication with its
invalid-proof/unauthorized/unauthenticated/valid/duplicate/
contradiction conclusions, the duplicate/contradiction same-site
accounting, the cross-site conflict that no majority outvotes, the
accepted/insufficient/conflicted statuses and the common report, the
original-order attestation digests, the offline adjudication
re-verification (structure, policy digest, vote count and signature)
and the type/value error taxonomy with input immutability.
"""

import copy
import hashlib
import hmac
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidPruneAdjudicationError,
    adjudicate_prune_attestations,
    prune_chain_archives,
    sign_prune_attestation,
    verify_prune_adjudication,
)

from test_chain_prune import PruneFixtures
from test_fork_convergence import (
    ALPHA,
    BETA,
    COORD,
    RING,
    SECRET_COORD,
    compact,
    parse,
)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


class PruneAttestationTest(PruneFixtures, unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        plan = self.make_plan()
        report = prune_chain_archives(
            [self.batch_item("i", "c", plan)], RING
        )[0]
        self.assertIsNone(report["error"], report["error"])
        self.receipt = report["receipt"]
        self.items = [
            {
                "id": "i",
                "receipt": self.receipt,
                "checkpoint": self.checkpoint,
            }
        ]
        self.batch = "batch-1"
        self.policy = {
            "batch": self.batch,
            "sites": {COORD: {1}, ALPHA: {1}, BETA: {1}},
            "threshold": 2,
        }

    def sign_att(self, site=COORD, items=None, batch=None):
        return sign_prune_attestation(
            self.items if items is None else items,
            self.batch if batch is None else batch,
            RING,
            self.moment,
            site,
            1,
        )

    def adjudicate_packets(self, packets, policy=None):
        return adjudicate_prune_attestations(
            packets,
            self.policy if policy is None else policy,
            RING,
            self.moment,
            COORD,
            1,
        )

    def test_sign_shape_and_signature(self):
        raw = self.sign_att()
        data = parse(raw)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        payload = data["payload"]
        self.assertEqual(
            set(payload.keys()),
            {"batch", "items", "keyVersion", "moment", "report", "site",
             "version"},
        )
        self.assertEqual(payload["batch"], self.batch)
        self.assertEqual(payload["site"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.moment)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(
            payload["items"],
            [{
                "checkpoint": sha256(self.checkpoint),
                "id": "i",
                "receipt": sha256(self.receipt),
            }],
        )
        report = payload["report"]
        self.assertEqual(report["version"], 1)
        self.assertEqual(len(report["items"]), 1)
        self.assertEqual(report["items"][0]["status"], "verified")
        self.assertEqual(report["items"][0]["result"]["project"], "c")
        expected = hmac.new(
            bytes.fromhex(SECRET_COORD), compact(payload), hashlib.sha256
        ).hexdigest()
        self.assertEqual(data["signature"], expected)
        self.assertEqual(compact(data), raw)

    def test_sign_preserves_failed_items(self):
        bad = [
            {"id": "bad", "receipt": b"garbage",
             "checkpoint": self.checkpoint}
        ]
        raw = self.sign_att(items=self.items + bad)
        report = parse(raw)["payload"]["report"]
        self.assertEqual(report["items"][1]["status"], "invalid")
        self.assertIsNone(report["items"][1]["result"])
        self.assertIsNotNone(report["items"][1]["error"])

    def test_sign_auth_and_argument_errors(self):
        with self.assertRaises(AuthenticationError):
            sign_prune_attestation(
                self.items, self.batch, RING, self.moment, "nobody", 1
            )
        with self.assertRaises(AuthenticationError):
            sign_prune_attestation(
                self.items, self.batch, RING, self.moment, COORD, 9
            )
        with self.assertRaises(TypeError):
            sign_prune_attestation(
                self.items, self.batch, RING, True, COORD, 1
            )
        with self.assertRaises(TypeError):
            sign_prune_attestation(
                self.items, self.batch, RING, self.moment, COORD, True
            )
        with self.assertRaises(ValueError):
            sign_prune_attestation(
                [], self.batch, RING, self.moment, COORD, 1
            )
        with self.assertRaises(ValueError):
            sign_prune_attestation(
                self.items, "", RING, self.moment, COORD, 1
            )
        with self.assertRaises(ValueError):
            sign_prune_attestation(
                self.items, self.batch, RING, -1, COORD, 1
            )
        with self.assertRaises(ValueError):
            sign_prune_attestation(
                self.items, self.batch, RING, self.moment, "", 1
            )
        with self.assertRaises(ValueError):
            sign_prune_attestation(
                self.items, self.batch, RING, self.moment, COORD, 0
            )

    def test_accepted_adjudication_verifies(self):
        packets = [
            {"id": "p1", "attestation": self.sign_att(COORD)},
            {"id": "p2", "attestation": self.sign_att(ALPHA)},
        ]
        raw = self.adjudicate_packets(packets)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertIsNotNone(payload["report"])
        self.assertEqual(payload["threshold"], 2)
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(
            payload["attestations"],
            [sha256(p["attestation"]) for p in packets],
        )
        self.assertEqual(
            [c["conclusion"] for c in payload["conclusions"]],
            ["valid", "valid"],
        )
        # Conclusions are stably sorted by site then id.
        self.assertEqual(
            [c["site"] for c in payload["conclusions"]], [ALPHA, COORD]
        )
        result = verify_prune_adjudication(raw, self.policy, RING,
                                           self.moment)
        self.assertEqual(result, payload)
        self.assertIsNot(result, payload)
        again = verify_prune_adjudication(raw, self.policy, RING,
                                          self.moment)
        self.assertEqual(result, again)
        self.assertIsNot(result, again)

    def test_insufficient_keeps_common_report(self):
        packets = [{"id": "p1", "attestation": self.sign_att(COORD)}]
        raw = self.adjudicate_packets(packets)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNotNone(payload["report"])
        verify_prune_adjudication(raw, self.policy, RING, self.moment)

    def test_duplicate_and_contradiction(self):
        first = self.sign_att(COORD)
        second = self.sign_att(COORD)  # identical content
        packets = [
            {"id": "p1", "attestation": first},
            {"id": "p2", "attestation": second},
            {"id": "p3", "attestation": self.sign_att(ALPHA)},
        ]
        payload = parse(self.adjudicate_packets(packets))["payload"]
        self.assertEqual(payload["status"], "accepted")
        by_id = {c["id"]: c["conclusion"] for c in payload["conclusions"]}
        self.assertEqual(
            by_id, {"p1": "valid", "p2": "duplicate", "p3": "valid"}
        )

        other_items = [
            {"id": "j", "receipt": self.receipt,
             "checkpoint": self.checkpoint}
        ]
        different = self.sign_att(COORD, items=other_items)
        packets = [
            {"id": "p1", "attestation": first},
            {"id": "p2", "attestation": different},
        ]
        raw = self.adjudicate_packets(packets)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["report"])
        by_id = {c["id"]: c["conclusion"] for c in payload["conclusions"]}
        self.assertEqual(
            by_id, {"p1": "contradiction", "p2": "contradiction"}
        )
        verify_prune_adjudication(raw, self.policy, RING, self.moment)

    def test_cross_site_conflict_is_not_outvoted(self):
        other_items = [
            {"id": "j", "receipt": self.receipt,
             "checkpoint": self.checkpoint}
        ]
        packets = [
            {"id": "p1", "attestation": self.sign_att(COORD)},
            {"id": "p2", "attestation": self.sign_att(ALPHA)},
            {"id": "p3", "attestation": self.sign_att(BETA,
                                                      items=other_items)},
        ]
        raw = self.adjudicate_packets(packets)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["report"])
        self.assertEqual(
            [c["conclusion"] for c in payload["conclusions"]],
            ["valid", "valid", "valid"],
        )
        verify_prune_adjudication(raw, self.policy, RING, self.moment)

    def test_rejection_conclusions(self):
        bad_proof = b'{"payload": {}, "signature": "0"}'
        wrong_batch = self.sign_att(ALPHA, batch="batch-2")
        unknown_site = sign_prune_attestation(
            self.items, self.batch, RING, self.moment, "gamma", 1
        )
        tampered = bytearray(self.sign_att(BETA))
        tampered[-20] = ord("x") if tampered[-20] != ord("x") else ord("y")
        packets = [
            {"id": "p1", "attestation": bad_proof},
            {"id": "p2", "attestation": wrong_batch},
            {"id": "p3", "attestation": unknown_site},
            {"id": "p4", "attestation": bytes(tampered)},
            {"id": "p5", "attestation": self.sign_att(COORD)},
            {"id": "p6", "attestation": self.sign_att(ALPHA)},
        ]
        raw = self.adjudicate_packets(packets)
        payload = parse(raw)["payload"]
        by_id = {c["id"]: c["conclusion"] for c in payload["conclusions"]}
        self.assertEqual(by_id["p1"], "invalid-proof")
        self.assertEqual(by_id["p2"], "unauthorized")
        self.assertEqual(by_id["p3"], "unauthorized")
        self.assertIn(by_id["p4"], ("invalid-proof", "unauthenticated"))
        self.assertEqual(by_id["p5"], "valid")
        self.assertEqual(by_id["p6"], "valid")
        self.assertEqual(payload["status"], "accepted")
        invalid = [c for c in payload["conclusions"] if c["id"] == "p1"][0]
        self.assertIsNone(invalid["site"])
        self.assertIsNone(invalid["keyVersion"])
        verify_prune_adjudication(raw, self.policy, RING, self.moment)

    def test_verify_rejects_tampering(self):
        packets = [
            {"id": "p1", "attestation": self.sign_att(COORD)},
            {"id": "p2", "attestation": self.sign_att(ALPHA)},
        ]
        raw = self.adjudicate_packets(packets)
        data = parse(raw)

        # A policy with a different digest.
        other_policy = {
            "batch": self.batch,
            "sites": {COORD: {1}, ALPHA: {1}},
            "threshold": 2,
        }
        with self.assertRaises(InvalidPruneAdjudicationError):
            verify_prune_adjudication(raw, other_policy, RING, self.moment)

        # A tampered status breaks the vote-count binding.
        forged = copy.deepcopy(data)
        forged["payload"]["status"] = "insufficient"
        with self.assertRaises(InvalidPruneAdjudicationError):
            verify_prune_adjudication(
                compact(forged), self.policy, RING, self.moment
            )

        # A forged signature over the untampered payload.
        forged = copy.deepcopy(data)
        forged["signature"] = hmac.new(
            bytes.fromhex("99" * 32), compact(forged["payload"]),
            hashlib.sha256,
        ).hexdigest()
        with self.assertRaises(AuthenticationError):
            verify_prune_adjudication(
                compact(forged), self.policy, RING, self.moment
            )

        # A tampered status re-signed with the right key still fails the
        # recount.
        forged = copy.deepcopy(data)
        forged["payload"]["status"] = "insufficient"
        forged["signature"] = hmac.new(
            bytes.fromhex(SECRET_COORD), compact(forged["payload"]),
            hashlib.sha256,
        ).hexdigest()
        with self.assertRaises(InvalidPruneAdjudicationError):
            verify_prune_adjudication(
                compact(forged), self.policy, RING, self.moment
            )

        # Encoding and argument faults.
        with self.assertRaises(InvalidPruneAdjudicationError):
            verify_prune_adjudication(raw + b"\n", self.policy, RING,
                                      self.moment)
        with self.assertRaises(InvalidPruneAdjudicationError):
            verify_prune_adjudication(b"{}", self.policy, RING, self.moment)
        with self.assertRaises(TypeError):
            verify_prune_adjudication("nope", self.policy, RING, self.moment)
        with self.assertRaises(TypeError):
            verify_prune_adjudication(raw, self.policy, RING, True)
        self.assertTrue(
            issubclass(InvalidPruneAdjudicationError, ValueError)
        )

    def test_no_input_mutation(self):
        items = copy.deepcopy(self.items)
        snapshot = copy.deepcopy(items)
        raw = self.sign_att(items=items)
        self.assertEqual(items, snapshot)
        packets = [{"id": "p1", "attestation": raw}]
        policy = {
            "batch": self.batch, "sites": {COORD: {1}}, "threshold": 1,
        }
        snapshot_policy = copy.deepcopy(policy)
        adjudicate_prune_attestations(
            packets, policy, RING, self.moment, COORD, 1
        )
        self.assertEqual(policy, snapshot_policy)


if __name__ == "__main__":
    unittest.main()
