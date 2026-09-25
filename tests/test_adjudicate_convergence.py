"""Tests for multi-site offline convergence adjudication.

Covers :func:`adjudicate_convergence`,
:func:`verify_convergence_decision` and
:func:`verify_convergence_decisions`: the whole-batch upfront
precheck (including every nested round chain), the verify-then-
authorize-then-authenticate per-certificate pipeline with its fixed
reasons, same-site duplicate/contradiction handling, cross-site
agreement on the plan summary, overall status and every operation
result, settled round and post digest, threshold acceptance and the
null common result/plan digest rules, the canonical signed packet and
every bound field, offline re-tally verification and credential rules,
and the batch wrapper's upfront validation, per-item isolation,
input-order reports and fresh results.
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
    InvalidConvergenceDecisionError,
    InvalidForkConvergenceError,
    adjudicate_convergence,
    certify_fork_convergence,
    verify_convergence_decision,
    verify_convergence_decisions,
)

from test_fork_convergence import (
    ALPHA,
    BETA,
    CERTIFIED_AT,
    COORD,
    ConvergenceFixtures,
    DELTA,
    GAMMA,
    RING,
    SECRET_ALPHA,
    SECRET_COORD,
    SECRET_OTHER,
    VERIFY_MOMENT,
    compact,
    decide,
    entry,
    parse,
    policy as fork_policy,
)

ADJUDICATE_MOMENT = 280
VERIFY_DECISION_MOMENT = 285


def site_policy(sites=None, threshold=2):
    if sites is None:
        sites = (COORD, ALPHA, GAMMA)
    return {"sites": {site: {1} for site in sites}, "threshold": threshold}


class AdjudicationFixtures(ConvergenceFixtures):
    """Shared accepted decision, plan, rounds and certificate builders."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.site_policy = site_policy()
        self.confirmation = self.confirm([
            self.execution_receipt(BETA, moment=220, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=225, post_digest="e2" * 32),
        ])
        self.rounds = self.chain(self.confirmation)
        self.cert_coord = self.certify(self.rounds)
        self.cert_alpha = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, CERTIFIED_AT,
            ALPHA, 1,
        )

    def adjudicate(self, items, sp=None, ring=RING, moment=ADJUDICATE_MOMENT,
                   issuer=COORD, version=1):
        return adjudicate_convergence(
            items, self.decision, self.pol, sp or self.site_policy, ring,
            moment, issuer, version,
        )

    def adjudicate_payload(self, items, **kwargs):
        return parse(self.adjudicate(items, **kwargs))["payload"]

    def verify(self, packet, sp=None, ring=RING, moment=VERIFY_DECISION_MOMENT,
               decision=None):
        return verify_convergence_decision(
            packet, decision or self.decision, sp or self.site_policy, ring,
            moment,
        )

    def verify_batch(self, items, sp=None, ring=RING,
                     moment=VERIFY_DECISION_MOMENT, decision=None):
        return verify_convergence_decisions(
            items, decision or self.decision, sp or self.site_policy, ring,
            moment,
        )

    def item(self, certificate=None, item_id="x", rounds=None):
        return {
            "id": item_id,
            "certificate": self.cert_coord if certificate is None
            else certificate,
            "rounds": self.rounds if rounds is None else rounds,
        }

    def reshape(self, post_beta="e1" * 32):
        """A second distinct confirmed convergence over the same plan."""
        confirmation = self.confirm([
            self.execution_receipt(BETA, moment=220, post_digest=post_beta),
            self.execution_receipt(GAMMA, moment=225, post_digest="e2" * 32),
        ])
        return self.chain(confirmation)

    def reshape_cert(self, issuer, post_beta="e9" * 32):
        rounds = self.reshape(post_beta)
        cert = certify_fork_convergence(
            rounds, self.decision, self.pol, RING, CERTIFIED_AT, issuer, 1
        )
        return cert, rounds


class PacketShapeTest(AdjudicationFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.items = [
            self.item(self.cert_coord, "c"),
            self.item(self.cert_alpha, "a"),
        ]
        self.raw = self.adjudicate(self.items)
        self.data = parse(self.raw)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(self.data), self.raw)

    def test_top_and_payload_key_sets(self):
        self.assertEqual(set(self.data.keys()), {"payload", "signature"})
        self.assertEqual(
            set(self.data["payload"].keys()),
            {"certificates", "common", "commonDigest", "decisionDigest",
             "issuer", "items", "keyVersion", "planDigest", "policyDigest",
             "status", "version"},
        )

    def test_signing_bindings(self):
        payload = self.data["payload"]
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertIsInstance(payload["version"], int)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(
            payload["decisionDigest"],
            hashlib.sha256(self.decision).hexdigest(),
        )
        self.assertEqual(payload["status"], "accepted")
        canonical_policy = {
            "sites": {site: [1] for site in (ALPHA, COORD, GAMMA)},
            "threshold": 2,
        }
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(compact(canonical_policy)).hexdigest(),
        )
        # Certificate digests stay in the original input order.
        self.assertEqual(
            payload["certificates"],
            [hashlib.sha256(self.cert_coord).hexdigest(),
             hashlib.sha256(self.cert_alpha).hexdigest()],
        )
        # Items are sorted by site then id regardless of input order.
        self.assertEqual(
            [(row["site"], row["id"]) for row in payload["items"]],
            [(ALPHA, "a"), (COORD, "c")],
        )

    def test_signature_is_the_payload_hmac(self):
        payload = self.data["payload"]
        self.assertEqual(
            self.data["signature"],
            __import__("hmac").new(
                bytes.fromhex(SECRET_COORD), compact(payload),
                hashlib.sha256,
            ).hexdigest(),
        )

    def test_row_key_set_and_common_result(self):
        payload = self.data["payload"]
        for row in payload["items"]:
            self.assertEqual(
                set(row.keys()),
                {"certificateDigest", "conclusion", "convergence", "id",
                 "keyVersion", "reason", "site"},
            )
            self.assertEqual(row["conclusion"], "valid")
            self.assertIsNone(row["reason"])
            self.assertEqual(
                set(row["convergence"].keys()),
                {"planDigest", "results", "status"},
            )
        common = payload["common"]
        self.assertEqual(common["status"], "confirmed")
        self.assertEqual(
            [r["target"] for r in common["results"]], [BETA, GAMMA]
        )
        self.assertEqual(
            payload["commonDigest"],
            hashlib.sha256(compact(common)).hexdigest(),
        )
        self.assertEqual(payload["planDigest"], common["planDigest"])

    def test_inputs_are_not_modified(self):
        items = copy.deepcopy(self.items)
        snapshot = copy.deepcopy(
            (items, self.decision, self.pol, self.site_policy, RING)
        )
        self.adjudicate(items)
        self.assertEqual(
            (items, self.decision, self.pol, self.site_policy, RING),
            snapshot,
        )


class AdjudicationSemanticsTest(AdjudicationFixtures, unittest.TestCase):
    def test_threshold_met_is_accepted_and_below_is_insufficient(self):
        sp = site_policy((COORD, ALPHA), threshold=2)
        payload = self.adjudicate_payload(
            [self.item(self.cert_coord, "c")], sp=sp
        )
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNone(payload["common"])
        self.assertIsNone(payload["commonDigest"])
        self.assertIsNone(payload["planDigest"])

        payload = self.adjudicate_payload([
            self.item(self.cert_coord, "c"),
            self.item(self.cert_alpha, "a"),
        ], sp=sp)
        self.assertEqual(payload["status"], "accepted")
        self.assertIsNotNone(payload["common"])
        self.assertEqual(payload["planDigest"], payload["common"]["planDigest"])

    def test_extra_same_site_certificate_is_a_duplicate(self):
        payload = self.adjudicate_payload([
            self.item(self.cert_coord, "c1"),
            self.item(self.cert_coord, "c2"),
            self.item(self.cert_alpha, "a"),
        ])
        rows = {(row["id"], row["site"]): (row["conclusion"], row["reason"])
                for row in payload["items"]}
        self.assertEqual(rows[("c1", COORD)], ("valid", None))
        self.assertEqual(rows[("c2", COORD)], ("duplicate", "duplicate"))
        self.assertEqual(rows[("a", ALPHA)], ("valid", None))
        self.assertEqual(payload["status"], "accepted")

    def test_duplicate_matches_the_full_result_not_the_bytes(self):
        # A second certificate signed at a different certifiedAt still
        # converges to the identical complete result, so it duplicates.
        later = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, 271, COORD, 1
        )
        payload = self.adjudicate_payload([
            self.item(self.cert_coord, "c1"),
            self.item(later, "c2"),
            self.item(self.cert_alpha, "a"),
        ])
        rows = {row["id"]: row for row in payload["items"]}
        self.assertEqual(rows["c2"]["conclusion"], "duplicate")

    def test_distinct_results_from_one_site_contradict(self):
        other_cert, other_rounds = self.reshape_cert(COORD)
        payload = self.adjudicate_payload([
            self.item(self.cert_coord, "c1"),
            self.item(other_cert, "c2", rounds=other_rounds),
            self.item(self.cert_alpha, "a"),
        ])
        rows = {row["id"]: row for row in payload["items"]}
        self.assertEqual(rows["c1"]["conclusion"], "contradiction")
        self.assertEqual(rows["c1"]["reason"], "contradiction")
        self.assertEqual(rows["c2"]["conclusion"], "contradiction")
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["common"])
        self.assertIsNone(payload["commonDigest"])
        self.assertIsNone(payload["planDigest"])

    def test_cross_site_difference_is_conflicted_without_majority_override(self):
        other_cert, other_rounds = self.reshape_cert(ALPHA)
        sp = site_policy((COORD, ALPHA, GAMMA), threshold=2)
        # Two coord votes cannot outvote the one alpha disagreement:
        # distinct sites are counted, so one vs one is a conflict.
        payload = self.adjudicate_payload([
            self.item(self.cert_coord, "c1"),
            self.item(self.cert_coord, "c2"),
            self.item(other_cert, "a", rounds=other_rounds),
        ], sp=sp)
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["common"])

    def test_rows_sort_stably_with_invalid_items_first(self):
        payload = self.adjudicate_payload([
            self.item(self.cert_alpha, "a"),
            self.item(b"{}", "bad"),
            self.item(self.cert_coord, "c"),
        ])
        self.assertEqual(
            [(row["site"], row["id"]) for row in payload["items"]],
            [(None, "bad"), (ALPHA, "a"), (COORD, "c")],
        )


class PerItemRejectionTest(AdjudicationFixtures, unittest.TestCase):
    def reason_for(self, item, **kwargs):
        payload = self.adjudicate_payload([item], **kwargs)
        row = payload["items"][0]
        return row["conclusion"], row["reason"], row["site"], row[
            "keyVersion"
        ], row["convergence"]

    def test_structurally_bad_certificate_is_invalid_proof(self):
        conclusion, reason, site, key_version, convergence = self.reason_for(
            self.item(b"{}", "z")
        )
        self.assertEqual((conclusion, reason), ("invalid", "invalid-proof"))
        self.assertIsNone(site)
        self.assertIsNone(key_version)
        self.assertIsNone(convergence)

    def test_broken_round_chain_is_invalid_proof_alone(self):
        broken = self.chain(self.confirmation)
        broken[0]["previous"] = "ab" * 32
        conclusion, reason, *_ = self.reason_for(
            self.item(self.cert_coord, "z", rounds=broken)
        )
        self.assertEqual((conclusion, reason), ("invalid", "invalid-proof"))

    def test_content_mismatch_is_invalid_proof(self):
        data = parse(self.cert_coord)
        data["payload"]["status"] = "partial"
        resigned = compact(data)  # signature now wrong and content differs
        # The tampered content fails re-convergence before the HMAC.
        conclusion, reason, *_ = self.reason_for(
            self.item(resigned, "z")
        )
        self.assertEqual((conclusion, reason), ("invalid", "invalid-proof"))

    def test_unauthorized_site(self):
        cert_gamma = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, CERTIFIED_AT,
            GAMMA, 1,
        )
        sp = site_policy((COORD, ALPHA), threshold=1)
        conclusion, reason, site, key_version, convergence = self.reason_for(
            self.item(cert_gamma, "g"), sp=sp
        )
        self.assertEqual((conclusion, reason, site),
                         ("invalid", "unauthorized-site", GAMMA))
        self.assertIsNotNone(convergence)

    def test_unauthorized_version(self):
        sp = {"sites": {COORD: {2}}, "threshold": 1}
        conclusion, reason, site, key_version, _ = self.reason_for(
            self.item(self.cert_coord, "c"), sp=sp
        )
        self.assertEqual((conclusion, reason, site, key_version),
                         ("invalid", "unauthorized-version", COORD, 1))

    def test_credential_unavailable_revoked_not_yet_valid_expired(self):
        # The certificate is signed by ALPHA; the adjudicator keeps its
        # own COORD credentials, so only the item's credential state is
        # observed.
        item = self.item(self.cert_alpha, "a")
        missing = {name: entries for name, entries in RING.items()
                   if name != ALPHA}
        self.assertEqual(
            self.reason_for(item, ring=missing)[1],
            "credential-unavailable",
        )
        revoked = {**RING, ALPHA: [entry(1, SECRET_ALPHA, revoked=True)]}
        self.assertEqual(
            self.reason_for(item, ring=revoked)[1], "revoked",
        )
        future = {**RING, ALPHA: [entry(1, SECRET_ALPHA, not_before=281)]}
        self.assertEqual(
            self.reason_for(item, ring=future)[1], "not-yet-valid",
        )
        expired = {**RING, ALPHA: [entry(1, SECRET_ALPHA, not_after=275)]}
        self.assertEqual(
            self.reason_for(item, ring=expired)[1], "expired",
        )

    def test_bad_signature(self):
        data = parse(self.cert_coord)
        data["signature"] = __import__("hmac").new(
            bytes.fromhex(SECRET_OTHER), compact(data["payload"]),
            hashlib.sha256,
        ).hexdigest()
        conclusion, reason, *_ = self.reason_for(
            self.item(compact(data), "c")
        )
        self.assertEqual((conclusion, reason), ("invalid", "bad-signature"))

    def test_a_rejection_never_stops_later_items(self):
        payload = self.adjudicate_payload([
            self.item(b"{}", "bad"),
            self.item(self.cert_alpha, "a"),
            self.item(self.cert_coord, "c"),
        ], sp=site_policy((COORD, ALPHA), threshold=2))
        rows = {row["id"]: row for row in payload["items"]}
        self.assertEqual(rows["bad"]["conclusion"], "invalid")
        self.assertEqual(rows["a"]["conclusion"], "valid")
        self.assertEqual(rows["c"]["conclusion"], "valid")
        self.assertEqual(payload["status"], "accepted")


class UpfrontValidationTest(AdjudicationFixtures, unittest.TestCase):
    def test_batch_container_type_faults(self):
        with self.assertRaises(TypeError):
            self.adjudicate("x")
        with self.assertRaises(TypeError):
            self.adjudicate(["x"])
        with self.assertRaises(TypeError):
            self.adjudicate([{"id": 1, "certificate": self.cert_coord,
                             "rounds": self.rounds}])
        with self.assertRaises(TypeError):
            self.adjudicate([{"id": "x", "certificate": "y",
                             "rounds": self.rounds}])
        with self.assertRaises(TypeError):
            self.adjudicate([{"id": "x", "certificate": self.cert_coord,
                             "rounds": "y"}])

    def test_nested_round_faults_preempt_the_whole_batch(self):
        # A nested type fault is raised before any certificate is reviewed.
        nested = [{"seq": True, "previous": None,
                   "confirmation": self.confirmation}]
        with self.assertRaises(TypeError):
            self.adjudicate([self.item(self.cert_coord, "ok"),
                             self.item(self.cert_coord, "bad", rounds=nested)])
        nested = [{"seq": "1", "previous": None,
                   "confirmation": self.confirmation}]
        with self.assertRaises(TypeError):
            self.adjudicate([self.item(self.cert_coord, "bad",
                                       rounds=nested)])
        # An empty round or confirmation is a ValueError, also upfront.
        with self.assertRaises(ValueError):
            self.adjudicate([self.item(self.cert_coord, "bad", rounds=[])])
        nested = [{"seq": 1, "previous": None, "confirmation": b""}]
        with self.assertRaises(ValueError):
            self.adjudicate([self.item(self.cert_coord, "bad",
                                       rounds=nested)])

    def test_batch_value_faults(self):
        with self.assertRaises(ValueError):
            self.adjudicate([])
        with self.assertRaises(ValueError):
            self.adjudicate([self.item(self.cert_coord, "")])
        with self.assertRaises(ValueError):
            self.adjudicate([
                self.item(self.cert_coord, "dup"),
                self.item(self.cert_alpha, "dup"),
            ])
        with self.assertRaises(ValueError):
            self.adjudicate([{"id": "x", "certificate": self.cert_coord,
                             "rounds": self.rounds, "extra": 1}])

    def test_shared_material_faults(self):
        items = [self.item(self.cert_coord, "c")]
        with self.assertRaises(TypeError):
            adjudicate_convergence(
                items, "x", self.pol, self.site_policy, RING,
                ADJUDICATE_MOMENT, COORD, 1,
            )
        with self.assertRaises(ValueError):
            adjudicate_convergence(
                items, self.decision, self.pol, {"sites": {}, "threshold": 1},
                RING, ADJUDICATE_MOMENT, COORD, 1,
            )
        with self.assertRaises(ValueError):
            adjudicate_convergence(
                items, self.decision, self.pol,
                {"sites": {COORD: {1}}, "threshold": 2}, RING,
                ADJUDICATE_MOMENT, COORD, 1,
            )
        with self.assertRaises(TypeError):
            adjudicate_convergence(
                items, self.decision, self.pol,
                {"sites": {COORD: [1]}, "threshold": 1}, RING,
                ADJUDICATE_MOMENT, COORD, 1,
            )
        with self.assertRaises(TypeError):
            adjudicate_convergence(
                items, self.decision, self.pol, self.site_policy, RING,
                True, COORD, 1,
            )
        with self.assertRaises(ValueError):
            adjudicate_convergence(
                items, self.decision, self.pol, self.site_policy, RING,
                -1, COORD, 1,
            )
        with self.assertRaises(TypeError):
            self.adjudicate(items, issuer=7)
        with self.assertRaises(ValueError):
            self.adjudicate(items, issuer="")
        with self.assertRaises(TypeError):
            self.adjudicate(items, version=True)
        with self.assertRaises(ValueError):
            self.adjudicate(items, version=0)

    def test_adjudicator_credentials_have_no_fallback(self):
        items = [self.item(self.cert_coord, "c")]
        with self.assertRaises(AuthenticationError):
            self.adjudicate(items, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.adjudicate(items, version=2)
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            self.adjudicate(items, ring=revoked)


class VerifyDecisionTest(AdjudicationFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.adjudicate([
            self.item(self.cert_coord, "c"),
            self.item(self.cert_alpha, "a"),
        ])

    def payload(self):
        return parse(self.raw)["payload"]

    def test_result_is_a_fresh_fixed_key_mapping(self):
        result = self.verify(self.raw)
        self.assertEqual(
            list(result.keys()),
            ["certificates", "common", "commonDigest",
             "convergenceDecisionDigest", "decisionDigest", "issuer",
             "items", "keyVersion", "planDigest", "policyDigest", "status",
             "version"],
        )
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["version"], 1)
        self.assertEqual(
            result["convergenceDecisionDigest"],
            hashlib.sha256(self.raw).hexdigest(),
        )
        self.assertEqual(
            result["decisionDigest"],
            hashlib.sha256(self.decision).hexdigest(),
        )

    def test_repeated_calls_share_no_mutable_object(self):
        first = self.verify(self.raw)
        first["items"].append("tampered")
        first["common"]["results"].append("tampered")
        second = self.verify(self.raw)
        self.assertNotEqual(first, second)
        self.assertEqual(len(second["items"]), 2)
        self.assertEqual(len(second["common"]["results"]), 2)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            self.verify("x")
        with self.assertRaises(TypeError):
            verify_convergence_decision(
                self.raw, "x", self.site_policy, RING, VERIFY_DECISION_MOMENT
            )
        with self.assertRaises(TypeError):
            self.verify(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.verify(self.raw, moment=-1)
        with self.assertRaises(ValueError):
            self.verify(self.raw, sp={"sites": {}, "threshold": 1})

    def test_encoding_and_key_set_faults(self):
        for raw in (self.raw + b"\n", self.raw + b" ", b"", b"{"):
            with self.assertRaises(InvalidConvergenceDecisionError):
                self.verify(raw)
        with self.assertRaises(TypeError):
            self.verify(b"[]")
        data = parse(self.raw)
        del data["signature"]
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify(compact(data))
        payload = self.payload()
        del payload["common"]
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify(compact({"payload": payload,
                                 "signature": parse(self.raw)["signature"]}))

    def test_embedded_field_type_fault_propagates_as_type_error(self):
        payload = self.payload()
        payload["keyVersion"] = "1"
        packet = compact({"payload": payload,
                          "signature": parse(self.raw)["signature"]})
        with self.assertRaises(TypeError):
            self.verify(packet)

    def test_bound_to_another_fork_decision_is_invalid(self):
        other = decide(fork_policy(threshold=3))
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify(self.raw, decision=other)

    def test_policy_digest_mismatch_is_invalid(self):
        other_policy = site_policy((COORD, ALPHA, DELTA), threshold=2)
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify(self.raw, sp=other_policy)

    def test_tampered_status_common_or_ordering_is_invalid(self):
        payload = self.payload()
        signature = parse(self.raw)["signature"]
        payload["status"] = "insufficient"
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify(compact({"payload": payload, "signature": signature}))

        payload = self.payload()
        payload["items"].reverse()
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify(compact({"payload": payload, "signature": signature}))

        payload = self.payload()
        payload["planDigest"] = "ab" * 32
        with self.assertRaises(InvalidConvergenceDecisionError):
            self.verify(compact({"payload": payload, "signature": signature}))

    def test_wrong_signature_is_authentication_error(self):
        data = parse(self.raw)
        data["signature"] = ("1" if data["signature"][0] == "0" else "0") \
            + data["signature"][1:]
        with self.assertRaises(AuthenticationError):
            self.verify(compact(data))

    def test_current_credential_state_is_checked(self):
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=revoked)
        expired = {**RING, COORD: [entry(1, SECRET_COORD, not_after=282)]}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=expired)
        unknown = {name: entries for name, entries in RING.items()
                   if name != COORD}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=unknown)

    def test_inputs_are_not_modified(self):
        snapshot = copy.deepcopy(
            (self.raw, self.decision, self.site_policy, RING)
        )
        self.verify(self.raw)
        self.assertEqual(
            (self.raw, self.decision, self.site_policy, RING), snapshot
        )


class VerifyDecisionsBatchTest(AdjudicationFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.good = self.adjudicate([self.item(self.cert_coord, "c"),
                                     self.item(self.cert_alpha, "a")])

    def batch(self, items, **kwargs):
        return self.verify_batch(items, **kwargs)

    def test_container_type_faults(self):
        with self.assertRaises(TypeError):
            self.batch("x")
        with self.assertRaises(TypeError):
            self.batch(["x"])
        with self.assertRaises(TypeError):
            self.batch([{"id": 1, "decision": self.good}])
        with self.assertRaises(TypeError):
            self.batch([{"id": "x", "decision": "y"}])

    def test_container_value_faults(self):
        with self.assertRaises(ValueError):
            self.batch([])
        with self.assertRaises(ValueError):
            self.batch([{"id": "", "decision": self.good}])
        with self.assertRaises(ValueError):
            self.batch([
                {"id": "x", "decision": self.good},
                {"id": "x", "decision": self.good},
            ])
        with self.assertRaises(ValueError):
            self.batch([{"id": "x", "decision": self.good, "n": 1}])

    def test_shared_material_faults(self):
        items = [{"id": "x", "decision": self.good}]
        with self.assertRaises(TypeError):
            verify_convergence_decisions(
                items, "x", self.site_policy, RING, VERIFY_DECISION_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_convergence_decisions(
                items, self.decision, self.site_policy, RING, True
            )
        with self.assertRaises(ValueError):
            verify_convergence_decisions(
                items, self.decision, self.site_policy, RING, -1
            )

    def test_reports_in_input_order_with_isolation(self):
        report = self.batch([
            {"id": "ok", "decision": self.good},
            {"id": "bad", "decision": b"{}"},
            {"id": "ok2", "decision": self.good},
        ])
        self.assertEqual([i["id"] for i in report["items"]],
                         ["ok", "bad", "ok2"])
        self.assertEqual(
            {i["id"]: i["status"] for i in report["items"]},
            {"ok": "verified", "bad": "invalid", "ok2": "verified"},
        )

    def test_embedded_type_fault_is_invalid_in_a_batch(self):
        payload = parse(self.good)["payload"]
        payload["keyVersion"] = True
        packet = compact({"payload": payload,
                          "signature": parse(self.good)["signature"]})
        report = self.batch([{"id": "x", "decision": packet}])
        self.assertEqual(report["items"][0]["status"], "invalid")

    def test_report_key_order_and_null_result(self):
        report = self.batch([{"id": "bad", "decision": b"{}"}])
        item = report["items"][0]
        self.assertEqual(list(item.keys()),
                         ["error", "id", "result", "status"])
        self.assertIsNone(item["result"])
        self.assertTrue(item["error"])

    def test_unauthenticated_item(self):
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        report = self.batch(
            [{"id": "x", "decision": self.good}], ring=revoked
        )
        item = report["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertIsNone(item["result"])
        self.assertTrue(item["error"])

    def test_top_level_shape_and_freshness(self):
        items = [{"id": "x", "decision": self.good}]
        report = self.batch(items)
        self.assertEqual(set(report.keys()), {"items", "version"})
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["items"][0]["result"]["status"], "accepted")
        second = self.batch(items)
        self.assertEqual(report, second)
        self.assertIsNot(report["items"][0]["result"],
                         second["items"][0]["result"])
        report["items"][0]["result"]["status"] = "tampered"
        self.assertEqual(
            self.batch(items)["items"][0]["result"]["status"], "accepted"
        )


if __name__ == "__main__":
    unittest.main()
