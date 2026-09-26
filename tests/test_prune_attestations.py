"""Tests for signed prune attestations and multi-site adjudication.

Covers :func:`sign_prune_attestation`,
:func:`adjudicate_prune_attestations` and
:func:`verify_prune_adjudication`: the canonical attestation packet
binding receipt/checkpoint byte digests and the complete batch report
in original order, the verbatim preservation of invalid and
unauthenticated items with no trusted identity filled in, exact
site/version HMAC signing with no fallback, the per-packet
``invalid-proof``/``unauthorized``/``unauthenticated`` taxonomy,
same-site duplicate and contradiction handling, cross-site report and
digest agreement that no majority can outvote, the accepted/
insufficient/conflicted outcomes with the common report present only
when accepted, stable site/id ordering with original-order attestation
digests, offline re-tally and signature verification, equal-but-
independent return values, error hierarchy, input immutability and the
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
    InvalidPruneAdjudicationError,
    adjudicate_prune_attestations,
    prune_chain_archives,
    sign_prune_attestation,
    verify_prune_adjudication,
    verify_prune_receipts,
)

from test_chain_prune import PruneFixtures
from test_fork_convergence import (
    COORD,
    RING,
    SECRET_COORD,
    compact,
    entry,
    parse,
)

SITE_A = COORD
SITE_B = "site-b"
SITE_C = "site-c"
JUDGE = "judge"
BATCH = "batch-prune-1"


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def hmac_hex(secret_hex, raw):
    return hmac.new(bytes.fromhex(secret_hex), raw, hashlib.sha256).hexdigest()


def make_ring(sites=(SITE_A, SITE_B, SITE_C, JUDGE), secret=SECRET_COORD,
              revoked=(), not_before=0, not_after=10 ** 9):
    return {
        site: [entry(
            1, secret, revoked=site in revoked, not_before=not_before,
            not_after=not_after,
        )]
        for site in sites
    }


def make_policy(sites=(SITE_A, SITE_B, SITE_C), threshold=2, batch=BATCH):
    return {"batch": batch, "sites": {site: {1} for site in sites},
            "threshold": threshold}


def batch_item(item_id, receipt, checkpoint):
    return {"id": item_id, "receipt": receipt, "checkpoint": checkpoint}


PACKET_KEYS = ["payload", "signature"]
ATTESTATION_PAYLOAD_KEYS = [
    "batch", "items", "keyVersion", "moment", "site", "version",
]
ENTRY_KEYS = ["checkpoint", "id", "receipt", "report"]
ADJUDICATION_PAYLOAD_KEYS = [
    "attestations", "issuer", "items", "keyVersion", "policyDigest",
    "report", "status", "version",
]
ROW_KEYS = ["conclusion", "digest", "entries", "id", "keyVersion",
            "reason", "site"]


class PruneAttestationFixtures(PruneFixtures):
    """Signed prune attestations shared across the test cases."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.ring = make_ring()
        self.policy = make_policy()
        plan = self.make_plan()
        report = prune_chain_archives(
            [self.batch_item("i", "c", plan)], RING
        )[0]
        self.assertIsNone(report["error"])
        self.good_receipt = report["receipt"]
        self.prune_items = [
            batch_item("ok", self.good_receipt, self.checkpoint),
            batch_item("broken", b"not-an-attestation", self.checkpoint),
        ]
        self.good_items = [
            batch_item("only", self.good_receipt, self.checkpoint),
        ]

    def sign_att(self, items=None, batch=BATCH, ring=None,
                    moment=None, site=SITE_A, version=1):
        return sign_prune_attestation(
            self.prune_items if items is None else items,
            batch,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
            site, version,
        )

    def decide(self, entries, policy=None, ring=None, moment=None,
                issuer=JUDGE, version=1):
        return adjudicate_prune_attestations(
            entries,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
            issuer, version,
        )

    @staticmethod
    def packet(item_id, raw):
        return {"id": item_id, "attestation": raw}


class SignPruneAttestationTest(PruneAttestationFixtures, unittest.TestCase):
    def test_packet_shape_and_canonical_encoding(self):
        raw = self.sign_att()
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), ATTESTATION_PAYLOAD_KEYS)
        self.assertEqual(payload["batch"], BATCH)
        self.assertEqual(payload["site"], SITE_A)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.moment)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        # The bytes are exactly the canonical compact form.
        self.assertEqual(compact(data), raw)

    def test_entries_bind_digests_and_full_reports_in_input_order(self):
        raw = self.sign_att()
        entries = parse(raw)["payload"]["items"]
        self.assertEqual([entry["id"] for entry in entries], ["ok", "broken"])
        for entry_obj, item in zip(entries, self.prune_items):
            self.assertEqual(list(entry_obj.keys()), ENTRY_KEYS)
            self.assertEqual(entry_obj["receipt"], sha256(item["receipt"]))
            self.assertEqual(
                entry_obj["checkpoint"], sha256(item["checkpoint"])
            )
        reports = [entry_obj["report"] for entry_obj in entries]
        direct = verify_prune_receipts(self.prune_items, RING, self.moment)
        self.assertEqual(reports, direct["items"])

    def test_invalid_and_unauthenticated_items_are_preserved_verbatim(self):
        ring_minus_coord = {
            site: entries for site, entries in self.ring.items()
            if site != COORD
        }
        # The signing site still has its key, but the checkpoint sealer
        # is unknown, so every receipt verifies unauthenticated.
        raw = self.sign_att(ring=ring_minus_coord, site=SITE_B)
        reports = parse(raw)["payload"]["items"]
        statuses = [entry_obj["report"]["status"] for entry_obj in reports]
        self.assertEqual(statuses, ["unauthenticated", "invalid"])
        for entry_obj in reports:
            self.assertIsNone(entry_obj["report"]["result"])
            self.assertIsInstance(entry_obj["report"]["error"], str)
            self.assertNotEqual(entry_obj["report"]["error"], "")
        # The authenticated report, by contrast, carries the full result.
        good = parse(self.sign_att(items=self.good_items))["payload"]
        result = good["items"][0]["report"]["result"]
        self.assertEqual(result["project"], "c")
        self.assertEqual(result["checkpoint"], sha256(self.checkpoint))

    def test_signature_uses_the_exact_site_version_key(self):
        raw = self.sign_att()
        payload = parse(raw)["payload"]
        self.assertEqual(
            parse(raw)["signature"],
            hmac_hex(SECRET_COORD, compact(payload)),
        )
        # No fallback to another version of the same site.
        ring_v2 = {SITE_A: [entry(2, "22" * 32)], JUDGE: [entry(1, SECRET_COORD)]}
        with self.assertRaises(AuthenticationError):
            self.sign_att(ring=ring_v2, site=SITE_A)

    def test_credential_states_raise_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.sign_att(ring=make_ring(sites=(SITE_B, SITE_C, JUDGE)))
        with self.assertRaises(AuthenticationError):
            self.sign_att(ring=make_ring(revoked=(SITE_A,)))
        with self.assertRaises(AuthenticationError):
            self.sign_att(
                ring=make_ring(not_before=self.moment + 1)
            )
        with self.assertRaises(AuthenticationError):
            self.sign_att(
                ring=make_ring(not_after=self.moment - 1)
            )

    def test_type_and_value_taxonomy(self):
        good = self.prune_items

        def sign(**kwargs):
            kwargs.setdefault("items", good)
            kwargs.setdefault("batch", BATCH)
            kwargs.setdefault("keyring", self.ring)
            kwargs.setdefault("moment", self.moment)
            kwargs.setdefault("site", SITE_A)
            kwargs.setdefault("version", 1)
            return sign_prune_attestation(**kwargs)

        def expect(exc, **kwargs):
            with self.assertRaises(exc):
                sign(**kwargs)

        expect(TypeError, items=(good[0],))
        expect(TypeError, items=["not-a-dict"])
        expect(TypeError, items=[
            batch_item(1, self.good_receipt, self.checkpoint)
        ])
        expect(TypeError, items=[
            {"id": "x", "receipt": "r", "checkpoint": self.checkpoint}
        ])
        expect(TypeError, items=[
            {"id": "x", "receipt": self.good_receipt, "checkpoint": 1}
        ])
        expect(ValueError, items=[])
        expect(ValueError, items=[
            batch_item("", self.good_receipt, self.checkpoint)
        ])
        expect(ValueError, items=[
            batch_item("dup", self.good_receipt, self.checkpoint),
            batch_item("dup", self.good_receipt, self.checkpoint),
        ])
        expect(ValueError, items=[
            {"id": "x", "receipt": self.good_receipt}
        ])

        expect(TypeError, batch=7)
        expect(ValueError, batch="")
        expect(TypeError, keyring=[])
        expect(TypeError, moment=True)
        expect(ValueError, moment=-1)
        expect(TypeError, site=9)
        expect(ValueError, site="")
        expect(TypeError, version=True)
        expect(TypeError, version="1")
        expect(ValueError, version=0)

    def test_repeated_calls_are_equal_and_independent(self):
        first = self.sign_att()
        second = self.sign_att()
        self.assertEqual(first, second)
        first_data = parse(first)
        first_data["payload"]["items"][0]["report"]["status"] = "tampered"
        self.assertEqual(parse(second)["payload"]["items"][0]["report"]["status"],
                         "verified")

    def test_no_input_is_modified_and_no_file_is_touched(self):
        items_copy = copy.deepcopy(self.prune_items)
        ring_copy = copy.deepcopy(self.ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.sign_att()
        self.assertEqual(self.prune_items, items_copy)
        self.assertEqual(self.ring, ring_copy)
        self.assertTrue(raw)


class AdjudicatePruneAttestationsTest(PruneAttestationFixtures,
                                      unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.att_a = self.sign_att(site=SITE_A)
        self.att_b = self.sign_att(site=SITE_B)
        self.att_c = self.sign_att(site=SITE_C)

    def decide(self, sites_raw, **kwargs):
        packets = [
            self.packet(item_id, raw) for item_id, raw in sites_raw
        ]
        return super().decide(packets, **kwargs)

    def test_accepted_when_distinct_sites_reach_threshold(self):
        raw = self.decide([("a", self.att_a), ("b", self.att_b)])
        payload = parse(raw)["payload"]
        self.assertEqual(list(payload.keys()), ADJUDICATION_PAYLOAD_KEYS)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["attestations"],
                         [sha256(self.att_a), sha256(self.att_b)])
        # The common report is the agreed complete batch report.
        expected_report = verify_prune_receipts(
            self.prune_items, RING, self.moment
        )
        self.assertEqual(payload["report"], expected_report)
        rows = payload["items"]
        self.assertEqual(
            [(row["site"], row["id"], row["conclusion"], row["reason"])
             for row in rows],
            [(SITE_A, "a", "valid", None),
             (SITE_B, "b", "valid", None)],
        )
        for row in rows:
            self.assertEqual(list(row.keys()), ROW_KEYS)
            self.assertEqual(row["keyVersion"], 1)
            self.assertIsNotNone(row["entries"])
            self.assertEqual(row["digest"], sha256(
                self.att_a if row["site"] == SITE_A else self.att_b
            ))
        self.assertEqual(compact(parse(raw)), raw)
        self.assertFalse(raw.endswith(b"\n"))

    def test_insufficient_below_threshold_carries_no_report(self):
        raw = self.decide([("a", self.att_a)])
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNone(payload["report"])

    def test_same_site_exact_copy_is_a_duplicate(self):
        raw = self.decide(
            [("first", self.att_a), ("second", self.att_a)],
            policy=make_policy(threshold=1),
        )
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(
            [(row["id"], row["conclusion"], row["reason"])
             for row in payload["items"]],
            [("first", "valid", None),
             ("second", "duplicate", "duplicate")],
        )

    def test_same_site_different_content_is_a_contradiction(self):
        att_reversed = self.sign_att(
            items=list(reversed(self.prune_items)), site=SITE_A
        )
        raw = self.decide([
            ("one", self.att_a), ("two", att_reversed),
            ("three", self.att_b),
        ])
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["report"])
        conclusions = {
            row["id"]: (row["conclusion"], row["reason"])
            for row in payload["items"]
        }
        self.assertEqual(conclusions["one"], ("contradiction", "contradiction"))
        self.assertEqual(conclusions["two"], ("contradiction", "contradiction"))
        self.assertEqual(conclusions["three"], ("valid", None))

    def test_cross_site_disagreement_conflicts_even_with_a_majority(self):
        # Two sites agree on one content, one site attests a different
        # report order: the 2-of-3 majority must not mask the fork.
        att_c_reversed = self.sign_att(
            items=list(reversed(self.prune_items)), site=SITE_C
        )
        raw = self.decide([
            ("a", self.att_a), ("b", self.att_b), ("c", att_c_reversed),
        ])
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["report"])

    def test_cross_site_difference_only_in_a_bound_digest_conflicts(self):
        # Same reports, but one site binds a different checkpoint digest
        # for the same item id.
        other = self.other_checkpoint()
        # Re-plan against the other checkpoint and produce a receipt for it.
        other_path = self.paths["c"]
        with open(other_path, "wb") as handle:
            handle.write(self.archive_bytes("c", self.cert_coord))
        from offline_coordination.replication import plan_chain_prune
        plan_other = plan_chain_prune(
            [other_path], other, self.decision, self.pol, RING, self.moment,
        )
        other_report = prune_chain_archives([{
            "id": "i", "path": other_path, "plan": plan_other,
            "checkpoint": other,
            "header": {"issuer": COORD, "keyVersion": 1,
                       "moment": self.moment},
        }], RING)[0]
        self.assertIsNone(other_report["error"], other_report["error"])
        other_items = [
            batch_item("ok", other_report["receipt"], other),
            batch_item("broken", b"not-an-attestation", other),
        ]
        att_other = self.sign_att(items=other_items, site=SITE_C)
        raw = self.decide([
            ("a", self.att_a), ("b", self.att_b), ("c", att_other),
        ])
        self.assertEqual(parse(raw)["payload"]["status"], "conflicted")

    def test_invalid_unauthorized_and_unauthenticated_rows(self):
        malformed = b"nope"

        wrong_batch = self.sign_att(batch="other-batch")
        unknown_site_payload = parse(self.att_a)["payload"]
        unknown_site = compact({
            "payload": {**unknown_site_payload, "site": "ghost"},
            "signature": hmac_hex("77" * 32, compact(
                {**unknown_site_payload, "site": "ghost"}
            )),
        })

        wrong_version = parse(self.att_a)
        wrong_version["payload"]["keyVersion"] = 2
        ring_v2 = {**self.ring, SITE_A: [
            entry(1, SECRET_COORD), entry(2, SECRET_COORD)
        ]}
        wrong_version_raw = compact({
            "payload": wrong_version["payload"],
            "signature": hmac_hex(
                SECRET_COORD, compact(wrong_version["payload"])
            ),
        })
        # Policy does not allow version 2 for site A.

        bad_signature = parse(self.att_a)
        flipped = ("0" if bad_signature["signature"][0] != "0" else "1") \
            + bad_signature["signature"][1:]
        bad_signature["signature"] = flipped
        bad_signature_raw = compact(bad_signature)

        raw = self.decide([
            ("malformed", malformed),
            ("batch", wrong_batch),
            ("site", unknown_site),
            ("version", wrong_version_raw),
            ("signature", bad_signature_raw),
            ("good", self.att_b),
        ], ring=ring_v2)
        rows = {
            row["id"]: row for row in parse(raw)["payload"]["items"]
        }
        self.assertEqual(
            (rows["malformed"]["conclusion"],
             rows["malformed"]["reason"]),
            ("invalid", "invalid-proof"),
        )
        self.assertIsNone(rows["malformed"]["site"])
        self.assertIsNone(rows["malformed"]["keyVersion"])
        self.assertIsNone(rows["malformed"]["entries"])
        self.assertEqual(
            (rows["batch"]["conclusion"], rows["batch"]["reason"]),
            ("invalid", "unauthorized"),
        )
        self.assertEqual(rows["batch"]["site"], SITE_A)
        self.assertIsNone(rows["batch"]["entries"])
        self.assertEqual(
            (rows["site"]["conclusion"], rows["site"]["reason"]),
            ("invalid", "unauthorized"),
        )
        self.assertEqual(
            (rows["version"]["conclusion"], rows["version"]["reason"]),
            ("invalid", "unauthorized"),
        )
        self.assertEqual(rows["version"]["keyVersion"], 2)
        self.assertEqual(
            (rows["signature"]["conclusion"],
             rows["signature"]["reason"]),
            ("invalid", "unauthenticated"),
        )
        self.assertEqual(
            (rows["good"]["conclusion"], rows["good"]["reason"]),
            ("valid", None),
        )
        # One valid site below threshold.
        self.assertEqual(parse(raw)["payload"]["status"], "insufficient")

    def test_revoked_or_expired_credentials_are_unauthenticated(self):
        revoked = self.decide(
            [("a", self.att_a)], ring=make_ring(revoked=(SITE_A,)),
            policy=make_policy(sites=(SITE_A,), threshold=1),
        )
        self.assertEqual(
            parse(revoked)["payload"]["items"][0]["reason"],
            "unauthenticated",
        )
        # Site A's key expires after moment 5 while the adjudicator key
        # stays valid: adjudicating at 6 rejects A as unauthenticated.
        expired_ring = {
            SITE_A: [entry(1, SECRET_COORD, not_after=5)],
            JUDGE: [entry(1, SECRET_COORD)],
        }
        expired_att = sign_prune_attestation(
            self.prune_items, BATCH, expired_ring, 5, SITE_A, 1
        )
        expired = adjudicate_prune_attestations(
            [self.packet("a", expired_att)],
            make_policy(sites=(SITE_A,), threshold=1),
            expired_ring, 6, JUDGE, 1,
        )
        self.assertEqual(
            parse(expired)["payload"]["items"][0]["reason"],
            "unauthenticated",
        )

    def test_rows_are_sorted_by_site_then_id_independent_of_input(self):
        raw = self.decide([
            ("z", self.att_c), ("y", self.att_a), ("x", self.att_b),
        ])
        self.assertEqual(
            [(row["site"], row["id"]) for row in parse(raw)["payload"]["items"]],
            [(SITE_A, "y"), (SITE_B, "x"), (SITE_C, "z")],
        )
        # Original order is still preserved for the attestation digests.
        self.assertEqual(
            parse(raw)["payload"]["attestations"],
            [sha256(self.att_c), sha256(self.att_a), sha256(self.att_b)],
        )

    def test_invalid_proof_rows_sort_before_authenticated_rows(self):
        # A malformed packet carries no site and therefore sorts first.
        raw = self.decide([("z", self.att_a), ("a", b"nope")],
                              policy=make_policy(threshold=1))
        self.assertEqual(
            [row["id"] for row in parse(raw)["payload"]["items"]],
            ["a", "z"],
        )

    def test_output_is_input_order_and_input_independent_for_same_votes(self):
        left = self.decide([("a", self.att_a), ("b", self.att_b)])
        right = self.decide([("b", self.att_b), ("a", self.att_a)])
        left_payload = parse(left)["payload"]
        right_payload = parse(right)["payload"]
        # Only the original-order attestation digest list may differ.
        self.assertEqual(
            left_payload["items"], right_payload["items"],
        )
        self.assertEqual(left_payload["report"], right_payload["report"])
        self.assertEqual(left_payload["status"], right_payload["status"])

    def test_argument_taxonomy(self):
        good = [self.packet("a", self.att_a)]

        def adjudicate(**kwargs):
            kwargs.setdefault("items", good)
            kwargs.setdefault("policy", self.policy)
            kwargs.setdefault("keyring", self.ring)
            kwargs.setdefault("moment", self.moment)
            kwargs.setdefault("issuer", JUDGE)
            kwargs.setdefault("version", 1)
            return adjudicate_prune_attestations(**kwargs)

        def expect(exc, **kwargs):
            with self.assertRaises(exc):
                adjudicate(**kwargs)

        expect(TypeError, items=(good[0],))
        expect(TypeError, items=["x"])
        expect(TypeError, items=[
            {"id": 1, "attestation": self.att_a}
        ])
        expect(TypeError, items=[
            {"id": "x", "attestation": "raw"}
        ])
        expect(ValueError, items=[])
        expect(ValueError, items=[
            self.packet("", self.att_a)
        ])
        expect(ValueError, items=[
            self.packet("dup", self.att_a), self.packet("dup", self.att_a),
        ])
        expect(ValueError, items=[
            {"id": "x"}
        ])
        expect(TypeError, policy=[])
        expect(ValueError, policy={
            "batch": BATCH, "sites": {SITE_A: {1}}, "threshold": 2,
        })
        expect(ValueError, policy={
            "batch": BATCH,
            "sites": {SITE_A: {0}},
            "threshold": 1,
        })
        expect(TypeError, policy={
            "batch": BATCH,
            "sites": {SITE_A: [1]},
            "threshold": 1,
        })
        expect(TypeError, moment=True)
        expect(ValueError, moment=-1)
        expect(TypeError, issuer=5)
        expect(ValueError, issuer="")
        expect(TypeError, version=True)
        expect(ValueError, version=-2)
        # Unknown adjudicator credentials.
        expect(AuthenticationError, issuer="ghost")

    def test_no_input_is_modified_and_no_file_is_touched(self):
        packets = [self.packet("a", self.att_a),
                   self.packet("b", self.att_b)]
        packets_copy = copy.deepcopy(packets)
        ring_copy = copy.deepcopy(self.ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.decide([("a", self.att_a), ("b", self.att_b)])
        self.assertEqual(packets, packets_copy)
        self.assertEqual(self.ring, ring_copy)


class VerifyPruneAdjudicationTest(PruneAttestationFixtures,
                                  unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.att_a = self.sign_att(site=SITE_A)
        self.att_b = self.sign_att(site=SITE_B)
        packets = [self.packet("a", self.att_a),
                   self.packet("b", self.att_b)]
        self.decision = self.decide(packets)

    def verify(self, raw=None, policy=None, ring=None, moment=None):
        return verify_prune_adjudication(
            self.decision if raw is None else raw,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
        )

    def resign(self, data):
        data["signature"] = hmac_hex(
            self.ring[JUDGE][0]["secret"], compact(data["payload"])
        )
        return compact(data)

    def test_success_returns_equal_but_independent_payload(self):
        result = self.verify()
        payload = parse(self.decision)["payload"]
        self.assertEqual(result, payload)
        self.assertIsNot(result, payload)
        again = self.verify()
        self.assertEqual(result, again)
        self.assertIsNot(result, again)
        self.assertIsNot(result["items"], again["items"])
        result["status"] = "tampered"
        result["items"][0]["conclusion"] = "tampered"
        fresh = self.verify()
        self.assertEqual(fresh["status"], "accepted")
        self.assertEqual(fresh["items"][0]["conclusion"], "valid")

    def test_policy_digest_binding(self):
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(policy=make_policy(batch="other-batch"))
        # A different threshold re-tallies to a different status.
        single = self.decide(
            [self.packet("a", self.att_a)],
            policy=make_policy(threshold=1),
        )
        with self.assertRaises(InvalidPruneAdjudicationError):
            verify_prune_adjudication(
                single, make_policy(threshold=2), self.ring, self.moment
            )
        # The same bytes verify fine against the true policy.
        self.assertEqual(
            verify_prune_adjudication(
                single, make_policy(threshold=1), self.ring, self.moment
            )["status"],
            "accepted",
        )

    def test_current_credentials_are_required(self):
        with self.assertRaises(AuthenticationError):
            self.verify(ring=make_ring(revoked=(JUDGE,)))
        with self.assertRaises(AuthenticationError):
            self.verify(ring=make_ring(not_after=self.moment - 1))
        with self.assertRaises(AuthenticationError):
            self.verify(moment=10 ** 12)
        ring_minus_judge = {
            site: entries for site, entries in self.ring.items()
            if site != JUDGE
        }
        with self.assertRaises(AuthenticationError):
            self.verify(ring=ring_minus_judge)

    def test_wrong_signature_is_unauthenticated(self):
        data = parse(self.decision)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.verify(raw=compact(data))

    def test_structural_faults_are_invalid(self):
        self.assertRaises(
            InvalidPruneAdjudicationError, self.verify, raw=b"nope"
        )
        self.assertRaises(
            InvalidPruneAdjudicationError, self.verify, raw=self.decision + b"\n"
        )
        indented = json.dumps(
            parse(self.decision), indent=1, sort_keys=True
        ).encode()
        self.assertRaises(
            InvalidPruneAdjudicationError, self.verify, raw=indented
        )

        data = parse(self.decision)
        del data["payload"]["report"]
        self.assertRaises(
            InvalidPruneAdjudicationError, self.verify, raw=self.resign(data)
        )
        data = parse(self.decision)
        data["payload"]["version"] = 2
        self.assertRaises(
            InvalidPruneAdjudicationError, self.verify, raw=self.resign(data)
        )

    def test_tampered_tally_bindings_are_invalid(self):
        # Reorder the signed rows without updating the digest multiset.
        data = parse(self.decision)
        data["payload"]["items"].reverse()
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(raw=self.resign(data))

        # Swap one bound attestation digest without touching the list.
        data = parse(self.decision)
        data["payload"]["attestations"][0] = "11" * 32
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(raw=self.resign(data))

        # Flip a conclusion/reason pair.
        data = parse(self.decision)
        row = data["payload"]["items"][0]
        row["conclusion"] = "duplicate"
        row["reason"] = "duplicate"
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(raw=self.resign(data))

        # Claim a report for an insufficient adjudication.
        insufficient = self.decide([self.packet("a", self.att_a)])
        data = parse(insufficient)
        data["payload"]["report"] = verify_prune_receipts(
            self.prune_items, RING, self.moment
        )
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(raw=self.resign(data))

        # Drop the common report while claiming accepted.
        data = parse(self.decision)
        data["payload"]["report"] = None
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(raw=self.resign(data))

        # Tamper the content of the common report.
        data = parse(self.decision)
        data["payload"]["report"]["items"][0]["id"] = "renamed"
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(raw=self.resign(data))

        # Claim accepted while the tallied content actually conflicts:
        # replace one site's entries with different content, keep
        # "accepted" and the old report.
        data = parse(self.decision)
        other_entries = parse(
            self.sign_att(items=list(reversed(self.prune_items)), site=SITE_B)
        )["payload"]["items"]
        for row in data["payload"]["items"]:
            if row["site"] == SITE_B:
                row["entries"] = other_entries
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(raw=self.resign(data))

    def test_duplicate_and_contradiction_markings_are_re_derived(self):
        duplicate = self.decide(
            [self.packet("a", self.att_a), self.packet("b", self.att_a)],
            policy=make_policy(threshold=1),
        )
        # Call the duplicate a valid row: tally re-derivation must catch it.
        data = parse(duplicate)
        dup_row = next(
            row for row in data["payload"]["items"] if row["id"] == "b"
        )
        dup_row["conclusion"] = "valid"
        dup_row["reason"] = None
        with self.assertRaises(InvalidPruneAdjudicationError):
            self.verify(
                raw=self.resign(data), policy=make_policy(threshold=1)
            )

    def test_argument_taxonomy(self):
        self.assertRaises(TypeError, self.verify, raw="bytes")
        self.assertRaises(TypeError, self.verify, policy=[])
        self.assertRaises(TypeError, self.verify, ring=[])
        self.assertRaises(TypeError, self.verify, moment=True)
        self.assertRaises(ValueError, self.verify, moment=-1)
        self.assertRaises(ValueError, self.verify, policy={
            "batch": BATCH, "sites": {}, "threshold": 1,
        })

    def test_error_hierarchy(self):
        self.assertTrue(
            issubclass(InvalidPruneAdjudicationError, ValueError)
        )
        self.assertTrue(issubclass(AuthenticationError, ValueError))

    def test_verification_reads_no_file(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.verify()


if __name__ == "__main__":
    unittest.main()
