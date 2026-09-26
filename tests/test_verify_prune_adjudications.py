"""Tests for batch verification and signed handover of prune adjudications.

Covers :func:`verify_prune_adjudications`,
:func:`sign_prune_adjudication_batch` and
:func:`verify_prune_adjudication_batch`: the batch container validated
in full before any adjudication is parsed, the per-item
verified/invalid/unauthenticated taxonomy with input-order reports and
no cross-item interference, the fixed error/id/result/status report
shape and the items/version top level, the canonical signed packet
binding the issuer, exact key version, verification moment, policy
digest and the original-order id/digest/full-report triples, verbatim
preservation of invalid and unauthenticated items with no trusted
identity filled in, exact issuer/version HMAC signing with no fallback,
offline re-checking of order, digest and report bindings (including a
full re-tally of every verified report's adjudication), the
InvalidPruneAdjudicationBatchError hierarchy, equal-but-independent
return values, input immutability and the purely offline guarantee.
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
    InvalidPruneAdjudicationBatchError,
    adjudicate_prune_attestations,
    sign_prune_adjudication_batch,
    verify_prune_adjudication,
    verify_prune_adjudication_batch,
    verify_prune_adjudications,
)

from test_fork_convergence import (
    COORD,
    SECRET_COORD,
    compact,
    entry,
    parse,
)
from test_prune_attestations import (
    BATCH,
    JUDGE,
    SITE_A,
    SITE_B,
    SITE_C,
    PruneAttestationFixtures,
    hmac_hex,
    make_policy,
    make_ring,
)

INNER_ISSUER = "inner-judge"

REPORT_KEYS = ["error", "id", "result", "status"]
BATCH_PACKET_KEYS = ["payload", "signature"]
BATCH_PAYLOAD_KEYS = [
    "issuer", "items", "keyVersion", "moment", "policyDigest", "version",
]
BATCH_ITEM_KEYS = ["digest", "id", "report"]


def adj_packet(item_id, raw):
    """One :func:`verify_prune_adjudications` input item."""
    return {"id": item_id, "adjudication": raw}


class PruneAdjudicationBatchFixtures(PruneAttestationFixtures):
    """Signed adjudications shared across the batch test cases."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.att_a = self.sign_att(site=SITE_A)
        self.att_b = self.sign_att(site=SITE_B)
        self.att_c = self.sign_att(site=SITE_C)
        self.accepted = self.decide([
            self.packet("a", self.att_a), self.packet("b", self.att_b),
        ])
        self.below = self.decide([self.packet("a", self.att_a)])
        self.no_votes = self.decide([self.packet("bad", b"nope")])
        att_c_reversed = self.sign_att(
            items=list(reversed(self.prune_items)), site=SITE_C
        )
        self.conflicted = self.decide([
            self.packet("a", self.att_a), self.packet("b", self.att_b),
            self.packet("c", att_c_reversed),
        ])
        ring_with_inner = {
            **self.ring, INNER_ISSUER: [entry(1, SECRET_COORD)],
        }
        self.inner_signed = adjudicate_prune_attestations(
            [self.packet("a", self.att_a), self.packet("b", self.att_b)],
            self.policy, ring_with_inner, self.moment, INNER_ISSUER, 1,
        )

    def batch_verify(self, adjudications, policy=None, ring=None,
                     moment=None):
        return verify_prune_adjudications(
            adjudications,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
        )

    def sign_batch(self, adjudications, policy=None, ring=None,
                   moment=None, issuer=JUDGE, version=1):
        return sign_prune_adjudication_batch(
            adjudications,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
            issuer, version,
        )

    def verify_batch(self, packet, policy=None, ring=None, moment=None):
        return verify_prune_adjudication_batch(
            packet,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
        )

    def resign_outer(self, data, secret=SECRET_COORD):
        data["signature"] = hmac_hex(secret, compact(data["payload"]))
        return compact(data)


class VerifyPruneAdjudicationsTest(PruneAdjudicationBatchFixtures,
                                  unittest.TestCase):
    def test_top_and_report_shape_in_input_order(self):
        result = self.batch_verify([
            adj_packet("one", self.accepted),
            adj_packet("two", b"nope"),
        ])
        self.assertEqual(list(result.keys()), ["items", "version"])
        self.assertEqual(result["version"], 1)
        self.assertIsNot(result["version"], True)
        reports = result["items"]
        self.assertEqual([r["id"] for r in reports], ["one", "two"])
        for report in reports:
            self.assertEqual(list(report.keys()), REPORT_KEYS)
        self.assertEqual(
            [r["status"] for r in reports], ["verified", "invalid"]
        )
        self.assertIsNone(reports[0]["error"])
        self.assertIsInstance(reports[1]["error"], str)
        self.assertNotEqual(reports[1]["error"], "")
        self.assertIsNone(reports[1]["result"])

    def test_verified_result_is_the_single_entry_payload(self):
        result = self.batch_verify([adj_packet("a", self.accepted)])
        direct = verify_prune_adjudication(
            self.accepted, self.policy, self.ring, self.moment
        )
        self.assertEqual(result["items"][0]["result"], direct)
        self.assertIsNone(result["items"][0]["error"])

    def test_one_failure_never_blocks_later_items_or_changes_reports(self):
        result = self.batch_verify([
            adj_packet("broken", b"nope"),
            adj_packet("good", self.accepted),
            adj_packet("also-broken", b'{"payload": {}'),
        ])
        self.assertEqual(
            [r["status"] for r in result["items"]],
            ["invalid", "verified", "invalid"],
        )
        self.assertIsNone(result["items"][1]["error"])
        self.assertEqual(
            result["items"][1]["result"]["status"], "accepted"
        )

    def test_invalid_statuses_for_structure_and_binding_faults(self):
        # A structurally illegal packet.
        malformed = adj_packet("malformed", b"nope")
        # A well-formed packet bound to a different policy.
        other_policy = make_policy(batch="other-batch")
        bound_elsewhere = self.decide(
            [self.packet("a", self.att_a)], policy=other_policy
        )
        # A tampered common report, resigned by the adjudicator: parsing
        # succeeds but the tally binding fails.
        data = parse(self.below)
        data["payload"]["report"] = None
        tampered = self.resign_outer(data)
        result = self.batch_verify([
            malformed,
            adj_packet("policy", bound_elsewhere),
            adj_packet("tampered", tampered),
        ])
        self.assertEqual(
            [r["status"] for r in result["items"]],
            ["invalid", "invalid", "invalid"],
        )
        for report in result["items"]:
            self.assertIsNone(report["result"])
            self.assertTrue(report["error"])

    def test_unauthenticated_status_for_credential_and_signature_faults(self):
        # The inner issuer no longer exists in the current keyring.
        missing = self.batch_verify(
            [adj_packet("missing", self.inner_signed)]
        )
        self.assertEqual(
            missing["items"][0]["status"], "unauthenticated"
        )
        # A revoked inner issuer.
        revoked_ring = {
            **self.ring,
            INNER_ISSUER: [entry(1, SECRET_COORD, revoked=True)],
        }
        revoked = self.batch_verify(
            [adj_packet("revoked", self.inner_signed)], ring=revoked_ring
        )
        self.assertEqual(
            revoked["items"][0]["status"], "unauthenticated"
        )
        # An expired inner key at a later verification moment.
        expired_ring = {
            **self.ring,
            INNER_ISSUER: [entry(1, SECRET_COORD, not_after=self.moment)],
        }
        expired = self.batch_verify(
            [adj_packet("expired", self.inner_signed)],
            ring=expired_ring, moment=self.moment + 1,
        )
        self.assertEqual(
            expired["items"][0]["status"], "unauthenticated"
        )
        # A wrong inner signature.
        data = parse(self.accepted)
        flipped = ("0" if data["signature"][0] != "0" else "1") \
            + data["signature"][1:]
        data["signature"] = flipped
        bad_sig = self.batch_verify([adj_packet("sig", compact(data))])
        self.assertEqual(bad_sig["items"][0]["status"], "unauthenticated")
        for report in (
            missing["items"] + revoked["items"] + expired["items"]
            + bad_sig["items"]
        ):
            self.assertIsNone(report["result"])
            self.assertTrue(report["error"])

    def test_mixed_outcomes_keep_their_own_identity_scope(self):
        result = self.batch_verify([
            adj_packet("ok", self.accepted),
            adj_packet("bad", b"nope"),
            adj_packet("ghost", self.inner_signed),
        ])
        statuses = {r["id"]: r["status"] for r in result["items"]}
        self.assertEqual(
            statuses, {"ok": "verified", "bad": "invalid",
                       "ghost": "unauthenticated"}
        )
        # Only the verified item carries the adjudicator identity.
        self.assertEqual(
            result["items"][0]["result"]["issuer"], JUDGE
        )
        self.assertIsNone(result["items"][1]["result"])
        self.assertIsNone(result["items"][2]["result"])

    def test_structure_is_validated_before_any_adjudication_is_parsed(self):
        # Every byte string here is garbage; the empty id and the
        # duplicate id are nevertheless batch-level ValueErrors raised
        # before any per-item report exists.
        with self.assertRaises(ValueError):
            self.batch_verify([
                adj_packet("a", b"nope"), adj_packet("", b"nope"),
            ])
        with self.assertRaises(ValueError):
            self.batch_verify([
                adj_packet("dup", b"nope"), adj_packet("dup", b"nope"),
            ])
        with self.assertRaises(ValueError):
            self.batch_verify([{"id": "a"}])

    def test_repeated_calls_are_equal_but_deep_independent(self):
        items = [
            adj_packet("ok", self.accepted), adj_packet("bad", b"nope"),
        ]
        first = self.batch_verify(items)
        second = self.batch_verify(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(
            first["items"][0]["result"], second["items"][0]["result"]
        )
        first["items"][0]["result"]["status"] = "tampered"
        self.assertEqual(
            self.batch_verify(items)["items"][0]["result"]["status"],
            "accepted",
        )

    def test_argument_taxonomy(self):
        good = [adj_packet("a", self.accepted)]

        def verify(**kwargs):
            kwargs.setdefault("items", good)
            kwargs.setdefault("policy", self.policy)
            kwargs.setdefault("keyring", self.ring)
            kwargs.setdefault("moment", self.moment)
            return verify_prune_adjudications(**kwargs)

        def expect(exc, **kwargs):
            with self.assertRaises(exc):
                verify(**kwargs)

        expect(TypeError, items=(good[0],))
        expect(TypeError, items=["x"])
        expect(TypeError, items=[{"id": 1, "adjudication": self.accepted}])
        expect(TypeError, items=[{"id": "x", "adjudication": "raw"}])
        expect(ValueError, items=[])
        expect(ValueError, items=[adj_packet("", self.accepted)])
        expect(ValueError,
               items=[adj_packet("dup", self.accepted),
                      adj_packet("dup", self.accepted)])
        expect(ValueError, items=[{"id": "x"}])
        expect(TypeError, policy=[])
        expect(ValueError, policy={
            "batch": BATCH, "sites": {}, "threshold": 1,
        })
        expect(TypeError, keyring=[])
        expect(TypeError, moment=True)
        expect(ValueError, moment=-1)

    def test_no_input_is_modified_and_no_file_is_touched(self):
        items = [
            adj_packet("ok", self.accepted), adj_packet("bad", b"nope"),
        ]
        items_copy = copy.deepcopy(items)
        ring_copy = copy.deepcopy(self.ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            result = self.batch_verify(items)
        self.assertEqual(items, items_copy)
        self.assertEqual(self.ring, ring_copy)
        self.assertTrue(result["items"])


class SignPruneAdjudicationBatchTest(PruneAdjudicationBatchFixtures,
                                     unittest.TestCase):
    def test_packet_shape_and_canonical_encoding(self):
        raw = self.sign_batch([
            adj_packet("ok", self.accepted), adj_packet("bad", b"nope"),
        ])
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), BATCH_PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), BATCH_PAYLOAD_KEYS)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.moment)
        self.assertEqual(payload["version"], 1)
        # The outer policy digest is the same digest the adjudications
        # already bind.
        self.assertEqual(
            payload["policyDigest"],
            parse(self.accepted)["payload"]["policyDigest"],
        )
        self.assertEqual(compact(data), raw)

    def test_items_bind_digests_and_full_reports_in_input_order(self):
        adjudications = [
            adj_packet("ok", self.accepted),
            adj_packet("bad", b"nope"),
            adj_packet("ghost", self.inner_signed),
        ]
        raw = self.sign_batch(adjudications)
        items = parse(raw)["payload"]["items"]
        self.assertEqual([item["id"] for item in items],
                         ["ok", "bad", "ghost"])
        direct = self.batch_verify(adjudications)
        for item, source, report in zip(items, adjudications, direct["items"]):
            self.assertEqual(list(item.keys()), BATCH_ITEM_KEYS)
            self.assertEqual(item["digest"],
                             hashlib.sha256(source["adjudication"]).hexdigest())
            self.assertEqual(item["report"], report)

    def test_failed_items_are_preserved_verbatim(self):
        raw = self.sign_batch([
            adj_packet("bad", b"nope"), adj_packet("ghost", self.inner_signed),
        ])
        reports = parse(raw)["payload"]["items"]
        statuses = [item["report"]["status"] for item in reports]
        self.assertEqual(statuses, ["invalid", "unauthenticated"])
        for item in reports:
            self.assertIsNone(item["report"]["result"])
            self.assertTrue(item["report"]["error"])
            self.assertEqual(item["report"]["id"], item["id"])

    def test_signature_uses_the_exact_issuer_version_key(self):
        raw = self.sign_batch([adj_packet("a", self.accepted)])
        data = parse(raw)
        self.assertEqual(
            data["signature"],
            hmac_hex(SECRET_COORD, compact(data["payload"])),
        )
        ring_v2 = {
            SITE_A: [entry(1, SECRET_COORD)],
            SITE_B: [entry(1, SECRET_COORD)],
            SITE_C: [entry(1, SECRET_COORD)],
            JUDGE: [entry(2, "22" * 32)],
        }
        with self.assertRaises(AuthenticationError):
            self.sign_batch(
                [adj_packet("a", self.accepted)], ring=ring_v2,
            )

    def test_credential_states_raise_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.sign_batch(
                [adj_packet("a", self.accepted)], issuer="ghost"
            )
        with self.assertRaises(AuthenticationError):
            self.sign_batch(
                [adj_packet("a", self.accepted)],
                ring=make_ring(revoked=(JUDGE,)),
            )
        with self.assertRaises(AuthenticationError):
            self.sign_batch(
                [adj_packet("a", self.accepted)],
                ring=make_ring(not_before=self.moment + 1),
            )
        with self.assertRaises(AuthenticationError):
            self.sign_batch(
                [adj_packet("a", self.accepted)],
                ring=make_ring(not_after=self.moment - 1),
            )

    def test_type_and_value_taxonomy(self):
        good = [adj_packet("a", self.accepted)]

        def sign(**kwargs):
            kwargs.setdefault("items", good)
            kwargs.setdefault("policy", self.policy)
            kwargs.setdefault("keyring", self.ring)
            kwargs.setdefault("moment", self.moment)
            kwargs.setdefault("issuer", JUDGE)
            kwargs.setdefault("version", 1)
            return sign_prune_adjudication_batch(**kwargs)

        def expect(exc, **kwargs):
            with self.assertRaises(exc):
                sign(**kwargs)

        expect(TypeError, items=(good[0],))
        expect(TypeError, items=["x"])
        expect(TypeError, items=[{"id": 1, "adjudication": self.accepted}])
        expect(TypeError, items=[{"id": "x", "adjudication": "raw"}])
        expect(ValueError, items=[])
        expect(ValueError, items=[adj_packet("", self.accepted)])
        expect(ValueError,
               items=[adj_packet("dup", self.accepted),
                      adj_packet("dup", self.accepted)])
        expect(ValueError, items=[{"id": "x"}])
        expect(TypeError, policy=[])
        expect(TypeError, keyring=[])
        expect(TypeError, moment=True)
        expect(ValueError, moment=-1)
        expect(TypeError, issuer=9)
        expect(ValueError, issuer="")
        expect(TypeError, version=True)
        expect(TypeError, version="1")
        expect(ValueError, version=0)

    def test_repeated_calls_equal_and_independent(self):
        first = self.sign_batch([adj_packet("a", self.accepted)])
        second = self.sign_batch([adj_packet("a", self.accepted)])
        self.assertEqual(first, second)
        parse(first)["payload"]["items"][0]["report"]["result"]["status"] = "x"
        self.assertEqual(
            parse(second)["payload"]["items"][0]["report"]["result"]["status"],
            "accepted",
        )

    def test_no_input_is_modified_and_no_file_is_touched(self):
        items = [
            adj_packet("ok", self.accepted), adj_packet("bad", b"nope"),
        ]
        items_copy = copy.deepcopy(items)
        ring_copy = copy.deepcopy(self.ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.sign_batch(items)
        self.assertEqual(items, items_copy)
        self.assertEqual(self.ring, ring_copy)
        self.assertTrue(raw)


class VerifyPruneAdjudicationBatchTest(PruneAdjudicationBatchFixtures,
                                      unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.packet = self.sign_batch([
            adj_packet("ok", self.accepted),
            adj_packet("bad", b"nope"),
            adj_packet("ghost", self.inner_signed),
        ])

    def test_success_returns_equal_but_independent_payload(self):
        result = self.verify_batch(self.packet)
        payload = parse(self.packet)["payload"]
        self.assertEqual(result, payload)
        self.assertIsNot(result, payload)
        again = self.verify_batch(self.packet)
        self.assertEqual(result, again)
        self.assertIsNot(result, again)
        self.assertIsNot(result["items"], again["items"])
        result["items"][0]["report"]["result"]["status"] = "tampered"
        fresh = self.verify_batch(self.packet)
        self.assertEqual(
            fresh["items"][0]["report"]["result"]["status"], "accepted"
        )
        # Invalid and unauthenticated items survive the round trip.
        self.assertEqual(
            [item["report"]["status"] for item in fresh["items"]],
            ["verified", "invalid", "unauthenticated"],
        )

    def test_policy_digest_binding(self):
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.packet, policy=make_policy(batch="other"))
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(
                self.packet, policy=make_policy(threshold=3)
            )

    def test_future_moment_is_rejected(self):
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.packet, moment=self.moment - 1)
        # The exact signing moment still verifies.
        self.assertTrue(self.verify_batch(self.packet))

    def test_current_credentials_are_required(self):
        with self.assertRaises(AuthenticationError):
            self.verify_batch(self.packet, ring=make_ring(revoked=(JUDGE,)))
        with self.assertRaises(AuthenticationError):
            self.verify_batch(
                self.packet, ring=make_ring(not_after=self.moment - 1)
            )
        ring_minus_judge = {
            site: entries for site, entries in self.ring.items()
            if site != JUDGE
        }
        with self.assertRaises(AuthenticationError):
            self.verify_batch(self.packet, ring=ring_minus_judge)

    def test_wrong_signature_is_unauthenticated(self):
        data = parse(self.packet)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.verify_batch(compact(data))

    def test_structural_faults_are_invalid(self):
        self.assertRaises(
            InvalidPruneAdjudicationBatchError,
            self.verify_batch, b"nope",
        )
        self.assertRaises(
            InvalidPruneAdjudicationBatchError,
            self.verify_batch, self.packet + b"\n",
        )
        indented = json.dumps(
            parse(self.packet), indent=1, sort_keys=True
        ).encode()
        self.assertRaises(
            InvalidPruneAdjudicationBatchError,
            self.verify_batch, indented,
        )
        data = parse(self.packet)
        del data["payload"]["policyDigest"]
        self.assertRaises(
            InvalidPruneAdjudicationBatchError,
            self.verify_batch, self.resign_outer(data),
        )
        data = parse(self.packet)
        data["payload"]["version"] = 2
        self.assertRaises(
            InvalidPruneAdjudicationBatchError,
            self.verify_batch, self.resign_outer(data),
        )

    def test_duplicate_ids_are_invalid(self):
        data = parse(self.packet)
        data["payload"]["items"][1]["id"] = "ok"
        data["payload"]["items"][1]["report"]["id"] = "ok"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.resign_outer(data))

    def test_report_id_binding_is_checked(self):
        data = parse(self.packet)
        data["payload"]["items"][1]["report"]["id"] = "renamed"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.resign_outer(data))

    def test_report_shape_is_checked(self):
        # A failure must carry a non-empty error and a null result.
        data = parse(self.packet)
        bad_item = data["payload"]["items"][1]
        bad_item["report"]["error"] = ""
        self.assertRaises(
            InvalidPruneAdjudicationBatchError,
            self.verify_batch, self.resign_outer(data),
        )
        data = parse(self.packet)
        data["payload"]["items"][1]["report"]["result"] = {}
        self.assertRaises(
            InvalidPruneAdjudicationBatchError,
            self.verify_batch, self.resign_outer(data),
        )
        # A verified report must carry the full result and a null error.
        data = parse(self.packet)
        data["payload"]["items"][0]["report"]["result"] = None
        self.assertRaises(
            TypeError, self.verify_batch, self.resign_outer(data),
        )
        data = parse(self.packet)
        data["payload"]["items"][0]["report"]["error"] = "surprise"
        self.assertRaises(
            InvalidPruneAdjudicationBatchError,
            self.verify_batch, self.resign_outer(data),
        )

    def test_tampered_reports_are_re_tallied(self):
        # Flip the aggregate status of a verified report.
        data = parse(self.packet)
        data["payload"]["items"][0]["report"]["result"]["status"] = \
            "conflicted"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.resign_outer(data))

        # Tamper the content of the common report.
        data = parse(self.packet)
        data["payload"]["items"][0]["report"]["result"]["report"]["items"][0]["id"] = "renamed"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.resign_outer(data))

        # A verified report whose result disagrees with its own signed
        # rows is caught even when the aggregate status is untouched:
        # point one row at a different attestation digest.
        data = parse(self.packet)
        data["payload"]["items"][0]["report"]["result"]["attestations"][0] = "11" * 32
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.resign_outer(data))

        # Flip a conclusion of one signed row.
        data = parse(self.packet)
        row = data["payload"]["items"][0]["report"]["result"]["items"][0]
        row["conclusion"] = "duplicate"
        row["reason"] = "duplicate"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.resign_outer(data))

        # A packet whose outer policy digest names another policy fails
        # the digest check before the HMAC is even considered.
        other = self.sign_batch(
            [adj_packet("x", self.accepted)],
            policy=make_policy(batch="other-batch"),
        )
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(other)

    def test_bound_digest_must_be_a_digest(self):
        data = parse(self.packet)
        data["payload"]["items"][0]["digest"] = "not-a-digest"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify_batch(self.resign_outer(data))

    def test_below_threshold_and_conflicted_reports_round_trip(self):
        packet = self.sign_batch([
            adj_packet("below", self.below),
            adj_packet("conflicted", self.conflicted),
        ])
        items = self.verify_batch(packet)["items"]
        below, conflicted = items
        self.assertEqual(
            below["report"]["result"]["status"], "insufficient"
        )
        self.assertIsNotNone(below["report"]["result"]["report"])
        self.assertEqual(
            conflicted["report"]["result"]["status"], "conflicted"
        )
        self.assertIsNone(conflicted["report"]["result"]["report"])

    def test_argument_taxonomy(self):
        self.assertRaises(
            TypeError, self.verify_batch, packet="bytes"
        )
        self.assertRaises(
            TypeError, self.verify_batch, self.packet, []
        )
        self.assertRaises(
            TypeError, self.verify_batch, self.packet, self.policy, []
        )
        self.assertRaises(
            TypeError, self.verify_batch, self.packet, self.policy,
            self.ring, True,
        )
        self.assertRaises(
            ValueError, self.verify_batch, self.packet, self.policy,
            self.ring, -1,
        )
        self.assertRaises(ValueError, self.verify_batch, self.packet, {
            "batch": BATCH, "sites": {}, "threshold": 1,
        })

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(
            InvalidPruneAdjudicationBatchError, ValueError
        ))
        self.assertTrue(issubclass(AuthenticationError, ValueError))

    def test_verification_reads_no_file(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.verify_batch(self.packet)


if __name__ == "__main__":
    unittest.main()
