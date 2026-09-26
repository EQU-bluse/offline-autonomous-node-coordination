"""Tests for prune adjudication batch verification and its signed handover.

Covers :func:`verify_prune_adjudications`,
:func:`sign_prune_adjudication_batch` and
:func:`verify_prune_adjudication_batch`: the whole-batch structural
validation before any adjudication is parsed, the isolated per-item
``verified``/``invalid``/``unauthenticated`` outcomes with the fixed
``error``/``id``/``result``/``status`` report shape, the signed
handover package binding issuer, exact key version, moment, policy
digest and the original-order adjudication ids, digests and complete
reports, the verbatim preservation of failed items with no trusted
content filled in, the offline re-verification of order, digest and
report bindings, the future-moment, duplicate-id, tampered-report and
non-canonical-encoding rejections, the error taxonomy, equal-but-
independent return values, input immutability and the purely offline
guarantee.
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
    InvalidPruneAdjudicationBatchError,
    sign_prune_adjudication_batch,
    verify_prune_adjudication,
    verify_prune_adjudication_batch,
    verify_prune_adjudications,
)

from test_fork_convergence import RING, compact, entry, parse
from test_prune_attestations import (
    BATCH,
    JUDGE,
    SITE_A,
    SITE_B,
    PruneAttestationFixtures,
    hmac_hex,
    make_policy,
    make_ring,
    sha256,
)

RELAYER = "relayer"

REPORT_KEYS = ["error", "id", "result", "status"]
BATCH_PACKET_KEYS = ["payload", "signature"]
BATCH_PAYLOAD_KEYS = [
    "issuer", "items", "keyVersion", "moment", "policyDigest", "version",
]
BATCH_ITEM_KEYS = ["digest", "id", "report"]


def relayer_ring(**kwargs):
    sites = kwargs.pop("sites", (SITE_A, SITE_B, JUDGE, RELAYER))
    return make_ring(sites=sites, **kwargs)


class PruneAdjudicationBatchFixtures(PruneAttestationFixtures):
    """Signed prune adjudications shared across the batch test cases."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.ring = relayer_ring()
        self.att_a = self.sign_att(site=SITE_A)
        self.att_b = self.sign_att(site=SITE_B)
        self.accepted = self.decide(
            [self.packet("a", self.att_a), self.packet("b", self.att_b)]
        )
        self.insufficient = self.decide([self.packet("a", self.att_a)])
        # A well-formed packet whose signature does not match.
        flipped = parse(self.accepted)
        flipped["signature"] = (
            "0" if flipped["signature"][0] != "0" else "1"
        ) + flipped["signature"][1:]
        self.bad_signature = compact(flipped)
        self.malformed = b"not-an-adjudication"
        self.batch_items = [
            {"id": "accepted", "adjudication": self.accepted},
            {"id": "insufficient", "adjudication": self.insufficient},
            {"id": "malformed", "adjudication": self.malformed},
            {"id": "bad-signature", "adjudication": self.bad_signature},
        ]

    def verify_batch(self, items=None, **kwargs):
        kwargs.setdefault("policy", self.policy)
        kwargs.setdefault("keyring", self.ring)
        kwargs.setdefault("moment", self.moment)
        return verify_prune_adjudications(
            self.batch_items if items is None else items, **kwargs
        )

    def sign_batch(self, items=None, **kwargs):
        kwargs.setdefault("policy", self.policy)
        kwargs.setdefault("keyring", self.ring)
        kwargs.setdefault("moment", self.moment)
        kwargs.setdefault("issuer", RELAYER)
        kwargs.setdefault("version", 1)
        return sign_prune_adjudication_batch(
            self.batch_items if items is None else items, **kwargs
        )

    def resign(self, data, issuer=RELAYER):
        data["signature"] = hmac_hex(
            self.ring[issuer][0]["secret"], compact(data["payload"])
        )
        return compact(data)


class VerifyPruneAdjudicationsTest(PruneAdjudicationBatchFixtures,
                                   unittest.TestCase):
    def test_mixed_batch_reports_in_input_order(self):
        result = self.verify_batch()
        self.assertEqual(list(result.keys()), ["items", "version"])
        self.assertEqual(result["version"], 1)
        self.assertIsNot(result["version"], True)
        reports = result["items"]
        self.assertEqual(
            [report["id"] for report in reports],
            ["accepted", "insufficient", "malformed", "bad-signature"],
        )
        self.assertEqual(
            [report["status"] for report in reports],
            ["verified", "verified", "invalid", "unauthenticated"],
        )
        for report in reports:
            self.assertEqual(list(report.keys()), REPORT_KEYS)
        for report in reports[:2]:
            self.assertIsNone(report["error"])
            self.assertIsNotNone(report["result"])
        for report in reports[2:]:
            self.assertIsNone(report["result"])
            self.assertIsInstance(report["error"], str)
            self.assertNotEqual(report["error"], "")

    def test_verified_result_matches_the_single_entry_point(self):
        result = self.verify_batch()
        self.assertEqual(
            result["items"][0]["result"],
            verify_prune_adjudication(
                self.accepted, self.policy, self.ring, self.moment
            ),
        )
        # The insufficient adjudication keeps its unique common report.
        insufficient_result = result["items"][1]["result"]
        self.assertEqual(insufficient_result["status"], "insufficient")
        self.assertIsNotNone(insufficient_result["report"])

    def test_one_failure_never_blocks_or_changes_the_others(self):
        alone = self.verify_batch(items=[
            {"id": "accepted", "adjudication": self.accepted},
        ])
        mixed = self.verify_batch()
        self.assertEqual(mixed["items"][0], alone["items"][0])

    def test_whole_batch_structure_is_validated_before_any_parsing(self):
        # The duplicate id is a batch-level fault even though the first
        # item's adjudication bytes are themselves unparseable.
        with self.assertRaises(ValueError):
            self.verify_batch(items=[
                {"id": "dup", "adjudication": b"garbage"},
                {"id": "dup", "adjudication": b"also-garbage"},
            ])

    def test_argument_taxonomy(self):
        good = [{"id": "a", "adjudication": self.accepted}]

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
        expect(TypeError, items=[{"id": "a", "adjudication": "raw"}])
        expect(ValueError, items=[])
        expect(ValueError, items=[{"id": "", "adjudication": self.accepted}])
        expect(ValueError, items=[
            {"id": "dup", "adjudication": self.accepted},
            {"id": "dup", "adjudication": self.insufficient},
        ])
        expect(ValueError, items=[{"id": "a"}])
        expect(ValueError, items=[
            {"id": "a", "adjudication": self.accepted, "extra": 1}
        ])
        expect(TypeError, policy=[])
        expect(ValueError, policy={
            "batch": BATCH, "sites": {}, "threshold": 1,
        })
        expect(TypeError, keyring=[])
        expect(TypeError, moment=True)
        expect(ValueError, moment=-1)

    def test_repeated_calls_are_equal_and_independent(self):
        first = self.verify_batch()
        second = self.verify_batch()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(
            first["items"][0]["result"], second["items"][0]["result"]
        )
        first["items"][0]["result"]["status"] = "tampered"
        self.assertEqual(
            self.verify_batch()["items"][0]["result"]["status"], "accepted"
        )

    def test_no_input_is_modified_and_no_file_is_touched(self):
        items_copy = copy.deepcopy(self.batch_items)
        ring_copy = copy.deepcopy(self.ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.verify_batch()
        self.assertEqual(self.batch_items, items_copy)
        self.assertEqual(self.ring, ring_copy)


class SignPruneAdjudicationBatchTest(PruneAdjudicationBatchFixtures,
                                     unittest.TestCase):
    def test_packet_shape_and_canonical_encoding(self):
        raw = self.sign_batch()
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), BATCH_PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), BATCH_PAYLOAD_KEYS)
        self.assertEqual(payload["issuer"], RELAYER)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], self.moment)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(compact(data), raw)

    def test_items_bind_ids_digests_and_reports_in_input_order(self):
        payload = parse(self.sign_batch())["payload"]
        items = payload["items"]
        self.assertEqual(
            [item["id"] for item in items],
            ["accepted", "insufficient", "malformed", "bad-signature"],
        )
        for item, source in zip(items, self.batch_items):
            self.assertEqual(list(item.keys()), BATCH_ITEM_KEYS)
            self.assertEqual(item["digest"], sha256(source["adjudication"]))
        direct = self.verify_batch()
        self.assertEqual(
            [item["report"] for item in items], direct["items"]
        )

    def test_failed_items_are_preserved_without_trusted_content(self):
        payload = parse(self.sign_batch())["payload"]
        failed = {
            item["id"]: item["report"] for item in payload["items"]
        }["bad-signature"]
        self.assertEqual(failed["status"], "unauthenticated")
        self.assertIsNone(failed["result"])
        self.assertIsInstance(failed["error"], str)
        self.assertNotEqual(failed["error"], "")
        # The verified report binds the complete adjudication payload.
        verified = payload["items"][0]["report"]
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(
            verified["result"], parse(self.accepted)["payload"]
        )

    def test_policy_digest_matches_the_canonical_policy(self):
        payload = parse(self.sign_batch())["payload"]
        canonical_policy = compact({
            "batch": BATCH,
            "sites": {site: [1] for site in sorted((SITE_A, SITE_B, "site-c"))},
            "threshold": 2,
        })
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(canonical_policy).hexdigest(),
        )

    def test_signature_uses_the_exact_issuer_version_key(self):
        raw = self.sign_batch()
        payload = parse(raw)["payload"]
        self.assertEqual(
            parse(raw)["signature"],
            hmac_hex(self.ring[RELAYER][0]["secret"], compact(payload)),
        )
        ring_v2 = {**self.ring, RELAYER: [entry(2, "22" * 32)]}
        with self.assertRaises(AuthenticationError):
            self.sign_batch(keyring=ring_v2)

    def test_credential_states_raise_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.sign_batch(issuer="ghost")
        with self.assertRaises(AuthenticationError):
            self.sign_batch(keyring=relayer_ring(revoked=(RELAYER,)))
        with self.assertRaises(AuthenticationError):
            self.sign_batch(
                keyring=relayer_ring(not_before=self.moment + 1)
            )
        with self.assertRaises(AuthenticationError):
            self.sign_batch(
                keyring=relayer_ring(not_after=self.moment - 1)
            )

    def test_argument_taxonomy(self):
        def expect(exc, **kwargs):
            with self.assertRaises(exc):
                self.sign_batch(**kwargs)

        expect(TypeError, items="not-a-list")
        expect(ValueError, items=[])
        expect(TypeError, items=[{"id": "a", "adjudication": "raw"}])
        expect(ValueError, items=[{"id": "", "adjudication": self.accepted}])
        expect(TypeError, moment=True)
        expect(ValueError, moment=-1)
        expect(TypeError, issuer=5)
        expect(ValueError, issuer="")
        expect(TypeError, version=True)
        expect(TypeError, version="1")
        expect(ValueError, version=0)

    def test_repeated_calls_are_equal(self):
        self.assertEqual(self.sign_batch(), self.sign_batch())

    def test_no_input_is_modified_and_no_file_is_touched(self):
        items_copy = copy.deepcopy(self.batch_items)
        ring_copy = copy.deepcopy(self.ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.sign_batch()
        self.assertEqual(self.batch_items, items_copy)
        self.assertEqual(self.ring, ring_copy)
        self.assertTrue(raw)


class VerifyPruneAdjudicationBatchTest(PruneAdjudicationBatchFixtures,
                                       unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.batch = self.sign_batch()

    def verify(self, raw=None, **kwargs):
        kwargs.setdefault("policy", self.policy)
        kwargs.setdefault("keyring", self.ring)
        kwargs.setdefault("moment", self.moment)
        return verify_prune_adjudication_batch(
            self.batch if raw is None else raw, **kwargs
        )

    def test_success_returns_equal_but_independent_payload(self):
        result = self.verify()
        payload = parse(self.batch)["payload"]
        self.assertEqual(result, payload)
        self.assertIsNot(result, payload)
        again = self.verify()
        self.assertEqual(result, again)
        self.assertIsNot(result["items"], again["items"])
        self.assertIsNot(
            result["items"][0]["report"], again["items"][0]["report"]
        )
        result["items"][0]["report"]["status"] = "tampered"
        self.assertEqual(
            self.verify()["items"][0]["report"]["status"], "verified"
        )

    def test_future_moment_is_rejected(self):
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(moment=self.moment - 1)

    def test_duplicate_item_ids_are_rejected(self):
        data = parse(self.batch)
        first = data["payload"]["items"][0]
        data["payload"]["items"].append(copy.deepcopy(first))
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=self.resign(data))

    def test_tampered_reports_are_rejected(self):
        # A failed item must keep its error and its null result.
        data = parse(self.batch)
        report = data["payload"]["items"][2]["report"]
        self.assertEqual(report["status"], "invalid")
        report["result"] = parse(self.accepted)["payload"]
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=self.resign(data))

        # A verified item must bind a complete adjudication payload.
        data = parse(self.batch)
        data["payload"]["items"][0]["report"]["result"] = {
            "status": "accepted"
        }
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=self.resign(data))

        # A verified item must carry no error.
        data = parse(self.batch)
        data["payload"]["items"][0]["report"]["error"] = "made up"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=self.resign(data))

        # A report id must match its item id.
        data = parse(self.batch)
        data["payload"]["items"][0]["report"]["id"] = "renamed"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=self.resign(data))

        # A bound digest must be a digest.
        data = parse(self.batch)
        data["payload"]["items"][0]["digest"] = "not-a-digest"
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=self.resign(data))

    def test_non_canonical_encoding_is_rejected(self):
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=self.batch + b"\n")
        indented = json.dumps(
            parse(self.batch), indent=1, sort_keys=True
        ).encode()
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=indented)
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(raw=b"nope")

    def test_policy_digest_binding(self):
        with self.assertRaises(InvalidPruneAdjudicationBatchError):
            self.verify(policy=make_policy(batch="other-batch"))

    def test_current_credentials_are_required(self):
        with self.assertRaises(AuthenticationError):
            self.verify(keyring=relayer_ring(revoked=(RELAYER,)))
        with self.assertRaises(AuthenticationError):
            self.verify(
                keyring=relayer_ring(not_after=self.moment - 1)
            )
        ring_minus_relayer = {
            site: entries for site, entries in self.ring.items()
            if site != RELAYER
        }
        with self.assertRaises(AuthenticationError):
            self.verify(keyring=ring_minus_relayer)
        data = parse(self.batch)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.verify(raw=compact(data))

    def test_argument_taxonomy(self):
        self.assertRaises(TypeError, self.verify, raw="bytes")
        self.assertRaises(TypeError, self.verify, policy=[])
        self.assertRaises(TypeError, self.verify, keyring=[])
        self.assertRaises(TypeError, self.verify, moment=True)
        self.assertRaises(ValueError, self.verify, moment=-1)
        self.assertRaises(ValueError, self.verify, policy={
            "batch": BATCH, "sites": {}, "threshold": 1,
        })

    def test_error_hierarchy(self):
        self.assertTrue(
            issubclass(InvalidPruneAdjudicationBatchError, ValueError)
        )
        self.assertTrue(issubclass(AuthenticationError, ValueError))

    def test_verification_reads_no_file(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.verify()


if __name__ == "__main__":
    unittest.main()
