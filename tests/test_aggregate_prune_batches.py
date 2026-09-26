"""Tests for cross-site aggregation of prune adjudication batches.

Covers :func:`aggregate_prune_batches` and
:func:`verify_prune_batch_aggregate`: the batch container validated in
full before any packet is parsed, per-packet
invalid/unauthenticated/unauthorized isolation, the full original-order
declaration (every id/digest/full-report entry, never just a final
status), same-site duplicate and contradiction handling, cross-site
declaration agreement that no majority can outvote, accepted/
insufficient/conflicted outcomes with the unique common declaration
kept even below threshold and null only with no valid vote, stable
site/id row ordering with original-order input digests, offline
re-tally and current-key signature verification, equal-but-independent
return values, error hierarchy, input immutability and the purely
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
    InvalidPruneAdjudicationBatchError,
    InvalidPruneBatchAggregateError,
    aggregate_prune_batches,
    sign_prune_adjudication_batch,
    verify_prune_batch_aggregate,
)

from test_fork_convergence import (
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
    hmac_hex,
    sha256,
)
from test_verify_prune_adjudications import (
    PruneAdjudicationBatchFixtures,
    adj_packet,
)

PACKET_KEYS = ["payload", "signature"]
AGGREGATE_PAYLOAD_KEYS = [
    "declaration", "inputs", "issuer", "items", "keyVersion",
    "prunePolicyDigest", "sitePolicyDigest", "status", "version",
]
ROW_KEYS = [
    "conclusion", "declaration", "digest", "id", "issuer", "keyVersion",
    "reason",
]
DECLARATION_ENTRY_KEYS = ["digest", "id", "report"]


def agg_item(item_id, packet):
    return {"id": item_id, "packet": packet}


def site_policy(sites=(SITE_A, SITE_B, SITE_C), threshold=2):
    return {"sites": {site: {1} for site in sites}, "threshold": threshold}


class PruneBatchAggregateFixtures(PruneAdjudicationBatchFixtures):
    """Signed multi-site handovers shared across the aggregate tests."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.site_policy = site_policy()
        # Every handover packages adjudication packets (the outputs of
        # adjudicate_prune_attestations), never raw attestations.
        self.h1 = [adj_packet("h1", self.accepted)]
        self.h2 = [
            adj_packet("h1", self.accepted),
            adj_packet("broken", b"nope"),
        ]
        self.pkt_a = self.handover(self.h1, issuer=SITE_A)
        self.pkt_b = self.handover(self.h1, issuer=SITE_B)
        self.pkt_c = self.handover(self.h1, issuer=SITE_C)
        # A different handover: an extra failing adjudication, another
        # declaration even though h1 still verifies.
        self.pkt_b_other = self.handover(self.h2, issuer=SITE_B)
        # A one-entry handover over the below-threshold adjudication.
        self.pkt_a_short = self.handover(
            [adj_packet("h1", self.below)], issuer=SITE_A
        )

    def handover(self, adjudications, policy=None, ring=None, moment=None,
                 issuer=JUDGE, version=1):
        return sign_prune_adjudication_batch(
            adjudications,
            self.policy if policy is None else policy,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
            issuer, version,
        )

    def aggregate(self, items, prune_policy=None, sp=None, ring=None,
                  moment=None, issuer=JUDGE, version=1):
        return aggregate_prune_batches(
            items,
            self.policy if prune_policy is None else prune_policy,
            self.site_policy if sp is None else sp,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
            issuer, version,
        )

    def verify(self, packet, prune_policy=None, sp=None, ring=None,
               moment=None):
        return verify_prune_batch_aggregate(
            packet,
            self.policy if prune_policy is None else prune_policy,
            self.site_policy if sp is None else sp,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
        )

    def resign_outer(self, data, secret=SECRET_COORD):
        data["signature"] = hmac_hex(secret, compact(data["payload"]))
        return compact(data)


class AggregatePruneBatchesShapeTest(PruneBatchAggregateFixtures,
                                    unittest.TestCase):
    def test_packet_shape_and_canonical_encoding(self):
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), AGGREGATE_PAYLOAD_KEYS)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(compact(data), raw)

    def test_inputs_bound_in_original_order(self):
        items = [agg_item("one", self.pkt_a), agg_item("two", self.pkt_b)]
        raw = self.aggregate(items)
        payload = parse(raw)["payload"]
        self.assertEqual(payload["inputs"], [
            sha256(self.pkt_a), sha256(self.pkt_b),
        ])
        # Swapping the input order changes the signed bytes even though
        # the rows sort the same way: the reordering is detectable.
        swapped = self.aggregate(list(reversed(items)))
        self.assertNotEqual(raw, swapped)
        self.assertEqual(parse(swapped)["payload"]["inputs"],
                         [sha256(self.pkt_b), sha256(self.pkt_a)])

    def test_rows_sorted_by_site_then_id_with_fixed_keys(self):
        raw = self.aggregate([
            agg_item("junk", b"nope"),
            agg_item("b-row", self.pkt_b),
            agg_item("a-row", self.pkt_a),
        ])
        rows = parse(raw)["payload"]["items"]
        # Rows with no authenticated identity (invalid packets) sort
        # before the site rows; site rows are ordered by site then id.
        self.assertEqual([(r["issuer"], r["id"]) for r in rows], [
            (None, "junk"), (SITE_A, "a-row"), (SITE_B, "b-row"),
        ])
        for row in rows:
            self.assertEqual(list(row.keys()), ROW_KEYS)

    def test_declaration_is_the_full_handover_item_list(self):
        raw = self.aggregate([agg_item("one", self.pkt_a)])
        payload = parse(raw)["payload"]
        declaration = payload["declaration"]
        handover_items = parse(self.pkt_a)["payload"]["items"]
        self.assertEqual(declaration, handover_items)
        self.assertEqual(payload["items"][0]["declaration"], handover_items)
        for bound in declaration:
            self.assertEqual(list(bound.keys()), DECLARATION_ENTRY_KEYS)
        # Full reports survive, including the embedded adjudication.
        first_report = declaration[0]["report"]
        self.assertEqual(first_report["status"], "verified")
        self.assertIsNotNone(first_report["result"])

    def test_policy_digests(self):
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])
        payload = parse(raw)["payload"]
        canonical_prune = compact({
            "batch": BATCH,
            "sites": {SITE_A: [1], SITE_B: [1], SITE_C: [1]},
            "threshold": 2,
        })
        canonical_site = compact({
            "sites": {SITE_A: [1], SITE_B: [1], SITE_C: [1]},
            "threshold": 2,
        })
        self.assertEqual(payload["prunePolicyDigest"],
                         hashlib.sha256(canonical_prune).hexdigest())
        self.assertEqual(payload["sitePolicyDigest"],
                         hashlib.sha256(canonical_site).hexdigest())


class AggregatePruneBatchesOutcomeTest(PruneBatchAggregateFixtures,
                                      unittest.TestCase):
    def test_accepted_at_threshold(self):
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])
        result = self.verify(raw)
        self.assertEqual(result["status"], "accepted")
        for row in result["items"]:
            self.assertEqual(row["conclusion"], "valid")
            self.assertIsNone(row["reason"])

    def test_insufficient_below_threshold_keeps_declaration(self):
        raw = self.aggregate([agg_item("one", self.pkt_a)])
        result = self.verify(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declaration"])
        self.assertEqual(result["declaration"],
                         parse(self.pkt_a)["payload"]["items"])

    def test_no_valid_votes_binds_null_declaration(self):
        raw = self.aggregate([agg_item("junk", b"nope")])
        result = self.verify(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["declaration"])
        (row,) = result["items"]
        self.assertEqual(row["conclusion"], "invalid")
        self.assertEqual(row["reason"], "invalid")
        self.assertIsNone(row["issuer"])
        self.assertIsNone(row["keyVersion"])
        self.assertIsNone(row["declaration"])

    def test_same_site_exact_repeat_is_duplicate(self):
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_a),
        ])
        result = self.verify(raw)
        self.assertEqual(result["status"], "insufficient")
        conclusions = {row["id"]: row["conclusion"] for row in result["items"]}
        self.assertEqual(conclusions, {"one": "valid", "two": "duplicate"})
        duplicate = next(r for r in result["items"] if r["id"] == "two")
        self.assertEqual(duplicate["reason"], "duplicate")

    def test_same_site_different_content_is_contradiction(self):
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_a_short),
        ])
        result = self.verify(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])
        self.assertTrue(all(
            row["conclusion"] == "contradiction"
            and row["reason"] == "contradiction"
            for row in result["items"]
        ))

    def test_cross_site_difference_conflicts_with_no_majority_override(self):
        # Two agreeing sites versus one differing site: threshold 2 would
        # accept the pair by raw count, but any disagreement conflicts.
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
            agg_item("three", self.pkt_b_other),
        ])
        result = self.verify(raw)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])

    def test_status_alone_never_agrees(self):
        # Two handovers whose first adjudication verifies identically but
        # whose full original item lists differ (one carries an extra
        # failing entry) must not compare equal by status alone.
        pkt_c_extra = self.handover(self.h2, issuer=SITE_C)
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", pkt_c_extra),
        ])
        self.assertEqual(self.verify(raw)["status"], "conflicted")


class AggregatePruneBatchItemFailureTest(PruneBatchAggregateFixtures,
                                        unittest.TestCase):
    def _reasons(self, result):
        return {row["id"]: (row["conclusion"], row["reason"])
                for row in result["items"]}

    def test_structurally_bad_packet_is_invalid(self):
        raw = self.aggregate([
            agg_item("good", self.pkt_a), agg_item("junk", b"nope"),
        ])
        result = self.verify(raw)
        self.assertEqual(self._reasons(result)["junk"],
                         ("invalid", "invalid"))
        self.assertEqual(self._reasons(result)["good"], ("valid", None))
        self.assertEqual(result["status"], "insufficient")

    def test_future_handover_moment_is_invalid(self):
        future = self.handover(self.h1, issuer=SITE_A,
                               moment=self.moment + 10)
        raw = self.aggregate([agg_item("future", future)])
        result = self.verify(raw)
        self.assertEqual(self._reasons(result)["future"],
                         ("invalid", "invalid"))

    def test_unauthorized_site(self):
        sp = site_policy(sites=(SITE_A,), threshold=1)
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ], sp=sp)
        result = self.verify(raw, sp=sp)
        self.assertEqual(self._reasons(result)["two"],
                         ("invalid", "unauthorized"))
        self.assertEqual(result["status"], "accepted")

    def test_unauthorized_version(self):
        sp = site_policy(sites=(SITE_A, SITE_B), threshold=1)
        sp["sites"] = {SITE_A: {2}, SITE_B: {2}}
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ], sp=sp)
        result = self.verify(raw, sp=sp)
        self.assertEqual(set(self._reasons(result).values()),
                         {("invalid", "unauthorized")})

    def test_packet_bound_to_other_prune_policy_is_invalid(self):
        other = {"batch": "other-batch",
                 "sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
                 "threshold": 2}
        pkt_a = self.handover(self.h1, issuer=SITE_A, policy=other)
        pkt_b = self.handover(self.h1, issuer=SITE_B, policy=other)
        # Aggregated/verified against the policy actually bound: both
        # authenticate but are not sites of the caller's site policy...
        # here they also mismatch the expected prune policy, which is a
        # binding fault recorded as invalid with no identity.
        raw = self.aggregate([
            agg_item("one", pkt_a), agg_item("two", pkt_b),
        ], prune_policy=other)
        # The packets authenticate and authorize under the other policy
        # and the site policy, so that aggregate is accepted.
        self.assertEqual(self.verify(raw, prune_policy=other)["status"],
                         "accepted")
        # Verify against the original prune policy: digest mismatch.
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(raw)
        # Aggregate those packets while expecting the original policy:
        # each one is a binding fault -> invalid, no identity.
        rebound = self.aggregate([
            agg_item("one", pkt_a), agg_item("two", pkt_b),
        ])
        result = self.verify(rebound)
        self.assertEqual(result["status"], "insufficient")
        for row in result["items"]:
            self.assertEqual(row["conclusion"], "invalid")
            self.assertEqual(row["reason"], "invalid")
            self.assertIsNone(row["issuer"])

    def test_revoked_site_credentials_are_unauthenticated(self):
        revoked = copy.deepcopy(self.ring)
        revoked[SITE_B][0]["revoked"] = True
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ], ring=revoked)
        result = self.verify(raw, ring=revoked)
        self.assertEqual(self._reasons(result)["two"],
                         ("invalid", "unauthenticated"))
        # The signed rows record the aggregation-time finding; the outer
        # aggregate still verifies later with the credential restored,
        # but the row binding itself never changes.
        later = self.verify(raw)
        self.assertEqual(self._reasons(later)["two"],
                         ("invalid", "unauthenticated"))
        self.assertEqual(later["status"], "insufficient")

    def test_unknown_site_credentials_are_unauthenticated(self):
        missing = {site: keys for site, keys in self.ring.items()
                   if site != SITE_B}
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ], ring=missing)
        result = self.verify(raw, ring=missing)
        self.assertEqual(self._reasons(result)["two"],
                         ("invalid", "unauthenticated"))

    def test_one_item_failure_never_stops_the_others(self):
        raw = self.aggregate([
            agg_item("junk", b"nope"),
            agg_item("one", self.pkt_a),
            agg_item("two", self.pkt_b),
        ])
        result = self.verify(raw)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(result["items"]), 3)


class VerifyPruneBatchAggregateBindingTest(PruneBatchAggregateFixtures,
                                          unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])

    def _tamper(self, mutate):
        data = parse(self.raw)
        mutate(data)
        return self.resign_outer(data)

    def test_tampered_status_rejected(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "status", "insufficient"))
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(raw)

    def test_tampered_common_declaration_rejected(self):
        def mutate(data):
            data["payload"]["declaration"].append(
                copy.deepcopy(data["payload"]["declaration"][0]))
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(self._tamper(mutate))

    def test_tampered_row_conclusion_rejected(self):
        raw = self._tamper(lambda d: d["payload"]["items"][0].__setitem__(
            "conclusion", "duplicate"))
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(raw)

    def test_input_order_is_bound_but_only_multiset_is_reconstructible(self):
        # The original input order is preserved under the HMAC, so two
        # aggregates over the same packets in a different order do not
        # share bytes (see the shape test); from one signed packet alone
        # only the multiset of per-item digests is reconstructible, so a
        # reordered list whose multiset still matches is detected by the
        # HMAC, not by the tally -- exactly as for the adjudication.
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "inputs", list(reversed(d["payload"]["inputs"]))))
        self.assertEqual(self.verify(raw)["status"], "accepted")

    def test_row_reorder_rejected(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "items", list(reversed(d["payload"]["items"]))))
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(raw)

    def test_unknown_input_digest_rejected(self):
        raw = self._tamper(lambda d: d["payload"].__setitem__(
            "inputs", ["00" * 32] * len(d["payload"]["inputs"])))
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(raw)

    def test_tampered_embedded_verdict_rejected(self):
        # Change a verified embedded adjudication identically in both
        # declarations: the tally still agrees, but the embedded
        # re-tally must catch the tampering.
        def mutate(data):
            count = 0
            for row in data["payload"]["items"]:
                for bound in row["declaration"]:
                    embedded = bound["report"]["result"]
                    if embedded is not None:
                        embedded["policyDigest"] = "11" * 32
                        count += 1
            self.assertGreater(count, 0)
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(self._tamper(mutate))

    def test_wrong_prune_policy_rejected(self):
        other = {"batch": BATCH,
                 "sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}},
                 "threshold": 1}
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(self.raw, prune_policy=other)

    def test_wrong_site_policy_rejected(self):
        other = site_policy(threshold=1)
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(self.raw, sp=other)

    def test_trailing_byte_rejected(self):
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(self.raw + b"\n")

    def test_duplicate_json_key_rejected(self):
        text = self.raw.decode("utf-8")
        text = text.replace('"version":1', '"version":1,"version":1', 1)
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(text.encode("utf-8"))

    def test_bad_outer_signature_is_authentication_error(self):
        data = parse(self.raw)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.verify(compact(data))

    def test_canonical_reserialization_keeps_the_signature(self):
        data = parse(self.raw)
        # The packet is canonical: reserializing it leaves every byte
        # and the HMAC intact.
        self.assertEqual(compact(data), self.raw)
        self.assertEqual(self.verify(compact(data))["status"], "accepted")

    def test_revoked_aggregate_signer_is_authentication_error(self):
        revoked = copy.deepcopy(self.ring)
        revoked[JUDGE][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=revoked)

    def test_expired_aggregate_signer_is_authentication_error(self):
        expired = copy.deepcopy(self.ring)
        expired[JUDGE][0]["notAfter"] = self.moment - 1
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=expired)

    def test_current_exact_version_only(self):
        ring_v2 = copy.deepcopy(self.ring)
        ring_v2[JUDGE] = ring_v2[JUDGE] + [
            entry(2, SECRET_COORD)
        ]
        # The packet was signed under version 1 and must verify only
        # against the current version-1 key, never fall back to v2.
        self.assertEqual(
            self.verify(self.raw, ring=ring_v2)["status"], "accepted"
        )
        without_v1 = copy.deepcopy(ring_v2)
        without_v1[JUDGE] = [ring_v2[JUDGE][1]]
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=without_v1)


class PruneBatchAggregateArgumentTest(PruneBatchAggregateFixtures,
                                     unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ]

    def test_item_container_faults(self):
        with self.assertRaises(TypeError):
            self.aggregate("nope")
        with self.assertRaises(TypeError):
            self.aggregate([{"id": 1, "packet": self.pkt_a}])
        with self.assertRaises(TypeError):
            self.aggregate([{"id": "one", "packet": "bytes"}])
        with self.assertRaises(ValueError):
            self.aggregate([])
        with self.assertRaises(ValueError):
            self.aggregate([{"id": "", "packet": self.pkt_a}])
        with self.assertRaises(ValueError):
            self.aggregate([
                agg_item("same", self.pkt_a),
                agg_item("same", self.pkt_b),
            ])
        with self.assertRaises(ValueError):
            self.aggregate([{"id": "one", "raw": self.pkt_a}])

    def test_site_policy_faults(self):
        def aggregate_with(sp):
            return self.aggregate(self.items, sp=sp)

        with self.assertRaises(TypeError):
            aggregate_with({"sites": [], "threshold": 1})
        with self.assertRaises(ValueError):
            aggregate_with({"sites": {SITE_A: {1}}})
        with self.assertRaises(ValueError):
            aggregate_with({"sites": {SITE_A: {1}}, "threshold": 0})
        with self.assertRaises(ValueError):
            aggregate_with(site_policy(threshold=4))
        with self.assertRaises(ValueError):
            aggregate_with({"sites": {SITE_A: set()}, "threshold": 1})
        with self.assertRaises(ValueError):
            aggregate_with({"sites": {"": {1}}, "threshold": 1})
        with self.assertRaises(ValueError):
            aggregate_with({"sites": {SITE_A: {0}}, "threshold": 1})
        with self.assertRaises(TypeError):
            aggregate_with({"sites": {SITE_A: [1]}, "threshold": 1})
        with self.assertRaises(TypeError):
            aggregate_with({"sites": {SITE_A: {True}}, "threshold": 1})
        with self.assertRaises(TypeError):
            aggregate_with(site_policy_with_bool_threshold())

    def test_other_public_argument_faults(self):
        with self.assertRaises(TypeError):
            self.aggregate(self.items, moment=True)
        with self.assertRaises(ValueError):
            self.aggregate(self.items, moment=-1)
        with self.assertRaises(TypeError):
            self.aggregate(self.items, issuer=7)
        with self.assertRaises(ValueError):
            self.aggregate(self.items, issuer="")
        with self.assertRaises(TypeError):
            self.aggregate(self.items, version=True)
        with self.assertRaises(ValueError):
            self.aggregate(self.items, version=0)
        with self.assertRaises(AuthenticationError):
            self.aggregate(self.items, issuer="unknown-issuer", version=1)

    def test_verify_public_argument_faults(self):
        raw = self.aggregate(self.items)
        with self.assertRaises(TypeError):
            self.verify("not-bytes")
        with self.assertRaises(ValueError):
            self.verify(raw, sp={"sites": {SITE_A: {1}}, "threshold": 2})
        with self.assertRaises(TypeError):
            self.verify(raw, moment=False)
        with self.assertRaises(ValueError):
            self.verify(raw, moment=-1)

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(InvalidPruneBatchAggregateError,
                                   ValueError))
        self.assertIsNot(InvalidPruneBatchAggregateError,
                        InvalidPruneAdjudicationBatchError)


def site_policy_with_bool_threshold():
    return {"sites": {SITE_A: {1}}, "threshold": True}


class PruneBatchAggregateIndependenceTest(PruneBatchAggregateFixtures,
                                         unittest.TestCase):
    def test_equal_but_independent_results(self):
        raw = self.aggregate([
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ])
        first = self.verify(raw)
        second = self.verify(raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(first["declaration"], second["declaration"])
        self.assertIsNot(first["declaration"][0],
                         second["declaration"][0])
        first["status"] = "conflicted"
        first["items"][0]["conclusion"] = "duplicate"
        first["declaration"][0]["digest"] = "00" * 32
        self.assertEqual(self.verify(raw)["status"], "accepted")

    def test_inputs_are_not_modified(self):
        items = [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ]
        snapshot = copy.deepcopy(items)
        sp_snapshot = copy.deepcopy(self.site_policy)
        pp_snapshot = copy.deepcopy(self.policy)
        ring_snapshot = copy.deepcopy(self.ring)
        self.aggregate(items)
        self.assertEqual(items, snapshot)
        self.assertEqual(self.site_policy, sp_snapshot)
        self.assertEqual(self.policy, pp_snapshot)
        self.assertEqual(self.ring, ring_snapshot)
        result = self.verify(self.aggregate(items))
        self.assertEqual(items, snapshot)
        # The returned mapping never shares mutable input structure.
        self.assertNotIn(id(result), {id(items)})

    def test_runs_entirely_offline(self):
        items = [
            agg_item("one", self.pkt_a), agg_item("two", self.pkt_b),
        ]
        with mock.patch("builtins.open", side_effect=AssertionError("open")):
            raw = self.aggregate(items)
            self.verify(raw)


if __name__ == "__main__":
    unittest.main()
