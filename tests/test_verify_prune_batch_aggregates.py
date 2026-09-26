"""Tests for cross-site aggregation of signed prune handover batches.

Covers :func:`aggregate_prune_batches` and
:func:`verify_prune_batch_aggregate`: the item container and both
policies validated in full before any batch is parsed, the per-packet
invalid/unauthenticated/unauthorized taxonomy with no cross-packet
interference, site statements compared as complete original-order
verdict summaries rather than final statuses, same-site duplicate and
contradiction markings, cross-site statement agreement that no majority
can outvote, the accepted/insufficient/conflicted outcomes with the
unique common declaration kept below threshold and present only with a
valid vote, stable site/id row ordering with input-order batch digests
that make reorderings detectable, canonical signing with exact
aggregator credentials, offline re-tally, digest and declaration
binding checks, the InvalidPruneBatchAggregateError hierarchy,
equal-but-independent return values, input immutability and the purely
offline guarantee.
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
    InvalidPruneBatchAggregateError,
    aggregate_prune_batches,
    verify_prune_batch_aggregate,
)

from test_verify_prune_adjudications import (
    PruneAdjudicationBatchFixtures,
    adj_packet,
)
from test_fork_convergence import SECRET_COORD, compact, entry, parse
from test_prune_attestations import (
    JUDGE,
    SITE_A,
    SITE_B,
    SITE_C,
    hmac_hex,
    make_policy,
    make_ring,
)

AGGREGATOR = JUDGE
SECRET = SECRET_COORD

PACKET_KEYS = ["payload", "signature"]
AGGREGATE_PAYLOAD_KEYS = [
    "attestations", "issuer", "items", "keyVersion", "policyDigest",
    "prunePolicyDigest", "report", "status", "version",
]
ROW_KEYS = ["conclusion", "digest", "id", "keyVersion", "site",
            "statement"]
SUMMARY_KEYS = ["digest", "id", "report"]


def batch_item(item_id, raw):
    """One :func:`aggregate_prune_batches` input item."""
    return {"id": item_id, "batch": raw}


def prune_policy(base=None, sites=None, threshold=2, action="isolate"):
    return {
        "action": action,
        "base": make_policy() if base is None else base,
        "sites": {SITE_A: {1}, SITE_B: {1}, SITE_C: {1}}
        if sites is None else sites,
        "threshold": threshold,
    }


def site_policy(sites=None, threshold=2):
    return {
        "sites": {SITE_A: {1}, SITE_B: {1}, JUDGE: {1}}
        if sites is None else sites,
        "threshold": threshold,
    }


class PruneBatchAggregateFixtures(PruneAdjudicationBatchFixtures,
                                 unittest.TestCase):
    """Signed handover batches from distinct sites shared by the tests."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.prune_policy = prune_policy(base=self.policy)
        self.site_policy = site_policy()
        self.hand_a = self.sign_batch(
            [adj_packet("h1", self.accepted)], issuer=SITE_A
        )
        self.hand_b = self.sign_batch(
            [adj_packet("h1", self.accepted)], issuer=SITE_B
        )
        self.hand_judge = self.sign_batch(
            [adj_packet("h1", self.accepted)], issuer=JUDGE
        )
        self.below_judge = self.sign_batch(
            [adj_packet("h2", self.below)], issuer=JUDGE
        )
        # A handover packet whose one adjudication is structurally bad.
        self.bad_judge = self.sign_batch(
            [adj_packet("bad", b"nope")], issuer=JUDGE
        )

    def aggregate(self, items, prune=None, sites=None, ring=None,
                  moment=None, issuer=AGGREGATOR, version=1):
        return aggregate_prune_batches(
            items,
            self.prune_policy if prune is None else prune,
            self.site_policy if sites is None else sites,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
            issuer, version,
        )

    def verify(self, packet, prune=None, sites=None, ring=None,
               moment=None):
        return verify_prune_batch_aggregate(
            packet,
            self.prune_policy if prune is None else prune,
            self.site_policy if sites is None else sites,
            self.ring if ring is None else ring,
            self.moment if moment is None else moment,
        )

    def resign(self, data, secret=None):
        data["signature"] = hmac_hex(
            SECRET if secret is None else secret,
            compact(data["payload"]),
        )
        return compact(data)

    def agreed_pair(self):
        return [
            batch_item("one", self.hand_a),
            batch_item("two", self.hand_b),
        ]


class AggregatePruneBatchesTest(PruneBatchAggregateFixtures):
    def test_packet_shape_and_canonical_encoding(self):
        raw = self.aggregate(self.agreed_pair())
        self.assertFalse(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b" "))
        data = parse(raw)
        self.assertEqual(list(data.keys()), PACKET_KEYS)
        payload = data["payload"]
        self.assertEqual(list(payload.keys()), AGGREGATE_PAYLOAD_KEYS)
        self.assertEqual(payload["issuer"], AGGREGATOR)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["version"], 1)
        self.assertIsNot(payload["version"], True)
        self.assertEqual(compact(data), raw)
        # Both policy digests are bound independently.
        from offline_coordination.replication import (
            _aggregate_site_policy_bytes,
            _fork_policy_bytes,
            _validated_aggregate_site_policy,
            _validated_fork_policy,
        )
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(
                _aggregate_site_policy_bytes(
                    _validated_aggregate_site_policy(self.site_policy)
                )
            ).hexdigest(),
        )
        self.assertEqual(
            payload["prunePolicyDigest"],
            hashlib.sha256(
                _fork_policy_bytes(
                    _validated_fork_policy(self.prune_policy)
                )
            ).hexdigest(),
        )

    def test_rows_and_input_order_digests(self):
        items = [
            batch_item("ok", self.hand_a),
            batch_item("broken", b"nope"),
            batch_item("also", self.hand_b),
        ]
        raw = self.aggregate(items)
        payload = parse(raw)["payload"]
        # The digest list preserves the exact input order ...
        self.assertEqual(
            payload["attestations"],
            [hashlib.sha256(item["batch"]).hexdigest() for item in items],
        )
        # ... while rows are sorted stably by site then id, with the
        # sited rows before the identity-less invalid row.
        rows = payload["items"]
        self.assertEqual(
            [(row["site"], row["id"]) for row in rows],
            [(None, "broken"), (SITE_A, "ok"), (SITE_B, "also")],
        )
        for row in rows:
            self.assertEqual(list(row.keys()), ROW_KEYS)

    def test_counted_rows_bind_their_full_statement(self):
        raw = self.aggregate([
            batch_item("ok", self.hand_judge),
            batch_item("again", self.hand_judge),
        ], sites=site_policy(sites={JUDGE: {1}}, threshold=1))
        rows = parse(raw)["payload"]["items"]
        expected = parse(self.hand_judge)["payload"]["items"]
        for row in rows:
            self.assertEqual(row["statement"], expected)
            for summary in row["statement"]:
                self.assertEqual(list(summary.keys()), SUMMARY_KEYS)

    def test_per_packet_taxonomy(self):
        # Garbage names no identity.
        garbage = batch_item("garbage", b"nope")
        # A packet bound to another adjudication policy fails the
        # existing handover verification under this prune policy: a
        # binding fault, not an authorization decision.
        other_base = make_policy(batch="other-batch")
        foreign = self.sign_batch(
            [adj_packet("h1", self.accepted)],
            policy=other_base,
        )
        foreign_item = batch_item("foreign", foreign)
        # A wrong HMAC names its site but never authenticates.
        tampered_data = parse(self.hand_a)
        tampered_data["signature"] = "00" * 32
        bad_sig = batch_item("badsig", compact(tampered_data))
        # An authorized, fully valid packet.
        good = batch_item("good", self.hand_a)
        # The same issuer but not named by the site policy.
        ghost = batch_item("ghost", self.hand_judge)

        # JUDGE is missing from the site policy: the judge packet is
        # unauthorized, the foreign policy packet is invalid, and the
        # site-a packets authenticate normally.
        local_sites = site_policy(sites={SITE_A: {1}, SITE_B: {1}})
        raw = self.aggregate(
            [garbage, foreign_item, bad_sig, good, ghost],
            sites=local_sites,
        )
        rows = {row["id"]: row for row in parse(raw)["payload"]["items"]}
        self.assertEqual(rows["garbage"]["conclusion"], "invalid")
        self.assertIsNone(rows["garbage"]["site"])
        self.assertIsNone(rows["garbage"]["keyVersion"])
        self.assertIsNone(rows["garbage"]["statement"])
        self.assertEqual(rows["foreign"]["conclusion"], "invalid")
        self.assertIsNone(rows["foreign"]["site"])
        self.assertEqual(rows["badsig"]["conclusion"], "unauthenticated")
        self.assertEqual(rows["badsig"]["site"], SITE_A)
        self.assertEqual(rows["badsig"]["keyVersion"], 1)
        self.assertIsNone(rows["badsig"]["statement"])
        self.assertEqual(rows["good"]["conclusion"], "valid")
        self.assertEqual(rows["good"]["site"], SITE_A)
        self.assertEqual(rows["ghost"]["conclusion"], "unauthorized")
        self.assertEqual(rows["ghost"]["site"], JUDGE)
        self.assertEqual(rows["ghost"]["keyVersion"], 1)
        self.assertIsNone(rows["ghost"]["statement"])

    def test_unauthorized_key_version_is_precise(self):
        raw = self.aggregate(
            [batch_item("x", self.hand_judge)],
            sites=site_policy(sites={JUDGE: {2}}, threshold=1),
        )
        row = parse(raw)["payload"]["items"][0]
        self.assertEqual(row["conclusion"], "unauthorized")
        self.assertEqual(row["keyVersion"], 1)

    def test_expired_current_credentials_are_unauthenticated(self):
        # Site A's handover key has expired while the aggregator key
        # stays usable, so only the one packet is unauthenticated.
        expired_ring = {
            **self.ring,
            SITE_A: [entry(1, SECRET_COORD, not_after=self.moment - 1)],
        }
        raw = self.aggregate(
            [batch_item("x", self.hand_a),
             batch_item("ok", self.hand_b)],
            ring=expired_ring,
        )
        rows = {row["id"]: row for row in parse(raw)["payload"]["items"]}
        self.assertEqual(rows["x"]["conclusion"], "unauthenticated")
        self.assertEqual(rows["x"]["site"], SITE_A)
        self.assertEqual(rows["ok"]["conclusion"], "valid")

    def test_one_packet_failure_never_blocks_the_others(self):
        raw = self.aggregate([
            batch_item("bad", b"nope"),
            batch_item("ok", self.hand_a),
            batch_item("alsobad", b'{"payload": {}'),
            batch_item("ok2", self.hand_b),
        ])
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(
            [row["conclusion"] for row in payload["items"]
             if row["site"] is not None],
            ["valid", "valid"],
        )

    def test_same_site_duplicate_counts_once(self):
        raw = self.aggregate(
            [batch_item("first", self.hand_judge),
             batch_item("second", self.hand_judge)],
            sites=site_policy(sites={JUDGE: {1}}, threshold=1),
        )
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "accepted")
        conclusions = {row["id"]: row["conclusion"]
                       for row in payload["items"]}
        self.assertEqual(conclusions, {"first": "valid", "second": "duplicate"})
        for row in payload["items"]:
            self.assertIsNotNone(row["statement"])

    def test_same_site_differing_statements_contradict(self):
        raw = self.aggregate(
            [batch_item("aa", self.hand_judge),
             batch_item("bb", self.below_judge),
             batch_item("cc", self.hand_judge)],
            sites=site_policy(sites={JUDGE: {1}}, threshold=1),
        )
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["report"])
        conclusions = {row["id"]: row["conclusion"]
                       for row in payload["items"]}
        # Each distinct statement group's smallest id contradicts; the
        # exact repeat of the first group is a duplicate.
        self.assertEqual(conclusions["aa"], "contradiction")
        self.assertEqual(conclusions["bb"], "contradiction")
        self.assertEqual(conclusions["cc"], "duplicate")

    def test_cross_site_agreement_is_accepted(self):
        raw = self.aggregate(self.agreed_pair())
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "accepted")
        self.assertIsNotNone(payload["report"])
        expected = parse(self.hand_a)["payload"]["items"]
        self.assertEqual(payload["report"]["items"], expected)
        self.assertEqual(payload["report"]["version"], 1)

    def test_cross_site_disagreement_is_conflicted_without_majority(self):
        # Both packets ultimately carry accepted adjudications but their
        # verdict summaries differ (different item id): final statuses
        # agree, statements do not.
        hand_b_other = self.sign_batch(
            [adj_packet("h2", self.accepted)], issuer=SITE_B
        )
        raw = self.aggregate([
            batch_item("a", self.hand_a),
            batch_item("b", hand_b_other),
        ])
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["report"])
        self.assertEqual(
            sorted(row["site"] for row in payload["items"]
                   if row["conclusion"] == "valid"),
            [SITE_A, SITE_B],
        )

    def test_below_threshold_keeps_the_unique_declaration(self):
        raw = self.aggregate(
            [batch_item("a", self.hand_a), batch_item("bad", b"nope")],
            sites=site_policy(threshold=3),
        )
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNotNone(payload["report"])
        self.assertEqual(
            payload["report"]["items"],
            parse(self.hand_a)["payload"]["items"],
        )

    def test_no_valid_vote_binds_a_null_declaration(self):
        raw = self.aggregate(
            [batch_item("bad", b"nope")],
            sites=site_policy(sites={JUDGE: {1}}, threshold=1),
        )
        payload = parse(raw)["payload"]
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNone(payload["report"])

    def test_reordering_changes_the_packet_not_the_sorted_rows(self):
        first = self.aggregate(self.agreed_pair())
        second = self.aggregate(list(reversed(self.agreed_pair())))
        self.assertNotEqual(first, second)
        # Rows are sorted identically; only the input-order digest list
        # exposes the different arrangement.
        self.assertEqual(
            parse(first)["payload"]["items"],
            parse(second)["payload"]["items"],
        )
        self.assertNotEqual(
            parse(first)["payload"]["attestations"],
            parse(second)["payload"]["attestations"],
        )

    def test_exact_aggregator_credentials_sign(self):
        raw = self.aggregate([batch_item("a", self.hand_a)],
                             sites=site_policy(sites={SITE_A: {1}},
                                               threshold=1))
        data = parse(raw)
        self.assertEqual(data["signature"],
                         hmac_hex(SECRET_COORD, compact(data["payload"])))
        ring_v2 = make_ring()
        ring_v2[JUDGE] = [self.ring[JUDGE][0].copy()]
        ring_v2[JUDGE][0]["version"] = 2
        ring_v2[JUDGE][0]["secret"] = "22" * 32
        with self.assertRaises(AuthenticationError):
            self.aggregate(
                [batch_item("a", self.hand_a)], ring=ring_v2,
                sites=site_policy(sites={SITE_A: {1}}, threshold=1),
            )

    def test_aggregator_credential_states_raise(self):
        items = [batch_item("a", self.hand_a)]
        sites = site_policy(sites={SITE_A: {1}}, threshold=1)
        with self.assertRaises(AuthenticationError):
            self.aggregate(items, issuer="ghost", sites=sites)
        with self.assertRaises(AuthenticationError):
            self.aggregate(items, ring=make_ring(revoked=(JUDGE,)),
                           sites=sites)
        with self.assertRaises(AuthenticationError):
            self.aggregate(items, ring=make_ring(not_before=self.moment + 1),
                           sites=sites)
        with self.assertRaises(AuthenticationError):
            self.aggregate(items, ring=make_ring(not_after=self.moment - 1),
                           sites=sites)

    def test_type_and_value_taxonomy(self):
        good = [batch_item("a", self.hand_a)]
        sites = site_policy(sites={SITE_A: {1}}, threshold=1)

        def aggregate(**kwargs):
            kwargs.setdefault("items", good)
            kwargs.setdefault("prune_policy", self.prune_policy)
            kwargs.setdefault("site_policy", sites)
            kwargs.setdefault("keyring", self.ring)
            kwargs.setdefault("moment", self.moment)
            kwargs.setdefault("issuer", AGGREGATOR)
            kwargs.setdefault("version", 1)
            return aggregate_prune_batches(**kwargs)

        def expect(exc, **kwargs):
            with self.assertRaises(exc):
                aggregate(**kwargs)

        expect(TypeError, items=tuple(good))
        expect(TypeError, items=["x"])
        expect(TypeError, items=[{"id": 1, "batch": self.hand_a}])
        expect(TypeError, items=[{"id": "x", "batch": "raw"}])
        expect(ValueError, items=[])
        expect(ValueError, items=[batch_item("", self.hand_a)])
        expect(ValueError,
               items=[batch_item("dup", self.hand_a),
                      batch_item("dup", self.hand_a)])
        expect(ValueError, items=[{"id": "x"}])
        expect(TypeError, prune_policy=[])
        expect(ValueError, prune_policy={**self.prune_policy, "action": "bogus"})
        expect(ValueError, prune_policy={
            "action": "isolate", "base": self.policy,
            "sites": {SITE_A: {1}}, "threshold": 2,
        })
        expect(TypeError, prune_policy={
            "action": "isolate",
            "base": {**self.policy,
                     "sites": {SITE_A: [1], SITE_B: {1}, SITE_C: {1}}},
            "sites": {SITE_A: {1}}, "threshold": 1,
        })
        expect(TypeError, site_policy=[])
        expect(ValueError, site_policy={"threshold": 1})
        expect(TypeError,
               sites={"sites": {SITE_A: [1]}, "threshold": 1})
        expect(ValueError,
               site_policy={"sites": {}, "threshold": 1})
        expect(ValueError,
               site_policy={"sites": {SITE_A: {1}}, "threshold": 2})
        expect(TypeError,
               sites={"sites": {SITE_A: {True}}, "threshold": 1})
        expect(ValueError,
               site_policy={"sites": {SITE_A: {0}}, "threshold": 1})
        expect(TypeError,
               sites={"sites": {SITE_A: {1}}, "threshold": True})
        expect(ValueError,
               site_policy={"sites": {SITE_A: {1}}, "threshold": 0})
        expect(TypeError, keyring=[])
        expect(TypeError, moment=True)
        expect(ValueError, moment=-1)
        expect(TypeError, issuer=9)
        expect(ValueError, issuer="")
        expect(TypeError, version=True)
        expect(TypeError, version="1")
        expect(ValueError, version=0)

    def test_structure_is_validated_before_any_packet_is_parsed(self):
        sites = site_policy(sites={JUDGE: {1}}, threshold=1)
        with self.assertRaises(ValueError):
            self.aggregate(
                [batch_item("a", b"nope"), batch_item("", b"nope")],
                sites=sites,
            )
        with self.assertRaises(ValueError):
            self.aggregate(
                [batch_item("dup", b"nope"), batch_item("dup", b"nope")],
                sites=sites,
            )
        with self.assertRaises(ValueError):
            self.aggregate([{"id": "a"}], sites=sites)

    def test_repeated_calls_are_equal_and_independent(self):
        items = self.agreed_pair()
        first = self.aggregate(items)
        second = self.aggregate(items)
        self.assertEqual(first, second)
        parsed = parse(first)
        parsed["payload"]["status"] = "x"
        self.assertEqual(
            parse(second)["payload"]["status"], "accepted"
        )

    def test_no_input_is_modified_and_no_file_is_touched(self):
        items = [
            batch_item("ok", self.hand_a),
            batch_item("bad", b"nope"),
        ]
        items_copy = copy.deepcopy(items)
        ring_copy = copy.deepcopy(self.ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.aggregate(items)
        self.assertEqual(items, items_copy)
        self.assertEqual(self.ring, ring_copy)
        self.assertTrue(raw)


class VerifyPruneBatchAggregateTest(PruneBatchAggregateFixtures):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.packet = self.aggregate([
            batch_item("ok", self.hand_a),
            batch_item("bad", b"nope"),
            batch_item("ok2", self.hand_b),
        ])

    def test_success_returns_equal_but_independent_payload(self):
        result = self.verify(self.packet)
        payload = parse(self.packet)["payload"]
        self.assertEqual(result, payload)
        self.assertIsNot(result, payload)
        again = self.verify(self.packet)
        self.assertEqual(result, again)
        self.assertIsNot(result, again)
        self.assertIsNot(result["items"], again["items"])
        self.assertIsNot(result["report"], again["report"])
        result["items"][1]["statement"] = None
        result["status"] = "tampered"
        fresh = self.verify(self.packet)
        self.assertEqual(fresh["status"], "accepted")
        self.assertEqual(
            [row["conclusion"] for row in fresh["items"]],
            ["invalid", "valid", "valid"],
        )

    def test_site_policy_digest_binding(self):
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(self.packet, sites=site_policy(threshold=3))
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(
                self.packet,
                sites=site_policy(sites={SITE_A: {1}, JUDGE: {1}}),
            )

    def test_prune_policy_digest_binding(self):
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(self.packet,
                        prune=prune_policy(action="rollback",
                                           base=self.policy))
        other_base = make_policy(batch="other-batch")
        with self.assertRaises(InvalidPruneBatchAggregateError):
            self.verify(self.packet, prune=prune_policy(base=other_base))

    def test_current_credentials_are_required(self):
        with self.assertRaises(AuthenticationError):
            self.verify(self.packet, ring=make_ring(revoked=(JUDGE,)))
        with self.assertRaises(AuthenticationError):
            self.verify(self.packet,
                        ring=make_ring(not_after=self.moment - 1))
        ring_minus = {site: entries for site, entries in self.ring.items()
                      if site != JUDGE}
        with self.assertRaises(AuthenticationError):
            self.verify(self.packet, ring=ring_minus)

    def test_wrong_signature_is_unauthenticated(self):
        data = parse(self.packet)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.verify(compact(data))

    def test_structural_faults_are_invalid(self):
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, b"nope"
        )
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.packet + b"\n"
        )
        indented = json.dumps(
            parse(self.packet), indent=1, sort_keys=True
        ).encode()
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, indented
        )
        data = parse(self.packet)
        del data["payload"]["prunePolicyDigest"]
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        data = parse(self.packet)
        data["payload"]["version"] = 2
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )

    def test_duplicate_row_ids_are_invalid(self):
        data = parse(self.packet)
        data["payload"]["items"][2]["id"] = "ok"
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )

    def test_tampered_status_and_report_are_retallied(self):
        # Flip the aggregate status.
        data = parse(self.packet)
        data["payload"]["status"] = "insufficient"
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        # Null the common declaration of an accepted aggregate.
        data = parse(self.packet)
        data["payload"]["report"] = None
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        # Forge a declaration onto a conflicted aggregate.
        conflicted = self.aggregate([
            batch_item("a", self.hand_a),
            batch_item("b", self.sign_batch(
                [adj_packet("h2", self.accepted)], issuer=SITE_B)),
        ])
        data = parse(conflicted)
        self.assertIsNone(data["payload"]["report"])
        data["payload"]["report"] = {
            "items": data["payload"]["items"][0]["statement"],
            "version": 1,
        }
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )

    def test_tampered_rows_are_retallied(self):
        # Point a row at a different batch digest: the digest multiset
        # binding against the attestation list breaks.
        data = parse(self.packet)
        data["payload"]["items"][1]["digest"] = "11" * 32
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        # Swap the row order: the site/id ordering binding breaks.
        data = parse(self.packet)
        data["payload"]["items"] = [
            data["payload"]["items"][2],
            data["payload"]["items"][1],
            data["payload"]["items"][0],
        ]
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        # Flip a counted conclusion without the matching tally.
        data = parse(self.packet)
        row = data["payload"]["items"][1]
        self.assertEqual(row["conclusion"], "valid")
        row["conclusion"] = "duplicate"
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        # Change one site's statement so the two counted sites no longer
        # agree while the status still claims accepted.
        data = parse(self.packet)
        statement = data["payload"]["items"][1]["statement"]
        statement[0]["digest"] = "22" * 32
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )

    def test_rejected_row_shapes_are_enforced(self):
        # An invalid row must carry no site and no statement.
        data = parse(self.packet)
        invalid_row = next(
            row for row in data["payload"]["items"]
            if row["conclusion"] == "invalid"
        )
        invalid_row["site"] = SITE_A
        invalid_row["keyVersion"] = 1
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        data = parse(self.packet)
        invalid_row = next(
            row for row in data["payload"]["items"]
            if row["conclusion"] == "invalid"
        )
        invalid_row["statement"] = []
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        # A counted row must carry a statement; a null where the list of
        # summaries belongs is a JSON field type fault.
        data = parse(self.packet)
        valid_row = data["payload"]["items"][1]
        valid_row["statement"] = None
        self.assertRaises(
            TypeError, self.verify, self.resign(data)
        )

    def test_statement_reports_are_structurally_checked(self):
        data = parse(self.packet)
        statement = data["payload"]["items"][1]["statement"]
        statement[0]["report"]["id"] = "renamed"
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )
        data = parse(self.packet)
        statement = data["payload"]["items"][1]["statement"]
        statement[0]["digest"] = "not-a-digest"
        self.assertRaises(
            InvalidPruneBatchAggregateError, self.verify, self.resign(data)
        )

    def test_insufficient_and_conflicted_packets_round_trip(self):
        below_sites = site_policy(threshold=3)
        below = self.aggregate(
            [batch_item("a", self.hand_a)],
            sites=below_sites,
        )
        payload = self.verify(below, sites=below_sites)
        self.assertEqual(payload["status"], "insufficient")
        self.assertIsNotNone(payload["report"])

        conflicted = self.aggregate([
            batch_item("a", self.hand_a),
            batch_item("b", self.sign_batch(
                [adj_packet("h2", self.accepted)], issuer=SITE_B)),
        ])
        payload = self.verify(conflicted)
        self.assertEqual(payload["status"], "conflicted")
        self.assertIsNone(payload["report"])

    def test_argument_taxonomy(self):
        self.assertRaises(TypeError, self.verify, packet="bytes")
        self.assertRaises(TypeError, self.verify, self.packet, [])
        self.assertRaises(
            TypeError, self.verify, self.packet, self.prune_policy, []
        )
        self.assertRaises(
            TypeError, self.verify, self.packet, self.prune_policy,
            self.site_policy, [],
        )
        self.assertRaises(
            TypeError, self.verify, self.packet, self.prune_policy,
            self.site_policy, self.ring, True,
        )
        self.assertRaises(
            ValueError, self.verify, self.packet, self.prune_policy,
            self.site_policy, self.ring, -1,
        )
        self.assertRaises(
            ValueError, self.verify, self.packet, prune_policy(
                base=self.policy, sites={SITE_A: {1}}, threshold=2,
            )
        )
        self.assertRaises(
            ValueError, self.verify, self.packet,
            prune=self.prune_policy,
            sites={"sites": {}, "threshold": 1},
        )

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(
            InvalidPruneBatchAggregateError, ValueError
        ))
        self.assertTrue(issubclass(AuthenticationError, ValueError))

    def test_verification_reads_no_file(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            self.verify(self.packet)


if __name__ == "__main__":
    unittest.main()
