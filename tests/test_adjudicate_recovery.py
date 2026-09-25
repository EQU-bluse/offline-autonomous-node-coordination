"""Tests for offline multi-site adjudication of recovery attestations.

Covers :func:`adjudicate_recovery`: the batch/policy/keyring argument
contract and its type/value taxonomy, per-item isolation, the fixed
reject reasons, same-site duplicate and contradiction rules,
cross-site fork detection, the ``accepted``/``conflicted``/
``insufficient`` verdicts, canonical byte output and stable sorting,
the purely offline guarantee and input immutability.
"""

import copy
import hashlib
import hmac
import json
import unittest
from unittest import mock

from offline_coordination.replication import adjudicate_recovery

SECRET_1 = "ab" * 32
SECRET_2 = "cd" * 32
SECRET_3 = "ef" * 32
SITE_1 = "site-a"
SITE_2 = "site-b"
SITE_3 = "site-c"
BATCH = "batch-7"
MOMENT = 10
DIGEST = "a" * 64
OTHER_DIGEST = "c" * 64
TAIL = "b" * 64
OTHER_TAIL = "d" * 64
LAST_SEQ = 5

VERIFIED = "verified"
INCOMPLETE = "incomplete"


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_payload(payload, secret):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def key_entry(secret, revoked=False, not_before=0, not_after=10 ** 9):
    return {
        "version": 1,
        "secret": secret,
        "notBefore": not_before,
        "notAfter": not_after,
        "revoked": revoked,
    }


def make_keyring(site_secrets, revoked=(), expired=(), unready=()):
    ring = {}
    for site, secret in site_secrets.items():
        ring[site] = [
            key_entry(
                secret,
                revoked=site in revoked,
                not_before=MOMENT + 1 if site in unready else 0,
                not_after=MOMENT - 1 if site in expired else 10 ** 9,
            )
        ]
    return ring


THREE_SITES = (SITE_1, SITE_2, SITE_3)


def make_policy(threshold=2, sites=THREE_SITES, versions=None, batch=BATCH):
    return {
        "batch": batch,
        "threshold": threshold,
        "versions": (
            {site: {1} for site in sites} if versions is None else versions
        ),
    }


def attestation(
    site,
    secret,
    *,
    key_version=1,
    status=VERIFIED,
    digest=DIGEST,
    last_seq=LAST_SEQ,
    tail=TAIL,
    batch=BATCH,
    signature_secret=None,
):
    """Build a canonical signed attestation; signature_secret forges HMAC."""
    payload = {
        "batch": batch,
        "digest": digest,
        "keyVersion": key_version,
        "lastSeq": last_seq,
        "site": site,
        "status": status,
        "tail": tail,
    }
    signing = signature_secret if signature_secret is not None else secret
    return compact(
        {"payload": payload, "signature": sign_payload(payload, signing)}
    )


def item(item_id, site, secret, **kwargs):
    return {"id": item_id, "attestation": attestation(site, secret, **kwargs)}


class AdjudicateCase(unittest.TestCase):
    def setUp(self):
        self.keyring = make_keyring(
            {SITE_1: SECRET_1, SITE_2: SECRET_2, SITE_3: SECRET_3}
        )

    def judge(self, items, policy=None, keyring=None, moment=MOMENT):
        return json.loads(
            adjudicate_recovery(
                items,
                make_policy() if policy is None else policy,
                self.keyring if keyring is None else keyring,
                moment,
            )
        )

    def raw(self, items, policy=None, keyring=None, moment=MOMENT):
        return adjudicate_recovery(
            items,
            make_policy() if policy is None else policy,
            self.keyring if keyring is None else keyring,
            moment,
        )

    def two_matching(self):
        return [
            item("i1", SITE_1, SECRET_1),
            item("i2", SITE_2, SECRET_2),
        ]


class StructureTest(AdjudicateCase):
    def test_items_container_and_element_types_are_type_errors(self):
        good = self.two_matching()
        for bad in (None, "x", tuple(good), 1, {}):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    self.judge(bad)
        for bad in (None, 1, "x", []):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    self.judge([bad])
        with self.assertRaises(TypeError):
            self.judge([{"id": 1, "attestation": b"x"}])
        with self.assertRaises(TypeError):
            self.judge([{"id": "x", "attestation": "x"}])

    def test_items_value_faults(self):
        with self.assertRaises(ValueError):
            self.judge([])
        with self.assertRaises(ValueError):
            self.judge([{"id": "", "attestation": b"x"}])
        with self.assertRaises(ValueError):
            self.judge(
                [
                    {"id": "x", "attestation": b"x"},
                    {"id": "x", "attestation": b"y"},
                ]
            )
        with self.assertRaises(ValueError):
            self.judge([{"id": "x", "attestation": b"x", "extra": 1}])
        with self.assertRaises(ValueError):
            self.judge([{"id": "x"}])

    def test_whole_batch_is_validated_before_any_item_is_examined(self):
        good = self.two_matching()
        # A structural fault in the second item must raise, not return a
        # report for the first good item.
        with self.assertRaises(ValueError):
            self.judge(good + [{"id": "i3", "attestation": b"z", "x": 1}])

    def test_policy_type_and_value_faults(self):
        good_items = self.two_matching()
        for bad_policy in (None, [], "x", 1):
            with self.subTest(bad=type(bad_policy)):
                with self.assertRaises(TypeError):
                    adjudicate_recovery(
                        good_items, bad_policy, self.keyring, MOMENT
                    )
        with self.assertRaises(ValueError):
            self.judge(good_items, policy=make_policy(versions={}))
        with self.assertRaises(ValueError):
            self.judge(good_items, policy=make_policy(versions={SITE_1: set()}))
        with self.assertRaises(ValueError):
            self.judge(good_items, policy=make_policy(versions={SITE_1: {0}}))
        with self.assertRaises(ValueError):
            self.judge(good_items, policy=make_policy(versions={SITE_1: {1, 1}}))
        with self.assertRaises(ValueError):
            self.judge(good_items, policy=make_policy(threshold=0))
        with self.assertRaises(ValueError):
            self.judge(good_items, policy=make_policy(threshold=4))
        with self.assertRaises(ValueError):
            self.judge(good_items, policy=make_policy(batch=""))
        with self.assertRaises(ValueError):
            self.judge(good_items, policy=make_policy(versions={"": {1}}))
        with self.assertRaises(TypeError):
            self.judge(good_items, policy=make_policy(threshold=True))
        with self.assertRaises(TypeError):
            self.judge(good_items, policy=make_policy(versions={SITE_1: {True}}))
        with self.assertRaises(TypeError):
            self.judge(good_items, policy=make_policy(versions={SITE_1: 1}))
        with self.assertRaises(TypeError):
            self.judge(
                good_items,
                policy={"batch": 1, "threshold": 1, "versions": {SITE_1: {1}}},
            )

    def test_keyring_and_moment_keep_their_classification(self):
        good = self.two_matching()
        with self.assertRaises(TypeError):
            adjudicate_recovery(good, make_policy(), None, MOMENT)
        with self.assertRaises(TypeError):
            adjudicate_recovery(good, make_policy(), [], MOMENT)
        with self.assertRaises(ValueError):
            bad_ring = {SITE_1: [key_entry("zz")]}
            adjudicate_recovery(good, make_policy(), bad_ring, MOMENT)
        for bad_moment in (True, 1.5, "10"):
            with self.assertRaises(TypeError):
                adjudicate_recovery(good, make_policy(), self.keyring, bad_moment)
        with self.assertRaises(ValueError):
            adjudicate_recovery(good, make_policy(), self.keyring, -1)


class VerdictTest(AdjudicateCase):
    def test_threshold_reached_is_accepted_with_aggregate(self):
        result = self.judge(self.two_matching())
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["digest"], DIGEST)
        self.assertEqual(result["boundary"], {"lastSeq": LAST_SEQ, "tail": TAIL})
        self.assertEqual(
            [i["conclusion"] for i in result["items"]],
            [VERIFIED, VERIFIED],
        )
        for entry in result["items"]:
            self.assertIsNone(entry["reason"])

    def test_one_of_two_is_insufficient_with_null_aggregate(self):
        result = self.judge([item("i1", SITE_1, SECRET_1)])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["digest"])
        self.assertIsNone(result["boundary"])

    def test_threshold_one_accepts_a_single_site(self):
        result = self.judge(
            [item("i1", SITE_1, SECRET_1)],
            policy=make_policy(threshold=1, sites=(SITE_1,)),
        )
        self.assertEqual(result["status"], "accepted")

    def test_three_of_three(self):
        items = [
            item("i1", SITE_1, SECRET_1),
            item("i2", SITE_2, SECRET_2),
            item("i3", SITE_3, SECRET_3),
        ]
        result = self.judge(items, policy=make_policy(threshold=3))
        self.assertEqual(result["status"], "accepted")


class DuplicateAndContradictionTest(AdjudicateCase):
    def test_same_site_identical_packet_counts_once(self):
        one = item("i1", SITE_1, SECRET_1)
        two = item("i2", SITE_2, SECRET_2)
        dup = item("dup", SITE_1, SECRET_1)
        result = self.judge([one, two, dup])
        conclusions = {(i["site"], i["conclusion"]) for i in result["items"]}
        self.assertIn((SITE_1, VERIFIED), conclusions)
        dup_report = next(i for i in result["items"] if i["id"] == "dup")
        self.assertEqual(dup_report["conclusion"], "duplicate")
        self.assertEqual(dup_report["reason"], "duplicate")
        # Only two distinct sites voted: threshold 2 still met.
        self.assertEqual(result["status"], "accepted")

    def test_same_site_differing_packet_self_contradicts(self):
        one = item("i1", SITE_1, SECRET_1)
        two = item("i2", SITE_2, SECRET_2)
        # Same site, a different claimed tail: self-contradiction.
        contradicting = item("con", SITE_1, SECRET_1, tail=OTHER_TAIL)
        result = self.judge([one, two, contradicting])
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["digest"])
        self.assertIsNone(result["boundary"])
        bad = next(i for i in result["items"] if i["id"] == "con")
        self.assertEqual(bad["conclusion"], "rejected")
        self.assertEqual(bad["reason"], "conflict")

    def test_same_site_different_status_is_self_contradiction(self):
        verified = item("v", SITE_1, SECRET_1)
        incomplete = item("inc", SITE_1, SECRET_1, status=INCOMPLETE)
        # Presented after the verified packet: differs, so conflicts.
        result = self.judge(
            [verified, item("i2", SITE_2, SECRET_2), incomplete]
        )
        self.assertEqual(result["status"], "conflicted")
        bad = next(i for i in result["items"] if i["id"] == "inc")
        self.assertEqual(bad["reason"], "conflict")

    def test_identical_non_verified_packets_are_duplicates(self):
        a = item("a", SITE_1, SECRET_1, status=INCOMPLETE)
        b = item("b", SITE_1, SECRET_1, status=INCOMPLETE)
        result = self.judge([a, b])
        reasons = {i["id"]: (i["conclusion"], i["reason"]) for i in result["items"]}
        self.assertEqual(reasons["a"], ("rejected", "not-verified"))
        self.assertEqual(reasons["b"], ("duplicate", "duplicate"))
        self.assertEqual(result["status"], "insufficient")


class ForkTest(AdjudicateCase):
    def test_distinct_digests_fork_even_past_threshold(self):
        items = [
            item("i1", SITE_1, SECRET_1),
            item("i2", SITE_2, SECRET_2, digest=OTHER_DIGEST),
            item("i3", SITE_3, SECRET_3, digest=OTHER_DIGEST),
        ]
        result = self.judge(items)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["digest"])
        self.assertIsNone(result["boundary"])

    def test_distinct_tail_forks(self):
        items = [
            item("i1", SITE_1, SECRET_1),
            item("i2", SITE_2, SECRET_2, tail=OTHER_TAIL),
        ]
        self.assertEqual(self.judge(items)["status"], "conflicted")

    def test_distinct_lastseq_forks(self):
        items = [
            item("i1", SITE_1, SECRET_1),
            item("i2", SITE_2, SECRET_2, last_seq=LAST_SEQ + 1),
        ]
        self.assertEqual(self.judge(items)["status"], "conflicted")

    def test_majority_does_not_mask_a_fork(self):
        # Two sites agree, one disagrees: 2/3 majority still conflicts.
        items = [
            item("i1", SITE_1, SECRET_1),
            item("i2", SITE_2, SECRET_2),
            item("i3", SITE_3, SECRET_3, digest=OTHER_DIGEST),
        ]
        result = self.judge(items, policy=make_policy(threshold=2))
        self.assertEqual(result["status"], "conflicted")


class RejectReasonTest(AdjudicateCase):
    def reasons(self, items, policy=None, keyring=None):
        result = self.judge(items, policy=policy, keyring=keyring)
        return {i["id"]: i for i in result["items"]}

    def test_malformed_attestation_is_isolated_invalid_attestation(self):
        reports = self.reasons(
            [
                {"id": "bad", "attestation": b"nope"},
                item("ok", SITE_1, SECRET_1),
            ]
        )
        bad = reports["bad"]
        self.assertEqual(bad["conclusion"], "rejected")
        self.assertEqual(bad["reason"], "invalid-attestation")
        self.assertIsNone(bad["site"])
        self.assertIsNone(bad["keyVersion"])
        self.assertIsNone(bad["boundary"])
        # The good item is unaffected.
        self.assertEqual(reports["ok"]["conclusion"], VERIFIED)

    def test_wrong_key_set_and_noncanonical_encoding_are_invalid(self):
        payload = {
            "batch": BATCH, "digest": DIGEST, "keyVersion": 1,
            "lastSeq": LAST_SEQ, "site": SITE_1, "status": VERIFIED,
            "tail": TAIL,
        }
        extra_key = compact(
            {"payload": {**payload, "extra": 1},
             "signature": sign_payload(payload, SECRET_1)}
        )
        with_newline = compact(
            {"payload": payload, "signature": sign_payload(payload, SECRET_1)}
        ) + b"\n"
        pretty = (
            json.dumps({"payload": payload,
                        "signature": sign_payload(payload, SECRET_1)},
                       sort_keys=True, indent=2)
            .encode("utf-8")
        )
        for raw in (extra_key, with_newline, pretty, b"", b"{}"):
            with self.subTest(raw=raw[:12]):
                reports = self.reasons([{"id": "x", "attestation": raw}])
                self.assertEqual(reports["x"]["reason"], "invalid-attestation")

    def test_unauthorized_batch(self):
        reports = self.reasons(
            [item("x", SITE_1, SECRET_1, batch="other-batch")]
        )
        self.assertEqual(reports["x"]["reason"], "unauthorized-batch")

    def test_unauthorized_site(self):
        reports = self.reasons(
            [item("x", "unknown-site", SECRET_1)]
        )
        self.assertEqual(reports["x"]["reason"], "unauthorized-site")

    def test_unauthorized_version(self):
        # Site may use only version 1 but claims version 2 (which exists
        # in the keyring): policy rejects before the keyring is consulted.
        ring = make_keyring({SITE_1: SECRET_1})
        ring[SITE_1].append({**key_entry(SECRET_1), "version": 2})
        reports = self.reasons(
            [item("x", SITE_1, SECRET_1, key_version=2)],
            keyring=ring,
        )
        self.assertEqual(reports["x"]["reason"], "unauthorized-version")

    def test_unknown_credentials_revoked_expired_unready(self):
        # Site authorized by policy but absent from the keyring.
        reports = self.reasons(
            [item("x", SITE_1, SECRET_1)],
            keyring=make_keyring({SITE_2: SECRET_2}),
        )
        self.assertEqual(reports["x"]["reason"], "unknown-credentials")

        reports = self.reasons(
            [item("x", SITE_1, SECRET_1)],
            keyring=make_keyring({SITE_1: SECRET_1}, revoked=(SITE_1,)),
        )
        self.assertEqual(reports["x"]["reason"], "revoked")

        reports = self.reasons(
            [item("x", SITE_1, SECRET_1)],
            keyring=make_keyring({SITE_1: SECRET_1}, expired=(SITE_1,)),
        )
        self.assertEqual(reports["x"]["reason"], "expired")

        reports = self.reasons(
            [item("x", SITE_1, SECRET_1)],
            keyring=make_keyring({SITE_1: SECRET_1}, unready=(SITE_1,)),
        )
        self.assertEqual(reports["x"]["reason"], "not-yet-valid")

    def test_bad_signature(self):
        # Correct key in the keyring but HMAC made with a different secret.
        reports = self.reasons(
            [item("x", SITE_1, SECRET_1, signature_secret=SECRET_2)]
        )
        self.assertEqual(reports["x"]["reason"], "bad-signature")

    def test_non_verified_status_does_not_vote(self):
        for status in (INCOMPLETE, "invalid-checkpoint", "invalid-page",
                       "unauthenticated"):
            with self.subTest(status=status):
                reports = self.reasons(
                    [item("x", SITE_1, SECRET_1, status=status)]
                )
                self.assertEqual(reports["x"]["reason"], "not-verified")
                self.assertEqual(reports["x"]["boundary"],
                                 {"lastSeq": LAST_SEQ, "tail": TAIL})

    def test_one_bad_item_never_blocks_the_others_or_the_verdict(self):
        items = [
            {"id": "bad", "attestation": b"nope"},
            item("ok1", SITE_1, SECRET_1),
            item("ok2", SITE_2, SECRET_2),
        ]
        result = self.judge(items)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(
            [i["id"] for i in result["items"]], ["bad", "ok1", "ok2"]
        )


class ReportShapeAndOrderTest(AdjudicateCase):
    # Output bytes are canonical (sorted keys), so parsed order is sorted.
    REPORT_KEYS = ["boundary", "conclusion", "id", "keyVersion", "reason",
                   "site"]
    TOP_KEYS = ["boundary", "digest", "items", "status", "version"]

    def test_report_key_shapes_and_order(self):
        raw = self.raw(self.two_matching())
        # Canonical compact JSON: sorted keys, no trailing byte.
        self.assertFalse(raw.endswith(b"\n"))
        self.assertEqual(compact(json.loads(raw)), raw)
        result = json.loads(raw)
        self.assertEqual(list(result.keys()), self.TOP_KEYS)
        for entry in result["items"]:
            self.assertEqual(list(entry.keys()), self.REPORT_KEYS)

    def test_items_sorted_by_site_then_id(self):
        items = [
            item("z", SITE_2, SECRET_2),
            item("a", SITE_1, SECRET_1),
            {"id": "m", "attestation": b"bad"},
            item("b", SITE_1, SECRET_1),
        ]
        # Two packets from SITE_1: 'a' first... but sorting is by id after
        # site. 'a' and 'b' are distinct ids on the same site; 'b'
        # duplicates 'a' payload.
        result = self.judge(items)
        ordered = [(i["site"], i["id"]) for i in result["items"]]
        # null-site malformed item sorts first, then site/id.
        self.assertEqual(
            ordered,
            [(None, "m"), (SITE_1, "a"), (SITE_1, "b"), (SITE_2, "z")],
        )

    def test_order_of_input_never_changes_the_bytes(self):
        one = item("a", SITE_1, SECRET_1)
        two = item("b", SITE_2, SECRET_2, digest=OTHER_DIGEST)
        first = self.raw([one, two])
        second = self.raw([two, one])
        self.assertEqual(first, second)

    def test_non_ascii_is_preserved_unescaped(self):
        payload = {
            "batch": BATCH, "digest": DIGEST, "keyVersion": 1,
            "lastSeq": LAST_SEQ, "site": "sité-λ", "status": VERIFIED,
            "tail": TAIL,
        }
        raw_att = compact(
            {"payload": payload, "signature": sign_payload(payload, SECRET_1)}
        )
        policy = make_policy(
            threshold=1, sites=("sité-λ",), versions={"sité-λ": {1}}
        )
        ring = make_keyring({"sité-λ": SECRET_1})
        raw = adjudicate_recovery(
            [{"id": "id-λ", "attestation": raw_att}], policy, ring, MOMENT
        )
        self.assertIn("sité-λ".encode("utf-8"), raw)
        self.assertEqual(compact(json.loads(raw)), raw)


class ImmutabilityAndOfflineTest(AdjudicateCase):
    def test_inputs_are_not_modified(self):
        items = self.two_matching()
        snapshot = copy.deepcopy(items)
        policy = make_policy()
        policy_snapshot = copy.deepcopy(policy)
        keyring_snapshot = copy.deepcopy(self.keyring)
        adjudicate_recovery(items, policy, self.keyring, MOMENT)
        self.assertEqual(items, snapshot)
        self.assertEqual(policy, policy_snapshot)
        self.assertEqual(self.keyring, keyring_snapshot)

    def test_result_is_fresh_and_detached(self):
        result = self.judge(self.two_matching())
        result["items"][0]["conclusion"] = "tampered"
        result["boundary"]["lastSeq"] = -1
        again = self.judge(self.two_matching())
        self.assertEqual(again["items"][0]["conclusion"], VERIFIED)
        self.assertEqual(again["boundary"]["lastSeq"], LAST_SEQ)

    def test_no_file_is_read(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = self.raw(self.two_matching())
        result = json.loads(raw)
        self.assertEqual(result["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
