"""Tests for offline multi-site recovery adjudication.

Covers :func:`adjudicate_recovery`: the item/policy/keyring/moment
type and value taxonomy, per-packet isolation, the fixed rejection
reasons, same-site duplicate and contradiction handling, cross-site
fork conflicts, the accepted/insufficient/conflicted verdicts, stable
order- and input-independent output, canonical JSON bytes, the purely
offline guarantee and input immutability.
"""

import copy
import hashlib
import hmac
import json
import unittest
from unittest import mock

from offline_coordination.replication import adjudicate_recovery

SECRET_A = "ab" * 32
SECRET_B = "cd" * 32
SECRET_C = "ef" * 32
SECRETS = {"a": SECRET_A, "b": SECRET_B, "c": SECRET_C}
BATCH = "batch-1"
MOMENT = 10
DIGEST = "bb" * 32
OTHER_DIGEST = "cc" * 32
BOUNDARY = {"lastSeq": 5, "tail": "aa" * 32}
OTHER_BOUNDARY = {"lastSeq": 6, "tail": "dd" * 32}

TOP_KEYS = ["boundary", "digest", "items", "status", "threshold", "version"]
ITEM_KEYS = [
    "boundary", "conclusion", "digest", "id", "keyVersion", "reason",
    "site", "status",
]


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring(secrets=SECRETS, revoked=(), not_before=0, not_after=10 ** 9):
    return {
        site: [
            {
                "version": 1,
                "secret": secret,
                "notBefore": not_before,
                "notAfter": not_after,
                "revoked": site in revoked,
            }
        ]
        for site, secret in secrets.items()
    }


def policy(sites=("a", "b", "c"), threshold=2, batch=BATCH):
    return {"batch": batch, "sites": {site: {1} for site in sites},
            "threshold": threshold}


def verification_result(
    rid="res-1",
    digest=DIGEST,
    boundary=BOUNDARY,
    status="verified",
    error=None,
    issuer="issuer-x",
    key_version=1,
):
    return {
        "boundary": boundary,
        "digest": digest,
        "error": error,
        "id": rid,
        "issuer": issuer,
        "keyVersion": key_version,
        "status": status,
    }


def make_attestation(
    site="a",
    result=None,
    key_version=1,
    batch=BATCH,
    secret=SECRET_A,
    tamper_signature=False,
):
    result = verification_result() if result is None else result
    payload = {
        "batch": batch,
        "keyVersion": key_version,
        "result": result,
        "site": site,
    }
    signature = hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()
    if tamper_signature:
        signature = ("0" if signature[0] != "0" else "1") + signature[1:]
    return compact({"payload": payload, "signature": signature})


def make_item(item_id, attestation=None, **kwargs):
    return {
        "id": item_id,
        "attestation": (
            make_attestation(**kwargs) if attestation is None else attestation
        ),
    }


def adjudicate(items, pol=None, ring=None, moment=MOMENT):
    return json.loads(
        adjudicate_recovery(
            items,
            policy() if pol is None else pol,
            keyring() if ring is None else ring,
            moment,
        )
    )


def three_agreed():
    return [
        make_item("i1", site="a", result=verification_result(rid="r1")),
        make_item("i2", site="b", secret=SECRET_B,
                  result=verification_result(rid="r2")),
        make_item("i3", site="c", secret=SECRET_C,
                  result=verification_result(rid="r3")),
    ]


class StructureTest(unittest.TestCase):
    def test_items_container_and_field_type_faults_are_type_errors(self):
        good = make_item("ok")
        for bad_items in (None, "x", (good,), 1, {"id": "x"}):
            with self.subTest(bad=type(bad_items)):
                with self.assertRaises(TypeError):
                    adjudicate(bad_items)
        for bad_element in (None, 1, "x", []):
            with self.subTest(bad=type(bad_element)):
                with self.assertRaises(TypeError):
                    adjudicate([bad_element])
        with self.assertRaises(TypeError):
            adjudicate([{"id": 1, "attestation": b"x"}])
        with self.assertRaises(TypeError):
            adjudicate([{"id": "x", "attestation": "x"}])

    def test_items_value_faults(self):
        with self.assertRaises(ValueError):
            adjudicate([])
        with self.assertRaises(ValueError):
            adjudicate([{"id": "", "attestation": b"x"}])
        with self.assertRaises(ValueError):
            adjudicate(
                [make_item("dup"), make_item("dup", site="b",
                                              secret=SECRET_B)]
            )
        with self.assertRaises(ValueError):
            adjudicate([{"id": "x", "attestation": b"x", "extra": 1}])
        with self.assertRaises(ValueError):
            adjudicate([{"id": "x"}])

    def test_container_is_validated_before_any_packet_is_read(self):
        good = make_item("ok")
        # A structural fault on the second item raises instead of
        # producing a verdict from the first.
        with self.assertRaises(ValueError):
            adjudicate([good, {"id": "ok"}])
        with self.assertRaises(ValueError):
            adjudicate(
                [good, {"id": "ok2", "attestation": b"x", "extra": 1}]
            )
        with self.assertRaises(TypeError):
            adjudicate([good, {"id": "ok2", "attestation": []}])

    def test_policy_type_faults(self):
        good = three_agreed()
        for bad_policy in (None, [], "x", 1):
            with self.subTest(bad=type(bad_policy)):
                with self.assertRaises(TypeError):
                    adjudicate_recovery(good, bad_policy, keyring(), MOMENT)
        with self.assertRaises(ValueError):
            adjudicate_recovery(good, {"batch": BATCH, "sites": {"a": {1}}},
                                keyring(), MOMENT)
        with self.assertRaises(TypeError):
            adjudicate_recovery(good, policy(batch=1), keyring(), MOMENT)
        with self.assertRaises(ValueError):
            adjudicate_recovery(good, policy(batch=""), keyring(), MOMENT)
        for bad_threshold in (True, 1.0, "2"):
            with self.subTest(bad=bad_threshold):
                with self.assertRaises(TypeError):
                    adjudicate_recovery(
                        good, policy(threshold=bad_threshold),
                        keyring(), MOMENT,
                    )

    def test_policy_value_faults(self):
        good = three_agreed()
        with self.assertRaises(ValueError):
            adjudicate_recovery(good, policy(threshold=0), keyring(), MOMENT)
        with self.assertRaises(ValueError):
            adjudicate_recovery(good, policy(threshold=-2), keyring(), MOMENT)
        with self.assertRaises(ValueError):
            adjudicate_recovery(good, policy(threshold=4), keyring(), MOMENT)
        with self.assertRaises(TypeError):
            adjudicate_recovery(
                good,
                {"batch": BATCH, "threshold": 1, "sites": []},
                keyring(), MOMENT,
            )
        with self.assertRaises(ValueError):
            adjudicate_recovery(
                good,
                {"batch": BATCH, "threshold": 1, "sites": {}},
                keyring(), MOMENT,
            )
        with self.assertRaises(TypeError):
            adjudicate_recovery(
                good,
                {"batch": BATCH, "threshold": 1, "sites": {1: {1}}},
                keyring(), MOMENT,
            )
        with self.assertRaises(ValueError):
            adjudicate_recovery(
                good,
                {"batch": BATCH, "threshold": 1, "sites": {"": {1}}},
                keyring(), MOMENT,
            )
        for bad_versions in ([1], (1,), frozenset({1}), "x", 1):
            with self.subTest(bad=type(bad_versions)):
                with self.assertRaises(TypeError):
                    adjudicate_recovery(
                        good,
                        {"batch": BATCH, "threshold": 1,
                         "sites": {"a": bad_versions}},
                        keyring(), MOMENT,
                    )
        with self.assertRaises(ValueError):
            adjudicate_recovery(
                good,
                {"batch": BATCH, "threshold": 1, "sites": {"a": set()}},
                keyring(), MOMENT,
            )
        for bad_version in (True, 1.0, "1"):
            with self.subTest(bad=bad_version):
                with self.assertRaises(TypeError):
                    adjudicate_recovery(
                        good,
                        {"batch": BATCH, "threshold": 1,
                         "sites": {"a": {bad_version}}},
                        keyring(), MOMENT,
                    )
        with self.assertRaises(ValueError):
            adjudicate_recovery(
                good,
                {"batch": BATCH, "threshold": 1, "sites": {"a": {0}}},
                keyring(), MOMENT,
            )

    def test_keyring_and_moment_faults_keep_their_classification(self):
        good = three_agreed()
        with self.assertRaises(TypeError):
            adjudicate_recovery(good, policy(), None, MOMENT)
        with self.assertRaises(ValueError):
            adjudicate_recovery(
                good, policy(),
                {"a": [{"version": 1, "secret": "zz", "notBefore": 0,
                        "notAfter": 1, "revoked": False}]},
                MOMENT,
            )
        for bad_moment in (True, 1.5, "10"):
            with self.subTest(bad=bad_moment):
                with self.assertRaises(TypeError):
                    adjudicate_recovery(good, policy(), keyring(), bad_moment)
        with self.assertRaises(ValueError):
            adjudicate_recovery(good, policy(), keyring(), -1)


class CanonicalBytesTest(unittest.TestCase):
    def test_output_is_canonical_compact_json_without_trailing_byte(self):
        raw = adjudicate_recovery(three_agreed(), policy(), keyring(), MOMENT)
        self.assertIsInstance(raw, bytes)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw)
        data = json.loads(raw)
        self.assertEqual(compact(data), raw)
        self.assertEqual(list(data.keys()), TOP_KEYS)
        self.assertEqual(list(data["items"][0].keys()), ITEM_KEYS)

    def test_non_ascii_is_preserved(self):
        items = [
            make_item("ï1", site="a", result=verification_result(rid="r1")),
            make_item("ï2", site="b", secret=SECRET_B,
                      result=verification_result(rid="r2")),
        ]
        pol = policy(sites=("a", "b"))
        raw = adjudicate_recovery(items, pol, keyring(), MOMENT)
        self.assertIn("ï".encode("utf-8"), raw)
        self.assertEqual(json.loads(raw)["items"][0]["id"], "ï1")


class AcceptedTest(unittest.TestCase):
    def test_threshold_of_distinct_sites_accepts(self):
        data = adjudicate(three_agreed())
        self.assertEqual(data["status"], "accepted")
        self.assertEqual(data["digest"], DIGEST)
        self.assertEqual(data["boundary"], BOUNDARY)
        self.assertEqual(data["threshold"], 2)
        self.assertEqual(data["version"], 1)
        self.assertEqual(
            [(i["site"], i["conclusion"], i["reason"]) for i in data["items"]],
            [("a", "valid", None), ("b", "valid", None),
             ("c", "valid", None)],
        )

    def test_extra_same_site_packets_are_duplicates_and_do_not_add_votes(self):
        items = [
            make_item("i1", site="a", result=verification_result(rid="r1")),
            make_item("i2", site="a", result=verification_result(rid="r1")),
            make_item("i3", site="b", secret=SECRET_B,
                      result=verification_result(rid="r2")),
        ]
        data = adjudicate(items)
        self.assertEqual(data["status"], "accepted")
        labels = {(i["site"], i["conclusion"]) for i in data["items"]}
        self.assertEqual(
            labels, {("a", "valid"), ("a", "duplicate"), ("b", "valid")}
        )
        duplicate = [i for i in data["items"]
                     if i["conclusion"] == "duplicate"][0]
        self.assertEqual(duplicate["reason"], "duplicate")
        self.assertEqual(duplicate["digest"], DIGEST)
        self.assertEqual(duplicate["boundary"], BOUNDARY)

    def test_same_digest_and_boundary_but_different_result_contradicts(self):
        # Only a complete, field-identical result is a duplicate; the
        # same digest and boundary under a different result id is a
        # self-contradiction.
        items = [
            make_item("i1", site="a", result=verification_result(rid="r1")),
            make_item("i2", site="a", result=verification_result(rid="r1b")),
        ]
        data = adjudicate(items)
        self.assertEqual(data["status"], "conflicted")
        self.assertEqual(
            [i["conclusion"] for i in data["items"]],
            ["contradiction", "contradiction"],
        )

    def test_one_site_below_threshold_is_insufficient(self):
        items = [
            make_item("i1", site="a", result=verification_result(rid="r1")),
            make_item("i2", site="a", result=verification_result(rid="r1")),
        ]
        data = adjudicate(items)
        self.assertEqual(data["status"], "insufficient")
        self.assertIsNone(data["digest"])
        self.assertIsNone(data["boundary"])


class RejectionReasonTest(unittest.TestCase):
    def _one_good(self, bad_item):
        return [
            bad_item,
            make_item("ok", site="b", secret=SECRET_B,
                      result=verification_result(rid="r2")),
        ]

    def test_unauthorized_batch(self):
        data = adjudicate(
            self._one_good(
                make_item("x", batch="other",
                          result=verification_result(rid="r1"))
            )
        )
        report = data["items"][0]
        self.assertEqual(report["conclusion"], "invalid")
        self.assertEqual(report["reason"], "unauthorized-batch")
        self.assertEqual(report["site"], "a")
        self.assertEqual(data["status"], "insufficient")

    def test_unauthorized_site(self):
        data = adjudicate(
            self._one_good(
                make_item("x", site="zzz",
                          result=verification_result(rid="r1"))
            )
        )
        report = next(i for i in data["items"] if i["id"] == "x")
        self.assertEqual(report["reason"], "unauthorized-site")

    def test_unauthorized_version(self):
        data = adjudicate(
            self._one_good(
                make_item("x", key_version=9,
                          result=verification_result(key_version=9, rid="r1"))
            )
        )
        self.assertEqual(data["items"][0]["reason"], "unauthorized-version")

    def test_credential_unavailable(self):
        data = adjudicate(
            self._one_good(
                make_item("x", result=verification_result(rid="r1"))
            ),
            ring=keyring(secrets={"b": SECRET_B, "c": SECRET_C}),
        )
        self.assertEqual(data["items"][0]["reason"], "credential-unavailable")

    def test_revoked_not_yet_valid_expired(self):
        cases = {
            "revoked": dict(ring=keyring(revoked=("a",))),
            "not-yet-valid": dict(ring=keyring(not_before=MOMENT + 1)),
            "expired": dict(ring=keyring(not_after=MOMENT - 1)),
        }
        for label, kwargs in cases.items():
            with self.subTest(label=label):
                data = adjudicate(
                    [make_item("x", result=verification_result(rid="r1"))],
                    **kwargs,
                )
                self.assertEqual(data["items"][0]["reason"], label)

    def test_bad_signature(self):
        data = adjudicate(
            [make_item("x", tamper_signature=True,
                       result=verification_result(rid="r1"))]
        )
        self.assertEqual(data["items"][0]["reason"], "bad-signature")

    def test_non_verified_result_is_not_verified(self):
        result = verification_result(
            status="incomplete", error="pages exhausted before the signed lastSeq"
        )
        data = adjudicate([make_item("x", result=result)])
        report = data["items"][0]
        self.assertEqual(report["reason"], "not-verified")
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["boundary"], BOUNDARY)

    def test_rejected_packet_keeps_identity_and_boundary(self):
        result = verification_result(status="invalid-page", error="bad page")
        data = adjudicate([make_item("x", result=result)])
        report = data["items"][0]
        self.assertEqual(report["site"], "a")
        self.assertEqual(report["keyVersion"], 1)
        self.assertEqual(report["digest"], DIGEST)
        self.assertEqual(report["boundary"], BOUNDARY)
        self.assertEqual(report["status"], "invalid-page")

    def test_failed_result_without_identity_or_boundary_is_not_verified(self):
        # A checkpoint that does not parse reports no issuer, keyVersion
        # or boundary; the packet is still a legal verification result.
        result = verification_result(
            status="invalid-checkpoint", error="bad checkpoint",
            issuer=None, key_version=None, boundary=None,
        )
        data = adjudicate([make_item("x", result=result)])
        report = data["items"][0]
        self.assertEqual(report["conclusion"], "invalid")
        self.assertEqual(report["reason"], "not-verified")
        self.assertEqual(report["site"], "a")
        self.assertEqual(report["keyVersion"], 1)
        self.assertEqual(report["digest"], DIGEST)
        self.assertIsNone(report["boundary"])
        self.assertEqual(report["status"], "invalid-checkpoint")

    def test_verified_result_requires_identity_and_boundary(self):
        for result in (
            verification_result(issuer=None, key_version=None),
            verification_result(boundary=None),
        ):
            with self.subTest(result=result):
                data = adjudicate([make_item("x", result=result)])
                self.assertEqual(data["items"][0]["reason"],
                                 "invalid-attestation")

    def test_identity_must_be_both_null_or_both_set(self):
        result = verification_result(status="invalid-page", error="bad page",
                                     key_version=None)
        data = adjudicate([make_item("x", result=result)])
        self.assertEqual(data["items"][0]["reason"], "invalid-attestation")


class InvalidPacketTest(unittest.TestCase):
    def test_malformed_packets_are_rejected_alone(self):
        malformed_result = dict(verification_result())
        del malformed_result["issuer"]
        cases = {
            "not-json": b"nope",
            "trailing-newline": make_attestation() + b"\n",
            "trailing-space": make_attestation()[:-1] + b" }",
            "whitespace": b'{"payload": {}, "signature": "' + b"a" * 64 + b'"}',
            "wrong-top-keys": compact(
                {"payload": {}, "signature": "a" * 64, "extra": 1}
            ),
            "bad-signature-format": compact(
                {"payload": {"batch": BATCH, "keyVersion": 1,
                             "result": verification_result(), "site": "a"},
                 "signature": "ZZ"}
            ),
            "payload-extra-field": compact(
                {"payload": {"batch": BATCH, "keyVersion": 1,
                             "result": verification_result(), "site": "a",
                             "extra": 1},
                 "signature": "a" * 64}
            ),
            "bad-result-keys": compact(
                {"payload": {"batch": BATCH, "keyVersion": 1,
                             "result": malformed_result, "site": "a"},
                 "signature": "a" * 64}
            ),
        }
        for label, raw in cases.items():
            with self.subTest(label=label):
                data = adjudicate(
                    [
                        {"id": "bad", "attestation": raw},
                        make_item("ok", site="b", secret=SECRET_B,
                                  result=verification_result(rid="r2")),
                    ]
                )
                bad, good = data["items"]
                self.assertEqual(bad["id"], "bad")
                self.assertEqual(bad["conclusion"], "invalid")
                self.assertEqual(bad["reason"], "invalid-attestation")
                self.assertIsNone(bad["site"])
                self.assertIsNone(bad["keyVersion"])
                self.assertIsNone(bad["digest"])
                self.assertIsNone(bad["boundary"])
                self.assertIsNone(bad["status"])
                self.assertEqual(good["id"], "ok")
                self.assertEqual(good["conclusion"], "valid")

    def test_duplicate_json_keys_reject_the_packet(self):
        payload = {"batch": BATCH, "keyVersion": 1,
                   "result": verification_result(), "site": "a"}
        signed = make_attestation()
        # Rebuild the envelope with a duplicated payload key.
        text = (
            '{"payload":' + compact(payload).decode()
            + ',"payload":{},"signature":"' + "a" * 64 + '"}'
        )
        data = adjudicate([{"id": "dup", "attestation": text.encode("utf-8")}])
        self.assertEqual(data["items"][0]["reason"], "invalid-attestation")

    def test_bool_field_inside_payload_rejects_the_packet(self):
        # A bool masquerading as keyVersion lives inside one packet, so
        # it rejects that packet rather than raising at the batch level.
        payload_text = (
            '{"batch":"' + BATCH + '","keyVersion":true,"result":'
            + compact(verification_result()).decode()
            + ',"site":"a"}'
        )
        envelope = (
            b'{"payload":' + payload_text.encode()
            + b',"signature":"' + b"a" * 64 + b'"}'
        )
        data = adjudicate([{"id": "b", "attestation": envelope}])
        self.assertEqual(data["items"][0]["reason"], "invalid-attestation")

    def test_verified_result_requires_null_error_and_vice_versa(self):
        bad_verified = compact(
            {"payload": {"batch": BATCH, "keyVersion": 1,
                         "result": verification_result(error="surprise"),
                         "site": "a"},
             "signature": "a" * 64}
        )
        bad_incomplete = compact(
            {"payload": {"batch": BATCH, "keyVersion": 1,
                         "result": verification_result(status="incomplete"),
                         "site": "a"},
             "signature": "a" * 64}
        )
        for raw in (bad_verified, bad_incomplete):
            with self.subTest(raw=raw[:20]):
                data = adjudicate([{"id": "x", "attestation": raw}])
                self.assertEqual(data["items"][0]["reason"],
                                 "invalid-attestation")


class ContradictionAndConflictTest(unittest.TestCase):
    def test_differing_results_from_one_site_contradict(self):
        items = [
            make_item("i1", site="a", result=verification_result(rid="r1")),
            make_item("i9", site="a",
                      result=verification_result(rid="r9",
                                                 digest=OTHER_DIGEST,
                                                 boundary=OTHER_BOUNDARY)),
            make_item("i2", site="b", secret=SECRET_B,
                      result=verification_result(rid="r2")),
        ]
        data = adjudicate(items)
        self.assertEqual(data["status"], "conflicted")
        self.assertIsNone(data["digest"])
        self.assertIsNone(data["boundary"])
        a_sites = [i for i in data["items"] if i["site"] == "a"]
        self.assertEqual(
            sorted(i["conclusion"] for i in a_sites),
            ["contradiction", "contradiction"],
        )
        self.assertTrue(all(i["reason"] == "contradiction" for i in a_sites))

    def test_same_digest_but_different_boundary_contradicts(self):
        items = [
            make_item("i1", site="a", result=verification_result(rid="r1")),
            make_item("i2", site="a",
                      result=verification_result(rid="r2",
                                                 boundary=OTHER_BOUNDARY)),
        ]
        data = adjudicate(items)
        self.assertEqual(data["status"], "conflicted")

    def test_duplicate_beside_a_contradiction_stays_duplicate(self):
        items = [
            make_item("i1", site="a", result=verification_result(rid="r1")),
            make_item("i2", site="a", result=verification_result(rid="r1")),
            make_item("i3", site="a",
                      result=verification_result(rid="r3",
                                                 digest=OTHER_DIGEST,
                                                 boundary=OTHER_BOUNDARY)),
        ]
        data = adjudicate(items)
        self.assertEqual(data["status"], "conflicted")
        conclusions = {i["id"]: i["conclusion"] for i in data["items"]}
        self.assertEqual(conclusions["i3"], "contradiction")
        self.assertEqual(conclusions["i1"], "contradiction")
        self.assertEqual(conclusions["i2"], "duplicate")

    def test_cross_site_digest_fork_cannot_be_majority_masked(self):
        items = [
            make_item("i1", site="a", result=verification_result(rid="r1")),
            make_item("i2", site="b", secret=SECRET_B,
                      result=verification_result(rid="r2")),
            make_item("i3", site="c", secret=SECRET_C,
                      result=verification_result(rid="r3",
                                                 digest=OTHER_DIGEST,
                                                 boundary=OTHER_BOUNDARY)),
        ]
        data = adjudicate(items, pol=policy(threshold=2))
        self.assertEqual(data["status"], "conflicted")

    def test_two_site_majority_over_one_fork_is_still_conflicted(self):
        items = [
            make_item("i1", site="a", result=verification_result(rid="r1")),
            make_item("i2", site="b", secret=SECRET_B,
                      result=verification_result(rid="r2")),
            make_item("i3", site="c", secret=SECRET_C,
                      result=verification_result(rid="r3",
                                                 digest=OTHER_DIGEST)),
        ]
        data = adjudicate(items)
        self.assertEqual(data["status"], "conflicted")
        self.assertIsNone(data["boundary"])


class OrderingTest(unittest.TestCase):
    def test_reports_are_sorted_by_site_then_id(self):
        items = [
            make_item("z9", site="c", secret=SECRET_C,
                      result=verification_result(rid="r3")),
            {"id": "bad0", "attestation": b"nope"},
            make_item("a1", site="a", result=verification_result(rid="r1")),
            make_item("b5", site="b", secret=SECRET_B,
                      result=verification_result(rid="r2")),
        ]
        data = adjudicate(items)
        self.assertEqual(
            [(i["site"], i["id"]) for i in data["items"]],
            [(None, "bad0"), ("a", "a1"), ("b", "b5"), ("c", "z9")],
        )

    def test_conclusion_is_independent_of_input_order(self):
        import itertools

        packets = [
            ("i1", "a", "r1", DIGEST, BOUNDARY),
            ("i2", "a", "r2", DIGEST, BOUNDARY),
            ("i9", "a", "r9", OTHER_DIGEST, OTHER_BOUNDARY),
            ("ib", "b", "rb", DIGEST, BOUNDARY),
            ("ic", "c", "rc", OTHER_DIGEST, OTHER_BOUNDARY),
            ("bad", None, None, None, None),
        ]

        def build(permutation):
            built = []
            for pid, site, rid, digest, boundary in permutation:
                if site is None:
                    built.append({"id": pid, "attestation": b"nope"})
                else:
                    built.append(
                        make_item(
                            pid, site=site, secret=SECRETS[site],
                            result=verification_result(
                                rid=rid, digest=digest, boundary=boundary
                            ),
                        )
                    )
            return built

        outputs = {
            adjudicate_recovery(build(permutation), policy(), keyring(), MOMENT)
            for permutation in itertools.permutations(packets)
        }
        self.assertEqual(len(outputs), 1)
        data = json.loads(next(iter(outputs)))
        self.assertEqual(data["status"], "conflicted")


class OfflineAndImmutabilityTest(unittest.TestCase):
    def test_no_file_is_read(self):
        items = three_agreed()
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            raw = adjudicate_recovery(items, policy(), keyring(), MOMENT)
        self.assertEqual(json.loads(raw)["status"], "accepted")

    def test_inputs_are_not_modified(self):
        items = three_agreed()
        items += [
            make_item("dup", site="a", result=verification_result(rid="zz")),
            {"id": "bad", "attestation": b"nope"},
        ]
        pol = policy()
        ring = keyring()
        items_copy = copy.deepcopy(items)
        policy_copy = copy.deepcopy(pol)
        ring_copy = copy.deepcopy(ring)
        adjudicate_recovery(items, pol, ring, MOMENT)
        self.assertEqual(items, items_copy)
        self.assertEqual(pol, policy_copy)
        self.assertEqual(ring, ring_copy)


if __name__ == "__main__":
    unittest.main()
