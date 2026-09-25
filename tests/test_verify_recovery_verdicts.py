"""Tests for offline batch verification of recovery verdict proofs.

Covers :func:`verify_recovery_verdicts`: the batch container contract
and its type/value taxonomy with full pre-validation, per-item
isolation, the ``verified``/``invalid-proof``/``unauthenticated``
statuses, exact issuer/version key selection across a mixed batch, the
fixed report shape and key order, result freshness/independence, the
purely offline guarantee and input immutability.
"""

import copy
import hashlib
import hmac
import json
import unittest
from unittest import mock

from offline_coordination.replication import (
    AuthenticationError,
    InvalidRecoveryVerdictProofError,
    adjudicate_recovery,
    export_recovery_verdict,
    verify_recovery_verdict,
    verify_recovery_verdicts,
)

SECRET_A = "ab" * 32
SECRET_B = "cd" * 32
SECRET_C = "ef" * 32
SECRET_COORD = "11" * 32
SECRET_COORD_V2 = "22" * 32
SECRET_COORD2 = "33" * 32
SITE_SECRETS = {"a": SECRET_A, "b": SECRET_B, "c": SECRET_C}
BATCH = "batch-1"
MOMENT = 100
ISSUER = "coord"
ISSUER2 = "coord-2"
DIGEST = "bb" * 32
BOUNDARY = {"lastSeq": 5, "tail": "aa" * 32}

TOP_KEYS = ["items", "version"]
REPORT_KEYS = ["error", "id", "result", "status"]
SINGLE_RESULT_KEYS = [
    "batch", "issuer", "keyVersion", "signedAt", "policyDigest",
    "verdictDigest", "status", "digest", "boundary", "items", "version",
]


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring(
    revoked=(),
    not_before=0,
    not_after=10 ** 9,
    issuers=((ISSUER, (1,), SECRET_COORD),),
):
    ring = {
        site: [
            {
                "version": 1,
                "secret": secret,
                "notBefore": 0,
                "notAfter": 10 ** 9,
                "revoked": False,
            }
        ]
        for site, secret in SITE_SECRETS.items()
    }
    for issuer, versions, secret in issuers:
        entries = []
        for version in versions:
            version_secret = secret
            if issuer == ISSUER and version == 2:
                version_secret = SECRET_COORD_V2
            entries.append(
                {
                    "version": version,
                    "secret": version_secret,
                    "notBefore": not_before,
                    "notAfter": not_after,
                    "revoked": issuer in revoked,
                }
            )
        ring[issuer] = entries
    return ring


FULL_RING_ISSUERS = (
    (ISSUER, (1, 2), SECRET_COORD),
    (ISSUER2, (1,), SECRET_COORD2),
)


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


def make_attestation(site):
    result = verification_result(rid=f"r-{site}")
    payload = {
        "batch": BATCH,
        "keyVersion": 1,
        "result": result,
        "site": site,
    }
    signature = hmac.new(
        bytes.fromhex(SITE_SECRETS[site]), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


def agreed_items(sites=("a", "b", "c")):
    return [
        {"id": item_id, "attestation": make_attestation(site)}
        for item_id, site in zip(("i1", "i2", "i3"), sites)
    ]


def make_verdict():
    return adjudicate_recovery(agreed_items(), policy(), keyring(), MOMENT)


def make_proof(
    verdict=None,
    pol=None,
    ring=None,
    issuer=ISSUER,
    version=1,
    moment=MOMENT,
):
    return export_recovery_verdict(
        make_verdict() if verdict is None else verdict,
        policy() if pol is None else pol,
        keyring(issuers=FULL_RING_ISSUERS) if ring is None else ring,
        issuer,
        version,
        moment,
    )


def make_item(item_id, proof):
    return {"id": item_id, "proof": proof}


class BatchShapeTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring(issuers=FULL_RING_ISSUERS)
        self.proofs = [
            make_proof(issuer=ISSUER, version=1, ring=self.ring),
            make_proof(issuer=ISSUER, version=2, ring=self.ring),
            make_proof(issuer=ISSUER2, version=1, ring=self.ring),
        ]

    def batch(self, proofs=None, ring=None, moment=MOMENT):
        proofs = self.proofs if proofs is None else proofs
        items = [make_item(f"id-{i}", proof) for i, proof in enumerate(proofs)]
        return verify_recovery_verdicts(
            items, policy(), self.ring if ring is None else ring, moment
        )

    def test_top_level_shape_and_version(self):
        result = self.batch()
        self.assertIsInstance(result, dict)
        self.assertEqual(list(result.keys()), TOP_KEYS)
        self.assertEqual(result["version"], 1)
        self.assertIsInstance(result["version"], int)
        self.assertIsInstance(result["items"], list)

    def test_reports_verify_in_input_order_with_fixed_shape(self):
        result = self.batch()
        reports = result["items"]
        self.assertEqual([report["id"] for report in reports],
                         ["id-0", "id-1", "id-2"])
        for position, report in enumerate(reports):
            self.assertEqual(list(report.keys()), REPORT_KEYS, position)
            self.assertEqual(report["status"], "verified")
            self.assertIsNone(report["error"])

    def test_verified_result_is_the_single_entry_result(self):
        reports = self.batch()["items"]
        for position, (report, proof) in enumerate(
            zip(reports, self.proofs)
        ):
            with self.subTest(position=position):
                single = verify_recovery_verdict(
                    proof, policy(), self.ring, MOMENT
                )
                self.assertEqual(list(report["result"].keys()),
                                 SINGLE_RESULT_KEYS)
                self.assertEqual(report["result"], single)
                self.assertEqual(report["result"]["issuer"],
                                 [ISSUER, ISSUER, ISSUER2][position])
                self.assertEqual(report["result"]["keyVersion"],
                                 [1, 2, 1][position])

    def test_different_issuers_and_versions_in_one_batch(self):
        # Exact issuer/version selection: a mixed rotation batch verifies
        # while the keyring retains every version.
        reports = self.batch()["items"]
        self.assertTrue(
            all(report["status"] == "verified" for report in reports)
        )


class BatchValidationTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring(issuers=FULL_RING_ISSUERS)
        self.good_proof = make_proof(ring=self.ring)

    def verify(self, items, pol=None, ring=None, moment=MOMENT):
        return verify_recovery_verdicts(
            items,
            policy() if pol is None else pol,
            self.ring if ring is None else ring,
            moment,
        )

    def test_container_and_element_type_faults_are_type_errors(self):
        good = make_item("id-0", self.good_proof)
        cases = [
            (good,),  # tuple, not list
            [good, "not-a-dict"],
            [good, {"id": 1, "proof": b"x"}],
            [good, {"id": "id-1", "proof": "not-bytes"}],
        ]
        for items in cases:
            with self.subTest(items=items):
                with self.assertRaises(TypeError):
                    self.verify(items)

    def test_value_faults_are_value_errors(self):
        good = make_item("id-0", self.good_proof)
        cases = [
            [],
            [{"id": "", "proof": b"x"}],
            [good, make_item("id-0", b"x")],
            [{"id": "id-0"}],
            [{"proof": b"x"}],
            [{"id": "id-0", "proof": b"x", "other": 9}],
        ]
        for items in cases:
            with self.subTest(items=items):
                with self.assertRaises(ValueError):
                    self.verify(items)

    def test_batch_is_validated_in_full_before_any_proof_runs(self):
        # A broken proof never downgrades a structural fault: bad proofs
        # in the list do not stop the structural validation from raising.
        broken_structure = [
            make_item("ok", b"nope"),
            {"id": 7, "proof": b"also-bad-but-id-type-faults-first"},
        ]
        with self.assertRaises(TypeError):
            self.verify(broken_structure)
        duplicate_with_bad_proofs = [
            make_item("dup", b""),
            make_item("dup", b""),
        ]
        with self.assertRaises(ValueError):
            self.verify(duplicate_with_bad_proofs)

    def test_policy_keyring_and_moment_keep_single_entry_classification(self):
        good = [make_item("id-0", self.good_proof)]
        with self.assertRaises(TypeError):
            self.verify(good, pol=["not", "a", "dict"])
        with self.assertRaises(ValueError):
            self.verify(good, pol=policy(threshold=9))
        with self.assertRaises(TypeError):
            self.verify(good, ring=["not", "a", "dict"])
        with self.assertRaises(ValueError):
            self.verify(
                good,
                ring={ISSUER: [{"version": 1, "secret": "zz",
                                "notBefore": 0, "notAfter": 1,
                                "revoked": False}]},
            )
        with self.assertRaises(TypeError):
            self.verify(good, moment=True)
        with self.assertRaises(TypeError):
            self.verify(good, moment="100")
        with self.assertRaises(ValueError):
            self.verify(good, moment=-1)


class PerItemIsolationTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring(issuers=FULL_RING_ISSUERS)
        self.good_proof = make_proof(ring=self.ring)

    def report_for(self, proof, item_id="id", ring=None, moment=MOMENT,
                   pol=None):
        return verify_recovery_verdicts(
            [make_item(item_id, proof)],
            policy() if pol is None else pol,
            self.ring if ring is None else ring,
            moment,
        )["items"][0]

    def test_one_failure_never_blocks_later_items_or_changes_earlier(self):
        # Revoke only ISSUER; a proof bound to ISSUER2 stays valid, so a
        # verified item both precedes and follows the failing one.
        ring_after_revoke = keyring(
            revoked=(ISSUER,), issuers=FULL_RING_ISSUERS
        )
        revoked_proof = make_proof(issuer=ISSUER, ring=self.ring)
        valid_proof = make_proof(issuer=ISSUER2, ring=self.ring)
        items = [
            make_item("garbage", b"nope"),
            make_item("good", valid_proof),
            make_item("revoked", revoked_proof),
            make_item("good-other", valid_proof),
        ]
        result = verify_recovery_verdicts(
            items, policy(), ring_after_revoke, MOMENT
        )
        reports = result["items"]
        self.assertEqual(
            [report["id"] for report in reports],
            ["garbage", "good", "revoked", "good-other"],
        )
        self.assertEqual(
            [report["status"] for report in reports],
            ["invalid-proof", "verified", "unauthenticated", "verified"],
        )
        # The earlier verified report is unchanged by the revoked proof
        # that follows it, and the later item still verifies.
        before, failed, after = reports[1], reports[2], reports[3]
        self.assertEqual(before["result"]["issuer"], ISSUER2)
        self.assertIsNone(before["error"])
        self.assertIsNone(failed["result"])
        self.assertTrue(failed["error"])
        self.assertEqual(after["result"]["issuer"], ISSUER2)
        self.assertIsNone(after["error"])

    def test_failure_reports_have_non_null_result_and_non_empty_error(self):
        for proof, expected in (
            (b"nope", "invalid-proof"),
            (self.good_proof, "unauthenticated"),
        ):
            ring = self.ring
            if expected == "unauthenticated":
                ring = {
                    site: self.ring[site] for site in SITE_SECRETS
                }
            with self.subTest(expected=expected):
                report = self.report_for(proof, ring=ring)
                self.assertEqual(report["status"], expected)
                self.assertIsNone(report["result"])
                self.assertIsInstance(report["error"], str)
                self.assertNotEqual(report["error"], "")

    def test_failed_report_carries_no_identity_digest_or_boundary(self):
        # Unknown credentials: the payload binds an identity, but it must
        # not surface in a failed report -- result stays null and the
        # report carries only error/id/result/status.  (The error text is
        # the single-entry AuthenticationError message, which may name the
        # issuer; the signed digest and boundary never appear there.)
        ring = {site: self.ring[site] for site in SITE_SECRETS}
        report = self.report_for(self.good_proof, ring=ring)
        self.assertEqual(report["status"], "unauthenticated")
        self.assertEqual(set(report.keys()), set(REPORT_KEYS))
        self.assertIsNone(report["result"])
        self.assertNotIn(DIGEST, json.dumps(report))
        self.assertNotIn(BOUNDARY["tail"], json.dumps(report))

    def test_unauthenticated_credential_states(self):
        issuer_proof = make_proof(issuer=ISSUER, ring=self.ring)
        issuer2_proof = make_proof(issuer=ISSUER2, ring=self.ring)
        v2_proof = make_proof(issuer=ISSUER, version=2, ring=self.ring)
        cases = [
            (issuer_proof,
             keyring(revoked=(ISSUER,), issuers=FULL_RING_ISSUERS)),
            (issuer_proof,
             keyring(not_before=MOMENT + 1, issuers=FULL_RING_ISSUERS)),
            (issuer_proof,
             keyring(not_after=MOMENT - 1, issuers=FULL_RING_ISSUERS)),
            # coord missing entirely: the ring only knows coord-2.
            (issuer_proof, {ISSUER2: self.ring[ISSUER2]}),
            # v2 signature against a ring holding only v1: no fallback.
            (v2_proof, keyring()),
        ]
        for proof, ring in cases:
            with self.subTest(ring=sorted(ring.keys())):
                report = self.report_for(proof, ring=ring)
                self.assertEqual(report["status"], "unauthenticated")
                self.assertTrue(report["error"])
        # Sanity: a proof that really does belong to coord-2 verifies
        # against the coord-2-only ring above.
        self.assertEqual(
            self.report_for(
                issuer2_proof, ring={ISSUER2: self.ring[ISSUER2]}
            )["status"],
            "verified",
        )

    def test_wrong_signature_is_unauthenticated(self):
        data = json.loads(self.good_proof)
        sig = data["signature"]
        data["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        report = self.report_for(compact(data))
        self.assertEqual(report["status"], "unauthenticated")

    def test_no_fallback_from_a_dropped_version(self):
        # v2 signature against a ring that kept only v1: must not verify
        # by falling back to the v1 secret.
        v2_proof = make_proof(issuer=ISSUER, version=2, ring=self.ring)
        v1_only = keyring()
        report = self.report_for(v2_proof, ring=v1_only)
        self.assertEqual(report["status"], "unauthenticated")
        # But the same proof verifies once v2 is present.
        self.assertEqual(
            self.report_for(v2_proof, ring=self.ring)["status"],
            "verified",
        )


class InvalidProofClassificationTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring(issuers=FULL_RING_ISSUERS)
        self.good = json.loads(make_proof(ring=self.ring))

    def classify(self, raw_proof, pol=None, moment=MOMENT):
        return verify_recovery_verdicts(
            [make_item("id-0", raw_proof)],
            policy() if pol is None else pol,
            self.ring,
            moment,
        )["items"][0]["status"]

    def test_encoding_and_structure_faults_are_invalid_proof(self):
        payload = self.good["payload"]
        cases = [
            b"",
            b"nope",
            compact(self.good) + b"\n",
            compact({"payload": payload}),
            compact({"payload": payload, "signature": "z" * 64}),
            compact({"payload": payload, "signature": 7}),
            compact({"payload": [], "signature": "0" * 64}),
            compact({"payload": dict(payload, keyVersion="1"),
                     "signature": "0" * 64}),
            compact({"payload": payload, "signature": "0" * 64,
                     "extra": 1}),
        ]
        for raw in cases:
            with self.subTest(raw=raw[:40]):
                self.assertEqual(self.classify(raw), "invalid-proof")

    def test_illegal_bound_verdict_is_invalid_proof(self):
        data = copy.deepcopy(self.good)
        data["payload"]["verdict"] = {"unexpected": True}
        self.assertEqual(self.classify(compact(data)), "invalid-proof")
        typed = copy.deepcopy(self.good)
        typed["payload"]["verdict"]["version"] = "1"
        self.assertEqual(self.classify(compact(typed)), "invalid-proof")

    def test_digest_batch_threshold_and_signing_moment_faults(self):
        with self.subTest("policy digest"):
            self.assertEqual(
                self.classify(compact(self.good), pol=policy(threshold=1)),
                "invalid-proof",
            )
        with self.subTest("batch"):
            self.assertEqual(
                self.classify(compact(self.good), pol=policy(batch="other")),
                "invalid-proof",
            )
        with self.subTest("signedAt in the future"):
            self.assertEqual(
                self.classify(compact(self.good), moment=MOMENT - 1),
                "invalid-proof",
            )

    def test_threshold_bound_inside_verdict_is_invalid_proof(self):
        # A proof exported under threshold 1 re-verified against that same
        # threshold policy still fails: the bound verdict says 2.
        mismatched = make_proof(pol=policy(threshold=1), ring=self.ring)
        self.assertEqual(
            self.classify(mismatched, pol=policy(threshold=1)),
            "invalid-proof",
        )

    def test_errors_are_the_single_entry_error_text(self):
        proof = compact(self.good) + b"\n"
        with self.assertRaises(InvalidRecoveryVerdictProofError) as caught:
            verify_recovery_verdict(proof, policy(), self.ring, MOMENT)
        report = self.report(proof)
        self.assertEqual(report["error"], str(caught.exception))

    def report(self, raw_proof):
        return verify_recovery_verdicts(
            [make_item("id-0", raw_proof)], policy(), self.ring, MOMENT
        )["items"][0]


class FreshnessAndOfflineTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring(issuers=FULL_RING_ISSUERS)
        self.pol = policy()
        proof_one = make_proof(issuer=ISSUER, ring=self.ring)
        proof_two = make_proof(issuer=ISSUER2, ring=self.ring)
        self.items = [make_item("one", proof_one), make_item("two", proof_two)]

    def test_repeated_calls_are_equal_but_independent(self):
        first = verify_recovery_verdicts(
            self.items, self.pol, self.ring, MOMENT
        )
        second = verify_recovery_verdicts(
            self.items, self.pol, self.ring, MOMENT
        )
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        for left, right in zip(first["items"], second["items"]):
            self.assertIsNot(left, right)
            self.assertIsNot(left["result"], right["result"])
            self.assertIsNot(left["result"]["items"],
                             right["result"]["items"])

    def test_results_do_not_share_mutable_objects_with_inputs(self):
        result = verify_recovery_verdicts(
            self.items, self.pol, self.ring, MOMENT
        )
        result["items"].append("tampered")
        result["items"][0]["result"]["items"].append("tampered")
        again = verify_recovery_verdicts(
            self.items, self.pol, self.ring, MOMENT
        )
        self.assertEqual(len(again["items"]), 2)
        self.assertEqual(len(again["items"][0]["result"]["items"]), 3)

    def test_no_input_is_modified(self):
        items_copy = copy.deepcopy(self.items)
        pol_copy = copy.deepcopy(self.pol)
        ring_copy = copy.deepcopy(self.ring)
        verify_recovery_verdicts(self.items, self.pol, self.ring, MOMENT)
        self.assertEqual(self.items, items_copy)
        self.assertEqual(self.pol, pol_copy)
        self.assertEqual(self.ring, ring_copy)

    def test_no_file_is_read_or_written(self):
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            result = verify_recovery_verdicts(
                self.items, self.pol, self.ring, MOMENT
            )
        self.assertEqual(
            [report["status"] for report in result["items"]],
            ["verified", "verified"],
        )

    def test_authentication_error_text_is_definitive(self):
        # A failed item keeps the actual exception's message verbatim.
        ring = {site: self.ring[site] for site in SITE_SECRETS}
        with self.assertRaises(AuthenticationError) as caught:
            verify_recovery_verdict(
                self.items[0]["proof"], self.pol, ring, MOMENT
            )
        report = verify_recovery_verdicts(
            self.items[:1], self.pol, ring, MOMENT
        )["items"][0]
        self.assertEqual(report["error"], str(caught.exception))


if __name__ == "__main__":
    unittest.main()
