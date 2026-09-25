"""Tests for the signed batch verification receipt.

Covers :func:`sign_batch_receipt` and :func:`verify_batch_receipt`:
the receipt/payload/item key sets, input-order binding of ids and proof
digests, reuse of the exact batch verification reports (failures keep
status, error and a null result), the policy digest, canonical
encoding, exact issuer/version key selection, the offline verification
contract (moment binding, current-credential checks, deep-copy result)
and the ``TypeError``/``ValueError``/``InvalidBatchReceiptError``/
``AuthenticationError`` taxonomy.
"""

import copy
import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    AuthenticationError,
    InvalidBatchReceiptError,
    adjudicate_recovery,
    export_recovery_verdict,
    sign_batch_receipt,
    verify_batch_receipt,
    verify_recovery_verdicts,
)

SECRET_A = "ab" * 32
SECRET_B = "cd" * 32
SECRET_C = "ef" * 32
SECRET_COORD = "11" * 32
SECRET_COORD_V2 = "22" * 32
SITE_SECRETS = {"a": SECRET_A, "b": SECRET_B, "c": SECRET_C}
BATCH = "batch-1"
MOMENT = 100
ISSUER = "coord"
DIGEST = "bb" * 32
BOUNDARY = {"lastSeq": 5, "tail": "aa" * 32}

PAYLOAD_KEYS = {"issuer", "items", "keyVersion", "moment", "policy",
                "version"}
ITEM_KEYS = {"digest", "id", "report"}
REPORT_KEYS = {"error", "id", "result", "status"}


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring(revoked=()):
    ring = {
        site: [
            {"version": 1, "secret": secret, "notBefore": 0,
             "notAfter": 10 ** 9, "revoked": False}
        ]
        for site, secret in SITE_SECRETS.items()
    }
    ring[ISSUER] = [
        {"version": 1, "secret": SECRET_COORD, "notBefore": 0,
         "notAfter": 10 ** 9, "revoked": ISSUER in revoked},
        {"version": 2, "secret": SECRET_COORD_V2, "notBefore": 0,
         "notAfter": 10 ** 9, "revoked": ISSUER in revoked},
    ]
    return ring


def policy():
    return {"batch": BATCH, "sites": {s: {1} for s in ("a", "b", "c")},
            "threshold": 2}


def policy_digest(pol):
    canonical = {
        "batch": pol["batch"],
        "sites": {site: sorted(pol["sites"][site])
                  for site in sorted(pol["sites"])},
        "threshold": pol["threshold"],
    }
    return hashlib.sha256(compact(canonical)).hexdigest()


def make_attestation(site):
    result = {"boundary": BOUNDARY, "digest": DIGEST, "error": None,
              "id": f"r-{site}", "issuer": "issuer-x", "keyVersion": 1,
              "status": "verified"}
    payload = {"batch": BATCH, "keyVersion": 1, "result": result,
               "site": site}
    signature = hmac.new(
        bytes.fromhex(SITE_SECRETS[site]), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


def make_proof(moment=MOMENT):
    verdict = adjudicate_recovery(
        [{"id": f"i{n}", "attestation": make_attestation(site)}
         for n, site in enumerate(("a", "b", "c"))],
        policy(), keyring(), moment,
    )
    return export_recovery_verdict(
        verdict, policy(), keyring(), ISSUER, 1, moment
    )


class ReceiptFixture(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.pol = policy()
        self.good_proof = make_proof()
        self.bad_proof = compact(
            {"payload": {}, "signature": "00" * 32}
        )
        self.items = [
            {"id": "p1", "proof": self.good_proof},
            {"id": "bad", "proof": self.bad_proof},
            {"id": "p2", "proof": make_proof()},
        ]

    def sign(self, items=None, ring=None, moment=MOMENT, issuer=ISSUER,
             version=2):
        return sign_batch_receipt(
            self.items if items is None else items,
            self.pol,
            self.ring if ring is None else ring,
            moment,
            issuer,
            version,
        )

    def payload(self, receipt):
        return json.loads(receipt.decode("utf-8"))["payload"]


class SignShapeTest(ReceiptFixture):
    def test_receipt_is_canonical_with_exact_top_keys(self):
        receipt = self.sign()
        data = json.loads(receipt.decode("utf-8"))
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        self.assertEqual(receipt, compact(data))
        self.assertNotIn(receipt[-1:], b"\n\r\t ")

    def test_payload_binds_exact_fields(self):
        payload = self.payload(self.sign())
        self.assertEqual(set(payload.keys()), PAYLOAD_KEYS)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["issuer"], ISSUER)
        self.assertEqual(payload["keyVersion"], 2)
        self.assertEqual(payload["moment"], MOMENT)
        self.assertEqual(payload["policy"], policy_digest(self.pol))

    def test_items_bind_ids_and_proof_digests_in_input_order(self):
        payload = self.payload(self.sign())
        self.assertEqual([i["id"] for i in payload["items"]],
                         ["p1", "bad", "p2"])
        for item, source in zip(payload["items"], self.items):
            self.assertEqual(set(item.keys()), ITEM_KEYS)
            self.assertEqual(
                item["digest"],
                hashlib.sha256(source["proof"]).hexdigest(),
            )

    def test_items_bind_the_exact_batch_reports(self):
        payload = self.payload(self.sign())
        batch = verify_recovery_verdicts(
            self.items, self.pol, self.ring, MOMENT
        )
        self.assertEqual(
            [item["report"] for item in payload["items"]], batch["items"]
        )
        for item in payload["items"]:
            self.assertEqual(set(item["report"].keys()), REPORT_KEYS)

    def test_failed_item_keeps_status_error_and_null_result(self):
        payload = self.payload(self.sign())
        report = payload["items"][1]["report"]
        self.assertEqual(report["status"], "invalid-proof")
        self.assertIsInstance(report["error"], str)
        self.assertNotEqual(report["error"], "")
        self.assertIsNone(report["result"])
        self.assertNotIn("issuer", report)
        self.assertNotIn("boundary", report)

    def test_signature_is_hmac_of_canonical_payload(self):
        receipt = self.sign()
        data = json.loads(receipt.decode("utf-8"))
        expected = hmac.new(
            bytes.fromhex(SECRET_COORD_V2),
            compact(data["payload"]),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(data["signature"], expected)

    def test_sign_does_not_modify_inputs(self):
        snapshot = copy.deepcopy(self.items)
        self.sign()
        self.assertEqual(self.items, snapshot)


class SignValidationTest(ReceiptFixture):
    def test_batch_faults_raise_before_signing(self):
        with self.assertRaises(ValueError):
            self.sign(items=[])
        with self.assertRaises(ValueError):
            self.sign(items=[{"id": "x", "proof": self.good_proof},
                             {"id": "x", "proof": self.good_proof}])
        with self.assertRaises(TypeError):
            self.sign(items=[{"id": "x", "proof": "not-bytes"}])
        with self.assertRaises(ValueError):
            self.sign(items=[{"id": "x", "proof": self.good_proof,
                              "extra": 1}])

    def test_issuer_and_version_boundaries(self):
        with self.assertRaises(TypeError):
            self.sign(issuer=1)
        with self.assertRaises(ValueError):
            self.sign(issuer="")
        with self.assertRaises(TypeError):
            self.sign(version=True)
        with self.assertRaises(ValueError):
            self.sign(version=0)

    def test_moment_boundaries(self):
        with self.assertRaises(TypeError):
            self.sign(moment=True)
        with self.assertRaises(ValueError):
            self.sign(moment=-1)

    def test_unknown_or_unusable_credentials_raise(self):
        with self.assertRaises(AuthenticationError):
            self.sign(issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.sign(version=3)
        with self.assertRaises(AuthenticationError):
            self.sign(ring=keyring(revoked=(ISSUER,)))


class VerifyReceiptTest(ReceiptFixture):
    def setUp(self):
        super().setUp()
        self.receipt = self.sign()

    def test_verify_returns_fresh_deep_copy_of_payload(self):
        expected = self.payload(self.receipt)
        first = verify_batch_receipt(
            self.receipt, self.pol, self.ring, MOMENT
        )
        self.assertEqual(first, expected)
        first["items"][0]["report"]["status"] = "mutated"
        second = verify_batch_receipt(
            self.receipt, self.pol, self.ring, MOMENT
        )
        self.assertEqual(second, expected)

    def test_verify_accepts_later_verification_moment(self):
        result = verify_batch_receipt(
            self.receipt, self.pol, self.ring, MOMENT + 500
        )
        self.assertEqual(result["moment"], MOMENT)

    def test_non_bytes_receipt_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_batch_receipt("receipt", self.pol, self.ring, MOMENT)

    def test_trailing_byte_rejected(self):
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt(
                self.receipt + b"\n", self.pol, self.ring, MOMENT
            )

    def test_invalid_batch_receipt_error_is_value_error(self):
        self.assertTrue(issubclass(InvalidBatchReceiptError, ValueError))

    def test_policy_digest_mismatch_rejected(self):
        other = {"batch": "batch-2",
                 "sites": {s: {1} for s in ("a", "b", "c")}, "threshold": 2}
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt(self.receipt, other, self.ring, MOMENT)

    def test_future_receipt_rejected(self):
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt(
                self.receipt, self.pol, self.ring, MOMENT - 1
            )

    def test_bad_signature_rejected(self):
        data = json.loads(self.receipt.decode("utf-8"))
        tampered = compact(
            {"payload": data["payload"], "signature": "ff" * 32}
        )
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt(tampered, self.pol, self.ring, MOMENT)

    def test_reordered_items_break_the_signature(self):
        data = json.loads(self.receipt.decode("utf-8"))
        payload = data["payload"]
        payload["items"] = list(reversed(payload["items"]))
        tampered = compact(
            {"payload": payload, "signature": data["signature"]}
        )
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt(tampered, self.pol, self.ring, MOMENT)

    def test_current_credentials_are_rechecked(self):
        revoked = keyring(revoked=(ISSUER,))
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt(self.receipt, self.pol, revoked, MOMENT)

    def test_wrong_key_version_credentials_rejected(self):
        ring = keyring()
        ring[ISSUER] = [entry for entry in ring[ISSUER]
                        if entry["version"] != 2]
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt(self.receipt, self.pol, ring, MOMENT)

    def test_forged_report_binding_rejected(self):
        payload = copy.deepcopy(self.payload(self.receipt))
        payload["items"][0]["report"]["id"] = "other"
        signature = hmac.new(
            bytes.fromhex(SECRET_COORD_V2), compact(payload), hashlib.sha256
        ).hexdigest()
        forged = compact({"payload": payload, "signature": signature})
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt(forged, self.pol, self.ring, MOMENT)

    def test_forged_failure_with_result_rejected(self):
        payload = copy.deepcopy(self.payload(self.receipt))
        payload["items"][1]["report"]["result"] = {"status": "verified"}
        signature = hmac.new(
            bytes.fromhex(SECRET_COORD_V2), compact(payload), hashlib.sha256
        ).hexdigest()
        forged = compact({"payload": payload, "signature": signature})
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt(forged, self.pol, self.ring, MOMENT)

    def test_verification_does_not_modify_inputs(self):
        snapshot = self.receipt
        verify_batch_receipt(self.receipt, self.pol, self.ring, MOMENT)
        self.assertEqual(self.receipt, snapshot)


if __name__ == "__main__":
    unittest.main()
