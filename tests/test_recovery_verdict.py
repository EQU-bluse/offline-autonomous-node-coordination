"""Tests for signed recovery verdict proofs.

Covers :func:`export_recovery_verdict` and
:func:`verify_recovery_verdict`: the canonical proof bytes, the policy
digest normalization, the exact key selection, the offline
verification of both digests and every binding, the error taxonomy
(TypeError / ValueError / InvalidRecoveryVerdictError /
InvalidRecoveryVerdictProofError / AuthenticationError), the purely
offline guarantee and input immutability.
"""

import copy
import hashlib
import hmac
import json
import unittest
from unittest import mock

from offline_coordination.replication import (
    AuthenticationError,
    InvalidRecoveryVerdictError,
    InvalidRecoveryVerdictProofError,
    adjudicate_recovery,
    export_recovery_verdict,
    verify_recovery_verdict,
)

SECRET_A = "ab" * 32
SECRET_B = "cd" * 32
SECRET_C = "ef" * 32
ISSUER_SECRET = "09" * 32
SECRETS = {"a": SECRET_A, "b": SECRET_B, "c": SECRET_C}
BATCH = "batch-1"
MOMENT = 10
ISSUER = "issuer-1"
DIGEST = "bb" * 32
BOUNDARY = {"lastSeq": 5, "tail": "aa" * 32}

RESULT_KEYS = [
    "batch", "issuer", "keyVersion", "signedAt", "policyDigest",
    "verdictDigest", "status", "digest", "boundary", "items", "version",
]


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring(revoked=(), not_before=0, not_after=10 ** 9, with_issuer=True):
    ring = {
        site: [
            {
                "version": 1,
                "secret": secret,
                "notBefore": not_before,
                "notAfter": not_after,
                "revoked": site in revoked,
            }
        ]
        for site, secret in SECRETS.items()
    }
    if with_issuer:
        ring[ISSUER] = [
            {
                "version": 2,
                "secret": ISSUER_SECRET,
                "notBefore": not_before,
                "notAfter": not_after,
                "revoked": ISSUER in revoked,
            }
        ]
    return ring


def policy(sites=("a", "b", "c"), threshold=2, batch=BATCH):
    return {"batch": batch, "sites": {site: {1} for site in sites},
            "threshold": threshold}


def canonical_policy(pol):
    return {
        "batch": pol["batch"],
        "sites": {site: sorted(versions)
                  for site, versions in sorted(pol["sites"].items())},
        "threshold": pol["threshold"],
    }


def policy_digest(pol):
    return hashlib.sha256(compact(canonical_policy(pol))).hexdigest()


def verification_result(rid, digest=DIGEST, boundary=BOUNDARY):
    return {
        "boundary": boundary,
        "digest": digest,
        "error": None,
        "id": rid,
        "issuer": "issuer-x",
        "keyVersion": 1,
        "status": "verified",
    }


def make_attestation(site, result, key_version=1, batch=BATCH):
    payload = {
        "batch": batch,
        "keyVersion": key_version,
        "result": result,
        "site": site,
    }
    signature = hmac.new(
        bytes.fromhex(SECRETS[site]), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


def make_verdict(pol=None, moment=MOMENT):
    pol = policy() if pol is None else pol
    items = [
        {"id": f"i-{site}",
         "attestation": make_attestation(site, verification_result(f"r-{site}"))}
        for site in sorted(pol["sites"])
    ]
    return adjudicate_recovery(items, pol, keyring(), moment)


def export(verdict=None, pol=None, ring=None, issuer=ISSUER, version=2,
           moment=MOMENT):
    return export_recovery_verdict(
        make_verdict() if verdict is None else verdict,
        policy() if pol is None else pol,
        keyring() if ring is None else ring,
        issuer,
        version,
        moment,
    )


def verify(proof, pol=None, ring=None, moment=MOMENT):
    return verify_recovery_verdict(
        proof,
        policy() if pol is None else pol,
        keyring() if ring is None else ring,
        moment,
    )


class ExportTest(unittest.TestCase):
    def test_proof_is_canonical_and_carries_only_payload_and_signature(self):
        proof = export()
        self.assertIsInstance(proof, bytes)
        self.assertFalse(proof.endswith(b"\n"))
        self.assertNotIn(b" ", proof)
        data = json.loads(proof)
        self.assertEqual(compact(data), proof)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        payload = data["payload"]
        self.assertEqual(
            set(payload.keys()),
            {"batch", "issuer", "keyVersion", "signedAt", "policyDigest",
             "verdict"},
        )
        self.assertEqual(payload["batch"], BATCH)
        self.assertEqual(payload["issuer"], ISSUER)
        self.assertEqual(payload["keyVersion"], 2)
        self.assertEqual(payload["signedAt"], MOMENT)
        self.assertEqual(payload["policyDigest"], policy_digest(policy()))

    def test_signature_is_the_hmac_of_the_canonical_payload(self):
        proof = export()
        data = json.loads(proof)
        expected = hmac.new(
            bytes.fromhex(ISSUER_SECRET),
            compact(data["payload"]),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(data["signature"], expected)

    def test_policy_digest_normalizes_sites_and_versions(self):
        pol = {"batch": BATCH, "threshold": 2,
               "sites": {"b": {3, 1}, "a": {2}}}
        proof = export(pol=pol)
        payload = json.loads(proof)["payload"]
        self.assertEqual(payload["policyDigest"], policy_digest(pol))
        # The canonical form sorts sites and turns sets into arrays.
        self.assertEqual(
            canonical_policy(pol),
            {"batch": BATCH, "sites": {"a": [2], "b": [1, 3]},
             "threshold": 2},
        )

    def test_verdict_is_embedded_whole(self):
        verdict = make_verdict()
        payload = json.loads(export(verdict=verdict))["payload"]
        self.assertEqual(compact(payload["verdict"]), verdict)

    def test_type_faults(self):
        verdict = make_verdict()
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                "x", policy(), keyring(), ISSUER, 2, MOMENT)
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                verdict, None, keyring(), ISSUER, 2, MOMENT)
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                verdict, policy(), None, ISSUER, 2, MOMENT)
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                verdict, policy(), keyring(), 1, 2, MOMENT)
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                verdict, policy(), keyring(), ISSUER, True, MOMENT)
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                verdict, policy(), keyring(), ISSUER, 2, True)

    def test_value_faults(self):
        verdict = make_verdict()
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                verdict, policy(), keyring(), "", 2, MOMENT)
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                verdict, policy(), keyring(), ISSUER, 0, MOMENT)
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                verdict, policy(), keyring(), ISSUER, 2, -1)
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                verdict, policy(threshold=9), keyring(), ISSUER, 2, MOMENT)

    def test_invalid_verdict_bytes(self):
        good = make_verdict()
        tampered = json.loads(good)
        tampered["status"] = "bogus"
        accepted_without_digest = json.loads(good)
        accepted_without_digest["digest"] = None
        cases = [
            good + b"\n",
            good[:-1] + b" ",
            b"not json",
            compact(tampered),
            compact(accepted_without_digest),
            good.replace(b'"threshold":2', b'"threshold":0'),
        ]
        for raw in cases:
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(InvalidRecoveryVerdictError):
                    export_recovery_verdict(
                        raw, policy(), keyring(), ISSUER, 2, MOMENT)
        self.assertTrue(issubclass(InvalidRecoveryVerdictError, ValueError))

    def test_credential_faults(self):
        verdict = make_verdict()
        with self.assertRaises(AuthenticationError):
            export_recovery_verdict(
                verdict, policy(), keyring(), "nobody", 2, MOMENT)
        with self.assertRaises(AuthenticationError):
            export_recovery_verdict(
                verdict, policy(), keyring(), ISSUER, 9, MOMENT)
        with self.assertRaises(AuthenticationError):
            export_recovery_verdict(
                verdict, policy(), keyring(revoked=(ISSUER,)),
                ISSUER, 2, MOMENT)
        with self.assertRaises(AuthenticationError):
            export_recovery_verdict(
                verdict, policy(), keyring(not_before=MOMENT + 1),
                ISSUER, 2, MOMENT)
        with self.assertRaises(AuthenticationError):
            export_recovery_verdict(
                verdict, policy(), keyring(not_after=MOMENT - 1),
                ISSUER, 2, MOMENT)

    def test_no_file_io_and_inputs_untouched(self):
        verdict = make_verdict()
        pol = policy()
        ring = keyring()
        verdict_copy = bytes(verdict)
        pol_copy = copy.deepcopy(pol)
        ring_copy = copy.deepcopy(ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            proof = export_recovery_verdict(verdict, pol, ring, ISSUER, 2, MOMENT)
        self.assertIsInstance(proof, bytes)
        self.assertEqual(verdict, verdict_copy)
        self.assertEqual(pol, pol_copy)
        self.assertEqual(ring, ring_copy)


class VerifyTest(unittest.TestCase):
    def test_round_trip_accepted(self):
        verdict = make_verdict()
        proof = export(verdict=verdict)
        result = verify(proof)
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertEqual(result["batch"], BATCH)
        self.assertEqual(result["issuer"], ISSUER)
        self.assertEqual(result["keyVersion"], 2)
        self.assertEqual(result["signedAt"], MOMENT)
        self.assertEqual(result["policyDigest"], policy_digest(policy()))
        self.assertEqual(
            result["verdictDigest"], hashlib.sha256(verdict).hexdigest())
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["digest"], DIGEST)
        self.assertEqual(result["boundary"], BOUNDARY)
        self.assertEqual(len(result["items"]), 3)
        self.assertEqual(result["version"], 1)

    def test_round_trip_conflicted_and_insufficient(self):
        conflicted_items = [
            {"id": "i1",
             "attestation": make_attestation(
                 "a", verification_result("r1"))},
            {"id": "i2",
             "attestation": make_attestation(
                 "b", verification_result("r2", digest="cc" * 32,
                                          boundary={"lastSeq": 6,
                                                    "tail": "dd" * 32}))},
        ]
        conflicted = adjudicate_recovery(
            conflicted_items, policy(), keyring(), MOMENT)
        self.assertEqual(verify(export(verdict=conflicted))["status"],
                         "conflicted")
        insufficient = adjudicate_recovery(
            conflicted_items[:1], policy(), keyring(), MOMENT)
        result = verify(export(verdict=insufficient))
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["digest"])
        self.assertIsNone(result["boundary"])

    def test_result_is_a_fresh_dict(self):
        proof = export()
        first = verify(proof)
        second = verify(proof)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        first["items"].append("junk")
        self.assertEqual(len(verify(proof)["items"]), 3)

    def test_type_faults(self):
        proof = export()
        with self.assertRaises(TypeError):
            verify_recovery_verdict("x", policy(), keyring(), MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_verdict(proof, None, keyring(), MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_verdict(proof, policy(), None, MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_verdict(proof, policy(), keyring(), True)

    def test_value_faults(self):
        proof = export()
        with self.assertRaises(ValueError):
            verify_recovery_verdict(proof, policy(batch=""), keyring(), MOMENT)
        with self.assertRaises(ValueError):
            verify_recovery_verdict(proof, policy(), keyring(), -1)

    def test_proof_structure_faults(self):
        proof = export()
        data = json.loads(proof)
        cases = [proof + b"\n", proof[:-1] + b" ", b"not json"]
        wrong_keys = dict(data)
        wrong_keys["extra"] = 1
        cases.append(compact(wrong_keys))
        bad_signature_format = {"payload": data["payload"], "signature": "ZZ"}
        cases.append(compact(bad_signature_format))
        for raw in cases:
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(InvalidRecoveryVerdictProofError):
                    verify(raw)
        self.assertTrue(
            issubclass(InvalidRecoveryVerdictProofError, ValueError))

    def test_digest_and_binding_faults(self):
        proof = export()
        data = json.loads(proof)

        def resigned(payload):
            signature = hmac.new(
                bytes.fromhex(ISSUER_SECRET), compact(payload), hashlib.sha256
            ).hexdigest()
            return compact({"payload": payload, "signature": signature})

        # A different policy no longer matches the signed digest.
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify(proof, pol=policy(batch="other-batch"))
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify(proof, pol=policy(threshold=1))
        # A payload re-signed over a wrong batch still fails the batch
        # binding even though its signature is well-formed.
        wrong_batch = dict(data["payload"])
        wrong_batch["batch"] = "other-batch"
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify(resigned(wrong_batch))
        # A proof bound to a threshold-1 policy whose verdict still says
        # threshold 2 fails the threshold binding.
        wrong_threshold = dict(data["payload"])
        wrong_threshold["policyDigest"] = policy_digest(policy(threshold=1))
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify(resigned(wrong_threshold), pol=policy(threshold=1))

    def test_authentication_faults(self):
        proof = export()
        data = json.loads(proof)
        tampered = dict(data)
        signature = data["signature"]
        tampered["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
        with self.assertRaises(AuthenticationError):
            verify(compact(tampered))
        with self.assertRaises(AuthenticationError):
            verify(proof, ring=keyring(revoked=(ISSUER,)))
        with self.assertRaises(AuthenticationError):
            verify(proof, ring=keyring(not_after=MOMENT - 1))
        with self.assertRaises(AuthenticationError):
            verify(proof, ring=keyring(not_before=MOMENT + 1))
        ring = keyring()
        del ring[ISSUER]
        with self.assertRaises(AuthenticationError):
            verify(proof, ring=ring)

    def test_key_rotation_selects_the_exact_version(self):
        verdict = make_verdict()
        ring = keyring()
        ring[ISSUER].append(
            {"version": 3, "secret": "ff" * 32, "notBefore": 0,
             "notAfter": 10 ** 9, "revoked": False}
        )
        proof_v2 = export_recovery_verdict(
            verdict, policy(), ring, ISSUER, 2, MOMENT)
        proof_v3 = export_recovery_verdict(
            verdict, policy(), ring, ISSUER, 3, MOMENT)
        self.assertEqual(
            verify_recovery_verdict(proof_v2, policy(), ring, MOMENT)
            ["keyVersion"], 2)
        self.assertEqual(
            verify_recovery_verdict(proof_v3, policy(), ring, MOMENT)
            ["keyVersion"], 3)

    def test_no_file_io_and_inputs_untouched(self):
        proof = export()
        pol = policy()
        ring = keyring()
        proof_copy = bytes(proof)
        pol_copy = copy.deepcopy(pol)
        ring_copy = copy.deepcopy(ring)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            verify_recovery_verdict(proof, pol, ring, MOMENT)
        self.assertEqual(proof, proof_copy)
        self.assertEqual(pol, pol_copy)
        self.assertEqual(ring, ring_copy)


if __name__ == "__main__":
    unittest.main()
