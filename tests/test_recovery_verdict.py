"""Tests for the offline signed recovery-verdict handover.

Covers :func:`export_recovery_verdict` and
:func:`verify_recovery_verdict`: canonical proof bytes, the policy and
verdict digests, exact credential selection and current-keyring
re-checking, the batch/threshold/signedAt bindings, the
TypeError/ValueError/format-error/AuthenticationError taxonomy, result
shape and freshness, the purely offline guarantee and input
immutability.
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
SECRET_ISSUER = "11" * 32
SECRET_ISSUER_V2 = "22" * 32
SITE_SECRETS = {"a": SECRET_A, "b": SECRET_B, "c": SECRET_C}
BATCH = "batch-1"
MOMENT = 100
ISSUER = "coord"
DIGEST = "bb" * 32
OTHER_DIGEST = "cc" * 32
BOUNDARY = {"lastSeq": 5, "tail": "aa" * 32}
OTHER_BOUNDARY = {"lastSeq": 6, "tail": "dd" * 32}

RESULT_KEYS = [
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
    extra=(),
    issuer_secret=SECRET_ISSUER,
    issuer_versions=(1,),
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
    entries = []
    for version in issuer_versions:
        secret = issuer_secret if version == 1 else SECRET_ISSUER_V2
        entries.append(
            {
                "version": version,
                "secret": secret,
                "notBefore": not_before,
                "notAfter": not_after,
                "revoked": ISSUER in revoked,
            }
        )
    ring[ISSUER] = entries
    for node, entry in extra:
        ring[node] = [entry]
    return ring


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


def make_attestation(site, result=None, key_version=1, batch=BATCH):
    result = verification_result(rid=f"r-{site}") if result is None else result
    payload = {
        "batch": batch,
        "keyVersion": key_version,
        "result": result,
        "site": site,
    }
    signature = hmac.new(
        bytes.fromhex(SITE_SECRETS[site]), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


def make_item(item_id, site, result=None):
    return {"id": item_id, "attestation": make_attestation(site, result)}


def agreed_items(sites=("a", "b", "c")):
    return [
        make_item(item_id, site, verification_result(rid=f"r-{site}"))
        for item_id, site in zip(("i1", "i2", "i3"), sites)
    ]


def canonical_policy_bytes(pol):
    return compact(
        {
            "batch": pol["batch"],
            "sites": {
                site: sorted(versions)
                for site, versions in sorted(pol["sites"].items())
            },
            "threshold": pol["threshold"],
        }
    )


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.verdict = adjudicate_recovery(
            agreed_items(), policy(), keyring(), MOMENT
        )

    def export(self, verdict=None, pol=None, ring=None, moment=MOMENT):
        return export_recovery_verdict(
            self.verdict if verdict is None else verdict,
            policy() if pol is None else pol,
            keyring() if ring is None else ring,
            ISSUER,
            1,
            moment,
        )

    def verify(self, proof=None, pol=None, ring=None, moment=MOMENT):
        return verify_recovery_verdict(
            self.export() if proof is None else proof,
            policy() if pol is None else pol,
            keyring() if ring is None else ring,
            moment,
        )

    def test_proof_is_canonical_payload_and_signature_only(self):
        proof = self.export()
        self.assertIsInstance(proof, bytes)
        self.assertFalse(proof.endswith(b"\n"))
        self.assertEqual(proof[-1:], b"}")
        self.assertNotIn(b" ", proof)
        data = json.loads(proof)
        self.assertEqual(compact(data), proof)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        self.assertEqual(
            set(data["payload"].keys()),
            {"batch", "issuer", "keyVersion", "policyDigest",
             "signedAt", "verdict"},
        )

    def test_round_trip_reports_the_authenticated_verdict(self):
        result = self.verify()
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["batch"], BATCH)
        self.assertEqual(result["issuer"], ISSUER)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["signedAt"], MOMENT)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["digest"], DIGEST)
        self.assertEqual(result["boundary"], BOUNDARY)
        self.assertEqual(len(result["items"]), 3)
        self.assertEqual(
            result["verdictDigest"],
            hashlib.sha256(self.verdict).hexdigest(),
        )
        self.assertEqual(
            result["policyDigest"],
            hashlib.sha256(canonical_policy_bytes(policy())).hexdigest(),
        )

    def test_result_is_a_fresh_dict_unrelated_to_inputs(self):
        proof = self.export()
        first = self.verify(proof)
        second = self.verify(proof)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        first["items"].append("tampered")
        third = self.verify(proof)
        self.assertEqual(len(third["items"]), 3)

    def test_conflicted_and_insufficient_verdict_statuses_round_trip(self):
        fork = [
            make_item("i1", "a"),
            make_item("i2", "b"),
            make_item("i3", "c", verification_result(
                rid="r-c", digest=OTHER_DIGEST, boundary=OTHER_BOUNDARY)),
        ]
        for items, expected, pol in (
            (fork, "conflicted", policy()),
            ([make_item("i1", "a", verification_result(
                status="incomplete", error="pages exhausted",
                boundary=BOUNDARY))],
             "insufficient", policy(sites=("a",), threshold=1)),
        ):
            with self.subTest(status=expected):
                verdict = adjudicate_recovery(items, pol, keyring(), MOMENT)
                proof = self.export(verdict=verdict, pol=pol)
                result = self.verify(proof, pol=pol)
                self.assertEqual(result["status"], expected)
                self.assertIsNone(result["digest"])
                self.assertIsNone(result["boundary"])
                self.assertEqual(
                    result["verdictDigest"],
                    hashlib.sha256(verdict).hexdigest(),
                )


class PolicyDigestTest(unittest.TestCase):
    def setUp(self):
        self.verdict = adjudicate_recovery(
            agreed_items(), policy(), keyring(), MOMENT
        )

    def export(self, pol):
        return export_recovery_verdict(
            self.verdict, pol, keyring(), ISSUER, 1, MOMENT
        )

    def test_policy_digest_is_independent_of_input_container_order(self):
        # Sets and dict insertion order must not change the canonical
        # policy digest, so the same logical policy always verifies.
        pol_one = {
            "batch": BATCH,
            "threshold": 2,
            "sites": {"c": {1}, "a": {3, 1, 2}, "b": {1}},
        }
        pol_two = {
            "sites": {"b": {1}, "c": {1}, "a": {2, 1, 3}},
            "batch": BATCH,
            "threshold": 2,
        }
        self.assertEqual(
            json.loads(self.export(pol_one))["payload"]["policyDigest"],
            json.loads(self.export(pol_two))["payload"]["policyDigest"],
        )

    def test_a_different_policy_rejects_the_proof(self):
        good = self.export(policy())
        variants = (
            policy(threshold=1),
            policy(batch="other"),
            policy(sites=("a", "b")),
            {"batch": BATCH, "threshold": 2,
             "sites": {"a": {1}, "b": {1}, "c": {2}}},
        )
        for other in variants:
            with self.subTest(other=other):
                with self.assertRaises(InvalidRecoveryVerdictProofError):
                    verify_recovery_verdict(
                        good, other, keyring(), MOMENT
                    )

    def test_equivalent_policy_verifies(self):
        proof = self.export(
            {"batch": BATCH, "threshold": 2,
             "sites": {"c": {1}, "a": {1}, "b": {1}}}
        )
        result = verify_recovery_verdict(proof, policy(), keyring(), MOMENT)
        self.assertEqual(result["status"], "accepted")


class CredentialTest(unittest.TestCase):
    def setUp(self):
        self.verdict = adjudicate_recovery(
            agreed_items(), policy(), keyring(), MOMENT
        )

    def export(self, **kwargs):
        kwargs.setdefault("moment", MOMENT)
        return export_recovery_verdict(
            self.verdict,
            kwargs.pop("pol", policy()),
            kwargs.pop("ring", keyring()),
            kwargs.pop("issuer", ISSUER),
            kwargs.pop("version", 1),
            kwargs["moment"],
        )

    def test_unknown_issuer_or_version_at_export_is_auth_error(self):
        with self.assertRaises(AuthenticationError):
            self.export(issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.export(version=9)
        ring = {site: keyring()[site] for site in ("a", "b", "c")}
        with self.assertRaises(AuthenticationError):
            self.export(ring=ring)

    def test_revoked_future_and_expired_keys_at_export(self):
        with self.assertRaises(AuthenticationError):
            self.export(ring=keyring(revoked=(ISSUER,)))
        with self.assertRaises(AuthenticationError):
            self.export(ring=keyring(not_before=MOMENT + 1))
        with self.assertRaises(AuthenticationError):
            self.export(ring=keyring(not_after=MOMENT - 1))

    def test_signature_selects_exact_version_without_fallback(self):
        proof_v2 = export_recovery_verdict(
            self.verdict, policy(),
            keyring(issuer_versions=(1, 2)),
            ISSUER, 2, MOMENT,
        )
        payload = json.loads(proof_v2)["payload"]
        self.assertEqual(payload["keyVersion"], 2)
        # A ring holding both versions verifies; a ring from which v2 was
        # dropped must not fall back to v1.
        result = verify_recovery_verdict(
            proof_v2, policy(), keyring(issuer_versions=(1, 2)), MOMENT
        )
        self.assertEqual(result["keyVersion"], 2)
        with self.assertRaises(AuthenticationError):
            verify_recovery_verdict(proof_v2, policy(), keyring(), MOMENT)

    def test_current_keyring_recheck_rejects_later_revocation_or_expiry(self):
        proof = self.export()
        with self.assertRaises(AuthenticationError):
            verify_recovery_verdict(
                proof, policy(), keyring(revoked=(ISSUER,)), MOMENT
            )
        with self.assertRaises(AuthenticationError):
            verify_recovery_verdict(
                proof, policy(), keyring(not_after=MOMENT - 1), MOMENT
            )

    def test_tampered_signature_is_authentication_error(self):
        proof = self.export()
        data = json.loads(proof)
        sig = data["signature"]
        data["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        with self.assertRaises(AuthenticationError):
            verify_recovery_verdict(compact(data), policy(), keyring(), MOMENT)

    def test_tampered_signed_field_breaks_the_signature(self):
        proof = self.export()
        data = json.loads(proof)
        data["payload"]["signedAt"] = MOMENT + 1
        with self.assertRaises(AuthenticationError):
            verify_recovery_verdict(
                compact(data), policy(), keyring(), MOMENT + 1
            )


class BindingTest(unittest.TestCase):
    def setUp(self):
        self.verdict = adjudicate_recovery(
            agreed_items(), policy(), keyring(), MOMENT
        )
        self.proof = export_recovery_verdict(
            self.verdict, policy(), keyring(), ISSUER, 1, MOMENT
        )

    def test_payload_threshold_binding(self):
        # Same batch/sites but a different threshold policy: the verdict
        # adjudicated under threshold 2 cannot verify against threshold 1.
        other = policy(threshold=1)
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify_recovery_verdict(
                self.proof, other, keyring(), MOMENT
            )

    def test_payload_batch_binding(self):
        # Same sites/threshold, different batch id: rejected.
        other = policy(batch="other")
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify_recovery_verdict(
                self.proof, other, keyring(), MOMENT
            )

    def test_signed_at_in_the_future_is_a_proof_error(self):
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify_recovery_verdict(
                self.proof, policy(), keyring(), MOMENT - 1
            )

    def test_older_signature_verifies_at_a_later_moment(self):
        result = verify_recovery_verdict(
            self.proof, policy(), keyring(), MOMENT + 5000
        )
        self.assertEqual(result["signedAt"], MOMENT)

    def test_verdict_threshold_mismatch_is_rejected_at_verification(self):
        # Export signs whatever canonical verdict it is given against the
        # supplied policy; the threshold binding is enforced offline at
        # verification time.
        proof = export_recovery_verdict(
            self.verdict, policy(threshold=1), keyring(),
            ISSUER, 1, MOMENT,
        )
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify_recovery_verdict(
                proof, policy(threshold=1), keyring(), MOMENT
            )

    def test_tampered_bound_verdict_digest_fails(self):
        data = json.loads(self.proof)
        data["payload"]["verdict"]["status"] = "insufficient"
        data["payload"]["verdict"]["digest"] = None
        data["payload"]["verdict"]["boundary"] = None
        with self.assertRaises(AuthenticationError):
            verify_recovery_verdict(
                compact(data), policy(), keyring(), MOMENT
            )


class ProofStructureTest(unittest.TestCase):
    def setUp(self):
        verdict = adjudicate_recovery(
            agreed_items(), policy(), keyring(), MOMENT
        )
        self.proof = export_recovery_verdict(
            verdict, policy(), keyring(), ISSUER, 1, MOMENT
        )
        self.verdict = verdict

    def test_illegal_verdict_bytes_at_export(self):
        for bad in (b"", b"nope", b"{}", self.verdict + b"\n"):
            with self.subTest(bad=bad[:10]):
                with self.assertRaises(InvalidRecoveryVerdictError):
                    export_recovery_verdict(
                        bad, policy(), keyring(), ISSUER, 1, MOMENT
                    )

    def test_proof_structure_faults_are_proof_errors(self):
        good = json.loads(self.proof)
        payload = good["payload"]
        cases = [
            b"nope",
            self.proof + b"\n",
            compact({"payload": payload}),
            compact({"payload": payload, "signature": good["signature"],
                     "extra": 1}),
            compact({"payload": payload, "signature": "z" * 64}),
            compact({"payload": payload, "signature": "0" * 63}),
        ]
        for key in ("batch", "issuer", "keyVersion", "policyDigest",
                    "signedAt", "verdict"):
            broken = dict(payload)
            del broken[key]
            cases.append(
                compact({"payload": broken, "signature": "0" * 64})
            )
        cases.append(compact({"payload": dict(payload, keyVersion=0),
                              "signature": "0" * 64}))
        cases.append(compact({"payload": dict(payload, signedAt=-1),
                              "signature": "0" * 64}))
        cases.append(compact({"payload": dict(payload, issuer=""),
                              "signature": "0" * 64}))
        cases.append(compact({"payload": dict(payload, batch=""),
                              "signature": "0" * 64}))
        cases.append(compact({"payload": dict(payload, policyDigest="z" * 64),
                              "signature": "0" * 64}))
        # Non-canonical encoding.
        cases.append(
            b'{"payload": ' + compact(payload)
            + b', "signature": "' + good["signature"].encode() + b'"}'
        )
        for bad in cases:
            with self.subTest(bad=bad[:50]):
                with self.assertRaises(InvalidRecoveryVerdictProofError):
                    verify_recovery_verdict(bad, policy(), keyring(), MOMENT)

    def test_proof_field_type_faults_are_type_errors(self):
        good = json.loads(self.proof)
        payload = good["payload"]
        cases = [
            compact([1, 2]),
            compact({"payload": payload, "signature": 7}),
            compact({"payload": [], "signature": "0" * 64}),
            compact({"payload": dict(payload, keyVersion=True),
                     "signature": "0" * 64}),
            compact({"payload": dict(payload, keyVersion="1"),
                     "signature": "0" * 64}),
            compact({"payload": dict(payload, signedAt=0.5),
                     "signature": "0" * 64}),
            compact({"payload": dict(payload, issuer=1),
                     "signature": "0" * 64}),
            compact({"payload": dict(payload, batch=1),
                     "signature": "0" * 64}),
            compact({"payload": dict(payload, policyDigest=1),
                     "signature": "0" * 64}),
            compact({"payload": dict(payload, verdict=[]),
                     "signature": "0" * 64}),
        ]
        for bad in cases:
            with self.subTest(bad=bad[:50]):
                with self.assertRaises(TypeError):
                    verify_recovery_verdict(bad, policy(), keyring(), MOMENT)

    def test_duplicate_json_keys_are_proof_errors(self):
        text = (
            '{"payload":' + compact(json.loads(self.proof)["payload"]).decode()
            + ',"payload":{},"signature":"' + "a" * 64 + '"}'
        )
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify_recovery_verdict(
                text.encode("utf-8"), policy(), keyring(), MOMENT
            )

    def test_illegal_verdict_inside_proof_is_a_proof_error(self):
        data = json.loads(self.proof)
        data["payload"]["verdict"] = {"unexpected": True}
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify_recovery_verdict(
                compact(data), policy(), keyring(), MOMENT
            )

    def test_verdict_field_type_fault_inside_proof_is_a_proof_error(self):
        data = json.loads(self.proof)
        data["payload"]["verdict"]["threshold"] = "2"
        with self.assertRaises(InvalidRecoveryVerdictProofError):
            verify_recovery_verdict(
                compact(data), policy(), keyring(), MOMENT
            )


class ArgumentTaxonomyTest(unittest.TestCase):
    def setUp(self):
        self.verdict = adjudicate_recovery(
            agreed_items(), policy(), keyring(), MOMENT
        )
        self.proof = export_recovery_verdict(
            self.verdict, policy(), keyring(), ISSUER, 1, MOMENT
        )

    def test_export_argument_types(self):
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                json.loads(self.verdict), policy(), keyring(),
                ISSUER, 1, MOMENT,
            )
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                self.verdict, policy(), keyring(), 1, 1, MOMENT
            )
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                self.verdict, policy(), keyring(), ISSUER, "1", MOMENT
            )
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                self.verdict, policy(), keyring(), ISSUER, True, MOMENT
            )
        for bad_moment in (True, 1.5, "100"):
            with self.subTest(bad=bad_moment):
                with self.assertRaises(TypeError):
                    export_recovery_verdict(
                        self.verdict, policy(), keyring(),
                        ISSUER, 1, bad_moment,
                    )

    def test_export_argument_values(self):
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                self.verdict, policy(), keyring(), "", 1, MOMENT
            )
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                self.verdict, policy(), keyring(), ISSUER, 0, MOMENT
            )
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                self.verdict, policy(), keyring(), ISSUER, 1, -1
            )
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                self.verdict, policy(threshold=0), keyring(),
                ISSUER, 1, MOMENT,
            )
        with self.assertRaises(TypeError):
            export_recovery_verdict(
                self.verdict, policy(), None, ISSUER, 1, MOMENT
            )
        with self.assertRaises(ValueError):
            export_recovery_verdict(
                self.verdict, policy(),
                {ISSUER: [{"version": 1, "secret": "zz",
                           "notBefore": 0, "notAfter": 1,
                           "revoked": False}]},
                ISSUER, 1, MOMENT,
            )

    def test_verify_argument_types_and_values(self):
        with self.assertRaises(TypeError):
            verify_recovery_verdict(json.loads(self.proof), policy(),
                                   keyring(), MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_verdict(self.proof, policy(), None, MOMENT)
        for bad_moment in (True, 1.5, "100"):
            with self.subTest(bad=bad_moment):
                with self.assertRaises(TypeError):
                    verify_recovery_verdict(
                        self.proof, policy(), keyring(), bad_moment
                    )
        with self.assertRaises(ValueError):
            verify_recovery_verdict(self.proof, policy(), keyring(), -1)
        with self.assertRaises(ValueError):
            verify_recovery_verdict(
                self.proof, policy(threshold=4), keyring(), MOMENT
            )

    def test_format_errors_are_value_errors(self):
        self.assertTrue(issubclass(InvalidRecoveryVerdictError, ValueError))
        self.assertTrue(
            issubclass(InvalidRecoveryVerdictProofError, ValueError)
        )
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class NonAsciiAndEncodingTest(unittest.TestCase):
    def test_non_ascii_batch_and_site_names_are_preserved(self):
        batch = "批次-1"
        pol = {"batch": batch, "sites": {"站α": {1}, "站β": {1}},
               "threshold": 2}
        ring = keyring()
        ring["站α"] = [{"version": 1, "secret": SECRET_A, "notBefore": 0,
                       "notAfter": 10 ** 9, "revoked": False}]
        ring["站β"] = [{"version": 1, "secret": SECRET_B, "notBefore": 0,
                       "notAfter": 10 ** 9, "revoked": False}]

        def att(site, rid):
            payload = {"batch": batch, "keyVersion": 1,
                       "result": verification_result(rid=rid), "site": site}
            secret = SECRET_A if site == "站α" else SECRET_B
            sig = hmac.new(bytes.fromhex(secret), compact(payload),
                           hashlib.sha256).hexdigest()
            return compact({"payload": payload, "signature": sig})

        items = [
            {"id": "α", "attestation": att("站α", "r1")},
            {"id": "β", "attestation": att("站β", "r2")},
        ]
        verdict = adjudicate_recovery(items, pol, ring, MOMENT)
        proof = export_recovery_verdict(
            verdict, pol, ring, ISSUER, 1, MOMENT
        )
        self.assertIn("批".encode("utf-8"), proof)
        result = verify_recovery_verdict(proof, pol, ring, MOMENT)
        self.assertEqual(result["batch"], batch)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(
            result["verdictDigest"], hashlib.sha256(verdict).hexdigest()
        )


class OfflineAndImmutabilityTest(unittest.TestCase):
    def test_no_file_is_read_or_written(self):
        verdict = adjudicate_recovery(
            agreed_items(), policy(), keyring(), MOMENT
        )
        pol = policy()
        ring = keyring()
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            proof = export_recovery_verdict(
                verdict, pol, ring, ISSUER, 1, MOMENT
            )
            result = verify_recovery_verdict(proof, pol, ring, MOMENT)
        self.assertEqual(result["status"], "accepted")

    def test_inputs_are_not_modified(self):
        verdict = adjudicate_recovery(
            agreed_items(), policy(), keyring(), MOMENT
        )
        pol = {"batch": BATCH, "threshold": 2,
               "sites": {"c": {1}, "a": {1}, "b": {1}}}
        ring = keyring()
        verdict_copy = bytes(verdict)
        pol_copy = copy.deepcopy(pol)
        ring_copy = copy.deepcopy(ring)
        proof = export_recovery_verdict(
            verdict, pol, ring, ISSUER, 1, MOMENT
        )
        proof_copy = bytes(proof)
        verify_recovery_verdict(proof, pol, ring, MOMENT)
        self.assertEqual(verdict, verdict_copy)
        self.assertEqual(pol, pol_copy)
        self.assertEqual(ring, ring_copy)
        self.assertEqual(proof, proof_copy)


class EmbeddedResultCompatTest(unittest.TestCase):
    """adjudicate_recovery accepts every producer-shaped failed result."""

    def _attestation(self, result, site="a"):
        payload = {"batch": BATCH, "keyVersion": 1, "result": result,
                   "site": site}
        sig = hmac.new(bytes.fromhex(SECRET_A), compact(payload),
                       hashlib.sha256).hexdigest()
        return compact({"payload": payload, "signature": sig})

    def test_failed_result_with_null_identity_and_boundary(self):
        # The exact shape verify_recovery_checkpoints emits for an
        # unparseable checkpoint.
        result = verification_result(
            status="invalid-checkpoint",
            error="invalid recovery checkpoint: nope",
            issuer=None,
            key_version=None,
            boundary=None,
        )
        data = json.loads(
            adjudicate_recovery(
                [{"id": "x", "attestation": self._attestation(result)}],
                policy(sites=("a",), threshold=1), keyring(), MOMENT,
            )
        )
        report = data["items"][0]
        self.assertEqual(report["reason"], "not-verified")
        self.assertEqual(report["site"], "a")
        # The report carries the attestation payload's key version; the
        # null identity lives inside the embedded failed result.
        self.assertEqual(report["keyVersion"], 1)
        self.assertIsNone(report["boundary"])
        self.assertEqual(report["digest"], DIGEST)
        self.assertEqual(report["status"], "invalid-checkpoint")

    def test_unauthenticated_result_keeps_identity_and_null_boundary(self):
        result = verification_result(
            status="unauthenticated",
            error="no credentials for issuer",
            issuer="issuer-x",
            key_version=1,
            boundary=None,
        )
        data = json.loads(
            adjudicate_recovery(
                [{"id": "x", "attestation": self._attestation(result)}],
                policy(sites=("a",), threshold=1), keyring(), MOMENT,
            )
        )
        report = data["items"][0]
        self.assertEqual(report["reason"], "not-verified")
        self.assertIsNone(report["boundary"])
        self.assertEqual(report["status"], "unauthenticated")

    def test_null_issuer_with_non_null_identity_is_invalid_attestation(self):
        cases = (
            verification_result(
                status="invalid-checkpoint", error="x",
                issuer=None, key_version=1, boundary=BOUNDARY,
            ),
            verification_result(
                status="invalid-checkpoint", error="x",
                issuer="issuer-x", key_version=None, boundary=BOUNDARY,
            ),
        )
        for result in cases:
            with self.subTest(result=result["issuer"]):
                data = json.loads(
                    adjudicate_recovery(
                        [{"id": "x", "attestation": self._attestation(result)}],
                        policy(sites=("a",), threshold=1), keyring(), MOMENT,
                    )
                )
                self.assertEqual(
                    data["items"][0]["reason"], "invalid-attestation"
                )


if __name__ == "__main__":
    unittest.main()
