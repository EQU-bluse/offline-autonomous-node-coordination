"""Tests for offline batch verification of recovery verdict proofs.

Covers :func:`verify_recovery_verdicts`: the batch container contract
and its type/value taxonomy, up-front whole-batch validation, per-item
isolation and input order, the ``verified``/``invalid-proof``/
``unauthenticated`` statuses, exact issuer/version key selection with
no fallback, result shape and freshness, the purely offline guarantee
and input immutability.
"""

import copy
import hashlib
import hmac
import json
import unittest
from unittest import mock

from offline_coordination.replication import (
    adjudicate_recovery,
    export_recovery_verdict,
    verify_recovery_verdict,
    verify_recovery_verdicts,
)

SECRET_A = "ab" * 32
SECRET_B = "cd" * 32
SECRET_C = "ef" * 32
SECRET_ISSUER = "11" * 32
SECRET_ISSUER_V2 = "22" * 32
SECRET_OTHER = "33" * 32
SITE_SECRETS = {"a": SECRET_A, "b": SECRET_B, "c": SECRET_C}
BATCH = "batch-1"
MOMENT = 100
ISSUER = "coord"
OTHER_ISSUER = "coord-2"
DIGEST = "bb" * 32
BOUNDARY = {"lastSeq": 5, "tail": "aa" * 32}

ITEM_KEY_ORDER = ["error", "id", "result", "status"]
RESULT_KEYS = [
    "batch", "issuer", "keyVersion", "signedAt", "policyDigest",
    "verdictDigest", "status", "digest", "boundary", "items", "version",
]


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring(issuer_versions=(1,), revoked=(), not_before=0,
            not_after=10 ** 9, other_issuer=False):
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
    ring[ISSUER] = [
        {
            "version": version,
            "secret": SECRET_ISSUER if version == 1 else SECRET_ISSUER_V2,
            "notBefore": not_before,
            "notAfter": not_after,
            "revoked": ISSUER in revoked,
        }
        for version in issuer_versions
    ]
    if other_issuer:
        ring[OTHER_ISSUER] = [
            {
                "version": 1,
                "secret": SECRET_OTHER,
                "notBefore": 0,
                "notAfter": 10 ** 9,
                "revoked": False,
            }
        ]
    return ring


def policy(sites=("a", "b", "c"), threshold=2, batch=BATCH):
    return {"batch": batch, "sites": {site: {1} for site in sites},
            "threshold": threshold}


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


def make_attestation(site, rid):
    payload = {
        "batch": BATCH,
        "keyVersion": 1,
        "result": verification_result(rid),
        "site": site,
    }
    signature = hmac.new(
        bytes.fromhex(SITE_SECRETS[site]), compact(payload), hashlib.sha256
    ).hexdigest()
    return compact({"payload": payload, "signature": signature})


def make_verdict(pol=None, ring=None):
    pol = policy() if pol is None else pol
    ring = keyring() if ring is None else ring
    items = [
        {"id": item_id, "attestation": make_attestation(site, f"r-{site}")}
        for item_id, site in zip(("i1", "i2", "i3"), ("a", "b", "c"))
    ]
    return adjudicate_recovery(items, pol, ring, MOMENT)


def make_proof(verdict=None, pol=None, ring=None, issuer=ISSUER, version=1,
               moment=MOMENT):
    pol = policy() if pol is None else pol
    ring = keyring() if ring is None else ring
    return export_recovery_verdict(
        make_verdict(pol, ring) if verdict is None else verdict,
        pol, ring, issuer, version, moment,
    )


def make_item(item_id, proof):
    return {"id": item_id, "proof": proof}


class BatchStructureTest(unittest.TestCase):
    def test_container_and_element_type_faults(self):
        proof = make_proof()
        with self.assertRaises(TypeError):
            verify_recovery_verdicts("x", policy(), keyring(), MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_verdicts([proof], policy(), keyring(), MOMENT)
        with self.assertRaises(TypeError):
            verify_recovery_verdicts(
                [make_item(1, proof)], policy(), keyring(), MOMENT
            )
        with self.assertRaises(TypeError):
            verify_recovery_verdicts(
                [make_item("x", json.loads(proof))],
                policy(), keyring(), MOMENT,
            )

    def test_batch_value_faults(self):
        proof = make_proof()
        with self.assertRaises(ValueError):
            verify_recovery_verdicts([], policy(), keyring(), MOMENT)
        with self.assertRaises(ValueError):
            verify_recovery_verdicts(
                [make_item("", proof)], policy(), keyring(), MOMENT
            )
        with self.assertRaises(ValueError):
            verify_recovery_verdicts(
                [make_item("x", proof), make_item("x", proof)],
                policy(), keyring(), MOMENT,
            )
        for broken in (
            {"id": "x"},
            {"proof": proof},
            {"id": "x", "proof": proof, "extra": 1},
        ):
            with self.subTest(broken=broken):
                with self.assertRaises(ValueError):
                    verify_recovery_verdicts(
                        [broken], policy(), keyring(), MOMENT
                    )

    def test_shared_argument_classification(self):
        items = [make_item("x", make_proof())]
        with self.assertRaises(TypeError):
            verify_recovery_verdicts(items, [], keyring(), MOMENT)
        with self.assertRaises(ValueError):
            verify_recovery_verdicts(
                items, policy(threshold=4), keyring(), MOMENT
            )
        with self.assertRaises(TypeError):
            verify_recovery_verdicts(items, policy(), None, MOMENT)
        with self.assertRaises(ValueError):
            verify_recovery_verdicts(
                items, policy(),
                {ISSUER: [{"version": 1, "secret": "zz",
                           "notBefore": 0, "notAfter": 1,
                           "revoked": False}]},
                MOMENT,
            )
        for bad_moment in (True, 1.5, "100"):
            with self.subTest(bad=bad_moment):
                with self.assertRaises(TypeError):
                    verify_recovery_verdicts(
                        items, policy(), keyring(), bad_moment
                    )
        with self.assertRaises(ValueError):
            verify_recovery_verdicts(items, policy(), keyring(), -1)

    def test_whole_batch_is_validated_before_any_verification(self):
        # A later structural fault must raise even when an earlier item
        # would fail verification on its own.
        items = [
            make_item("bad", b"nope"),
            make_item("dup", make_proof()),
            make_item("dup", make_proof()),
        ]
        with self.assertRaises(ValueError):
            verify_recovery_verdicts(items, policy(), keyring(), MOMENT)


class BatchVerificationTest(unittest.TestCase):
    def test_all_verified_reports_input_order_and_shape(self):
        proofs = [make_proof() for _ in range(3)]
        items = [make_item(f"p{i}", proof) for i, proof in enumerate(proofs)]
        report = verify_recovery_verdicts(
            items, policy(), keyring(), MOMENT
        )
        self.assertEqual(list(report.keys()), ["items", "version"])
        self.assertEqual(report["version"], 1)
        self.assertEqual(len(report["items"]), 3)
        for index, item in enumerate(report["items"]):
            self.assertEqual(list(item.keys()), ITEM_KEY_ORDER)
            self.assertEqual(item["id"], f"p{index}")
            self.assertEqual(item["status"], "verified")
            self.assertIsNone(item["error"])
            self.assertEqual(list(item["result"].keys()), RESULT_KEYS)
            self.assertEqual(item["result"]["status"], "accepted")
            self.assertEqual(item["result"]["digest"], DIGEST)
            self.assertEqual(
                item["result"],
                verify_recovery_verdict(
                    proofs[index], policy(), keyring(), MOMENT
                ),
            )

    def test_one_failure_never_stops_or_alters_the_others(self):
        good = make_proof()
        tampered = json.loads(good)
        tampered["signature"] = ("0" if tampered["signature"][0] != "0"
                                 else "1") + tampered["signature"][1:]
        items = [
            make_item("first", good),
            make_item("bad", compact(tampered)),
            make_item("last", good),
        ]
        report = verify_recovery_verdicts(
            items, policy(), keyring(), MOMENT
        )
        statuses = [item["status"] for item in report["items"]]
        self.assertEqual(
            statuses, ["verified", "unauthenticated", "verified"]
        )
        self.assertIsNone(report["items"][1]["result"])
        self.assertIsInstance(report["items"][1]["error"], str)
        self.assertNotEqual(report["items"][1]["error"], "")
        self.assertEqual(
            report["items"][0]["result"], report["items"][2]["result"]
        )

    def test_invalid_proof_item(self):
        good = make_proof()
        cases = [
            b"nope",                                  # encoding
            good + b"\n",                             # trailing byte
            compact({"payload": {}}),                 # key set
            compact({"payload": json.loads(good)["payload"],
                     "signature": "z" * 64}),         # signature format
        ]
        verdict_broken = json.loads(good)
        verdict_broken["payload"]["verdict"] = {"unexpected": True}
        cases.append(compact(verdict_broken))         # bound verdict
        items = [make_item(f"bad-{i}", proof) for i, proof in enumerate(cases)]
        items.append(make_item("good", good))
        report = verify_recovery_verdicts(
            items, policy(), keyring(), MOMENT
        )
        for item in report["items"][:-1]:
            self.assertEqual(item["status"], "invalid-proof")
            self.assertIsNone(item["result"])
            self.assertIsInstance(item["error"], str)
            self.assertNotEqual(item["error"], "")
        self.assertEqual(report["items"][-1]["status"], "verified")

    def test_field_type_fault_inside_proof_is_invalid_proof(self):
        good = json.loads(make_proof())
        good["payload"]["keyVersion"] = True
        report = verify_recovery_verdicts(
            [make_item("typed", compact(good))], policy(), keyring(), MOMENT
        )
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_binding_faults_are_invalid_proof(self):
        proof = make_proof()
        for pol in (policy(threshold=1), policy(batch="other")):
            with self.subTest(pol=pol):
                report = verify_recovery_verdicts(
                    [make_item("x", proof)], pol, keyring(), MOMENT
                )
                self.assertEqual(
                    report["items"][0]["status"], "invalid-proof"
                )
        report = verify_recovery_verdicts(
            [make_item("x", proof)], policy(), keyring(), MOMENT - 1
        )
        self.assertEqual(report["items"][0]["status"], "invalid-proof")

    def test_unauthenticated_item(self):
        proof = make_proof()
        variants = [
            keyring(revoked=(ISSUER,)),          # revoked
            keyring(not_before=MOMENT + 1),      # not yet valid
            keyring(not_after=MOMENT - 1),       # expired
            {k: v for k, v in keyring().items() if k != ISSUER},  # unknown
        ]
        for ring in variants:
            with self.subTest(ring=ring.get(ISSUER)):
                report = verify_recovery_verdicts(
                    [make_item("x", proof)], policy(), ring, MOMENT
                )
                item = report["items"][0]
                self.assertEqual(item["status"], "unauthenticated")
                self.assertIsNone(item["result"])
                self.assertNotEqual(item["error"], "")

    def test_distinct_issuers_and_versions_select_exact_keys(self):
        ring = keyring(issuer_versions=(1, 2), other_issuer=True)
        verdict = make_verdict(ring=ring)
        proof_v1 = export_recovery_verdict(
            verdict, policy(), ring, ISSUER, 1, MOMENT
        )
        proof_v2 = export_recovery_verdict(
            verdict, policy(), ring, ISSUER, 2, MOMENT
        )
        proof_other = export_recovery_verdict(
            verdict, policy(), ring, OTHER_ISSUER, 1, MOMENT
        )
        items = [
            make_item("v1", proof_v1),
            make_item("v2", proof_v2),
            make_item("other", proof_other),
        ]
        report = verify_recovery_verdicts(items, policy(), ring, MOMENT)
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["verified", "verified", "verified"],
        )
        self.assertEqual(report["items"][0]["result"]["issuer"], ISSUER)
        self.assertEqual(report["items"][0]["result"]["keyVersion"], 1)
        self.assertEqual(report["items"][1]["result"]["keyVersion"], 2)
        self.assertEqual(
            report["items"][2]["result"]["issuer"], OTHER_ISSUER
        )
        # Dropping version 2 must not fall back to version 1.
        dropped = keyring(issuer_versions=(1,), other_issuer=True)
        report = verify_recovery_verdicts(items, policy(), dropped, MOMENT)
        self.assertEqual(
            [item["status"] for item in report["items"]],
            ["verified", "unauthenticated", "verified"],
        )


class FreshnessOfflineImmutabilityTest(unittest.TestCase):
    def test_repeated_calls_are_equal_but_independent(self):
        items = [make_item("x", make_proof()), make_item("y", make_proof())]
        first = verify_recovery_verdicts(items, policy(), keyring(), MOMENT)
        second = verify_recovery_verdicts(items, policy(), keyring(), MOMENT)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(
            first["items"][0]["result"], second["items"][0]["result"]
        )
        self.assertIsNot(
            first["items"][0]["result"]["items"],
            second["items"][0]["result"]["items"],
        )
        first["items"][0]["result"]["items"].append("tampered")
        third = verify_recovery_verdicts(items, policy(), keyring(), MOMENT)
        self.assertEqual(len(third["items"][0]["result"]["items"]), 3)

    def test_no_file_is_read_or_written(self):
        batch_items = [make_item("x", make_proof())]
        pol = policy()
        ring = keyring()
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            report = verify_recovery_verdicts(
                batch_items, pol, ring, MOMENT
            )
        self.assertEqual(report["items"][0]["status"], "verified")

    def test_inputs_are_not_modified(self):
        items = [make_item("x", make_proof()), make_item("y", b"nope")]
        pol = policy()
        ring = keyring()
        items_copy = copy.deepcopy(items)
        pol_copy = copy.deepcopy(pol)
        ring_copy = copy.deepcopy(ring)
        verify_recovery_verdicts(items, pol, ring, MOMENT)
        self.assertEqual(items, items_copy)
        self.assertEqual(pol, pol_copy)
        self.assertEqual(ring, ring_copy)


if __name__ == "__main__":
    unittest.main()
