"""Tests for batch receipt chain verification and fork detection.

Covers :func:`verify_batch_receipt_chains`: the full-batch pre-validation
and its ``TypeError``/``ValueError`` taxonomy, the per-chain isolation
and failure statuses, the input-order reports, the receipt-digest
grouping, fork detection across divergent audiences (a path-prefix
extension never forks) and the freshness of the result.  Also pins the
single-chain classification of public field type faults inside a hop's
proof as ``TypeError``.
"""

import copy
import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    InvalidReceiptDelegationError,
    verify_batch_receipt_chain,
    verify_batch_receipt_chains,
)

SECRET_COORD = "11" * 32
SECRET_ALPHA = "22" * 32
SECRET_BETA = "33" * 32
SECRET_GAMMA = "44" * 32
SECRET_GHOST = "55" * 32

ISSUER = "coord"
ALPHA = "alpha"
BETA = "beta"
GAMMA = "gamma"

POLICY = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
MOMENT = 100
VERIFY_MOMENT = 200


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring():
    return {
        ISSUER: [entry(1, SECRET_COORD)],
        ALPHA: [entry(1, SECRET_ALPHA)],
        BETA: [entry(1, SECRET_BETA)],
        GAMMA: [entry(1, SECRET_GAMMA)],
    }


def entry(version, secret, not_before=0, not_after=10 ** 9, revoked=False):
    return {
        "version": version,
        "secret": secret,
        "notBefore": not_before,
        "notAfter": not_after,
        "revoked": revoked,
    }


def sign(payload, secret):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def make_receipt(item_id="item-1"):
    canonical_policy = {
        "batch": POLICY["batch"],
        "sites": {site: sorted(POLICY["sites"][site])
                  for site in sorted(POLICY["sites"])},
        "threshold": POLICY["threshold"],
    }
    report = {"error": "boom", "id": item_id, "result": None,
              "status": "invalid-proof"}
    payload = {
        "issuer": ISSUER,
        "keyVersion": 1,
        "moment": MOMENT,
        "policy": hashlib.sha256(compact(canonical_policy)).hexdigest(),
        "items": [{"id": item_id, "digest": "aa" * 32, "report": report}],
        "version": 1,
    }
    return compact(
        {"payload": payload, "signature": sign(payload, SECRET_COORD)}
    )


def make_hop(issuer, secret, audience, upstream_bytes, moment,
             key_version=1):
    payload = {
        "issuer": issuer,
        "keyVersion": key_version,
        "moment": moment,
        "audience": audience,
        "upstream": hashlib.sha256(upstream_bytes).hexdigest(),
        "version": 1,
    }
    return compact(
        {"payload": payload, "signature": sign(payload, secret)}
    )


class VerifyBatchReceiptChainsTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.receipt = make_receipt()
        self.hop1 = make_hop(ISSUER, SECRET_COORD, ALPHA, self.receipt, 110)
        self.hop2_beta = make_hop(ALPHA, SECRET_ALPHA, BETA, self.hop1, 120)
        self.hop2_gamma = make_hop(ALPHA, SECRET_ALPHA, GAMMA, self.hop1, 120)

    def chain_item(self, item_id, hops, target, receipt=None):
        return {
            "id": item_id,
            "receipt": self.receipt if receipt is None else receipt,
            "hops": hops,
            "target": target,
        }

    def test_verified_chain(self):
        out = verify_batch_receipt_chains(
            [self.chain_item("a", [self.hop1, self.hop2_beta], BETA)],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual(list(out.keys()), ["forks", "items", "version"])
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["forks"], [])
        self.assertEqual(len(out["items"]), 1)
        item = out["items"][0]
        self.assertEqual(list(item.keys()), ["error", "id", "result", "status"])
        self.assertEqual(item["id"], "a")
        self.assertEqual(item["status"], "verified")
        self.assertIsNone(item["error"])
        self.assertEqual(
            item["result"],
            verify_batch_receipt_chain(
                self.receipt, [self.hop1, self.hop2_beta], POLICY,
                self.ring, VERIFY_MOMENT, BETA,
            ),
        )

    def test_fork_marks_both_chains_conflicted(self):
        out = verify_batch_receipt_chains(
            [
                self.chain_item("a", [self.hop1, self.hop2_beta], BETA),
                self.chain_item("b", [self.hop1, self.hop2_gamma], GAMMA),
                self.chain_item("c", [self.hop1], ALPHA),
            ],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        statuses = {item["id"]: item["status"] for item in out["items"]}
        self.assertEqual(
            statuses,
            {"a": "conflicted", "b": "conflicted", "c": "verified"},
        )
        by_id = {item["id"]: item for item in out["items"]}
        self.assertEqual(by_id["a"]["error"], "forked-delegation")
        self.assertIsNotNone(by_id["a"]["result"])
        self.assertEqual(by_id["b"]["error"], "forked-delegation")
        self.assertIsNone(by_id["c"]["error"])
        self.assertEqual(len(out["forks"]), 1)
        fork = out["forks"][0]
        self.assertEqual(
            list(fork.keys()), ["receiptDigest", "upstream", "audiences", "ids"]
        )
        self.assertEqual(
            fork["receiptDigest"], hashlib.sha256(self.receipt).hexdigest()
        )
        self.assertEqual(fork["upstream"], hashlib.sha256(self.hop1).hexdigest())
        self.assertEqual(fork["audiences"], [BETA, GAMMA])
        self.assertEqual(fork["ids"], ["a", "b"])

    def test_prefix_extension_is_not_a_fork(self):
        out = verify_batch_receipt_chains(
            [
                self.chain_item("a", [self.hop1], ALPHA),
                self.chain_item("b", [self.hop1, self.hop2_beta], BETA),
            ],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual(out["forks"], [])
        self.assertEqual(
            [item["status"] for item in out["items"]], ["verified", "verified"]
        )

    def test_forks_only_compared_within_one_base_receipt(self):
        other = make_receipt(item_id="item-2")
        hop1 = make_hop(ISSUER, SECRET_COORD, ALPHA, other, 110)
        hop2 = make_hop(ALPHA, SECRET_ALPHA, GAMMA, hop1, 120)
        out = verify_batch_receipt_chains(
            [
                self.chain_item("a", [self.hop1, self.hop2_beta], BETA),
                self.chain_item("b", [hop1, hop2], GAMMA, receipt=other),
            ],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual(out["forks"], [])
        self.assertEqual(
            [item["status"] for item in out["items"]], ["verified", "verified"]
        )

    def test_failure_statuses_and_isolation(self):
        ghost1 = make_hop(ISSUER, SECRET_COORD, "ghost", self.receipt, 110)
        ghost2 = make_hop("ghost", SECRET_GHOST, BETA, ghost1, 120)
        items = [
            self.chain_item("bad-receipt", [self.hop1], ALPHA, receipt=b"{}"),
            self.chain_item("bad-hop", [self.hop1 + b"\n"], ALPHA),
            self.chain_item("bad-auth", [ghost1, ghost2], BETA),
            self.chain_item("good", [self.hop1], ALPHA),
        ]
        out = verify_batch_receipt_chains(
            items, POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(
            [item["id"] for item in out["items"]],
            ["bad-receipt", "bad-hop", "bad-auth", "good"],
        )
        by_id = {item["id"]: item for item in out["items"]}
        self.assertEqual(by_id["bad-receipt"]["status"], "invalid-receipt")
        self.assertEqual(by_id["bad-hop"]["status"], "invalid-delegation")
        self.assertEqual(by_id["bad-auth"]["status"], "unauthenticated")
        self.assertEqual(by_id["good"]["status"], "verified")
        for item_id in ("bad-receipt", "bad-hop", "bad-auth"):
            item = by_id[item_id]
            self.assertIsNone(item["result"])
            self.assertIsInstance(item["error"], str)
            self.assertNotEqual(item["error"], "")

    def test_hop_field_type_fault_is_invalid_delegation_item(self):
        payload = {
            "issuer": ISSUER,
            "keyVersion": True,
            "moment": 110,
            "audience": ALPHA,
            "upstream": hashlib.sha256(self.receipt).hexdigest(),
            "version": 1,
        }
        bad_hop = compact(
            {"payload": payload, "signature": sign(payload, SECRET_COORD)}
        )
        out = verify_batch_receipt_chains(
            [
                self.chain_item("bad", [bad_hop], ALPHA),
                self.chain_item("good", [self.hop1], ALPHA),
            ],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual(out["items"][0]["status"], "invalid-delegation")
        self.assertEqual(out["items"][1]["status"], "verified")

    def test_batch_validation_taxonomy(self):
        good = self.chain_item("a", [self.hop1], ALPHA)
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains("x", POLICY, self.ring, VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains([], POLICY, self.ring, VERIFY_MOMENT)
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(["x"], POLICY, self.ring, VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [{"id": "a"}], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [dict(good, id=1)], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [dict(good, id="")], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [good, dict(good)], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [dict(good, receipt="x")], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [dict(good, hops="x")], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [dict(good, hops=[])], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [dict(good, hops=["x"])], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [dict(good, target=1)], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [dict(good, target="")], POLICY, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains([good], POLICY, self.ring, True)
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains([good], POLICY, self.ring, -1)

    def test_batch_validated_before_any_chain_runs(self):
        # A batch-level fault raises even when the first item would fail
        # verification on its own.
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [self.chain_item("a", [], ALPHA)],
                POLICY, self.ring, VERIFY_MOMENT,
            )

    def test_inputs_are_not_modified(self):
        items = [
            self.chain_item("a", [self.hop1, self.hop2_beta], BETA),
            self.chain_item("b", [self.hop1, self.hop2_gamma], GAMMA),
        ]
        snapshot = copy.deepcopy(items)
        policy = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
        verify_batch_receipt_chains(items, policy, self.ring, VERIFY_MOMENT)
        self.assertEqual(items, snapshot)
        self.assertEqual(
            policy, {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
        )

    def test_results_are_fresh_and_independent(self):
        items = [self.chain_item("a", [self.hop1], ALPHA)]
        first = verify_batch_receipt_chains(
            items, POLICY, self.ring, VERIFY_MOMENT
        )
        first["items"][0]["result"]["hops"][0]["audience"] = "tampered"
        second = verify_batch_receipt_chains(
            items, POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(
            second["items"][0]["result"]["hops"][0]["audience"], ALPHA
        )


class HopFieldTypeClassificationTest(unittest.TestCase):
    """Public field type faults inside a hop proof raise TypeError."""

    def setUp(self):
        self.ring = keyring()
        self.receipt = make_receipt()

    def hop_with_payload(self, payload):
        return compact(
            {"payload": payload, "signature": sign(payload, SECRET_COORD)}
        )

    def base_payload(self, **overrides):
        payload = {
            "issuer": ISSUER,
            "keyVersion": 1,
            "moment": 110,
            "audience": ALPHA,
            "upstream": hashlib.sha256(self.receipt).hexdigest(),
            "version": 1,
        }
        payload.update(overrides)
        return payload

    def verify(self, hop):
        return verify_batch_receipt_chain(
            self.receipt, [hop], POLICY, self.ring, VERIFY_MOMENT, ALPHA
        )

    def test_bool_key_version_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.verify(self.hop_with_payload(
                self.base_payload(keyVersion=True)
            ))

    def test_bool_moment_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.verify(self.hop_with_payload(self.base_payload(moment=True)))

    def test_bool_version_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.verify(self.hop_with_payload(
                self.base_payload(version=True)
            ))

    def test_non_str_audience_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.verify(self.hop_with_payload(self.base_payload(audience=1)))

    def test_non_str_upstream_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.verify(self.hop_with_payload(self.base_payload(upstream=1)))

    def test_value_faults_stay_delegation_errors(self):
        with self.assertRaises(InvalidReceiptDelegationError):
            self.verify(self.hop_with_payload(self.base_payload(keyVersion=0)))
        with self.assertRaises(InvalidReceiptDelegationError):
            self.verify(self.hop_with_payload(self.base_payload(moment=-1)))
        with self.assertRaises(InvalidReceiptDelegationError):
            self.verify(self.hop_with_payload(self.base_payload(audience="")))
        with self.assertRaises(InvalidReceiptDelegationError):
            self.verify(self.hop_with_payload(self.base_payload(upstream="zz")))
        with self.assertRaises(InvalidReceiptDelegationError):
            self.verify(self.hop_with_payload(self.base_payload(version=2)))


if __name__ == "__main__":
    unittest.main()
