"""Tests for batch receipt uniqueness and receipt delegation chains.

Covers the duplicate-id rejection in :func:`verify_batch_receipt` ahead
of any signature check, :func:`delegate_batch_receipt` (signing the next
hop over a verified base receipt and an existing delegation sequence)
and :func:`verify_batch_receipt_chain` (offline whole-chain
verification): the canonical hop contract, the upstream digest and
issuer/audience chaining, the moment bounds, the dual-moment credential
validity, the exception taxonomy and the freshness of the result.
"""

import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    AuthenticationError,
    InvalidBatchReceiptError,
    InvalidReceiptDelegationError,
    delegate_batch_receipt,
    verify_batch_receipt,
    verify_batch_receipt_chain,
)

SECRET_COORD = "11" * 32
SECRET_ALPHA = "22" * 32
SECRET_BETA = "33" * 32

ISSUER = "coord"
ALPHA = "alpha"
BETA = "beta"

POLICY = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
MOMENT = 100
VERIFY_MOMENT = 200


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring(**overrides):
    ring = {
        ISSUER: [entry(1, SECRET_COORD)],
        ALPHA: [entry(1, SECRET_ALPHA)],
        BETA: [entry(1, SECRET_BETA)],
    }
    for node, entries in overrides.items():
        ring[node] = entries
    return ring


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


def make_report(item_id="item-1"):
    return {
        "error": "boom",
        "id": item_id,
        "result": None,
        "status": "invalid-proof",
    }


def make_item(item_id="item-1"):
    return {
        "id": item_id,
        "digest": "aa" * 32,
        "report": make_report(item_id),
    }


def make_receipt(items=None, issuer=ISSUER, secret=SECRET_COORD,
                 key_version=1, moment=MOMENT, policy=POLICY):
    if items is None:
        items = [make_item()]
    canonical_policy = {
        "batch": policy["batch"],
        "sites": {
            site: sorted(policy["sites"][site])
            for site in sorted(policy["sites"])
        },
        "threshold": policy["threshold"],
    }
    payload = {
        "issuer": issuer,
        "keyVersion": key_version,
        "moment": moment,
        "policy": hashlib.sha256(compact(canonical_policy)).hexdigest(),
        "items": items,
        "version": 1,
    }
    return compact(
        {"payload": payload, "signature": sign(payload, secret)}
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


def hop_payload(hop):
    return json.loads(hop.decode("utf-8"))["payload"]


def tamper_signature(data):
    """Flip the last hex digit of the trailing signature, keeping JSON."""
    # The proof ends with `..."<64 hex>"}`; index -3 is the last hex char.
    mutated = bytearray(data)
    mutated[-3] = ord("0") if mutated[-3] != ord("0") else ord("1")
    return bytes(mutated)


class VerifyBatchReceiptDuplicateIdsTest(unittest.TestCase):
    def test_duplicate_ids_rejected(self):
        receipt = make_receipt(items=[make_item("x"), make_item("x")])
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt(receipt, POLICY, keyring(), VERIFY_MOMENT)

    def test_duplicate_ids_rejected_before_signature_check(self):
        items = [make_item("x"), make_item("x")]
        # Corrupt the signature hex, keeping the JSON valid: the
        # duplicate-id fault must still surface as
        # InvalidBatchReceiptError, not AuthenticationError.
        receipt = tamper_signature(make_receipt(items=items))
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt(receipt, POLICY, keyring(), VERIFY_MOMENT)

    def test_distinct_ids_still_verify(self):
        receipt = make_receipt(items=[make_item("a"), make_item("b")])
        payload = verify_batch_receipt(
            receipt, POLICY, keyring(), VERIFY_MOMENT
        )
        self.assertEqual([item["id"] for item in payload["items"]],
                         ["a", "b"])


class DelegateBatchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.receipt = make_receipt()

    def test_first_hop_shape_and_encoding(self):
        hop = delegate_batch_receipt(
            self.receipt, [], POLICY, self.ring, 110, ISSUER, 1, ALPHA
        )
        self.assertIsInstance(hop, bytes)
        self.assertFalse(hop.endswith(b"\n"))
        data = json.loads(hop.decode("utf-8"))
        self.assertEqual(compact(data), hop)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        payload = data["payload"]
        self.assertEqual(payload, {
            "issuer": ISSUER,
            "keyVersion": 1,
            "moment": 110,
            "audience": ALPHA,
            "upstream": hashlib.sha256(self.receipt).hexdigest(),
            "version": 1,
        })
        expected = sign(payload, SECRET_COORD)
        self.assertEqual(data["signature"], expected)

    def test_second_hop_chains_previous_hop_bytes(self):
        hop1 = delegate_batch_receipt(
            self.receipt, [], POLICY, self.ring, 110, ISSUER, 1, ALPHA
        )
        hop2 = delegate_batch_receipt(
            self.receipt, [hop1], POLICY, self.ring, 120, ALPHA, 1, BETA
        )
        payload = hop_payload(hop2)
        self.assertEqual(payload["issuer"], ALPHA)
        self.assertEqual(payload["audience"], BETA)
        self.assertEqual(payload["upstream"],
                         hashlib.sha256(hop1).hexdigest())

    def test_issuer_must_equal_receipt_issuer_on_first_hop(self):
        with self.assertRaises(InvalidReceiptDelegationError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, 110, ALPHA, 1, BETA
            )

    def test_issuer_must_equal_previous_audience(self):
        hop1 = delegate_batch_receipt(
            self.receipt, [], POLICY, self.ring, 110, ISSUER, 1, ALPHA
        )
        with self.assertRaises(InvalidReceiptDelegationError):
            delegate_batch_receipt(
                self.receipt, [hop1], POLICY, self.ring, 120, ISSUER, 1,
                BETA,
            )

    def test_self_delegation_rejected(self):
        with self.assertRaises(InvalidReceiptDelegationError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, 110, ISSUER, 1, ISSUER
            )

    def test_audience_must_not_repeat_chain_domain(self):
        hop1 = delegate_batch_receipt(
            self.receipt, [], POLICY, self.ring, 110, ISSUER, 1, ALPHA
        )
        with self.assertRaises(InvalidReceiptDelegationError):
            delegate_batch_receipt(
                self.receipt, [hop1], POLICY, self.ring, 120, ALPHA, 1,
                ISSUER,
            )

    def test_moment_must_not_precede_upstream(self):
        # A hop whose moment is earlier than its upstream's moment is a
        # chain-binding fault, reported at that hop.
        hop1 = make_hop(ISSUER, SECRET_COORD, ALPHA, self.receipt, 110)
        hop2 = make_hop(ALPHA, SECRET_ALPHA, BETA, hop1, 105)
        with self.assertRaises(InvalidReceiptDelegationError) as caught:
            verify_batch_receipt_chain(
                self.receipt, [hop1, hop2], POLICY, self.ring,
                VERIFY_MOMENT, BETA,
            )
        self.assertIn("hop 1", str(caught.exception))

    def test_invalid_base_receipt_raises_batch_receipt_error(self):
        with self.assertRaises(InvalidBatchReceiptError):
            delegate_batch_receipt(
                b"{}", [], POLICY, self.ring, 110, ISSUER, 1, ALPHA
            )

    def test_tampered_existing_hop_raises_authentication_error(self):
        hop1 = delegate_batch_receipt(
            self.receipt, [], POLICY, self.ring, 110, ISSUER, 1, ALPHA
        )
        with self.assertRaises(AuthenticationError):
            delegate_batch_receipt(
                self.receipt, [tamper_signature(hop1)], POLICY, self.ring,
                120, ALPHA, 1, BETA,
            )

    def test_unknown_credentials_raise_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, 110, ISSUER, 9, ALPHA
            )

    def test_argument_type_and_value_taxonomy(self):
        with self.assertRaises(TypeError):
            delegate_batch_receipt(
                "x", [], POLICY, self.ring, 110, ISSUER, 1, ALPHA
            )
        with self.assertRaises(TypeError):
            delegate_batch_receipt(
                self.receipt, None, POLICY, self.ring, 110, ISSUER, 1,
                ALPHA,
            )
        with self.assertRaises(TypeError):
            delegate_batch_receipt(
                self.receipt, ["x"], POLICY, self.ring, 110, ISSUER, 1,
                ALPHA,
            )
        with self.assertRaises(TypeError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, True, ISSUER, 1, ALPHA
            )
        with self.assertRaises(ValueError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, -1, ISSUER, 1, ALPHA
            )
        with self.assertRaises(ValueError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, 110, "", 1, ALPHA
            )
        with self.assertRaises(ValueError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, 110, ISSUER, 0, ALPHA
            )
        with self.assertRaises(ValueError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, 110, ISSUER, 1, ""
            )
        with self.assertRaises(TypeError):
            delegate_batch_receipt(
                self.receipt, [], POLICY, self.ring, 110, ISSUER, True,
                ALPHA,
            )


class VerifyBatchReceiptChainTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.receipt = make_receipt()
        self.hop1 = delegate_batch_receipt(
            self.receipt, [], POLICY, self.ring, 110, ISSUER, 1, ALPHA
        )
        self.hop2 = delegate_batch_receipt(
            self.receipt, [self.hop1], POLICY, self.ring, 120, ALPHA, 1,
            BETA,
        )

    def test_full_chain_verifies(self):
        result = verify_batch_receipt_chain(
            self.receipt, [self.hop1, self.hop2], POLICY, self.ring,
            VERIFY_MOMENT, BETA,
        )
        self.assertEqual(
            list(result.keys()),
            ["hops", "receipt", "receiptDigest", "target", "version"],
        )
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["target"], BETA)
        self.assertEqual(result["receiptDigest"],
                         hashlib.sha256(self.receipt).hexdigest())
        self.assertEqual(result["receipt"],
                         verify_batch_receipt(
                             self.receipt, POLICY, self.ring, VERIFY_MOMENT
                         ))
        self.assertEqual(
            [hop["audience"] for hop in result["hops"]], [ALPHA, BETA]
        )
        self.assertEqual(
            result["hops"][0]["upstream"],
            hashlib.sha256(self.receipt).hexdigest(),
        )
        self.assertEqual(
            result["hops"][1]["upstream"],
            hashlib.sha256(self.hop1).hexdigest(),
        )

    def test_results_are_fresh_and_independent(self):
        first = verify_batch_receipt_chain(
            self.receipt, [self.hop1, self.hop2], POLICY, self.ring,
            VERIFY_MOMENT, BETA,
        )
        first["hops"][0]["audience"] = "tampered"
        first["receipt"]["issuer"] = "tampered"
        second = verify_batch_receipt_chain(
            self.receipt, [self.hop1, self.hop2], POLICY, self.ring,
            VERIFY_MOMENT, BETA,
        )
        self.assertEqual(second["hops"][0]["audience"], ALPHA)
        self.assertEqual(second["receipt"]["issuer"], ISSUER)

    def test_single_hop_chain(self):
        result = verify_batch_receipt_chain(
            self.receipt, [self.hop1], POLICY, self.ring, VERIFY_MOMENT,
            ALPHA,
        )
        self.assertEqual(len(result["hops"]), 1)
        self.assertEqual(result["target"], ALPHA)

    def test_empty_hops_rejected(self):
        with self.assertRaises(ValueError):
            verify_batch_receipt_chain(
                self.receipt, [], POLICY, self.ring, VERIFY_MOMENT, BETA
            )

    def test_empty_target_rejected(self):
        with self.assertRaises(ValueError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1], POLICY, self.ring,
                VERIFY_MOMENT, "",
            )

    def test_wrong_target_names_last_hop(self):
        with self.assertRaises(InvalidReceiptDelegationError) as caught:
            verify_batch_receipt_chain(
                self.receipt, [self.hop1, self.hop2], POLICY, self.ring,
                VERIFY_MOMENT, "gamma",
            )
        self.assertIn("hop 1", str(caught.exception))

    def test_first_failing_hop_is_located(self):
        bad = make_hop(ALPHA, SECRET_ALPHA, BETA, self.receipt, 120)
        with self.assertRaises(InvalidReceiptDelegationError) as caught:
            verify_batch_receipt_chain(
                self.receipt, [self.hop1, bad], POLICY, self.ring,
                VERIFY_MOMENT, BETA,
            )
        self.assertIn("hop 1", str(caught.exception))

    def test_tampered_hop_signature_raises_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1, tamper_signature(self.hop2)],
                POLICY, self.ring, VERIFY_MOMENT, BETA,
            )

    def test_hop_moment_after_verification_moment_rejected(self):
        with self.assertRaises(InvalidReceiptDelegationError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1, self.hop2], POLICY, self.ring,
                115, BETA,
            )

    def test_revoked_credential_raises_authentication_error(self):
        ring = keyring(**{ALPHA: [entry(1, SECRET_ALPHA, revoked=True)]})
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1, self.hop2], POLICY, ring,
                VERIFY_MOMENT, BETA,
            )

    def test_credential_must_be_valid_at_verification_moment(self):
        # Valid at the hop's own moment (120) but expired before the
        # verification moment.
        ring = keyring(**{ALPHA: [entry(1, SECRET_ALPHA, not_after=150)]})
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1, self.hop2], POLICY, ring,
                VERIFY_MOMENT, BETA,
            )

    def test_credential_must_be_valid_at_signing_moment(self):
        ring = keyring(**{ALPHA: [entry(1, SECRET_ALPHA, not_before=130)]})
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1, self.hop2], POLICY, ring,
                VERIFY_MOMENT, BETA,
            )

    def test_unknown_hop_credentials_raise_authentication_error(self):
        # The hop issuer "ghost" has no keyring entry; the audience of a
        # hop needs no credentials, only the issuer does.
        hop1 = make_hop(ISSUER, SECRET_COORD, "ghost", self.receipt, 110)
        hop2 = make_hop("ghost", SECRET_ALPHA, BETA, hop1, 120)
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(
                self.receipt, [hop1, hop2], POLICY, self.ring,
                VERIFY_MOMENT, BETA,
            )

    def test_invalid_base_receipt_raises_batch_receipt_error(self):
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt_chain(
                b"{}", [self.hop1], POLICY, self.ring, VERIFY_MOMENT, ALPHA
            )

    def test_malformed_hop_encoding_raises_delegation_error(self):
        with self.assertRaises(InvalidReceiptDelegationError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1 + b"\n"], POLICY, self.ring,
                VERIFY_MOMENT, ALPHA,
            )

    def test_argument_type_and_value_taxonomy(self):
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(
                "x", [self.hop1], POLICY, self.ring, VERIFY_MOMENT, ALPHA
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(
                self.receipt, None, POLICY, self.ring, VERIFY_MOMENT, ALPHA
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(
                self.receipt, ["x"], POLICY, self.ring, VERIFY_MOMENT,
                ALPHA,
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1], POLICY, self.ring, True, ALPHA
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1], POLICY, self.ring, -1, ALPHA
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(
                self.receipt, [self.hop1], POLICY, self.ring,
                VERIFY_MOMENT, 1,
            )

    def test_inputs_are_not_modified(self):
        hops = [self.hop1, self.hop2]
        policy = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
        verify_batch_receipt_chain(
            self.receipt, hops, policy, self.ring, VERIFY_MOMENT, BETA
        )
        self.assertEqual(hops, [self.hop1, self.hop2])
        self.assertEqual(
            policy,
            {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1},
        )


if __name__ == "__main__":
    unittest.main()
