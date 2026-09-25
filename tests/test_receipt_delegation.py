"""Tests for batch receipt uniqueness and delegation chains.

Covers the duplicate-id rejection in :func:`verify_batch_receipt`
(before any signature check) and the two delegation entries:
:func:`delegate_batch_receipt` signing the next hop over a verified
receipt chain, and :func:`verify_batch_receipt_chain` verifying the
whole chain offline against the policy, the current keyring and the
expected target domain.
"""

import copy
import hashlib
import hmac
import json
import unittest
from unittest import mock

from offline_coordination.replication import (
    AuthenticationError,
    InvalidBatchReceiptError,
    InvalidReceiptDelegationError,
    delegate_batch_receipt,
    sign_batch_receipt,
    verify_batch_receipt,
    verify_batch_receipt_chain,
)

SECRET_ROOT = "aa" * 32
SECRET_ALICE = "bb" * 32
SECRET_BOB = "cc" * 32
MOMENT = 100

CHAIN_RESULT_KEYS = ["hops", "receipt", "receiptDigest", "target", "version"]
HOP_PAYLOAD_KEYS = [
    "audience", "issuer", "keyVersion", "moment", "upstream", "version",
]


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def entry(version, secret, not_before=0, not_after=10 ** 9, revoked=False):
    return {
        "version": version,
        "secret": secret,
        "notBefore": not_before,
        "notAfter": not_after,
        "revoked": revoked,
    }


def keyring(**overrides):
    ring = {
        "root": [entry(1, SECRET_ROOT)],
        "alice": [entry(2, SECRET_ALICE)],
        "bob": [entry(3, SECRET_BOB)],
    }
    ring.update(overrides)
    return ring


def policy():
    return {"batch": "batch-1", "sites": {"site-1": {1}}, "threshold": 1}


def items():
    return [{"id": "one", "proof": b"proof-1"}, {"id": "two", "proof": b"proof-2"}]


def receipt():
    return sign_batch_receipt(items(), policy(), keyring(), 10, "root", 1)


def hop_chain():
    """A verified receipt and a two-hop chain root -> alice -> bob."""
    raw = receipt()
    hop1 = delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", 1, "alice")
    hop2 = delegate_batch_receipt(
        raw, [hop1], policy(), keyring(), 30, "alice", 2, "bob"
    )
    return raw, [hop1, hop2]


def decode(proof):
    return json.loads(proof.decode("utf-8"))


class BatchReceiptDuplicateIdTest(unittest.TestCase):
    def forged(self, payload, signature="0" * 64):
        return compact({"payload": payload, "signature": signature})

    def test_duplicate_item_id_rejected(self):
        payload = decode(receipt())["payload"]
        payload["items"].append(dict(payload["items"][0]))
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt(self.forged(payload), policy(), keyring(), MOMENT)

    def test_duplicate_id_is_a_value_error(self):
        payload = decode(receipt())["payload"]
        payload["items"].append(dict(payload["items"][0]))
        with self.assertRaises(ValueError):
            verify_batch_receipt(self.forged(payload), policy(), keyring(), MOMENT)

    def test_duplicate_id_checked_before_signature(self):
        # The forged receipt carries a nonsense signature; the duplicate
        # id must still surface as InvalidBatchReceiptError, not as an
        # AuthenticationError.
        payload = decode(receipt())["payload"]
        payload["items"].append(dict(payload["items"][1]))
        try:
            verify_batch_receipt(self.forged(payload), policy(), keyring(), MOMENT)
        except InvalidBatchReceiptError:
            pass
        except AuthenticationError:
            self.fail("duplicate id must be rejected before the signature check")
        else:
            self.fail("expected InvalidBatchReceiptError")

    def test_unique_ids_still_verify(self):
        result = verify_batch_receipt(receipt(), policy(), keyring(), MOMENT)
        self.assertEqual([item["id"] for item in result["items"]], ["one", "two"])


class DelegateBatchReceiptTest(unittest.TestCase):
    def test_first_hop_shape_and_binding(self):
        raw = receipt()
        hop = delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", 1, "alice")
        self.assertIsInstance(hop, bytes)
        self.assertFalse(hop.endswith(b"\n"))
        proof = decode(hop)
        self.assertEqual(set(proof.keys()), {"payload", "signature"})
        payload = proof["payload"]
        self.assertEqual(sorted(payload.keys()), HOP_PAYLOAD_KEYS)
        self.assertEqual(payload["issuer"], "root")
        self.assertEqual(payload["audience"], "alice")
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], 20)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(
            payload["upstream"], hashlib.sha256(raw).hexdigest()
        )
        expected = hmac.new(
            bytes.fromhex(SECRET_ROOT), compact(payload), hashlib.sha256
        ).hexdigest()
        self.assertEqual(proof["signature"], expected)
        self.assertEqual(hop, compact(proof))

    def test_second_hop_binds_previous_proof_bytes(self):
        raw, hops = hop_chain()
        payload = decode(hops[1])["payload"]
        self.assertEqual(payload["issuer"], "alice")
        self.assertEqual(payload["audience"], "bob")
        self.assertEqual(
            payload["upstream"], hashlib.sha256(hops[0]).hexdigest()
        )

    def test_non_ascii_names_preserved_unescaped(self):
        raw = receipt()
        ring = keyring(**{"névé": [entry(4, SECRET_ALICE)]})
        hop = delegate_batch_receipt(raw, [], policy(), ring, 20, "root", 1, "névé")
        self.assertIn("névé".encode("utf-8"), hop)
        self.assertNotIn(b"\\u", hop)

    def test_issuer_must_continue_the_chain(self):
        raw, hops = hop_chain()
        with self.assertRaises(InvalidReceiptDelegationError):
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, "alice", 2, "bob")
        with self.assertRaises(InvalidReceiptDelegationError):
            delegate_batch_receipt(
                raw, [hops[0]], policy(), keyring(), 30, "root", 1, "bob"
            )

    def test_self_delegation_rejected(self):
        raw = receipt()
        with self.assertRaises(InvalidReceiptDelegationError) as caught:
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", 1, "root")
        self.assertIn("hop 0", str(caught.exception))

    def test_repeated_identity_rejected(self):
        raw, hops = hop_chain()
        with self.assertRaises(InvalidReceiptDelegationError) as caught:
            delegate_batch_receipt(
                raw, hops, policy(), keyring(), 40, "bob", 3, "root"
            )
        self.assertIn("hop 2", str(caught.exception))

    def test_existing_chain_is_verified_before_extending(self):
        raw, hops = hop_chain()
        broken = hops[1][:-2] + b"xx"  # no longer valid hex/JSON
        with self.assertRaises(InvalidReceiptDelegationError):
            delegate_batch_receipt(
                raw, [hops[0], broken], policy(), keyring(), 40, "bob", 3, "carol"
            )

    def test_invalid_base_receipt_raises_batch_receipt_error(self):
        raw = bytearray(receipt())
        raw[-3] = ord("x")
        with self.assertRaises(InvalidBatchReceiptError):
            delegate_batch_receipt(
                bytes(raw), [], policy(), keyring(), 20, "root", 1, "alice"
            )

    def test_type_and_value_classification(self):
        raw = receipt()
        with self.assertRaises(TypeError):
            delegate_batch_receipt("x", [], policy(), keyring(), 20, "root", 1, "alice")
        with self.assertRaises(TypeError):
            delegate_batch_receipt(raw, (), policy(), keyring(), 20, "root", 1, "alice")
        with self.assertRaises(TypeError):
            delegate_batch_receipt(raw, ["x"], policy(), keyring(), 20, "root", 1, "a")
        with self.assertRaises(TypeError):
            delegate_batch_receipt(raw, [], policy(), keyring(), True, "root", 1, "a")
        with self.assertRaises(ValueError):
            delegate_batch_receipt(raw, [], policy(), keyring(), -1, "root", 1, "a")
        with self.assertRaises(TypeError):
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, 1, 1, "alice")
        with self.assertRaises(ValueError):
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, "", 1, "alice")
        with self.assertRaises(TypeError):
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", True, "a")
        with self.assertRaises(ValueError):
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", 0, "a")
        with self.assertRaises(TypeError):
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", 1, 2)
        with self.assertRaises(ValueError):
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", 1, "")

    def test_unknown_or_unusable_credentials(self):
        raw = receipt()
        with self.assertRaises(AuthenticationError):
            delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", 9, "alice")
        ring = keyring(root=[entry(1, SECRET_ROOT, revoked=True)])
        with self.assertRaises(AuthenticationError):
            delegate_batch_receipt(raw, [], policy(), ring, 20, "root", 1, "alice")
        ring = keyring(root=[entry(1, SECRET_ROOT, not_after=15)])
        with self.assertRaises(AuthenticationError):
            delegate_batch_receipt(raw, [], policy(), ring, 20, "root", 1, "alice")

    def test_no_file_io_and_no_input_mutation(self):
        raw = receipt()
        hops = []
        ring = keyring()
        pol = policy()
        snapshot = (raw, list(hops), copy.deepcopy(pol))
        with mock.patch("builtins.open", side_effect=AssertionError("file io")):
            delegate_batch_receipt(raw, hops, pol, ring, 20, "root", 1, "alice")
        self.assertEqual((raw, hops, pol), snapshot)


class VerifyBatchReceiptChainTest(unittest.TestCase):
    def test_round_trip_result(self):
        raw, hops = hop_chain()
        result = verify_batch_receipt_chain(
            raw, hops, policy(), keyring(), 50, "bob"
        )
        self.assertEqual(list(result.keys()), CHAIN_RESULT_KEYS)
        self.assertEqual(result["target"], "bob")
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["receiptDigest"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(
            [(h["issuer"], h["audience"]) for h in result["hops"]],
            [("root", "alice"), ("alice", "bob")],
        )
        self.assertEqual(result["receipt"]["issuer"], "root")
        self.assertEqual(len(result["receipt"]["items"]), 2)

    def test_single_hop_chain(self):
        raw = receipt()
        hop = delegate_batch_receipt(raw, [], policy(), keyring(), 20, "root", 1, "alice")
        result = verify_batch_receipt_chain(raw, [hop], policy(), keyring(), 50, "alice")
        self.assertEqual(len(result["hops"]), 1)

    def test_results_are_fresh_and_independent(self):
        raw, hops = hop_chain()
        first = verify_batch_receipt_chain(raw, hops, policy(), keyring(), 50, "bob")
        second = verify_batch_receipt_chain(raw, hops, policy(), keyring(), 50, "bob")
        self.assertEqual(first, second)
        first["hops"][0]["issuer"] = "mutated"
        first["receipt"]["issuer"] = "mutated"
        self.assertEqual(second["hops"][0]["issuer"], "root")
        self.assertEqual(second["receipt"]["issuer"], "root")

    def test_empty_hops_and_target_classification(self):
        raw, hops = hop_chain()
        with self.assertRaises(ValueError):
            verify_batch_receipt_chain(raw, [], policy(), keyring(), 50, "bob")
        with self.assertRaises(ValueError):
            verify_batch_receipt_chain(raw, hops, policy(), keyring(), 50, "")
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(raw, hops, policy(), keyring(), 50, 3)
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(raw, hops, policy(), keyring(), True, "bob")
        with self.assertRaises(ValueError):
            verify_batch_receipt_chain(raw, hops, policy(), keyring(), -1, "bob")
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(raw, "x", policy(), keyring(), 50, "bob")
        with self.assertRaises(TypeError):
            verify_batch_receipt_chain(raw, ["x"], policy(), keyring(), 50, "bob")

    def test_wrong_target_rejected(self):
        raw, hops = hop_chain()
        with self.assertRaises(InvalidReceiptDelegationError) as caught:
            verify_batch_receipt_chain(raw, hops, policy(), keyring(), 50, "root")
        self.assertIn("hop 1", str(caught.exception))

    def test_invalid_base_receipt_raises_batch_receipt_error(self):
        raw, hops = hop_chain()
        forged = decode(raw)
        forged["payload"]["version"] = 2  # structural fault, not a bad signature
        with self.assertRaises(InvalidBatchReceiptError):
            verify_batch_receipt_chain(
                compact(forged), hops, policy(), keyring(), 50, "bob"
            )

    def test_hop_encoding_faults(self):
        raw, hops = hop_chain()
        with self.assertRaises(InvalidReceiptDelegationError):
            verify_batch_receipt_chain(
                raw, [hops[0] + b"\n", hops[1]], policy(), keyring(), 50, "bob"
            )
        proof = decode(hops[0])
        proof["payload"]["version"] = 2
        with self.assertRaises(InvalidReceiptDelegationError):
            verify_batch_receipt_chain(
                raw, [compact(proof), hops[1]], policy(), keyring(), 50, "bob"
            )
        proof = decode(hops[0])
        del proof["payload"]["audience"]
        with self.assertRaises(InvalidReceiptDelegationError):
            verify_batch_receipt_chain(
                raw, [compact(proof), hops[1]], policy(), keyring(), 50, "bob"
            )

    def test_upstream_mismatch_rejected(self):
        raw, hops = hop_chain()
        proof = decode(hops[1])
        proof["payload"]["upstream"] = "0" * 64
        # Re-sign so only the binding is wrong.
        proof["signature"] = hmac.new(
            bytes.fromhex(SECRET_ALICE), compact(proof["payload"]), hashlib.sha256
        ).hexdigest()
        with self.assertRaises(InvalidReceiptDelegationError) as caught:
            verify_batch_receipt_chain(
                raw, [hops[0], compact(proof)], policy(), keyring(), 50, "bob"
            )
        self.assertIn("hop 1", str(caught.exception))

    def test_moment_binding_rejected(self):
        raw, hops = hop_chain()
        proof = decode(hops[0])
        proof["payload"]["moment"] = 60  # later than the verification moment
        proof["signature"] = hmac.new(
            bytes.fromhex(SECRET_ROOT), compact(proof["payload"]), hashlib.sha256
        ).hexdigest()
        with self.assertRaises(InvalidReceiptDelegationError):
            verify_batch_receipt_chain(
                raw, [compact(proof), hops[1]], policy(), keyring(), 50, "bob"
            )

    def test_bad_signature_rejected(self):
        raw, hops = hop_chain()
        proof = decode(hops[1])
        proof["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(
                raw, [hops[0], compact(proof)], policy(), keyring(), 50, "bob"
            )

    def test_credential_faults_rejected(self):
        raw, hops = hop_chain()
        ring = keyring(alice=[entry(2, SECRET_ALICE, revoked=True)])
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(raw, hops, policy(), ring, 50, "bob")
        # Valid at the hop moment, expired at the verification moment.
        ring = keyring(alice=[entry(2, SECRET_ALICE, not_after=35)])
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(raw, hops, policy(), ring, 50, "bob")
        # Not yet valid at the hop's own moment.
        ring = keyring(alice=[entry(2, SECRET_ALICE, not_before=31)])
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(raw, hops, policy(), ring, 50, "bob")
        # Unknown credentials.
        ring = keyring(alice=[entry(9, SECRET_ALICE)])
        with self.assertRaises(AuthenticationError):
            verify_batch_receipt_chain(raw, hops, policy(), ring, 50, "bob")

    def test_error_names_first_failing_hop(self):
        raw, hops = hop_chain()
        proof = decode(hops[1])
        proof["payload"]["audience"] = "root"  # repeats the receipt issuer
        proof["signature"] = hmac.new(
            bytes.fromhex(SECRET_ALICE), compact(proof["payload"]), hashlib.sha256
        ).hexdigest()
        with self.assertRaises(InvalidReceiptDelegationError) as caught:
            verify_batch_receipt_chain(
                raw, [hops[0], compact(proof)], policy(), keyring(), 50, "root"
            )
        self.assertIn("hop 1", str(caught.exception))

    def test_no_file_io_and_no_input_mutation(self):
        raw, hops = hop_chain()
        pol, ring = policy(), keyring()
        snapshot = (raw, list(hops), copy.deepcopy(pol))
        with mock.patch("builtins.open", side_effect=AssertionError("file io")):
            verify_batch_receipt_chain(raw, hops, pol, ring, 50, "bob")
        self.assertEqual((raw, hops, pol), snapshot)


if __name__ == "__main__":
    unittest.main()
