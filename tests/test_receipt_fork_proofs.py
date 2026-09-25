"""Tests for the offline-handover receipt fork proof.

Covers :func:`sign_receipt_fork_proof`,
:func:`verify_receipt_fork_proof` and
:func:`verify_receipt_fork_proofs`: the canonical compact proof shape,
the signing identity/version/moment/policy-digest/report/chain-material
bindings, input-order and no-omission chain summaries, the fork-only
signing rule, input non-modification, the TypeError/ValueError/
InvalidReceiptForkProofError/AuthenticationError taxonomy, offline
credential and signature checks, report and fork-table binding checks,
and the batch wrapper's upfront shared-material validation, per-item
isolation, statuses and fresh independent results.
"""

import copy
import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    AuthenticationError,
    InvalidReceiptForkProofError,
    sign_receipt_fork_proof,
    verify_receipt_fork_proof,
    verify_receipt_fork_proofs,
)

SECRET_COORD = "11" * 32
SECRET_ALPHA = "22" * 32
SECRET_BETA = "33" * 32
SECRET_GAMMA = "44" * 32
SECRET_DELTA = "55" * 32

ISSUER = "coord"
ALPHA = "alpha"
BETA = "beta"
GAMMA = "gamma"
DELTA = "delta"

POLICY = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
SIGN_MOMENT = 150
MOMENT = 200


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
        ISSUER: [entry(1, SECRET_COORD)],
        ALPHA: [entry(1, SECRET_ALPHA)],
        BETA: [entry(1, SECRET_BETA)],
        GAMMA: [entry(1, SECRET_GAMMA)],
        DELTA: [entry(1, SECRET_DELTA)],
    }
    for node, entries in overrides.items():
        ring[node] = entries
    return ring


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
                 key_version=1, moment=100, policy=POLICY):
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


def chain(receipt, path, moments=()):
    hops = []
    upstream = receipt
    domains = [ISSUER] + list(path)
    for index, audience in enumerate(path):
        moment = moments[index] if moments else 110 + index
        hops.append(
            make_hop(
                domains[index],
                keyring_secrets()[domains[index]],
                audience,
                upstream,
                moment,
            )
        )
        upstream = hops[-1]
    return hops


def keyring_secrets():
    return {
        ISSUER: SECRET_COORD,
        ALPHA: SECRET_ALPHA,
        BETA: SECRET_BETA,
        GAMMA: SECRET_GAMMA,
        DELTA: SECRET_DELTA,
        "epsilon": "66" * 32,
    }


def chain_item(item_id, receipt, path, target=None, moments=()):
    return {
        "id": item_id,
        "receipt": receipt,
        "hops": chain(receipt, path, moments),
        "target": target if target is not None else path[-1],
    }


def fork_batch(receipt=None):
    if receipt is None:
        receipt = make_receipt()
    item_a = chain_item("a", receipt, [ALPHA, BETA], moments=(110, 120))
    item_b = chain_item("b", receipt, [GAMMA, DELTA], moments=(111, 121))
    return [item_a, item_b], receipt


def tamper_last(data):
    mutated = bytearray(data)
    mutated[-3] = ord("0") if mutated[-3] != ord("0") else ord("1")
    return bytes(mutated)


class SignForkProofTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.items, self.receipt = fork_batch()

    def test_proof_is_canonical_compact_with_no_trailing_byte(self):
        proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )
        self.assertIsInstance(proof, bytes)
        self.assertTrue(proof)
        self.assertEqual(proof[-1:], b"}")
        data = json.loads(proof.decode("utf-8"))
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        self.assertEqual(
            set(data["payload"].keys()),
            {"issuer", "keyVersion", "moment", "policyDigest", "report",
             "chains", "version"},
        )
        # Recursively sorted keys and compact separators: re-encoding the
        # parsed object canonically must reproduce the exact bytes.
        self.assertEqual(compact(data), proof)

    def test_proof_preserves_non_ascii_unescaped(self):
        # A non-ASCII identity/audience survives unescaped in the report.
        ring = keyring()
        ring["ω"] = [entry(1, "77" * 32)]
        receipt = make_receipt()
        item_a = chain_item("a", receipt, [ALPHA])
        item_b = chain_item("b", receipt, ["ω"])
        proof = sign_receipt_fork_proof(
            [item_a, item_b], POLICY, ring, SIGN_MOMENT, ISSUER, 1
        )
        self.assertIn("ω".encode("utf-8"), proof)
        self.assertNotIn(b"\\u", proof)

    def test_payload_binds_identity_version_moment_and_policy_digest(self):
        proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )
        payload = json.loads(proof)["payload"]
        self.assertEqual(payload["issuer"], ISSUER)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertNotIsInstance(payload["keyVersion"], bool)
        self.assertEqual(payload["moment"], SIGN_MOMENT)
        self.assertEqual(payload["version"], 1)
        canonical_policy = {
            "batch": POLICY["batch"],
            "sites": {
                site: sorted(versions)
                for site, versions in sorted(POLICY["sites"].items())
            },
            "threshold": POLICY["threshold"],
        }
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(compact(canonical_policy)).hexdigest(),
        )

    def test_chain_material_summaries_preserve_order_and_full_bytes(self):
        proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )
        chains = json.loads(proof)["payload"]["chains"]
        self.assertEqual([c["id"] for c in chains], ["a", "b"])
        for summary, item in zip(chains, self.items):
            self.assertEqual(
                set(summary.keys()),
                {"id", "receiptDigest", "target", "hops"},
            )
            self.assertEqual(
                summary["receiptDigest"],
                hashlib.sha256(item["receipt"]).hexdigest(),
            )
            self.assertEqual(summary["target"], item["target"])
            self.assertEqual(
                summary["hops"],
                [hashlib.sha256(hop).hexdigest() for hop in item["hops"]],
            )
            # One digest per hop, in order, none omitted.
            self.assertEqual(len(summary["hops"]), len(item["hops"]))

    def test_report_is_the_complete_batch_summary(self):
        proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )
        from offline_coordination.replication import (
            verify_batch_receipt_chains,
        )
        expected = verify_batch_receipt_chains(
            self.items, POLICY, self.ring, SIGN_MOMENT
        )
        self.assertEqual(json.loads(proof)["payload"]["report"], expected)

    def test_inputs_are_not_modified(self):
        items_snapshot = copy.deepcopy(self.items)
        policy_snapshot = copy.deepcopy(POLICY)
        sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )
        self.assertEqual(self.items, items_snapshot)
        self.assertEqual(POLICY, policy_snapshot)

    def test_no_fork_refuses_to_sign(self):
        only_one = [chain_item("a", self.receipt, [ALPHA, BETA])]
        with self.assertRaises(ValueError):
            sign_receipt_fork_proof(
                only_one, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
            )

    def test_sign_parameter_type_and_value_rules(self):
        def sign_with(**kwargs):
            defaults = dict(
                items=self.items, policy=POLICY, keyring=self.ring,
                moment=SIGN_MOMENT, issuer=ISSUER, version=1,
            )
            defaults.update(kwargs)
            return sign_receipt_fork_proof(**defaults)

        with self.assertRaises(TypeError):
            sign_with(moment=True)
        with self.assertRaises(TypeError):
            sign_with(issuer=5)
        with self.assertRaises(TypeError):
            sign_with(version=True)
        with self.assertRaises(ValueError):
            sign_with(moment=-1)
        with self.assertRaises(ValueError):
            sign_with(issuer="")
        with self.assertRaises(ValueError):
            sign_with(version=0)
        with self.assertRaises(ValueError):
            sign_with(policy={"batch": "x"})
        with self.assertRaises(TypeError):
            sign_with(items=())
        with self.assertRaises(ValueError):
            sign_with(items=[])

    def test_unknown_revoked_or_expired_signing_credentials(self):
        # The signing identity is independent of the forking chains, so
        # the batch still reports a fork before the signing key is used.
        signer = "signer"
        secret_signer = "88" * 32
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, self.ring, SIGN_MOMENT, "nobody", 1
            )
        ring = keyring(**{
            signer: [entry(1, secret_signer, revoked=True)],
        })
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, ring, SIGN_MOMENT, signer, 1
            )
        ring = keyring(**{
            signer: [entry(1, secret_signer, not_before=SIGN_MOMENT + 1)],
        })
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, ring, SIGN_MOMENT, signer, 1
            )
        ring = keyring(**{
            signer: [entry(1, secret_signer, not_after=SIGN_MOMENT - 1)],
        })
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, ring, SIGN_MOMENT, signer, 1
            )
        # An exact version with no fallback: version 2 is absent.
        ring = keyring(**{signer: [entry(1, secret_signer)]})
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, ring, SIGN_MOMENT, signer, 2
            )


class VerifyForkProofTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.items, self.receipt = fork_batch()
        self.proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )

    def test_success_result_shape_and_digest(self):
        result = verify_receipt_fork_proof(
            self.proof, POLICY, self.ring, MOMENT
        )
        self.assertEqual(
            list(result.keys()),
            ["chains", "digest", "issuer", "keyVersion", "moment",
             "policyDigest", "report", "version"],
        )
        self.assertEqual(result["issuer"], ISSUER)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["moment"], SIGN_MOMENT)
        self.assertEqual(result["version"], 1)
        self.assertEqual(
            result["digest"], hashlib.sha256(self.proof).hexdigest()
        )
        self.assertEqual([c["id"] for c in result["chains"]], ["a", "b"])
        self.assertEqual(len(result["report"]["forks"]), 1)

    def test_success_at_exact_boundary_moments(self):
        # Signing moment equal to verification moment is allowed.
        self.assertIsNotNone(
            verify_receipt_fork_proof(
                self.proof, POLICY, self.ring, SIGN_MOMENT
            )
        )

    def test_result_is_a_fresh_independent_copy(self):
        first = verify_receipt_fork_proof(
            self.proof, POLICY, self.ring, MOMENT
        )
        first["chains"][0]["id"] = "tampered"
        first["report"]["forks"][0]["audiences"] = ["x"]
        second = verify_receipt_fork_proof(
            self.proof, POLICY, self.ring, MOMENT
        )
        self.assertEqual(second["chains"][0]["id"], "a")
        self.assertEqual(
            second["report"]["forks"][0]["audiences"], [ALPHA, GAMMA]
        )

    def test_arguments_are_not_modified(self):
        proof_snapshot = self.proof
        policy_snapshot = copy.deepcopy(POLICY)
        verify_receipt_fork_proof(self.proof, POLICY, self.ring, MOMENT)
        self.assertEqual(self.proof, proof_snapshot)
        self.assertEqual(POLICY, policy_snapshot)

    def test_non_bytes_proof_is_type_error(self):
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof("x", POLICY, self.ring, MOMENT)

    def test_shared_material_rules(self):
        with self.assertRaises(ValueError):
            verify_receipt_fork_proof(
                self.proof, {"batch": "x"}, self.ring, MOMENT
            )
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                self.proof, POLICY, self.ring, True
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proof(
                self.proof, POLICY, self.ring, -1
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proof(
                self.proof, POLICY, {"": []}, MOMENT
            )

    def test_wrong_policy_digest_is_invalid(self):
        other = {"batch": "batch-2", "sites": {"a": {1}}, "threshold": 1}
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(self.proof, other, self.ring, MOMENT)

    def test_signing_moment_in_the_future_is_invalid(self):
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.proof, POLICY, self.ring, SIGN_MOMENT - 1
            )

    def test_credential_states_are_authentication_errors(self):
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, keyring(), MOMENT + 10 ** 10
            )
        revoked = keyring(**{ISSUER: [entry(1, SECRET_COORD, revoked=True)]})
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, revoked, MOMENT
            )
        future_key = keyring(**{
            ISSUER: [entry(1, SECRET_COORD, not_before=MOMENT + 1)],
        })
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, future_key, MOMENT
            )
        expired = keyring(**{
            ISSUER: [entry(1, SECRET_COORD, not_after=MOMENT - 1)],
        })
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, expired, MOMENT
            )
        minimal = {k: v for k, v in self.ring.items() if k != ISSUER}
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, minimal, MOMENT
            )

    def test_signature_mismatch_is_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                tamper_last(self.proof), POLICY, self.ring, MOMENT
            )

    def test_trailing_byte_is_invalid(self):
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.proof + b"\n", POLICY, self.ring, MOMENT
            )

    def test_malformed_bytes_are_invalid(self):
        for bad in (b"", b"{", b"not json"):
            with self.assertRaises(InvalidReceiptForkProofError):
                verify_receipt_fork_proof(bad, POLICY, self.ring, MOMENT)

    def test_non_object_json_is_type_error(self):
        for bad in (b"[]", b"123", b'"x"', b"null"):
            with self.assertRaises(TypeError):
                verify_receipt_fork_proof(bad, POLICY, self.ring, MOMENT)

    def reencode(self, mutate):
        data = json.loads(self.proof.decode("utf-8"))
        mutate(data)
        return compact(data)

    def test_wrong_top_and_payload_key_sets_are_invalid(self):
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(lambda d: d.pop("signature")),
                POLICY, self.ring, MOMENT,
            )
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(lambda d: d["payload"].pop("chains")),
                POLICY, self.ring, MOMENT,
            )
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(lambda d: d["payload"].update(extra=1)),
                POLICY, self.ring, MOMENT,
            )

    def test_bad_version_is_invalid(self):
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(lambda d: d["payload"].__setitem__(
                    "version", 2)),
                POLICY, self.ring, MOMENT,
            )

    def test_bool_posing_as_int_is_type_error(self):
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                self.reencode(lambda d: d["payload"].__setitem__(
                    "keyVersion", True)),
                POLICY, self.ring, MOMENT,
            )

    def test_bad_digest_fields_are_invalid(self):
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(lambda d: d["payload"].__setitem__(
                    "policyDigest", "z" * 64)),
                POLICY, self.ring, MOMENT,
            )
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(lambda d: d["payload"]["chains"][0].__setitem__(
                    "receiptDigest", "z" * 64)),
                POLICY, self.ring, MOMENT,
            )

    def test_non_canonical_encoding_is_invalid(self):
        text = self.proof.decode("utf-8").replace(",", ", ", 1)
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                text.encode("utf-8"), POLICY, self.ring, MOMENT
            )

    def test_reordered_chains_are_invalid(self):
        def swap(d):
            d["payload"]["chains"] = list(reversed(d["payload"]["chains"]))
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(swap), POLICY, self.ring, MOMENT
            )

    def test_omitted_chain_is_invalid(self):
        def drop(d):
            d["payload"]["chains"] = d["payload"]["chains"][:1]
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(drop), POLICY, self.ring, MOMENT
            )

    def test_chain_reference_mismatch_is_invalid(self):
        def corrupt(d):
            d["payload"]["chains"][0]["target"] = "somewhere-else"
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(corrupt), POLICY, self.ring, MOMENT
            )

        def corrupt_hop(d):
            d["payload"]["chains"][0]["hops"][0] = "bb" * 32
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(corrupt_hop), POLICY, self.ring, MOMENT
            )

    def test_report_missing_a_fork_is_invalid(self):
        def no_forks(d):
            d["payload"]["report"]["forks"] = []
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(no_forks), POLICY, self.ring, MOMENT
            )

    def test_report_fork_table_mismatch_is_invalid(self):
        def bad_audience(d):
            d["payload"]["report"]["forks"][0]["audiences"] = [ALPHA, BETA]
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(bad_audience), POLICY, self.ring, MOMENT
            )

        def bad_ids(d):
            d["payload"]["report"]["forks"][0]["ids"] = ["a"]
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(bad_ids), POLICY, self.ring, MOMENT
            )

    def test_conflicted_binding_mismatch_is_invalid(self):
        def unconflict(d):
            d["payload"]["report"]["items"][0]["status"] = "verified"
            d["payload"]["report"]["items"][0]["error"] = None
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(unconflict), POLICY, self.ring, MOMENT
            )

    def test_report_item_id_must_match_chain_position(self):
        def rename(d):
            d["payload"]["report"]["items"][0]["id"] = "zzz"
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(rename), POLICY, self.ring, MOMENT
            )

    def test_malformed_embedded_receipt_payload_is_invalid(self):
        def corrupt(d):
            receipt = d["payload"]["report"]["items"][0]["result"]["receipt"]
            receipt.pop("version")
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(corrupt), POLICY, self.ring, MOMENT
            )

        def bad_type(d):
            receipt = d["payload"]["report"]["items"][0]["result"]["receipt"]
            receipt["keyVersion"] = True
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                self.reencode(bad_type), POLICY, self.ring, MOMENT
            )

        def bad_item(d):
            receipt = d["payload"]["report"]["items"][0]["result"]["receipt"]
            receipt["items"] = []
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.reencode(bad_item), POLICY, self.ring, MOMENT
            )


class VerifyForkProofsBatchTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.items, _ = fork_batch()
        self.proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )

    def batch(self, *rows):
        return [{"id": i, "proof": p} for i, p in rows]

    def test_structure_validated_upfront(self):
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs((), POLICY, self.ring, MOMENT)
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs([], POLICY, self.ring, MOMENT)
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs(
                [{"id": "x", "proof": "y"}], POLICY, self.ring, MOMENT
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [{"id": "x", "proof": self.proof, "extra": 1}],
                POLICY, self.ring, MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [{"id": "", "proof": self.proof}],
                POLICY, self.ring, MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                self.batch(("dup", self.proof), ("dup", self.proof)),
                POLICY, self.ring, MOMENT,
            )

    def test_shared_material_validated_before_any_proof(self):
        good = self.batch(("a", self.proof))
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                good, {"batch": "x"}, self.ring, MOMENT
            )
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs(good, POLICY, self.ring, True)
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(good, POLICY, self.ring, -1)

    def test_per_item_statuses_in_input_order_with_isolation(self):
        revoked = keyring(**{ISSUER: [entry(1, SECRET_COORD, revoked=True)]})
        revoked_proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )  # valid bytes, current keyring below revokes coord
        rows = [
            ("good", self.proof),
            ("bad", b"{}"),
            ("revoked", revoked_proof),
            ("good2", self.proof),
        ]
        out = verify_receipt_fork_proofs(
            self.batch(*rows), POLICY, revoked, MOMENT
        )
        self.assertEqual(list(out.keys()), ["items", "version"])
        self.assertEqual(out["version"], 1)
        reports = out["items"]
        self.assertEqual([r["id"] for r in reports],
                         ["good", "bad", "revoked", "good2"])
        statuses = [r["status"] for r in reports]
        self.assertEqual(
            statuses,
            ["unauthenticated", "invalid-proof", "unauthenticated",
             "unauthenticated"],
        )
        # With the healthy keyring the same bytes verify.
        out2 = verify_receipt_fork_proofs(
            self.batch(*rows), POLICY, self.ring, MOMENT
        )
        self.assertEqual(
            [r["status"] for r in out2["items"]],
            ["verified", "invalid-proof", "verified", "verified"],
        )
        for row in out2["items"]:
            self.assertEqual(list(row.keys()),
                             ["error", "id", "result", "status"])
            if row["status"] == "verified":
                self.assertIsNone(row["error"])
                self.assertIsNotNone(row["result"])
            else:
                self.assertIsInstance(row["error"], str)
                self.assertNotEqual(row["error"], "")
                self.assertIsNone(row["result"])

    def test_repeated_calls_are_independent(self):
        rows = self.batch(("a", self.proof), ("b", self.proof))
        first = verify_receipt_fork_proofs(rows, POLICY, self.ring, MOMENT)
        first["items"][0]["result"]["chains"][0]["id"] = "tampered"
        second = verify_receipt_fork_proofs(rows, POLICY, self.ring, MOMENT)
        self.assertEqual(second["items"][0]["result"]["chains"][0]["id"], "a")


if __name__ == "__main__":
    unittest.main()
