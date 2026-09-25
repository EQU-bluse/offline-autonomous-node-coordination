"""Tests for the offline signed receipt fork evidence.

Covers :func:`sign_receipt_fork_proof`,
:func:`verify_receipt_fork_proof` and
:func:`verify_receipt_fork_proofs`: the sign-time batch/fork
preconditions and exception taxonomy, the canonical proof encoding and
payload bindings (identity, key version, moment, policy digest, the
complete chain-batch report and the per-chain material summary in input
order), the offline verification rules and credential checks, and the
batch wrapper's upfront shared-material validation, per-item isolation,
input-order reports and fresh results.
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
    verify_batch_receipt_chains,
    verify_receipt_fork_proof,
    verify_receipt_fork_proofs,
)

SECRET_COORD = "11" * 32
SECRET_ALPHA = "22" * 32
SECRET_BETA = "33" * 32
SECRET_GAMMA = "44" * 32
SECRET_DELTA = "55" * 32
SECRET_OTHER = "77" * 32

ISSUER = "coord"
ALPHA = "alpha"
BETA = "beta"
GAMMA = "gamma"
DELTA = "delta"

POLICY = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
UNICODE_POLICY = {"batch": "bätch-1", "sites": {"a": {1}}, "threshold": 1}
MOMENT = 100
SIGN_MOMENT = 150
VERIFY_MOMENT = 200


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


SECRETS = {
    ISSUER: SECRET_COORD,
    ALPHA: SECRET_ALPHA,
    BETA: SECRET_BETA,
    GAMMA: SECRET_GAMMA,
    DELTA: SECRET_DELTA,
}


def sign_bytes(payload, secret):
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


def make_receipt(items=None, issuer=ISSUER, secret=SECRET_COORD,
                 key_version=1, moment=MOMENT, policy=POLICY):
    if items is None:
        items = [{"id": "item-1", "digest": "aa" * 32,
                  "report": make_report()}]
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
        {"payload": payload, "signature": sign_bytes(payload, secret)}
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
        {"payload": payload, "signature": sign_bytes(payload, secret)}
    )


def chain(receipt, path, moments=()):
    hops = []
    upstream = receipt
    domains = [ISSUER] + list(path)
    for index, audience in enumerate(path):
        moment = moments[index] if moments else 110 + index
        hops.append(
            make_hop(
                domains[index], SECRETS[domains[index]], audience,
                upstream, moment,
            )
        )
        upstream = hops[-1]
    return hops


def chain_item(item_id, receipt, path, target=None, moments=()):
    path = list(path)
    return {
        "id": item_id,
        "receipt": receipt,
        "hops": chain(receipt, path, moments),
        "target": target if target is not None else path[-1],
    }


def fork_items(receipt=None):
    """Two chains that fork on their first hop off the base receipt."""
    receipt = receipt if receipt is not None else make_receipt()
    return [
        chain_item("a", receipt, [ALPHA, BETA], moments=(110, 120)),
        chain_item("b", receipt, [GAMMA, DELTA], moments=(111, 121)),
    ]


def rewrap(payload, secret=SECRET_COORD):
    """Sign a (possibly tampered) fork-proof payload into proof bytes."""
    return compact(
        {
            "payload": payload,
            "signature": sign_bytes(payload, secret),
        }
    )


def parse_proof(proof):
    return json.loads(proof.decode("utf-8"))


class SignValidationTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.items = fork_items()

    def test_runs_existing_batch_verification_and_requires_a_fork(self):
        # A single, non-forking chain is a legal batch but cannot anchor a
        # fork proof.
        no_fork = [
            chain_item("a", make_receipt(), [ALPHA, BETA],
                       moments=(110, 120))
        ]
        with self.assertRaises(ValueError):
            sign_receipt_fork_proof(
                no_fork, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
            )

    def test_items_structure_faults_keep_batch_classification(self):
        with self.assertRaises(TypeError):
            sign_receipt_fork_proof(
                "x", POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
            )
        with self.assertRaises(ValueError):
            sign_receipt_fork_proof(
                [], POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
            )
        bad = copy.deepcopy(self.items[0])
        del bad["target"]
        with self.assertRaises(ValueError):
            sign_receipt_fork_proof(
                [bad], POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
            )
        bad = copy.deepcopy(self.items[0])
        bad["receipt"] = "x"
        with self.assertRaises(TypeError):
            sign_receipt_fork_proof(
                [bad], POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
            )
        duplicate = copy.deepcopy(self.items)
        duplicate[1]["id"] = "a"
        with self.assertRaises(ValueError):
            sign_receipt_fork_proof(
                duplicate, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
            )

    def test_identity_version_and_moment_rules(self):
        kwargs = dict(
            items=self.items, policy=POLICY, keyring=self.ring,
            moment=SIGN_MOMENT, issuer=ISSUER, version=1,
        )

        def must_fail(**changed):
            merged = dict(kwargs)
            merged.update(changed)
            with self.assertRaises((TypeError, ValueError)):
                sign_receipt_fork_proof(**merged)

        must_fail(issuer="")          # empty identity -> ValueError
        must_fail(issuer=7)           # wrong type -> TypeError
        must_fail(version=0)          # non-positive -> ValueError
        must_fail(version=-3)
        must_fail(version=True)       # bool never poses as int
        must_fail(moment=-1)          # negative -> ValueError
        must_fail(moment=True)        # bool never poses as int
        must_fail(policy="x")         # wrong type -> TypeError
        must_fail(keyring="x")

    def test_illegal_shared_policy_value_raises_value_error(self):
        bad_policy = {"batch": "x", "sites": {"a": {1}}, "threshold": 2}
        with self.assertRaises(ValueError):
            sign_receipt_fork_proof(
                self.items, bad_policy, self.ring, SIGN_MOMENT, ISSUER, 1
            )
        with self.assertRaises(ValueError):
            sign_receipt_fork_proof(
                self.items, {"batch": "", "sites": {"a": {1}},
                             "threshold": 1},
                self.ring, SIGN_MOMENT, ISSUER, 1,
            )

    def test_signing_credentials_are_checked_with_no_fallback(self):
        # The proof issuer is independent of the chain issuers, so
        # rotating or revoking the signer key leaves the fork summary
        # intact while rejecting the signature step.
        signer = "signer"
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, self.ring, SIGN_MOMENT, "nobody", 1
            )
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, self.ring, SIGN_MOMENT, signer, 1
            )
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, keyring(
                    **{signer: [entry(1, SECRET_COORD)]}
                ),
                SIGN_MOMENT, signer, 2,
            )
        revoked = keyring(**{signer: [entry(1, SECRET_COORD, revoked=True)]})
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, revoked, SIGN_MOMENT, signer, 1
            )
        future_key = keyring(
            **{signer: [entry(1, SECRET_COORD, not_before=180)]}
        )
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, future_key, SIGN_MOMENT, signer, 1
            )
        expired = keyring(
            **{signer: [entry(1, SECRET_COORD, not_after=140)]}
        )
        with self.assertRaises(AuthenticationError):
            sign_receipt_fork_proof(
                self.items, POLICY, expired, SIGN_MOMENT, signer, 1
            )

    def test_inputs_are_not_modified(self):
        items_snapshot = copy.deepcopy(self.items)
        policy_snapshot = copy.deepcopy(POLICY)
        ring_snapshot = copy.deepcopy(self.ring)
        sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )
        self.assertEqual(self.items, items_snapshot)
        self.assertEqual(POLICY, policy_snapshot)
        self.assertEqual(self.ring, ring_snapshot)


class SignedProofShapeTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.receipt = make_receipt()
        self.items = fork_items(self.receipt)
        self.proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.proof, bytes)
        self.assertTrue(self.proof.endswith(b"}"))
        self.assertFalse(self.proof.endswith(b"\n"))
        self.assertNotIn(b"\n", self.proof)
        data = parse_proof(self.proof)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        # Re-encoding the parsed object with recursive key sorting must
        # reproduce every byte.
        self.assertEqual(compact(data), self.proof)

    def test_non_ascii_is_preserved_unescaped(self):
        receipt = make_receipt(policy=UNICODE_POLICY)
        items = fork_items(receipt)
        proof = sign_receipt_fork_proof(
            items, UNICODE_POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )
        self.assertNotIn(b"\\u", proof)
        result = verify_receipt_fork_proof(
            proof, UNICODE_POLICY, self.ring, VERIFY_MOMENT
        )
        canonical_policy = {
            "batch": "bätch-1",
            "sites": {"a": [1]},
            "threshold": 1,
        }
        self.assertEqual(
            result["policyDigest"],
            hashlib.sha256(compact(canonical_policy)).hexdigest(),
        )

    def test_payload_binds_exactly_the_seven_fields(self):
        payload = parse_proof(self.proof)["payload"]
        self.assertEqual(
            set(payload.keys()),
            {"issuer", "keyVersion", "moment", "policy", "report",
             "chains", "version"},
        )
        self.assertEqual(payload["issuer"], ISSUER)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertIsInstance(payload["keyVersion"], int)
        self.assertNotIsInstance(payload["keyVersion"], bool)
        self.assertEqual(payload["moment"], SIGN_MOMENT)
        self.assertEqual(payload["version"], 1)
        canonical_policy = {
            "batch": "batch-1",
            "sites": {"a": [1]},
            "threshold": 1,
        }
        self.assertEqual(
            payload["policy"],
            hashlib.sha256(compact(canonical_policy)).hexdigest(),
        )

    def test_chain_materials_keep_input_order_without_omission(self):
        chains = parse_proof(self.proof)["payload"]["chains"]
        self.assertEqual([chain["id"] for chain in chains], ["a", "b"])
        receipt_digest = hashlib.sha256(self.receipt).hexdigest()
        for position, item in enumerate(self.items):
            material = chains[position]
            self.assertEqual(
                set(material.keys()),
                {"id", "digest", "target", "hops"},
            )
            self.assertEqual(material["id"], item["id"])
            self.assertEqual(
                material["digest"],
                hashlib.sha256(item["receipt"]).hexdigest(),
            )
            self.assertEqual(material["digest"], receipt_digest)
            self.assertEqual(material["target"], item["target"])
            self.assertEqual(
                material["hops"],
                [hashlib.sha256(hop).hexdigest() for hop in item["hops"]],
            )

    def test_complete_report_is_bound(self):
        summary = verify_batch_receipt_chains(
            self.items, POLICY, self.ring, VERIFY_MOMENT
        )
        payload = parse_proof(self.proof)["payload"]
        self.assertEqual(payload["report"], summary)
        self.assertEqual(len(payload["report"]["forks"]), 1)


class VerifySuccessTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.items = fork_items()
        self.proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )

    def test_success_result_is_a_fresh_fixed_key_mapping(self):
        result = verify_receipt_fork_proof(
            self.proof, POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(
            list(result.keys()),
            ["chains", "issuer", "keyVersion", "moment", "policyDigest",
             "proofDigest", "report", "version"],
        )
        self.assertEqual(result["issuer"], ISSUER)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["moment"], SIGN_MOMENT)
        self.assertEqual(result["version"], 1)
        self.assertIsInstance(result["version"], int)
        self.assertNotIsInstance(result["version"], bool)
        canonical_policy = {
            "batch": "batch-1", "sites": {"a": [1]}, "threshold": 1,
        }
        self.assertEqual(
            result["policyDigest"],
            hashlib.sha256(compact(canonical_policy)).hexdigest(),
        )
        self.assertEqual(
            result["proofDigest"],
            hashlib.sha256(self.proof).hexdigest(),
        )
        summary = verify_batch_receipt_chains(
            self.items, POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(result["report"], summary)
        self.assertEqual(
            [chain["id"] for chain in result["chains"]], ["a", "b"]
        )

    def test_repeated_calls_share_no_mutable_object(self):
        first = verify_receipt_fork_proof(
            self.proof, POLICY, self.ring, VERIFY_MOMENT
        )
        first["report"]["forks"][0]["audiences"] = ["tampered"]
        first["chains"][0]["id"] = "tampered"
        second = verify_receipt_fork_proof(
            self.proof, POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(
            second["report"]["forks"][0]["audiences"], [ALPHA, GAMMA]
        )
        self.assertEqual(second["chains"][0]["id"], "a")
        self.assertNotEqual(first, second)
        self.assertIsNot(first["report"], second["report"])
        self.assertIsNot(first["chains"], second["chains"])

    def test_verifies_at_signing_moment_and_does_not_require_receipts(self):
        # Offline: no item material beyond the proof and the policy is
        # needed; the signing moment itself is acceptable.
        result = verify_receipt_fork_proof(
            self.proof, POLICY, self.ring, SIGN_MOMENT
        )
        self.assertEqual(result["moment"], SIGN_MOMENT)

    def test_key_rotation_both_versions_verify(self):
        # The proof issuer is independent of the base receipt issuer, so
        # rotate its credentials while the chain material stays valid.
        signer = "signer"
        ring = keyring(**{
            signer: [
                entry(1, SECRET_OTHER, not_after=180),
                entry(2, SECRET_COORD, not_before=180),
            ]
        })
        old = sign_receipt_fork_proof(
            self.items, POLICY, ring, 160, signer, 1
        )
        new = sign_receipt_fork_proof(
            self.items, POLICY, ring, 190, signer, 2
        )
        self.assertEqual(
            verify_receipt_fork_proof(old, POLICY, ring, 170)["keyVersion"],
            1,
        )
        # At moment 200 version 1 has expired -- a current check rejects
        # it even though it was valid when signed -- while version 2 still
        # verifies.
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(old, POLICY, ring, 200)
        self.assertEqual(
            verify_receipt_fork_proof(new, POLICY, ring, 200)["keyVersion"],
            2,
        )


class VerifyProofStructureTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.items = fork_items()
        self.proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )

    def payload(self):
        return parse_proof(self.proof)["payload"]

    def assert_invalid(self, raw):
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(raw, POLICY, self.ring, VERIFY_MOMENT)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                "x", POLICY, self.ring, VERIFY_MOMENT
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
                self.proof, {"batch": "x"}, self.ring, VERIFY_MOMENT
            )

    def test_encoding_faults_are_invalid_proofs(self):
        self.assert_invalid(self.proof + b"\n")
        self.assert_invalid(self.proof + b" ")
        self.assert_invalid(b"")
        self.assert_invalid(b"{")
        self.assert_invalid("héllo".encode("latin-1"))
        # A JSON value of the wrong outer type is a field type fault.
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                b"[]", POLICY, self.ring, VERIFY_MOMENT
            )

    def test_top_and_payload_key_sets(self):
        data = parse_proof(self.proof)
        del data["signature"]
        self.assert_invalid(compact(data))
        data = parse_proof(self.proof)
        data["extra"] = 1
        self.assert_invalid(compact(data))
        payload = self.payload()
        del payload["report"]
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["extra"] = 1
        self.assert_invalid(rewrap(payload))

    def test_version_must_be_integer_one(self):
        payload = self.payload()
        payload["version"] = 2
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["version"] = True
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                rewrap(payload), POLICY, self.ring, VERIFY_MOMENT
            )

    def test_field_type_faults_inside_the_proof_are_type_errors(self):
        checks = [
            ("issuer", 7, TypeError),
            ("issuer", "", InvalidReceiptForkProofError),
            ("keyVersion", "1", TypeError),
            ("keyVersion", 0, InvalidReceiptForkProofError),
            ("keyVersion", True, TypeError),
            ("moment", "150", TypeError),
            ("moment", -1, InvalidReceiptForkProofError),
            ("moment", True, TypeError),
            ("policy", 7, TypeError),
            ("policy", "z" * 64, InvalidReceiptForkProofError),
            ("report", [], TypeError),
            ("chains", {}, TypeError),
        ]
        for field, value, expected in checks:
            payload = self.payload()
            payload[field] = value
            with self.assertRaises(expected):
                verify_receipt_fork_proof(
                    rewrap(payload), POLICY, self.ring, VERIFY_MOMENT
                )

    def test_signature_format_fault(self):
        data = parse_proof(self.proof)
        data["signature"] = "zz" * 32
        self.assert_invalid(compact(data))
        data = parse_proof(self.proof)
        data["signature"] = 7
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                compact(data), POLICY, self.ring, VERIFY_MOMENT
            )

    def test_non_canonical_encoding_is_invalid(self):
        text = self.proof.decode("utf-8")
        # A trailing space and a pretty-printed form are both rejected.
        self.assert_invalid((text + " ").encode("utf-8"))
        pretty = json.dumps(
            parse_proof(self.proof), ensure_ascii=False, indent=2
        ).encode("utf-8")
        self.assert_invalid(pretty)

    def test_duplicate_object_keys_are_invalid(self):
        text = self.proof.decode("utf-8")
        marker = '"version":1'
        duplicated = text.replace(
            marker, marker + ',' + marker, 1
        ).encode("utf-8")
        self.assert_invalid(duplicated)

    def test_chains_structure_faults(self):
        payload = self.payload()
        payload["chains"] = []
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0] = []
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                rewrap(payload), POLICY, self.ring, VERIFY_MOMENT
            )
        payload = self.payload()
        del payload["chains"][0]["hops"]
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0]["id"] = ""
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0]["digest"] = "z" * 64
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0]["hops"] = []
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0]["hops"][0] = "z" * 64
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][1]["id"] = "a"
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0]["hops"] = "x"
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                rewrap(payload), POLICY, self.ring, VERIFY_MOMENT
            )

    def test_chain_materials_must_not_be_reordered_or_omitted(self):
        payload = self.payload()
        payload["chains"] = list(reversed(payload["chains"]))
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"] = [payload["chains"][0]]
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0]["digest"] = "bb" * 32
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0]["hops"][0] = "bb" * 32
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["chains"][0]["target"] = GAMMA
        self.assert_invalid(rewrap(payload))

    def test_report_key_set_and_version(self):
        payload = self.payload()
        del payload["report"]["version"]
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["report"]["extra"] = 1
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["report"]["version"] = 2
        self.assert_invalid(rewrap(payload))

    def test_report_without_a_fork_is_invalid(self):
        # Build a proof payload over a non-forking batch and reuse the
        # matching (single-chain) report and chain materials.
        receipt = make_receipt(items=[
            {"id": "solo", "digest": "aa" * 32,
             "report": make_report("solo")}
        ])
        items = [
            chain_item("solo", receipt, [ALPHA, BETA], moments=(110, 120))
        ]
        report = verify_batch_receipt_chains(
            items, POLICY, self.ring, VERIFY_MOMENT
        )
        canonical_policy = {
            "batch": "batch-1", "sites": {"a": [1]}, "threshold": 1,
        }
        payload = {
            "issuer": ISSUER,
            "keyVersion": 1,
            "moment": SIGN_MOMENT,
            "policy": hashlib.sha256(compact(canonical_policy)).hexdigest(),
            "report": report,
            "chains": [
                {
                    "id": "solo",
                    "digest": hashlib.sha256(receipt).hexdigest(),
                    "target": BETA,
                    "hops": [
                        hashlib.sha256(hop).hexdigest() for hop in items[0]["hops"]
                    ],
                }
            ],
            "version": 1,
        }
        self.assert_invalid(rewrap(payload))

    def test_report_item_bindings(self):
        # The item id at a position must equal the chain material id.
        payload = self.payload()
        payload["report"]["items"][0]["id"] = "b"
        self.assert_invalid(rewrap(payload))
        # A successful result must bind the chain's base digest.
        payload = self.payload()
        payload["report"]["items"][0]["result"]["receiptDigest"] = "cc" * 32
        self.assert_invalid(rewrap(payload))
        # The hop count must match the materials.
        payload = self.payload()
        result_hops = payload["report"]["items"][0]["result"]["hops"]
        result_hops.append(copy.deepcopy(result_hops[-1]))
        self.assert_invalid(rewrap(payload))
        # Hop upstream chaining inside the bound result must agree with
        # the material digests.
        payload = self.payload()
        hops = payload["report"]["items"][0]["result"]["hops"]
        hops[1]["upstream"] = "dd" * 32
        self.assert_invalid(rewrap(payload))
        # The final audience must equal the target.
        payload = self.payload()
        payload["report"]["items"][0]["result"]["target"] = GAMMA
        self.assert_invalid(rewrap(payload))
        # The embedded base receipt must share the proof policy.
        payload = self.payload()
        receipt_payload = payload["report"]["items"][0]["result"]["receipt"]
        receipt_payload["policy"] = "ee" * 32
        self.assert_invalid(rewrap(payload))
        # A verified/conflicted result cannot carry the wrong error.
        payload = self.payload()
        payload["report"]["items"][0]["error"] = "boom"
        self.assert_invalid(rewrap(payload))

    def test_fork_bindings(self):
        # Forks must be sorted by receiptDigest then upstream.
        payload = self.payload()
        forks = payload["report"]["forks"]
        self.assertEqual(
            [(f["receiptDigest"], f["upstream"]) for f in forks],
            sorted((f["receiptDigest"], f["upstream"]) for f in forks),
        )
        # Audiences and ids are ascending and complete.
        fork = forks[0]
        self.assertEqual(fork["audiences"], [ALPHA, GAMMA])
        self.assertEqual(fork["ids"], ["a", "b"])
        # Tampering with an audience invalidates the proof.
        payload = self.payload()
        payload["report"]["forks"][0]["audiences"] = [ALPHA, BETA]
        self.assert_invalid(rewrap(payload))
        # Dropping a crossing chain invalidates the proof.
        payload = self.payload()
        payload["report"]["forks"][0]["ids"] = ["a"]
        self.assert_invalid(rewrap(payload))
        # Inventing an extra fork edge invalidates the proof.
        payload = self.payload()
        extra = copy.deepcopy(payload["report"]["forks"][0])
        extra["upstream"] = "ff" * 32
        payload["report"]["forks"].append(extra)
        self.assert_invalid(rewrap(payload))
        # The conflicted items must equal the chains crossing fork edges.
        payload = self.payload()
        payload["report"]["items"][0]["status"] = "verified"
        payload["report"]["items"][0]["error"] = None
        self.assert_invalid(rewrap(payload))

    def test_policy_and_moment_bindings(self):
        other = {"batch": "other", "sites": {"a": {1}}, "threshold": 1}
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.proof, other, self.ring, VERIFY_MOMENT
            )
        # A signing moment later than the verification moment is invalid.
        with self.assertRaises(InvalidReceiptForkProofError):
            verify_receipt_fork_proof(
                self.proof, POLICY, self.ring, SIGN_MOMENT - 1
            )


    def test_chain_materials_cover_a_failed_chain_in_a_fork_batch(self):
        # Two verified chains fork; a third chain fails single-chain
        # verification. Its material is still summarized in input order
        # and the proof still signs because one fork exists.
        third = chain_item("c", make_receipt(), [ALPHA])
        third["hops"][0] = third["hops"][0] + b"\n"
        items = self.items + [third]
        proof = sign_receipt_fork_proof(
            items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )
        result = verify_receipt_fork_proof(
            proof, POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(
            [chain["id"] for chain in result["chains"]], ["a", "b", "c"]
        )
        self.assertEqual(
            result["chains"][2]["digest"],
            hashlib.sha256(third["receipt"]).hexdigest(),
        )
        statuses = {
            row["id"]: row["status"] for row in result["report"]["items"]
        }
        self.assertEqual(statuses["c"], "invalid-delegation")
        self.assertEqual(statuses["a"], "conflicted")

    def test_nested_bool_never_poses_as_int(self):
        payload = self.payload()
        payload["report"]["items"][0]["result"]["version"] = True
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                rewrap(payload), POLICY, self.ring, VERIFY_MOMENT
            )
        payload = self.payload()
        payload["report"]["items"][0]["result"]["hops"][0][
            "keyVersion"
        ] = True
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                rewrap(payload), POLICY, self.ring, VERIFY_MOMENT
            )
        payload = self.payload()
        payload["report"]["version"] = True
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                rewrap(payload), POLICY, self.ring, VERIFY_MOMENT
            )
        payload = self.payload()
        payload["chains"][0]["hops"] = True
        with self.assertRaises(TypeError):
            verify_receipt_fork_proof(
                rewrap(payload), POLICY, self.ring, VERIFY_MOMENT
            )

    def test_resigned_tampered_report_is_still_rejected(self):
        # Re-signing with the legitimate key cannot launder a binding
        # change: the fork edges are recomputed from the bound results.
        payload = self.payload()
        payload["report"]["forks"][0]["ids"] = ["a"]
        raw = rewrap(payload)
        # Signature is now valid, but the bindings are not.
        self.assert_invalid(raw)


class VerifyAuthenticationTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.items = fork_items()
        self.proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )

    def test_signature_mismatch_is_authentication_error(self):
        data = parse_proof(self.proof)
        last = data["signature"]
        data["signature"] = (
            "0" * 64 if last != "0" * 64 else "1" * 64
        )
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                compact(data), POLICY, self.ring, VERIFY_MOMENT
            )

    def test_tampered_payload_fails_structure_or_signature(self):
        # A mutation that keeps the proof structurally legal still cannot
        # match the HMAC; the structural binding is checked first so the
        # exact class follows the mutation, but neither can authenticate.
        mutated = bytearray(self.proof)
        mutated[20] = ord("0") if mutated[20] != ord("0") else ord("1")
        with self.assertRaises(
            (InvalidReceiptForkProofError, AuthenticationError)
        ):
            verify_receipt_fork_proof(
                bytes(mutated), POLICY, self.ring, VERIFY_MOMENT
            )

    def test_unknown_credentials(self):
        ring = {node: entries for node, entries in self.ring.items()
                if node != ISSUER}
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, ring, VERIFY_MOMENT
            )
        ring = keyring(**{ISSUER: [entry(2, SECRET_OTHER)]})
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, ring, VERIFY_MOMENT
            )

    def test_revoked_not_yet_valid_and_expired(self):
        revoked = keyring(**{ISSUER: [entry(1, SECRET_COORD, revoked=True)]})
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, revoked, VERIFY_MOMENT
            )
        future = keyring(
            **{ISSUER: [entry(1, SECRET_COORD, not_before=250)]}
        )
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, future, VERIFY_MOMENT
            )
        expired = keyring(
            **{ISSUER: [entry(1, SECRET_COORD, not_after=180)]}
        )
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, expired, VERIFY_MOMENT
            )

    def test_wrong_key_secret_is_a_signature_mismatch(self):
        ring = keyring(**{ISSUER: [entry(1, SECRET_OTHER)]})
        with self.assertRaises(AuthenticationError):
            verify_receipt_fork_proof(
                self.proof, POLICY, ring, VERIFY_MOMENT
            )

    def test_authentication_error_is_a_value_error(self):
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class ForkProofsBatchTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.items = fork_items()
        self.proof = sign_receipt_fork_proof(
            self.items, POLICY, self.ring, SIGN_MOMENT, ISSUER, 1
        )

    def good(self, item_id="x"):
        return {"id": item_id, "proof": self.proof}

    def test_structure_validated_before_shared_material_and_proofs(self):
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs("x", POLICY, self.ring, VERIFY_MOMENT)
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs(["x"], POLICY, self.ring, VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs([], POLICY, self.ring, VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [{"id": "", "proof": self.proof}],
                POLICY, self.ring, VERIFY_MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [self.good("a"), self.good("a")],
                POLICY, self.ring, VERIFY_MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [{"id": "a", "proof": self.proof, "extra": 1}],
                POLICY, self.ring, VERIFY_MOMENT,
            )
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs(
                [{"id": "a", "proof": "x"}],
                POLICY, self.ring, VERIFY_MOMENT,
            )
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs(
                [{"id": 7, "proof": self.proof}],
                POLICY, self.ring, VERIFY_MOMENT,
            )

    def test_shared_materials_validated_upfront(self):
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [self.good()], {"batch": "x"}, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs(
                [self.good()], POLICY, "x", VERIFY_MOMENT
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [self.good()], POLICY, {"": []}, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_receipt_fork_proofs(
                [self.good()], POLICY, self.ring, True
            )
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [self.good()], POLICY, self.ring, -1
            )

    def test_batch_level_fault_surfaces_even_when_a_proof_is_bad(self):
        bad_proof_item = {"id": "a", "proof": b"{}"}
        duplicate_key = {"id": "a", "proof": self.proof}
        with self.assertRaises(ValueError):
            verify_receipt_fork_proofs(
                [bad_proof_item, duplicate_key],
                POLICY, self.ring, VERIFY_MOMENT,
            )

    def test_per_item_isolation_in_input_order(self):
        invalid_bytes = {"id": "i", "proof": b"{}"}
        unauthenticated = {"id": "u", "proof": self._proof_with_other_secret()}
        bad_signature = self._bad_signature_item("s")
        good_one = {"id": "g1", "proof": self.proof}
        good_two = {"id": "g2", "proof": self.proof}

        report = verify_receipt_fork_proofs(
            [good_one, invalid_bytes, unauthenticated, bad_signature,
             good_two],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual(list(report.keys()), ["items", "version"])
        self.assertEqual(report["version"], 1)
        self.assertEqual(
            [row["id"] for row in report["items"]],
            ["g1", "i", "u", "s", "g2"],
        )
        statuses = [row["status"] for row in report["items"]]
        self.assertEqual(
            statuses,
            ["verified", "invalid-proof", "unauthenticated",
             "unauthenticated", "verified"],
        )
        for row in report["items"]:
            self.assertEqual(
                list(row.keys()), ["error", "id", "result", "status"]
            )
            if row["status"] == "verified":
                self.assertIsNone(row["error"])
                self.assertIsNotNone(row["result"])
            else:
                self.assertIsInstance(row["error"], str)
                self.assertNotEqual(row["error"], "")
                self.assertIsNone(row["result"])
        self.assertIn("invalid", report["items"][1]["error"])
        # Identity of an unauthenticated payload never enters a result.
        self.assertIsNone(report["items"][2]["result"])

    def _proof_with_other_secret(self):
        data = parse_proof(self.proof)
        return rewrap(data["payload"], secret=SECRET_OTHER)

    def _bad_signature_item(self, item_id):
        data = parse_proof(self.proof)
        data["signature"] = "0" * 64
        return {"id": item_id, "proof": compact(data)}

    def test_one_failure_does_not_change_other_reports(self):
        report = verify_receipt_fork_proofs(
            [
                {"id": "a", "proof": self.proof},
                {"id": "b", "proof": self._proof_with_other_secret()},
            ],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["verified", "unauthenticated"],
        )
        single = verify_receipt_fork_proof(
            self.proof, POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(report["items"][0]["result"], single)

    def test_results_are_fresh_and_independent(self):
        report = verify_receipt_fork_proofs(
            [self.good()], POLICY, self.ring, VERIFY_MOMENT
        )
        report["items"][0]["result"]["report"]["forks"] = []
        again = verify_receipt_fork_proofs(
            [self.good()], POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(len(again["items"][0]["result"]["report"]["forks"]), 1)

    def test_inputs_are_not_modified(self):
        items = [self.good(), self.good("y")]
        snapshot = copy.deepcopy(items)
        policy_snapshot = copy.deepcopy(POLICY)
        verify_receipt_fork_proofs(
            items, POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(items, snapshot)
        self.assertEqual(POLICY, policy_snapshot)


if __name__ == "__main__":
    unittest.main()
