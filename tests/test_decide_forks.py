"""Tests for the offline multi-site fork disposition decision.

Covers :func:`decide_forks`, :func:`verify_fork_decision` and
:func:`verify_fork_decisions`: input and policy validation, the
verify-then-authorize-then-authenticate per-proof pipeline with its
fixed reasons, same-site duplicate/contradiction handling, cross-site
fork-boundary agreement, threshold acceptance and the isolate/rollback/
manual-review recommendations, the canonical signed packet and its
bindings, the offline re-tally verification and credential rules, and
the batch wrapper's upfront validation, per-item isolation, input-order
reports and fresh results.
"""

import copy
import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    AuthenticationError,
    InvalidForkDecisionError,
    decide_forks,
    sign_receipt_fork_proof,
    verify_fork_decision,
    verify_fork_decisions,
)

SECRET_COORD = "11" * 32
SECRET_ALPHA = "22" * 32
SECRET_BETA = "33" * 32
SECRET_GAMMA = "44" * 32
SECRET_DELTA = "55" * 32
SECRET_OTHER = "77" * 32

COORD = "coord"
ALPHA = "alpha"
BETA = "beta"
GAMMA = "gamma"
DELTA = "delta"

BASE = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
BASE_OTHER = {"batch": "other", "sites": {"a": {1}}, "threshold": 1}
UNICODE_BASE = {"batch": "bätch-1", "sites": {"a": {1}}, "threshold": 1}

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


SECRETS = {
    COORD: SECRET_COORD,
    ALPHA: SECRET_ALPHA,
    BETA: SECRET_BETA,
    GAMMA: SECRET_GAMMA,
    DELTA: SECRET_DELTA,
}


def keyring(**overrides):
    ring = {node: [entry(1, secret)] for node, secret in SECRETS.items()}
    ring.update(overrides)
    return ring


RING = keyring()


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


def make_receipt(policy=BASE, item_id="item-1"):
    canonical_policy = {
        "batch": policy["batch"],
        "sites": {
            site: sorted(policy["sites"][site])
            for site in sorted(policy["sites"])
        },
        "threshold": policy["threshold"],
    }
    payload = {
        "issuer": COORD,
        "keyVersion": 1,
        "moment": 100,
        "policy": hashlib.sha256(compact(canonical_policy)).hexdigest(),
        "items": [{"id": item_id, "digest": "aa" * 32,
                   "report": make_report(item_id)}],
        "version": 1,
    }
    return compact(
        {"payload": payload, "signature": sign_bytes(payload, SECRET_COORD)}
    )


def make_hop(issuer, audience, upstream, moment, secret=None):
    payload = {
        "issuer": issuer,
        "keyVersion": 1,
        "moment": moment,
        "audience": audience,
        "upstream": hashlib.sha256(upstream).hexdigest(),
        "version": 1,
    }
    return compact(
        {"payload": payload,
         "signature": sign_bytes(payload, secret or SECRETS[issuer])}
    )


def fork_chain_items(first, receipt=None, moments=(110, 120)):
    """Two chains forking off one receipt at their second hop.

    Both chains first delegate ``coord -> first``; they then split to
    ``beta`` and ``gamma``, so the forking edge is the digest of the
    shared first hop with audiences ``{beta, gamma}``.
    """
    receipt = receipt if receipt is not None else make_receipt()
    to_beta = [
        make_hop(COORD, first, receipt, moments[0]),
    ]
    to_beta.append(make_hop(first, BETA, to_beta[0], moments[1]))
    to_gamma = [
        make_hop(COORD, first, receipt, moments[0]),
    ]
    to_gamma.append(make_hop(first, GAMMA, to_gamma[0], moments[1]))
    return [
        {"id": "a", "receipt": receipt, "hops": to_beta, "target": BETA},
        {"id": "b", "receipt": receipt, "hops": to_gamma, "target": GAMMA},
    ]


def fork_proof(issuer, first=ALPHA, policy=BASE, moment=SIGN_MOMENT,
               version=1, receipt=None):
    items = fork_chain_items(first, receipt=receipt)
    return sign_receipt_fork_proof(items, policy, RING, moment, issuer, version)


def policy(action="isolate", sites=None, threshold=2, base=BASE):
    if sites is None:
        sites = {ALPHA: {1}, BETA: {1}, GAMMA: {1}, DELTA: {1}}
    return {"action": action, "base": base, "sites": sites,
            "threshold": threshold}


def decision(items, pol=None, ring=None, moment=MOMENT,
             issuer=COORD, version=1):
    return decide_forks(
        items, pol or policy(), ring or RING, moment, issuer, version
    )


def proof_item(item_id, proof):
    return {"id": item_id, "proof": proof}


def parse(raw):
    return json.loads(raw.decode("utf-8"))


def rewrap(payload, secret=SECRET_COORD):
    return compact({"payload": payload,
                    "signature": sign_bytes(payload, secret)})


class DecideValidationTest(unittest.TestCase):
    def setUp(self):
        self.proof_alpha = fork_proof(ALPHA)
        self.proof_beta = fork_proof(BETA)
        self.items = [proof_item("x", self.proof_alpha),
                      proof_item("y", self.proof_beta)]

    def test_items_container_type_faults(self):
        with self.assertRaises(TypeError):
            decision("x")
        with self.assertRaises(TypeError):
            decision(["x"])
        with self.assertRaises(TypeError):
            decision([{"id": 1, "proof": self.proof_alpha}])
        with self.assertRaises(TypeError):
            decision([{"id": "x", "proof": "y"}])

    def test_items_value_faults(self):
        with self.assertRaises(ValueError):
            decision([])
        with self.assertRaises(ValueError):
            decision([{"id": "", "proof": self.proof_alpha}])
        with self.assertRaises(ValueError):
            decision([
                proof_item("x", self.proof_alpha),
                proof_item("x", self.proof_beta),
            ])
        with self.assertRaises(ValueError):
            decision([{"id": "x", "proof": self.proof_alpha, "n": 1}])

    def test_policy_must_carry_exactly_the_four_fields(self):
        good = policy()
        for key in ("action", "base", "sites", "threshold"):
            bad = dict(good)
            del bad[key]
            with self.assertRaises(ValueError):
                decision(self.items, bad)
        extra = dict(good, extra=1)
        with self.assertRaises(ValueError):
            decision(self.items, extra)

    def test_policy_type_faults(self):
        with self.assertRaises(TypeError):
            decide_forks(self.items, "x", RING, MOMENT, COORD, 1)
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(base="x"), RING, MOMENT, COORD, 1)
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(sites="x"), RING, MOMENT, COORD, 1)

    def test_policy_action_enum(self):
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(action=7), RING, MOMENT, COORD, 1)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(action="wipe"),
                         RING, MOMENT, COORD, 1)

    def test_policy_sites_and_versions(self):
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(sites={}),
                         RING, MOMENT, COORD, 1)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(sites={"": {1}}),
                         RING, MOMENT, COORD, 1)
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(sites={ALPHA: [1]}),
                         RING, MOMENT, COORD, 1)
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(sites={ALPHA: {True}}),
                         RING, MOMENT, COORD, 1)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(sites={ALPHA: {0}}),
                         RING, MOMENT, COORD, 1)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(sites={ALPHA: set()}),
                         RING, MOMENT, COORD, 1)

    def test_policy_threshold_bounds(self):
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(threshold=True),
                         RING, MOMENT, COORD, 1)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(threshold=0),
                         RING, MOMENT, COORD, 1)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(threshold=5),
                         RING, MOMENT, COORD, 1)

    def test_invalid_base_policy_is_a_value_error(self):
        bad_base = {"batch": "x"}
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(base=bad_base),
                         RING, MOMENT, COORD, 1)

    def test_moment_issuer_version_rules(self):
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(), RING, True, COORD, 1)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(), RING, -1, COORD, 1)
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(), RING, MOMENT, 7, 1)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(), RING, MOMENT, "", 1)
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(), RING, MOMENT, COORD, True)
        with self.assertRaises(ValueError):
            decide_forks(self.items, policy(), RING, MOMENT, COORD, 0)

    def test_keyring_type_faults(self):
        with self.assertRaises(TypeError):
            decide_forks(self.items, policy(), "x", MOMENT, COORD, 1)

    def test_signing_credentials_have_no_fallback(self):
        with self.assertRaises(AuthenticationError):
            decision(self.items, issuer="nobody")
        # Unknown version for a known issuer.
        with self.assertRaises(AuthenticationError):
            decision(self.items, issuer=COORD, version=2)
        revoked = keyring(**{COORD: [entry(1, SECRET_COORD, revoked=True)]})
        with self.assertRaises(AuthenticationError):
            decision(self.items, ring=revoked)
        future = keyring(**{COORD: [entry(1, SECRET_COORD, not_before=250)]})
        with self.assertRaises(AuthenticationError):
            decision(self.items, ring=future)
        expired = keyring(**{COORD: [entry(1, SECRET_COORD, not_after=180)]})
        with self.assertRaises(AuthenticationError):
            decision(self.items, ring=expired)

    def test_inputs_are_not_modified(self):
        snapshot = copy.deepcopy((self.items, policy(), RING))
        decision(self.items)
        self.assertEqual((self.items, policy(), RING), snapshot)


class PerItemRulingTest(unittest.TestCase):
    def setUp(self):
        self.proof_alpha = fork_proof(ALPHA)
        self.proof_beta = fork_proof(BETA)

    def decide_rows(self, items, pol=None):
        raw = decision(items, pol or policy())
        return verify_fork_decision(raw, pol or policy(), RING, MOMENT)[
            "decisions"
        ]

    def test_invalid_bytes_are_rejected_alone(self):
        rows = self.decide_rows([
            proof_item("good", self.proof_alpha),
            proof_item("bad", b"{}"),
            proof_item("good2", self.proof_beta),
        ])
        by_id = {row["id"]: row for row in rows}
        bad = by_id["bad"]
        self.assertEqual(bad["conclusion"], "invalid")
        self.assertEqual(bad["reason"], "invalid-proof")
        self.assertIsNone(bad["site"])
        self.assertIsNone(bad["keyVersion"])
        self.assertIsNone(bad["boundaries"])
        # The valid items are unaffected and the batch can still accept.
        self.assertEqual(by_id["good"]["conclusion"], "valid")
        self.assertEqual(by_id["good2"]["conclusion"], "valid")

    def test_empty_proof_bytes_are_invalid_proof(self):
        rows = self.decide_rows([proof_item("e", b"")])
        self.assertEqual(rows[0]["reason"], "invalid-proof")
        self.assertIsNone(rows[0]["site"])

    def test_unauthorized_site(self):
        pol = policy(sites={BETA: {1}, GAMMA: {1}})
        rows = self.decide_rows([
            proof_item("x", self.proof_alpha),
            proof_item("y", self.proof_beta),
        ], pol)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(by_id["x"]["conclusion"], "invalid")
        self.assertEqual(by_id["x"]["reason"], "unauthorized-site")
        self.assertEqual(by_id["x"]["site"], ALPHA)
        self.assertIsNotNone(by_id["x"]["boundaries"])
        self.assertEqual(by_id["y"]["conclusion"], "valid")

    def test_unauthorized_version(self):
        pol = policy(sites={ALPHA: {2}, BETA: {1}})
        rows = self.decide_rows([
            proof_item("x", self.proof_alpha),
            proof_item("y", self.proof_beta),
        ], pol)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(by_id["x"]["reason"], "unauthorized-version")
        self.assertEqual(by_id["x"]["keyVersion"], 1)

    def test_credential_states(self):
        pol = policy(sites={ALPHA: {1}}, threshold=1)
        cases = [
            (keyring(**{ALPHA: [entry(2, SECRET_OTHER)]}),
             "credential-unavailable"),
            (keyring(**{ALPHA: [entry(1, SECRET_ALPHA, revoked=True)]}),
             "revoked"),
            (keyring(**{ALPHA: [entry(1, SECRET_ALPHA, not_before=250)]}),
             "not-yet-valid"),
            (keyring(**{ALPHA: [entry(1, SECRET_ALPHA, not_after=180)]}),
             "expired"),
        ]
        for ring, reason in cases:
            raw = decide_forks(
                [proof_item("x", fork_proof(ALPHA))], pol, ring,
                MOMENT, COORD, 1,
            )
            rows = verify_fork_decision(raw, pol, ring, MOMENT)["decisions"]
            self.assertEqual(rows[0]["reason"], reason)

    def test_bad_signature(self):
        data = parse(self.proof_alpha)
        forged = rewrap(data["payload"], secret=SECRET_OTHER)
        rows = self.decide_rows([proof_item("x", forged)])
        self.assertEqual(rows[0]["reason"], "bad-signature")
        self.assertEqual(rows[0]["site"], ALPHA)

    def test_wrong_base_policy_is_invalid_proof_without_identity(self):
        # The fork proof and its embedded base receipt must both be bound
        # to the other base policy for the proof itself to be structurally
        # valid under sign_receipt_fork_proof.
        other = fork_proof(
            ALPHA, policy=BASE_OTHER, receipt=make_receipt(BASE_OTHER)
        )
        rows = self.decide_rows([proof_item("x", other)])
        self.assertEqual(rows[0]["reason"], "invalid-proof")
        self.assertIsNone(rows[0]["site"])

    def test_future_dated_proof_is_invalid_proof(self):
        future = fork_proof(ALPHA, moment=SIGN_MOMENT + 100)
        rows = self.decide_rows([proof_item("x", future)])
        self.assertEqual(rows[0]["reason"], "invalid-proof")

    def test_duplicate_digest_counts_once(self):
        pol = policy(sites={ALPHA: {1}}, threshold=1)
        raw = decision([
            proof_item("first", self.proof_alpha),
            proof_item("second", self.proof_alpha),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        rows = {row["id"]: row for row in result["decisions"]}
        self.assertEqual(rows["first"]["conclusion"], "valid")
        self.assertIsNone(rows["first"]["reason"])
        self.assertEqual(rows["second"]["conclusion"], "duplicate")
        self.assertEqual(rows["second"]["reason"], "duplicate")
        # One site still meets a threshold of one.
        self.assertEqual(result["status"], "accepted")

    def test_same_site_duplicates_alone_cannot_meet_threshold_two(self):
        pol = policy(threshold=2, sites={ALPHA: {1}, BETA: {1}})
        raw = decision([
            proof_item("a", self.proof_alpha),
            proof_item("b", self.proof_alpha),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        self.assertEqual(result["status"], "insufficient")
        conclusions = {row["id"]: row["conclusion"]
                       for row in result["decisions"]}
        self.assertEqual(conclusions, {"a": "valid", "b": "duplicate"})

    def test_same_site_different_proofs_contradict(self):
        pol = policy(sites={ALPHA: {1}, DELTA: {1}}, threshold=1)
        raw = decision([
            proof_item("a", fork_proof(ALPHA, first=ALPHA)),
            proof_item("b", fork_proof(ALPHA, first=DELTA)),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        self.assertEqual(result["status"], "conflicted")
        for row in result["decisions"]:
            self.assertEqual(row["site"], ALPHA)
            self.assertEqual(row["conclusion"], "contradiction")
            self.assertEqual(row["reason"], "contradiction")


class AggregationTest(unittest.TestCase):
    def test_accepted_isolate_dedups_and_sorts_targets(self):
        pol = policy(action="isolate", threshold=2)
        raw = decision([
            proof_item("x", fork_proof(ALPHA)),
            proof_item("y", fork_proof(BETA)),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["recommendation"], "isolate")
        self.assertEqual(result["action"], "isolate")
        self.assertEqual(result["targets"], [BETA, GAMMA])
        receipts = {b["receiptDigest"] for b in result["boundaries"]}
        self.assertEqual(len(receipts), 1)
        self.assertEqual(
            sorted((b["upstream"], b["target"]) for b in result["boundaries"]),
            sorted((b["upstream"], b["target"]) for b in result["boundaries"]),
        )

    def test_accepted_rollback(self):
        pol = policy(action="rollback", threshold=2)
        raw = decision([
            proof_item("x", fork_proof(ALPHA)),
            proof_item("y", fork_proof(BETA)),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["recommendation"], "rollback")
        # Rollback still names the fork boundaries but acts on no domain.
        self.assertEqual(result["targets"], [BETA, GAMMA])
        self.assertEqual(len(result["boundaries"]), 2)

    def test_below_threshold_is_insufficient_and_claims_nothing(self):
        pol = policy(threshold=3)
        raw = decision([
            proof_item("x", fork_proof(ALPHA)),
            proof_item("y", fork_proof(BETA)),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["recommendation"], "manual-review")
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["boundaries"], [])

    def test_cross_site_boundary_disagreement_is_conflicted(self):
        pol = policy(threshold=2)
        raw = decision([
            proof_item("x", fork_proof(ALPHA, first=ALPHA)),
            proof_item("y", fork_proof(BETA, first=DELTA)),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        self.assertEqual(result["status"], "conflicted")
        self.assertEqual(result["recommendation"], "manual-review")
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["boundaries"], [])
        # The rows themselves stay valid -- the fork is between sites.
        self.assertTrue(
            all(row["conclusion"] == "valid"
                for row in result["decisions"])
        )

    def test_only_valid_rows_count_toward_the_threshold(self):
        pol = policy(threshold=2)
        raw = decision([
            proof_item("x", fork_proof(ALPHA)),
            proof_item("bad", b"{}"),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        self.assertEqual(result["status"], "insufficient")

    def test_decisions_sort_by_site_then_id_with_invalid_rows_first(self):
        pol = policy()
        raw = decision([
            proof_item("z", fork_proof(BETA)),
            proof_item("a", fork_proof(ALPHA)),
            proof_item("m", b"{}"),
        ], pol)
        result = verify_fork_decision(raw, pol, RING, MOMENT)
        # Invalid (null-site) rows come first, then site and id ascending;
        # this matches the adjudication report ordering.
        sites_ids = [
            (row["site"] is not None, row["site"], row["id"])
            for row in result["decisions"]
        ]
        self.assertEqual(sites_ids, sorted(sites_ids))
        self.assertIsNone(result["decisions"][0]["site"])


class PacketShapeTest(unittest.TestCase):
    def setUp(self):
        self.proof_alpha = fork_proof(ALPHA)
        self.proof_beta = fork_proof(BETA)
        self.items = [proof_item("x", self.proof_alpha),
                      proof_item("y", self.proof_beta)]
        self.pol = policy()
        self.raw = decision(self.items, self.pol)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertFalse(self.raw.endswith(b"\n"))
        self.assertNotIn(b"\n", self.raw)
        data = parse(self.raw)
        self.assertEqual(compact(data), self.raw)

    def test_non_ascii_is_preserved_unescaped(self):
        upol = policy(base=UNICODE_BASE,
                      sites={ALPHA: {1}, BETA: {1}}, threshold=2)
        receipt = make_receipt(UNICODE_BASE)
        raw = decision([
            proof_item("x", fork_proof(ALPHA, policy=UNICODE_BASE,
                                       receipt=receipt)),
            proof_item("y", fork_proof(BETA, policy=UNICODE_BASE,
                                       receipt=receipt)),
        ], upol)
        self.assertNotIn(b"\\u", raw)
        result = verify_fork_decision(raw, upol, RING, MOMENT)
        self.assertEqual(result["status"], "accepted")

    def test_top_and_payload_key_sets(self):
        data = parse(self.raw)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        payload = data["payload"]
        self.assertEqual(
            set(payload.keys()),
            {"action", "boundaries", "decisions", "issuer", "keyVersion",
             "policyDigest", "proofs", "recommendation", "targets",
             "version"},
        )

    def test_payload_identity_and_version_bindings(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        canonical_policy = {
            "action": "isolate",
            "base": {"batch": "batch-1", "sites": {"a": [1]},
                     "threshold": 1},
            "sites": {ALPHA: [1], BETA: [1], GAMMA: [1], DELTA: [1]},
            "threshold": 2,
        }
        self.assertEqual(
            payload["policyDigest"],
            hashlib.sha256(compact(canonical_policy)).hexdigest(),
        )

    def test_proofs_are_bound_in_original_order(self):
        payload = parse(self.raw)["payload"]
        self.assertEqual(
            payload["proofs"],
            [hashlib.sha256(self.proof_alpha).hexdigest(),
             hashlib.sha256(self.proof_beta).hexdigest()],
        )
        # Reverse the input order: the proofs binding reverses with it.
        raw_reversed = decision(list(reversed(self.items)), self.pol)
        self.assertEqual(
            parse(raw_reversed)["payload"]["proofs"],
            list(reversed(payload["proofs"])),
        )

    def test_decision_row_keys(self):
        for row in parse(self.raw)["payload"]["decisions"]:
            self.assertEqual(
                set(row.keys()),
                {"boundaries", "conclusion", "id", "keyVersion", "digest",
                 "reason", "site"},
            )
            self.assertEqual(
                row["digest"],
                hashlib.sha256(
                    self.proof_alpha if row["id"] == "x" else self.proof_beta
                ).hexdigest(),
            )


class VerifySuccessTest(unittest.TestCase):
    def setUp(self):
        self.proof_alpha = fork_proof(ALPHA)
        self.proof_beta = fork_proof(BETA)
        self.items = [proof_item("x", self.proof_alpha),
                      proof_item("y", self.proof_beta)]
        self.pol = policy()
        self.raw = decision(self.items, self.pol)

    def test_result_is_a_fresh_fixed_key_mapping(self):
        result = verify_fork_decision(self.raw, self.pol, RING, MOMENT)
        self.assertEqual(
            list(result.keys()),
            ["action", "boundaries", "decisions", "issuer", "keyVersion",
             "policyDigest", "proofDigest", "proofs", "recommendation",
             "status", "targets", "version"],
        )
        self.assertEqual(result["proofDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["issuer"], COORD)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["proofs"],
                         parse(self.raw)["payload"]["proofs"])

    def test_repeated_calls_share_no_mutable_object(self):
        first = verify_fork_decision(self.raw, self.pol, RING, MOMENT)
        first["targets"].append("tampered")
        first["decisions"][0]["id"] = "tampered"
        second = verify_fork_decision(self.raw, self.pol, RING, MOMENT)
        self.assertEqual(second["targets"], [BETA, GAMMA])
        self.assertNotEqual(first, second)
        self.assertIsNot(first["decisions"], second["decisions"])

    def test_verifies_at_the_decision_moment(self):
        result = verify_fork_decision(self.raw, self.pol, RING, MOMENT)
        self.assertEqual(result["status"], "accepted")

    def test_inputs_are_not_modified(self):
        snapshot = copy.deepcopy((self.pol, RING))
        verify_fork_decision(self.raw, self.pol, RING, MOMENT)
        self.assertEqual((self.pol, RING), snapshot)


class VerifyStructureTest(unittest.TestCase):
    def setUp(self):
        self.proof_alpha = fork_proof(ALPHA)
        self.proof_beta = fork_proof(BETA)
        self.pol = policy()
        self.raw = decision([
            proof_item("x", self.proof_alpha),
            proof_item("y", self.proof_beta),
        ], self.pol)

    def payload(self):
        return parse(self.raw)["payload"]

    def assert_invalid(self, raw):
        with self.assertRaises(InvalidForkDecisionError):
            verify_fork_decision(raw, self.pol, RING, MOMENT)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            verify_fork_decision("x", self.pol, RING, MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decision(self.raw, self.pol, RING, True)
        with self.assertRaises(ValueError):
            verify_fork_decision(self.raw, self.pol, RING, -1)
        with self.assertRaises(ValueError):
            verify_fork_decision(self.raw, policy(action="nope"),
                                 RING, MOMENT)

    def test_encoding_faults(self):
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(self.raw + b" ")
        self.assert_invalid(b"")
        self.assert_invalid(b"{")
        self.assert_invalid("héllo".encode("latin-1"))
        with self.assertRaises(TypeError):
            verify_fork_decision(b"[]", self.pol, RING, MOMENT)

    def test_top_and_payload_key_sets(self):
        data = parse(self.raw)
        del data["signature"]
        self.assert_invalid(compact(data))
        data = parse(self.raw)
        data["extra"] = 1
        self.assert_invalid(compact(data))
        payload = self.payload()
        del payload["targets"]
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
            verify_fork_decision(rewrap(payload), self.pol, RING, MOMENT)

    def test_field_type_faults_inside_payload(self):
        checks = [
            ("issuer", 7, TypeError),
            ("issuer", "", InvalidForkDecisionError),
            ("keyVersion", "1", TypeError),
            ("keyVersion", 0, InvalidForkDecisionError),
            ("keyVersion", True, TypeError),
            ("action", 7, TypeError),
            ("action", "wipe", InvalidForkDecisionError),
            ("recommendation", 7, TypeError),
            ("recommendation", "nope", InvalidForkDecisionError),
            ("policyDigest", 7, TypeError),
            ("policyDigest", "z" * 64, InvalidForkDecisionError),
            ("proofs", {}, TypeError),
            ("proofs", [], InvalidForkDecisionError),
            ("decisions", {}, TypeError),
            ("targets", {}, TypeError),
            ("boundaries", {}, TypeError),
        ]
        for field, value, expected in checks:
            payload = self.payload()
            payload[field] = value
            with self.assertRaises(expected, msg=field):
                verify_fork_decision(rewrap(payload), self.pol, RING, MOMENT)

    def test_nested_bool_never_poses_as_int(self):
        payload = self.payload()
        payload["decisions"][0]["keyVersion"] = True
        with self.assertRaises(TypeError):
            verify_fork_decision(rewrap(payload), self.pol, RING, MOMENT)

    def test_signature_format_fault(self):
        data = parse(self.raw)
        data["signature"] = "zz" * 32
        self.assert_invalid(compact(data))
        data = parse(self.raw)
        data["signature"] = 7
        with self.assertRaises(TypeError):
            verify_fork_decision(compact(data), self.pol, RING, MOMENT)

    def test_non_canonical_and_duplicate_keys(self):
        pretty = json.dumps(parse(self.raw), ensure_ascii=False, indent=2)
        self.assert_invalid(pretty.encode("utf-8"))
        text = self.raw.decode("utf-8")
        marker = '"version":1'
        duplicated = text.replace(
            marker, marker + "," + marker, 1
        ).encode("utf-8")
        self.assert_invalid(duplicated)

    def test_row_structure_faults(self):
        payload = self.payload()
        row = payload["decisions"][0]
        # A valid row suddenly carrying a reason is inconsistent.
        row = self.payload()["decisions"][0]
        row["reason"] = "boom"
        self.assert_invalid(rewrap(self.payload_with(row)))

    def payload_with(self, row):
        payload = self.payload()
        payload["decisions"][0] = row
        return payload

    def test_boundary_and_target_value_faults(self):
        payload = self.payload()
        payload["targets"] = [GAMMA, BETA]  # unsorted
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["targets"] = [BETA, BETA]  # duplicate
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["boundaries"][0]["target"] = ""
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["boundaries"][0]["upstream"] = "z" * 64
        self.assert_invalid(rewrap(payload))


class VerifyBindingTest(unittest.TestCase):
    def setUp(self):
        self.proof_alpha = fork_proof(ALPHA)
        self.proof_beta = fork_proof(BETA)
        self.pol = policy()
        self.raw = decision([
            proof_item("x", self.proof_alpha),
            proof_item("y", self.proof_beta),
        ], self.pol)

    def payload(self):
        return parse(self.raw)["payload"]

    def assert_invalid(self, payload):
        with self.assertRaises(InvalidForkDecisionError):
            verify_fork_decision(rewrap(payload), self.pol, RING, MOMENT)

    def test_policy_digest_binding(self):
        other = policy(base=BASE_OTHER)
        with self.assertRaises(InvalidForkDecisionError):
            verify_fork_decision(self.raw, other, RING, MOMENT)
        payload = self.payload()
        payload["policyDigest"] = "bb" * 32
        self.assert_invalid(payload)

    def test_resigning_cannot_launder_a_tally_change(self):
        payload = self.payload()
        payload["decisions"][0]["conclusion"] = "duplicate"
        payload["decisions"][0]["reason"] = "duplicate"
        self.assert_invalid(payload)

    def test_resigning_cannot_launder_the_recommendation(self):
        payload = self.payload()
        payload["recommendation"] = "manual-review"
        payload["boundaries"] = []
        payload["targets"] = []
        self.assert_invalid(payload)

    def test_resigning_cannot_launder_targets_or_boundaries(self):
        payload = self.payload()
        payload["targets"] = [BETA]
        self.assert_invalid(payload)
        payload = self.payload()
        payload["boundaries"] = payload["boundaries"][:1]
        self.assert_invalid(payload)

    def test_decisions_must_cover_the_bound_proofs(self):
        payload = self.payload()
        payload["proofs"] = ["cc" * 32, payload["proofs"][1]]
        self.assert_invalid(payload)
        payload = self.payload()
        payload["decisions"][0]["digest"] = "dd" * 32
        self.assert_invalid(payload)

    def test_decisions_must_be_sorted(self):
        payload = self.payload()
        payload["decisions"] = list(reversed(payload["decisions"]))
        self.assert_invalid(payload)

    def test_action_change_forces_a_binding_failure(self):
        payload = self.payload()
        payload["action"] = "rollback"
        # Recommendation stays "isolate", which no longer matches.
        self.assert_invalid(payload)


class VerifyAuthenticationTest(unittest.TestCase):
    def setUp(self):
        self.pol = policy()
        self.raw = decision([
            proof_item("x", fork_proof(ALPHA)),
            proof_item("y", fork_proof(BETA)),
        ], self.pol)

    def test_signature_mismatch(self):
        data = parse(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            verify_fork_decision(compact(data), self.pol, RING, MOMENT)

    def test_unknown_revoked_future_expired_issuer(self):
        for ring in (
            {k: v for k, v in RING.items() if k != COORD},
            keyring(**{COORD: [entry(1, SECRET_COORD, revoked=True)]}),
            keyring(**{COORD: [entry(1, SECRET_COORD, not_before=250)]}),
            keyring(**{COORD: [entry(1, SECRET_COORD, not_after=180)]}),
        ):
            with self.assertRaises(AuthenticationError):
                verify_fork_decision(self.raw, self.pol, ring, MOMENT)

    def test_wrong_secret_is_a_signature_mismatch(self):
        ring = keyring(**{COORD: [entry(1, SECRET_OTHER)]})
        with self.assertRaises(AuthenticationError):
            verify_fork_decision(self.raw, self.pol, ring, MOMENT)

    def test_authentication_error_is_a_value_error(self):
        self.assertTrue(issubclass(AuthenticationError, ValueError))

    def test_invalid_decision_error_is_a_value_error(self):
        self.assertTrue(issubclass(InvalidForkDecisionError, ValueError))


class VerifyDecisionsBatchTest(unittest.TestCase):
    def setUp(self):
        self.pol = policy()
        self.good = decision([
            proof_item("x", fork_proof(ALPHA)),
            proof_item("y", fork_proof(BETA)),
        ], self.pol)

    def item(self, item_id, raw):
        return {"id": item_id, "decision": raw}

    def test_structure_validated_upfront(self):
        with self.assertRaises(TypeError):
            verify_fork_decisions("x", self.pol, RING, MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decisions(["x"], self.pol, RING, MOMENT)
        with self.assertRaises(ValueError):
            verify_fork_decisions([], self.pol, RING, MOMENT)
        with self.assertRaises(ValueError):
            verify_fork_decisions([self.item("a", self.good),
                                   self.item("a", self.good)],
                                  self.pol, RING, MOMENT)
        with self.assertRaises(ValueError):
            verify_fork_decisions(
                [{"id": "a", "decision": self.good, "n": 1}],
                self.pol, RING, MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_fork_decisions(
                [{"id": "", "decision": self.good}], self.pol, RING, MOMENT
            )
        with self.assertRaises(TypeError):
            verify_fork_decisions(
                [{"id": 7, "decision": self.good}], self.pol, RING, MOMENT
            )
        with self.assertRaises(TypeError):
            verify_fork_decisions(
                [{"id": "a", "decision": "x"}], self.pol, RING, MOMENT
            )

    def test_shared_materials_validated_upfront(self):
        with self.assertRaises(ValueError):
            verify_fork_decisions([self.item("a", self.good)],
                                 policy(action="nope"), RING, MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decisions([self.item("a", self.good)],
                                 self.pol, "x", MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decisions([self.item("a", self.good)],
                                 self.pol, RING, True)
        with self.assertRaises(ValueError):
            verify_fork_decisions([self.item("a", self.good)],
                                 self.pol, RING, -1)

    def test_batch_level_fault_surfaces_even_when_a_decision_is_bad(self):
        with self.assertRaises(ValueError):
            verify_fork_decisions(
                [self.item("a", b"{}"), self.item("a", self.good)],
                self.pol, RING, MOMENT,
            )

    def test_per_item_isolation_in_input_order(self):
        wrong_key = keyring(**{COORD: [entry(1, SECRET_OTHER)]})
        # A decision unauthenticatable under the current keyring.
        unauthenticated = decision(
            [proof_item("x", fork_proof(ALPHA)),
             proof_item("y", fork_proof(BETA))], self.pol,
        )
        report = verify_fork_decisions(
            [
                self.item("ok", self.good),
                self.item("bad", b"{}"),
                self.item("unauth", unauthenticated),
                self.item("ok2", self.good),
            ],
            self.pol, wrong_key, MOMENT,
        )
        self.assertEqual(list(report.keys()), ["items", "version"])
        self.assertEqual(report["version"], 1)
        self.assertEqual(
            [row["id"] for row in report["items"]],
            ["ok", "bad", "unauth", "ok2"],
        )
        statuses = [row["status"] for row in report["items"]]
        # Under wrong_key even the structurally good decision cannot auth.
        self.assertEqual(
            statuses,
            ["unauthenticated", "invalid", "unauthenticated",
             "unauthenticated"],
        )

    def test_mixed_verified_invalid_unauthenticated_with_good_keyring(self):
        report = verify_fork_decisions(
            [
                self.item("ok", self.good),
                self.item("bad", b"{}"),
            ],
            self.pol, RING, MOMENT,
        )
        rows = {row["id"]: row for row in report["items"]}
        good = rows["ok"]
        self.assertEqual(good["status"], "verified")
        self.assertIsNone(good["error"])
        self.assertIsNotNone(good["result"])
        self.assertEqual(list(good.keys()), ["error", "id", "result", "status"])
        bad = rows["bad"]
        self.assertEqual(bad["status"], "invalid")
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")
        self.assertIsNone(bad["result"])

    def test_one_failure_leaves_other_reports_intact(self):
        report = verify_fork_decisions(
            [self.item("ok", self.good), self.item("bad", b"{}")],
            self.pol, RING, MOMENT,
        )
        single = verify_fork_decision(self.good, self.pol, RING, MOMENT)
        self.assertEqual(report["items"][0]["result"], single)

    def test_results_are_fresh_and_independent(self):
        report = verify_fork_decisions(
            [self.item("ok", self.good)], self.pol, RING, MOMENT
        )
        report["items"][0]["result"]["targets"] = ["tampered"]
        again = verify_fork_decisions(
            [self.item("ok", self.good)], self.pol, RING, MOMENT
        )
        self.assertEqual(again["items"][0]["result"]["targets"], [BETA, GAMMA])

    def test_inputs_are_not_modified(self):
        items = [self.item("ok", self.good)]
        snapshot = copy.deepcopy((items, self.pol, RING))
        verify_fork_decisions(items, self.pol, RING, MOMENT)
        self.assertEqual((items, self.pol, RING), snapshot)


if __name__ == "__main__":
    unittest.main()
