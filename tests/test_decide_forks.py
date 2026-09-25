"""Tests for the offline multi-site signed fork disposition.

Covers :func:`decide_forks`, :func:`verify_fork_decision` and
:func:`verify_fork_decisions`: input/policy validation and exception
taxonomy, per-proof verification then precise site/version
authorization, duplicate and contradiction accounting, cross-site
boundary agreement, the accepted/conflicted/insufficient dispositions,
the canonical decision encoding and every signed binding, current
credential checks and the batch wrapper's upfront validation, per-item
isolation, input-order reports and fresh results.
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

DECISION_SITES = {ISSUER: {1}, ALPHA: {1}, BETA: {1}}


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_bytes(payload, secret):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


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


def make_report(item_id="item-1"):
    return {"error": "boom", "id": item_id, "result": None,
            "status": "invalid-proof"}


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
    return compact({"payload": payload, "signature": sign_bytes(payload, secret)})


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
    return compact({"payload": payload, "signature": sign_bytes(payload, secret)})


def chain(receipt, path, moments=()):
    hops = []
    upstream = receipt
    domains = [ISSUER] + list(path)
    for index, audience in enumerate(path):
        moment = moments[index] if moments else 110 + index
        hops.append(make_hop(domains[index], SECRETS[domains[index]],
                             audience, upstream, moment))
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
    receipt = receipt if receipt is not None else make_receipt()
    return [
        chain_item("a", receipt, [ALPHA, BETA], moments=(110, 120)),
        chain_item("b", receipt, [GAMMA, DELTA], moments=(111, 121)),
    ]


def fork_proof(site, items=None, secret=None, policy=POLICY,
               moment=SIGN_MOMENT, version=1, ring=None):
    items = items if items is not None else fork_items()
    ring = ring if ring is not None else keyring()
    return sign_receipt_fork_proof(items, policy, ring, moment, site, version)


def decision_policy(action="isolate", threshold=2, sites=None,
                    base=POLICY):
    return {
        "base": base,
        "sites": sites if sites is not None else DECISION_SITES,
        "threshold": threshold,
        "action": action,
    }


def parse_packet(raw):
    return json.loads(raw.decode("utf-8"))


def rewrap(payload, secret=SECRET_COORD):
    return compact({"payload": payload, "signature": sign_bytes(payload, secret)})


def decide(proofs, policy=None, **kwargs):
    """proofs: ordered mapping id -> proof bytes."""
    policy = policy if policy is not None else decision_policy()
    items = [{"id": item_id, "proof": proof}
             for item_id, proof in proofs.items()]
    options = dict(
        policy=policy, keyring=keyring(), moment=VERIFY_MOMENT,
        issuer=ISSUER, version=1,
    )
    options.update(kwargs)
    return decide_forks(items, **options)


class InputValidationTest(unittest.TestCase):
    def setUp(self):
        self.proof = fork_proof(ISSUER)

    def test_container_and_item_rules(self):
        with self.assertRaises(TypeError):
            decide_forks("x", decision_policy(), keyring(),
                         VERIFY_MOMENT, ISSUER, 1)
        with self.assertRaises(ValueError):
            decide_forks([], decision_policy(), keyring(),
                         VERIFY_MOMENT, ISSUER, 1)
        with self.assertRaises(ValueError):
            decide_forks([{"id": "", "proof": self.proof}],
                         decision_policy(), keyring(),
                         VERIFY_MOMENT, ISSUER, 1)
        with self.assertRaises(ValueError):
            decide_forks(
                [{"id": "a", "proof": self.proof},
                 {"id": "a", "proof": self.proof}],
                decision_policy(), keyring(), VERIFY_MOMENT, ISSUER, 1)
        with self.assertRaises(ValueError):
            decide_forks([{"id": "a", "proof": self.proof, "x": 1}],
                         decision_policy(), keyring(),
                         VERIFY_MOMENT, ISSUER, 1)
        with self.assertRaises(TypeError):
            decide_forks([{"id": 7, "proof": self.proof}],
                         decision_policy(), keyring(),
                         VERIFY_MOMENT, ISSUER, 1)
        with self.assertRaises(TypeError):
            decide_forks([{"id": "a", "proof": "x"}],
                         decision_policy(), keyring(),
                         VERIFY_MOMENT, ISSUER, 1)

    def test_policy_key_set_and_value_rules(self):
        good = decision_policy()
        # Wrong key set.
        bad = {k: v for k, v in good.items() if k != "action"}
        with self.assertRaises(ValueError):
            decide({"a": self.proof}, policy=bad)
        bad = dict(good, extra=1)
        with self.assertRaises(ValueError):
            decide({"a": self.proof}, policy=bad)
        # Action enum.
        with self.assertRaises(TypeError):
            decide({"a": self.proof}, policy=dict(good, action=7))
        with self.assertRaises(ValueError):
            decide({"a": self.proof}, policy=dict(good, action="freeze"))
        # Threshold domain and type (bool never poses as int).
        with self.assertRaises(ValueError):
            decide({"a": self.proof}, policy=dict(good, threshold=0))
        with self.assertRaises(ValueError):
            decide({"a": self.proof}, policy=dict(good, threshold=9))
        with self.assertRaises(TypeError):
            decide({"a": self.proof}, policy=dict(good, threshold=True))
        # Sites rules.
        with self.assertRaises(ValueError):
            decide({"a": self.proof}, policy=dict(good, sites={}))
        with self.assertRaises(ValueError):
            decide({"a": self.proof},
                   policy=dict(good, sites={ISSUER: set()}))
        with self.assertRaises(ValueError):
            decide({"a": self.proof},
                   policy=dict(good, sites={"": {1}}))
        with self.assertRaises(ValueError):
            decide({"a": self.proof},
                   policy=dict(good, sites={ISSUER: {0}}))
        with self.assertRaises(TypeError):
            decide({"a": self.proof},
                   policy=dict(good, sites={ISSUER: [1]}))
        with self.assertRaises(TypeError):
            decide({"a": self.proof},
                   policy=dict(good, sites={ISSUER: {True}}))
        # Illegal base policy still raises.
        with self.assertRaises(ValueError):
            decide({"a": self.proof}, policy=dict(good, base={"x": 1}))

    def test_identity_version_moment_classification(self):
        proofs = {"a": self.proof}
        with self.assertRaises(ValueError):
            decide(proofs, issuer="")
        with self.assertRaises(TypeError):
            decide(proofs, issuer=9)
        with self.assertRaises(ValueError):
            decide(proofs, version=0)
        with self.assertRaises(TypeError):
            decide(proofs, version=True)
        with self.assertRaises(ValueError):
            decide(proofs, moment=-1)
        with self.assertRaises(TypeError):
            decide(proofs, moment=True)
        with self.assertRaises(TypeError):
            decide(proofs, keyring="x")

    def test_decision_signing_credentials_are_authenticated(self):
        proofs = {"a": self.proof, "b": fork_proof(ALPHA)}
        with self.assertRaises(AuthenticationError):
            decide(proofs, issuer="nobody", version=1)
        with self.assertRaises(AuthenticationError):
            decide(proofs, issuer=ISSUER, version=2)
        revoked = keyring(**{ISSUER: [entry(1, SECRET_COORD, revoked=True)]})
        with self.assertRaises(AuthenticationError):
            decide(proofs, keyring=revoked)
        future = keyring(**{ISSUER: [entry(1, SECRET_COORD, not_before=300)]})
        with self.assertRaises(AuthenticationError):
            decide(proofs, keyring=future)
        expired = keyring(**{ISSUER: [entry(1, SECRET_COORD, not_after=120)]})
        with self.assertRaises(AuthenticationError):
            decide(proofs, keyring=expired)


class DispositionTest(unittest.TestCase):
    def test_two_sites_agreeing_reach_threshold_and_isolate(self):
        proofs = {"c": fork_proof(ISSUER), "a": fork_proof(ALPHA)}
        raw = decide(proofs)
        self.assertTrue(raw.endswith(b"}"))
        payload = verify_fork_decision(raw, decision_policy(),
                                       keyring(), VERIFY_MOMENT)
        self.assertEqual(payload["recommendation"], "isolate")
        self.assertEqual(payload["targets"], [ALPHA, GAMMA])
        self.assertEqual(payload["issuer"], ISSUER)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        # Verdicts are sorted by site then id.
        self.assertEqual(
            [(v["site"], v["id"], v["conclusion"]) for v in payload["items"]],
            [(ALPHA, "a", "valid"), (ISSUER, "c", "valid")],
        )
        for verdict in payload["items"]:
            self.assertIsNone(verdict["reason"])
        self.assertEqual(len(payload["boundaries"]), 1)
        boundary = payload["boundaries"][0]
        self.assertEqual(boundary["audiences"], [ALPHA, GAMMA])

    def test_rollback_recommendation(self):
        proofs = {"c": fork_proof(ISSUER), "a": fork_proof(ALPHA)}
        raw = decide(proofs, policy=decision_policy(action="rollback"))
        payload = verify_fork_decision(
            raw, decision_policy(action="rollback"), keyring(), VERIFY_MOMENT
        )
        self.assertEqual(payload["recommendation"], "rollback")
        self.assertEqual(payload["targets"], [ALPHA, GAMMA])

    def test_below_threshold_is_insufficient_manual_review(self):
        # Only one of the two required sites authorizes.
        proofs = {"c": fork_proof(ISSUER), "b": fork_proof(BETA)}
        # BETA is an authorized decision site but not in the 2-of-2 set
        # used elsewhere; build a policy requiring both coord and alpha.
        policy = decision_policy(
            threshold=2, sites={ISSUER: {1}, ALPHA: {1}}
        )
        raw = decide(proofs, policy=policy)
        payload = verify_fork_decision(raw, policy, keyring(), VERIFY_MOMENT)
        statuses = {v["id"]: (v["conclusion"], v["reason"])
                    for v in payload["items"]}
        self.assertEqual(statuses["c"], ("valid", None))
        self.assertEqual(statuses["b"], ("invalid", "unauthorized-site"))
        self.assertEqual(payload["recommendation"], "manual-review")
        self.assertIsNone(payload["boundaries"])
        self.assertEqual(payload["targets"], [])

    def test_all_rejected_is_insufficient(self):
        proofs = {"bad": b"{}", "also": b"{"}
        raw = decide(proofs, policy=decision_policy(threshold=1))
        payload = verify_fork_decision(
            raw, decision_policy(threshold=1), keyring(), VERIFY_MOMENT
        )
        self.assertEqual(payload["recommendation"], "manual-review")
        self.assertIsNone(payload["boundaries"])
        self.assertEqual(
            {v["reason"] for v in payload["items"]}, {"invalid-proof"}
        )

    def test_same_digest_counts_once_extra_is_duplicate(self):
        proof = fork_proof(ISSUER)
        proofs = {"x": proof, "y": proof, "z": proof}
        policy = decision_policy(threshold=1, sites={ISSUER: {1}})
        raw = decide(proofs, policy=policy)
        payload = verify_fork_decision(raw, policy, keyring(), VERIFY_MOMENT)
        conclusions = {v["id"]: (v["conclusion"], v["reason"])
                       for v in payload["items"]}
        self.assertEqual(conclusions["x"], ("valid", None))
        self.assertEqual(conclusions["y"], ("duplicate", "duplicate"))
        self.assertEqual(conclusions["z"], ("duplicate", "duplicate"))
        self.assertEqual(payload["recommendation"], "isolate")

    def test_distinct_valid_proofs_from_one_site_contradict(self):
        first = fork_proof(ISSUER)
        other_receipt = make_receipt(items=[
            {"id": "item-1", "digest": "bb" * 32, "report": make_report()}
        ])
        second = fork_proof(ISSUER, items=fork_items(other_receipt))
        proofs = {"one": first, "two": second, "a": fork_proof(ALPHA)}
        raw = decide(proofs)
        payload = verify_fork_decision(raw, decision_policy(),
                                       keyring(), VERIFY_MOMENT)
        by_id = {v["id"]: v for v in payload["items"]}
        self.assertEqual(by_id["one"]["conclusion"], "contradiction")
        self.assertEqual(by_id["two"]["conclusion"], "contradiction")
        self.assertEqual(by_id["one"]["reason"], "contradiction")
        self.assertEqual(by_id["a"]["conclusion"], "valid")
        self.assertEqual(payload["recommendation"], "manual-review")
        self.assertIsNone(payload["boundaries"])

    def test_cross_site_boundary_disagreement_is_conflicted(self):
        first = fork_proof(ISSUER)
        other = make_receipt(items=[
            {"id": "item-9", "digest": "cc" * 32,
             "report": make_report("item-9")}
        ])
        other_items = [
            chain_item("a", other, [ALPHA, BETA], moments=(110, 120)),
            chain_item("b", other, [DELTA, GAMMA], moments=(111, 121)),
        ]
        second = fork_proof(ALPHA, items=other_items)
        proofs = {"c": first, "a": second}
        raw = decide(proofs)
        payload = verify_fork_decision(raw, decision_policy(),
                                       keyring(), VERIFY_MOMENT)
        self.assertEqual(payload["recommendation"], "manual-review")
        self.assertIsNone(payload["boundaries"])
        self.assertEqual(payload["targets"], [])
        self.assertTrue(
            all(v["conclusion"] == "valid" for v in payload["items"])
        )

    def test_unauthorized_version_is_rejected_alone(self):
        proof = fork_proof(ISSUER)
        policy = decision_policy(
            threshold=1, sites={ISSUER: {2}, ALPHA: {1}}
        )
        raw = decide({"c": proof}, policy=policy)
        payload = verify_fork_decision(raw, policy, keyring(), VERIFY_MOMENT)
        self.assertEqual(payload["items"][0]["conclusion"], "invalid")
        self.assertEqual(payload["items"][0]["reason"],
                         "unauthorized-version")
        self.assertEqual(payload["recommendation"], "manual-review")

    def test_unauthenticated_proof_is_rejected_alone(self):
        # A fork proof signed by a key that has expired by the decision
        # moment fails the existing proof authentication there.  The
        # decision itself is signed by an independent, still-valid issuer.
        ring = keyring(**{ISSUER: [entry(1, SECRET_COORD, not_after=180)]})
        proof = sign_receipt_fork_proof(
            fork_items(), POLICY, ring, SIGN_MOMENT, ISSUER, 1
        )
        policy = decision_policy(threshold=1, sites={ISSUER: {1}})
        items = [{"id": "c", "proof": proof}]
        raw = decide_forks(items, policy, ring, VERIFY_MOMENT, ALPHA, 1)
        payload = verify_fork_decision(raw, policy, ring, VERIFY_MOMENT)
        self.assertEqual(payload["items"][0]["reason"], "unauthenticated")
        self.assertEqual(payload["recommendation"], "manual-review")


class DecisionEncodingTest(unittest.TestCase):
    def setUp(self):
        self.proofs = {"c": fork_proof(ISSUER), "a": fork_proof(ALPHA)}
        self.raw = decide(self.proofs)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        data = parse_packet(self.raw)
        self.assertEqual(compact(data), self.raw)
        self.assertEqual(set(data.keys()), {"payload", "signature"})

    def test_payload_binds_exactly_the_nine_fields(self):
        payload = parse_packet(self.raw)["payload"]
        self.assertEqual(
            set(payload.keys()),
            {"boundaries", "issuer", "items", "keyVersion",
             "policyDigest", "proofDigests", "recommendation", "targets",
             "version"},
        )
        self.assertEqual(
            payload["proofDigests"],
            [hashlib.sha256(self.proofs["c"]).hexdigest(),
             hashlib.sha256(self.proofs["a"]).hexdigest()],
        )

    def test_proof_digests_keep_original_order(self):
        raw = decide({"z": self.proofs["a"], "a": self.proofs["c"]})
        payload = parse_packet(raw)["payload"]
        self.assertEqual(
            payload["proofDigests"],
            [hashlib.sha256(self.proofs["a"]).hexdigest(),
             hashlib.sha256(self.proofs["c"]).hexdigest()],
        )
        # Items are still sorted by site/id regardless of input order.
        self.assertEqual(
            [(v["site"], v["id"]) for v in payload["items"]],
            [(ALPHA, "z"), (ISSUER, "a")],
        )

    def test_non_ascii_is_preserved_unescaped(self):
        receipt = make_receipt(policy=UNICODE_POLICY)
        proof = fork_proof(ISSUER, items=fork_items(receipt),
                           policy=UNICODE_POLICY)
        policy = decision_policy(
            threshold=1, sites={ISSUER: {1}}, base=UNICODE_POLICY
        )
        raw = decide({"c": proof}, policy=policy)
        self.assertNotIn(b"\\u", raw)
        verify_fork_decision(raw, policy, keyring(), VERIFY_MOMENT)


class VerifyDecisionTest(unittest.TestCase):
    def setUp(self):
        self.proofs = {"c": fork_proof(ISSUER), "a": fork_proof(ALPHA)}
        self.policy = decision_policy()
        self.raw = decide(self.proofs, policy=self.policy)

    def payload(self):
        return parse_packet(self.raw)["payload"]

    def assert_invalid(self, raw, policy=None):
        policy = policy if policy is not None else self.policy
        with self.assertRaises(InvalidForkDecisionError):
            verify_fork_decision(raw, policy, keyring(), VERIFY_MOMENT)

    def test_success_is_a_fresh_independent_copy(self):
        first = verify_fork_decision(self.raw, self.policy, keyring(),
                                     VERIFY_MOMENT)
        first["targets"].append("tampered")
        second = verify_fork_decision(self.raw, self.policy, keyring(),
                                      VERIFY_MOMENT)
        self.assertEqual(second["targets"], [ALPHA, GAMMA])
        self.assertNotEqual(first, second)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            verify_fork_decision("x", self.policy, keyring(), VERIFY_MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decision(self.raw, self.policy, keyring(), True)
        with self.assertRaises(ValueError):
            verify_fork_decision(self.raw, self.policy, keyring(), -1)
        with self.assertRaises(ValueError):
            verify_fork_decision(self.raw, {"x": 1}, keyring(), VERIFY_MOMENT)

    def test_encoding_and_key_set_faults(self):
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(self.raw + b" ")
        self.assert_invalid(b"{}")
        data = parse_packet(self.raw)
        del data["signature"]
        self.assert_invalid(compact(data))
        data = parse_packet(self.raw)
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
            verify_fork_decision(rewrap(payload), self.policy,
                                 keyring(), VERIFY_MOMENT)

    def test_policy_digest_binding(self):
        other = decision_policy(action="rollback")
        self.assert_invalid(self.raw, other)
        other = decision_policy(threshold=1)
        self.assert_invalid(self.raw, other)

    def test_target_binding_cannot_be_laundered_by_resigning(self):
        payload = self.payload()
        payload["targets"] = ["zzz"]
        self.assert_invalid(rewrap(payload))
        # An accepted decision must keep the exact boundary audiences.
        payload = self.payload()
        payload["boundaries"][0]["audiences"] = [ALPHA]
        self.assert_invalid(rewrap(payload))
        # A manual-review decision cannot carry targets/boundaries.
        single = decide({"c": fork_proof(ISSUER)},
                        policy=decision_policy(
                            threshold=2, sites={ISSUER: {1}, ALPHA: {1}}))
        payload = parse_packet(single)["payload"]
        payload["targets"] = [ALPHA]
        self.assert_invalid(rewrap(payload))

    def test_duplicate_and_contradiction_bindings(self):
        proof = fork_proof(ISSUER)
        policy = decision_policy(threshold=1, sites={ISSUER: {1}})
        raw = decide({"x": proof, "y": proof}, policy=policy)
        # Turning the lone duplicate into a valid second vote breaks the
        # one-counted-copy rule.
        payload = parse_packet(raw)["payload"]
        for verdict in payload["items"]:
            if verdict["conclusion"] == "duplicate":
                verdict["conclusion"] = "valid"
                verdict["reason"] = None
        self.assert_invalid(rewrap(payload), policy)

    def test_item_digest_and_sort_bindings(self):
        # Reversing the sorted items breaks the site/id ordering binding.
        payload = self.payload()
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(rewrap(payload))
        # A verdict digest must occur among the original-order digests.
        payload = self.payload()
        payload["items"][0]["digest"] = "dd" * 32
        self.assert_invalid(rewrap(payload))
        # Adding an unlisted proof digest breaks the reference set.
        payload = self.payload()
        payload["proofDigests"].append("ee" * 32)
        self.assert_invalid(rewrap(payload))

    def test_non_canonical_and_duplicate_keys(self):
        pretty = json.dumps(parse_packet(self.raw), indent=2).encode("utf-8")
        self.assert_invalid(pretty)
        text = self.raw.decode("utf-8")
        marker = '"version":1'
        duplicated = text.replace(
            marker, marker + "," + marker, 1
        ).encode("utf-8")
        self.assert_invalid(duplicated)

    def test_inner_bool_never_poses_as_int(self):
        payload = self.payload()
        payload["keyVersion"] = True
        with self.assertRaises(TypeError):
            verify_fork_decision(rewrap(payload), self.policy,
                                 keyring(), VERIFY_MOMENT)
        payload = self.payload()
        payload["items"][0]["keyVersion"] = True
        with self.assertRaises(TypeError):
            verify_fork_decision(rewrap(payload), self.policy,
                                 keyring(), VERIFY_MOMENT)

    def test_credentials_and_signature(self):
        # Unknown / revoked / not-yet-valid / expired signer at verify.
        with self.assertRaises(AuthenticationError):
            verify_fork_decision(self.raw, self.policy,
                                 keyring(**{ISSUER: [entry(2, SECRET_OTHER)]}),
                                 VERIFY_MOMENT)
        revoked = keyring(**{ISSUER: [entry(1, SECRET_COORD, revoked=True)]})
        with self.assertRaises(AuthenticationError):
            verify_fork_decision(self.raw, self.policy, revoked, VERIFY_MOMENT)
        future = keyring(**{ISSUER: [entry(1, SECRET_COORD, not_before=300)]})
        with self.assertRaises(AuthenticationError):
            verify_fork_decision(self.raw, self.policy, future, VERIFY_MOMENT)
        expired = keyring(**{ISSUER: [entry(1, SECRET_COORD, not_after=120)]})
        with self.assertRaises(AuthenticationError):
            verify_fork_decision(self.raw, self.policy, expired, VERIFY_MOMENT)
        wrong = keyring(**{ISSUER: [entry(1, SECRET_OTHER)]})
        with self.assertRaises(AuthenticationError):
            verify_fork_decision(self.raw, self.policy, wrong, VERIFY_MOMENT)
        data = parse_packet(self.raw)
        data["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            verify_fork_decision(compact(data), self.policy,
                                 keyring(), VERIFY_MOMENT)

    def test_error_is_value_error_subclass(self):
        self.assertTrue(issubclass(InvalidForkDecisionError, ValueError))
        self.assertTrue(issubclass(AuthenticationError, ValueError))


class BatchVerifyTest(unittest.TestCase):
    def setUp(self):
        self.proofs = {"c": fork_proof(ISSUER), "a": fork_proof(ALPHA)}
        self.policy = decision_policy()
        self.good = decide(self.proofs, policy=self.policy)

    def item(self, item_id, decision):
        return {"id": item_id, "decision": decision}

    def test_batch_validated_upfront(self):
        with self.assertRaises(TypeError):
            verify_fork_decisions("x", self.policy, keyring(), VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_fork_decisions([], self.policy, keyring(), VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_fork_decisions(
                [self.item("", self.good)], self.policy, keyring(),
                VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_fork_decisions(
                [self.item("a", self.good), self.item("a", self.good)],
                self.policy, keyring(), VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_fork_decisions(
                [{"id": "a", "decision": self.good, "x": 1}],
                self.policy, keyring(), VERIFY_MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decisions(
                [self.item("a", "x")], self.policy, keyring(), VERIFY_MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decisions(
                [self.item(7, self.good)], self.policy, keyring(),
                VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_fork_decisions(
                [self.item("a", self.good)], {"x": 1}, keyring(),
                VERIFY_MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decisions(
                [self.item("a", self.good)], self.policy, "x", VERIFY_MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_decisions(
                [self.item("a", self.good)], self.policy, keyring(), True)
        with self.assertRaises(ValueError):
            verify_fork_decisions(
                [self.item("a", self.good)], self.policy, keyring(), -1)

    def test_per_item_isolation_in_input_order(self):
        invalid = b"{}"
        unauth = rewrap(parse_packet(self.good)["payload"],
                        secret=SECRET_OTHER)
        report = verify_fork_decisions(
            [self.item("g1", self.good), self.item("i", invalid),
             self.item("u", unauth), self.item("g2", self.good)],
            self.policy, keyring(), VERIFY_MOMENT,
        )
        self.assertEqual(list(report.keys()), ["items", "version"])
        self.assertEqual(report["version"], 1)
        self.assertEqual(
            [row["id"] for row in report["items"]],
            ["g1", "i", "u", "g2"],
        )
        self.assertEqual(
            [row["status"] for row in report["items"]],
            ["verified", "invalid", "unauthenticated", "verified"],
        )
        for row in report["items"]:
            self.assertEqual(list(row.keys()),
                             ["error", "id", "result", "status"])
            if row["status"] == "verified":
                self.assertIsNone(row["error"])
                self.assertIsNotNone(row["result"])
            else:
                self.assertIsInstance(row["error"], str)
                self.assertNotEqual(row["error"], "")
                self.assertIsNone(row["result"])

    def test_verified_result_matches_single_entry(self):
        report = verify_fork_decisions(
            [self.item("g", self.good)], self.policy, keyring(),
            VERIFY_MOMENT)
        single = verify_fork_decision(self.good, self.policy, keyring(),
                                      VERIFY_MOMENT)
        self.assertEqual(report["items"][0]["result"], single)

    def test_results_are_fresh_and_inputs_unchanged(self):
        items = [self.item("g", self.good)]
        snapshot = copy.deepcopy(items)
        psnapshot = copy.deepcopy(self.policy)
        report = verify_fork_decisions(items, self.policy, keyring(),
                                       VERIFY_MOMENT)
        report["items"][0]["result"]["targets"].append("x")
        again = verify_fork_decisions(items, self.policy, keyring(),
                                      VERIFY_MOMENT)
        self.assertEqual(again["items"][0]["result"]["targets"],
                         [ALPHA, GAMMA])
        self.assertEqual(items, snapshot)
        self.assertEqual(self.policy, psnapshot)


if __name__ == "__main__":
    unittest.main()
