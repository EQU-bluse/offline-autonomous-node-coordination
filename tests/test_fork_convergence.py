"""Tests for multi-round fork convergence certificates.

Covers :func:`certify_fork_convergence`, :func:`verify_fork_convergence`
and :func:`verify_fork_convergences`: the round chain (consecutive
sequence numbers from one, previous-confirmation digest chaining,
strictly increasing aggregation moments, one shared plan), the
per-operation convergence (failed advancing to executed/rejected,
settled outcomes never rolling back or swapping, cross-round post-state
digest conflicts, conflict/rejected/partial/confirmed precedence), the
canonical signed certificate and every bound field, offline
re-verification and credential rules, and the batch wrapper's upfront
validation, per-item isolation, input-order reports and fresh results.
"""

import copy
import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    AuthenticationError,
    InvalidForkConvergenceError,
    InvalidForkExecutionError,
    certify_fork_convergence,
    confirm_fork_execution,
    decide_forks,
    plan_fork_execution,
    sign_receipt_fork_proof,
    verify_fork_convergence,
    verify_fork_convergences,
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

SIGN_MOMENT = 150
DECIDE_MOMENT = 200
GENERATED_AT = 210
EXPIRES_AT = 300
AGGREGATED_AT = 250
CERTIFIED_AT = 270
VERIFY_MOMENT = 280


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def parse(raw):
    return json.loads(raw.decode("utf-8"))


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

RING = {node: [entry(1, secret)] for node, secret in SECRETS.items()}


def sign_bytes(payload, secret):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def rewrap(payload, secret=SECRET_COORD):
    return compact({"payload": payload,
                    "signature": sign_bytes(payload, secret)})


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
    receipt = receipt if receipt is not None else make_receipt()
    to_beta = [make_hop(COORD, first, receipt, moments[0])]
    to_beta.append(make_hop(first, BETA, to_beta[0], moments[1]))
    to_gamma = [make_hop(COORD, first, receipt, moments[0])]
    to_gamma.append(make_hop(first, GAMMA, to_gamma[0], moments[1]))
    return [
        {"id": "a", "receipt": receipt, "hops": to_beta, "target": BETA},
        {"id": "b", "receipt": receipt, "hops": to_gamma, "target": GAMMA},
    ]


def fork_proof(issuer, first=ALPHA, policy=BASE):
    return sign_receipt_fork_proof(
        fork_chain_items(first), policy, RING, SIGN_MOMENT, issuer, 1
    )


def policy(action="isolate", sites=None, threshold=2, base=BASE):
    if sites is None:
        sites = {ALPHA: {1}, BETA: {1}, GAMMA: {1}, DELTA: {1}}
    return {"action": action, "base": base, "sites": sites,
            "threshold": threshold}


def decide(pol=None, proofs=None):
    pol = pol or policy()
    if proofs is None:
        proofs = [
            {"id": "x", "proof": fork_proof(ALPHA)},
            {"id": "y", "proof": fork_proof(BETA)},
        ]
    return decide_forks(proofs, pol, RING, DECIDE_MOMENT, COORD, 1)


class ConvergenceFixtures:
    """Mixin building a fresh accepted decision, plan and round helpers."""

    def setUp(self):  # noqa: D102
        self.pol = policy()
        self.decision = decide(self.pol)
        self.plan = plan_fork_execution(
            self.decision, self.pol, RING, GENERATED_AT, EXPIRES_AT
        )
        self.plan_obj = parse(self.plan)
        self.plan_digest = hashlib.sha256(self.plan).hexdigest()
        self.operations = {
            op["target"]: op for op in self.plan_obj["operations"]
        }

    def previous(self, operation):
        return hashlib.sha256(
            compact(operation["requires"])
        ).hexdigest()

    def execution_receipt(self, target, result="executed", moment=220,
                          post_digest="c0" * 32):
        operation = self.operations[target]
        payload = {
            "planDigest": self.plan_digest,
            "operationId": operation["operationId"],
            "site": target,
            "keyVersion": 1,
            "siteVersion": "sv-1",
            "executionMoment": moment,
            "previous": self.previous(operation),
            "result": result,
            "postDigest": post_digest if result == "executed" else None,
        }
        return rewrap(payload, SECRETS[target])

    def confirm(self, receipts, moment=AGGREGATED_AT):
        return confirm_fork_execution(
            self.plan, self.decision, self.pol, receipts,
            RING, moment, COORD, 1
        )

    def chain(self, *confirmations):
        """Build a valid round chain over confirmation packets."""
        rounds = []
        previous = None
        for position, confirmation in enumerate(confirmations):
            rounds.append({
                "confirmation": confirmation,
                "previous": previous,
                "seq": position + 1,
            })
            previous = hashlib.sha256(confirmation).hexdigest()
        return rounds

    def certify(self, rounds, ring=None, moment=CERTIFIED_AT,
                issuer=COORD, version=1):
        return certify_fork_convergence(
            rounds, self.decision, self.pol, ring or RING, moment,
            issuer, version,
        )

    def verify(self, certificate, rounds, ring=None, moment=VERIFY_MOMENT):
        return verify_fork_convergence(
            certificate, rounds, self.decision, self.pol, ring or RING,
            moment,
        )


class CertificateShapeTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        pair = [
            self.execution_receipt(BETA, moment=220, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=225, post_digest="e2" * 32),
        ]
        self.rounds = self.chain(self.confirm(pair))
        self.raw = self.certify(self.rounds)
        self.data = parse(self.raw)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertIsInstance(self.raw, bytes)
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(self.data), self.raw)

    def test_top_and_payload_key_sets(self):
        self.assertEqual(set(self.data.keys()), {"payload", "signature"})
        self.assertEqual(
            set(self.data["payload"].keys()),
            {"certifiedAt", "decisionDigest", "issuer", "keyVersion",
             "planDigest", "results", "rounds", "status", "version"},
        )

    def test_signing_and_digest_bindings(self):
        payload = self.data["payload"]
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["certifiedAt"], CERTIFIED_AT)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(
            payload["decisionDigest"],
            hashlib.sha256(self.decision).hexdigest(),
        )
        self.assertEqual(payload["planDigest"], self.plan_digest)
        self.assertEqual(
            payload["rounds"],
            [hashlib.sha256(entry["confirmation"]).hexdigest()
             for entry in self.rounds],
        )

    def test_signature_is_the_payload_hmac(self):
        payload = self.data["payload"]
        self.assertEqual(
            self.data["signature"], sign_bytes(payload, SECRET_COORD)
        )

    def test_result_rows_have_the_fixed_key_set_and_plan_order(self):
        results = self.data["payload"]["results"]
        self.assertEqual([row["target"] for row in results], [BETA, GAMMA])
        for row in results:
            self.assertEqual(
                set(row.keys()),
                {"operationId", "postDigest", "result", "settledRound",
                 "target"},
            )
            self.assertEqual(row["result"], "executed")
            self.assertEqual(row["settledRound"], 1)

    def test_inputs_are_not_modified(self):
        rounds = self.chain(self.confirm([
            self.execution_receipt(BETA, moment=220),
            self.execution_receipt(GAMMA, moment=225),
        ]))
        snapshot = copy.deepcopy((rounds, self.decision, self.pol, RING))
        self.certify(rounds)
        self.assertEqual((rounds, self.decision, self.pol, RING), snapshot)


class ConvergenceSemanticsTest(ConvergenceFixtures, unittest.TestCase):
    def converge(self, *confirmations):
        payload = parse(self.certify(self.chain(*confirmations)))["payload"]
        return payload["results"], payload["status"]

    def test_single_confirmed_round(self):
        results, status = self.converge(self.confirm([
            self.execution_receipt(BETA, moment=220, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=225, post_digest="e2" * 32),
        ]))
        self.assertEqual(status, "confirmed")
        self.assertEqual(
            [(r["target"], r["result"], r["settledRound"]) for r in results],
            [(BETA, "executed", 1), (GAMMA, "executed", 1)],
        )
        self.assertEqual(results[0]["postDigest"], "e1" * 32)
        self.assertEqual(results[1]["postDigest"], "e2" * 32)

    def test_failed_advances_to_executed_in_a_later_round(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, moment=220,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, result="failed", moment=221),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, moment=222,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, moment=223,
                                       post_digest="e2" * 32),
            ], moment=260),
        )
        self.assertEqual(status, "confirmed")
        self.assertEqual(
            [(r["result"], r["settledRound"]) for r in results],
            [("executed", 1), ("executed", 2)],
        )

    def test_failed_advances_to_rejected_gives_rejected(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, result="failed", moment=220),
                self.execution_receipt(GAMMA, moment=221,
                                       post_digest="e2" * 32),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, result="rejected", moment=222),
                self.execution_receipt(GAMMA, moment=223,
                                       post_digest="e2" * 32),
            ], moment=260),
        )
        self.assertEqual(status, "rejected")
        self.assertEqual(
            [(r["result"], r["settledRound"], r["postDigest"])
             for r in results],
            [("rejected", 2, None), ("executed", 1, "e2" * 32)],
        )

    def test_never_settled_operation_is_partial(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, result="failed", moment=220),
                self.execution_receipt(GAMMA, moment=221,
                                       post_digest="e2" * 32),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, result="failed", moment=222),
                self.execution_receipt(GAMMA, moment=223,
                                       post_digest="e2" * 32),
            ], moment=260),
        )
        self.assertEqual(status, "partial")
        self.assertEqual(
            (results[0]["result"], results[0]["settledRound"],
             results[0]["postDigest"]),
            ("failed", None, None),
        )

    def test_settled_execution_cannot_swap_to_rejected(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, moment=220,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, moment=221,
                                       post_digest="e2" * 32),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, result="rejected", moment=222),
                self.execution_receipt(GAMMA, moment=223,
                                       post_digest="e2" * 32),
            ], moment=260),
        )
        self.assertEqual(status, "conflicted")
        self.assertEqual(results[0]["result"], "conflicted")
        self.assertEqual(results[0]["settledRound"], 1)
        self.assertEqual(results[0]["postDigest"], "e1" * 32)
        self.assertEqual(results[1]["result"], "executed")

    def test_settled_rejection_cannot_swap_to_executed(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, result="rejected", moment=220),
                self.execution_receipt(GAMMA, moment=221,
                                       post_digest="e2" * 32),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, moment=222,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, moment=223,
                                       post_digest="e2" * 32),
            ], moment=260),
        )
        self.assertEqual(status, "conflicted")
        self.assertEqual(
            (results[0]["result"], results[0]["settledRound"],
             results[0]["postDigest"]),
            ("conflicted", 1, None),
        )

    def test_settled_execution_cannot_roll_back_to_failed(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, moment=220,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, moment=221,
                                       post_digest="e2" * 32),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, result="failed", moment=222),
                self.execution_receipt(GAMMA, moment=223,
                                       post_digest="e2" * 32),
            ], moment=260),
        )
        self.assertEqual(status, "conflicted")
        self.assertEqual(results[0]["result"], "conflicted")

    def test_cross_round_post_digest_conflict_keeps_the_first_evidence(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, moment=220,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, moment=221,
                                       post_digest="e2" * 32),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, moment=222,
                                       post_digest="e9" * 32),
                self.execution_receipt(GAMMA, moment=223,
                                       post_digest="e2" * 32),
            ], moment=260),
        )
        self.assertEqual(status, "conflicted")
        # The settled post-state digest is never overwritten by new
        # evidence.
        self.assertEqual(results[0]["postDigest"], "e1" * 32)

    def test_repeated_settled_outcome_stays_confirmed(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, moment=220,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, moment=221,
                                       post_digest="e2" * 32),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, moment=222,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, moment=223,
                                       post_digest="e2" * 32),
            ], moment=260),
        )
        self.assertEqual(status, "confirmed")
        self.assertEqual([r["settledRound"] for r in results], [1, 1])

    def test_conflict_beats_rejection_and_missing(self):
        results, status = self.converge(
            self.confirm([
                self.execution_receipt(BETA, moment=220,
                                       post_digest="e1" * 32),
                self.execution_receipt(GAMMA, result="failed", moment=221),
            ], moment=250),
            self.confirm([
                self.execution_receipt(BETA, result="rejected", moment=222),
                self.execution_receipt(GAMMA, result="rejected", moment=223),
            ], moment=260),
        )
        self.assertEqual(status, "conflicted")
        self.assertEqual(
            [r["result"] for r in results], ["conflicted", "rejected"]
        )


class RoundChainTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.first = self.confirm([
            self.execution_receipt(BETA, moment=220, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=221, post_digest="e2" * 32),
        ], moment=250)
        self.second = self.confirm([
            self.execution_receipt(BETA, moment=222, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=223, post_digest="e2" * 32),
        ], moment=260)

    def assert_convergence_invalid(self, rounds):
        with self.assertRaises(InvalidForkConvergenceError):
            self.certify(rounds)

    def test_rounds_must_start_at_one(self):
        rounds = self.chain(self.first)
        rounds[0]["seq"] = 0
        self.assert_convergence_invalid(rounds)
        rounds = self.chain(self.first)
        rounds[0]["seq"] = 2
        self.assert_convergence_invalid(rounds)

    def test_seq_gap_reorder_and_duplicate_are_rejected(self):
        rounds = self.chain(self.first, self.second)
        rounds[1]["seq"] = 3
        self.assert_convergence_invalid(rounds)
        rounds = self.chain(self.first, self.second)
        rounds[0]["seq"], rounds[1]["seq"] = 2, 1
        self.assert_convergence_invalid(rounds)
        rounds = self.chain(self.first, self.second)
        rounds[1]["seq"] = 1
        self.assert_convergence_invalid(rounds)

    def test_first_round_binds_no_previous(self):
        rounds = self.chain(self.first)
        rounds[0]["previous"] = "ab" * 32
        self.assert_convergence_invalid(rounds)

    def test_broken_chain_link_is_rejected(self):
        rounds = self.chain(self.first, self.second)
        rounds[1]["previous"] = "ab" * 32
        self.assert_convergence_invalid(rounds)
        rounds = self.chain(self.first, self.second)
        rounds[1]["previous"] = None
        self.assert_convergence_invalid(rounds)

    def test_aggregation_moments_must_strictly_increase(self):
        stale = self.confirm([
            self.execution_receipt(BETA, moment=224,
                                   post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=225,
                                   post_digest="e2" * 32),
        ], moment=250)
        self.assert_convergence_invalid(self.chain(self.first, stale))
        self.assert_convergence_invalid(self.chain(self.second, self.first))

    def test_rounds_must_bind_the_same_plan(self):
        other_plan = plan_fork_execution(
            self.decision, self.pol, RING, GENERATED_AT, EXPIRES_AT + 1
        )
        other_digest = hashlib.sha256(other_plan).hexdigest()
        operations = {op["target"]: op
                      for op in parse(other_plan)["operations"]}

        def oreceipt(target, moment, post):
            operation = operations[target]
            payload = {
                "planDigest": other_digest,
                "operationId": operation["operationId"],
                "site": target, "keyVersion": 1, "siteVersion": "sv-1",
                "executionMoment": moment,
                "previous": hashlib.sha256(
                    compact(operation["requires"])).hexdigest(),
                "result": "executed", "postDigest": post,
            }
            return rewrap(payload, SECRETS[target])

        other_confirmation = confirm_fork_execution(
            other_plan, self.decision, self.pol,
            [oreceipt(BETA, 222, "e1" * 32), oreceipt(GAMMA, 223, "e2" * 32)],
            RING, 260, COORD, 1,
        )
        self.assert_convergence_invalid(
            self.chain(self.first, other_confirmation)
        )

    def test_bad_confirmation_raises_invalid_fork_execution(self):
        rounds = self.chain(self.first)
        rounds[0]["confirmation"] = b"{}"
        rounds[0]["previous"] = None
        with self.assertRaises(InvalidForkExecutionError):
            self.certify(rounds)

    def test_container_and_field_faults(self):
        with self.assertRaises(TypeError):
            self.certify("x")
        with self.assertRaises(ValueError):
            self.certify([])
        with self.assertRaises(TypeError):
            self.certify(["x"])
        with self.assertRaises(ValueError):
            self.certify([{"seq": 1, "previous": None}])
        with self.assertRaises(ValueError):
            self.certify([{"seq": 1, "previous": None,
                           "confirmation": self.first, "extra": 1}])
        with self.assertRaises(TypeError):
            self.certify([{"seq": True, "previous": None,
                           "confirmation": self.first}])
        with self.assertRaises(TypeError):
            self.certify([{"seq": "1", "previous": None,
                           "confirmation": self.first}])
        with self.assertRaises(TypeError):
            self.certify([{"seq": 1, "previous": 7,
                           "confirmation": self.first}])
        with self.assertRaises(TypeError):
            self.certify([{"seq": 1, "previous": None,
                           "confirmation": "x"}])
        with self.assertRaises(ValueError):
            self.certify([{"seq": 1, "previous": None, "confirmation": b""}])

    def test_shared_argument_faults(self):
        rounds = self.chain(self.first)
        with self.assertRaises(TypeError):
            certify_fork_convergence(
                rounds, "x", self.pol, RING, CERTIFIED_AT, COORD, 1
            )
        with self.assertRaises(TypeError):
            self.certify(rounds, moment=True)
        with self.assertRaises(ValueError):
            self.certify(rounds, moment=-1)
        with self.assertRaises(TypeError):
            self.certify(rounds, issuer=7)
        with self.assertRaises(ValueError):
            self.certify(rounds, issuer="")
        with self.assertRaises(TypeError):
            self.certify(rounds, version=True)
        with self.assertRaises(ValueError):
            self.certify(rounds, version=0)

    def test_signing_credentials_have_no_fallback(self):
        rounds = self.chain(self.first)
        with self.assertRaises(AuthenticationError):
            self.certify(rounds, issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.certify(rounds, version=2)
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            self.certify(rounds, ring=revoked)
        future = {**RING, COORD: [entry(1, SECRET_COORD, not_before=271)]}
        with self.assertRaises(AuthenticationError):
            self.certify(rounds, ring=future)


class VerifyConvergenceTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        first = self.confirm([
            self.execution_receipt(BETA, result="failed", moment=220),
            self.execution_receipt(GAMMA, moment=221, post_digest="e2" * 32),
        ], moment=250)
        second = self.confirm([
            self.execution_receipt(BETA, moment=222, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=223, post_digest="e2" * 32),
        ], moment=260)
        self.rounds = self.chain(first, second)
        self.raw = self.certify(self.rounds)

    def payload(self):
        return parse(self.raw)["payload"]

    def test_result_is_a_fresh_fixed_key_mapping(self):
        result = self.verify(self.raw, self.rounds)
        self.assertEqual(
            list(result.keys()),
            ["certifiedAt", "certificateDigest", "decisionDigest", "issuer",
             "keyVersion", "planDigest", "results", "rounds", "status",
             "version"],
        )
        self.assertEqual(result["certificateDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["planDigest"], self.plan_digest)
        self.assertEqual(result["decisionDigest"],
                         hashlib.sha256(self.decision).hexdigest())
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["version"], 1)
        self.assertEqual(
            [r["settledRound"] for r in result["results"]], [2, 1]
        )

    def test_repeated_calls_share_no_mutable_object(self):
        first = self.verify(self.raw, self.rounds)
        first["results"].append("tampered")
        first["rounds"].append("tampered")
        second = self.verify(self.raw, self.rounds)
        self.assertNotEqual(first, second)
        self.assertEqual(len(second["results"]), 2)
        self.assertEqual(len(second["rounds"]), 2)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            verify_fork_convergence(
                "x", self.rounds, self.decision, self.pol, RING,
                VERIFY_MOMENT,
            )
        with self.assertRaises(TypeError):
            self.verify(self.raw, "x")
        with self.assertRaises(ValueError):
            self.verify(self.raw, [])
        with self.assertRaises(TypeError):
            verify_fork_convergence(
                self.raw, self.rounds, "x", self.pol, RING, VERIFY_MOMENT,
            )
        with self.assertRaises(TypeError):
            self.verify(self.raw, self.rounds, moment=True)
        with self.assertRaises(ValueError):
            self.verify(self.raw, self.rounds, moment=-1)

    def test_encoding_faults(self):
        for raw in (self.raw + b"\n", self.raw + b" ", b"", b"{"):
            with self.assertRaises(InvalidForkConvergenceError):
                self.verify(raw, self.rounds)
        with self.assertRaises(TypeError):
            self.verify(b"[]", self.rounds)

    def test_key_sets(self):
        data = parse(self.raw)
        del data["signature"]
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(compact(data), self.rounds)
        payload = self.payload()
        del payload["results"]
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(rewrap(payload), self.rounds)
        payload = self.payload()
        payload["extra"] = 1
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(rewrap(payload), self.rounds)

    def test_field_type_faults(self):
        checks = [
            ("issuer", 7, TypeError),
            ("issuer", "", InvalidForkConvergenceError),
            ("keyVersion", "1", TypeError),
            ("keyVersion", 0, InvalidForkConvergenceError),
            ("certifiedAt", True, TypeError),
            ("certifiedAt", -1, InvalidForkConvergenceError),
            ("decisionDigest", 7, TypeError),
            ("decisionDigest", "zz" * 32, InvalidForkConvergenceError),
            ("planDigest", "zz" * 32, InvalidForkConvergenceError),
            ("status", 7, TypeError),
            ("status", "nope", InvalidForkConvergenceError),
            ("version", True, TypeError),
            ("version", 2, InvalidForkConvergenceError),
            ("rounds", {}, TypeError),
            ("rounds", [], InvalidForkConvergenceError),
            ("rounds", ["zz" * 32], InvalidForkConvergenceError),
            ("results", {}, TypeError),
            ("results", [], InvalidForkConvergenceError),
        ]
        for field, value, expected in checks:
            payload = self.payload()
            payload[field] = value
            with self.assertRaises(expected, msg=field):
                self.verify(rewrap(payload), self.rounds)

    def test_result_row_faults(self):
        def tamper(row_update, expected=InvalidForkConvergenceError):
            payload = self.payload()
            payload["results"][0].update(row_update)
            with self.assertRaises(expected):
                self.verify(rewrap(payload), self.rounds)

        tamper({"operationId": "zz" * 32})
        tamper({"result": "nope"})
        tamper({"postDigest": 7}, TypeError)
        tamper({"settledRound": True}, TypeError)
        tamper({"settledRound": 0})
        tamper({"target": ""})
        tamper({"extra": 1})

    def test_tampered_status_or_results_are_invalid_even_if_resigned(self):
        payload = self.payload()
        payload["status"] = "partial"
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(rewrap(payload), self.rounds)
        payload = self.payload()
        payload["results"][0]["result"] = "failed"
        payload["results"][0]["postDigest"] = None
        payload["results"][0]["settledRound"] = None
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(rewrap(payload), self.rounds)

    def test_tampered_round_digests_are_invalid(self):
        payload = self.payload()
        payload["rounds"] = list(reversed(payload["rounds"]))
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(rewrap(payload), self.rounds)

    def test_certificate_bound_to_another_decision_is_invalid(self):
        other = decide(policy(threshold=3))
        with self.assertRaises(InvalidForkConvergenceError):
            verify_fork_convergence(
                self.raw, self.rounds, other, self.pol, RING, VERIFY_MOMENT,
            )

    def test_offered_rounds_must_match_the_bound_digests(self):
        third = self.confirm([
            self.execution_receipt(BETA, moment=224,
                                   post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=225,
                                   post_digest="e2" * 32),
        ], moment=265)
        rounds = self.chain(self.rounds[0]["confirmation"], third)
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(self.raw, rounds)

    def test_future_certification_is_invalid(self):
        future = self.certify(self.rounds, moment=290)
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(future, self.rounds, moment=VERIFY_MOMENT)
        self.assertEqual(
            self.verify(future, self.rounds, moment=300)["status"],
            "confirmed",
        )

    def test_credential_faults(self):
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, self.rounds, ring=revoked)
        expired = {**RING, COORD: [entry(1, SECRET_COORD, not_after=275)]}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, self.rounds, ring=expired)
        unknown = {k: v for k, v in RING.items() if k != COORD}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, self.rounds, ring=unknown)
        data = parse(self.raw)
        data["signature"] = ("1" if data["signature"][0] == "0" else "0") \
            + data["signature"][1:]
        with self.assertRaises(AuthenticationError):
            self.verify(compact(data), self.rounds)

    def test_inputs_are_not_modified(self):
        snapshot = copy.deepcopy(
            (self.raw, self.rounds, self.decision, self.pol, RING)
        )
        self.verify(self.raw, self.rounds)
        self.assertEqual(
            (self.raw, self.rounds, self.decision, self.pol, RING), snapshot
        )


class BatchConvergenceTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        confirmation = self.confirm([
            self.execution_receipt(BETA, moment=220, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=225, post_digest="e2" * 32),
        ])
        self.rounds = self.chain(confirmation)
        self.good = self.certify(self.rounds)

    def batch(self, items, ring=None, moment=VERIFY_MOMENT):
        return verify_fork_convergences(
            items, self.decision, self.pol, ring or RING, moment
        )

    def test_container_type_faults(self):
        with self.assertRaises(TypeError):
            self.batch("x")
        with self.assertRaises(TypeError):
            self.batch(["x"])
        with self.assertRaises(TypeError):
            self.batch([{"id": 1, "certificate": self.good,
                         "rounds": self.rounds}])
        with self.assertRaises(TypeError):
            self.batch([{"id": "x", "certificate": "y",
                         "rounds": self.rounds}])
        with self.assertRaises(TypeError):
            self.batch([{"id": "x", "certificate": self.good,
                         "rounds": "y"}])

    def test_container_value_faults(self):
        with self.assertRaises(ValueError):
            self.batch([])
        with self.assertRaises(ValueError):
            self.batch([{"id": "", "certificate": self.good,
                         "rounds": self.rounds}])
        with self.assertRaises(ValueError):
            self.batch([
                {"id": "x", "certificate": self.good, "rounds": self.rounds},
                {"id": "x", "certificate": self.good, "rounds": self.rounds},
            ])
        with self.assertRaises(ValueError):
            self.batch([{"id": "x", "certificate": self.good,
                         "rounds": self.rounds, "n": 1}])
        with self.assertRaises(ValueError):
            self.batch([{"id": "x", "certificate": self.good, "rounds": []}])

    def test_shared_material_faults(self):
        items = [{"id": "x", "certificate": self.good,
                  "rounds": self.rounds}]
        with self.assertRaises(TypeError):
            verify_fork_convergences(items, "x", self.pol, RING,
                                     VERIFY_MOMENT)
        with self.assertRaises(TypeError):
            verify_fork_convergences(items, self.decision, self.pol, RING,
                                     True)
        with self.assertRaises(ValueError):
            verify_fork_convergences(items, self.decision, self.pol, RING,
                                     -1)

    def test_reports_in_input_order_with_isolation(self):
        report = self.batch([
            {"id": "ok", "certificate": self.good, "rounds": self.rounds},
            {"id": "bad", "certificate": b"{}", "rounds": self.rounds},
            {"id": "ok2", "certificate": self.good, "rounds": self.rounds},
        ])
        self.assertEqual([item["id"] for item in report["items"]],
                         ["ok", "bad", "ok2"])
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses, {"ok": "verified", "bad": "invalid",
                                    "ok2": "verified"})

    def test_report_key_order_and_null_result(self):
        report = self.batch([
            {"id": "bad", "certificate": b"{}", "rounds": self.rounds},
        ])
        item = report["items"][0]
        self.assertEqual(list(item.keys()),
                         ["error", "id", "result", "status"])
        self.assertIsNone(item["result"])
        self.assertTrue(item["error"])

    def test_broken_item_rounds_are_invalid_alone(self):
        broken = self.chain(self.rounds[0]["confirmation"])
        broken[0]["previous"] = "ab" * 32
        report = self.batch([
            {"id": "broken", "certificate": self.good, "rounds": broken},
            {"id": "ok", "certificate": self.good, "rounds": self.rounds},
        ])
        self.assertEqual(report["items"][0]["status"], "invalid")
        self.assertEqual(report["items"][1]["status"], "verified")

    def test_bad_confirmation_inside_a_round_is_invalid(self):
        rounds = [{"seq": 1, "previous": None, "confirmation": b"{}"}]
        report = self.batch([
            {"id": "x", "certificate": self.good, "rounds": rounds},
        ])
        self.assertEqual(report["items"][0]["status"], "invalid")
        self.assertIn("fork execution", report["items"][0]["error"])

    def test_unauthenticated_item(self):
        ring = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        report = self.batch(
            [{"id": "x", "certificate": self.good, "rounds": self.rounds}],
            ring=ring,
        )
        item = report["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertIsNone(item["result"])
        self.assertTrue(item["error"])

    def test_top_level_shape_and_version(self):
        report = self.batch([
            {"id": "x", "certificate": self.good, "rounds": self.rounds},
        ])
        self.assertEqual(set(report.keys()), {"items", "version"})
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["items"][0]["result"]["status"], "confirmed")

    def test_repeated_calls_are_independent(self):
        items = [{"id": "x", "certificate": self.good,
                  "rounds": self.rounds}]
        first = self.batch(items)
        second = self.batch(items)
        self.assertEqual(first, second)
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])
        first["items"][0]["result"]["status"] = "tampered"
        self.assertEqual(
            self.batch(items)["items"][0]["result"]["status"], "confirmed"
        )


if __name__ == "__main__":
    unittest.main()
