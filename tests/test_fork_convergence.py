"""Tests for offline multi-round fork convergence certificates.

Covers :func:`certify_fork_convergence`,
:func:`verify_fork_convergence` and :func:`verify_fork_convergences`:
the canonical certificate and round-summary chain, single- and
multi-round convergence, the failed -> executed/rejected progression,
settled-state conflicts (reversal, swap and post-digest drift), the
confirmed/partial/rejected/conflicted overall statuses and per-operation
settling rounds, round numbering/chaining/moment validation, the exact
exception classification (``TypeError``/``ValueError``/
``InvalidForkExecutionError``/``InvalidForkConvergenceError``/
``AuthenticationError``), credential rules, tamper detection, and the
batch wrapper's upfront validation, strict input order, isolation and
fresh results.
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
SECRET_OTHER = "99" * 32

COORD = "coord"
ALPHA = "alpha"
BETA = "beta"
GAMMA = "gamma"
DELTA = "delta"

BASE = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}

SIGN_MOMENT = 150
DECIDE_MOMENT = 200
GENERATED_AT = 210
EXPIRES_AT = 400
CERTIFIED_AT = 260
VERIFY_MOMENT = 270


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def parse(raw):
    return json.loads(raw.decode("utf-8"))


def key_entry(secret, not_before=0, not_after=10 ** 9, revoked=False):
    return {
        "version": 1,
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

RING = {node: [key_entry(secret)] for node, secret in SECRETS.items()}


def sign_bytes(payload, secret):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def rewrap(payload, secret=SECRET_COORD):
    return compact(
        {"payload": payload, "signature": sign_bytes(payload, secret)}
    )


def make_report(item_id="item-1"):
    return {
        "error": "boom",
        "id": item_id,
        "result": None,
        "status": "invalid-proof",
    }


def make_receipt(item_id="item-1"):
    payload = {
        "issuer": COORD,
        "keyVersion": 1,
        "moment": 100,
        "policy": hashlib.sha256(compact({
            "batch": "batch-1", "sites": {"a": [1]}, "threshold": 1,
        })).hexdigest(),
        "items": [{
            "id": item_id,
            "digest": "aa" * 32,
            "report": make_report(item_id),
        }],
        "version": 1,
    }
    return rewrap(payload)


def make_hop(issuer, audience, upstream, moment):
    payload = {
        "issuer": issuer,
        "keyVersion": 1,
        "moment": moment,
        "audience": audience,
        "upstream": hashlib.sha256(upstream).hexdigest(),
        "version": 1,
    }
    return rewrap(payload, SECRETS[issuer])


def fork_chain_items():
    receipt = make_receipt()
    to_alpha = make_hop(COORD, ALPHA, receipt, 110)
    return [
        {
            "id": "a",
            "receipt": receipt,
            "hops": [to_alpha, make_hop(ALPHA, BETA, to_alpha, 120)],
            "target": BETA,
        },
        {
            "id": "b",
            "receipt": receipt,
            "hops": [to_alpha, make_hop(ALPHA, GAMMA, to_alpha, 120)],
            "target": GAMMA,
        },
    ]


def fork_proof(site):
    return sign_receipt_fork_proof(
        fork_chain_items(), BASE, RING, SIGN_MOMENT, site, 1
    )


def fork_policy():
    return {
        "action": "isolate",
        "base": BASE,
        "sites": {ALPHA: {1}, BETA: {1}, GAMMA: {1}, DELTA: {1}},
        "threshold": 2,
    }


def accepted_decision(pol):
    return decide_forks(
        [
            {"id": "x", "proof": fork_proof(ALPHA)},
            {"id": "y", "proof": fork_proof(BETA)},
        ],
        pol, RING, DECIDE_MOMENT, COORD, 1,
    )


def round_summary(number, previous_summary, confirmation_bytes):
    """Reference implementation of a round's chained summary."""
    return hashlib.sha256(compact({
        "confirmations": [
            hashlib.sha256(raw).hexdigest() for raw in confirmation_bytes
        ],
        "previousSummary": previous_summary,
        "round": number,
    })).hexdigest()


class ConvergenceFixtures:
    """Mixin building an accepted decision, plan and round helpers."""

    def setUp(self):  # noqa: D102
        self.pol = fork_policy()
        self.decision = accepted_decision(self.pol)
        self.plan = plan_fork_execution(
            self.decision, self.pol, RING, GENERATED_AT, EXPIRES_AT
        )
        self.plan_digest = hashlib.sha256(self.plan).hexdigest()
        self.operations = {
            op["target"]: op for op in parse(self.plan)["operations"]
        }

    def previous_digest(self, operation):
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
            "previous": self.previous_digest(operation),
            "result": result,
            "postDigest": (
                post_digest if result == "executed" else None
            ),
        }
        return rewrap(payload, SECRETS[target])

    def confirm(self, receipts, aggregated_at=240):
        return confirm_fork_execution(
            self.plan, self.decision, self.pol, receipts, RING,
            aggregated_at, COORD, 1,
        )

    def make_round(self, number, confirmations, previous_summary):
        return {
            "round": number,
            "previousSummary": previous_summary,
            "confirmations": list(confirmations),
        }

    def chain_rounds(self, confirmations_by_round):
        """Build the linked round list from one confirmation list per round."""
        rounds = []
        previous = None
        for index, confirmations in enumerate(confirmations_by_round, start=1):
            rounds.append(
                self.make_round(index, confirmations, previous)
            )
            previous = round_summary(index, previous, confirmations)
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
    def test_canonical_compact_bytes_without_trailing_byte(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        rounds = self.chain_rounds([[c1]])
        certificate = self.certify(rounds)
        self.assertIsInstance(certificate, bytes)
        self.assertTrue(certificate.endswith(b"}"))
        self.assertNotIn(b"\n", certificate)
        envelope = parse(certificate)
        self.assertEqual(compact(envelope), certificate)

    def test_envelope_and_payload_key_sets(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        rounds = self.chain_rounds([[c1]])
        envelope = parse(self.certify(rounds))
        self.assertEqual(set(envelope.keys()), {"payload", "signature"})
        payload = envelope["payload"]
        self.assertEqual(
            set(payload.keys()),
            {
                "certifiedAt", "decisionDigest", "issuer", "keyVersion",
                "planDigest", "policyDigest", "results", "roundSummaries",
                "status", "version",
            },
        )
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)
        self.assertEqual(payload["certifiedAt"], CERTIFIED_AT)
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["planDigest"], self.plan_digest)
        self.assertEqual(
            payload["decisionDigest"],
            hashlib.sha256(self.decision).hexdigest(),
        )

    def test_round_summary_chain_is_bound(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA, result="failed"),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(GAMMA, moment=225, post_digest="d1" * 32),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        payload = parse(self.certify(rounds))["payload"]
        first = round_summary(1, None, [c1])
        second = round_summary(2, first, [c2])
        self.assertEqual(payload["roundSummaries"], [first, second])

    def test_result_rows_have_the_fixed_shape_and_plan_order(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA, result="failed"),
        ])
        rounds = self.chain_rounds([[c1]])
        results = parse(self.certify(rounds))["payload"]["results"]
        self.assertEqual([row["target"] for row in results], [BETA, GAMMA])
        for row in results:
            self.assertEqual(
                set(row.keys()),
                {"operationId", "postDigest", "result", "settledRound",
                 "target"},
            )
        self.assertEqual(results[0]["result"], "executed")
        self.assertEqual(results[0]["settledRound"], 1)
        self.assertEqual(results[0]["postDigest"], "c0" * 32)
        self.assertEqual(results[1]["result"], "failed")
        self.assertEqual(results[1]["settledRound"], 0)
        self.assertIsNone(results[1]["postDigest"])


class ConvergenceTallyTest(ConvergenceFixtures, unittest.TestCase):
    def test_confirmed_single_round(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        rounds = self.chain_rounds([[c1]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(
            [(row["target"], row["result"], row["settledRound"])
             for row in result["results"]],
            [(BETA, "executed", 1), (GAMMA, "executed", 1)],
        )

    def test_partial_then_confirmed_across_rounds(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA, result="failed"),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(GAMMA, moment=225, post_digest="d1" * 32),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "confirmed")
        beta, gamma = result["results"]
        self.assertEqual(beta["result"], "executed")
        self.assertEqual(beta["settledRound"], 1)
        self.assertEqual(gamma["result"], "executed")
        self.assertEqual(gamma["settledRound"], 2)
        self.assertEqual(gamma["postDigest"], "d1" * 32)

    def test_failed_can_advance_to_rejected(self):
        c1 = self.confirm([
            self.execution_receipt(BETA, result="rejected"),
            self.execution_receipt(GAMMA, result="failed"),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(GAMMA, result="rejected", moment=225),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(
            [row["result"] for row in result["results"]],
            ["rejected", "rejected"],
        )
        self.assertEqual(result["results"][1]["settledRound"], 2)

    def test_rejected_beats_partial(self):
        c1 = self.confirm([
            self.execution_receipt(BETA, result="rejected"),
            self.execution_receipt(GAMMA, result="failed"),
        ])
        rounds = self.chain_rounds([[c1]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "rejected")

    def test_repeated_executed_keeps_original_settling_round(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(BETA, moment=221),
            self.execution_receipt(GAMMA, moment=226),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(
            [row["settledRound"] for row in result["results"]],
            [1, 1],
        )

    def test_executed_then_rejected_conflicts(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(BETA, result="rejected", moment=221),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "conflicted")
        beta, gamma = result["results"]
        self.assertEqual(beta["result"], "conflicted")
        self.assertEqual(beta["settledRound"], 2)
        self.assertIsNone(beta["postDigest"])
        self.assertEqual(gamma["result"], "executed")

    def test_rejected_then_executed_conflicts(self):
        c1 = self.confirm([
            self.execution_receipt(BETA, result="rejected"),
            self.execution_receipt(GAMMA, result="failed"),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(BETA, moment=221),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "conflicted")
        self.assertEqual(result["results"][0]["result"], "conflicted")

    def test_post_digest_drift_conflicts_without_new_evidence(self):
        c1 = self.confirm([
            self.execution_receipt(BETA, post_digest="e1" * 32),
            self.execution_receipt(GAMMA),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(
                BETA, moment=221, post_digest="e2" * 32
            ),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "conflicted")
        beta = result["results"][0]
        self.assertEqual(beta["result"], "conflicted")
        self.assertIsNone(beta["postDigest"])

    def test_later_failed_never_moves_a_settled_operation(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(BETA, result="failed", moment=221),
            self.execution_receipt(GAMMA, result="failed", moment=226),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(
            [row["settledRound"] for row in result["results"]],
            [1, 1],
        )

    def test_conflicted_operation_never_recovers(self):
        c1 = self.confirm([
            self.execution_receipt(BETA, post_digest="e1" * 32),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(
                BETA, moment=221, post_digest="e2" * 32
            ),
        ], aggregated_at=250)
        c3 = self.confirm([
            self.execution_receipt(
                BETA, moment=222, post_digest="e1" * 32
            ),
        ], aggregated_at=260)
        rounds = self.chain_rounds([[c1], [c2], [c3]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["results"][0]["result"], "conflicted")

    def test_multiple_confirmations_within_one_round_chain_together(self):
        c1a = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA, result="failed"),
        ], aggregated_at=240)
        c1b = self.confirm([
            self.execution_receipt(GAMMA, result="failed", moment=226),
        ], aggregated_at=240)
        rounds = self.chain_rounds([[c1a, c1b]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(
            result["roundSummaries"],
            [round_summary(1, None, [c1a, c1b])],
        )

    def test_within_round_executed_rejected_disagreement_conflicts(self):
        c_executed = self.confirm([
            self.execution_receipt(BETA),
        ], aggregated_at=240)
        c_rejected = self.confirm([
            self.execution_receipt(BETA, result="rejected"),
        ], aggregated_at=240)
        rounds = self.chain_rounds([[c_executed, c_rejected]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(result["status"], "conflicted")
        self.assertEqual(result["results"][0]["result"], "conflicted")
        self.assertEqual(result["results"][0]["settledRound"], 1)

    def test_verify_result_key_order(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        rounds = self.chain_rounds([[c1]])
        result = self.verify(self.certify(rounds), rounds)
        self.assertEqual(
            list(result.keys()),
            [
                "certifiedAt", "certificateDigest", "decisionDigest",
                "issuer", "keyVersion", "planDigest", "policyDigest",
                "results", "rounds", "roundSummaries", "status", "version",
            ],
        )
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["rounds"], [{
            "round": 1,
            "previousSummary": None,
            "confirmations": [hashlib.sha256(c1).hexdigest()],
        }])


class RoundStructureValidationTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])

    def test_rounds_must_be_a_list(self):
        with self.assertRaises(TypeError):
            self.certify(({"round": 1, "previousSummary": None,
                           "confirmations": [self.c1]},))
        with self.assertRaises(TypeError):
            self.verify(
                self.certify(self.chain_rounds([[self.c1]])),
                {"round": 1, "previousSummary": None,
                 "confirmations": [self.c1]},
            )

    def test_empty_rounds_raise_value_error(self):
        with self.assertRaises(ValueError):
            self.certify([])

    def test_round_must_be_a_dict_with_the_exact_keys(self):
        with self.assertRaises(TypeError):
            self.certify([("x",)])
        with self.assertRaises(ValueError):
            self.certify([{"round": 1,
                           "confirmations": [self.c1]}])
        with self.assertRaises(ValueError):
            self.certify([{"round": 1, "previousSummary": None,
                           "confirmations": [self.c1], "extra": 1}])

    def test_round_numbers_start_at_one(self):
        with self.assertRaises(ValueError):
            self.certify([{"round": 0, "previousSummary": None,
                           "confirmations": [self.c1]}])
        with self.assertRaises(ValueError):
            self.certify([{"round": 2, "previousSummary": None,
                           "confirmations": [self.c1]}])

    def test_gap_reordering_and_repetition_raise_value_error(self):
        gap = self.chain_rounds([[self.c1]])
        gap.append(self.make_round(3, [self.c1], "ab" * 32))
        with self.assertRaises(ValueError):
            self.certify(gap)
        swapped = [
            self.make_round(1, [self.c1], None),
            self.make_round(2, [self.c1], "ab" * 32),
        ]
        swapped[0], swapped[1] = swapped[1], swapped[0]
        with self.assertRaises(ValueError):
            self.certify(swapped)

    def test_bool_round_number_is_a_type_fault(self):
        with self.assertRaises(TypeError):
            self.certify([{"round": True, "previousSummary": None,
                           "confirmations": [self.c1]}])

    def test_first_previous_summary_must_be_null(self):
        with self.assertRaises(ValueError):
            self.certify([{"round": 1, "previousSummary": "ab" * 32,
                           "confirmations": [self.c1]}])

    def test_later_previous_summary_must_be_a_digest(self):
        with self.assertRaises(ValueError):
            self.certify([
                {"round": 1, "previousSummary": None,
                 "confirmations": [self.c1]},
                {"round": 2, "previousSummary": None,
                 "confirmations": [self.c1]},
            ])
        with self.assertRaises(ValueError):
            self.certify([
                {"round": 1, "previousSummary": None,
                 "confirmations": [self.c1]},
                {"round": 2, "previousSummary": "xyz",
                 "confirmations": [self.c1]},
            ])
        with self.assertRaises(TypeError):
            self.certify([
                {"round": 1, "previousSummary": None,
                 "confirmations": [self.c1]},
                {"round": 2, "previousSummary": 7,
                 "confirmations": [self.c1]},
            ])

    def test_confirmations_must_be_a_non_empty_list_of_bytes(self):
        with self.assertRaises(ValueError):
            self.certify([{"round": 1, "previousSummary": None,
                           "confirmations": []}])
        with self.assertRaises(TypeError):
            self.certify([{"round": 1, "previousSummary": None,
                           "confirmations": "x"}])
        with self.assertRaises(TypeError):
            self.certify([{"round": 1, "previousSummary": None,
                           "confirmations": ["x"]}])

    def test_empty_confirmation_bytes_are_a_bad_packet(self):
        with self.assertRaises(InvalidForkExecutionError):
            self.certify([{"round": 1, "previousSummary": None,
                           "confirmations": [b""]}])


class ConvergenceRelationshipTest(ConvergenceFixtures, unittest.TestCase):
    def _two_rounds(self, first_at=240, second_at=250):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA, result="failed"),
        ], aggregated_at=first_at)
        c2 = self.confirm([
            self.execution_receipt(GAMMA, moment=225, post_digest="d1" * 32),
        ], aggregated_at=second_at)
        return c1, c2

    def test_broken_summary_link_rejected(self):
        c1, c2 = self._two_rounds()
        rounds = self.chain_rounds([[c1], [c2]])
        rounds[1]["previousSummary"] = "ab" * 32
        with self.assertRaises(InvalidForkConvergenceError):
            self.certify(rounds)
        certificate = self.certify(self.chain_rounds([[c1], [c2]]))
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(certificate, rounds)

    def test_non_increasing_aggregation_moment_rejected(self):
        c1, c2 = self._two_rounds(first_at=250, second_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        with self.assertRaises(InvalidForkConvergenceError):
            self.certify(rounds)

    def test_verifying_with_different_rounds_fails(self):
        c1, c2 = self._two_rounds()
        good = self.chain_rounds([[c1], [c2]])
        certificate = self.certify(good)
        # Swapping the round contents breaks both the link and summaries.
        swapped = self.chain_rounds([[c2], [c1]])
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(certificate, swapped)
        # Repeating round one's packet in round two changes its summary.
        repeated = self.chain_rounds([[c1], [c1]])
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(certificate, repeated)

    def test_tampered_bound_results_fail_the_binding(self):
        c1, c2 = self._two_rounds()
        rounds = self.chain_rounds([[c1], [c2]])
        envelope = parse(self.certify(rounds))
        envelope["payload"]["status"] = "partial"
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(compact(envelope), rounds)

    def test_tampered_result_row_fails_the_binding(self):
        c1, c2 = self._two_rounds()
        rounds = self.chain_rounds([[c1], [c2]])
        envelope = parse(self.certify(rounds))
        envelope["payload"]["results"][0]["result"] = "rejected"
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(compact(envelope), rounds)

    def test_certification_moment_after_verification_moment_rejected(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ], aggregated_at=240)
        rounds = self.chain_rounds([[c1]])
        certificate = self.certify(rounds, moment=300)
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(certificate, rounds, moment=290)

    def test_round_confirmation_for_another_decision_is_a_bad_confirmation(self):
        # A fully authentic confirmation produced over a different
        # decision/plan (here a rollback plan for the same fork) cannot
        # enter a certificate for the isolate decision: the
        # single-packet rules reject it as a bad confirmation.
        rollback_policy = {**fork_policy(), "action": "rollback"}
        rollback_decision = accepted_decision(rollback_policy)
        rollback_plan = plan_fork_execution(
            rollback_decision, rollback_policy, RING, GENERATED_AT,
            EXPIRES_AT,
        )
        rollback_ops = {
            op["target"]: op for op in parse(rollback_plan)["operations"]
        }

        def rollback_failure(target, moment):
            operation = rollback_ops[target]
            payload = {
                "planDigest": hashlib.sha256(rollback_plan).hexdigest(),
                "operationId": operation["operationId"],
                "site": target,
                "keyVersion": 1,
                "siteVersion": "sv-1",
                "executionMoment": moment,
                "previous": hashlib.sha256(
                    compact(operation["requires"])
                ).hexdigest(),
                "result": "failed",
                "postDigest": None,
            }
            return rewrap(payload, SECRETS[target])

        other_confirmation = confirm_fork_execution(
            rollback_plan, rollback_decision, rollback_policy,
            [rollback_failure(BETA, 220), rollback_failure(GAMMA, 221)],
            RING, 240, COORD, 1,
        )
        rounds = [{
            "round": 1,
            "previousSummary": None,
            "confirmations": [other_confirmation],
        }]
        with self.assertRaises(InvalidForkExecutionError):
            certify_fork_convergence(
                rounds, self.decision, self.pol, RING, CERTIFIED_AT,
                COORD, 1,
            )

    def test_round_with_a_corrupt_packet_is_invalid_fork_execution(self):
        rounds = [{
            "round": 1,
            "previousSummary": None,
            "confirmations": [b"{not-json"],
        }]
        with self.assertRaises(InvalidForkExecutionError):
            self.certify(rounds)


class CertificateStructureTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        self.rounds = self.chain_rounds([[self.c1]])
        self.certificate = self.certify(self.rounds)

    def test_certificate_must_be_bytes(self):
        with self.assertRaises(TypeError):
            self.verify("x", self.rounds)

    def test_trailing_byte_rejected(self):
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(self.certificate + b"\n", self.rounds)
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(self.certificate + b" ", self.rounds)

    def test_not_json_rejected(self):
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(b"{nope", self.rounds)

    def test_wrong_envelope_keys_rejected(self):
        envelope = parse(self.certificate)
        del envelope["signature"]
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(compact(envelope), self.rounds)

    def test_wrong_payload_keys_rejected(self):
        envelope = parse(self.certificate)
        del envelope["payload"]["status"]
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(compact(envelope), self.rounds)
        envelope = parse(self.certificate)
        envelope["payload"]["extra"] = 1
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(compact(envelope), self.rounds)

    def test_illegal_status_rejected(self):
        envelope = parse(self.certificate)
        envelope["payload"]["status"] = "weird"
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(compact(envelope), self.rounds)

    def test_unknown_version_rejected(self):
        envelope = parse(self.certificate)
        envelope["payload"]["version"] = 2
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(compact(envelope), self.rounds)

    def test_bool_inside_payload_is_a_type_fault(self):
        envelope = parse(self.certificate)
        envelope["payload"]["version"] = True
        with self.assertRaises(TypeError):
            self.verify(compact(envelope), self.rounds)

    def test_noncanonical_encoding_rejected(self):
        text = self.certificate.decode("utf-8").replace(":", ": ", 1)
        with self.assertRaises(InvalidForkConvergenceError):
            self.verify(text.encode("utf-8"), self.rounds)


class CredentialTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        self.rounds = self.chain_rounds([[self.c1]])
        self.certificate = self.certify(self.rounds)

    def _ring(self, **coord_overrides):
        mapping = {
            "not_before": "notBefore",
            "not_after": "notAfter",
            "revoked": "revoked",
        }
        entry = dict(key_entry(SECRET_COORD))
        for key, value in coord_overrides.items():
            entry[mapping[key]] = value
        ring = {node: list(entries) for node, entries in RING.items()}
        ring[COORD] = [entry]
        return ring

    def test_unknown_certifier_raises_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.certify(self.rounds, issuer="nobody")

    def test_revoked_certifier_raises_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.certify(self.rounds, ring=self._ring(revoked=True))

    def test_expired_certifier_raises_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.certify(self.rounds, ring=self._ring(not_after=200))

    def test_not_yet_valid_certifier_raises_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.certify(self.rounds, ring=self._ring(not_before=300))

    def test_later_revocation_makes_verification_unauthenticated(self):
        with self.assertRaises(AuthenticationError):
            self.verify(
                self.certificate, self.rounds,
                ring=self._ring(revoked=True),
            )

    def test_later_expiry_makes_verification_unauthenticated(self):
        with self.assertRaises(AuthenticationError):
            self.verify(
                self.certificate, self.rounds,
                ring=self._ring(not_after=265),
            )

    def test_wrong_signature_raises_authentication_error(self):
        envelope = parse(self.certificate)
        signed = {
            "payload": envelope["payload"],
            "signature": sign_bytes(envelope["payload"], SECRET_OTHER),
        }
        with self.assertRaises(AuthenticationError):
            self.verify(compact(signed), self.rounds)

    def test_empty_issuer_and_non_positive_version(self):
        with self.assertRaises(ValueError):
            self.certify(self.rounds, issuer="")
        with self.assertRaises(ValueError):
            self.certify(self.rounds, version=0)
        with self.assertRaises(TypeError):
            self.certify(self.rounds, issuer=7)
        with self.assertRaises(TypeError):
            self.certify(self.rounds, version=True)


class PublicArgumentTypeTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        self.rounds = self.chain_rounds([[self.c1]])

    def test_decision_must_be_bytes(self):
        with self.assertRaises(TypeError):
            certify_fork_convergence(
                self.rounds, "decision", self.pol, RING, CERTIFIED_AT,
                COORD, 1,
            )
        with self.assertRaises(TypeError):
            verify_fork_convergence(
                self.certify(self.rounds), self.rounds, "decision",
                self.pol, RING, VERIFY_MOMENT,
            )

    def test_moment_rules(self):
        with self.assertRaises(TypeError):
            self.certify(self.rounds, moment=True)
        with self.assertRaises(TypeError):
            self.certify(self.rounds, moment="10")
        with self.assertRaises(ValueError):
            self.certify(self.rounds, moment=-1)

    def test_round_cannot_be_certified_before_its_confirmation(self):
        # The packet's aggregatedAt (240) must not be later than the
        # certification moment.
        with self.assertRaises(InvalidForkExecutionError):
            self.certify(self.rounds, moment=230)


class InputImmutabilityTest(ConvergenceFixtures, unittest.TestCase):
    def test_inputs_are_not_modified_and_results_are_independent(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA, result="failed"),
        ], aggregated_at=240)
        c2 = self.confirm([
            self.execution_receipt(GAMMA, moment=225, post_digest="d1" * 32),
        ], aggregated_at=250)
        rounds = self.chain_rounds([[c1], [c2]])
        snapshot = copy.deepcopy((rounds, self.decision, self.pol, RING))
        certificate = self.certify(copy.deepcopy(rounds))
        first = self.verify(certificate, copy.deepcopy(rounds))
        second = self.verify(certificate, copy.deepcopy(rounds))
        self.assertEqual((rounds, self.decision, self.pol, RING), snapshot)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["results"], second["results"])
        self.assertIsNot(first["rounds"], second["rounds"])
        first["results"][0]["result"] = "tampered"
        self.assertEqual(second["results"][0]["result"], "executed")


class BatchValidationTest(ConvergenceFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        self.rounds = self.chain_rounds([[self.c1]])
        self.certificate = self.certify(self.rounds)

    def _item(self, item_id="a", certificate=None, rounds=None):
        return {
            "id": item_id,
            "certificate": self.certificate if certificate is None
            else certificate,
            "rounds": self.rounds if rounds is None else rounds,
        }

    def test_empty_batch_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_fork_convergences(
                [], self.decision, self.pol, RING, VERIFY_MOMENT
            )

    def test_batch_must_be_a_list_of_dicts(self):
        with self.assertRaises(TypeError):
            verify_fork_convergences(
                ("x",), self.decision, self.pol, RING, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_fork_convergences(
                ["x"], self.decision, self.pol, RING, VERIFY_MOMENT
            )

    def test_wrong_item_key_set_raises_value_error(self):
        item = self._item()
        del item["rounds"]
        with self.assertRaises(ValueError):
            verify_fork_convergences(
                [item], self.decision, self.pol, RING, VERIFY_MOMENT
            )

    def test_empty_or_duplicate_id_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_fork_convergences(
                [self._item(item_id="")], self.decision, self.pol, RING,
                VERIFY_MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_fork_convergences(
                [self._item(item_id="a"), self._item(item_id="a")],
                self.decision, self.pol, RING, VERIFY_MOMENT,
            )

    def test_id_and_certificate_types(self):
        with self.assertRaises(TypeError):
            verify_fork_convergences(
                [self._item(certificate="x")], self.decision, self.pol,
                RING, VERIFY_MOMENT,
            )
        with self.assertRaises(TypeError):
            verify_fork_convergences(
                [{**self._item(), "id": 9}], self.decision, self.pol,
                RING, VERIFY_MOMENT,
            )

    def test_empty_rounds_in_an_item_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_fork_convergences(
                [self._item(rounds=[])], self.decision, self.pol, RING,
                VERIFY_MOMENT,
            )

    def test_shared_moment_rules(self):
        with self.assertRaises(TypeError):
            verify_fork_convergences(
                [self._item()], self.decision, self.pol, RING, True
            )
        with self.assertRaises(ValueError):
            verify_fork_convergences(
                [self._item()], self.decision, self.pol, RING, -1
            )

    def test_shared_decision_must_be_bytes(self):
        with self.assertRaises(TypeError):
            verify_fork_convergences(
                [self._item()], "decision", self.pol, RING, VERIFY_MOMENT
            )


class BatchIsolationTest(ConvergenceFixtures, unittest.TestCase):
    def test_verified_invalid_and_unauthenticated_in_input_order(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        rounds = self.chain_rounds([[c1]])
        certificate = self.certify(rounds)
        revoked_ring = {
            node: [
                dict(entry, revoked=(node == COORD)) for entry in entries
            ]
            for node, entries in RING.items()
        }
        items = [
            {"id": "ok", "certificate": certificate, "rounds": rounds},
            {"id": "bad-cert", "certificate": b"{nope", "rounds": rounds},
            {"id": "revoked", "certificate": certificate,
             "rounds": rounds},
            {"id": "ok-2", "certificate": certificate, "rounds": rounds},
        ]
        # The revoked item only differs by the shared ring, so run it in a
        # second batch of its own to keep the shared ring consistent.
        result = verify_fork_convergences(
            [items[0], items[1], items[3]],
            self.decision, self.pol, RING, VERIFY_MOMENT,
        )
        self.assertEqual(
            [item["status"] for item in result["items"]],
            ["verified", "invalid", "verified"],
        )
        revoked_result = verify_fork_convergences(
            [items[2]], self.decision, self.pol, revoked_ring, VERIFY_MOMENT,
        )
        self.assertEqual(
            revoked_result["items"][0]["status"], "unauthenticated"
        )

    def test_failed_items_keep_error_and_null_result(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        rounds = self.chain_rounds([[c1]])
        certificate = self.certify(rounds)
        bad_rounds = [{
            "round": 1,
            "previousSummary": None,
            "confirmations": [b"{bad"],
        }]
        result = verify_fork_convergences(
            [
                {"id": "ok", "certificate": certificate, "rounds": rounds},
                {"id": "broken", "certificate": certificate,
                 "rounds": bad_rounds},
            ],
            self.decision, self.pol, RING, VERIFY_MOMENT,
        )
        self.assertEqual(result["version"], 1)
        for item in result["items"]:
            self.assertEqual(
                list(item.keys()), ["error", "id", "result", "status"]
            )
        ok, broken = result["items"]
        self.assertIsNone(ok["error"])
        self.assertIsNotNone(ok["result"])
        self.assertIsNone(broken["result"])
        self.assertIsInstance(broken["error"], str)
        self.assertTrue(broken["error"])

    def test_unauthenticated_payload_identity_never_enters_result(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        rounds = self.chain_rounds([[c1]])
        certificate = self.certify(rounds)
        unknown_ring = {
            node: list(entries)
            for node, entries in RING.items() if node != COORD
        }
        result = verify_fork_convergences(
            [{"id": "x", "certificate": certificate, "rounds": rounds}],
            self.decision, self.pol, unknown_ring, VERIFY_MOMENT,
        )
        item = result["items"][0]
        self.assertEqual(item["status"], "unauthenticated")
        self.assertIsNone(item["result"])
        self.assertIsInstance(item["error"], str)

    def test_repeated_calls_are_equal_and_independent(self):
        c1 = self.confirm([
            self.execution_receipt(BETA),
            self.execution_receipt(GAMMA),
        ])
        rounds = self.chain_rounds([[c1]])
        items = [{"id": "a", "certificate": self.certify(rounds),
                  "rounds": rounds}]
        first = verify_fork_convergences(
            items, self.decision, self.pol, RING, VERIFY_MOMENT
        )
        second = verify_fork_convergences(
            copy.deepcopy(items), self.decision, self.pol, RING,
            VERIFY_MOMENT,
        )
        self.assertEqual(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(
            first["items"][0]["result"], second["items"][0]["result"]
        )


if __name__ == "__main__":
    unittest.main()
