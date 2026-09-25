"""Tests for offline fork execution planning and multi-site confirmation.

Covers :func:`plan_fork_execution`, :func:`confirm_fork_execution`,
:func:`verify_fork_confirmation` and :func:`verify_fork_confirmations`:
accepted-verdict planning with idempotent per-target operations and
their preconditions, the per-receipt tally (fixed rejection reasons,
duplicates, contradictions, invalid and unauthenticated receipts), the
confirmed/rejected/partial/conflicted aggregation, the canonical signed
packet and every bound field, offline reconciliation and credential
rules, and the batch wrapper's upfront validation, per-item isolation,
input-order reports and fresh results.
"""

import copy
import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    AuthenticationError,
    InvalidForkDecisionError,
    InvalidForkExecutionError,
    confirm_fork_execution,
    decide_forks,
    plan_fork_execution,
    sign_receipt_fork_proof,
    verify_fork_confirmation,
    verify_fork_confirmations,
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

SIGN_MOMENT = 150
DECIDE_MOMENT = 200
GENERATED_AT = 210
EXPIRES_AT = 300
AGGREGATED_AT = 250
VERIFY_MOMENT = 260


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


class ExecutionFixtures:
    """Mixin building a fresh accepted decision, plan and helpers."""

    action = "isolate"

    def setUp(self):  # noqa: D102
        self.pol = policy(action=self.action)
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
                          post_digest="c0" * 32, *, site=None, key_version=1,
                          site_version="sv-1", operation_id=None,
                          plan_digest=None, previous=None,
                          sign_secret=None, drop_post=False):
        operation = self.operations[target]
        payload = {
            "planDigest": plan_digest or self.plan_digest,
            "operationId": operation_id or operation["operationId"],
            "site": site or target,
            "keyVersion": key_version,
            "siteVersion": site_version,
            "executionMoment": moment,
            "previous": previous or self.previous(operation),
            "result": result,
        }
        if not drop_post:
            payload["postDigest"] = (
                post_digest if result == "executed" else None
            )
        signer = site or target
        secret = sign_secret if sign_secret is not None else SECRETS[signer]
        return rewrap(payload, secret)

    def executed_pair(self, post_beta="e1" * 32, post_gamma="e2" * 32):
        return [
            self.execution_receipt(BETA, post_digest=post_beta, moment=220),
            self.execution_receipt(GAMMA, post_digest=post_gamma, moment=225),
        ]

    def confirm(self, receipts, ring=None, moment=AGGREGATED_AT):
        return confirm_fork_execution(
            self.plan, self.decision, self.pol, receipts,
            ring or RING, moment, COORD, 1
        )

    def verify(self, confirmation, ring=None, moment=VERIFY_MOMENT):
        return verify_fork_confirmation(
            confirmation, self.decision, self.pol, ring or RING, moment
        )


class PlanShapeTest(ExecutionFixtures, unittest.TestCase):
    def test_plan_is_canonical_compact_bytes_without_trailing_byte(self):
        self.assertIsInstance(self.plan, bytes)
        self.assertTrue(self.plan.endswith(b"}"))
        self.assertNotIn(b"\n", self.plan)
        self.assertEqual(compact(self.plan_obj), self.plan)

    def test_plan_top_level_key_set(self):
        self.assertEqual(
            set(self.plan_obj.keys()),
            {"action", "boundaries", "decisionDigest", "expiresAt",
             "generatedAt", "operations", "policyDigest", "version"},
        )
        self.assertEqual(self.plan_obj["version"], 1)
        self.assertNotIsInstance(self.plan_obj["version"], bool)

    def test_plan_binds_decision_and_policy_digests(self):
        self.assertEqual(
            self.plan_obj["decisionDigest"],
            hashlib.sha256(self.decision).hexdigest(),
        )
        canonical_policy = {
            "action": "isolate",
            "base": {"batch": "batch-1", "sites": {"a": [1]},
                     "threshold": 1},
            "sites": {ALPHA: [1], BETA: [1], GAMMA: [1], DELTA: [1]},
            "threshold": 2,
        }
        self.assertEqual(
            self.plan_obj["policyDigest"],
            hashlib.sha256(compact(canonical_policy)).hexdigest(),
        )

    def test_plan_copies_no_unadopted_proof_material(self):
        text = self.plan.decode("utf-8")
        self.assertNotIn('"proofs"', text)
        self.assertNotIn('"decisions"', text)
        self.assertNotIn('"issuer"', text)

    def test_window_is_bound(self):
        self.assertEqual(self.plan_obj["generatedAt"], GENERATED_AT)
        self.assertEqual(self.plan_obj["expiresAt"], EXPIRES_AT)

    def test_one_operation_per_ascending_target(self):
        targets = [op["target"] for op in self.plan_obj["operations"]]
        self.assertEqual(targets, [BETA, GAMMA])
        self.assertEqual(targets, sorted(set(targets)))

    def test_all_boundaries_are_bound(self):
        decision_boundaries = parse(self.decision)["payload"]["boundaries"]
        self.assertEqual(self.plan_obj["boundaries"], decision_boundaries)
        for operation in self.plan_obj["operations"]:
            for boundary in operation["boundaries"]:
                self.assertIn(boundary, self.plan_obj["boundaries"])
                self.assertEqual(boundary["target"], operation["target"])

    def test_operation_key_set_and_isolate_precondition(self):
        for operation in self.plan_obj["operations"]:
            self.assertEqual(
                set(operation.keys()),
                {"action", "boundaries", "operationId", "requires", "target"},
            )
            self.assertEqual(operation["action"], "isolate")
            self.assertEqual(operation["requires"], {"state": "active"})

    def test_operation_id_is_the_specified_sha256(self):
        for operation in self.plan_obj["operations"]:
            hasher = hashlib.sha256()
            hasher.update(self.plan_obj["decisionDigest"].encode("ascii"))
            hasher.update(b"isolate")
            hasher.update(operation["target"].encode("utf-8"))
            for boundary in operation["boundaries"]:
                hasher.update(compact({
                    "receiptDigest": boundary["receiptDigest"],
                    "target": boundary["target"],
                    "upstream": boundary["upstream"],
                }))
            self.assertEqual(operation["operationId"], hasher.hexdigest())

    def test_operation_ids_are_idempotent_and_distinct(self):
        again = plan_fork_execution(
            self.decision, self.pol, RING, GENERATED_AT, EXPIRES_AT
        )
        self.assertEqual(
            [op["operationId"] for op in parse(again)["operations"]],
            [op["operationId"] for op in self.plan_obj["operations"]],
        )
        ids = [op["operationId"] for op in self.plan_obj["operations"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_inputs_are_not_modified(self):
        snapshot = copy.deepcopy((self.decision, self.pol, RING))
        plan_fork_execution(
            self.decision, self.pol, RING, GENERATED_AT, EXPIRES_AT
        )
        self.assertEqual((self.decision, self.pol, RING), snapshot)


class RollbackPlanTest(ExecutionFixtures, unittest.TestCase):
    action = "rollback"

    def test_rollback_preconditions_bind_base_and_upstream(self):
        for operation in self.plan_obj["operations"]:
            self.assertEqual(operation["action"], "rollback")
            boundary = operation["boundaries"][0]
            self.assertEqual(
                operation["requires"],
                {"base": boundary["receiptDigest"],
                 "upstream": boundary["upstream"]},
            )
            self.assertEqual(
                set(operation["requires"].keys()), {"base", "upstream"}
            )

    def test_confirmed_rollback_roundtrip(self):
        receipts = self.executed_pair()
        confirmation = self.confirm(receipts)
        result = self.verify(confirmation)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(
            [row["result"] for row in result["results"]],
            ["executed", "executed"],
        )


class PlanValidationTest(unittest.TestCase):
    def setUp(self):
        self.pol = policy()
        self.decision = decide(self.pol)

    def plan(self, decision=None, pol=None, ring=RING,
             generated=GENERATED_AT, expires=EXPIRES_AT):
        return plan_fork_execution(
            decision if decision is not None else self.decision,
            pol or self.pol, ring, generated, expires
        )

    def test_non_accepted_verdict_raises_value_error(self):
        insufficient = decide(policy(threshold=3))
        conflicted = decide(policy(threshold=2), [
            {"id": "x", "proof": fork_proof(ALPHA, first=ALPHA)},
            {"id": "y", "proof": fork_proof(BETA, first=DELTA)},
        ])
        for verdict in (insufficient, conflicted):
            with self.assertRaises(ValueError):
                self.plan(verdict)
            with self.assertRaises(ValueError):
                plan_fork_execution(
                    verdict, policy(), RING, GENERATED_AT, EXPIRES_AT
                )

    def test_argument_type_faults(self):
        with self.assertRaises(TypeError):
            self.plan(decision="x")
        with self.assertRaises(TypeError):
            plan_fork_execution(self.decision, self.pol, RING, True, 300)
        with self.assertRaises(TypeError):
            plan_fork_execution(self.decision, self.pol, RING, 210, True)
        with self.assertRaises(TypeError):
            plan_fork_execution(self.decision, "x", RING, 210, 300)
        with self.assertRaises(TypeError):
            plan_fork_execution(self.decision, self.pol, "x", 210, 300)

    def test_illegal_windows(self):
        with self.assertRaises(ValueError):
            self.plan(generated=-1)
        with self.assertRaises(ValueError):
            self.plan(generated=301, expires=300)

    def test_generation_moment_uses_current_keyring(self):
        future_ring = {
            **RING, COORD: [entry(1, SECRET_COORD, not_before=250)]
        }
        with self.assertRaises(AuthenticationError):
            self.plan(ring=future_ring, generated=210)

    def test_decision_for_another_policy_is_invalid(self):
        other_pol = policy(base=BASE_OTHER,
                           sites={ALPHA: {1}, BETA: {1}})
        with self.assertRaises((InvalidForkDecisionError, ValueError)):
            self.plan(pol=other_pol)

    def test_plan_is_deterministic(self):
        first = self.plan()
        second = self.plan()
        self.assertEqual(first, second)


class TallySuccessTest(ExecutionFixtures, unittest.TestCase):
    def test_all_executed_confirms(self):
        confirmation = self.confirm(self.executed_pair())
        payload = parse(confirmation)["payload"]
        self.assertEqual(payload["status"], "confirmed")
        result = self.verify(confirmation)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(
            [(r["target"], r["result"]) for r in result["results"]],
            [(BETA, "executed"), (GAMMA, "executed")],
        )

    def test_repeated_execution_with_same_outcome_stays_confirmed(self):
        receipts = [
            self.execution_receipt(BETA, moment=220, post_digest="e1" * 32),
            self.execution_receipt(BETA, moment=240, post_digest="e1" * 32),
            self.execution_receipt(GAMMA, moment=225, post_digest="e2" * 32),
        ]
        payload = parse(self.confirm(receipts))["payload"]
        self.assertEqual(payload["status"], "confirmed")

    def test_same_digest_counts_once_and_is_duplicate(self):
        first = self.execution_receipt(BETA)
        receipts = [first, first, self.execution_receipt(GAMMA)]
        payload = parse(self.confirm(receipts))["payload"]
        reasons = [(row["result"], row["reason"]) for row in payload["reasons"]]
        self.assertEqual(reasons[0], ("executed", None))
        self.assertEqual(reasons[1], ("executed", "duplicate"))
        self.assertEqual(reasons[2], ("executed", None))
        self.assertEqual(payload["status"], "confirmed")
        result = self.verify(self.confirm(receipts))
        self.assertEqual([row["reason"] for row in result["reasons"]],
                         [None, "duplicate", None])

    def test_receipts_keep_their_original_order(self):
        pair = self.executed_pair()
        payload = parse(self.confirm(list(reversed(pair))))["payload"]
        self.assertEqual(
            payload["receipts"],
            [hashlib.sha256(raw).hexdigest() for raw in reversed(pair)],
        )


class TallyRejectionTest(ExecutionFixtures, unittest.TestCase):
    def tally(self, receipts, ring=None):
        return parse(self.confirm(receipts, ring=ring))["payload"]

    def test_explicit_site_rejection_gives_rejected(self):
        payload = self.tally([
            self.execution_receipt(BETA, result="rejected"),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["status"], "rejected")
        self.assertEqual(payload["reasons"][0]["reason"], None)
        self.assertEqual(
            [r["result"] for r in payload["results"]],
            ["rejected", "executed"],
        )

    def test_failed_result_gives_partial(self):
        payload = self.tally([
            self.execution_receipt(BETA, result="failed"),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["status"], "partial")
        self.assertEqual(
            [r["result"] for r in payload["results"]],
            ["failed", "executed"],
        )

    def test_missing_operation_gives_partial(self):
        payload = self.tally([self.execution_receipt(BETA)])
        self.assertEqual(payload["status"], "partial")
        self.assertEqual(
            [r["result"] for r in payload["results"]],
            ["executed", "failed"],
        )

    def test_rejection_beats_missing(self):
        payload = self.tally([
            self.execution_receipt(BETA, result="rejected"),
        ])
        self.assertEqual(payload["status"], "rejected")

    def test_different_results_contradict(self):
        payload = self.tally([
            self.execution_receipt(BETA, moment=220, result="executed"),
            self.execution_receipt(BETA, moment=230, result="rejected"),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["status"], "conflicted")
        beta_reasons = [
            row["reason"] for row in payload["reasons"]
            if row["site"] == BETA
        ]
        self.assertEqual(beta_reasons, ["contradiction", "contradiction"])
        self.assertEqual(
            next(r["result"] for r in payload["results"]
                 if r["target"] == BETA),
            "failed",
        )

    def test_different_post_digests_contradict(self):
        payload = self.tally([
            self.execution_receipt(BETA, moment=220, post_digest="e1" * 32),
            self.execution_receipt(BETA, moment=230, post_digest="e9" * 32),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["status"], "conflicted")

    def test_contradiction_beats_rejection(self):
        payload = self.tally([
            self.execution_receipt(BETA, moment=220, result="executed"),
            self.execution_receipt(BETA, moment=230, result="rejected"),
            self.execution_receipt(GAMMA, result="rejected"),
        ])
        self.assertEqual(payload["status"], "conflicted")

    def test_decision_replaced(self):
        payload = self.tally([
            self.execution_receipt(BETA, plan_digest="ab" * 32),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["reasons"][0]["reason"],
                         "decision-replaced")
        self.assertEqual(payload["status"], "partial")

    def test_unknown_operation_id(self):
        payload = self.tally([
            self.execution_receipt(BETA, operation_id="ff" * 32),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["reasons"][0]["reason"],
                         "unknown-operation")

    def test_site_must_equal_operation_target(self):
        payload = self.tally([
            # GAMMA's key signs a receipt for BETA's operation.
            self.execution_receipt(BETA, site=GAMMA,
                                   sign_secret=SECRET_GAMMA),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["reasons"][0]["reason"],
                         "unknown-operation")

    def test_outside_validity_window(self):
        payload = self.tally([
            self.execution_receipt(BETA, moment=GENERATED_AT - 1),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["reasons"][0]["reason"],
                         "outside-validity")
        payload = self.tally([
            self.execution_receipt(BETA, moment=EXPIRES_AT + 1),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["reasons"][0]["reason"],
                         "outside-validity")

    def test_previous_digest_mismatch(self):
        payload = self.tally([
            self.execution_receipt(BETA, previous="00" * 32),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["reasons"][0]["reason"],
                         "previous-mismatch")

    def test_same_site_out_of_order(self):
        payload = self.tally([
            self.execution_receipt(BETA, moment=230, post_digest="e1" * 32),
            self.execution_receipt(BETA, moment=220, post_digest="e9" * 32),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(
            [row["reason"] for row in payload["reasons"]],
            [None, "out-of-order", None],
        )

    def test_distinct_sites_share_no_sequence(self):
        payload = self.tally([
            self.execution_receipt(GAMMA, moment=225),
            self.execution_receipt(BETA, moment=220),
        ])
        self.assertEqual(payload["status"], "confirmed")
        self.assertTrue(all(row["reason"] is None
                            for row in payload["reasons"]))

    def test_structurally_invalid_receipt_is_invalid_receipt_alone(self):
        payload = self.tally([b"not-json", self.execution_receipt(GAMMA)])
        row = payload["reasons"][0]
        self.assertEqual(row["reason"], "invalid-receipt")
        self.assertIsNone(row["site"])
        self.assertIsNone(row["operationId"])
        self.assertEqual(row["result"], "failed")
        self.assertIsNone(row["postDigest"])
        self.assertEqual(payload["reasons"][1]["reason"], None)
        self.assertEqual(payload["status"], "partial")

    def test_non_executed_receipt_with_post_digest_is_invalid(self):
        raw = self.execution_receipt(BETA, result="rejected")
        obj = parse(raw)
        obj["payload"]["postDigest"] = "dd" * 32
        raw = rewrap(obj["payload"], SECRET_BETA)
        payload = self.tally([raw, self.execution_receipt(GAMMA)])
        self.assertEqual(payload["reasons"][0]["reason"],
                         "invalid-receipt")

    def test_unknown_site_is_unknown_operation(self):
        # A receipt whose signing site is not the operation target cannot
        # act on it; the key selection is never reached.
        payload = self.tally([
            self.execution_receipt(BETA, site="nobody",
                                   sign_secret=SECRET_OTHER),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(payload["reasons"][0]["reason"],
                         "unknown-operation")

    def test_wrong_secret_for_a_known_site_is_bad_signature(self):
        # Correct target site and version, wrong HMAC secret.
        raw = self.execution_receipt(BETA, sign_secret=SECRET_OTHER)
        payload = self.tally([raw, self.execution_receipt(GAMMA)])
        self.assertEqual(payload["reasons"][0]["reason"], "bad-signature")

    def test_wrong_key_version_rejects_only_the_item(self):
        # The receipt claims version 2 but signs with a v1 secret.
        raw = self.execution_receipt(BETA, key_version=2)
        payload = self.tally([raw, self.execution_receipt(GAMMA)])
        self.assertEqual(payload["reasons"][0]["reason"], "bad-signature")

    def test_bad_signature_rejects_only_the_item(self):
        raw = self.execution_receipt(BETA, sign_secret=SECRET_OTHER)
        payload = self.tally([raw, self.execution_receipt(GAMMA)])
        self.assertEqual(payload["reasons"][0]["reason"], "bad-signature")

    def test_revoked_execution_key_rejects_only_the_item(self):
        ring = {**RING, BETA: [entry(1, SECRET_BETA, revoked=True)]}
        payload = self.tally(self.executed_pair(), ring=ring)
        self.assertEqual(payload["reasons"][0]["reason"], "bad-signature")
        self.assertEqual(payload["status"], "partial")

    def test_key_not_yet_valid_at_execution_rejects_the_item(self):
        ring = {**RING, BETA: [entry(1, SECRET_BETA, not_before=222)]}
        payload = self.tally(self.executed_pair(), ring=ring)
        self.assertEqual(payload["reasons"][0]["reason"], "bad-signature")

    def test_key_expired_at_execution_rejects_the_item(self):
        ring = {**RING, BETA: [entry(1, SECRET_BETA, not_after=219)]}
        payload = self.tally(self.executed_pair(), ring=ring)
        self.assertEqual(payload["reasons"][0]["reason"], "bad-signature")

    def test_key_revoked_between_execution_and_aggregation_rejects(self):
        # The key is valid at 220 but revoked for the aggregation at 250:
        # a revoked entry is unusable at both moments.
        ring = {**RING, BETA: [entry(1, SECRET_BETA, revoked=True)]}
        payload = self.tally(self.executed_pair(), ring=ring)
        self.assertEqual(payload["reasons"][0]["reason"], "bad-signature")

    def test_one_bad_receipt_never_stops_the_others(self):
        payload = self.tally([
            b"{}",
            self.execution_receipt(BETA, result="rejected"),
            self.execution_receipt(GAMMA),
        ])
        self.assertEqual(len(payload["reasons"]), 3)
        self.assertEqual(payload["reasons"][2]["reason"], None)


class ConfirmationPacketTest(ExecutionFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.confirm(self.executed_pair())
        self.data = parse(self.raw)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertTrue(self.raw.endswith(b"}"))
        self.assertNotIn(b"\n", self.raw)
        self.assertEqual(compact(self.data), self.raw)

    def test_top_and_payload_key_sets(self):
        self.assertEqual(set(self.data.keys()), {"payload", "signature"})
        self.assertEqual(
            set(self.data["payload"].keys()),
            {"aggregatedAt", "issuer", "keyVersion", "plan", "receipts",
             "reasons", "results", "status", "version"},
        )

    def test_identity_and_window_bindings(self):
        payload = self.data["payload"]
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["aggregatedAt"], AGGREGATED_AT)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["plan"], self.plan_obj)

    def test_results_follow_plan_operations(self):
        payload = self.data["payload"]
        self.assertEqual(
            [r["target"] for r in payload["results"]], [BETA, GAMMA]
        )
        for row in payload["results"]:
            self.assertEqual(
                set(row.keys()), {"operationId", "result", "target"}
            )

    def test_reason_rows_have_the_fixed_key_set(self):
        for row in self.data["payload"]["reasons"]:
            self.assertEqual(
                set(row.keys()),
                {"digest", "operationId", "postDigest", "result", "reason",
                 "site"},
            )

    def test_aggregator_credentials_have_no_fallback(self):
        pair = self.executed_pair()
        with self.assertRaises(AuthenticationError):
            confirm_fork_execution(
                self.plan, self.decision, self.pol, pair, RING,
                AGGREGATED_AT, "nobody", 1
            )
        with self.assertRaises(AuthenticationError):
            confirm_fork_execution(
                self.plan, self.decision, self.pol, pair, RING,
                AGGREGATED_AT, COORD, 2
            )
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            self.confirm(pair, ring=revoked)
        future = {**RING, COORD: [entry(1, SECRET_COORD, not_before=260)]}
        with self.assertRaises(AuthenticationError):
            self.confirm(pair, ring=future)

    def test_inputs_are_not_modified(self):
        receipts = self.executed_pair()
        snapshot = copy.deepcopy(
            (self.plan, self.decision, self.pol, receipts, RING)
        )
        self.confirm(receipts)
        self.assertEqual(
            (self.plan, self.decision, self.pol, receipts, RING), snapshot
        )


class ConfirmArgumentsTest(ExecutionFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.receipts = self.executed_pair()

    def test_type_faults(self):
        with self.assertRaises(TypeError):
            confirm_fork_execution(
                "x", self.decision, self.pol, self.receipts, RING,
                AGGREGATED_AT, COORD, 1,
            )
        with self.assertRaises(TypeError):
            confirm_fork_execution(
                self.plan, "x", self.pol, self.receipts, RING,
                AGGREGATED_AT, COORD, 1,
            )
        with self.assertRaises(InvalidForkExecutionError):
            confirm_fork_execution(
                self.plan, b"x", self.pol, self.receipts, RING,
                AGGREGATED_AT, COORD, 1,
            )
        with self.assertRaises(TypeError):
            self.confirm(["x"])
        with self.assertRaises(TypeError):
            self.confirm([self.receipts[0], "x"])
        with self.assertRaises(TypeError):
            confirm_fork_execution(
                self.plan, self.decision, self.pol, self.receipts, RING,
                True, COORD, 1,
            )
        with self.assertRaises(TypeError):
            confirm_fork_execution(
                self.plan, self.decision, self.pol, self.receipts, RING,
                AGGREGATED_AT, 7, 1,
            )
        with self.assertRaises(TypeError):
            confirm_fork_execution(
                self.plan, self.decision, self.pol, self.receipts, RING,
                AGGREGATED_AT, COORD, True,
            )

    def test_value_faults(self):
        with self.assertRaises(ValueError):
            self.confirm([])
        with self.assertRaises(ValueError):
            self.confirm([b""])
        with self.assertRaises(ValueError):
            confirm_fork_execution(
                self.plan, self.decision, self.pol, self.receipts, RING,
                -1, COORD, 1,
            )
        with self.assertRaises(ValueError):
            confirm_fork_execution(
                self.plan, self.decision, self.pol, self.receipts, RING,
                AGGREGATED_AT, "", 1,
            )
        with self.assertRaises(ValueError):
            confirm_fork_execution(
                self.plan, self.decision, self.pol, self.receipts, RING,
                AGGREGATED_AT, COORD, 0,
            )
        with self.assertRaises(ValueError):
            self.confirm(self.receipts, moment=GENERATED_AT - 1)

    def test_aggregation_after_expiry_is_allowed_but_execution_is_not(self):
        # Offline aggregation may lag past the window; the receipt
        # execution moments inside it were already rejected at tally.
        expired_pair = [
            self.execution_receipt(BETA, moment=EXPIRES_AT + 1),
            self.execution_receipt(GAMMA, moment=EXPIRES_AT + 2),
        ]
        payload = parse(
            self.confirm(expired_pair, moment=EXPIRES_AT + 10)
        )["payload"]
        self.assertTrue(
            all(row["reason"] == "outside-validity"
                for row in payload["reasons"])
        )
        self.assertEqual(payload["status"], "partial")

    def test_plan_bound_to_another_decision_is_invalid(self):
        other = decide(policy(threshold=3))
        with self.assertRaises(InvalidForkExecutionError):
            confirm_fork_execution(
                self.plan, other, self.pol, self.receipts, RING,
                AGGREGATED_AT, COORD, 1,
            )

    def test_plan_policy_mismatch_is_invalid(self):
        with self.assertRaises(InvalidForkExecutionError):
            confirm_fork_execution(
                self.plan, self.decision, policy(threshold=3), self.receipts,
                RING, AGGREGATED_AT, COORD, 1,
            )

    def test_malformed_plan_is_invalid(self):
        with self.assertRaises(InvalidForkExecutionError):
            confirm_fork_execution(
                b"{}", self.decision, self.pol, self.receipts, RING,
                AGGREGATED_AT, COORD, 1,
            )


class VerifySuccessTest(ExecutionFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.confirm(self.executed_pair())

    def test_result_is_a_fresh_fixed_key_mapping(self):
        result = self.verify(self.raw)
        self.assertEqual(
            list(result.keys()),
            ["aggregatedAt", "confirmationDigest", "decisionDigest",
             "expiresAt", "generatedAt", "issuer", "keyVersion",
             "operations", "planDigest", "policyDigest", "receipts",
             "reasons", "results", "status", "version"],
        )
        self.assertEqual(result["confirmationDigest"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["planDigest"], self.plan_digest)
        self.assertEqual(result["decisionDigest"],
                         hashlib.sha256(self.decision).hexdigest())
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["version"], 1)

    def test_repeated_calls_share_no_mutable_object(self):
        first = self.verify(self.raw)
        first["results"].append("tampered")
        first["reasons"][0]["site"] = "tampered"
        second = self.verify(self.raw)
        self.assertNotEqual(first, second)
        self.assertEqual([r["target"] for r in second["results"]],
                         [BETA, GAMMA])

    def test_receipt_digests_round_trip(self):
        pair = self.executed_pair()
        result = self.verify(self.confirm(pair))
        self.assertEqual(
            result["receipts"],
            [hashlib.sha256(raw).hexdigest() for raw in pair],
        )

    def test_non_ascii_is_preserved(self):
        unicode_base = {"batch": "bätch-1", "sites": {"a": {1}},
                        "threshold": 1}
        upol = policy(base=unicode_base,
                      sites={ALPHA: {1}, BETA: {1}})
        receipt = make_receipt(unicode_base)
        proofs = [
            {"id": "x", "proof": sign_receipt_fork_proof(
                fork_chain_items(ALPHA, receipt=receipt), unicode_base, RING,
                SIGN_MOMENT, ALPHA, 1)},
            {"id": "y", "proof": sign_receipt_fork_proof(
                fork_chain_items(ALPHA, receipt=receipt), unicode_base, RING,
                SIGN_MOMENT, BETA, 1)},
        ]
        udecision = decide_forks(
            proofs, upol, RING, DECIDE_MOMENT, COORD, 1
        )
        uplan = plan_fork_execution(
            udecision, upol, RING, GENERATED_AT, EXPIRES_AT
        )
        uobj = parse(uplan)
        uops = {op["target"]: op for op in uobj["operations"]}

        def ureceipt(target, moment, post):
            prev = hashlib.sha256(compact(uops[target]["requires"])).hexdigest()
            payload = {
                "planDigest": hashlib.sha256(uplan).hexdigest(),
                "operationId": uops[target]["operationId"],
                "site": target, "keyVersion": 1, "siteVersion": "sv",
                "executionMoment": moment, "previous": prev,
                "result": "executed", "postDigest": post,
            }
            return rewrap(payload, SECRETS[target])

        raw = confirm_fork_execution(
            uplan, udecision, upol,
            [ureceipt(BETA, 220, "e1" * 32), ureceipt(GAMMA, 225, "e2" * 32)],
            RING, AGGREGATED_AT, COORD, 1,
        )
        self.assertNotIn(b"\\u", raw)
        result = verify_fork_confirmation(
            raw, udecision, upol, RING, VERIFY_MOMENT
        )
        self.assertEqual(result["status"], "confirmed")


class VerifyStructureTest(ExecutionFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.confirm(self.executed_pair())

    def payload(self):
        return parse(self.raw)["payload"]

    def assert_invalid(self, raw):
        with self.assertRaises(InvalidForkExecutionError):
            self.verify(raw)

    def test_public_argument_types(self):
        with self.assertRaises(TypeError):
            verify_fork_confirmation(
                "x", self.decision, self.pol, RING, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_fork_confirmation(
                self.raw, "x", self.pol, RING, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            self.verify(self.raw, moment=True)
        with self.assertRaises(ValueError):
            self.verify(self.raw, moment=-1)

    def test_encoding_faults(self):
        self.assert_invalid(self.raw + b"\n")
        self.assert_invalid(self.raw + b" ")
        self.assert_invalid(b"")
        self.assert_invalid(b"{")
        with self.assertRaises(TypeError):
            self.verify(b"[]")

    def test_future_aggregation_is_invalid(self):
        # Aggregated at 280 (inside the plan window) but reviewed at 260.
        future_packet = self.confirm(self.executed_pair(), moment=280)
        with self.assertRaises(InvalidForkExecutionError):
            self.verify(future_packet, moment=VERIFY_MOMENT)
        # It verifies once the review moment catches up.
        self.assertEqual(
            self.verify(future_packet, moment=290)["status"], "confirmed"
        )

    def test_key_sets(self):
        data = parse(self.raw)
        del data["signature"]
        self.assert_invalid(compact(data))
        payload = self.payload()
        del payload["results"]
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["extra"] = 1
        self.assert_invalid(rewrap(payload))

    def test_version_must_be_integer_one(self):
        payload = self.payload()
        payload["version"] = 2
        self.assert_invalid(rewrap(payload))
        payload["version"] = True
        with self.assertRaises(TypeError):
            self.verify(rewrap(payload))

    def test_field_type_faults(self):
        checks = [
            ("issuer", 7, TypeError),
            ("issuer", "", InvalidForkExecutionError),
            ("keyVersion", "1", TypeError),
            ("keyVersion", 0, InvalidForkExecutionError),
            ("aggregatedAt", True, TypeError),
            ("aggregatedAt", -1, InvalidForkExecutionError),
            ("status", 7, TypeError),
            ("status", "nope", InvalidForkExecutionError),
            ("plan", [], TypeError),
            ("receipts", {}, TypeError),
            ("reasons", {}, TypeError),
            ("results", {}, TypeError),
        ]
        for field, value, expected in checks:
            payload = self.payload()
            payload[field] = value
            with self.assertRaises(expected, msg=field):
                self.verify(rewrap(payload))

    def test_reason_row_faults(self):
        payload = self.payload()
        payload["reasons"][0]["reason"] = "nope"
        self.assert_invalid(rewrap(payload))
        payload = self.payload()
        payload["reasons"][0]["result"] = "nope"
        self.assert_invalid(rewrap(payload))

    def test_bound_plan_must_be_self_consistent(self):
        payload = self.payload()
        # Changing only the plan action while the operations stay isolate
        # breaks the plan's internal action contract.
        payload["plan"]["action"] = "rollback"
        with self.assertRaises(InvalidForkExecutionError):
            self.verify(rewrap(payload))

    def test_bound_plan_decision_digest_must_match_the_decision(self):
        other = decide(policy(threshold=3))
        with self.assertRaises(InvalidForkExecutionError):
            verify_fork_confirmation(
                self.raw, other, self.pol, RING, VERIFY_MOMENT
            )

    def test_tampered_status_is_invalid_even_if_resigned(self):
        data = parse(self.raw)
        data["payload"]["status"] = "partial"
        # Re-derivation of the aggregate status runs before the HMAC is
        # trusted, so a bare edit is a binding fault either way.
        self.assert_invalid(compact(data))
        data["signature"] = sign_bytes(data["payload"], SECRET_COORD)
        self.assert_invalid(compact(data))

    def test_tampered_reason_is_invalid(self):
        data = parse(self.raw)
        data["payload"]["reasons"][0]["site"] = DELTA
        data["signature"] = sign_bytes(data["payload"], SECRET_COORD)
        self.assert_invalid(compact(data))

    def test_reordered_receipt_digests_break_the_binding(self):
        data = parse(self.raw)
        data["payload"]["receipts"].reverse()
        data["signature"] = sign_bytes(data["payload"], SECRET_COORD)
        self.assert_invalid(compact(data))


class VerifyCredentialTest(ExecutionFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.raw = self.confirm(self.executed_pair())

    def test_revoked_aggregator_rejects_review(self):
        ring = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=ring)

    def test_expired_aggregator_rejects_review(self):
        ring = {**RING, COORD: [entry(1, SECRET_COORD, not_after=255)]}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=ring)

    def test_unknown_aggregator_rejects_review(self):
        ring = {k: v for k, v in RING.items() if k != COORD}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=ring)

    def test_wrong_aggregator_signature_rejects_review(self):
        data = parse(self.raw)
        # Flip one hex digit while keeping the 64-character format.
        data["signature"] = ("1" if data["signature"][0] == "0" else "0") \
            + data["signature"][1:]
        with self.assertRaises(AuthenticationError):
            self.verify(compact(data))

    def test_decision_must_still_verify(self):
        # Reissue the plan against a decision signed by COORD, then drop
        # COORD's key: the embedded decision can no longer authenticate.
        ring = {k: v for k, v in RING.items() if k != COORD}
        with self.assertRaises(AuthenticationError):
            self.verify(self.raw, ring=ring)


class BatchTest(ExecutionFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.good = self.confirm(self.executed_pair())

    def batch(self, items, moment=VERIFY_MOMENT):
        return verify_fork_confirmations(
            items, self.decision, self.pol, RING, moment
        )

    def test_container_type_faults(self):
        with self.assertRaises(TypeError):
            self.batch("x")
        with self.assertRaises(TypeError):
            self.batch(["x"])
        with self.assertRaises(TypeError):
            self.batch([{"id": 1, "confirmation": self.good}])
        with self.assertRaises(TypeError):
            self.batch([{"id": "x", "confirmation": "y"}])

    def test_container_value_faults(self):
        with self.assertRaises(ValueError):
            self.batch([])
        with self.assertRaises(ValueError):
            self.batch([{"id": "", "confirmation": self.good}])
        with self.assertRaises(ValueError):
            self.batch([
                {"id": "x", "confirmation": self.good},
                {"id": "x", "confirmation": self.good},
            ])
        with self.assertRaises(ValueError):
            self.batch([{"id": "x", "confirmation": self.good, "n": 1}])

    def test_shared_material_faults(self):
        with self.assertRaises(TypeError):
            verify_fork_confirmations(
                [{"id": "x", "confirmation": self.good}], "x", self.pol,
                RING, VERIFY_MOMENT,
            )
        with self.assertRaises(TypeError):
            verify_fork_confirmations(
                [{"id": "x", "confirmation": self.good}], self.decision,
                self.pol, RING, True,
            )
        with self.assertRaises(ValueError):
            verify_fork_confirmations(
                [{"id": "x", "confirmation": self.good}], self.decision,
                self.pol, RING, -1,
            )

    def test_reports_in_input_order_with_isolation(self):
        report = self.batch([
            {"id": "ok", "confirmation": self.good},
            {"id": "bad", "confirmation": b"{}"},
            {"id": "ok2", "confirmation": self.good},
        ])
        self.assertEqual([item["id"] for item in report["items"]],
                         ["ok", "bad", "ok2"])
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses, {"ok": "verified", "bad": "invalid",
                                    "ok2": "verified"})

    def test_report_key_order_and_null_result(self):
        report = self.batch([
            {"id": "bad", "confirmation": b"{}"},
        ])
        item = report["items"][0]
        self.assertEqual(list(item.keys()), ["error", "id", "result", "status"])
        self.assertIsNone(item["result"])
        self.assertTrue(item["error"])

    def test_unauthenticated_item(self):
        ring = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        report = verify_fork_confirmations(
            [{"id": "x", "confirmation": self.good}], self.decision,
            self.pol, ring, VERIFY_MOMENT,
        )
        self.assertEqual(report["items"][0]["status"], "unauthenticated")
        self.assertIsNone(report["items"][0]["result"])

    def test_one_failure_never_stops_later_packets(self):
        rejected_packet = self.confirm([
            self.execution_receipt(BETA, result="rejected"),
            self.execution_receipt(GAMMA),
        ])
        report = self.batch([
            {"id": "bad", "confirmation": b"{}"},
            {"id": "rejected", "confirmation": rejected_packet},
            {"id": "good", "confirmation": self.good},
        ])
        results = {item["id"]: item for item in report["items"]}
        self.assertEqual(results["bad"]["status"], "invalid")
        self.assertEqual(results["rejected"]["status"], "verified")
        self.assertEqual(
            results["rejected"]["result"]["status"], "rejected"
        )
        self.assertEqual(results["good"]["status"], "verified")

    def test_top_level_shape_and_version(self):
        report = self.batch([{"id": "x", "confirmation": self.good}])
        self.assertEqual(set(report.keys()), {"items", "version"})
        self.assertEqual(report["version"], 1)
        self.assertEqual(
            report["items"][0]["result"]["status"], "confirmed"
        )

    def test_repeated_calls_are_independent(self):
        items = [{"id": "x", "confirmation": self.good}]
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
