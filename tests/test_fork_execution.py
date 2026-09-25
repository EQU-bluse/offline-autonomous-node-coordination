"""Tests for the fork execution plan, confirmation and verification layer.

Covers :func:`plan_fork_execution`, :func:`confirm_fork_execution`,
:func:`verify_fork_confirmation` and :func:`verify_fork_confirmations`:
plan derivation and bindings from an accepted fork decision, the
per-receipt confirmation pipeline with its fixed reasons,
duplicate/contradiction handling, the per-operation conclusions and the
overall status, the canonical signed packet, offline re-derivation
verification, credential rules and the batch wrapper's upfront
validation, per-item isolation and input-order reports.
"""

import copy
import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    AuthenticationError,
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

SIGN_MOMENT = 150
MOMENT = 200
EXPIRES = 300
AGG_MOMENT = 250
VERIFY_MOMENT = 260


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
    receipt = receipt if receipt is not None else make_receipt()
    to_beta = [make_hop(COORD, first, receipt, moments[0])]
    to_beta.append(make_hop(first, BETA, to_beta[0], moments[1]))
    to_gamma = [make_hop(COORD, first, receipt, moments[0])]
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


POLICY = policy()


def decision(items, pol=POLICY, ring=RING, moment=MOMENT,
             issuer=COORD, version=1):
    return decide_forks(items, pol, ring, moment, issuer, version)


def proof_item(item_id, proof):
    return {"id": item_id, "proof": proof}


def accepted_decision(pol=POLICY, moment=MOMENT):
    items = [proof_item("x", fork_proof(ALPHA)),
             proof_item("y", fork_proof(BETA))]
    return decision(items, pol=pol, moment=moment)


DECISION = accepted_decision()


def plan(decision_bytes=DECISION, pol=POLICY, ring=RING,
         moment=MOMENT, expires=EXPIRES):
    return plan_fork_execution(decision_bytes, pol, ring, moment, expires)


PLAN = plan()
PLAN_PAYLOAD = json.loads(PLAN.decode("utf-8"))
PLAN_DIGEST = hashlib.sha256(PLAN).hexdigest()
DECISION_DIGEST = hashlib.sha256(DECISION).hexdigest()


def parse(raw):
    return json.loads(raw.decode("utf-8"))


def rewrap(payload, secret=SECRET_COORD):
    return compact({"payload": payload,
                    "signature": sign_bytes(payload, secret)})


def operations(plan_payload=PLAN_PAYLOAD):
    return {op["target"]: op for op in plan_payload["operations"]}


def pre_digest(operation):
    return hashlib.sha256(compact(operation["precondition"])).hexdigest()


def exec_receipt(operation, moment=210, secret=None, result="executed",
                 post=None, pre=None, plan_digest=None, site=None,
                 key_version=1):
    if result == "executed" and post is None:
        post = "ee" * 32
    payload = {
        "keyVersion": key_version,
        "moment": moment,
        "operation": operation["id"],
        "planDigest": plan_digest if plan_digest is not None else PLAN_DIGEST,
        "post": post,
        "pre": pre if pre is not None else pre_digest(operation),
        "result": result,
        "site": site if site is not None else operation["target"],
        "version": 1,
    }
    return compact(
        {"payload": payload,
         "signature": sign_bytes(payload, secret or SECRETS[payload["site"]])}
    )


def receipt_item(item_id, receipt):
    return {"id": item_id, "receipt": receipt}


def default_receipts(plan_payload=PLAN_PAYLOAD):
    ops = operations(plan_payload)
    return [
        receipt_item("r-beta", exec_receipt(ops[BETA], 210)),
        receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
    ]


def confirm(receipts, plan_bytes=PLAN, decision_bytes=DECISION, pol=POLICY,
            ring=RING, issuer=COORD, version=1, moment=AGG_MOMENT):
    return confirm_fork_execution(
        plan_bytes, decision_bytes, pol, receipts, ring, issuer, version,
        moment,
    )


def confirm_payload(receipts=None, **kwargs):
    receipts = receipts if receipts is not None else default_receipts()
    return parse(confirm(receipts, **kwargs))["payload"]


def verify(confirmation, plan_bytes=PLAN, decision_bytes=DECISION,
           pol=POLICY, receipts=None, ring=RING, moment=VERIFY_MOMENT):
    receipts = receipts if receipts is not None else default_receipts()
    return verify_fork_confirmation(
        confirmation, plan_bytes, decision_bytes, pol, receipts, ring, moment
    )


class PlanValidationTest(unittest.TestCase):
    def test_argument_type_faults(self):
        with self.assertRaises(TypeError):
            plan_fork_execution("x", POLICY, RING, MOMENT, EXPIRES)
        with self.assertRaises(TypeError):
            plan_fork_execution(DECISION, "x", RING, MOMENT, EXPIRES)
        with self.assertRaises(TypeError):
            plan_fork_execution(DECISION, POLICY, "x", MOMENT, EXPIRES)
        with self.assertRaises(TypeError):
            plan_fork_execution(DECISION, POLICY, RING, True, EXPIRES)
        with self.assertRaises(TypeError):
            plan_fork_execution(DECISION, POLICY, RING, "m", EXPIRES)
        with self.assertRaises(TypeError):
            plan_fork_execution(DECISION, POLICY, RING, MOMENT, True)
        with self.assertRaises(TypeError):
            plan_fork_execution(DECISION, POLICY, RING, MOMENT, "e")

    def test_moment_value_faults(self):
        with self.assertRaises(ValueError):
            plan_fork_execution(DECISION, POLICY, RING, -1, EXPIRES)
        with self.assertRaises(ValueError):
            plan_fork_execution(DECISION, POLICY, RING, MOMENT, -1)
        with self.assertRaises(ValueError):
            plan_fork_execution(DECISION, POLICY, RING, EXPIRES, MOMENT)

    def test_equal_moment_and_expires_is_valid(self):
        plan(DECISION, moment=MOMENT, expires=MOMENT)

    def test_non_accepted_decision_raises_value_error(self):
        insufficient = decision(
            [proof_item("x", fork_proof(ALPHA)),
             proof_item("y", fork_proof(BETA))],
            pol=policy(threshold=3),
        )
        with self.assertRaises(ValueError) as caught:
            plan(insufficient, pol=policy(threshold=3))
        self.assertNotIsInstance(caught.exception, InvalidForkExecutionError)

    def test_tampered_decision_raises(self):
        with self.assertRaises(ValueError):
            plan(DECISION[:-2] + b"00")

    def test_decision_credential_faults_raise_authentication_error(self):
        ring = keyring(coord=[entry(1, SECRET_COORD, revoked=True)])
        with self.assertRaises(AuthenticationError):
            plan(DECISION, ring=ring)


class PlanContentTest(unittest.TestCase):
    def test_plan_is_canonical_compact(self):
        self.assertEqual(PLAN, compact(PLAN_PAYLOAD))
        self.assertFalse(PLAN.endswith(b"\n"))

    def test_plan_binds_decision_and_policy(self):
        self.assertEqual(PLAN_PAYLOAD["decisionDigest"], DECISION_DIGEST)
        canonical_policy = {
            "action": "isolate",
            "base": {"batch": "batch-1", "sites": {"a": [1]}, "threshold": 1},
            "sites": {site: [1] for site in sorted((ALPHA, BETA, GAMMA, DELTA))},
            "threshold": 2,
        }
        self.assertEqual(
            PLAN_PAYLOAD["policyDigest"],
            hashlib.sha256(compact(canonical_policy)).hexdigest(),
        )
        self.assertEqual(PLAN_PAYLOAD["action"], "isolate")
        self.assertEqual(PLAN_PAYLOAD["moment"], MOMENT)
        self.assertEqual(PLAN_PAYLOAD["expires"], EXPIRES)
        self.assertEqual(PLAN_PAYLOAD["version"], 1)

    def test_plan_key_set(self):
        self.assertEqual(
            set(PLAN_PAYLOAD.keys()),
            {"action", "boundaries", "decisionDigest", "expires", "moment",
             "operations", "policyDigest", "targets", "version"},
        )
        self.assertNotIn("proofs", PLAN_PAYLOAD)
        self.assertNotIn("decisions", PLAN_PAYLOAD)

    def test_plan_targets_and_boundaries_match_decision(self):
        decision_payload = parse(DECISION)["payload"]
        self.assertEqual(PLAN_PAYLOAD["targets"], ["beta", "gamma"])
        self.assertEqual(
            PLAN_PAYLOAD["boundaries"], decision_payload["boundaries"]
        )
        self.assertEqual(PLAN_PAYLOAD["targets"], decision_payload["targets"])

    def test_one_operation_per_target_with_idempotent_id(self):
        ops = operations()
        self.assertEqual(sorted(ops), [BETA, GAMMA])
        for target, operation in ops.items():
            self.assertEqual(set(operation.keys()),
                             {"id", "precondition", "target"})
            related = [
                boundary for boundary in PLAN_PAYLOAD["boundaries"]
                if boundary["target"] == target
            ]
            expected_id = hashlib.sha256(compact({
                "action": "isolate",
                "boundaries": related,
                "decisionDigest": DECISION_DIGEST,
                "target": target,
            })).hexdigest()
            self.assertEqual(operation["id"], expected_id)
            self.assertEqual(
                operation["precondition"],
                {"kind": "target-active", "target": target},
            )

    def test_rollback_precondition_binds_receipts_and_upstreams(self):
        rollback_decision = accepted_decision(pol=policy(action="rollback"))
        rollback_plan = plan(rollback_decision, pol=policy(action="rollback"))
        payload = parse(rollback_plan)
        self.assertEqual(payload["action"], "rollback")
        decision_payload = parse(rollback_decision)["payload"]
        for operation in payload["operations"]:
            related = [
                boundary for boundary in decision_payload["boundaries"]
                if boundary["target"] == operation["target"]
            ]
            self.assertEqual(
                operation["precondition"],
                {
                    "kind": "fork-rollback",
                    "receipts": sorted({
                        boundary["receiptDigest"] for boundary in related
                    }),
                    "upstreams": sorted({
                        boundary["upstream"] for boundary in related
                    }),
                },
            )

    def test_plan_is_deterministic(self):
        self.assertEqual(plan(), PLAN)


class ConfirmValidationTest(unittest.TestCase):
    def test_argument_type_faults(self):
        receipts = default_receipts()
        with self.assertRaises(TypeError):
            confirm(receipts, plan_bytes="x")
        with self.assertRaises(TypeError):
            confirm(receipts, decision_bytes="x")
        with self.assertRaises(TypeError):
            confirm(receipts, pol="x")
        with self.assertRaises(TypeError):
            confirm("x")
        with self.assertRaises(TypeError):
            confirm(["x"])
        with self.assertRaises(TypeError):
            confirm([{"id": 1, "receipt": b"x"}])
        with self.assertRaises(TypeError):
            confirm([{"id": "x", "receipt": "y"}])
        with self.assertRaises(TypeError):
            confirm(receipts, ring="x")
        with self.assertRaises(TypeError):
            confirm(receipts, issuer=1)
        with self.assertRaises(TypeError):
            confirm(receipts, version=True)
        with self.assertRaises(TypeError):
            confirm(receipts, moment="m")

    def test_argument_value_faults(self):
        receipts = default_receipts()
        with self.assertRaises(ValueError):
            confirm([])
        with self.assertRaises(ValueError):
            confirm([receipt_item("", receipts[0]["receipt"])])
        with self.assertRaises(ValueError):
            confirm([receipts[0], receipts[0]])
        with self.assertRaises(ValueError):
            confirm([{"id": "x", "receipt": b"y", "n": 1}])
        with self.assertRaises(ValueError):
            confirm(receipts, issuer="")
        with self.assertRaises(ValueError):
            confirm(receipts, version=0)
        with self.assertRaises(ValueError):
            confirm(receipts, moment=-1)

    def test_tampered_plan_raises_invalid_fork_execution(self):
        payload = dict(PLAN_PAYLOAD)
        payload["decisionDigest"] = "00" * 32
        with self.assertRaises(InvalidForkExecutionError):
            confirm(default_receipts(), plan_bytes=compact(payload))

    def test_plan_not_canonical_raises_invalid_fork_execution(self):
        with self.assertRaises(InvalidForkExecutionError):
            confirm(default_receipts(), plan_bytes=PLAN + b"\n")

    def test_replaced_decision_raises_invalid_fork_execution(self):
        other = decision([proof_item("a", fork_proof(ALPHA)),
                          proof_item("b", fork_proof(BETA))])
        self.assertNotEqual(other, DECISION)
        with self.assertRaises(InvalidForkExecutionError):
            confirm(default_receipts(), decision_bytes=other)

    def test_non_accepted_decision_raises_invalid_fork_execution(self):
        pol = policy(threshold=3)
        insufficient = decision(
            [proof_item("x", fork_proof(ALPHA)),
             proof_item("y", fork_proof(BETA))],
            pol=pol,
        )
        with self.assertRaises(InvalidForkExecutionError):
            confirm(default_receipts(), decision_bytes=insufficient, pol=pol)

    def test_wrong_policy_raises_invalid_fork_execution(self):
        with self.assertRaises(InvalidForkExecutionError):
            confirm(default_receipts(), pol=policy(threshold=3))

    def test_signing_credential_faults_raise_authentication_error(self):
        receipts = default_receipts()
        with self.assertRaises(AuthenticationError):
            confirm(receipts, issuer="other")
        with self.assertRaises(AuthenticationError):
            confirm(receipts, version=9)
        ring = keyring(coord=[entry(1, SECRET_COORD, revoked=True)])
        with self.assertRaises(AuthenticationError):
            confirm(receipts, ring=ring)
        ring = keyring(coord=[entry(1, SECRET_COORD, not_before=300)])
        with self.assertRaises(AuthenticationError):
            confirm(receipts, ring=ring)
        ring = keyring(coord=[entry(1, SECRET_COORD, not_after=200)])
        with self.assertRaises(AuthenticationError):
            confirm(receipts, ring=ring)


class ConfirmOutcomeTest(unittest.TestCase):
    def reports_by_id(self, payload):
        return {report["id"]: report for report in payload["receipts"]}

    def test_all_executed_confirms(self):
        payload = confirm_payload()
        self.assertEqual(payload["status"], "confirmed")
        conclusions = {op["target"]: op["conclusion"]
                       for op in payload["operations"]}
        self.assertEqual(conclusions, {BETA: "confirmed", GAMMA: "confirmed"})
        for report in payload["receipts"]:
            self.assertEqual(report["conclusion"], "executed")
            self.assertIsNone(report["reason"])
            self.assertEqual(
                report["digest"],
                hashlib.sha256(
                    dict((item["id"], item["receipt"])
                         for item in default_receipts())[report["id"]]
                ).hexdigest(),
            )

    def test_missing_operation_is_partial(self):
        receipts = default_receipts()[:1]
        payload = confirm_payload(receipts)
        self.assertEqual(payload["status"], "partial")
        conclusions = {op["target"]: op["conclusion"]
                       for op in payload["operations"]}
        self.assertEqual(conclusions, {BETA: "confirmed", GAMMA: "partial"})

    def test_failed_receipt_is_partial(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta", exec_receipt(ops[BETA], 210,
                                                result="failed")),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        payload = confirm_payload(receipts)
        self.assertEqual(payload["status"], "partial")
        report = self.reports_by_id(payload)["r-beta"]
        self.assertEqual(report["conclusion"], "failed")
        self.assertIsNone(report["reason"])

    def test_explicit_rejection_is_rejected(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta", exec_receipt(ops[BETA], 210,
                                                result="rejected")),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215,
                                                 result="failed")),
        ]
        payload = confirm_payload(receipts)
        self.assertEqual(payload["status"], "rejected")
        conclusions = {op["target"]: op["conclusion"]
                       for op in payload["operations"]}
        self.assertEqual(conclusions, {BETA: "rejected", GAMMA: "partial"})

    def test_identical_digest_counts_once(self):
        ops = operations()
        receipt = exec_receipt(ops[BETA], 210)
        receipts = [
            receipt_item("r-beta-1", receipt),
            receipt_item("r-beta-2", receipt),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        payload = confirm_payload(receipts)
        self.assertEqual(payload["status"], "confirmed")
        reports = self.reports_by_id(payload)
        self.assertEqual(reports["r-beta-1"]["conclusion"], "executed")
        self.assertEqual(reports["r-beta-2"]["conclusion"], "duplicate")
        self.assertEqual(reports["r-beta-2"]["reason"], "duplicate")

    def test_same_outcome_different_bytes_counts_once(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta-1", exec_receipt(ops[BETA], 210)),
            receipt_item("r-beta-2", exec_receipt(ops[BETA], 220)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        payload = confirm_payload(receipts)
        self.assertEqual(payload["status"], "confirmed")
        reports = self.reports_by_id(payload)
        self.assertEqual(reports["r-beta-2"]["conclusion"], "duplicate")

    def test_different_post_is_contradiction(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta-1", exec_receipt(ops[BETA], 210,
                                                  post="aa" * 32)),
            receipt_item("r-beta-2", exec_receipt(ops[BETA], 220,
                                                  post="bb" * 32)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        payload = confirm_payload(receipts)
        self.assertEqual(payload["status"], "conflicted")
        reports = self.reports_by_id(payload)
        self.assertEqual(reports["r-beta-2"]["conclusion"], "contradiction")
        self.assertEqual(reports["r-beta-2"]["reason"], "contradiction")
        conclusions = {op["target"]: op["conclusion"]
                       for op in payload["operations"]}
        self.assertEqual(conclusions[BETA], "conflicted")

    def test_different_result_is_contradiction(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta-1", exec_receipt(ops[BETA], 210)),
            receipt_item("r-beta-2", exec_receipt(ops[BETA], 220,
                                                  result="failed")),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        payload = confirm_payload(receipts)
        self.assertEqual(payload["status"], "conflicted")

    def test_structurally_bad_receipt_is_invalid_receipt(self):
        receipts = [
            receipt_item("r-beta", b"not json"),
            receipt_item("r-gamma", exec_receipt(operations()[GAMMA], 215)),
        ]
        payload = confirm_payload(receipts)
        report = self.reports_by_id(payload)["r-beta"]
        self.assertEqual(report["conclusion"], "invalid-receipt")
        self.assertEqual(report["reason"], "invalid-receipt")
        self.assertEqual(payload["status"], "partial")

    def test_receipt_result_post_mismatch_is_invalid_receipt(self):
        payload = {
            "keyVersion": 1,
            "moment": 210,
            "operation": operations()[BETA]["id"],
            "planDigest": PLAN_DIGEST,
            "post": None,
            "pre": pre_digest(operations()[BETA]),
            "result": "executed",
            "site": BETA,
            "version": 1,
        }
        receipts = [
            receipt_item("r-beta", rewrap(payload, SECRET_BETA)),
            receipt_item("r-gamma", exec_receipt(operations()[GAMMA], 215)),
        ]
        report = self.reports_by_id(confirm_payload(receipts))["r-beta"]
        self.assertEqual(report["reason"], "invalid-receipt")

    def test_decision_replaced_reason(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta", exec_receipt(ops[BETA], 210,
                                                plan_digest="00" * 32)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        report = self.reports_by_id(confirm_payload(receipts))["r-beta"]
        self.assertEqual(report["reason"], "decision-replaced")

    def test_unknown_operation_reason(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta", exec_receipt(
                dict(ops[BETA], id="00" * 32), 210)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        report = self.reports_by_id(confirm_payload(receipts))["r-beta"]
        self.assertEqual(report["reason"], "unknown-operation")

    def test_outside_validity_reason(self):
        ops = operations()
        for moment in (MOMENT - 1, EXPIRES + 1, AGG_MOMENT + 1):
            receipts = [
                receipt_item("r-beta", exec_receipt(ops[BETA], moment)),
                receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
            ]
            report = self.reports_by_id(confirm_payload(receipts))["r-beta"]
            self.assertEqual(report["reason"], "outside-validity", moment)

    def test_late_aggregation_is_outside_validity(self):
        payload = confirm_payload(moment=EXPIRES + 1)
        for report in payload["receipts"]:
            self.assertEqual(report["reason"], "outside-validity")
        self.assertEqual(payload["status"], "partial")

    def test_precondition_mismatch_reason(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta", exec_receipt(ops[BETA], 210,
                                                pre="00" * 32)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        report = self.reports_by_id(confirm_payload(receipts))["r-beta"]
        self.assertEqual(report["reason"], "precondition-mismatch")

    def test_unauthorized_site_reason(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta", exec_receipt(ops[BETA], 210, site=GAMMA)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        report = self.reports_by_id(confirm_payload(receipts))["r-beta"]
        self.assertEqual(report["reason"], "unauthorized-site")

    def test_credential_reasons(self):
        ops = operations()
        cases = [
            ("credential-unavailable",
             exec_receipt(ops[BETA], 210, key_version=9),
             RING),
            ("revoked",
             exec_receipt(ops[BETA], 210),
             keyring(beta=[entry(1, SECRET_BETA, revoked=True)])),
            ("not-yet-valid",
             exec_receipt(ops[BETA], 210),
             keyring(beta=[entry(1, SECRET_BETA, not_before=220)])),
            ("expired",
             exec_receipt(ops[BETA], 210),
             keyring(beta=[entry(1, SECRET_BETA, not_after=205)])),
            ("bad-signature",
             exec_receipt(ops[BETA], 210, secret=SECRET_OTHER),
             RING),
        ]
        for reason, receipt, ring in cases:
            receipts = [
                receipt_item("r-beta", receipt),
                receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
            ]
            report = self.reports_by_id(
                confirm_payload(receipts, ring=ring)
            )["r-beta"]
            self.assertEqual(report["conclusion"], "invalid-receipt")
            self.assertEqual(report["reason"], reason)

    def test_credential_must_be_usable_at_both_moments(self):
        ops = operations()
        # Usable at the receipt moment 210 but expired by aggregation 250.
        ring = keyring(beta=[entry(1, SECRET_BETA, not_after=220)])
        receipts = [
            receipt_item("r-beta", exec_receipt(ops[BETA], 210)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        report = self.reports_by_id(
            confirm_payload(receipts, ring=ring)
        )["r-beta"]
        self.assertEqual(report["reason"], "expired")

    def test_out_of_order_reason(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta-1", exec_receipt(ops[BETA], 220)),
            receipt_item("r-beta-2", exec_receipt(ops[BETA], 210)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        payload = confirm_payload(receipts)
        report = self.reports_by_id(payload)["r-beta-2"]
        self.assertEqual(report["reason"], "out-of-order")
        self.assertEqual(payload["status"], "confirmed")

    def test_failed_item_does_not_affect_others(self):
        ops = operations()
        receipts = [
            receipt_item("r-beta", exec_receipt(ops[BETA], 210,
                                                secret=SECRET_OTHER)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        payload = confirm_payload(receipts)
        reports = self.reports_by_id(payload)
        self.assertEqual(reports["r-beta"]["reason"], "bad-signature")
        self.assertEqual(reports["r-gamma"]["conclusion"], "executed")
        conclusions = {op["target"]: op["conclusion"]
                       for op in payload["operations"]}
        self.assertEqual(conclusions, {BETA: "partial", GAMMA: "confirmed"})

    def test_receipts_reported_in_input_order(self):
        ops = operations()
        receipts = [
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
            receipt_item("r-beta", exec_receipt(ops[BETA], 210)),
        ]
        payload = confirm_payload(receipts)
        self.assertEqual(
            [report["id"] for report in payload["receipts"]],
            ["r-gamma", "r-beta"],
        )
        self.assertEqual(payload["status"], "confirmed")

    def test_rollback_plan_confirms(self):
        rollback_decision = accepted_decision(pol=policy(action="rollback"))
        rollback_plan = plan(rollback_decision, pol=policy(action="rollback"))
        rollback_payload = parse(rollback_plan)
        rollback_digest = hashlib.sha256(rollback_plan).hexdigest()
        ops = operations(rollback_payload)
        receipts = [
            receipt_item("r-beta", exec_receipt(
                ops[BETA], 210, plan_digest=rollback_digest)),
            receipt_item("r-gamma", exec_receipt(
                ops[GAMMA], 215, plan_digest=rollback_digest)),
        ]
        payload = parse(confirm(
            receipts, plan_bytes=rollback_plan,
            decision_bytes=rollback_decision, pol=policy(action="rollback"),
        ))["payload"]
        self.assertEqual(payload["status"], "confirmed")

    def test_inputs_are_not_modified(self):
        receipts = default_receipts()
        snapshot = copy.deepcopy(receipts)
        pol = copy.deepcopy(POLICY)
        ring = copy.deepcopy(RING)
        confirm(receipts)
        self.assertEqual(receipts, snapshot)
        self.assertEqual(POLICY, pol)
        self.assertEqual(RING, ring)


class ConfirmPacketTest(unittest.TestCase):
    def test_packet_is_canonical_and_signed(self):
        receipts = default_receipts()
        packet = confirm(receipts)
        data = parse(packet)
        self.assertEqual(packet, compact(data))
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        payload = data["payload"]
        self.assertEqual(
            set(payload.keys()),
            {"decisionDigest", "issuer", "keyVersion", "moment", "operations",
             "planDigest", "receipts", "status", "version"},
        )
        self.assertEqual(payload["decisionDigest"], DECISION_DIGEST)
        self.assertEqual(payload["planDigest"], PLAN_DIGEST)
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["moment"], AGG_MOMENT)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(
            data["signature"], sign_bytes(payload, SECRET_COORD)
        )

    def test_operations_in_plan_order(self):
        payload = confirm_payload()
        self.assertEqual(
            [op["target"] for op in payload["operations"]], [BETA, GAMMA]
        )
        for operation in payload["operations"]:
            self.assertEqual(set(operation.keys()),
                             {"conclusion", "operation", "target"})
            self.assertEqual(
                operation["operation"],
                operations()[operation["target"]]["id"],
            )

    def test_confirm_is_deterministic(self):
        receipts = default_receipts()
        self.assertEqual(confirm(receipts), confirm(default_receipts()))


class VerifyConfirmationTest(unittest.TestCase):
    def setUp(self):
        self.receipts = default_receipts()
        self.packet = confirm(self.receipts)

    def test_verify_round_trip(self):
        result = verify(self.packet, receipts=self.receipts)
        self.assertEqual(
            list(result.keys()),
            ["confirmationDigest", "decisionDigest", "issuer", "keyVersion",
             "moment", "operations", "planDigest", "receipts", "status",
             "version"],
        )
        self.assertEqual(
            result["confirmationDigest"],
            hashlib.sha256(self.packet).hexdigest(),
        )
        self.assertEqual(result["decisionDigest"], DECISION_DIGEST)
        self.assertEqual(result["planDigest"], PLAN_DIGEST)
        self.assertEqual(result["issuer"], COORD)
        self.assertEqual(result["keyVersion"], 1)
        self.assertEqual(result["moment"], AGG_MOMENT)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["version"], 1)
        self.assertEqual(
            result["receipts"], parse(self.packet)["payload"]["receipts"]
        )
        self.assertEqual(
            result["operations"], parse(self.packet)["payload"]["operations"]
        )

    def test_verify_type_faults(self):
        with self.assertRaises(TypeError):
            verify("x", receipts=self.receipts)
        with self.assertRaises(TypeError):
            verify(self.packet, plan_bytes=1, receipts=self.receipts)
        with self.assertRaises(TypeError):
            verify(self.packet, receipts=self.receipts, moment=True)

    def test_verify_value_faults(self):
        with self.assertRaises(ValueError):
            verify(self.packet, receipts=[])
        with self.assertRaises(ValueError):
            verify(self.packet, receipts=self.receipts, moment=-1)

    def test_tampered_status_is_invalid(self):
        payload = parse(self.packet)["payload"]
        payload["status"] = "partial"
        with self.assertRaises(InvalidForkExecutionError):
            verify(rewrap(payload), receipts=self.receipts)

    def test_tampered_report_is_invalid(self):
        payload = parse(self.packet)["payload"]
        payload["receipts"][0]["conclusion"] = "failed"
        with self.assertRaises(InvalidForkExecutionError):
            verify(rewrap(payload), receipts=self.receipts)

    def test_replaced_plan_digest_is_invalid(self):
        payload = parse(self.packet)["payload"]
        payload["planDigest"] = "00" * 32
        with self.assertRaises(InvalidForkExecutionError):
            verify(rewrap(payload), receipts=self.receipts)

    def test_replaced_receipts_are_invalid(self):
        ops = operations()
        other_receipts = [
            receipt_item("r-beta", exec_receipt(ops[BETA], 211)),
            receipt_item("r-gamma", exec_receipt(ops[GAMMA], 215)),
        ]
        with self.assertRaises(InvalidForkExecutionError):
            verify(self.packet, receipts=other_receipts)

    def test_not_canonical_is_invalid(self):
        with self.assertRaises(InvalidForkExecutionError):
            verify(self.packet + b"\n", receipts=self.receipts)

    def test_bad_signature_is_unauthenticated(self):
        payload = parse(self.packet)["payload"]
        packet = compact({"payload": payload, "signature": "00" * 32})
        with self.assertRaises(AuthenticationError):
            verify(packet, receipts=self.receipts)

    def test_unknown_issuer_is_unauthenticated(self):
        ring = keyring(other=[entry(1, SECRET_OTHER)])
        packet = confirm(self.receipts, ring=ring, issuer="other")
        with self.assertRaises(AuthenticationError):
            verify(packet, receipts=self.receipts)

    def test_revoked_at_verification_moment_is_unauthenticated(self):
        ring = keyring(coord=[entry(1, SECRET_COORD, revoked=True)])
        with self.assertRaises(AuthenticationError):
            verify(self.packet, receipts=self.receipts, ring=ring)

    def test_results_are_fresh_and_independent(self):
        first = verify(self.packet, receipts=self.receipts)
        second = verify(self.packet, receipts=self.receipts)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["receipts"][0]["conclusion"] = "mutated"
        first["operations"][0]["conclusion"] = "mutated"
        self.assertEqual(
            verify(self.packet, receipts=self.receipts)["receipts"][0]
            ["conclusion"],
            "executed",
        )


class VerifyConfirmationsBatchTest(unittest.TestCase):
    def setUp(self):
        self.receipts = default_receipts()
        self.good = confirm(self.receipts)
        payload = parse(self.good)["payload"]
        tampered = dict(payload, status="partial")
        self.invalid = rewrap(tampered)
        self.unauthenticated = compact(
            {"payload": payload, "signature": "00" * 32}
        )

    def batch(self, items, **kwargs):
        receipts = kwargs.pop("receipts", self.receipts)
        return verify_fork_confirmations(
            items, PLAN, DECISION, POLICY, receipts, RING, VERIFY_MOMENT,
            **kwargs
        )

    def test_batch_validation_faults(self):
        with self.assertRaises(TypeError):
            self.batch("x")
        with self.assertRaises(TypeError):
            self.batch(["x"])
        with self.assertRaises(TypeError):
            self.batch([{"id": 1, "confirmation": self.good}])
        with self.assertRaises(TypeError):
            self.batch([{"id": "a", "confirmation": "x"}])
        with self.assertRaises(ValueError):
            self.batch([])
        with self.assertRaises(ValueError):
            self.batch([{"id": "", "confirmation": self.good}])
        with self.assertRaises(ValueError):
            self.batch([{"id": "a", "confirmation": self.good},
                        {"id": "a", "confirmation": self.good}])
        with self.assertRaises(ValueError):
            self.batch([{"id": "a", "confirmation": self.good, "n": 1}])

    def test_batch_shared_material_faults_raise(self):
        items = [{"id": "a", "confirmation": self.good}]
        with self.assertRaises(InvalidForkExecutionError):
            verify_fork_confirmations(
                items, PLAN + b"\n", DECISION, POLICY, self.receipts,
                RING, VERIFY_MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_fork_confirmations(
                items, PLAN, DECISION, POLICY, [], RING, VERIFY_MOMENT,
            )

    def test_batch_isolation_and_order(self):
        result = self.batch([
            {"id": "good", "confirmation": self.good},
            {"id": "invalid", "confirmation": self.invalid},
            {"id": "unauthenticated", "confirmation": self.unauthenticated},
        ])
        self.assertEqual(set(result.keys()), {"items", "version"})
        self.assertEqual(result["version"], 1)
        items = result["items"]
        self.assertEqual([item["id"] for item in items],
                         ["good", "invalid", "unauthenticated"])
        self.assertEqual(
            [item["status"] for item in items],
            ["verified", "invalid", "unauthenticated"],
        )
        good, invalid, unauthenticated = items
        self.assertIsNone(good["error"])
        self.assertEqual(good["result"]["status"], "confirmed")
        self.assertEqual(
            list(good["result"].keys()),
            ["confirmationDigest", "decisionDigest", "issuer", "keyVersion",
             "moment", "operations", "planDigest", "receipts", "status",
             "version"],
        )
        for item in (invalid, unauthenticated):
            self.assertIsInstance(item["error"], str)
            self.assertNotEqual(item["error"], "")
            self.assertIsNone(item["result"])
        for item in items:
            self.assertEqual(list(item.keys()),
                             ["error", "id", "result", "status"])

    def test_batch_results_are_fresh_and_independent(self):
        items = [{"id": "a", "confirmation": self.good}]
        first = self.batch(items)
        second = self.batch(items)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["items"][0]["result"]["status"] = "mutated"
        self.assertEqual(
            self.batch(items)["items"][0]["result"]["status"], "confirmed"
        )


if __name__ == "__main__":
    unittest.main()
