"""Equivalence regression tests for the refactored final fork decision
aggregate chain batch/anchor boundary.

These tests pin the *public* behavior of the three entry points whose
internals were extracted into the internal
``offline_coordination._ffdac_batch`` boundary --
:func:`verify_final_fork_decision_aggregate_chains`,
:func:`seal_final_fork_decision_aggregate_head` and
:func:`verify_final_fork_decision_aggregate_head` -- across the
dimensions the refactor had to preserve:

* identity: the documented ``offline_coordination.replication`` import
  path exposes the same function and exception objects the internal
  boundary defines, with unchanged call signatures and exception
  inheritance, and the internal modules are not new public entry
  points (the package ``__init__`` and the command line are untouched
  and no import order can produce a circular import);
* determinism: batch reports are equal (but deeply independent) across
  repeated runs, every verified batch row equals the single-chain
  entry point's result, and anchor sealing is byte-for-byte
  deterministic with the HMAC covering the canonical payload;
* forks: two successors over one predecessor are a fork with the fixed
  error and the verified result kept, a plain prefix extension is not
  a fork, identical chains are not a fork and failed chains never
  create or cross one;
* anchors: every payload binding -- root/head digest, height, final
  stage policy digest, policy version, declaration digest, sealing
  moment, issuer, key version and protocol version -- is recomputed
  against a freshly rebuilt batch, never trusted from the packet;
* credentials: key rotation seals and verifies at the new version
  while revoked, not-yet-valid and expired keys fail closed both at
  the sealing moment and at the verification moment;

plus the batch-level TypeError/ValueError taxonomy that must raise
before any single chain is examined, per-item isolation in input
order, input immutability and the purely offline guarantee.  The old
recovery, storage, state-merge, proof-chain and status surfaces are
structurally pinned to their original modules, and the full suite
covers their behavior.
"""

import copy
import hashlib
import hmac
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import offline_coordination._ffdac_batch as ffdac_batch
import offline_coordination._ffdacf_aggregation as ffdacf_aggregation
from offline_coordination import replication
from offline_coordination.replication import (
    AuthenticationError,
    InvalidFinalAggregateChainForkDecisionAggregateError,
    InvalidFinalForkDecisionAggregateAnchorError,
    InvalidFinalForkDecisionAggregateChainError,
    InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
    SECRET,
    _pac_policy_digest,
    _prune_compact,
    _usable_checkpoint_key,
    _validated_keyring,
    aggregate_final_fork_decision_aggregate_chain_fork_decisions,
    seal_final_fork_decision_aggregate_head,
    verify_final_fork_decision_aggregate_chain,
    verify_final_fork_decision_aggregate_chain_fork_decision_aggregate,
    verify_final_fork_decision_aggregate_chain_fork_decisions,
    verify_final_fork_decision_aggregate_chains,
    verify_final_fork_decision_aggregate_head,
)

from test_final_fork_decision_aggregate_chains import (
    FinalForkDecisionAggregateChainsFixtures,
)
from test_fork_convergence import entry
from test_prune_attestations import JUDGE

SECRET_V2 = "22" * 32

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FORKED_ERROR = "forked-final-fork-decision-aggregate-chain"

EXPECTED_SIGNATURES = {
    "verify_final_fork_decision_aggregate_chains": (
        "items, prune_policy, authorization_policy, site_policy, "
        "signer_site_policy, adjudication_site_policy, keyring, moment"
    ),
    "seal_final_fork_decision_aggregate_head": (
        "items, target, prune_policy, authorization_policy, site_policy, "
        "signer_site_policy, adjudication_site_policy, keyring, moment, "
        "issuer, version"
    ),
    "verify_final_fork_decision_aggregate_head": (
        "anchor, items, target, prune_policy, authorization_policy, "
        "site_policy, signer_site_policy, adjudication_site_policy, "
        "keyring, moment"
    ),
    "verify_final_fork_decision_aggregate_chain_fork_decisions": (
        "items, prune_policy, authorization_policy, site_policy, "
        "signer_site_policy, adjudication_site_policy, "
        "proof_site_policy, keyring, moment"
    ),
    "aggregate_final_fork_decision_aggregate_chain_fork_decisions": (
        "items, prune_policy, authorization_policy, site_policy, "
        "signer_site_policy, adjudication_site_policy, "
        "proof_site_policy, decision_site_policy, keyring, moment, "
        "issuer, version"
    ),
    "verify_final_fork_decision_aggregate_chain_fork_decision_aggregate": (
        "aggregate, prune_policy, authorization_policy, site_policy, "
        "signer_site_policy, adjudication_site_policy, "
        "proof_site_policy, decision_site_policy, keyring, moment"
    ),
}


def fresh_interpreter(code):
    """Run ``code`` in a fresh interpreter rooted at the repository."""
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
    )


class PublicBoundaryTest(unittest.TestCase):
    """The documented import path, identity and signatures survive the
    extraction; the internal modules are not new public entry points."""

    def test_public_names_resolve_to_the_internal_boundary_objects(self):
        for name in (
            "verify_final_fork_decision_aggregate_chains",
            "seal_final_fork_decision_aggregate_head",
            "verify_final_fork_decision_aggregate_head",
        ):
            self.assertIs(getattr(replication, name),
                          getattr(ffdac_batch, name), name)
        # The from-import names above are the replication attributes,
        # which are the internal boundary objects themselves.
        for function, module in (
            (verify_final_fork_decision_aggregate_chain_fork_decisions,
             ffdacf_aggregation),
            (aggregate_final_fork_decision_aggregate_chain_fork_decisions,
             ffdacf_aggregation),
            (verify_final_fork_decision_aggregate_chain_fork_decision_aggregate,
             ffdacf_aggregation),
        ):
            self.assertIs(
                function,
                getattr(module, function.__name__), function.__name__)
            self.assertIs(
                function,
                getattr(replication, function.__name__), function.__name__)
        self.assertIs(
            replication.InvalidFinalForkDecisionAggregateAnchorError,
            ffdac_batch.InvalidFinalForkDecisionAggregateAnchorError)
        self.assertIs(
            replication
            .InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
            ffdacf_aggregation
            .InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError)

    def test_call_signatures_are_unchanged(self):
        import inspect
        for name, expected in EXPECTED_SIGNATURES.items():
            parameters = ", ".join(
                inspect.signature(getattr(replication, name)).parameters
            )
            self.assertEqual(parameters, expected, name)

    def test_exception_hierarchy_is_unchanged(self):
        for cls in (
            InvalidFinalForkDecisionAggregateAnchorError,
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
        ):
            self.assertTrue(issubclass(cls, ValueError))
            self.assertEqual(cls.__bases__, (ValueError,))
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateAnchorError,
            InvalidFinalForkDecisionAggregateChainError)
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateAnchorError,
            InvalidFinalAggregateChainForkDecisionAggregateError)
        self.assertIsNot(
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
            InvalidFinalForkDecisionAggregateChainError)

    def test_only_the_two_protocol_groups_moved_modules(self):
        # The extracted entry points live in the internal boundary
        # modules; every older layer stays defined in the core module.
        self.assertEqual(
            verify_final_fork_decision_aggregate_chains.__module__,
            "offline_coordination._ffdac_batch")
        self.assertEqual(
            aggregate_final_fork_decision_aggregate_chain_fork_decisions
            .__module__,
            "offline_coordination._ffdacf_aggregation")
        for name in (
            "recover_authorized", "inspect_recovery",
            "export_recovery_audit", "inspect_node",
            "supersede_final_fork_decision_aggregate",
            "verify_final_fork_decision_aggregate_chain",
            "verify_final_fork_decision_aggregate_chain_fork_decision",
            "aggregate_final_aggregate_chain_fork_decisions",
            "adjudicate_final_fork_decision_aggregate_chain_forks",
            "sign_final_fork_decision_aggregate_chain_fork_proof",
        ):
            self.assertEqual(
                getattr(replication, name).__module__,
                "offline_coordination.replication", name)

    def test_package_init_does_not_import_the_boundary(self):
        result = fresh_interpreter(
            "import sys\n"
            "import offline_coordination\n"
            "assert 'offline_coordination.replication' not in sys.modules\n"
            "assert 'offline_coordination._ffdac_batch' not in sys.modules\n"
            "assert 'offline_coordination._ffdacf_aggregation' "
            "not in sys.modules\n"
            "assert not hasattr(offline_coordination, '_ffdac_batch')\n"
            "assert not hasattr("
            "offline_coordination, '_ffdacf_aggregation')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_older_modules_do_not_depend_on_the_boundary(self):
        result = fresh_interpreter(
            "import sys\n"
            "from offline_coordination import (\n"
            "    audit, merge, receipt, storage, transaction)\n"
            "assert 'offline_coordination._ffdac_batch' not in sys.modules\n"
            "assert 'offline_coordination._ffdacf_aggregation' "
            "not in sys.modules\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_import_order_can_create_a_cycle(self):
        for code in (
            "import offline_coordination.replication",
            "import offline_coordination._ffdac_batch",
            "import offline_coordination._ffdacf_aggregation",
            "import offline_coordination._ffdac_batch\n"
            "import offline_coordination._ffdacf_aggregation\n"
            "import offline_coordination.replication",
            "import offline_coordination._ffdacf_aggregation\n"
            "import offline_coordination._ffdac_batch\n"
            "import offline_coordination.replication",
        ):
            result = fresh_interpreter(
                code + "\n"
                "from offline_coordination import replication\n"
                "assert replication.verify_final_fork_decision_aggregate_chains"
                " is not None\n"
                "assert replication"
                ".verify_final_fork_decision_aggregate_chain_fork_decisions"
                " is not None\n"
            )
            self.assertEqual(result.returncode, 0,
                             f"{code!r}: {result.stderr}")

    def test_command_line_surface_is_unchanged(self):
        result = subprocess.run(
            [sys.executable, "-m", "offline_coordination", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": REPO_ROOT},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("{status,recovery}", result.stdout)


class BatchEquivalenceTest(FinalForkDecisionAggregateChainsFixtures,
                           unittest.TestCase):
    """The batch report is the single-chain ruling, per item, in input
    order, with total isolation between chains."""

    def test_verified_rows_equal_the_single_chain_results(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        report = self.ffreport(items)
        self.assertEqual([i["status"] for i in report["items"]],
                         ["verified", "verified"])
        self.assertEqual(report["forks"], [])
        self.assertEqual(report["version"], 1)
        for item, raw in zip(report["items"], items):
            self.assertEqual(
                item["result"],
                verify_final_fork_decision_aggregate_chain(
                    raw["root"], raw["successors"], self.policy, self.auth,
                    self.ssp, self.fsignerp, self.adjp, raw["policies"],
                    self.ring, self.vmoment))
            self.assertIsNone(item["error"])

    def test_reports_are_equal_but_deeply_independent(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        first = self.ffreport(items)
        second = self.ffreport(items)
        self.assertEqual(first, second)
        first["items"][0]["result"]["status"] = "tampered"
        first["forks"].append("tampered")
        again = self.ffreport(items)
        self.assertEqual(again, second)
        self.assertEqual(
            again["items"][0]["result"]["status"], "accepted")

    def test_forked_chains_keep_their_verified_results(self):
        items = [
            self.ffitem("b", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("a", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1]),
        ]
        report = self.ffreport(items)
        self.assertEqual([i["status"] for i in report["items"]],
                         ["conflicted", "conflicted"])
        self.assertEqual([i["error"] for i in report["items"]],
                         [FORKED_ERROR, FORKED_ERROR])
        for item, raw in zip(report["items"], items):
            self.assertEqual(
                item["result"],
                verify_final_fork_decision_aggregate_chain(
                    raw["root"], raw["successors"], self.policy, self.auth,
                    self.ssp, self.fsignerp, self.adjp, raw["policies"],
                    self.ring, self.vmoment))
        fork, = report["forks"]
        self.assertEqual(
            list(fork.keys()),
            ["rootDigest", "predecessorDigest", "successors", "ids"])
        self.assertEqual(
            fork["rootDigest"], hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(
            fork["predecessorDigest"],
            hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(fork["successors"], sorted([
            hashlib.sha256(self.s_grow).hexdigest(),
            hashlib.sha256(self.s_t1).hexdigest()]))
        self.assertEqual(fork["ids"], ["a", "b"])

    def test_prefix_extension_is_not_a_fork(self):
        report = self.ffreport([
            self.ffitem("long", self.froot_one,
                       [self.s_grow, self.sec_t1],
                       [self.pv1, self.pv1, self.pv2_t1]),
            self.ffitem("short", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("bare", self.froot_one)])
        self.assertEqual(report["forks"], [])
        self.assertEqual([i["status"] for i in report["items"]],
                         ["verified", "verified", "verified"])
        self.assertEqual(
            [i["result"]["height"] for i in report["items"]], [2, 1, 0])

    def test_identical_chains_are_not_a_fork(self):
        report = self.ffreport([
            self.ffitem("a", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("b", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1])])
        self.assertEqual(report["forks"], [])
        self.assertEqual([i["status"] for i in report["items"]],
                         ["verified", "verified"])

    def test_one_bad_item_never_blocks_or_alters_later_items(self):
        tampered = json.loads(self.froot_two.decode())
        tampered["signature"] = "00" * 32
        items = [
            self.ffitem("root", b"{"),
            self.ffitem("chain", self.froot_two, [b"{}"],
                       [self.pv1, self.pv1]),
            self.ffitem("auth", _prune_compact(tampered)),
            self.grow_item("ok"),
        ]
        report = self.ffreport(items)
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["invalid-root", "invalid-chain", "unauthenticated",
             "verified"])
        self.assertEqual(
            [i["id"] for i in report["items"]],
            ["root", "chain", "auth", "ok"])
        for item in report["items"][:3]:
            self.assertIsNone(item["result"])
            self.assertTrue(item["error"])
        self.assertEqual(
            report["items"][3]["result"],
            verify_final_fork_decision_aggregate_chain(
                self.froot_one, [self.s_grow], self.policy, self.auth,
                self.ssp, self.fsignerp, self.adjp, [self.pv1, self.pv1],
                self.ring, self.vmoment))

    def test_failed_chains_never_create_or_cross_forks(self):
        report = self.ffreport([
            self.ffitem("ok", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("bad", self.froot_one, [self.s_t1, b"{}"],
                       [self.pv1, self.pv2_t1, self.pv2_t1])])
        self.assertEqual(report["forks"], [])
        self.assertEqual([i["status"] for i in report["items"]],
                         ["verified", "invalid-chain"])

    def test_batch_level_faults_raise_before_any_item_is_examined(self):
        # Every item below carries garbage root bytes that item
        # processing would report as invalid-root; the batch-level
        # fault must win.
        garbage = self.ffitem("one", b"{")
        with self.assertRaises(TypeError):
            self.ffreport((garbage,))
        with self.assertRaises(ValueError):
            self.ffreport([])
        with self.assertRaises(TypeError):
            self.ffreport([{"id": 1, "root": b"{", "successors": [],
                           "policies": [self.pv1]}])
        with self.assertRaises(ValueError):
            self.ffreport([garbage, self.ffitem("one", b"{")])
        with self.assertRaises(ValueError):
            self.ffreport([{"id": "one", "root": b"{", "successors": [],
                           "policies": [self.pv1], "extra": 1}])
        with self.assertRaises(TypeError):
            self.ffreport([self.ffitem("one", b"{".hex())])
        with self.assertRaises(TypeError):
            self.ffreport([garbage], moment=True)
        with self.assertRaises(ValueError):
            self.ffreport([garbage], moment=-1)
        with self.assertRaises(ValueError):
            self.ffreport([garbage], adjp={"sites": {}, "threshold": 1})
        with self.assertRaises(TypeError):
            self.ffreport([garbage], ring={"x": "nope"})

    def test_inputs_are_never_modified_and_no_file_is_touched(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        snapshot = copy.deepcopy(
            (items, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.ring))
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.ffreport(items)
        self.assertEqual(
            (items, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.ring), snapshot)


class SealEquivalenceTest(FinalForkDecisionAggregateChainsFixtures,
                          unittest.TestCase):
    """The sealed anchor is one deterministic canonical packet whose
    bindings come from the freshly rebuilt batch alone."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = [self.bare_one("a"), self.grow_item("b")]

    def test_sealing_is_byte_for_byte_deterministic(self):
        first = self.ffseal(self.items, "a")
        second = self.ffseal(self.items, "a")
        self.assertEqual(first, second)
        self.assertEqual(_prune_compact(json.loads(first.decode())), first)

    def test_signature_covers_the_canonical_payload(self):
        raw = self.ffseal(self.items, "a")
        data = json.loads(raw.decode())
        key = _usable_checkpoint_key(
            _validated_keyring(self.ring), JUDGE, 1, self.vmoment)
        expected = hmac.new(
            bytes.fromhex(key[SECRET]), _prune_compact(data["payload"]),
            hashlib.sha256).hexdigest()
        self.assertEqual(data["signature"], expected)

    def test_payload_bindings_equal_the_fresh_batch_result(self):
        payload = json.loads(self.ffseal(self.items, "a").decode())["payload"]
        result = self.ffreport(self.items)["items"][0]["result"]
        self.assertEqual(
            list(payload.keys()),
            ["declarationDigest", "headDigest", "height", "issuer",
             "keyVersion", "policyDigest", "policyVersion", "rootDigest",
             "sealedAt", "version"])
        self.assertEqual(payload["rootDigest"], result["rootDigest"])
        self.assertEqual(payload["headDigest"], result["headDigest"])
        self.assertEqual(payload["height"], result["height"])
        self.assertEqual(payload["policyVersion"], result["policyVersion"])
        self.assertEqual(
            payload["declarationDigest"], result["declarationDigest"])
        self.assertEqual(
            payload["policyDigest"], _pac_policy_digest(self.pv1))
        self.assertEqual(payload["sealedAt"], self.vmoment)
        self.assertEqual(payload["issuer"], JUDGE)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)

    def test_multi_hop_head_binds_the_final_stage(self):
        item = self.ffitem(
            "h", self.froot_one, [self.s_grow, self.sec_t1],
            [self.pv1, self.pv1, self.pv2_t1])
        payload = json.loads(self.ffseal([item], "h").decode())["payload"]
        self.assertEqual(payload["height"], 2)
        self.assertEqual(payload["policyVersion"], 2)
        self.assertEqual(
            payload["policyDigest"], _pac_policy_digest(self.pv2_t1))
        self.assertEqual(
            payload["headDigest"], hashlib.sha256(self.sec_t1).hexdigest())

    def test_other_chains_failures_never_block_the_target(self):
        raw = self.ffseal(
            [self.bare_one("a"), self.ffitem("bad", b"{")], "a")
        self.assertIsInstance(raw, bytes)

    def test_only_a_verified_accepted_unforked_target_seals(self):
        with self.assertRaises(ValueError):
            self.ffseal([self.ffitem("a", self.froot_one)], "a")
        with self.assertRaises(ValueError):
            self.ffseal([
                self.ffitem("a", self.froot_one, [self.s_grow],
                           [self.pv1, self.pv1]),
                self.ffitem("b", self.froot_one, [self.s_t1],
                           [self.pv1, self.pv2_t1])], "a")
        with self.assertRaises(ValueError):
            self.ffseal([
                self.ffitem("a", self.froot_two, [self.t_conf],
                           [self.pv1, self.pv2_3])], "a")

    def test_target_faults_keep_their_dedicated_classes(self):
        with self.assertRaises(
            InvalidFinalAggregateChainForkDecisionAggregateError
        ):
            self.ffseal([self.ffitem("a", b"{}")], "a")
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self.ffseal([
                self.ffitem("a", self.froot_two, [b"{}"],
                           [self.pv1, self.pv1])], "a")

    def test_rotated_key_seals_and_verifies(self):
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = rotated[JUDGE] + [entry(2, SECRET_V2)]
        items = [self.bare_one("a")]
        raw = seal_final_fork_decision_aggregate_head(
            items, "a", self.policy, self.auth, self.ssp, self.fsignerp,
            self.adjp, rotated, self.vmoment, JUDGE, 2)
        payload = json.loads(raw.decode())["payload"]
        self.assertEqual(payload["keyVersion"], 2)
        result = verify_final_fork_decision_aggregate_head(
            raw, items, "a", self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, rotated, self.vmoment)
        self.assertEqual(
            result["anchorDigest"], hashlib.sha256(raw).hexdigest())
        # The old keyring without the rotated key rejects the anchor.
        with self.assertRaises(AuthenticationError):
            self.ffverify(raw, items, "a")

    def test_sealing_credentials_have_no_fallback(self):
        items = [self.bare_one("a")]
        with self.assertRaises(AuthenticationError):
            self.ffseal(items, "a", issuer="nobody")
        with self.assertRaises(AuthenticationError):
            self.ffseal(items, "a", version=2)
        for broken in (
            [entry(1, "11" * 32, revoked=True)],
            [entry(1, "11" * 32, not_before=self.vmoment + 1)],
            [entry(1, "11" * 32, not_after=self.vmoment - 1)],
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = broken
            with self.assertRaises(AuthenticationError):
                seal_final_fork_decision_aggregate_head(
                    items, "a", self.policy, self.auth, self.ssp,
                    self.fsignerp, self.adjp, ring, self.vmoment, JUDGE, 1)

    def test_inputs_are_never_modified_and_no_file_is_touched(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        snapshot = copy.deepcopy(
            (items, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.ring))
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.ffseal(items, "a")
        self.assertEqual(
            (items, self.policy, self.auth, self.ssp, self.fsignerp,
             self.adjp, self.ring), snapshot)


class VerifyAnchorEquivalenceTest(FinalForkDecisionAggregateChainsFixtures,
                                  unittest.TestCase):
    """The offline anchor review recomputes every binding against a
    freshly rebuilt batch and never trusts the packet."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = [self.bare_one("a"), self.grow_item("b")]
        self.raw = self.ffseal(self.items, "a")

    def test_result_is_the_anchor_binding_plus_digest(self):
        result = self.ffverify(self.raw, self.items, "a")
        payload = json.loads(self.raw.decode())["payload"]
        self.assertEqual(
            list(result.keys()),
            ["rootDigest", "headDigest", "height", "policyDigest",
             "policyVersion", "declarationDigest", "anchorDigest"])
        self.assertEqual(
            result["anchorDigest"], hashlib.sha256(self.raw).hexdigest())
        for key in (
            "rootDigest", "headDigest", "height", "policyDigest",
            "policyVersion", "declarationDigest",
        ):
            self.assertEqual(result[key], payload[key], key)

    def test_results_are_equal_but_deeply_independent(self):
        first = self.ffverify(self.raw, self.items, "a")
        second = self.ffverify(self.raw, self.items, "a")
        self.assertEqual(first, second)
        first["height"] = 99
        first["rootDigest"] = "0" * 64
        again = self.ffverify(self.raw, self.items, "a")
        self.assertEqual(again, second)

    def assert_anchor_invalid(self, payload):
        with self.assertRaises(InvalidFinalForkDecisionAggregateAnchorError):
            self.ffverify(self.ffrewrap(payload), self.items, "a")

    def test_every_digest_binding_is_recomputed(self):
        payload = json.loads(self.raw.decode())["payload"]
        for field in ("rootDigest", "headDigest", "policyDigest"):
            tampered = dict(payload, **{field: "9" * 64})
            self.assert_anchor_invalid(tampered)
        self.assert_anchor_invalid(dict(payload, declarationDigest=None))
        self.assert_anchor_invalid(
            dict(payload, declarationDigest="9" * 64))

    def test_every_scalar_binding_is_recomputed(self):
        payload = json.loads(self.raw.decode())["payload"]
        self.assert_anchor_invalid(dict(payload, height=5))
        self.assert_anchor_invalid(dict(payload, policyVersion=2))
        self.assert_anchor_invalid(dict(payload, version=2))
        # A sealing moment later than the verification moment rejects.
        self.assert_anchor_invalid(
            dict(payload, sealedAt=self.vmoment + 1))

    def test_issuer_and_version_bindings_have_no_fallback(self):
        payload = json.loads(self.raw.decode())["payload"]
        for tampered in (
            dict(payload, issuer="nobody"),
            dict(payload, keyVersion=99),
        ):
            # Re-signed under the genuine key, the claimed identity
            # still resolves to no usable credential.
            with self.assertRaises(AuthenticationError):
                self.ffverify(
                    self.ffrewrap(tampered, issuer=JUDGE, version=1),
                    self.items, "a")

    def test_signature_and_credentials_are_checked_at_the_verify_moment(
            self):
        data = json.loads(self.raw.decode())
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.ffverify(_prune_compact(data), self.items, "a")
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = rotated[JUDGE] + [entry(2, SECRET_V2)]
        raw = seal_final_fork_decision_aggregate_head(
            self.items, "a", self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, rotated, self.vmoment, JUDGE, 2)
        result = verify_final_fork_decision_aggregate_head(
            raw, self.items, "a", self.policy, self.auth, self.ssp,
            self.fsignerp, self.adjp, rotated, self.vmoment)
        self.assertEqual(
            result["anchorDigest"], hashlib.sha256(raw).hexdigest())
        for broken in (
            [entry(2, SECRET_V2, revoked=True)],
            [entry(2, SECRET_V2, not_before=self.vmoment + 1)],
            [entry(2, SECRET_V2, not_after=self.vmoment - 1)],
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = ring[JUDGE] + broken
            with self.assertRaises(AuthenticationError):
                verify_final_fork_decision_aggregate_head(
                    raw, self.items, "a", self.policy, self.auth, self.ssp,
                    self.fsignerp, self.adjp, ring, self.vmoment)

    def test_encoding_faults_keep_their_classification(self):
        with self.assertRaises(TypeError):
            self.ffverify("bytes", self.items, "a")
        with self.assertRaises(TypeError):
            self.ffverify(b"[]", self.items, "a")
        for raw in (self.raw + b"\n", self.raw.replace(b":", b": ", 1),
                    b"", b"{", b'{"payload":{}}'):
            with self.assertRaises(
                InvalidFinalForkDecisionAggregateAnchorError, msg=raw
            ):
                self.ffverify(raw, self.items, "a")

    def test_drifted_or_conflicted_target_is_anchor_error(self):
        extended = [self.ffitem("a", self.froot_two, [self.t_rot],
                               [self.pv1, self.pv2_t1])]
        with self.assertRaises(InvalidFinalForkDecisionAggregateAnchorError):
            self.ffverify(self.raw, extended, "a")
        with self.assertRaises(InvalidFinalForkDecisionAggregateAnchorError):
            self.ffverify(self.raw, [
                self.ffitem("a", self.froot_two, [self.t_rot],
                           [self.pv1, self.pv2_t1]),
                self.ffitem("z", self.froot_two, [self.t_conf],
                           [self.pv1, self.pv2_3])], "a")

    def test_target_faults_keep_their_dedicated_classes(self):
        with self.assertRaises(
            InvalidFinalAggregateChainForkDecisionAggregateError
        ):
            self.ffverify(self.raw, [self.ffitem("a", b"{}")], "a")
        with self.assertRaises(InvalidFinalForkDecisionAggregateChainError):
            self.ffverify(self.raw, [
                self.ffitem("a", self.froot_two, [b"{}"],
                           [self.pv1, self.pv1])], "a")

    def test_inputs_are_never_modified_and_no_file_is_touched(self):
        snapshot = copy.deepcopy(
            (self.raw, self.items, self.policy, self.auth, self.ssp,
             self.fsignerp, self.adjp, self.ring))
        with mock.patch("builtins.open", side_effect=AssertionError(
                "no file access")):
            self.ffverify(self.raw, self.items, "a")
        self.assertEqual(
            (self.raw, self.items, self.policy, self.auth, self.ssp,
             self.fsignerp, self.adjp, self.ring), snapshot)


if __name__ == "__main__":
    unittest.main()
