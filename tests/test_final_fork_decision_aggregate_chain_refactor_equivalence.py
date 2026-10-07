"""Refactor regression tests for the extracted final fork decision
aggregate chain boundaries.

The batch verification and stable head anchor layer
(:func:`verify_final_fork_decision_aggregate_chains`,
:func:`seal_final_fork_decision_aggregate_head`,
:func:`verify_final_fork_decision_aggregate_head`) and the fork decision
batch/cross-site aggregation layer
(:func:`verify_final_fork_decision_aggregate_chain_fork_decisions`,
:func:`aggregate_final_fork_decision_aggregate_chain_fork_decisions`,
:func:`verify_final_fork_decision_aggregate_chain_fork_decision_aggregate`)
were extracted out of the monolithic ``offline_coordination.replication``
module into the private sibling modules
``offline_coordination._ffdac_chain_batch`` and
``offline_coordination._ffdac_decision_aggregation``, with the shared
batch validation, signature wrapping and deterministic merge rules kept
as single authoritative implementations.

These tests pin, through the *public* ``offline_coordination.replication``
path only:

* the import surface: identical names, call signatures, exception
  inheritance and class object identity, with the private modules never
  acting as new public entry points and the package staying free of
  import cycles;
* byte-for-byte equivalence: the same legal, forked, fork-free,
  prefix-extension, threshold-shortfall and cross-site-contradiction
  materials yield the same reports, canonical bytes, digests and HMAC
  signatures as the single-chain and single-decision entry points
  dictate;
* tamper recomputation: the seven policy digest bindings, the original
  input digest vector, the declaration row ordering, the term-by-term
  proof digest order, the signature and the credential boundaries are
  all recomputed, never trusted from the packet;
* isolation and determinism: repeated calls return equal but deeply
  independent results and one bad item never blocks or alters a later
  good one;
* the older layers -- ledger recovery, state storage, state merging,
  the audit proof chain and the ``status`` command -- are untouched.
"""

import copy
import hashlib
import hmac
import inspect
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import offline_coordination
import offline_coordination.replication as replication
from offline_coordination.replication import (
    AuthenticationError,
    InvalidFinalAggregateChainForkDecisionAggregateError,
    InvalidFinalForkDecisionAggregateAnchorError,
    InvalidFinalForkDecisionAggregateChainError,
    InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
    InvalidFinalForkDecisionAggregateChainForkDecisionError,
    SECRET,
    _prune_compact,
    _usable_checkpoint_key,
    _validated_keyring,
    aggregate_final_fork_decision_aggregate_chain_fork_decisions,
    inspect_recovery,
    recover_ledger,
    seal_final_fork_decision_aggregate_head,
    verify_final_fork_decision_aggregate_chain,
    verify_final_fork_decision_aggregate_chain_fork_decision,
    verify_final_fork_decision_aggregate_chain_fork_decision_aggregate,
    verify_final_fork_decision_aggregate_chain_fork_decisions,
    verify_final_fork_decision_aggregate_chains,
    verify_final_fork_decision_aggregate_head,
)

from test_final_fork_decision_aggregate_chains import (
    FinalForkDecisionAggregateChainsFixtures,
)
from test_final_fork_decision_aggregate_chain_fork_decision_aggregates import (
    FinalForkDecisionAggregateChainForkDecisionFixtures,
    parse,
)
from test_adjudicate_prune_aggregate_forks import proof_item
from test_aggregate_prune_fork_decisions import decision_item
from test_fork_convergence import entry
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C

JUDGE_B = SITE_C
SECRET_V2_A = "22" * 32
SECRET_V2_B = "33" * 32

CHAIN_PUBLIC_SIGNATURES = {
    "verify_final_fork_decision_aggregate_chains": (
        "items", "prune_policy", "authorization_policy", "site_policy",
        "signer_site_policy", "adjudication_site_policy", "keyring",
        "moment",
    ),
    "seal_final_fork_decision_aggregate_head": (
        "items", "target", "prune_policy", "authorization_policy",
        "site_policy", "signer_site_policy", "adjudication_site_policy",
        "keyring", "moment", "issuer", "version",
    ),
    "verify_final_fork_decision_aggregate_head": (
        "anchor", "items", "target", "prune_policy", "authorization_policy",
        "site_policy", "signer_site_policy", "adjudication_site_policy",
        "keyring", "moment",
    ),
    "verify_final_fork_decision_aggregate_chain_fork_decisions": (
        "items", "prune_policy", "authorization_policy", "site_policy",
        "signer_site_policy", "adjudication_site_policy",
        "proof_site_policy", "keyring", "moment",
    ),
    "aggregate_final_fork_decision_aggregate_chain_fork_decisions": (
        "items", "prune_policy", "authorization_policy", "site_policy",
        "signer_site_policy", "adjudication_site_policy",
        "proof_site_policy", "decision_site_policy", "keyring", "moment",
        "issuer", "version",
    ),
    "verify_final_fork_decision_aggregate_chain_fork_decision_aggregate": (
        "aggregate", "prune_policy", "authorization_policy", "site_policy",
        "signer_site_policy", "adjudication_site_policy",
        "proof_site_policy", "decision_site_policy", "keyring", "moment",
    ),
}

DIGEST_FIELDS = (
    "prunePolicyDigest",
    "authorizationPolicyDigest",
    "sitePolicyDigest",
    "signerSitePolicyDigest",
    "adjudicationSitePolicyDigest",
    "proofSitePolicyDigest",
    "decisionSitePolicyDigest",
)

ANCHOR_BINDING_FIELDS = (
    "rootDigest",
    "headDigest",
    "height",
    "policyDigest",
    "policyVersion",
    "declarationDigest",
)

PRIVATE_MODULES = (
    "offline_coordination._ffdac_chain_batch",
    "offline_coordination._ffdac_decision_aggregation",
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PublicBoundaryTest(unittest.TestCase):
    """The public surface is unchanged and the extracted modules stay
    private, with no import cycle."""

    def test_public_names_keep_their_original_path_and_identity(self):
        for name in CHAIN_PUBLIC_SIGNATURES:
            self.assertTrue(
                inspect.isfunction(getattr(replication, name)), name)
        for name in (
            "InvalidFinalForkDecisionAggregateAnchorError",
            "InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError",
        ):
            error_class = getattr(replication, name)
            self.assertTrue(inspect.isclass(error_class), name)
            self.assertTrue(issubclass(error_class, ValueError), name)
            self.assertEqual(
                error_class.__module__, "offline_coordination.replication",
                name)
            # Repeated attribute access resolves to one and the same
            # class object.
            self.assertIs(getattr(replication, name), error_class)

    def test_public_call_signatures_are_unchanged(self):
        for name, parameters in CHAIN_PUBLIC_SIGNATURES.items():
            signature = inspect.signature(getattr(replication, name))
            self.assertEqual(
                tuple(signature.parameters), parameters, name)

    def test_dedicated_errors_stay_distinct_from_every_sibling(self):
        siblings = (
            InvalidFinalAggregateChainForkDecisionAggregateError,
            InvalidFinalForkDecisionAggregateChainError,
            InvalidFinalForkDecisionAggregateChainForkDecisionError,
        )
        for error_class in (
            InvalidFinalForkDecisionAggregateAnchorError,
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
        ):
            for sibling in siblings:
                self.assertIsNot(error_class, sibling)
                self.assertFalse(issubclass(error_class, sibling))
                self.assertFalse(issubclass(sibling, error_class))

    def test_private_modules_are_not_new_public_entry_points(self):
        init_source = inspect.getsource(offline_coordination)
        for module_name in PRIVATE_MODULES:
            self.assertNotIn(module_name, init_source)
        # A bare ``import offline_coordination`` never pulls the
        # extracted modules: they load only on first use of one of the
        # public replication entry points.
        script = (
            "import sys; import offline_coordination; "
            "assert not any(m in sys.modules for m in %r); "
            "print('ok')"
        ) % (PRIVATE_MODULES,)
        completed = subprocess.run(
            [sys.executable, "-c", script], cwd=REPO_ROOT,
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "ok")

    def test_package_import_has_no_cycle(self):
        # Importing the public module alone must not require either
        # private module, and each private module must import cleanly on
        # its own; both directions are checked in fresh interpreters.
        script = (
            "import sys; "
            "import offline_coordination.replication; "
            "assert not any(m in sys.modules for m in %r); "
            "import offline_coordination._ffdac_chain_batch; "
            "import offline_coordination._ffdac_decision_aggregation; "
            "print('ok')"
        ) % (PRIVATE_MODULES,)
        completed = subprocess.run(
            [sys.executable, "-c", script], cwd=REPO_ROOT,
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "ok")

    def test_command_line_surface_is_unchanged(self):
        completed = subprocess.run(
            [sys.executable, "-m", "offline_coordination", "status"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["connectivity"], "offline")
        self.assertEqual(report["nodeId"], "local-node")
        self.assertEqual(report["pendingChanges"], 0)


class ChainBatchRefactorEquivalenceTest(
    FinalForkDecisionAggregateChainsFixtures, unittest.TestCase
):
    """The extracted chain batch layer reports exactly what the
    single-chain entry point rules, in input order and in isolation."""

    def test_legal_batch_rows_equal_the_single_chain_results(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        report = self.ffreport(items)
        self.assertEqual(list(report.keys()), ["forks", "items", "version"])
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["forks"], [])
        for item_report, item in zip(report["items"], items):
            self.assertEqual(item_report["status"], "verified")
            self.assertIsNone(item_report["error"])
            self.assertEqual(
                item_report["result"],
                verify_final_fork_decision_aggregate_chain(
                    item["root"], item["successors"], self.policy,
                    self.auth, self.ssp, self.fsignerp, self.adjp,
                    item["policies"], self.ring, self.vmoment))

    def test_forked_batch_reclassifies_only_the_forking_chains(self):
        items = [
            self.ffitem("b", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("a", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1]),
            self.bare_one("c"),
        ]
        report = self.ffreport(items)
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["conflicted", "conflicted", "verified"])
        fork, = report["forks"]
        self.assertEqual(
            fork["rootDigest"], hashlib.sha256(self.froot_one).hexdigest())
        self.assertEqual(
            fork["successors"], sorted([
                hashlib.sha256(self.s_grow).hexdigest(),
                hashlib.sha256(self.s_t1).hexdigest()]))
        self.assertEqual(fork["ids"], ["a", "b"])
        for item in report["items"][:2]:
            self.assertEqual(
                item["error"], "forked-final-fork-decision-aggregate-chain")
            self.assertIsNotNone(item["result"])

    def test_prefix_extension_is_not_a_fork(self):
        report = self.ffreport([
            self.ffitem("long", self.froot_one,
                       [self.s_grow, self.sec_t1],
                       [self.pv1, self.pv1, self.pv2_t1]),
            self.ffitem("short", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("bare", self.froot_one)])
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["verified", "verified", "verified"])

    def test_one_bad_chain_never_blocks_or_alters_later_chains(self):
        items = [
            self.ffitem("garbage", b"{"),
            self.ffitem("bad-chain", self.froot_one, [b"{"],
                       [self.pv1, self.pv1]),
            self.bare_one("ok"),
        ]
        report = self.ffreport(items)
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["invalid-root", "invalid-chain", "verified"])
        self.assertEqual([i["id"] for i in report["items"]],
                         ["garbage", "bad-chain", "ok"])
        self.assertIsNone(report["items"][0]["result"])
        self.assertIsNone(report["items"][1]["result"])
        self.assertTrue(report["items"][0]["error"])
        self.assertTrue(report["items"][1]["error"])

    def test_reports_are_equal_but_deeply_independent(self):
        items = [self.bare_one("a"), self.grow_item("b")]
        first = self.ffreport(items)
        second = self.ffreport(items)
        self.assertEqual(first, second)
        first["items"][0]["result"]["status"] = "x"
        first["forks"].append("x")
        again = self.ffreport(items)
        self.assertEqual(again, second)
        self.assertEqual(again["items"][0]["result"]["status"], "accepted")

    def test_batch_is_validated_before_any_chain_runs(self):
        garbage = self.ffitem("one", b"{")
        with self.assertRaises(TypeError):
            self.ffreport((garbage,))
        with self.assertRaises(ValueError):
            self.ffreport([])
        with self.assertRaises(ValueError):
            self.ffreport([garbage, self.ffitem("one", b"{")])
        with self.assertRaises(TypeError):
            self.ffreport([garbage], moment=True)
        with self.assertRaises(ValueError):
            self.ffreport([garbage], moment=-1)

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


class HeadAnchorRefactorEquivalenceTest(
    FinalForkDecisionAggregateChainsFixtures, unittest.TestCase
):
    """The extracted anchor layer seals byte-identical anchors and
    recomputes every binding instead of trusting the packet."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.items = [self.bare_one("a"), self.grow_item("b")]
        self.raw = self.ffseal(self.items, "a")

    def test_sealing_is_byte_for_byte_deterministic(self):
        again = self.ffseal(self.items, "a")
        self.assertEqual(self.raw, again)
        self.assertEqual(_prune_compact(parse(self.raw)), self.raw)

    def test_signature_covers_the_canonical_payload(self):
        data = parse(self.raw)
        self.assertEqual(list(data.keys()), ["payload", "signature"])
        key = _usable_checkpoint_key(
            _validated_keyring(self.ring), JUDGE, 1, self.vmoment)
        expected = hmac.new(
            bytes.fromhex(key[SECRET]), _prune_compact(data["payload"]),
            hashlib.sha256).hexdigest()
        self.assertEqual(data["signature"], expected)

    def test_verify_result_matches_the_batch_and_the_digest(self):
        result = self.ffverify(self.raw, self.items, "a")
        single = self.ffreport(self.items)["items"][0]["result"]
        self.assertEqual(result["rootDigest"], single["rootDigest"])
        self.assertEqual(result["headDigest"], single["headDigest"])
        self.assertEqual(result["height"], single["height"])
        self.assertEqual(result["policyVersion"], single["policyVersion"])
        self.assertEqual(
            result["declarationDigest"], single["declarationDigest"])
        self.assertEqual(
            result["anchorDigest"], hashlib.sha256(self.raw).hexdigest())

    def test_every_anchor_binding_is_recomputed(self):
        payload = parse(self.raw)["payload"]
        for field in ANCHOR_BINDING_FIELDS:
            tampered = copy.deepcopy(payload)
            value = tampered[field]
            if isinstance(value, str):
                tampered[field] = "9" * 64
            elif value is None:
                tampered[field] = "9" * 64
            else:
                tampered[field] = value + 1
            with self.assertRaises(
                InvalidFinalForkDecisionAggregateAnchorError, msg=field
            ):
                self.ffverify(self.ffrewrap(tampered), self.items, "a")

    def test_sealed_at_and_version_bounds_are_recomputed(self):
        payload = parse(self.raw)["payload"]
        tampered = copy.deepcopy(payload)
        tampered["sealedAt"] = self.vmoment + 1
        with self.assertRaises(InvalidFinalForkDecisionAggregateAnchorError):
            self.ffverify(self.ffrewrap(tampered), self.items, "a")
        tampered = copy.deepcopy(payload)
        tampered["version"] = 2
        with self.assertRaises(InvalidFinalForkDecisionAggregateAnchorError):
            self.ffverify(self.ffrewrap(tampered), self.items, "a")

    def test_signature_and_credential_boundaries(self):
        tampered = parse(self.raw)
        tampered["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.ffverify(_prune_compact(tampered), self.items, "a")
        payload = parse(self.raw)["payload"]
        for broken in (
            [entry(1, "11" * 32, revoked=True)],
            [entry(1, "11" * 32, not_before=self.vmoment + 1)],
            [entry(1, "11" * 32, not_after=self.vmoment - 1)],
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = broken
            with self.assertRaises(AuthenticationError):
                self.ffverify(self.raw, self.items, "a", ring=ring)
        # An anchor naming another issuer or key version has no fallback.
        foreign = copy.deepcopy(payload)
        foreign["issuer"] = "nobody"
        with self.assertRaises(AuthenticationError):
            self.ffverify(
                self.ffrewrap(foreign, issuer=JUDGE), self.items, "a")

    def test_a_forked_target_cannot_be_sealed_or_verified(self):
        items = [
            self.ffitem("b", self.froot_one, [self.s_grow],
                       [self.pv1, self.pv1]),
            self.ffitem("a", self.froot_one, [self.s_t1],
                       [self.pv1, self.pv2_t1]),
        ]
        with self.assertRaises(ValueError):
            self.ffseal(items, "a")
        with self.assertRaises(InvalidFinalForkDecisionAggregateAnchorError):
            self.ffverify(self.raw, items, "a")

    def test_results_are_equal_but_deeply_independent(self):
        first = self.ffverify(self.raw, self.items, "a")
        second = self.ffverify(self.raw, self.items, "a")
        self.assertEqual(first, second)
        first["height"] = 99
        self.assertEqual(
            self.ffverify(self.raw, self.items, "a")["height"],
            second["height"])

    def test_error_class_stays_distinct(self):
        try:
            self.ffverify(self.raw + b"\n", self.items, "a")
        except ValueError as exc:
            self.assertIsInstance(
                exc, InvalidFinalForkDecisionAggregateAnchorError)
            self.assertNotIsInstance(
                exc, InvalidFinalForkDecisionAggregateChainError)
        else:
            self.fail("a trailing byte must raise")


class DecisionBatchRefactorEquivalenceTest(
    FinalForkDecisionAggregateChainForkDecisionFixtures,
    unittest.TestCase
):
    """The extracted decision batch layer reports exactly what the
    single-decision entry point rules, in input order and in isolation."""

    def test_legal_batch_rows_equal_the_single_decision_results(self):
        report = self.cfd_batch_report(self.fdecision_items())
        self.assertEqual(list(report.keys()), ["items", "version"])
        for item, decision in zip(
            report["items"], (self.decision_ja, self.decision_jb)
        ):
            self.assertEqual(item["status"], "verified")
            self.assertEqual(
                item["result"],
                verify_final_fork_decision_aggregate_chain_fork_decision(
                    decision, self.policy, self.auth, self.ssp,
                    self.fsignerp, self.adjp, self.proofp, self.ring,
                    self.m))

    def test_fork_free_decisions_verify_with_empty_common(self):
        report = self.cfd_batch_report([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb)])
        for item in report["items"]:
            self.assertEqual(item["status"], "verified")
            self.assertEqual(item["result"]["common"], [])

    def test_one_bad_decision_never_blocks_or_alters_later_ones(self):
        tampered = parse(self.decision_ja)["payload"]
        tampered["status"] = "insufficient"
        items = [
            decision_item("garbage", b"{"),
            decision_item("tampered", self.rewrap(tampered)),
            decision_item("ok", self.decision_jb),
        ]
        report = self.cfd_batch_report(items)
        self.assertEqual(
            [i["status"] for i in report["items"]],
            ["invalid-decision", "invalid-decision", "verified"])
        self.assertEqual([i["id"] for i in report["items"]],
                         ["garbage", "tampered", "ok"])
        self.assertIsNone(report["items"][2]["error"])

    def test_reports_are_equal_but_deeply_independent(self):
        first = self.cfd_batch_report(self.fdecision_items())
        second = self.cfd_batch_report(self.fdecision_items())
        self.assertEqual(first, second)
        first["items"][0]["result"]["items"][0]["conclusion"] = "x"
        again = self.cfd_batch_report(self.fdecision_items())
        self.assertEqual(again, second)

    def test_batch_is_validated_before_any_decision_runs(self):
        garbage = decision_item("one", b"{")
        with self.assertRaises(TypeError):
            self.cfd_batch_report((garbage,))
        with self.assertRaises(ValueError):
            self.cfd_batch_report([])
        with self.assertRaises(ValueError):
            self.cfd_batch_report([garbage, decision_item("one", b"{")])
        with self.assertRaises(TypeError):
            self.cfd_batch_report([garbage], moment=True)
        with self.assertRaises(ValueError):
            self.cfd_batch_report([garbage], moment=-1)


class CrossSiteAggregateRefactorEquivalenceTest(
    FinalForkDecisionAggregateChainForkDecisionFixtures,
    unittest.TestCase
):
    """The extracted cross-site aggregate seals one canonical packet
    whose every binding is recomputed by the offline review."""

    def test_sealing_is_byte_for_byte_deterministic(self):
        first = self.cfd_make_aggregate(self.fdecision_items())
        second = self.cfd_make_aggregate(self.fdecision_items())
        self.assertEqual(first, second)
        self.assertEqual(_prune_compact(parse(first)), first)

    def test_legal_aggregate_verifies_and_binds_everything(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        result = self.cfd_verify_aggregate(raw)
        payload = parse(raw)["payload"]
        self.assertEqual(result["aggregateDigest"],
                         hashlib.sha256(raw).hexdigest())
        for key in payload:
            self.assertEqual(result[key], payload[key], key)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(
            result["inputs"],
            [hashlib.sha256(d).hexdigest()
             for d in (self.decision_ja, self.decision_jb)])

    def test_fork_free_consensus_binds_the_empty_common_set(self):
        raw = self.cfd_make_aggregate([
            decision_item("one", self.free_ja),
            decision_item("two", self.free_jb)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["declaration"]["common"], [])

    def test_threshold_shortfall_keeps_the_common_declaration(self):
        raw = self.cfd_make_aggregate(
            [decision_item("one", self.decision_ja)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNotNone(result["declaration"])

    def test_cross_site_contradiction_conflicts_with_no_majority(self):
        dsp3 = {"sites": {JUDGE: {1}, JUDGE_B: {1}, SITE_A: {1}},
                "threshold": 2}
        free_c = self.ffdacf_judge(self.free_proof_items, issuer=SITE_A)
        raw = self.cfd_make_aggregate([
            decision_item("a", self.decision_ja),
            decision_item("b", self.decision_jb),
            decision_item("c", free_c)], dsp=dsp3)
        result = self.cfd_verify_aggregate(raw, dsp=dsp3)
        self.assertEqual(result["status"], "conflicted")
        self.assertIsNone(result["declaration"])

    def test_one_bad_item_never_blocks_the_other_votes(self):
        raw = self.cfd_make_aggregate([
            decision_item("bad", b"{"),
            decision_item("one", self.decision_ja),
            decision_item("two", self.decision_jb)])
        result = self.cfd_verify_aggregate(raw)
        self.assertEqual(result["status"], "accepted")
        rows = {r["id"]: r for r in result["items"]}
        self.assertEqual(rows["bad"]["conclusion"], "invalid")
        self.assertIsNone(rows["bad"]["issuer"])
        self.assertEqual(rows["one"]["conclusion"], "valid")
        self.assertEqual(rows["two"]["conclusion"], "valid")

    def test_every_policy_digest_binding_is_recomputed(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        for field in DIGEST_FIELDS:
            payload = parse(raw)["payload"]
            payload[field] = "9" * 64
            self.assert_invalid(self.rewrap(payload), )

    def test_input_digest_vector_is_recomputed(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        payload = parse(raw)["payload"]
        payload["inputs"][0] = "ab" * 32
        self.assert_invalid(self.rewrap(payload))

    def test_declaration_row_ordering_is_recomputed(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        payload = parse(raw)["payload"]
        payload["items"] = list(reversed(payload["items"]))
        self.assert_invalid(self.rewrap(payload))

    def test_proof_digest_order_is_recomputed(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        payload = parse(raw)["payload"]
        declaration = payload["items"][0]["declaration"]
        declaration["proofs"] = list(reversed(declaration["proofs"]))
        self.assert_invalid(self.rewrap(payload))

    def test_signature_and_credential_boundaries(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        tampered = parse(raw)
        tampered["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.cfd_verify_aggregate(_prune_compact(tampered))
        rotated = copy.deepcopy(self.ring)
        rotated[JUDGE] = rotated[JUDGE] + [entry(2, SECRET_V2_A)]
        rotated_raw = self.cfd_make_aggregate(
            self.fdecision_items(), ring=rotated, issuer=JUDGE, version=2)
        result = self.cfd_verify_aggregate(rotated_raw, ring=rotated)
        self.assertEqual(result["keyVersion"], 2)
        for broken in (
            [entry(2, SECRET_V2_A, revoked=True)],
            [entry(2, SECRET_V2_A, not_before=self.m + 1)],
            [entry(2, SECRET_V2_A, not_after=self.m - 1)],
        ):
            ring = copy.deepcopy(self.ring)
            ring[JUDGE] = broken
            with self.assertRaises(AuthenticationError):
                self.cfd_verify_aggregate(rotated_raw, ring=ring)

    def test_results_are_equal_but_deeply_independent(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        first = self.cfd_verify_aggregate(raw)
        second = self.cfd_verify_aggregate(raw)
        self.assertEqual(first, second)
        first["items"][0]["declaration"]["common"].append("x")
        first["declaration"]["status"] = "x"
        again = self.cfd_verify_aggregate(raw)
        self.assertEqual(again, second)

    def test_error_class_stays_distinct(self):
        raw = self.cfd_make_aggregate(self.fdecision_items())
        try:
            self.cfd_verify_aggregate(raw + b"\n")
        except ValueError as exc:
            self.assertIsInstance(
                exc,
                InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError)
        else:
            self.fail("a trailing byte must raise")


class UnaffectedLegacyBehaviorTest(unittest.TestCase):
    """The older layers -- recovery, storage, state merge, the audit
    proof chain and the status command -- are untouched by the
    extraction."""

    def test_recovery_behavior_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "missing.ledger")
            verdict = recover_ledger(missing)
            self.assertEqual(verdict["status"], "clean")
            self.assertIsNone(verdict["digest"])
            report = inspect_recovery([missing])
            self.assertEqual(report[0]["status"], "clean")
            self.assertEqual(report[0]["path"], missing)

    def test_storage_roundtrip_is_unchanged(self):
        from offline_coordination import storage
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            state = {
                "clock": {"node-a": 1},
                "records": {
                    "k": ["v", False, {"node-a": 1}, "node-a"],
                },
            }
            storage.save_state(path, state)
            self.assertEqual(storage.load_state(path), state)

    def test_state_merge_is_unchanged(self):
        from offline_coordination.merge import merge_states
        left = {
            "clock": {"a": 1},
            "records": {"x": ["left", False, {"a": 1}, "a"]},
        }
        right = {
            "clock": {"b": 1},
            "records": {"y": ["right", False, {"b": 1}, "b"]},
        }
        merged = merge_states(left, right)
        self.assertEqual(merged["clock"], {"a": 1, "b": 1})
        self.assertEqual(
            merged["records"],
            {"x": ["left", False, {"a": 1}, "a"],
             "y": ["right", False, {"b": 1}, "b"]})
        self.assertEqual(
            left,
            {"clock": {"a": 1},
             "records": {"x": ["left", False, {"a": 1}, "a"]}})

    def test_audit_proof_chain_is_unchanged(self):
        from offline_coordination import audit
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            audit.append(path, {"source": "node", "kind": "local",
                                "detail": "one"})
            audit.append(path, {"source": "node", "kind": "merge",
                                "detail": "two"})
            records = audit.read(path)
            self.assertEqual([r["seq"] for r in records], [1, 2])
            self.assertEqual(records[0]["kind"], "local")
            self.assertEqual(records[1]["kind"], "merge")
            self.assertEqual(records[1]["prev"], records[0]["hash"])

    def test_status_function_is_unchanged(self):
        from offline_coordination.__main__ import status
        report = status()
        self.assertEqual(report["connectivity"], "offline")
        self.assertEqual(report["nodeId"], "local-node")
        self.assertEqual(report["pendingChanges"], 0)
        self.assertEqual(report["revision"], 0)


if __name__ == "__main__":
    unittest.main()
