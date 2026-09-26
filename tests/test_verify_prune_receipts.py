"""Tests for offline verification of signed chain prune receipts.

Covers :func:`verify_prune_receipt` and :func:`verify_prune_receipts`:
the version-1 canonical receipt and embedded-plan contract, the
receipt/plan/checkpoint triple binding (checkpoint digest, delete and
retain equality, signing identity and exact key version), unique
project location from status and before/after digests, independent
version-1 marker regeneration with no trust in receipt-derived
digests, the ``pruned``/``duplicate`` branch rules, the fixed single
and batch result shapes with result freshness and independence, the
batch container contract with full pre-validation, per-item isolation
across ``verified``/``invalid``/``unauthenticated``, credential and
three-layer signature rules, and the purely offline, read-only
guarantee.
"""

import copy
import hashlib
import hmac
import json
import os
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination import replication
from offline_coordination.replication import (
    AuthenticationError,
    prune_chain_archives,
    verify_prune_receipt,
    verify_prune_receipts,
)

from test_chain_prune import PruneFixtures
from test_fork_convergence import (
    COORD,
    RING,
    SECRET_COORD,
    compact,
    entry,
    parse,
)

RESULT_KEYS = [
    "project", "status", "beforeDigest", "afterDigest", "checkpoint",
    "plan", "moment", "version",
]
TOP_KEYS = ["items", "version"]
REPORT_KEYS = ["error", "id", "result", "status"]

INVALID = "invalid"
UNAUTHENTICATED = "unauthenticated"
VERIFIED = "verified"


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def sign(payload, secret=SECRET_COORD):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def resign_receipt(receipt, mutate, secret=SECRET_COORD):
    """Copy a receipt envelope, mutate its payload and re-sign it."""
    data = copy.deepcopy(parse(receipt))
    mutate(data["payload"])
    data["signature"] = sign(data["payload"], secret)
    return compact(data)


def resign_plan(plan, mutate, secret=SECRET_COORD):
    """Copy a plan envelope, mutate its payload and re-sign it."""
    data = copy.deepcopy(parse(plan))
    mutate(data["payload"])
    data["signature"] = sign(data["payload"], secret)
    return compact(data)


def fresh_fixture():
    fixture = PruneFixtures()
    fixture.setUp()
    return fixture


def issue_pruned(fixture, name="c", names=("c", "a", "g"), ring=RING):
    plan = fixture.make_plan(names)
    report = prune_chain_archives(
        [fixture.batch_item(f"item-{name}", name, plan)], ring
    )[0]
    assert report["error"] is None, report["error"]
    return report["receipt"], plan


def issue_duplicate(fixture, name="c", names=("c", "a", "g"), ring=RING):
    plan = fixture.make_plan(names)
    with open(fixture.paths[name], "wb") as handle:
        handle.write(replication._prune_pruned_bytes(name))
    report = prune_chain_archives(
        [fixture.batch_item(f"item-{name}", name, plan)], ring
    )[0]
    assert report["error"] is None, report["error"]
    return report["receipt"], plan


def embed_plan(receipt, plan, mutate=None, secret=SECRET_COORD):
    """Re-embed a (possibly modified) plan into a receipt and re-sign."""
    data = copy.deepcopy(parse(receipt))
    data["payload"]["plan"] = parse(plan)
    if mutate is not None:
        mutate(data["payload"])
    data["signature"] = sign(data["payload"], secret)
    return compact(data)


class ReceiptVerificationTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = []

    def tearDown(self):
        for fixture in self.fixtures:
            shutil.rmtree(fixture.tmp, ignore_errors=True)

    def fixture(self):
        fixture = fresh_fixture()
        self.fixtures.append(fixture)
        return fixture

    def pruned(self, *args, **kwargs):
        fixture = self.fixture()
        return fixture, *issue_pruned(fixture, *args, **kwargs)

    def duplicated(self, *args, **kwargs):
        fixture = self.fixture()
        return fixture, *issue_duplicate(fixture, *args, **kwargs)

    # -- single-entry result shape ---------------------------------------

    def test_pruned_result_shape_and_bindings(self):
        fixture, receipt, plan = self.pruned()
        result = verify_prune_receipt(
            receipt, fixture.checkpoint, RING, fixture.moment
        )
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertEqual(result["project"], "c")
        self.assertEqual(result["status"], "pruned")
        self.assertEqual(result["checkpoint"], sha256(fixture.checkpoint))
        self.assertEqual(result["plan"], sha256(plan))
        self.assertEqual(result["moment"], fixture.moment)
        self.assertEqual(result["version"], 1)
        self.assertNotIsInstance(result["version"], bool)
        plan_payload = parse(plan)["payload"]
        self.assertEqual(result["beforeDigest"],
                         plan_payload["source"]["c"])
        self.assertEqual(result["afterDigest"],
                         plan_payload["target"]["c"])

    def test_duplicate_result_has_equal_before_and_after(self):
        fixture, receipt, plan = self.duplicated()
        result = verify_prune_receipt(
            receipt, fixture.checkpoint, RING, fixture.moment
        )
        self.assertEqual(result["status"], "duplicate")
        target = parse(plan)["payload"]["target"]["c"]
        self.assertEqual(result["beforeDigest"], target)
        self.assertEqual(result["afterDigest"], target)

    def test_project_is_located_inside_a_multi_project_plan(self):
        fixture, receipt, _plan = self.pruned("a", names=("c", "a"))
        result = verify_prune_receipt(
            receipt, fixture.checkpoint, RING, fixture.moment
        )
        self.assertEqual(result["project"], "a")

    def test_repeated_verification_is_equal_but_independent(self):
        fixture, receipt, _plan = self.pruned()
        first = verify_prune_receipt(
            receipt, fixture.checkpoint, RING, fixture.moment
        )
        second = verify_prune_receipt(
            receipt, fixture.checkpoint, RING, fixture.moment
        )
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_non_ascii_project_round_trips(self):
        fixture = self.fixture()
        name = "项目-α"
        fixture.projects = {name: fixture.cert_coord}
        fixture.paths = {name: f"{fixture.tmp}/p.arc"}
        fixture.write_archive(name, fixture.cert_coord)
        plan = fixture.make_plan((name,))
        report = prune_chain_archives(
            [fixture.batch_item("i", name, plan)], RING
        )[0]
        self.assertIsNone(report["error"])
        result = verify_prune_receipt(
            report["receipt"], fixture.checkpoint, RING, fixture.moment
        )
        self.assertEqual(result["project"], name)

    # -- independent marker recomputation --------------------------------

    def test_plan_target_is_checked_against_recomputed_marker(self):
        # A fully self-consistent forgery: the plan lies about the
        # target digest and the receipt repeats the same lie, both
        # correctly signed.  Location succeeds (the lie agrees with
        # itself), but the verifier regenerates the version-1 marker
        # and rejects the receipt instead of trusting the derived
        # digest.
        fixture, receipt, plan = self.pruned()
        bogus = "0" * 64
        bad_plan = resign_plan(
            plan,
            lambda payload: payload["target"].__setitem__("c", bogus),
        )
        bad_receipt = embed_plan(
            receipt, bad_plan,
            mutate=lambda payload: payload.__setitem__("afterDigest", bogus),
        )
        with self.assertRaisesRegex(ValueError, "pruned marker"):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_a_dishonest_after_digest_never_locates_a_project(self):
        # The honest plan's target is the real marker; a receipt that
        # names another afterDigest matches no plan target.
        fixture, receipt, _plan = self.pruned()
        bad_receipt = resign_receipt(
            receipt,
            lambda payload: payload.__setitem__("afterDigest", "9" * 64),
        )
        with self.assertRaisesRegex(ValueError, "uniquely"):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_status_and_digests_must_uniquely_name_a_project(self):
        fixture, receipt, plan = self.pruned()
        plan_payload = parse(plan)["payload"]

        def force_collision(payload):
            payload["source"]["a"] = plan_payload["source"]["c"]
            payload["target"]["a"] = plan_payload["target"]["c"]

        colliding_plan = resign_plan(plan, force_collision)
        data = copy.deepcopy(parse(receipt))
        data["payload"]["plan"] = parse(colliding_plan)
        data["payload"]["delete"] = ["a", "c"]
        data["payload"]["beforeDigest"] = plan_payload["source"]["c"]
        data["payload"]["afterDigest"] = plan_payload["target"]["c"]
        data["signature"] = sign(data["payload"])
        with self.assertRaisesRegex(ValueError, "uniquely"):
            verify_prune_receipt(
                compact(data), fixture.checkpoint, RING, fixture.moment
            )

    def test_no_candidate_is_rejected(self):
        fixture, receipt, _plan = self.pruned()
        bad_receipt = resign_receipt(
            receipt,
            lambda payload: payload.__setitem__("beforeDigest", "8" * 64),
        )
        with self.assertRaisesRegex(ValueError, "uniquely"):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_pruned_requires_before_equal_source(self):
        fixture, receipt, plan = self.pruned()
        target = parse(plan)["payload"]["target"]["c"]
        bad_receipt = resign_receipt(
            receipt,
            lambda payload, target=target:
                payload.__setitem__("beforeDigest", target),
        )
        with self.assertRaises(ValueError):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_duplicate_requires_both_digests_equal_target(self):
        fixture, receipt, plan = self.duplicated()
        source = parse(plan)["payload"]["source"]["c"]
        bad_receipt = resign_receipt(
            receipt,
            lambda payload, source=source:
                payload.__setitem__("beforeDigest", source),
        )
        with self.assertRaises(ValueError):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    # -- bindings ---------------------------------------------------------

    def test_delete_must_equal_the_plan_exactly(self):
        fixture, receipt, _plan = self.pruned()
        for mutate in (
            lambda p: p.__setitem__("delete", []),
            lambda p: p.__setitem__("delete", ["a"]),
            lambda p: p.__setitem__("delete", ["c", "a"]),
            lambda p: p.__setitem__("delete", ["x"]),
        ):
            with self.subTest():
                with self.assertRaises(ValueError):
                    verify_prune_receipt(
                        resign_receipt(receipt, mutate),
                        fixture.checkpoint, RING, fixture.moment,
                    )

    def test_retain_must_equal_the_plan_exactly(self):
        fixture, receipt, _plan = self.pruned()
        bad_receipt = resign_receipt(
            receipt, lambda p: p.__setitem__("retain", ["0" * 64])
        )
        with self.assertRaises(ValueError):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_receipt_must_bind_the_checkpoint_bytes(self):
        fixture, receipt, _plan = self.pruned()
        bad_receipt = resign_receipt(
            receipt, lambda p: p.__setitem__("checkpoint", "0" * 64)
        )
        with self.assertRaises(ValueError):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_plan_must_bind_the_checkpoint_bytes(self):
        fixture, receipt, plan = self.pruned()
        bad_plan = resign_plan(
            plan, lambda p: p.__setitem__("checkpoint", "0" * 64)
        )
        bad_receipt = embed_plan(receipt, bad_plan)
        with self.assertRaises(ValueError):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_a_different_valid_checkpoint_is_rejected(self):
        fixture, receipt, _plan = self.pruned()
        other = fixture.other_checkpoint()
        with self.assertRaises((ValueError, AuthenticationError)):
            verify_prune_receipt(
                receipt, other, RING, fixture.moment
            )

    def test_embedded_plan_with_illegal_shape_is_invalid(self):
        fixture, receipt, _plan = self.pruned()
        bad_receipt = resign_receipt(
            receipt, lambda p: p.__setitem__("plan", {"unexpected": True})
        )
        with self.assertRaises(ValueError):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    # -- content faults ---------------------------------------------------

    def test_encoding_faults_are_invalid(self):
        fixture, receipt, _plan = self.pruned()
        spaced = json.dumps(parse(receipt)).encode("utf-8")
        for raw in (b"", b"nope", receipt + b"\n", receipt + b" ", spaced):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(ValueError):
                    verify_prune_receipt(
                        raw, fixture.checkpoint, RING, fixture.moment
                    )

    def test_key_sets_are_checked(self):
        fixture, receipt, _plan = self.pruned()
        for mutate in (
            lambda d: d.pop("signature"),
            lambda d: d.__setitem__("extra", 1),
            lambda d: d["payload"].__setitem__("extra", 1),
            lambda d: d["payload"].pop("status"),
        ):
            data = copy.deepcopy(parse(receipt))
            mutate(data)
            with self.subTest():
                with self.assertRaises(ValueError):
                    verify_prune_receipt(
                        compact(data), fixture.checkpoint, RING,
                        fixture.moment,
                    )

    def test_bad_version_status_digest_and_moment_are_invalid(self):
        fixture, receipt, _plan = self.pruned()
        cases = [
            lambda p: p.__setitem__("version", 2),
            lambda p: p.__setitem__("version", True),
            lambda p: p.__setitem__("status", "weird"),
            lambda p: p.__setitem__("moment", -1),
            lambda p: p.__setitem__("moment", True),
            lambda p: p.__setitem__("checkpoint", "zz"),
            lambda p: p.__setitem__("delete", [""]),
            lambda p: p.__setitem__("retain", ["zz"]),
        ]
        for mutate in cases:
            with self.subTest():
                with self.assertRaises(ValueError):
                    verify_prune_receipt(
                        resign_receipt(receipt, mutate),
                        fixture.checkpoint, RING, fixture.moment,
                    )

    def test_garbage_checkpoint_is_invalid(self):
        fixture, receipt, _plan = self.pruned()
        with self.assertRaises(ValueError):
            verify_prune_receipt(
                receipt, b"not-a-checkpoint", RING, fixture.moment
            )

    def test_invalid_receipt_error_subclasses_value_error(self):
        from offline_coordination.replication import InvalidPruneReceiptError
        self.assertTrue(issubclass(InvalidPruneReceiptError, ValueError))
        fixture, receipt, _plan = self.pruned()
        with self.assertRaises(InvalidPruneReceiptError):
            verify_prune_receipt(
                b"nope", fixture.checkpoint, RING, fixture.moment
            )

    def test_public_argument_types(self):
        fixture, receipt, _plan = self.pruned()
        with self.assertRaises(TypeError):
            verify_prune_receipt(
                "x", fixture.checkpoint, RING, fixture.moment
            )
        with self.assertRaises(TypeError):
            verify_prune_receipt(receipt, "x", RING, fixture.moment)
        with self.assertRaises(TypeError):
            verify_prune_receipt(
                receipt, fixture.checkpoint, "x", fixture.moment
            )
        with self.assertRaises(ValueError):
            verify_prune_receipt(
                receipt, fixture.checkpoint, RING, -1
            )
        for bad_moment in (True, "1", 1.5):
            with self.assertRaises(TypeError):
                verify_prune_receipt(
                    receipt, fixture.checkpoint, RING, bad_moment
                )

    # -- authentication ---------------------------------------------------

    def test_credential_states_are_unauthenticated(self):
        fixture, receipt, _plan = self.pruned()
        cases = {
            "unknown": {},
            "revoked": {
                **RING, COORD: [entry(1, SECRET_COORD, revoked=True)],
            },
            "not-yet-valid": {
                **RING,
                COORD: [entry(1, SECRET_COORD,
                              not_before=fixture.moment + 1)],
            },
            "expired": {
                **RING,
                COORD: [entry(1, SECRET_COORD,
                              not_after=fixture.moment - 1)],
            },
        }
        for label, ring in cases.items():
            with self.subTest(label):
                with self.assertRaises(AuthenticationError):
                    verify_prune_receipt(
                        receipt, fixture.checkpoint, ring, fixture.moment
                    )

    def test_expired_verification_moment_is_unauthenticated(self):
        fixture, receipt, _plan = self.pruned()
        with self.assertRaises(AuthenticationError):
            verify_prune_receipt(
                receipt, fixture.checkpoint, RING, 10 ** 12
            )

    def test_wrong_receipt_signature_is_unauthenticated(self):
        fixture, receipt, _plan = self.pruned()
        data = parse(receipt)
        signature = data["signature"]
        data["signature"] = ("0" if signature[0] != "0" else "1") + \
            signature[1:]
        with self.assertRaises(AuthenticationError):
            verify_prune_receipt(
                compact(data), fixture.checkpoint, RING, fixture.moment
            )

    def test_wrong_plan_signature_is_unauthenticated(self):
        fixture, receipt, plan = self.pruned()
        plan_data = parse(plan)
        plan_data["signature"] = "0" * 64
        bad_receipt = embed_plan(receipt, compact(plan_data))
        with self.assertRaises(AuthenticationError):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_wrong_checkpoint_signature_is_unauthenticated(self):
        # Flip the checkpoint HMAC and re-bind both layers to the
        # resulting checkpoint bytes' digest, so verification reaches
        # (and fails at) the checkpoint signature check rather than the
        # earlier binding comparison.
        fixture, receipt, plan = self.pruned()
        cp_data = parse(fixture.checkpoint)
        cp_data["signature"] = "0" * 64
        tampered_checkpoint = compact(cp_data)
        tampered_digest = sha256(tampered_checkpoint)
        rebound_plan = resign_plan(
            plan,
            lambda p: p.__setitem__("checkpoint", tampered_digest),
        )
        rebound_receipt = embed_plan(
            receipt, rebound_plan,
            mutate=lambda p: p.__setitem__("checkpoint", tampered_digest),
        )
        with self.assertRaises(AuthenticationError):
            verify_prune_receipt(
                rebound_receipt, tampered_checkpoint, RING, fixture.moment
            )

    def test_plan_signed_by_another_key_is_unauthenticated(self):
        fixture, receipt, plan = self.pruned()
        bad_plan = resign_plan(
            plan, lambda payload: None, secret="77" * 32
        )
        bad_receipt = embed_plan(receipt, bad_plan)
        with self.assertRaises(AuthenticationError):
            verify_prune_receipt(
                bad_receipt, fixture.checkpoint, RING, fixture.moment
            )

    def test_no_key_version_fallback(self):
        fixture, receipt, _plan = self.pruned()
        v2_ring = {**RING, COORD: [entry(2, SECRET_COORD)]}
        with self.assertRaises(AuthenticationError):
            verify_prune_receipt(
                receipt, fixture.checkpoint, v2_ring, fixture.moment
            )

    def test_three_layers_use_the_current_key(self):
        fixture, receipt, _plan = self.pruned()
        rotated = {
            **RING,
            COORD: [
                entry(1, SECRET_COORD, revoked=True),
                entry(2, "22" * 32, not_before=fixture.moment),
            ],
        }
        with self.assertRaises(AuthenticationError):
            verify_prune_receipt(
                receipt, fixture.checkpoint, rotated, fixture.moment
            )


class BatchVerificationTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = []

    def tearDown(self):
        for fixture in self.fixtures:
            shutil.rmtree(fixture.tmp, ignore_errors=True)

    def fixture(self):
        fixture = fresh_fixture()
        self.fixtures.append(fixture)
        return fixture

    def batch(self, items, ring=RING, moment=None, fixture=None):
        if fixture is None:
            fixture = self.fixtures[0]
        if moment is None:
            moment = fixture.moment
        return verify_prune_receipts(items, ring, moment)

    # -- shape ------------------------------------------------------------

    def test_top_level_shape_and_version(self):
        fixture = self.fixture()
        receipt, _plan = issue_pruned(fixture)
        result = self.batch(
            [{"id": "one", "receipt": receipt,
              "checkpoint": fixture.checkpoint}],
            fixture=fixture,
        )
        self.assertEqual(list(result.keys()), TOP_KEYS)
        self.assertEqual(result["version"], 1)
        self.assertNotIsInstance(result["version"], bool)
        self.assertIsInstance(result["items"], list)

    def test_report_shape_for_verified(self):
        fixture = self.fixture()
        receipt, plan = issue_pruned(fixture)
        report = self.batch(
            [{"id": "one", "receipt": receipt,
              "checkpoint": fixture.checkpoint}],
            fixture=fixture,
        )["items"][0]
        self.assertEqual(list(report.keys()), REPORT_KEYS)
        self.assertEqual(report["id"], "one")
        self.assertEqual(report["status"], VERIFIED)
        self.assertIsNone(report["error"])
        self.assertEqual(list(report["result"].keys()), RESULT_KEYS)
        self.assertEqual(report["result"]["plan"], sha256(plan))

    # -- preflight --------------------------------------------------------

    def test_type_faults(self):
        fixture = self.fixture()
        receipt, _plan = issue_pruned(fixture)
        good = {"id": "ok", "receipt": receipt,
                "checkpoint": fixture.checkpoint}
        cases = [
            (good,),
            [good, "not-a-dict"],
            [good, {"id": 1, "receipt": receipt,
                    "checkpoint": fixture.checkpoint}],
            [good, {"id": "x", "receipt": "bytes",
                    "checkpoint": fixture.checkpoint}],
            [good, {"id": "x", "receipt": receipt,
                    "checkpoint": "bytes"}],
        ]
        for items in cases:
            with self.subTest():
                with self.assertRaises(TypeError):
                    self.batch(items, fixture=fixture)

    def test_value_faults(self):
        fixture = self.fixture()
        receipt, _plan = issue_pruned(fixture)
        cases = [
            [],
            [{"id": "", "receipt": receipt,
              "checkpoint": fixture.checkpoint}],
            [{"id": "ok", "receipt": receipt,
              "checkpoint": fixture.checkpoint, "extra": 1}],
            [{"id": "ok"}],
            [{"receipt": receipt, "checkpoint": fixture.checkpoint}],
        ]
        for items in cases:
            with self.subTest():
                with self.assertRaises(ValueError):
                    self.batch(items, fixture=fixture)

    def test_duplicate_ids_are_value_errors(self):
        fixture = self.fixture()
        receipt, _plan = issue_pruned(fixture)
        good = {"id": "ok", "receipt": receipt,
                "checkpoint": fixture.checkpoint}
        with self.assertRaises(ValueError):
            self.batch([good, dict(good)], fixture=fixture)

    def test_batch_is_fully_preflighted_before_any_verification(self):
        fixture = self.fixture()
        broken = [
            {"id": "ok", "receipt": b"garbage",
             "checkpoint": fixture.checkpoint},
            {"id": 7, "receipt": b"garbage",
             "checkpoint": fixture.checkpoint},
        ]
        with self.assertRaises(TypeError):
            self.batch(broken, fixture=fixture)
        duplicate_bad = [
            {"id": "dup", "receipt": b"", "checkpoint": fixture.checkpoint},
            {"id": "dup", "receipt": b"", "checkpoint": fixture.checkpoint},
        ]
        with self.assertRaises(ValueError):
            self.batch(duplicate_bad, fixture=fixture)

    def test_keyring_and_moment_keep_single_entry_classification(self):
        fixture = self.fixture()
        receipt, _plan = issue_pruned(fixture)
        good = [{"id": "ok", "receipt": receipt,
                 "checkpoint": fixture.checkpoint}]
        with self.assertRaises(TypeError):
            self.batch(good, ring="x", fixture=fixture)
        with self.assertRaises(ValueError):
            self.batch(
                good,
                ring={COORD: [{"version": 1, "secret": "zz",
                               "notBefore": 0, "notAfter": 1,
                               "revoked": False}]},
                fixture=fixture,
            )
        with self.assertRaises(ValueError):
            self.batch(good, moment=-1, fixture=fixture)
        for bad_moment in (True, "1", 1.5):
            with self.assertRaises(TypeError):
                self.batch(good, moment=bad_moment, fixture=fixture)

    # -- per-item isolation ----------------------------------------------

    def test_mixed_statuses_verify_in_input_order(self):
        # One batch carries invalid, verified and unauthenticated items
        # (each pairing its own receipt with its own checkpoint); no
        # item's failure affects any other.
        pruned_fixture = self.fixture()
        pruned_receipt, _ = issue_pruned(pruned_fixture, "c")
        duplicate_fixture = self.fixture()
        duplicate_receipt, _ = issue_duplicate(
            duplicate_fixture, "a", names=("c", "a")
        )
        # A structurally valid receipt whose receipt-layer signature is
        # wrong is unauthenticated, not invalid.
        bad_signature = copy.deepcopy(parse(pruned_receipt))
        signature = bad_signature["signature"]
        bad_signature["signature"] = (
            ("0" if signature[0] != "0" else "1") + signature[1:]
        )
        items = [
            {"id": "garbage", "receipt": b"nope",
             "checkpoint": pruned_fixture.checkpoint},
            {"id": "pruned", "receipt": pruned_receipt,
             "checkpoint": pruned_fixture.checkpoint},
            {"id": "bad-signature", "receipt": compact(bad_signature),
             "checkpoint": pruned_fixture.checkpoint},
            {"id": "duplicate", "receipt": duplicate_receipt,
             "checkpoint": duplicate_fixture.checkpoint},
            {"id": "bad-binding",
             "receipt": resign_receipt(
                 pruned_receipt,
                 lambda p: p.__setitem__("checkpoint", "0" * 64),
             ),
             "checkpoint": pruned_fixture.checkpoint},
        ]
        result = verify_prune_receipts(
            items, RING, pruned_fixture.moment
        )
        self.assertEqual(
            [report["id"] for report in result["items"]],
            [item["id"] for item in items],
        )
        self.assertEqual(
            [report["status"] for report in result["items"]],
            [INVALID, VERIFIED, UNAUTHENTICATED, VERIFIED, INVALID],
        )

    def test_revoked_credentials_report_in_isolation(self):
        fixture = self.fixture()
        receipt, _ = issue_pruned(fixture)
        revoked_ring = {
            **RING,
            COORD: [entry(1, SECRET_COORD, revoked=True)],
        }
        result = verify_prune_receipts(
            [
                {"id": "revoked", "receipt": receipt,
                 "checkpoint": fixture.checkpoint},
                {"id": "invalid", "receipt": b"nope",
                 "checkpoint": fixture.checkpoint},
            ],
            revoked_ring, fixture.moment,
        )
        revoked, invalid = result["items"]
        self.assertEqual(revoked["status"], UNAUTHENTICATED)
        self.assertIsNone(revoked["result"])
        self.assertTrue(revoked["error"])
        # A structural fault stays invalid even when the credentials are
        # also unusable.
        self.assertEqual(invalid["status"], INVALID)

    def test_failed_items_have_null_result_and_non_empty_error(self):
        fixture = self.fixture()
        receipt, _ = issue_pruned(fixture)
        result = verify_prune_receipts(
            [
                {"id": "bad", "receipt": b"nope",
                 "checkpoint": fixture.checkpoint},
                {"id": "good", "receipt": receipt,
                 "checkpoint": fixture.checkpoint},
            ],
            RING, fixture.moment,
        )
        bad, good = result["items"]
        self.assertEqual(bad["status"], INVALID)
        self.assertIsNone(bad["result"])
        self.assertIsInstance(bad["error"], str)
        self.assertNotEqual(bad["error"], "")
        self.assertEqual(good["status"], VERIFIED)
        self.assertIsNone(good["error"])
        self.assertIsNotNone(good["result"])

    def test_invalid_before_verified_does_not_stop_the_batch(self):
        fixture = self.fixture()
        receipt, _ = issue_pruned(fixture)
        result = verify_prune_receipts(
            [
                {"id": "bad", "receipt": b"nope",
                 "checkpoint": fixture.checkpoint},
                {"id": "good", "receipt": receipt,
                 "checkpoint": fixture.checkpoint},
            ],
            RING, fixture.moment,
        )
        self.assertEqual(
            [report["status"] for report in result["items"]],
            [INVALID, VERIFIED],
        )

    # -- freshness / offline ---------------------------------------------

    def test_repeated_batch_calls_are_equal_but_independent(self):
        fixture = self.fixture()
        receipt, _ = issue_pruned(fixture)
        items = [{"id": "one", "receipt": receipt,
                  "checkpoint": fixture.checkpoint}]
        first = verify_prune_receipts(items, RING, fixture.moment)
        second = verify_prune_receipts(items, RING, fixture.moment)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(first["items"][0]["result"],
                         second["items"][0]["result"])

    def test_results_do_not_share_mutable_objects_with_inputs(self):
        fixture = self.fixture()
        receipt, _ = issue_pruned(fixture)
        items = [{"id": "one", "receipt": receipt,
                  "checkpoint": fixture.checkpoint}]
        result = verify_prune_receipts(items, RING, fixture.moment)
        result["items"].append("tampered")
        result["items"][0]["result"]["status"] = "tampered"
        again = verify_prune_receipts(items, RING, fixture.moment)
        self.assertEqual(len(again["items"]), 1)
        self.assertEqual(again["items"][0]["result"]["status"], "pruned")

    def test_no_input_is_modified(self):
        fixture = self.fixture()
        receipt, _ = issue_pruned(fixture)
        items = [{"id": "one", "receipt": receipt,
                  "checkpoint": fixture.checkpoint}]
        items_copy = copy.deepcopy(items)
        ring_copy = copy.deepcopy(RING)
        verify_prune_receipts(items, RING, fixture.moment)
        self.assertEqual(items, items_copy)
        self.assertEqual(RING, ring_copy)

    def test_no_file_is_read_or_written(self):
        fixture = self.fixture()
        receipt, _ = issue_pruned(fixture)
        with mock.patch("builtins.open",
                        side_effect=AssertionError("no file I/O")):
            single = verify_prune_receipt(
                receipt, fixture.checkpoint, RING, fixture.moment
            )
            batch = verify_prune_receipts(
                [{"id": "one", "receipt": receipt,
                  "checkpoint": fixture.checkpoint}],
                RING, fixture.moment,
            )
        self.assertEqual(single["status"], "pruned")
        self.assertEqual(batch["items"][0]["status"], VERIFIED)


if __name__ == "__main__":
    unittest.main()
