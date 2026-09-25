"""Tests for pruning multi-round fork convergence archives.

Covers :func:`plan_chain_prune`, :func:`prune_chain_archives` and
:func:`recover_chain_prune`: the version-1 archive and trimmed archive
encoding, the read-only signed plan (evidence-prefix eligibility, full
round-group re-verification, checkpoint binding, source/target and
retain digests, ascending delete ids, byte stability and credential
rules), the batch entry point (item/header validation, per-item
isolation with pruned/duplicate receipts and recorded stale, invalid
and credential errors, canonical receipts and same-plan in-flight
re-entry), and the two-phase ``.prune.txn`` recovery (prepared
rollback, installed completion, clean idempotence, corrupt-intent
classification and OSError propagation).
"""

import hashlib
import hmac
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination import replication
from offline_coordination.replication import (
    AuthenticationError,
    InvalidCheckpointError,
    InvalidPruneError,
    StalePruneError,
    plan_chain_prune,
    prune_chain_archives,
    recover_chain_prune,
    seal_chain_checkpoint,
)

from test_chain_checkpoint import CheckpointFixtures
from test_fork_convergence import (
    ALPHA,
    COORD,
    RING,
    SECRET_COORD,
    compact,
    entry,
    parse,
)
from test_supersede_decision import SIGN_MOMENT, VERIFY_MOMENT


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def read_file(path):
    with open(path, "rb") as handle:
        return handle.read()


PLAN_PAYLOAD_KEYS = {
    "checkpoint", "delete", "retain", "source", "target", "version",
}
RECEIPT_PAYLOAD_KEYS = {
    "afterDigest", "beforeDigest", "checkpoint", "delete", "moment",
    "plan", "retain", "status", "version",
}


class PruneFixtures(CheckpointFixtures):
    """Archive files, plans and batch items over the sealed chain."""

    def setUp(self):  # noqa: D102
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.checkpoint = self.checkpoint()
        self.moment = VERIFY_MOMENT
        self.header = {
            "issuer": COORD, "keyVersion": 1, "moment": self.moment,
        }
        # cert_coord/cert_alpha/cert_coord_2/cert_coord_3 are in the
        # checkpoint evidence prefix; cert_gamma is not.
        self.projects = {
            "c": self.cert_coord,
            "a": self.cert_alpha,
            "g": self.cert_gamma,
        }
        self.paths = {
            name: os.path.join(self.tmp, f"{name}.arc")
            for name in self.projects
        }
        for name, cert in self.projects.items():
            self.write_archive(name, cert)

    def tearDown(self):  # noqa: D102
        shutil.rmtree(self.tmp, ignore_errors=True)
        super().tearDown()

    def archive_obj(self, project, cert):
        confirmation = self.rounds[0]["confirmation"]
        return {
            "certificate": cert.hex(),
            "project": project,
            "rounds": [{"confirmation": confirmation.hex(), "seq": 1}],
            "version": 1,
        }

    def archive_bytes(self, project, cert, obj=None):
        data = obj if obj is not None else self.archive_obj(project, cert)
        return json.dumps(
            data, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"

    def write_archive(self, name, cert=None, raw=None):
        path = self.paths[name]
        if raw is None:
            raw = self.archive_bytes(
                name, cert if cert is not None else self.projects[name],
            )
        with open(path, "wb") as handle:
            handle.write(raw)
        return path

    def pruned_bytes(self, project="c"):
        return replication._prune_pruned_bytes(project)

    def other_checkpoint(self):
        """A second distinct valid checkpoint over the same accepted head."""
        return seal_chain_checkpoint(
            self.items, "x", self.decision, self.pol, RING,
            SIGN_MOMENT + 1, COORD, 1,
        )

    def make_plan(self, names=("c", "a", "g"), moment=None):
        return plan_chain_prune(
            [self.paths[name] for name in names],
            self.checkpoint, self.decision, self.pol, RING,
            self.moment if moment is None else moment,
        )

    def batch_item(self, item_id, name, plan=None):
        return {
            "id": item_id,
            "path": self.paths[name],
            "plan": plan if plan is not None else self.make_plan(),
            "checkpoint": self.checkpoint,
            "header": dict(self.header),
        }

    def batch(self, names=("c", "a", "g"), plan=None):
        return [
            self.batch_item(f"item-{name}", name, plan) for name in names
        ]


class ArchiveEncodingTest(PruneFixtures, unittest.TestCase):
    def test_archive_round_trips_through_the_parser(self):
        raw = self.archive_bytes("c", self.cert_coord)
        record = replication._prune_parse_archive(raw)
        self.assertEqual(record["project"], "c")
        self.assertEqual(record["certificate"], self.cert_coord)
        self.assertEqual(len(record["rounds"]), 1)
        self.assertEqual(record["rounds"][0]["seq"], 1)
        self.assertEqual(
            record["rounds"][0]["confirmation"],
            self.rounds[0]["confirmation"],
        )

    def test_non_ascii_project_is_preserved(self):
        raw = self.archive_bytes("项目-α", self.cert_coord)
        self.assertIn("项目-α".encode("utf-8"), raw)
        record = replication._prune_parse_archive(raw)
        self.assertEqual(record["project"], "项目-α")

    def test_trimmed_archive_is_a_project_marker(self):
        trimmed = self.pruned_bytes("c")
        self.assertTrue(trimmed.endswith(b"\n"))
        self.assertFalse(trimmed.endswith(b"\n\n"))
        data = json.loads(trimmed)
        self.assertEqual(set(data.keys()), {"project", "version"})
        self.assertEqual(data["project"], "c")
        self.assertIsNone(replication._prune_parse_pruned(trimmed, "c"))
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_pruned(trimmed, "a")

    def test_archive_faults(self):
        base = self.archive_obj("c", self.cert_coord)

        def raw(**changes):
            data = json.loads(json.dumps(base))
            data.update(changes)
            return json.dumps(
                data, sort_keys=True, separators=(",", ":")
            ).encode() + b"\n"

        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(b"not json\n")
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(raw(version=2))
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(raw(project=""))
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(raw(certificate="zz"))
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(raw(rounds=[]))
        bad_rounds = [{"confirmation": self.cert_coord.hex(), "seq": 2}]
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(raw(rounds=bad_rounds))
        wrong_keys = dict(base)
        wrong_keys["extra"] = 1
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(
                self.archive_bytes("c", self.cert_coord, obj=wrong_keys)
            )
        # No trailing newline, a trailing space and non-canonical order.
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(
                json.dumps(base, sort_keys=True,
                           separators=(",", ":")).encode()
            )
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(
                json.dumps(base, sort_keys=True,
                           separators=(",", ":")).encode() + b" \n"
            )
        reordered = {
            "version": 1,
            "rounds": base["rounds"],
            "project": "c",
            "certificate": base["certificate"],
        }
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_archive(
                json.dumps(reordered, separators=(",", ":")).encode() + b"\n"
            )

    def test_bool_never_poses_as_an_int(self):
        base = self.archive_obj("c", self.cert_coord)
        for field, value in (("version", True),):
            data = json.loads(json.dumps(base))
            data[field] = value
            raw = json.dumps(
                data, sort_keys=True, separators=(",", ":")
            ).encode() + b"\n"
            with self.assertRaises(TypeError):
                replication._prune_parse_archive(raw)
        data = json.loads(json.dumps(base))
        data["rounds"] = [
            {"confirmation": self.rounds[0]["confirmation"].hex(), "seq": True}
        ]
        raw = json.dumps(
            data, sort_keys=True, separators=(",", ":"),
        ).encode() + b"\n"
        with self.assertRaises(TypeError):
            replication._prune_parse_archive(raw)

    def test_non_bytes_arguments_are_type_errors(self):
        with self.assertRaises(TypeError):
            replication._prune_parse_archive("x")
        with self.assertRaises(InvalidPruneError):
            replication._prune_parse_pruned(b"{}\n", "c")


class PruneErrorClassificationTest(PruneFixtures, unittest.TestCase):
    def test_error_hierarchy(self):
        for error_type in (InvalidPruneError, StalePruneError):
            self.assertTrue(issubclass(error_type, ValueError))
        self.assertIsNot(InvalidCheckpointError, InvalidPruneError)

    def test_stale_outcome_is_recorded_with_stale_text(self):
        stable_plan = self.make_plan()
        with open(self.paths["c"], "wb") as handle:
            handle.write(b"changed bytes\n")
        report = prune_chain_archives(
            [self.batch_item("i", "c", stable_plan)], RING)[0]
        self.assertIsNone(report["receipt"])
        with self.assertRaises(StalePruneError):
            raise StalePruneError(report["error"])


class PlanChainPruneTest(PruneFixtures, unittest.TestCase):
    def test_plan_is_a_canonical_signed_envelope(self):
        plan = self.make_plan()
        self.assertTrue(plan.endswith(b"}"))
        self.assertNotIn(b"\n", plan)
        data = parse(plan)
        self.assertEqual(set(data.keys()), {"payload", "signature"})
        self.assertEqual(compact(data), plan)
        payload = data["payload"]
        self.assertEqual(set(payload.keys()), PLAN_PAYLOAD_KEYS)
        self.assertEqual(payload["version"], 1)
        self.assertNotIsInstance(payload["version"], bool)

    def test_plan_bindings(self):
        plan = self.make_plan()
        payload = parse(plan)["payload"]
        self.assertEqual(payload["checkpoint"], sha256(self.checkpoint))
        self.assertEqual(payload["delete"], ["a", "c"])
        self.assertEqual(
            payload["retain"], [sha256(self.archive_bytes("g", self.cert_gamma))]
        )
        self.assertEqual(
            payload["source"],
            {
                "a": sha256(self.archive_bytes("a", self.cert_alpha)),
                "c": sha256(self.archive_bytes("c", self.cert_coord)),
            },
        )
        self.assertEqual(
            payload["target"],
            {
                "a": sha256(self.pruned_bytes("a")),
                "c": sha256(self.pruned_bytes("c")),
            },
        )

    def test_signature_is_the_checkpoint_key_hmac(self):
        plan = self.make_plan()
        data = parse(plan)
        self.assertEqual(
            data["signature"],
            hmac.new(
                bytes.fromhex(SECRET_COORD), compact(data["payload"]),
                hashlib.sha256,
            ).hexdigest(),
        )

    def test_plan_is_byte_stable_and_read_only(self):
        before = {
            path: read_file(path)
            for path in self.paths.values()
        }
        first = self.make_plan()
        second = self.make_plan()
        self.assertEqual(first, second)
        after = {
            path: read_file(path)
            for path in self.paths.values()
        }
        self.assertEqual(before, after)

    def test_only_evidence_prefix_certificates_are_eligible(self):
        # gamma is not in the checkpoint evidence prefix: mixed with an
        # eligible archive it is retained, and alone the plan refuses.
        payload = parse(self.make_plan(("c", "g")))["payload"]
        self.assertEqual(payload["delete"], ["c"])
        self.assertEqual(
            payload["retain"],
            [sha256(self.archive_bytes("g", self.cert_gamma))],
        )
        self.assertNotIn("g", payload["source"])
        with self.assertRaises(ValueError):
            self.make_plan(("g",))

    def test_no_eligible_archive_is_a_value_error(self):
        with self.assertRaises(ValueError):
            self.make_plan(("g",))

    def test_missing_archive_raises_file_not_found(self):
        missing = os.path.join(self.tmp, "missing.arc")
        with self.assertRaises(FileNotFoundError):
            plan_chain_prune(
                [missing], self.checkpoint, self.decision, self.pol, RING,
                self.moment,
            )

    def test_round_group_must_reverify(self):
        # An eligible certificate paired with rounds it did not seal
        # cannot be pruned: the whole round group must re-verify.
        raw = self.archive_bytes(
            "c", self.cert_coord,
            obj={
                "certificate": self.cert_coord.hex(),
                "project": "c",
                "rounds": [{
                    "confirmation":
                        self.rounds_conflict[0]["confirmation"].hex(),
                    "seq": 1,
                }],
                "version": 1,
            },
        )
        with open(self.paths["c"], "wb") as handle:
            handle.write(raw)
        with self.assertRaises(InvalidPruneError):
            self.make_plan(("c",))

    def test_archive_is_checkpoint_agnostic(self):
        # The archive carries no checkpoint: the same eligible archive
        # plans under any authenticated sealing checkpoint whose
        # evidence prefix covers its certificate.
        other = self.other_checkpoint()
        self.assertNotEqual(other, self.checkpoint)
        plan = plan_chain_prune(
            [self.paths["c"]], other, self.decision, self.pol, RING,
            self.moment,
        )
        self.assertEqual(
            parse(plan)["payload"]["checkpoint"], sha256(other)
        )

    def test_certificate_outside_a_checkpoint_prefix_is_not_eligible(self):
        # gamma's certificate is covered by neither sealing checkpoint.
        other = self.other_checkpoint()
        with self.assertRaises(ValueError):
            plan_chain_prune(
                [self.paths["g"]], other, self.decision, self.pol, RING,
                self.moment,
            )

    def test_duplicate_projects_and_paths_are_value_errors(self):
        duplicate = os.path.join(self.tmp, "c-copy.arc")
        with open(duplicate, "wb") as handle:
            handle.write(self.archive_bytes("c", self.cert_coord))
        with self.assertRaises(ValueError):
            plan_chain_prune(
                [self.paths["c"], duplicate], self.checkpoint,
                self.decision, self.pol, RING, self.moment,
            )
        with self.assertRaises(ValueError):
            plan_chain_prune(
                [self.paths["c"], self.paths["c"]], self.checkpoint,
                self.decision, self.pol, RING, self.moment,
            )

    def test_path_list_faults(self):
        with self.assertRaises(TypeError):
            plan_chain_prune("x", self.checkpoint, self.decision, self.pol,
                             RING, self.moment)
        with self.assertRaises(ValueError):
            plan_chain_prune([], self.checkpoint, self.decision, self.pol,
                             RING, self.moment)
        with self.assertRaises(TypeError):
            plan_chain_prune([1], self.checkpoint, self.decision, self.pol,
                             RING, self.moment)
        with self.assertRaises(ValueError):
            plan_chain_prune([""], self.checkpoint, self.decision, self.pol,
                             RING, self.moment)

    def test_argument_type_faults(self):
        good = [self.paths["c"]]
        with self.assertRaises(TypeError):
            plan_chain_prune(good, "cp", self.decision, self.pol, RING,
                             self.moment)
        with self.assertRaises(TypeError):
            plan_chain_prune(good, self.checkpoint, "d", self.pol, RING,
                             self.moment)
        with self.assertRaises(TypeError):
            plan_chain_prune(good, self.checkpoint, self.decision, self.pol,
                             RING, True)
        with self.assertRaises(ValueError):
            plan_chain_prune(good, self.checkpoint, self.decision, self.pol,
                             RING, -1)

    def test_checkpoint_credentials(self):
        with self.assertRaises(AuthenticationError):
            plan_chain_prune(
                [self.paths["c"]], self.checkpoint, self.decision, self.pol,
                RING, 10 ** 12,
            )
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            plan_chain_prune(
                [self.paths["c"]], self.checkpoint, self.decision, self.pol,
                revoked, self.moment,
            )

    def test_malformed_checkpoint_is_invalid_prune(self):
        with self.assertRaises(InvalidPruneError):
            plan_chain_prune(
                [self.paths["c"]], b"{}", self.decision, self.pol, RING,
                self.moment,
            )

    def test_rebound_checkpoint_is_authentication_error(self):
        data = parse(self.checkpoint)
        data["payload"]["moment"] = self.moment + 1
        with self.assertRaises(AuthenticationError):
            plan_chain_prune(
                [self.paths["c"]], compact(data), self.decision, self.pol,
                RING, self.moment,
            )

    def test_corrupt_archive_is_invalid_prune(self):
        with open(self.paths["c"], "wb") as handle:
            handle.write(b"{}\n")
        with self.assertRaises(InvalidPruneError):
            self.make_plan(("c",))

    def test_planning_does_not_require_a_header_or_signer_argument(self):
        # The plan is signed with the checkpoint's own sealer key.
        payload = parse(self.make_plan(("c",)))["payload"]
        self.assertNotIn("moment", payload)
        self.assertNotIn("issuer", payload)


class PruneChainArchivesBatchTest(PruneFixtures, unittest.TestCase):
    def test_batch_structure_faults(self):
        good = self.batch_item("i", "c")
        with self.assertRaises(TypeError):
            prune_chain_archives("x", RING)
        with self.assertRaises(ValueError):
            prune_chain_archives([], RING)
        with self.assertRaises(TypeError):
            prune_chain_archives([dict(good, id=1)], RING)
        with self.assertRaises(ValueError):
            prune_chain_archives([dict(good, id="")], RING)
        with self.assertRaises(ValueError):
            prune_chain_archives([good, dict(good)], RING)
        with self.assertRaises(ValueError):
            prune_chain_archives([{"id": "i", "path": self.paths["c"],
                                   "plan": self.make_plan(),
                                   "checkpoint": self.checkpoint}], RING)
        with self.assertRaises(TypeError):
            prune_chain_archives([dict(good, path=1)], RING)
        with self.assertRaises(ValueError):
            prune_chain_archives([dict(good, path="")], RING)
        with self.assertRaises(TypeError):
            prune_chain_archives([dict(good, plan="x")], RING)
        with self.assertRaises(TypeError):
            prune_chain_archives([dict(good, checkpoint="x")], RING)

    def test_header_faults(self):
        good = self.batch_item("i", "c")
        with self.assertRaises(TypeError):
            prune_chain_archives(
                [dict(good, header={"issuer": COORD, "keyVersion": 1,
                                    "moment": "x"})], RING)
        with self.assertRaises(TypeError):
            prune_chain_archives(
                [dict(good, header={"issuer": COORD, "keyVersion": True,
                                    "moment": 1})], RING)
        with self.assertRaises(ValueError):
            prune_chain_archives(
                [dict(good, header={"issuer": "", "keyVersion": 1,
                                    "moment": 1})], RING)
        with self.assertRaises(ValueError):
            prune_chain_archives(
                [dict(good, header={"issuer": COORD, "keyVersion": 0,
                                    "moment": 1})], RING)
        with self.assertRaises(ValueError):
            prune_chain_archives(
                [dict(good, header={"issuer": COORD, "keyVersion": 1,
                                    "moment": -1})], RING)

    def test_pruned_receipt_and_trimmed_archive(self):
        self._captured_plan = self.make_plan()
        reports = prune_chain_archives(
            [self.batch_item("i", "c", self._captured_plan)], RING)
        self.assertEqual(len(reports), 1)
        report = reports[0]
        self.assertEqual(list(report.keys()), ["id", "receipt", "error"])
        self.assertEqual(report["id"], "i")
        self.assertIsNone(report["error"])
        receipt = report["receipt"]
        self.assertTrue(receipt.endswith(b"}"))
        data = parse(receipt)
        self.assertEqual(compact(data), receipt)
        payload = data["payload"]
        self.assertEqual(set(payload.keys()), RECEIPT_PAYLOAD_KEYS)
        self.assertEqual(payload["status"], "pruned")
        self.assertEqual(payload["checkpoint"], sha256(self.checkpoint))
        source = self.archive_bytes("c", self.cert_coord)
        self.assertEqual(payload["beforeDigest"], sha256(source))
        self.assertEqual(payload["afterDigest"], sha256(self.pruned_bytes("c")))
        self.assertEqual(payload["delete"], ["a", "c"])
        self.assertEqual(payload["retain"],
                         [sha256(self.archive_bytes("g", self.cert_gamma))])
        self.assertEqual(payload["moment"], self.moment)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(compact(payload["plan"]), self._captured_plan)
        self.assertEqual(
            data["signature"],
            hmac.new(
                bytes.fromhex(SECRET_COORD), compact(payload),
                hashlib.sha256,
            ).hexdigest(),
        )
        self.assertEqual(
            read_file(self.paths["c"]), self.pruned_bytes("c")
        )
        self.assertFalse(os.path.exists(self.paths["c"] + ".prune.txn"))
        self.assertFalse(any(
            name.startswith("c.arc.")
            for name in os.listdir(self.tmp)
        ))

    def test_stale_retained_and_other_items_run_in_order(self):
        plan = self.make_plan()
        with open(self.paths["a"], "wb") as handle:
            handle.write(b"changed bytes\n")
        reports = prune_chain_archives(
            [self.batch_item("item-c", "c", plan),
             self.batch_item("item-a", "a", plan),
             self.batch_item("item-g", "g", plan)],
            RING,
        )
        self.assertEqual([r["id"] for r in reports],
                         ["item-c", "item-a", "item-g"])
        statuses = {}
        for report in reports:
            if report["receipt"] is not None:
                statuses[report["id"]] = parse(report["receipt"])["payload"]["status"]
            else:
                statuses[report["id"]] = report["error"]
        self.assertEqual(statuses["item-c"], "pruned")
        self.assertIn("stale chain prune", statuses["item-a"])
        self.assertIn("stale chain prune", statuses["item-g"])
        # The stale archives are byte-for-byte unchanged.
        self.assertEqual(read_file(self.paths["a"]), b"changed bytes\n")
        self.assertEqual(
            read_file(self.paths["g"]),
            self.archive_bytes("g", self.cert_gamma),
        )

    def test_second_completion_is_a_duplicate_receipt(self):
        stable_plan = self.make_plan()
        first = prune_chain_archives(
            [self.batch_item("i", "c", stable_plan)], RING)[0]
        second = prune_chain_archives(
            [self.batch_item("i", "c", stable_plan)], RING)[0]
        self.assertEqual(parse(first["receipt"])["payload"]["status"], "pruned")
        payload = parse(second["receipt"])["payload"]
        self.assertEqual(payload["status"], "duplicate")
        self.assertEqual(payload["beforeDigest"], payload["afterDigest"])
        self.assertEqual(
            read_file(self.paths["c"]), self.pruned_bytes("c")
        )

    def test_invalid_credentials_are_recorded_and_the_batch_continues(self):
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        reports = prune_chain_archives(self.batch(), revoked)
        self.assertEqual(len(reports), 3)
        for report in reports:
            self.assertIsNone(report["receipt"])
            self.assertIsInstance(report["error"], str)
            self.assertTrue(report["error"])
        # Nothing changed on disk.
        self.assertEqual(
            read_file(self.paths["c"]),
            self.archive_bytes("c", self.cert_coord),
        )

    def test_header_must_name_the_checkpoint_sealer(self):
        item = self.batch_item("i", "c")
        item["header"] = {"issuer": ALPHA, "keyVersion": 1,
                          "moment": self.moment}
        report = prune_chain_archives([item], RING)[0]
        self.assertIsNone(report["receipt"])
        self.assertIsInstance(report["error"], str)
        self.assertEqual(
            read_file(self.paths["c"]),
            self.archive_bytes("c", self.cert_coord),
        )

    def test_malformed_plan_and_checkpoint_are_recorded(self):
        bad_plan = dict(self.batch_item("i", "c"))
        bad_plan["plan"] = b"{}"
        bad_cp = dict(self.batch_item("j", "a"))
        bad_cp["checkpoint"] = b"{}"
        good = self.batch_item("k", "g")
        reports = prune_chain_archives([bad_plan, bad_cp, good], RING)
        self.assertEqual([r["id"] for r in reports], ["i", "j", "k"])
        self.assertTrue(reports[0]["error"])
        self.assertTrue(reports[1]["error"])
        self.assertTrue(reports[2]["error"])

    def test_plan_must_bind_the_item_checkpoint(self):
        other_checkpoint = self.other_checkpoint()
        item = self.batch_item("i", "c")
        item["checkpoint"] = other_checkpoint
        report = prune_chain_archives([item], RING)[0]
        self.assertIsNone(report["receipt"])
        self.assertIn("not bound", report["error"])

    def test_os_error_is_recorded_and_transaction_material_retained(self):
        # Reading a directory as an archive raises IsADirectoryError.
        item = {
            "id": "dir", "path": self.tmp, "plan": self.make_plan(),
            "checkpoint": self.checkpoint, "header": dict(self.header),
        }
        reports = prune_chain_archives([item, self.batch_item("ok", "c")], RING)
        self.assertIsNone(reports[0]["receipt"])
        self.assertIsInstance(reports[0]["error"], str)
        self.assertEqual(
            parse(reports[1]["receipt"])["payload"]["status"], "pruned"
        )

    def test_unrelated_files_are_never_scanned(self):
        junk = os.path.join(self.tmp, "random.leftover")
        with open(junk, "wb") as handle:
            handle.write(b"junk")
        prune_chain_archives([self.batch_item("i", "c")], RING)
        self.assertTrue(os.path.exists(junk))

    def test_non_ascii_project_round_trips(self):
        path = os.path.join(self.tmp, "项目.arc")
        raw = self.archive_bytes("项目", self.cert_coord)
        with open(path, "wb") as handle:
            handle.write(raw)
        plan = plan_chain_prune(
            [path], self.checkpoint, self.decision, self.pol, RING,
            self.moment,
        )
        item = {
            "id": "i", "path": path, "plan": plan,
            "checkpoint": self.checkpoint, "header": dict(self.header),
        }
        report = prune_chain_archives([item], RING)[0]
        self.assertIsNone(report["error"])
        self.assertEqual(
            json.loads(read_file(path))["project"], "项目"
        )


class SamePlanReentryTest(PruneFixtures, unittest.TestCase):
    """First completion and same-plan in-flight re-entry agree exactly."""

    def setUp(self):  # noqa: D102
        super().setUp()
        # Captured while every archive is still intact; stable bytes.
        self.plan_bytes = self.make_plan()
        self.plan_digest = sha256(self.plan_bytes)

    def batch_item(self, item_id, name):  # noqa: D102
        return {
            "id": item_id,
            "path": self.paths[name],
            "plan": self.plan_bytes,
            "checkpoint": self.checkpoint,
            "header": dict(self.header),
        }

    def _intent(self, phase, new_digest, old_digest, candidate, predecessor):
        return replication._prune_intent_payload(
            phase, os.path.basename(self.paths["c"]),
            self.plan_digest, sha256(self.checkpoint),
            new_digest, old_digest, candidate, predecessor,
        )

    def test_installed_intent_reentry_returns_the_pruned_receipt(self):
        # First, complete normally and record the canonical receipt.
        first = prune_chain_archives([self.batch_item("i", "c")], RING)[0]
        first_receipt = first["receipt"]
        # Reset the archive to its source, then stage an *installed*
        # in-flight transaction: target bytes in place, predecessor
        # link retained, installed intent published.
        source = self.archive_bytes("c", self.cert_coord)
        target = self.pruned_bytes("c")
        with open(self.paths["c"], "wb") as handle:
            handle.write(source)
        predecessor = self.paths["c"] + ".old.keep"
        staged = self.paths["c"] + ".tmp.staged"
        os.link(self.paths["c"], predecessor)
        with open(staged, "wb") as handle:
            handle.write(target)
        os.replace(staged, self.paths["c"])
        intent = self._intent(
            "installed", sha256(target), sha256(source),
            "candidate.gone", os.path.basename(predecessor),
        )
        replication._prune_publish_intent(self.paths["c"], intent)

        report = prune_chain_archives([self.batch_item("j", "c")], RING)[0]
        self.assertIsNone(report["error"])
        self.assertEqual(report["receipt"], first_receipt)
        self.assertEqual(
            parse(report["receipt"])["payload"]["status"], "pruned"
        )
        self.assertFalse(os.path.exists(self.paths["c"] + ".prune.txn"))
        self.assertFalse(os.path.exists(predecessor))

    def test_prepared_intent_reentry_rolls_back_then_prunes(self):
        source = self.archive_bytes("c", self.cert_coord)
        target = self.pruned_bytes("c")
        predecessor = self.paths["c"] + ".old.keep"
        candidate = self.paths["c"] + ".tmp.cand"
        os.link(self.paths["c"], predecessor)
        with open(candidate, "wb") as handle:
            handle.write(target)
        intent = self._intent(
            "prepared", sha256(target), sha256(source),
            os.path.basename(candidate), os.path.basename(predecessor),
        )
        replication._prune_publish_intent(self.paths["c"], intent)

        report = prune_chain_archives([self.batch_item("i", "c")], RING)[0]
        self.assertIsNone(report["error"])
        self.assertEqual(
            parse(report["receipt"])["payload"]["status"], "pruned"
        )
        self.assertEqual(read_file(self.paths["c"]), target)
        self.assertFalse(os.path.exists(candidate))
        self.assertFalse(os.path.exists(self.paths["c"] + ".prune.txn"))

    def test_intent_for_another_plan_is_stale(self):
        target = self.pruned_bytes("c")
        predecessor = self.paths["c"] + ".old.keep"
        candidate = self.paths["c"] + ".tmp.cand"
        os.link(self.paths["c"], predecessor)
        with open(candidate, "wb") as handle:
            handle.write(target)
        intent = replication._prune_intent_payload(
            "prepared", os.path.basename(self.paths["c"]),
            "11" * 32, sha256(self.checkpoint),
            sha256(target), sha256(self.archive_bytes("c", self.cert_coord)),
            os.path.basename(candidate), os.path.basename(predecessor),
        )
        replication._prune_publish_intent(self.paths["c"], intent)
        report = prune_chain_archives([self.batch_item("i", "c")], RING)[0]
        self.assertIsNone(report["receipt"])
        self.assertIn("different plan", report["error"])
        self.assertTrue(os.path.exists(self.paths["c"] + ".prune.txn"))


class RecoverChainPruneTest(PruneFixtures, unittest.TestCase):
    def setUp(self):  # noqa: D102
        super().setUp()
        self.plan_bytes = self.make_plan()
        self.plan_digest = sha256(self.plan_bytes)

    def _publish(self, path, intent):
        with open(path + ".prune.txn", "wb") as handle:
            handle.write(intent)

    def test_clean_with_and_without_archive(self):
        path = os.path.join(self.tmp, "absent.arc")
        self.assertEqual(
            recover_chain_prune(path),
            {"digest": None, "status": "clean"},
        )
        result = recover_chain_prune(self.paths["c"])
        self.assertEqual(result["status"], "clean")
        self.assertEqual(
            result["digest"],
            sha256(self.archive_bytes("c", self.cert_coord)),
        )

    def test_path_type_fault(self):
        with self.assertRaises(TypeError):
            recover_chain_prune(1)

    def _prepared_state(self, name="c", existed=True):
        path = self.paths[name]
        source = self.archive_bytes(name, self.projects[name])
        target = self.pruned_bytes(name)
        predecessor = path + ".old.keep"
        candidate = path + ".tmp.cand"
        old_digest = sha256(source) if existed else None
        if existed:
            os.link(path, predecessor)
        with open(candidate, "wb") as handle:
            handle.write(target)
        intent = replication._prune_intent_payload(
            "prepared", os.path.basename(path),
            self.plan_digest, sha256(self.checkpoint),
            sha256(target), old_digest,
            os.path.basename(candidate),
            os.path.basename(predecessor) if existed else None,
        )
        self._publish(path, intent)
        if not existed:
            with open(path, "wb") as handle:
                handle.write(target)
        return path, source, target, predecessor, candidate

    def test_prepared_rolls_back_to_the_source(self):
        path, source, _target, predecessor, candidate = self._prepared_state()
        result = recover_chain_prune(path)
        self.assertEqual(result["status"], "rolled-back")
        self.assertEqual(result["digest"], sha256(source))
        self.assertEqual(read_file(path), source)
        self.assertFalse(os.path.exists(candidate))
        self.assertFalse(os.path.exists(predecessor))
        self.assertFalse(os.path.exists(path + ".prune.txn"))
        # Recovery is idempotent.
        self.assertEqual(recover_chain_prune(path)["status"], "clean")

    def test_prepared_rolls_back_a_path_that_was_missing(self):
        path = os.path.join(self.tmp, "fresh.arc")
        target = self.pruned_bytes("c")
        candidate = path + ".tmp.cand"
        with open(candidate, "wb") as handle:
            handle.write(target)
        with open(path, "wb") as handle:
            handle.write(target)
        intent = replication._prune_intent_payload(
            "prepared", os.path.basename(path),
            self.plan_digest, sha256(self.checkpoint),
            sha256(target), None,
            os.path.basename(candidate), None,
        )
        self._publish(path, intent)
        result = recover_chain_prune(path)
        self.assertEqual(result["status"], "rolled-back")
        self.assertIsNone(result["digest"])
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(candidate))

    def test_installed_completes_the_target(self):
        path = self.paths["c"]
        source = self.archive_bytes("c", self.cert_coord)
        target = self.pruned_bytes("c")
        predecessor = path + ".old.keep"
        staged = path + ".tmp.staged"
        os.link(path, predecessor)
        with open(staged, "wb") as handle:
            handle.write(target)
        os.replace(staged, path)
        intent = replication._prune_intent_payload(
            "installed", os.path.basename(path),
            self.plan_digest, sha256(self.checkpoint),
            sha256(target), sha256(source),
            "candidate.gone", os.path.basename(predecessor),
        )
        self._publish(path, intent)
        result = recover_chain_prune(path)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["digest"], sha256(target))
        self.assertEqual(read_file(path), target)
        self.assertFalse(os.path.exists(predecessor))
        self.assertFalse(os.path.exists(path + ".prune.txn"))

    def test_only_intent_named_files_are_touched(self):
        junk = os.path.join(self.tmp, "c.arc.junk")
        with open(junk, "wb") as handle:
            handle.write(b"junk")
        self._prepared_state()
        recover_chain_prune(self.paths["c"])
        self.assertTrue(os.path.exists(junk))

    def test_corrupt_intents_are_invalid_prune(self):
        path = self.paths["c"]

        def expect(intent):
            self._publish(path, intent)
            with self.assertRaises(InvalidPruneError):
                recover_chain_prune(path)
            os.unlink(path + ".prune.txn")

        expect(b"{}\n")
        good = replication._prune_intent_payload(
            "prepared", os.path.basename(path),
            self.plan_digest, sha256(self.checkpoint),
            "22" * 32, "33" * 32, "cand", "pred",
        )
        # Bad phase.
        data = json.loads(good)
        data["phase"] = "committed"
        expect(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
               + b"\n")
        # Illegal version.
        data = json.loads(good)
        data["version"] = 2
        expect(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
               + b"\n")
        # Target names a different file.
        data = json.loads(good)
        data["target"] = "other.arc"
        expect(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
               + b"\n")
        # Path traversal in an artifact name.
        data = json.loads(good)
        data["candidate"] = "../escape"
        expect(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
               + b"\n")
        # Non-canonical encoding (extra trailing newline).
        expect(good + b"\n")

    def test_intent_target_mismatch_is_invalid_prune(self):
        path = self.paths["c"]
        intent = replication._prune_intent_payload(
            "prepared", "g.arc", self.plan_digest,
            sha256(self.checkpoint), "22" * 32, "33" * 32, "cand", "pred",
        )
        self._publish(path, intent)
        with self.assertRaises(InvalidPruneError):
            recover_chain_prune(path)

    def test_missing_predecessor_is_invalid_prune(self):
        path = self.paths["c"]
        source = self.archive_bytes("c", self.cert_coord)
        target = self.pruned_bytes("c")
        # The path vanished and the predecessor link is gone too.
        os.unlink(path)
        candidate = path + ".tmp.cand"
        with open(candidate, "wb") as handle:
            handle.write(target)
        intent = replication._prune_intent_payload(
            "prepared", os.path.basename(path),
            self.plan_digest, sha256(self.checkpoint),
            sha256(target), sha256(source),
            os.path.basename(candidate), "pred.gone",
        )
        self._publish(path, intent)
        with self.assertRaises(InvalidPruneError):
            recover_chain_prune(path)

    def test_installed_bytes_must_match_new_digest(self):
        path = self.paths["c"]
        source = self.archive_bytes("c", self.cert_coord)
        intent = replication._prune_intent_payload(
            "installed", os.path.basename(path),
            self.plan_digest, sha256(self.checkpoint),
            "22" * 32, sha256(source), "cand", "pred.gone",
        )
        self._publish(path, intent)
        with self.assertRaises(InvalidPruneError):
            recover_chain_prune(path)

    def test_os_error_propagates_unchanged(self):
        # An intent beside a directory: reading the current bytes raises
        # IsADirectoryError, which must surface as an OSError.
        directory = os.path.join(self.tmp, "adir")
        os.mkdir(directory)
        intent = replication._prune_intent_payload(
            "installed", "adir", self.plan_digest,
            sha256(self.checkpoint), "22" * 32, None, "cand", None,
        )
        with open(directory + ".prune.txn", "wb") as handle:
            handle.write(intent)
        with self.assertRaises(OSError):
            recover_chain_prune(directory)


if __name__ == "__main__":
    unittest.main()
