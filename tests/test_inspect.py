import hashlib
import os
import tempfile
import unittest

from offline_coordination import audit, receipt, storage, transaction
from offline_coordination.storage import CorruptStateError
from offline_coordination.transaction import inspect
from offline_coordination.transaction import (
    CorruptTransactionError,
)
from offline_coordination.audit import CorruptAuditError
from offline_coordination.receipt import CorruptReceiptError

STATE = {"clock": {"n1": 0}, "records": {}}
OTHER_STATE = {"clock": {"n1": 7}, "records": {}}
EVENT = {"source": "n1", "kind": "local", "detail": "first"}
OTHER_EVENT = {"source": "n2", "kind": "merge", "detail": "other"}

ITEM_KEYS = ("audit", "id", "stage", "state", "status")


def state_digest(state=STATE) -> str:
    payload = storage._serialize(*storage._validated_state(state))
    return hashlib.sha256(payload).hexdigest()


def planned_audit_digest(audit_path: str, event=EVENT) -> str:
    return transaction._planned_audit_digest(audit._read_all_records(audit_path), event)


class InspectFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.paths = {
            "checkpoint": os.path.join(self.dir, "checkpoint.json"),
            "state": os.path.join(self.dir, "state.json"),
            "audit": os.path.join(self.dir, "audit.log"),
            "receipt": os.path.join(self.dir, "receipt.json"),
        }
        self.sd = state_digest()
        self.ad = planned_audit_digest(self.paths["audit"])

    def checkpoint(self, rid="x", stage="prepared", sd=None, ad=None) -> None:
        sd = self.sd if sd is None else sd
        ad = self.ad if ad is None else ad
        transaction.checkpoint(
            self.paths["checkpoint"],
            {"id": rid, "state": sd, "audit": ad, "stage": "prepared"},
        )
        current = "prepared"
        for next_stage in ("state", "audit", "committed"):
            if current == stage:
                break
            transaction.checkpoint(
                self.paths["checkpoint"],
                {"id": rid, "state": sd, "audit": ad, "stage": next_stage},
            )
            current = next_stage

    def set_state(self, mode: str) -> None:
        if mode == "match":
            storage.save_state(self.paths["state"], STATE)
        elif mode == "other":
            storage.save_state(self.paths["state"], OTHER_STATE)
        elif mode == "none":
            for suffix in ("", ".bak", ".tmp"):
                try:
                    os.remove(self.paths["state"] + suffix)
                except FileNotFoundError:
                    pass
        else:  # pragma: no cover - test programming error
            raise AssertionError(mode)

    def set_audit(self, mode: str) -> None:
        if mode == "match":
            audit.append(self.paths["audit"], EVENT)
        elif mode == "other":
            audit.append(self.paths["audit"], OTHER_EVENT)
        elif mode == "none":
            try:
                os.remove(self.paths["audit"])
            except FileNotFoundError:
                pass
        else:  # pragma: no cover
            raise AssertionError(mode)

    def set_receipt(self, mode: str) -> None:
        if mode == "match":
            receipt.put(
                self.paths["receipt"],
                {"id": "x", "state": self.sd, "audit": self.ad},
            )
        elif mode == "wrong":
            receipt.put(
                self.paths["receipt"],
                {"id": "x", "state": "f" * 64, "audit": self.ad},
            )
        elif mode == "none":
            try:
                os.remove(self.paths["receipt"])
            except FileNotFoundError:
                pass
        else:  # pragma: no cover
            raise AssertionError(mode)

    def reset(self) -> None:
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        self.sd = state_digest()
        self.ad = planned_audit_digest(self.paths["audit"])

    def build(
        self, stage: str, *, state_mode="none", audit_mode="none",
        receipt_mode="none",
    ):
        self.reset()
        self.checkpoint(stage=stage)
        self.set_state(state_mode)
        self.set_audit(audit_mode)
        self.set_receipt(receipt_mode)
        return inspect(self.paths)[0]

    def snapshot(self) -> tuple[dict[str, bytes], list[str]]:
        files = {}
        for name in os.listdir(self.dir):
            with open(os.path.join(self.dir, name), "rb") as handle:
                files[name] = handle.read()
        return files, sorted(os.listdir(self.dir))


class InspectValidationTest(InspectFixture):
    def test_paths_must_be_dict(self) -> None:
        for bad in (None, [], "x", 1, True):
            with self.assertRaises(TypeError, msg=f"paths={bad!r}"):
                inspect(bad)

    def test_paths_key_set_must_match_exactly(self) -> None:
        with self.assertRaises(ValueError):
            inspect({key: self.paths[key] for key in self.paths if key != "receipt"})
        with self.assertRaises(ValueError):
            inspect({**self.paths, "extra": "z"})

    def test_paths_values_must_be_str(self) -> None:
        for key in self.paths:
            with self.assertRaises(TypeError, msg=f"key={key}"):
                inspect({**self.paths, key: 1})

    def test_type_errors_precede_file_access(self) -> None:
        # A corrupt checkpoint must not mask paths type/value errors.
        with open(self.paths["checkpoint"], "wb") as handle:
            handle.write(b"")
        with self.assertRaises(TypeError):
            inspect(None)
        with self.assertRaises(ValueError):
            inspect({key: self.paths[key] for key in self.paths if key != "state"})


class InspectBasicTest(InspectFixture):
    def test_missing_checkpoint_returns_empty_list(self) -> None:
        self.assertEqual(inspect(self.paths), [])

    def test_missing_checkpoint_ignores_other_artifacts(self) -> None:
        # Even an unrecoverable state is not consulted without a checkpoint.
        with open(self.paths["state"], "wb") as handle:
            handle.write(b"garbage")
        with open(self.paths["state"] + ".bak", "wb") as handle:
            handle.write(b"garbage")
        os.mkdir(self.paths["audit"])
        self.assertEqual(inspect(self.paths), [])

    def test_item_key_order_and_checkpoint_values(self) -> None:
        item = self.build("prepared")
        self.assertEqual(tuple(item.keys()), ITEM_KEYS)
        self.assertEqual(item["audit"], self.ad)
        self.assertEqual(item["id"], "x")
        self.assertEqual(item["stage"], "prepared")
        self.assertEqual(item["state"], self.sd)
        self.assertEqual(item["status"], "recoverable")

    def test_items_sorted_by_id_and_fresh_copies(self) -> None:
        self.checkpoint(rid="c", stage="committed")
        self.checkpoint(rid="a", stage="prepared")
        self.checkpoint(rid="b", stage="state")
        result = inspect(self.paths)
        self.assertEqual([item["id"] for item in result], ["a", "b", "c"])
        self.assertTrue(all(tuple(item.keys()) == ITEM_KEYS for item in result))
        again = inspect(self.paths)
        self.assertIsNot(result, again)
        self.assertTrue(all(x is not y for x, y in zip(result, again)))
        result[0]["status"] = "mutated"
        self.assertEqual(inspect(self.paths)[0]["status"], "recoverable")


class InspectStatusMatrixTest(InspectFixture):
    def test_prepared_requires_no_audit_record_and_no_receipt(self) -> None:
        # S is irrelevant at prepared.
        for state_mode in ("none", "match", "other"):
            item = self.build(
                "prepared", state_mode=state_mode,
                audit_mode="none", receipt_mode="none",
            )
            self.assertEqual(item["status"], "recoverable", state_mode)

        self.assertEqual(
            self.build("prepared", audit_mode="match", receipt_mode="none")[
                "status"
            ],
            "conflict",
        )
        self.assertEqual(
            self.build("prepared", audit_mode="other", receipt_mode="none")[
                "status"
            ],
            "recoverable",
        )
        self.assertEqual(
            self.build("prepared", audit_mode="none", receipt_mode="match")[
                "status"
            ],
            "conflict",
        )
        self.assertEqual(
            self.build("prepared", audit_mode="none", receipt_mode="wrong")[
                "status"
            ],
            "conflict",
        )

    def test_state_stage_requires_matching_state_and_no_receipt(self) -> None:
        # A is irrelevant at state.
        for audit_mode in ("none", "match", "other"):
            item = self.build(
                "state", state_mode="match", audit_mode=audit_mode,
                receipt_mode="none",
            )
            self.assertEqual(item["status"], "recoverable", audit_mode)

        self.assertEqual(
            self.build("state", state_mode="other", receipt_mode="none")[
                "status"
            ],
            "conflict",
        )
        self.assertEqual(
            self.build("state", state_mode="none", receipt_mode="none")[
                "status"
            ],
            "conflict",
        )
        self.assertEqual(
            self.build("state", state_mode="match", receipt_mode="match")[
                "status"
            ],
            "conflict",
        )
        self.assertEqual(
            self.build("state", state_mode="match", receipt_mode="wrong")[
                "status"
            ],
            "conflict",
        )

    def test_audit_stage_requires_state_audit_and_absent_or_matching_receipt(
        self,
    ) -> None:
        self.assertEqual(
            self.build(
                "audit", state_mode="match", audit_mode="match",
                receipt_mode="none",
            )["status"],
            "recoverable",
        )
        self.assertEqual(
            self.build(
                "audit", state_mode="match", audit_mode="match",
                receipt_mode="match",
            )["status"],
            "recoverable",
        )
        self.assertEqual(
            self.build(
                "audit", state_mode="other", audit_mode="match",
                receipt_mode="none",
            )["status"],
            "conflict",
        )
        self.assertEqual(
            self.build(
                "audit", state_mode="match", audit_mode="other",
                receipt_mode="none",
            )["status"],
            "conflict",
        )
        self.assertEqual(
            self.build(
                "audit", state_mode="match", audit_mode="none",
                receipt_mode="none",
            )["status"],
            "conflict",
        )
        self.assertEqual(
            self.build(
                "audit", state_mode="match", audit_mode="match",
                receipt_mode="wrong",
            )["status"],
            "conflict",
        )

    def test_committed_requires_everything_bound(self) -> None:
        self.assertEqual(
            self.build(
                "committed", state_mode="match", audit_mode="match",
                receipt_mode="match",
            )["status"],
            "committed",
        )
        self.assertEqual(
            self.build(
                "committed", state_mode="other", audit_mode="match",
                receipt_mode="match",
            )["status"],
            "conflict",
        )
        self.assertEqual(
            self.build(
                "committed", state_mode="match", audit_mode="other",
                receipt_mode="match",
            )["status"],
            "conflict",
        )
        self.assertEqual(
            self.build(
                "committed", state_mode="match", audit_mode="match",
                receipt_mode="none",
            )["status"],
            "conflict",
        )
        self.assertEqual(
            self.build(
                "committed", state_mode="match", audit_mode="match",
                receipt_mode="wrong",
            )["status"],
            "conflict",
        )

    def test_independent_records_classified_separately(self) -> None:
        self.checkpoint(rid="c", stage="committed")
        self.checkpoint(rid="a", stage="prepared")
        self.set_state("match")
        self.set_audit("match")
        receipt.put(
            self.paths["receipt"],
            {"id": "c", "state": self.sd, "audit": self.ad},
        )
        statuses = {item["id"]: item["status"] for item in inspect(self.paths)}
        # 'a' is prepared but its audit record is already present -> conflict;
        # 'c' has state, audit and receipt all bound -> committed.
        self.assertEqual(statuses, {"a": "conflict", "c": "committed"})


class InspectStateFallbackTest(InspectFixture):
    def test_valid_backup_keeps_corrupt_main_loadable_but_s_uses_main(self) -> None:
        # Rotate STATE into the backup, then corrupt the new main.
        storage.save_state(self.paths["state"], STATE)
        storage.save_state(self.paths["state"], OTHER_STATE)
        with open(self.paths["state"], "wb") as handle:
            handle.write(b"not a state")
        self.checkpoint(stage="committed")
        self.set_audit("match")
        self.set_receipt("match")
        # The backup is valid, so no CorruptStateError -- but S is about
        # the main file, so the committed checkpoint is a conflict.
        self.assertEqual(inspect(self.paths)[0]["status"], "conflict")

    def test_missing_main_with_valid_backup_is_not_corrupt(self) -> None:
        storage.save_state(self.paths["state"], STATE)
        storage.save_state(self.paths["state"], STATE)
        os.remove(self.paths["state"])
        self.assertTrue(os.path.exists(self.paths["state"] + ".bak"))
        self.checkpoint(stage="prepared")
        self.assertEqual(inspect(self.paths)[0]["status"], "recoverable")

    def test_tmp_file_alone_is_not_an_existing_state(self) -> None:
        with open(self.paths["state"] + ".tmp", "wb") as handle:
            handle.write(b"garbage")
        self.checkpoint(stage="prepared")
        self.assertEqual(inspect(self.paths)[0]["status"], "recoverable")


class InspectCorruptionTest(InspectFixture):
    def test_corrupt_main_and_backup_raises_corrupt_state_error(self) -> None:
        self.checkpoint(stage="prepared")
        with open(self.paths["state"], "wb") as handle:
            handle.write(b"garbage")
        with open(self.paths["state"] + ".bak", "wb") as handle:
            handle.write(b"also garbage")
        with self.assertRaises(CorruptStateError):
            inspect(self.paths)

    def test_corrupt_main_without_backup_raises_corrupt_state_error(self) -> None:
        self.checkpoint(stage="committed")
        with open(self.paths["state"], "wb") as handle:
            handle.write(b"{")
        with self.assertRaises(CorruptStateError):
            inspect(self.paths)

    def test_corrupt_checkpoint_propagates(self) -> None:
        with open(self.paths["checkpoint"], "wb") as handle:
            handle.write(b"")
        with self.assertRaises(CorruptTransactionError):
            inspect(self.paths)

    def test_corrupt_audit_propagates(self) -> None:
        self.checkpoint(stage="prepared")
        with open(self.paths["audit"], "wb") as handle:
            handle.write(b"not json\n")
        with self.assertRaises(CorruptAuditError):
            inspect(self.paths)

    def test_corrupt_receipt_propagates(self) -> None:
        self.checkpoint(stage="prepared")
        with open(self.paths["receipt"], "wb") as handle:
            handle.write(b"")
        with self.assertRaises(CorruptReceiptError):
            inspect(self.paths)

    def test_os_error_propagates(self) -> None:
        self.checkpoint(stage="prepared")
        os.mkdir(self.paths["audit"])
        with self.assertRaises(OSError):
            inspect(self.paths)

    def test_corrupt_state_os_error_is_not_value_conflict(self) -> None:
        self.checkpoint(stage="committed")
        with open(self.paths["state"], "wb") as handle:
            handle.write(b"garbage")
        try:
            inspect(self.paths)
        except ValueError as exc:
            self.assertIsInstance(exc, CorruptStateError)
        else:  # pragma: no cover
            self.fail("expected CorruptStateError")


class InspectReadOnlyTest(InspectFixture):
    def assert_unchanged(self) -> None:
        before = self.snapshot()
        inspect(self.paths)
        self.assertEqual(self.snapshot(), before)

    def test_read_only_on_recoverable_prepared(self) -> None:
        self.checkpoint(stage="prepared")
        self.assert_unchanged()

    def test_read_only_on_committed(self) -> None:
        self.checkpoint(stage="committed")
        self.set_state("match")
        self.set_audit("match")
        self.set_receipt("match")
        self.assert_unchanged()

    def test_read_only_on_conflict(self) -> None:
        # A committed checkpoint without any of its artifacts is a conflict.
        self.checkpoint(stage="committed")
        self.assert_unchanged()

    def test_read_only_on_corrupt_state(self) -> None:
        self.checkpoint(stage="prepared")
        with open(self.paths["state"], "wb") as handle:
            handle.write(b"garbage")
        before = self.snapshot()
        with self.assertRaises(CorruptStateError):
            inspect(self.paths)
        self.assertEqual(self.snapshot(), before)

    def test_no_tmp_files_created(self) -> None:
        self.checkpoint(stage="committed")
        self.set_state("match")
        self.set_audit("match")
        self.set_receipt("match")
        inspect(self.paths)
        self.assertEqual(
            [name for name in os.listdir(self.dir) if name.endswith(".tmp")],
            [],
        )


def commit_paths(directory: str) -> dict[str, str]:
    return {
        "checkpoint": os.path.join(directory, "checkpoint.json"),
        "state": os.path.join(directory, "state.json"),
        "audit": os.path.join(directory, "audit.log"),
        "receipt": os.path.join(directory, "receipt.json"),
    }


class CommitCorruptStateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.paths = commit_paths(self.dir)

    def write(self, name: str, payload: bytes) -> None:
        with open(os.path.join(self.dir, name), "wb") as handle:
            handle.write(payload)

    def request(self, state=STATE, event=EVENT, rid="x") -> dict:
        return {"id": rid, "state": state, "event": event}

    def snapshot(self) -> dict[str, bytes]:
        files = {}
        for name in os.listdir(self.dir):
            with open(os.path.join(self.dir, name), "rb") as handle:
                files[name] = handle.read()
        return files

    def test_corrupt_main_and_backup_before_first_commit_raises(self) -> None:
        self.write("state.json", b"garbage")
        self.write("state.json.bak", b"also garbage")
        before = self.snapshot()
        with self.assertRaises(CorruptStateError):
            transaction.commit(self.paths, self.request())
        self.assertEqual(self.snapshot(), before)

    def test_corrupt_main_without_backup_at_committed_raises(self) -> None:
        result = transaction.commit(self.paths, self.request())
        self.assertEqual(result["stage"], "committed")
        self.write("state.json", b"junk")
        with self.assertRaises(CorruptStateError):
            transaction.commit(self.paths, self.request())

    def test_valid_backup_lets_recovery_commit_finish(self) -> None:
        # prepared checkpoint, main corrupt, backup holding the bound state
        storage.save_state(self.paths["state"], STATE)
        sd = state_digest()
        ad = planned_audit_digest(self.paths["audit"])
        transaction.checkpoint(
            self.paths["checkpoint"],
            {"id": "x", "state": sd, "audit": ad, "stage": "prepared"},
        )
        storage.save_state(self.paths["state"], OTHER_STATE)
        self.write("state.json", b"corrupt main")
        result = transaction.commit(self.paths, self.request())
        self.assertEqual(result["stage"], "committed")
        self.assertEqual(inspect(self.paths)[0]["status"], "committed")

    def test_conflicting_valid_state_is_value_error_not_corrupt(self) -> None:
        transaction.commit(self.paths, self.request())
        storage.save_state(self.paths["state"], OTHER_STATE)
        before = self.snapshot()
        with self.assertRaises(ValueError) as caught:
            transaction.commit(self.paths, self.request())
        self.assertNotIsInstance(caught.exception, CorruptStateError)
        self.assertEqual(self.snapshot(), before)

    def test_recoverable_state_stage_resumes_and_is_idempotent(self) -> None:
        storage.save_state(self.paths["state"], STATE)
        sd = state_digest()
        ad = planned_audit_digest(self.paths["audit"])
        for stage in ("prepared", "state"):
            transaction.checkpoint(
                self.paths["checkpoint"],
                {"id": "x", "state": sd, "audit": ad, "stage": stage},
            )
        self.assertEqual(inspect(self.paths)[0]["status"], "recoverable")
        result = transaction.commit(self.paths, self.request())
        self.assertEqual(result["stage"], "committed")
        files_after = self.snapshot()
        replay = transaction.commit(self.paths, self.request())
        self.assertEqual(replay, result)
        self.assertEqual(self.snapshot(), files_after)
        self.assertEqual(inspect(self.paths)[0]["status"], "committed")


if __name__ == "__main__":
    unittest.main()
