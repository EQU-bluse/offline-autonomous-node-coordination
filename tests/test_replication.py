import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import audit
from offline_coordination.audit import CorruptAuditError, append
from offline_coordination.replication import export_batch

KEYS = ("detail", "hash", "kind", "prev", "seq", "source")
TOP_KEYS = ("after", "complete", "next", "records", "version")


def event(source="node-a", kind="local", detail="did something"):
    return {"source": source, "kind": kind, "detail": detail}


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def decode(data: bytes):
    return json.loads(data)


class ExportBatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")

    def seed(self, n: int) -> None:
        for i in range(n):
            append(self.path, event(detail=f"event {i} ☃"))

    def test_missing_log_empty_batch(self) -> None:
        data = export_batch(self.path)
        self.assertEqual(data, b'{"after":0,"complete":true,"next":0,"records":[],"version":1}\n')

    def test_top_level_key_order_version_and_lf(self) -> None:
        self.seed(1)
        data = export_batch(self.path)
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\n\n"))
        self.assertEqual(tuple(decode(data).keys()), TOP_KEYS)
        self.assertEqual(decode(data)["version"], 1)
        self.assertIs(decode(data)["complete"], True)

    def test_records_keep_key_order_values_and_unicode(self) -> None:
        self.seed(2)
        batch = decode(export_batch(self.path))
        records = batch["records"]
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(tuple(record.keys()), KEYS)
        self.assertEqual(records[1]["detail"], "event 1 ☃")
        self.assertIn("☃".encode("utf-8"), export_batch(self.path))
        self.assertEqual(records, audit.read(self.path))

    def test_selection_and_pagination(self) -> None:
        self.seed(5)
        batch = decode(export_batch(self.path, after=0, limit=2))
        self.assertEqual([r["seq"] for r in batch["records"]], [1, 2])
        self.assertEqual(batch["after"], 0)
        self.assertEqual(batch["next"], 2)
        self.assertIs(batch["complete"], False)

        batch = decode(export_batch(self.path, after=2, limit=2))
        self.assertEqual([r["seq"] for r in batch["records"]], [3, 4])
        self.assertEqual(batch["next"], 4)
        self.assertIs(batch["complete"], False)

        batch = decode(export_batch(self.path, after=4, limit=2))
        self.assertEqual([r["seq"] for r in batch["records"]], [5])
        self.assertEqual(batch["next"], 5)
        self.assertIs(batch["complete"], True)

    def test_after_at_last_seq_yields_empty_complete_batch(self) -> None:
        self.seed(3)
        batch = decode(export_batch(self.path, after=3))
        self.assertEqual(batch["records"], [])
        self.assertEqual(batch["next"], 3)
        self.assertIs(batch["complete"], True)

    def test_default_limit_is_100(self) -> None:
        self.seed(101)
        batch = decode(export_batch(self.path))
        self.assertEqual(len(batch["records"]), 100)
        self.assertEqual(batch["next"], 100)
        self.assertIs(batch["complete"], False)

    def test_limit_1000_allowed(self) -> None:
        self.seed(1)
        batch = decode(export_batch(self.path, limit=1000))
        self.assertEqual(len(batch["records"]), 1)
        self.assertIs(batch["complete"], True)

    def test_encoding_is_compact_and_canonical(self) -> None:
        self.seed(2)
        data = export_batch(self.path, after=1, limit=1)
        self.assertEqual(data, canonical(decode(data)) + b"\n")

    def test_uses_audit_read_contract(self) -> None:
        self.seed(1)
        with mock.patch("offline_coordination.audit.read", wraps=audit.read) as patched:
            export_batch(self.path)
        patched.assert_called_once_with(self.path)

    def test_does_not_modify_log_on_success(self) -> None:
        self.seed(2)
        with open(self.path, "rb") as handle:
            before = handle.read()
        export_batch(self.path, after=0, limit=1)
        with open(self.path, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_corrupt_log_propagates_and_is_not_modified(self) -> None:
        self.seed(2)
        good = open(self.path, "rb").read()
        with open(self.path, "wb") as handle:
            handle.write(good[:-1])
        with self.assertRaises(CorruptAuditError):
            export_batch(self.path)
        with open(self.path, "rb") as handle:
            self.assertEqual(handle.read(), good[:-1])

    def test_oserror_propagates(self) -> None:
        with mock.patch("offline_coordination.audit.read", side_effect=OSError):
            with self.assertRaises(OSError):
                export_batch(self.path)


class ExportBatchValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            export_batch(1)
        with self.assertRaises(TypeError):
            export_batch(None)

    def test_after_must_be_int_not_bool(self) -> None:
        with self.assertRaises(TypeError):
            export_batch(self.path, after=1.0)
        with self.assertRaises(TypeError):
            export_batch(self.path, after=True)
        with self.assertRaises(TypeError):
            export_batch(self.path, after="1")

    def test_limit_must_be_int_not_bool(self) -> None:
        with self.assertRaises(TypeError):
            export_batch(self.path, limit=1.0)
        with self.assertRaises(TypeError):
            export_batch(self.path, limit=True)
        with self.assertRaises(TypeError):
            export_batch(self.path, limit="100")

    def test_negative_after_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            export_batch(self.path, after=-1)

    def test_limit_range(self) -> None:
        with self.assertRaises(ValueError):
            export_batch(self.path, limit=0)
        with self.assertRaises(ValueError):
            export_batch(self.path, limit=1001)

    def test_after_must_not_exceed_last_seq(self) -> None:
        append(self.path, event())
        append(self.path, event())
        with self.assertRaises(ValueError):
            export_batch(self.path, after=3)

    def test_empty_log_only_accepts_after_zero(self) -> None:
        with self.assertRaises(ValueError):
            export_batch(self.path, after=1)
        # Does not raise:
        export_batch(self.path, after=0)

    def test_validation_runs_before_read(self) -> None:
        with mock.patch("offline_coordination.audit.read") as patched:
            with self.assertRaises(TypeError):
                export_batch(1)
            with self.assertRaises(ValueError):
                export_batch(self.path, after=-1)
            with self.assertRaises(ValueError):
                export_batch(self.path, limit=0)
        patched.assert_not_called()


if __name__ == "__main__":
    unittest.main()
