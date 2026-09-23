import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import audit
from offline_coordination.audit import CorruptAuditError, append
from offline_coordination.replication import export_batch, import_batch

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


class ImportBatchTest(unittest.TestCase):
    RESULT_KEYS = ("need", "next", "status")

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "src.jsonl")
        self.dst = os.path.join(self.dir, "dst.jsonl")

    def seed(self, path: str, n: int, prefix="event") -> None:
        for i in range(n):
            append(path, event(detail=f"{prefix} {i} ☃"))

    def batch(self, n: int, after: int = 0, limit: int = 1000) -> bytes:
        return export_batch(self.src, after=after, limit=limit)

    def test_types(self) -> None:
        with self.assertRaises(TypeError):
            import_batch(1, b"{}\n")
        with self.assertRaises(TypeError):
            import_batch(self.dst, "{}")
        with self.assertRaises(TypeError):
            import_batch(self.dst, None)

    def test_apply_into_empty_log(self) -> None:
        self.seed(self.src, 3)
        result = import_batch(self.dst, self.batch(3))
        self.assertEqual(tuple(result.keys()), self.RESULT_KEYS)
        self.assertEqual(result, {"need": None, "next": 3, "status": "applied"})
        local = audit.read(self.dst)
        self.assertEqual([r["seq"] for r in local], [1, 2, 3])
        self.assertEqual(local, audit.read(self.src))

    def test_append_suffix_after_partial_local_log(self) -> None:
        self.seed(self.src, 5)
        self.seed(self.dst, 2)
        result = import_batch(self.dst, self.batch(5))
        self.assertEqual(result, {"need": None, "next": 5, "status": "applied"})
        self.assertEqual(audit.read(self.dst), audit.read(self.src))

    def test_duplicate_full_overlap(self) -> None:
        self.seed(self.src, 3)
        self.seed(self.dst, 3)
        before = open(self.dst, "rb").read()
        result = import_batch(self.dst, self.batch(3))
        self.assertEqual(result, {"need": None, "next": 3, "status": "duplicate"})
        self.assertEqual(open(self.dst, "rb").read(), before)

    def test_idempotent_prefix_then_apply(self) -> None:
        self.seed(self.src, 4)
        self.seed(self.dst, 2)
        data = self.batch(4)
        self.assertEqual(import_batch(self.dst, data)["status"], "applied")
        # Replaying the same whole batch now skips every record.
        self.assertEqual(
            import_batch(self.dst, data),
            {"need": None, "next": 4, "status": "duplicate"},
        )

    def test_paginated_batches_apply_in_order(self) -> None:
        self.seed(self.src, 5)
        first = import_batch(self.dst, self.batch(5, after=0, limit=2))
        self.assertEqual(first, {"need": None, "next": 2, "status": "applied"})
        second = import_batch(self.dst, self.batch(5, after=2, limit=2))
        self.assertEqual(second, {"need": None, "next": 4, "status": "applied"})
        third = import_batch(self.dst, self.batch(5, after=4, limit=2))
        self.assertEqual(third, {"need": None, "next": 5, "status": "applied"})
        self.assertEqual(audit.read(self.dst), audit.read(self.src))

    def test_empty_batch_against_empty_log_is_duplicate(self) -> None:
        result = import_batch(self.dst, export_batch(self.src, after=0))
        self.assertEqual(result, {"need": None, "next": 0, "status": "duplicate"})
        self.assertFalse(os.path.exists(self.dst))

    def test_empty_batch_at_tail_is_duplicate(self) -> None:
        self.seed(self.src, 2)
        self.seed(self.dst, 2)
        result = import_batch(self.dst, self.batch(2, after=2))
        self.assertEqual(result, {"need": None, "next": 2, "status": "duplicate"})

    def test_missing_when_after_past_local_tail(self) -> None:
        self.seed(self.src, 5)
        self.seed(self.dst, 2)
        before = open(self.dst, "rb").read()
        result = import_batch(self.dst, self.batch(5, after=3, limit=2))
        self.assertEqual(tuple(result.keys()), self.RESULT_KEYS)
        self.assertEqual(result, {"need": [3, 3], "next": 2, "status": "missing"})
        self.assertEqual(open(self.dst, "rb").read(), before)

    def test_missing_on_empty_local_log(self) -> None:
        self.seed(self.src, 3)
        result = import_batch(self.dst, self.batch(3, after=2, limit=1))
        self.assertEqual(result, {"need": [1, 2], "next": 0, "status": "missing"})
        self.assertFalse(os.path.exists(self.dst))

    def test_conflicting_record_raises_and_does_not_write(self) -> None:
        self.seed(self.src, 4)
        # Build a divergent local log with the same seqs but different detail.
        self.seed(self.dst, 2, prefix="other")
        before = open(self.dst, "rb").read()
        with self.assertRaises(ValueError):
            import_batch(self.dst, self.batch(4))
        self.assertEqual(open(self.dst, "rb").read(), before)

    def test_broken_prev_at_suffix_boundary_raises(self) -> None:
        self.seed(self.src, 4)
        self.seed(self.dst, 2)
        obj = json.loads(self.batch(4, after=2, limit=2))
        # Re-chain records 3/4 from the zero hash: internally consistent, but
        # record 3's prev no longer equals the local tail hash.
        zero = "0" * 64
        prev = zero
        for record in obj["records"]:
            record["prev"] = prev
            without = {
                key: record[key] for key in ("detail", "kind", "prev", "seq", "source")
            }
            record["hash"] = hashlib.sha256(canonical(without)).hexdigest()
            prev = record["hash"]
        tampered = canonical(obj) + b"\n"
        before = open(self.dst, "rb").read()
        with self.assertRaises(ValueError):
            import_batch(self.dst, tampered)
        self.assertEqual(open(self.dst, "rb").read(), before)


class ImportBatchValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "src.jsonl")
        self.dst = os.path.join(self.dir, "dst.jsonl")

    def seed(self, n: int) -> None:
        for i in range(n):
            append(self.src, event(detail=f"event {i}"))

    def good(self, n: int = 2) -> bytes:
        self.seed(n)
        return export_batch(self.src)

    def reject(self, data: bytes) -> None:
        with self.assertRaises(ValueError):
            import_batch(self.dst, data)
        self.assertFalse(os.path.exists(self.dst))

    def test_not_json(self) -> None:
        self.reject(b"not json\n")

    def test_missing_newline(self) -> None:
        data = self.good()
        self.reject(data[:-1])

    def test_double_newline(self) -> None:
        self.reject(self.good() + b"\n")

    def test_not_object(self) -> None:
        self.reject(b"[]\n")

    def test_wrong_top_level_keys(self) -> None:
        obj = json.loads(self.good())
        del obj["version"]
        self.reject(canonical(obj) + b"\n")
        obj = json.loads(self.good())
        obj["extra"] = 1
        self.reject(canonical(obj) + b"\n")

    def test_wrong_key_order(self) -> None:
        obj = json.loads(self.good())
        reordered = (
            b'{"records":' + canonical(obj["records"])
            + b',"after":0,"complete":true,"next":2,"version":1}\n'
        )
        self.reject(reordered)

    def test_version_must_be_integer_1(self) -> None:
        obj = json.loads(self.good())
        obj["version"] = "1"
        self.reject(canonical(obj) + b"\n")
        obj["version"] = 2
        self.reject(canonical(obj) + b"\n")
        obj["version"] = True
        self.reject(canonical(obj) + b"\n")
        obj["version"] = 1.0
        self.reject(canonical(obj) + b"\n")

    def test_complete_must_be_bool(self) -> None:
        obj = json.loads(self.good())
        obj["complete"] = "true"
        self.reject(canonical(obj) + b"\n")

    def test_after_next_rules(self) -> None:
        obj = json.loads(self.good())
        obj["after"] = -1
        self.reject(canonical(obj) + b"\n")
        obj = json.loads(self.good())
        obj["after"] = True
        self.reject(canonical(obj) + b"\n")
        obj = json.loads(self.good())
        obj["next"] = 1
        self.reject(canonical(obj) + b"\n")
        obj = json.loads(self.good())
        obj["next"] = 3
        self.reject(canonical(obj) + b"\n")

    def test_empty_batch_next_must_be_after(self) -> None:
        self.seed(1)
        data = export_batch(self.src, after=1)
        obj = json.loads(data)
        obj["next"] = 2
        self.reject(canonical(obj) + b"\n")

    def test_records_must_be_list(self) -> None:
        obj = json.loads(self.good())
        obj["records"] = {}
        self.reject(canonical(obj) + b"\n")

    def test_record_wrong_keys(self) -> None:
        obj = json.loads(self.good())
        del obj["records"][0]["source"]
        self.reject(canonical(obj) + b"\n")
        obj = json.loads(self.good())
        obj["records"][0]["extra"] = 1
        self.reject(canonical(obj) + b"\n")

    def test_record_field_types(self) -> None:
        obj = json.loads(self.good())
        obj["records"][0]["seq"] = "1"
        self.reject(canonical(obj) + b"\n")
        obj = json.loads(self.good())
        obj["records"][0]["seq"] = True
        self.reject(canonical(obj) + b"\n")
        obj = json.loads(self.good())
        obj["records"][0]["detail"] = 1
        self.reject(canonical(obj) + b"\n")

    def test_seq_must_be_contiguous_from_after_plus_one(self) -> None:
        obj = json.loads(self.good())
        obj["after"] = 1
        obj["records"] = obj["records"][1:]
        # seq 2 with after 1 is valid; bump it to 3 (rehashing) to make a gap.
        record = obj["records"][0]
        record["seq"] = 3
        without = {
            key: record[key] for key in ("detail", "kind", "prev", "seq", "source")
        }
        record["hash"] = hashlib.sha256(canonical(without)).hexdigest()
        self.reject(canonical(obj) + b"\n")

    def test_duplicate_seq_rejected(self) -> None:
        obj = json.loads(self.good())
        record = obj["records"][1]
        record["seq"] = 1
        without = {
            key: record[key] for key in ("detail", "kind", "prev", "seq", "source")
        }
        record["hash"] = hashlib.sha256(canonical(without)).hexdigest()
        self.reject(canonical(obj) + b"\n")

    def test_broken_prev_chain(self) -> None:
        obj = json.loads(self.good())
        obj["records"][1]["prev"] = "f" * 64
        self.reject(canonical(obj) + b"\n")

    def test_broken_hash(self) -> None:
        obj = json.loads(self.good())
        obj["records"][0]["detail"] = "changed"
        self.reject(canonical(obj) + b"\n")

    def test_first_prev_must_be_zero_hash(self) -> None:
        obj = json.loads(self.good())
        obj["records"][0]["prev"] = "f" * 64
        self.reject(canonical(obj) + b"\n")

    def test_noncanonical_whitespace(self) -> None:
        self.reject(self.good().replace(b'{"after"', b'{ "after"', 1))

    def test_validation_runs_before_local_read(self) -> None:
        with mock.patch("offline_coordination.audit.read") as patched:
            with self.assertRaises(TypeError):
                import_batch(1, b"{}\n")
            with self.assertRaises(ValueError):
                import_batch(self.dst, b"{}\n")
        patched.assert_not_called()

    def test_corrupt_local_log_propagates(self) -> None:
        with open(self.dst, "wb") as handle:
            handle.write(b"{broken\n")
        with self.assertRaises(CorruptAuditError):
            import_batch(self.dst, self.good())

    def test_oserror_propagates(self) -> None:
        with mock.patch("offline_coordination.audit.read", side_effect=OSError):
            with self.assertRaises(OSError):
                import_batch(self.dst, self.good())


if __name__ == "__main__":
    unittest.main()
