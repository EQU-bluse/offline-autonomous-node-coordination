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
RESULT_KEYS = ("need", "next", "status")


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
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "src.jsonl")
        self.dst = os.path.join(self.dir, "dst.jsonl")

    def seed(self, path: str, n: int, source: str = "node-a", word: str = "event") -> None:
        for i in range(n):
            append(path, {"source": source, "kind": "local", "detail": f"{word} {i} ☃"})

    def test_applies_to_empty_log_and_returns_applied(self) -> None:
        self.seed(self.src, 3)
        batch = export_batch(self.src)
        result = import_batch(self.dst, batch)
        self.assertEqual(result, {"need": None, "next": 3, "status": "applied"})
        self.assertEqual(tuple(result.keys()), RESULT_KEYS)
        self.assertEqual(audit.read(self.dst), audit.read(self.src))

    def test_reimport_is_duplicate_and_does_not_modify_log(self) -> None:
        self.seed(self.src, 3)
        batch = export_batch(self.src)
        import_batch(self.dst, batch)
        with open(self.dst, "rb") as handle:
            before = handle.read()
        result = import_batch(self.dst, batch)
        self.assertEqual(result, {"need": None, "next": 3, "status": "duplicate"})
        with open(self.dst, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_appends_only_overlapping_suffix(self) -> None:
        self.seed(self.src, 5)
        import_batch(self.dst, export_batch(self.src, after=0, limit=3))
        self.seed(self.src, 2)
        batch = export_batch(self.src, after=2, limit=10)
        result = import_batch(self.dst, batch)
        self.assertEqual(result, {"need": None, "next": 7, "status": "applied"})
        self.assertEqual(audit.read(self.dst), audit.read(self.src))

    def test_missing_gap_is_reported_without_writing(self) -> None:
        self.seed(self.src, 5)
        batch = export_batch(self.src, after=3)
        result = import_batch(self.dst, batch)
        self.assertEqual(result, {"need": [1, 3], "next": 0, "status": "missing"})
        self.assertEqual(tuple(result.keys()), RESULT_KEYS)
        self.assertFalse(os.path.exists(self.dst))

    def test_missing_gap_after_nonempty_log(self) -> None:
        self.seed(self.src, 3)
        import_batch(self.dst, export_batch(self.src))
        batch = b'{"after":6,"complete":true,"next":6,"records":[],"version":1}\n'
        result = import_batch(self.dst, batch)
        self.assertEqual(result, {"need": [4, 6], "next": 3, "status": "missing"})

    def test_empty_batch_at_local_tip_is_duplicate(self) -> None:
        self.seed(self.src, 3)
        import_batch(self.dst, export_batch(self.src))
        result = import_batch(self.dst, export_batch(self.src, after=3))
        self.assertEqual(result, {"need": None, "next": 3, "status": "duplicate"})

    def test_empty_batch_with_complete_false_is_rejected(self) -> None:
        self.seed(self.src, 3)
        import_batch(self.dst, export_batch(self.src))
        batch = b'{"after":1,"complete":false,"next":1,"records":[],"version":1}\n'
        with self.assertRaises(ValueError):
            import_batch(self.dst, batch)

    def test_conflicting_shared_record_raises_and_keeps_log(self) -> None:
        self.seed(self.src, 3)
        import_batch(self.dst, export_batch(self.src))
        other = os.path.join(self.dir, "other.jsonl")
        self.seed(other, 3, source="node-b", word="other")
        with open(self.dst, "rb") as handle:
            before = handle.read()
        with self.assertRaises(ValueError):
            import_batch(self.dst, export_batch(other))
        with open(self.dst, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_first_appended_record_must_chain_to_local_last_hash(self) -> None:
        self.seed(self.src, 1)
        import_batch(self.dst, export_batch(self.src))
        record = {
            "detail": "x", "kind": "local", "prev": "0" * 64,
            "seq": 2, "source": "node-z",
        }
        record["hash"] = audit._record_hash(record)
        ordered = {key: record[key] for key in KEYS}
        batch = canonical(
            {"after": 1, "complete": True, "next": 2,
             "records": [ordered], "version": 1}
        ) + b"\n"
        with self.assertRaises(ValueError):
            import_batch(self.dst, batch)
        self.assertEqual(len(audit.read(self.dst)), 1)

    def test_reads_through_audit_read(self) -> None:
        self.seed(self.src, 2)
        batch = export_batch(self.src)
        with mock.patch("offline_coordination.audit.read", wraps=audit.read) as patched:
            import_batch(self.dst, batch)
        patched.assert_called_with(self.dst)

    def test_success_log_is_readable_via_audit_read(self) -> None:
        self.seed(self.src, 4)
        import_batch(self.dst, export_batch(self.src, after=0, limit=2))
        import_batch(self.dst, export_batch(self.src, after=2))
        records = audit.read(self.dst)
        self.assertEqual([r["seq"] for r in records], [1, 2, 3, 4])
        self.assertEqual(records, audit.read(self.src))

    def test_corrupt_local_log_propagates(self) -> None:
        self.seed(self.src, 2)
        self.seed(self.dst, 2)
        good = open(self.dst, "rb").read()
        with open(self.dst, "wb") as handle:
            handle.write(good[:-1])
        with self.assertRaises(CorruptAuditError):
            import_batch(self.dst, export_batch(self.src))

    def test_oserror_propagates(self) -> None:
        self.seed(self.src, 1)
        batch = export_batch(self.src)
        with mock.patch("offline_coordination.audit.read", side_effect=OSError):
            with self.assertRaises(OSError):
                import_batch(self.dst, batch)


def write_raw_log(path: str, events: list) -> None:
    """Write a hash-chained log whose values may lie outside the
    audit.append event input domain but which audit.read still accepts."""
    prev = "0" * 64
    lines = []
    for index, event_fields in enumerate(events, start=1):
        record = {
            "detail": event_fields["detail"],
            "kind": event_fields["kind"],
            "prev": prev,
            "seq": index,
            "source": event_fields["source"],
        }
        record["hash"] = audit._record_hash(record)
        prev = record["hash"]
        lines.append(canonical({key: record[key] for key in KEYS}))
    with open(path, "wb") as handle:
        handle.write(b"".join(line + b"\n" for line in lines))


class ImportBatchCompatibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "src.jsonl")
        self.dst = os.path.join(self.dir, "dst.jsonl")

    def test_out_of_domain_values_round_trip(self) -> None:
        events = [
            {"source": "", "kind": "odd", "detail": ""},
            {"source": "node-a", "kind": "local", "detail": "plain"},
            {"source": "n", "kind": "restore", "detail": "雪man ☃"},
        ]
        write_raw_log(self.src, events)
        # The source log is readable, so its export must be importable.
        self.assertEqual(len(audit.read(self.src)), 3)
        result = import_batch(self.dst, export_batch(self.src))
        self.assertEqual(result, {"need": None, "next": 3, "status": "applied"})
        self.assertEqual(audit.read(self.dst), audit.read(self.src))

    def test_out_of_domain_overlap_matches_and_dedupes(self) -> None:
        events = [
            {"source": "", "kind": "odd", "detail": ""},
            {"source": "x", "kind": "merge", "detail": "two"},
        ]
        write_raw_log(self.src, events)
        import_batch(self.dst, export_batch(self.src, after=0, limit=1))
        append_more = [
            {"source": "", "kind": "odd", "detail": ""},
            {"source": "x", "kind": "merge", "detail": "two"},
            {"source": "y", "kind": "weird", "detail": "three"},
        ]
        write_raw_log(self.src, append_more)
        result = import_batch(self.dst, export_batch(self.src))
        self.assertEqual(result, {"need": None, "next": 3, "status": "applied"})
        self.assertEqual(audit.read(self.dst), audit.read(self.src))
        again = import_batch(self.dst, export_batch(self.src))
        self.assertEqual(again, {"need": None, "next": 3, "status": "duplicate"})


class ImportBatchAtomicityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "src.jsonl")
        self.dst = os.path.join(self.dir, "dst.jsonl")

    def seed(self, path: str, n: int) -> None:
        for i in range(n):
            append(path, {"source": "node-a", "kind": "local", "detail": f"event {i}"})

    def test_fsync_failure_keeps_existing_log_bytes(self) -> None:
        self.seed(self.src, 4)
        self.seed(self.dst, 2)
        with open(self.dst, "rb") as handle:
            before = handle.read()
        batch = export_batch(self.src, after=2)
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                import_batch(self.dst, batch)
        with open(self.dst, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_flush_failure_keeps_missing_path_missing(self) -> None:
        self.seed(self.src, 2)
        batch = export_batch(self.src)
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                import_batch(self.dst, batch)
        self.assertFalse(os.path.exists(self.dst))

    def test_write_failure_keeps_existing_log_bytes(self) -> None:
        self.seed(self.src, 4)
        self.seed(self.dst, 2)
        with open(self.dst, "rb") as handle:
            before = handle.read()
        batch = export_batch(self.src, after=2)
        real_open = open

        class FailingFile:
            def __init__(self, *args, **kwargs):
                self._handle = real_open(*args, **kwargs)

            def write(self, data):
                raise OSError("write failed")

            def __getattr__(self, name):
                return getattr(self._handle, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._handle.close()
                return False

        with mock.patch("builtins.open", side_effect=lambda *a, **k: FailingFile(*a, **k)):
            with self.assertRaises(OSError):
                import_batch(self.dst, batch)
        with open(self.dst, "rb") as handle:
            self.assertEqual(handle.read(), before)


class ImportBatchValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")

    def batch(self, n: int = 2, **overrides) -> bytes:
        src = os.path.join(self.dir, "src.jsonl")
        for i in range(n):
            append(src, {"source": "node-a", "kind": "local", "detail": f"event {i}"})
        data = decode(export_batch(src))
        data.update(overrides)
        return canonical(data) + b"\n"

    def rec_batch(self, mutate) -> bytes:
        src = os.path.join(self.dir, "src.jsonl")
        append(src, {"source": "node-a", "kind": "local", "detail": "event 0"})
        append(src, {"source": "node-a", "kind": "local", "detail": "event 1"})
        data = decode(export_batch(src))
        mutate(data["records"])
        return canonical(data) + b"\n"

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            import_batch(1, b"{}\n")

    def test_batch_must_be_bytes(self) -> None:
        with self.assertRaises(TypeError):
            import_batch(self.path, "{}")
        with self.assertRaises(TypeError):
            import_batch(self.path, None)

    def test_not_json_or_not_terminated(self) -> None:
        with self.assertRaises(ValueError):
            import_batch(self.path, b"garbage\n")
        with self.assertRaises(ValueError):
            import_batch(self.path, b'{"a":1}')
        with self.assertRaises(ValueError):
            import_batch(self.path, b'{"a":1}\n\n')

    def test_top_level_key_set_and_order(self) -> None:
        with self.assertRaises(ValueError):
            import_batch(
                self.path,
                b'{"version":1,"after":0,"complete":true,"next":0,"records":[]}\n',
            )
        with self.assertRaises(ValueError):
            import_batch(
                self.path,
                b'{"after":0,"complete":true,"next":0,"records":[],"version":1,"x":2}\n',
            )

    def test_non_canonical_encoding(self) -> None:
        with self.assertRaises(ValueError):
            import_batch(
                self.path,
                b'{"after": 0, "complete": true, "next": 0, "records": [], "version": 1}\n',
            )

    def test_version_must_be_integer_1(self) -> None:
        with self.assertRaises(ValueError):
            import_batch(self.path, self.batch(version=2))
        with self.assertRaises(ValueError):
            import_batch(self.path, self.batch(version=True))
        with self.assertRaises(ValueError):
            import_batch(self.path, self.batch(version=1.0))

    def test_after_and_next_must_be_non_negative_ints(self) -> None:
        with self.assertRaises(ValueError):
            import_batch(self.path, self.batch(after=True, next=True))
        with self.assertRaises(ValueError):
            import_batch(self.path, self.batch(next="2"))
        records = decode(self.batch(2))["records"]
        bad = canonical(
            {"after": -1, "complete": True, "next": 1,
             "records": records, "version": 1}
        ) + b"\n"
        with self.assertRaises(ValueError):
            import_batch(self.path, bad)

    def test_complete_must_be_bool(self) -> None:
        with self.assertRaises(ValueError):
            import_batch(self.path, self.batch(complete=1))

    def test_next_must_equal_last_seq_or_after(self) -> None:
        with self.assertRaises(ValueError):
            import_batch(self.path, self.batch(2, next=1))
        empty = b'{"after":3,"complete":true,"next":2,"records":[],"version":1}\n'
        with self.assertRaises(ValueError):
            import_batch(self.path, empty)

    def test_records_must_be_list_with_fixed_keys_in_order(self) -> None:
        with self.assertRaises(ValueError):
            import_batch(self.path, self.batch(records={}))

        def reorder(records):
            r = records[0]
            records[0] = {k: r[k] for k in ("seq", "detail", "hash", "kind", "prev", "source")}

        with self.assertRaises(ValueError):
            import_batch(self.path, self.rec_batch(reorder))

    def test_seq_continuous_from_after_plus_one(self) -> None:
        def gap(records):
            records[1]["seq"] = 3

        with self.assertRaises(ValueError):
            import_batch(self.path, self.rec_batch(gap))

    def test_seq_bool_rejected(self) -> None:
        def boolean_seq(records):
            records[0]["seq"] = True

        with self.assertRaises(ValueError):
            import_batch(self.path, self.rec_batch(boolean_seq))

    def test_broken_prev_chain_rejected(self) -> None:
        def break_prev(records):
            records[1]["prev"] = "f" * 64

        with self.assertRaises(ValueError):
            import_batch(self.path, self.rec_batch(break_prev))

    def test_bad_hash_rejected(self) -> None:
        def break_hash(records):
            records[0]["hash"] = "0" * 64

        with self.assertRaises(ValueError):
            import_batch(self.path, self.rec_batch(break_hash))

    def test_first_prev_must_be_64_hex(self) -> None:
        src = os.path.join(self.dir, "src.jsonl")
        append(src, {"source": "node-a", "kind": "local", "detail": "event 0"})
        data = decode(export_batch(src, after=0))
        record = data["records"][0]
        record["prev"] = "Z" * 64
        record["hash"] = audit._record_hash(
            {k: record[k] for k in ("detail", "kind", "prev", "seq", "source")}
        )
        with self.assertRaises(ValueError):
            import_batch(self.path, canonical(data) + b"\n")

    def test_records_over_1000_rejected_before_local_read(self) -> None:
        batch = canonical(
            {"after": 0, "complete": True, "next": 1001,
             "records": [{}] * 1001, "version": 1}
        ) + b"\n"
        with mock.patch("offline_coordination.audit.read") as patched:
            with self.assertRaises(ValueError):
                import_batch(self.path, batch)
        patched.assert_not_called()
        self.assertFalse(os.path.exists(self.path))

    def test_empty_records_require_complete_true(self) -> None:
        batch = b'{"after":0,"complete":false,"next":0,"records":[],"version":1}\n'
        with mock.patch("offline_coordination.audit.read") as patched:
            with self.assertRaises(ValueError):
                import_batch(self.path, batch)
        patched.assert_not_called()
        self.assertFalse(os.path.exists(self.path))

    def test_out_of_domain_record_values_accepted(self) -> None:
        src = os.path.join(self.dir, "src.jsonl")
        write_raw_log(src, [{"source": "", "kind": "odd", "detail": ""}])
        batch = export_batch(src)
        with mock.patch("offline_coordination.audit.read", wraps=audit.read) as patched:
            result = import_batch(self.path, batch)
        self.assertEqual(result["status"], "applied")
        patched.assert_called_with(self.path)

    def test_validation_runs_before_local_read(self) -> None:
        with mock.patch("offline_coordination.audit.read") as patched:
            with self.assertRaises(TypeError):
                import_batch(1, b"")
            with self.assertRaises(TypeError):
                import_batch(self.path, "")
            with self.assertRaises(ValueError):
                import_batch(self.path, b"garbage\n")
        patched.assert_not_called()


if __name__ == "__main__":
    unittest.main()
