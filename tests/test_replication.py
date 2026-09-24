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


# ---------------------------------------------------------------------------
# apply_remote: persistent remote-state application
# ---------------------------------------------------------------------------

from offline_coordination import replication  # noqa: E402
from offline_coordination import merge as _merge  # noqa: E402
from offline_coordination import storage  # noqa: E402

APPLY_RESULT_KEYS = ("items", "receipt", "status")
ITEM_KEYS = ("key", "decision", "need")


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, deleted, clock, writer):
    return [value, deleted, dict(clock), writer]


def request(rid="r1", source="node-a", base=None, remote=None):
    return {
        "id": rid,
        "source": source,
        "base": state() if base is None else base,
        "remote": state() if remote is None else remote,
    }


def read_ledger(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read())


def ledger_raw(path):
    with open(path, "rb") as handle:
        return handle.read()


class ApplyRemoteBasicTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def test_applies_to_missing_ledger_taking_base_as_current(self) -> None:
        remote = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        result = replication.apply_remote(self.path, request(remote=remote))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(tuple(result.keys()), APPLY_RESULT_KEYS)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(tuple(result["items"][0].keys()), ITEM_KEYS)
        self.assertEqual(result["items"][0],
                         {"key": "k", "decision": "apply", "need": None})
        self.assertIsNotNone(result["receipt"])

    def test_state_and_clock_persisted(self) -> None:
        remote = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        replication.apply_remote(self.path, request(remote=remote))
        ledger = read_ledger(self.path)
        self.assertEqual(ledger["version"], 1)
        self.assertEqual(ledger["state"],
                         {"clock": {"a": 1},
                          "records": {"k": ["v", False, {"a": 1}, "a"]}})

    def test_ledger_is_canonical_compact_json_with_one_lf(self) -> None:
        remote = state({"a": 1}, {"k": record("☃", False, {"a": 1}, "a")})
        replication.apply_remote(self.path, request(remote=remote))
        raw = ledger_raw(self.path)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        decoded = json.loads(raw)
        self.assertEqual(
            raw,
            json.dumps(decoded, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode("utf-8") + b"\n",
        )
        self.assertEqual(tuple(decoded.keys()), ("audit", "requests", "state", "version"))
        self.assertIn("☃".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        self.assertEqual(
            tuple(decoded["audit"][0].keys()),
            ("after", "before", "id", "seq", "source"),
        )

    def test_outer_clock_raised_per_node_from_applied_records(self) -> None:
        # Two records by different writers apply from an empty ledger in one
        # request; the outer clock advances on both nodes.
        remote = state(
            {"a": 1, "b": 1},
            {
                "ak": record("v", False, {"a": 1}, "a"),
                "bk": record("w", False, {"b": 1}, "b"),
            },
        )
        replication.apply_remote(self.path, request(remote=remote))
        self.assertEqual(read_ledger(self.path)["state"]["clock"], {"a": 1, "b": 1})

    def test_items_sorted_by_remote_key(self) -> None:
        remote = state(
            {"a": 1},
            {
                "z": record("z", False, {"a": 1}, "a"),
                "a": record("a", False, {"a": 1}, "a"),
                "m": record("m", False, {"a": 1}, "a"),
            },
        )
        result = replication.apply_remote(self.path, request(remote=remote))
        self.assertEqual([item["key"] for item in result["items"]], ["a", "m", "z"])
        self.assertTrue(all(item["decision"] == "apply" for item in result["items"]))

    def test_receipt_carries_id_source_digests_and_seq(self) -> None:
        remote = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        result = replication.apply_remote(
            self.path, request(rid="r-1", source="node-b", remote=remote)
        )
        receipt = result["receipt"]
        self.assertEqual(tuple(receipt.keys()),
                         ("id", "source", "before", "after", "seq"))
        self.assertEqual(receipt["id"], "r-1")
        self.assertEqual(receipt["source"], "node-b")
        self.assertEqual(receipt["seq"], 1)
        self.assertNotEqual(receipt["before"], receipt["after"])
        self.assertRegex(receipt["before"], r"[0-9a-f]{64}")
        self.assertRegex(receipt["after"], r"[0-9a-f]{64}")

    def test_remote_tombstone_applied(self) -> None:
        remote = state({"a": 1}, {"k": record("", True, {"a": 1}, "a")})
        result = replication.apply_remote(self.path, request(remote=remote))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_ledger(self.path)["state"]["records"]["k"],
                         ["", True, {"a": 1}, "a"])


class ApplyRemoteChainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def apply(self, rid, base, remote, source="s"):
        return replication.apply_remote(
            self.path, request(rid=rid, source=source, base=base, remote=remote)
        )

    def test_seqs_contiguous_and_entries_chain(self) -> None:
        s0 = state()
        s1 = state({"a": 1}, {"k": record("v1", False, {"a": 1}, "a")})
        s2 = state({"a": 2}, {"k": record("v2", False, {"a": 2}, "a")})
        s3 = state({"a": 2, "b": 1},
                   {"k": record("v2", False, {"a": 2}, "a"),
                    "g": record("g", False, {"b": 1}, "b")})
        self.apply("r1", s0, s1)
        self.apply("r2", s1, s2)
        r3 = self.apply("r3", s2, s3)
        ledger = read_ledger(self.path)
        entries = ledger["audit"]
        self.assertEqual([entry["seq"] for entry in entries], [1, 2, 3])
        self.assertEqual(entries[1]["before"], entries[0]["after"])
        self.assertEqual(entries[2]["before"], entries[1]["after"])
        import hashlib
        state_digest = hashlib.sha256(replication._state_bytes(s3)).hexdigest()
        self.assertEqual(entries[-1]["after"], state_digest)
        self.assertEqual(r3["receipt"]["seq"], 3)
        self.assertEqual(set(ledger["requests"]), {"r1", "r2", "r3"})

    def test_requests_bound_to_digests_are_stable(self) -> None:
        s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.apply("r1", state(), s1)
        ledger = read_ledger(self.path)
        self.assertEqual(
            ledger["requests"]["r1"],
            replication._request_digest("r1", "s", state(), s1),
        )


class ApplyRemoteReplayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        # Two records under keys that are not submission-order sorted, so a
        # replay must re-sort them by remote record key.
        self.s1 = state(
            {"a": 1, "b": 1},
            {
                "k": record("v", False, {"a": 1}, "a"),
                "g": record("w", False, {"b": 1}, "b"),
            },
        )
        self.req = request(remote=self.s1)
        self.first = replication.apply_remote(self.path, self.req)

    def replay_items(self):
        return [
            {"key": "g", "decision": "duplicate", "need": {}},
            {"key": "k", "decision": "duplicate", "need": {}},
        ]

    def test_immediate_replay_is_duplicate_with_items_and_no_receipt(self) -> None:
        before = ledger_raw(self.path)
        again = replication.apply_remote(self.path, self.req)
        self.assertEqual(again["status"], "duplicate")
        self.assertEqual(tuple(again.keys()), APPLY_RESULT_KEYS)
        # Items follow the remote records in stable key order and only
        # state that each record is already duplicate.
        self.assertEqual(again["items"], self.replay_items())
        self.assertEqual(
            [item["key"] for item in again["items"]],
            sorted(self.req["remote"]["records"]),
        )
        for item in again["items"]:
            self.assertEqual(tuple(item.keys()), ITEM_KEYS)
            self.assertEqual(item["need"], {})
        # A replay never mints a receipt.
        self.assertIsNone(again["receipt"])
        self.assertEqual(ledger_raw(self.path), before)

    def test_immediate_replay_performs_no_write_operations(self) -> None:
        with mock.patch("os.replace") as replaced, \
                mock.patch("os.fsync") as fsynced, \
                mock.patch("os.link") as linked, \
                mock.patch("os.unlink") as unlinked:
            again = replication.apply_remote(self.path, self.req)
        self.assertEqual(again["status"], "duplicate")
        replaced.assert_not_called()
        fsynced.assert_not_called()
        linked.assert_not_called()
        unlinked.assert_not_called()

    def test_replay_after_later_commits_still_duplicate_from_binding(self) -> None:
        # Advance the ledger past r1: k now holds w@a:2, which dominates
        # the k record (v@a:1) the replayed request carries, and the outer
        # clock has moved past g's prerequisite.  Judged against current
        # state the records would be stale/missing; the saved request
        # binding must make the replay an unchanged duplicate instead.
        s2 = state(
            {"a": 2, "b": 1},
            {
                "k": record("w", False, {"a": 2}, "a"),
                "g": record("w", False, {"b": 1}, "b"),
            },
        )
        before_r2 = replication.apply_remote(self.path, self.req)

        second = replication.apply_remote(
            self.path, request(rid="r2", base=self.s1, remote=s2)
        )
        self.assertEqual(second["status"], "applied")
        before = ledger_raw(self.path)

        immediate = replication.apply_remote(self.path, self.req)
        again = replication.apply_remote(self.path, self.req)
        self.assertEqual(immediate, again)
        # The replay object is identical whether taken before or after the
        # intervening commit.
        self.assertEqual(immediate, before_r2)
        self.assertEqual(again["status"], "duplicate")
        self.assertEqual(again["items"], self.replay_items())
        self.assertTrue(all(item["decision"] == "duplicate" for item in again["items"]))
        self.assertTrue(all(item["need"] == {} for item in again["items"]))
        self.assertIsNone(again["receipt"])
        self.assertEqual(ledger_raw(self.path), before)

    def test_same_id_different_remote_raises_and_keeps_bytes(self) -> None:
        changed = request(
            remote=state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        )
        before = ledger_raw(self.path)
        with self.assertRaises(ValueError):
            replication.apply_remote(self.path, changed)
        self.assertEqual(ledger_raw(self.path), before)
        # A rejected differing request must not poison the true replay.
        self.assertEqual(
            replication.apply_remote(self.path, self.req)["status"], "duplicate"
        )

    def test_same_id_different_source_raises(self) -> None:
        changed = dict(self.req, source="other-node")
        with self.assertRaises(ValueError):
            replication.apply_remote(self.path, changed)

    def test_same_id_different_base_raises(self) -> None:
        changed = dict(self.req, base=state({"a": 1}))
        with self.assertRaises(ValueError):
            replication.apply_remote(self.path, changed)


class ApplyRemoteStaleGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        replication.apply_remote(self.path, request(rid="r1", remote=self.s1))

    def test_unknown_id_with_wrong_base_is_stale_and_writes_nothing(self) -> None:
        before = ledger_raw(self.path)
        remote = state({"a": 1}, {"z": record("q", False, {"a": 1}, "a")})
        result = replication.apply_remote(
            self.path, request(rid="r2", base=state(), remote=remote)
        )
        self.assertEqual(result["status"], "stale")
        self.assertEqual(result["items"], [])
        self.assertIsNone(result["receipt"])
        self.assertEqual(ledger_raw(self.path), before)

    def test_unknown_id_matching_base_proceeds_past_gate(self) -> None:
        remote = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        result = replication.apply_remote(
            self.path, request(rid="r2", base=self.s1, remote=remote)
        )
        self.assertEqual(result["status"], "applied")

    def test_stale_gate_uses_canonical_state_equivalence(self) -> None:
        # A zero-valued clock component serialises identically either way.
        base = state({"a": 1, "z": 0}, {"k": record("v", False, {"a": 1}, "a")})
        # Stored state has no z component; canonical bytes still differ, so
        # this is stale -- the comparison is exact canonical bytes.
        remote = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        result = replication.apply_remote(
            self.path, request(rid="r3", base=base, remote=remote)
        )
        self.assertEqual(result["status"], "stale")


class ApplyRemoteDecisionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def seed(self, seed_state):
        replication.apply_remote(
            self.path, request(rid="seed", base=state(), remote=seed_state)
        )

    def apply_against(self, seed_state, remote, rid="r"):
        return replication.apply_remote(
            self.path, request(rid=rid, base=seed_state, remote=remote)
        )

    def test_remote_dominates_is_apply(self) -> None:
        s = state({"a": 1}, {"k": record("old", False, {"a": 1}, "a")})
        self.seed(s)
        nxt = state({"a": 2}, {"k": record("new", False, {"a": 2}, "a")})
        result = self.apply_against(s, nxt)
        self.assertEqual(result["items"][0]["decision"], "apply")
        self.assertEqual(result["status"], "applied")

    def test_equal_record_is_duplicate_and_writes_nothing(self) -> None:
        s = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.seed(s)
        before = ledger_raw(self.path)
        result = self.apply_against(s, s, rid="d1")
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(result["items"][0]["decision"], "duplicate")
        self.assertIsNone(result["receipt"])
        self.assertEqual(ledger_raw(self.path), before)

    def test_local_dominates_is_stale(self) -> None:
        current = state({"a": 2}, {"k": record("new", False, {"a": 2}, "a")})
        self.seed(current)
        older = state({"a": 2}, {"k": record("old", False, {"a": 1}, "a")})
        result = self.apply_against(current, older, rid="s1")
        self.assertEqual(result["items"][0]["decision"], "stale")
        self.assertEqual(result["status"], "stale")
        self.assertIsNone(result["receipt"])

    def test_concurrent_records_conflict_and_do_not_commit(self) -> None:
        current = state({"a": 1, "b": 1},
                        {"k": record("x", False, {"a": 1}, "a"),
                         "bk": record("z", False, {"b": 1}, "b")})
        self.seed(current)
        other = state({"a": 1, "b": 1},
                      {"k": record("y", False, {"b": 1}, "b"),
                       "bk": record("z", False, {"b": 1}, "b")})
        before = ledger_raw(self.path)
        result = self.apply_against(current, other, rid="c1")
        decisions = {item["key"]: item["decision"] for item in result["items"]}
        self.assertEqual(decisions, {"bk": "duplicate", "k": "conflict"})
        self.assertEqual(result["status"], "conflict")
        self.assertIsNone(result["receipt"])
        self.assertEqual(ledger_raw(self.path), before)

    def test_apply_and_duplicate_together_commit(self) -> None:
        current = state({"a": 1},
                        {"k": record("x", False, {"a": 1}, "a"),
                         "g": record("g0", False, {"a": 1}, "a")})
        self.seed(current)
        nxt = state({"a": 2},
                    {"k": record("x", False, {"a": 1}, "a"),
                     "g": record("g1", False, {"a": 2}, "a")})
        result = self.apply_against(current, nxt, rid="mix")
        self.assertEqual(result["status"], "applied")
        self.assertEqual(
            [(i["key"], i["decision"]) for i in result["items"]],
            [("g", "apply"), ("k", "duplicate")],
        )
        stored = read_ledger(self.path)["state"]["records"]
        self.assertEqual(stored["g"], ["g1", False, {"a": 2}, "a"])
        self.assertEqual(stored["k"], ["x", False, {"a": 1}, "a"])

    def test_conflict_plus_apply_does_not_commit(self) -> None:
        current = state({"a": 1},
                        {"k": record("x", False, {"a": 1}, "a"),
                         "g": record("g0", False, {"a": 1}, "a")})
        self.seed(current)
        nxt = state({"a": 2, "b": 1},
                    {"k": record("y", False, {"b": 1}, "b"),
                     "g": record("g1", False, {"a": 2}, "a")})
        before = ledger_raw(self.path)
        result = self.apply_against(current, nxt, rid="cx")
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(ledger_raw(self.path), before)

    def test_stale_plus_apply_does_not_commit(self) -> None:
        s1 = state({"a": 1},
                   {"k": record("new", False, {"a": 1}, "a"),
                    "g": record("g0", False, {"a": 1}, "a")})
        replication.apply_remote(
            self.path, request(rid="p1", base=state(), remote=s1)
        )
        current = state({"a": 2},
                        {"k": record("new", False, {"a": 2}, "a"),
                         "g": record("g0", False, {"a": 1}, "a")})
        replication.apply_remote(
            self.path, request(rid="p2", base=s1, remote=current)
        )
        nxt = state({"a": 3},
                    {"k": record("old", False, {"a": 1}, "a"),
                     "g": record("g1", False, {"a": 3}, "a")})
        before = ledger_raw(self.path)
        result = replication.apply_remote(
            self.path, request(rid="sx", base=current, remote=nxt)
        )
        self.assertEqual(result["status"], "stale")
        self.assertEqual(ledger_raw(self.path), before)

    def test_missing_takes_precedence_over_conflict(self) -> None:
        current = state({"a": 1}, {"k": record("x", False, {"a": 1}, "a")})
        self.seed(current)
        nxt = state({"a": 1, "b": 2},
                    {"k": record("y", False, {"b": 1}, "b"),
                     "g": record("g", False, {"b": 2}, "b")})
        before = ledger_raw(self.path)
        result = self.apply_against(current, nxt, rid="mx")
        self.assertEqual(result["status"], "missing")
        self.assertEqual(ledger_raw(self.path), before)

    def test_empty_remote_records_is_duplicate_and_creates_nothing(self) -> None:
        path = os.path.join(self.dir, "fresh.json")
        result = replication.apply_remote(
            path, request(rid="e0", base=state(), remote=state())
        )
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(result["items"], [])
        self.assertIsNone(result["receipt"])
        self.assertFalse(os.path.exists(path))


class ApplyRemoteMissingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def seed(self, seed_state):
        replication.apply_remote(
            self.path, request(rid="seed", base=state(), remote=seed_state)
        )

    def test_writer_component_decremented_by_one_is_prerequisite(self) -> None:
        # Local outer clock a:2; record clock {a:3} written by a needs only
        # a:2 first, which is present, so it applies.
        current = state({"a": 2}, {"k": record("v2", False, {"a": 2}, "a")})
        self.seed(current)
        ready = state({"a": 3}, {"g": record("g", False, {"a": 3}, "a")})
        result = replication.apply_remote(
            self.path, request(rid="ok", base=current, remote=ready)
        )
        self.assertEqual(result["status"], "applied")

    def test_missing_interval_single_node(self) -> None:
        result = replication.apply_remote(
            self.path,
            request(remote=state({"a": 3}, {"k": record("v", False, {"a": 3}, "a")})),
        )
        self.assertEqual(result["status"], "missing")
        item = result["items"][0]
        self.assertEqual(item["decision"], "missing")
        self.assertEqual(item["need"], {"a": [1, 2]})
        self.assertFalse(os.path.exists(self.path))

    def test_missing_intervals_multiple_nodes_sorted(self) -> None:
        current = state({"a": 2}, {"x": record("v", False, {"a": 2}, "a")})
        self.seed(current)
        remote = state(
            {"a": 5, "b": 3},
            {"y": record("w", False, {"a": 5, "b": 3}, "b")},
        )
        result = replication.apply_remote(
            self.path, request(rid="m", base=current, remote=remote)
        )
        self.assertEqual(result["status"], "missing")
        self.assertEqual(
            result["items"][0]["need"], {"a": [3, 5], "b": [1, 2]}
        )

    def test_need_is_none_for_non_missing_items(self) -> None:
        current = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.seed(current)
        nxt = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        result = replication.apply_remote(
            self.path, request(rid="n", base=current, remote=nxt)
        )
        self.assertIsNone(result["items"][0]["need"])


class ApplyRemoteLedgerCorruptionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        replication.apply_remote(self.path, request(remote=self.s1))
        self.good = ledger_raw(self.path)

    def corrupt(self, raw):
        path = os.path.join(self.dir, "corrupt.json")
        with open(path, "wb") as handle:
            handle.write(raw)
        return path

    def reject(self, raw):
        path = self.corrupt(raw)
        with self.assertRaises(ValueError):
            replication.apply_remote(
                path, request(rid="x", base=self.s1, remote=self.s1)
            )
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), raw)

    def test_missing_trailing_newline(self) -> None:
        self.reject(self.good[:-1])

    def test_double_trailing_newline(self) -> None:
        self.reject(self.good + b"\n")

    def test_bad_version(self) -> None:
        self.reject(self.good.replace(b'"version":1', b'"version":2'))

    def test_wrong_top_level_key_set(self) -> None:
        data = json.loads(self.good)
        del data["requests"]
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.reject(raw)

    def test_invalid_state_is_value_error(self) -> None:
        self.reject(self.good.replace(b'"clock":{"a":1}', b'"clock":{"a":2}'))

    def test_state_type_fault_reports_as_value_error(self) -> None:
        data = json.loads(self.good)
        data["state"]["clock"]["a"] = True
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.reject(raw)

    def test_non_canonical_encoding(self) -> None:
        self.reject(self.good.replace(b'{"audit"', b'{ "audit"', 1))

    def test_bad_request_digest(self) -> None:
        self.reject(self.good.replace(b'"requests":{"r1":"',
                                      b'"requests":{"r1":"0', 1))

    def test_request_without_audit_entry(self) -> None:
        data = json.loads(self.good)
        data["requests"]["extra"] = "f" * 64
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.reject(raw)

    def test_audit_entry_without_request_binding(self) -> None:
        data = json.loads(self.good)
        data["audit"][0]["id"] = "renamed"
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.reject(raw)

    def test_broken_audit_chain(self) -> None:
        s2 = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        replication.apply_remote(
            self.path, request(rid="r2", base=self.s1, remote=s2)
        )
        data = json.loads(ledger_raw(self.path))
        data["audit"][1]["before"] = "f" * 64
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.reject(raw)

    def test_tail_after_must_hash_state(self) -> None:
        self.reject(self.good.replace(b'"k":["v"', b'"k":["w"', 1))

    def test_bad_seq(self) -> None:
        data = json.loads(self.good)
        data["audit"][0]["seq"] = 2
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.reject(raw)

    def test_requests_not_an_object(self) -> None:
        data = json.loads(self.good)
        data["requests"] = []
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.reject(raw)

    def test_empty_file_is_invalid(self) -> None:
        self.reject(b"")

    def test_garbage_is_invalid(self) -> None:
        self.reject(b"not json\n")

    def test_replay_still_requires_a_decodable_ledger(self) -> None:
        # A duplicate verdict is read from the saved binding, so a ledger
        # that can no longer be decoded is a ValueError (not a replay) and
        # is left untouched.
        path = self.corrupt(b"not json\n")
        with self.assertRaises(ValueError):
            replication.apply_remote(path, request(remote=self.s1))
        self.assertEqual(ledger_raw(path), b"not json\n")


class ApplyRemoteValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def call(self, request_obj):
        return replication.apply_remote(self.path, request_obj)

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            replication.apply_remote(1, request())

    def test_request_must_be_dict(self) -> None:
        with self.assertRaises(TypeError):
            self.call([])
        with self.assertRaises(TypeError):
            self.call(None)

    def test_request_key_set_must_match(self) -> None:
        good = request()
        with self.assertRaises(ValueError):
            self.call({"id": "r", "source": "s", "base": state()})
        extra = dict(good, extra=1)
        with self.assertRaises(ValueError):
            self.call(extra)

    def test_id_must_be_nonempty_str(self) -> None:
        with self.assertRaises(TypeError):
            self.call(request(rid=1))
        with self.assertRaises(TypeError):
            self.call(request(rid=True))
        with self.assertRaises(ValueError):
            self.call(request(rid=""))

    def test_source_must_be_nonempty_str(self) -> None:
        with self.assertRaises(TypeError):
            self.call(request(source=1))
        with self.assertRaises(ValueError):
            self.call(request(source=""))

    def test_states_must_obey_merge_contract(self) -> None:
        bad_clock = {"clock": {"a": -1}, "records": {}}
        with self.assertRaises(ValueError):
            self.call(request(base=bad_clock))
        bool_clock = {"clock": {"a": True}, "records": {}}
        with self.assertRaises(TypeError):
            self.call(request(remote=bool_clock))
        bad_record = state({"a": 1},
                           {"k": record("v", True, {"a": 1}, "a")})
        with self.assertRaises(ValueError):
            self.call(request(remote=bad_record))

    def test_input_validation_runs_before_filesystem(self) -> None:
        with mock.patch("builtins.open") as patched:
            with self.assertRaises(TypeError):
                replication.apply_remote(1, request())
            with self.assertRaises(ValueError):
                self.call(request(rid=""))
        patched.assert_not_called()


class ApplyRemoteAtomicityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.s2 = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        replication.apply_remote(self.path, request(remote=self.s1))
        self.before = ledger_raw(self.path)

    def advance(self, path, rid="r2"):
        return replication.apply_remote(
            path, request(rid=rid, base=self.s1, remote=self.s2)
        )

    def assert_no_artifacts(self, path) -> None:
        self.assertFalse(os.path.exists(path + ".tmp"))
        self.assertFalse(os.path.exists(path + ".old"))

    def failing_open(self, failing_attr: str, exc: OSError):
        real_open = open

        class FailingFile:
            def __init__(self, *args, **kwargs):
                self._handle = real_open(*args, **kwargs)

            def write(self, data):
                if failing_attr == "write":
                    raise exc
                return self._handle.write(data)

            def flush(self):
                if failing_attr == "flush":
                    raise exc
                return self._handle.flush()

            def __getattr__(self, name):
                return getattr(self._handle, name)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self._handle.close()
                return False

        return mock.patch(
            "builtins.open",
            side_effect=lambda *a, **k: FailingFile(*a, **k),
        )

    def failure_injectors(self, exc: OSError):
        # name -> context manager factory simulating an OSError at one
        # specific stage of the commit boundary.
        return [
            ("write", lambda: self.failing_open("write", exc)),
            ("flush", lambda: self.failing_open("flush", exc)),
            ("file fsync", lambda: mock.patch("os.fsync", side_effect=exc)),
            ("link", lambda: mock.patch("os.link", side_effect=exc)),
            ("replace", lambda: mock.patch("os.replace", side_effect=exc)),
            ("dir open", lambda: mock.patch("os.open", side_effect=exc)),
            ("dir fsync",
             lambda: mock.patch("offline_coordination.storage._fsync_dir",
                                side_effect=exc)),
        ]

    def seed_ledger(self, name):
        path = os.path.join(self.dir, f"ledger-{name}.json")
        replication.apply_remote(path, request(remote=self.s1))
        return path, ledger_raw(path)

    def test_every_failure_stage_preserves_existing_ledger_bytes(self) -> None:
        for name, make_patch in self.failure_injectors(OSError("disk gone")):
            tag = name.replace(" ", "-")
            with self.subTest(stage=name):
                path, before = self.seed_ledger(tag)
                with make_patch():
                    with self.assertRaises(OSError):
                        replication.apply_remote(
                            path, request(rid="r2", base=self.s1, remote=self.s2)
                        )
                self.assertEqual(
                    ledger_raw(path), before,
                    msg=f"ledger bytes changed after failure at {name}",
                )
                self.assert_no_artifacts(path)
                # The failed transaction commits cleanly on retry: the id
                # was never bound and the predecessor stayed readable.
                result = replication.apply_remote(
                    path, request(rid="r2", base=self.s1, remote=self.s2)
                )
                self.assertEqual(result["status"], "applied")
                self.assertTrue(
                    replication.apply_remote(
                        path, request(rid="r2", base=self.s1, remote=self.s2)
                    )["status"]
                    == "duplicate"
                )

    def test_every_failure_stage_keeps_missing_ledger_missing(self) -> None:
        # The link stage only exists when a predecessor is retained; a
        # missing ledger goes write -> install -> sync instead.
        for name, make_patch in self.failure_injectors(OSError("disk gone")):
            if name == "link":
                continue
            fresh = os.path.join(self.dir, f"fresh-{name.replace(' ', '-')}.json")
            with self.subTest(stage=name):
                with make_patch():
                    with self.assertRaises(OSError):
                        replication.apply_remote(
                            fresh, request(remote=self.s1)
                        )
                self.assertFalse(os.path.exists(fresh))
                self.assert_no_artifacts(fresh)
                # No recognizable ledger or artifact may influence retry.
                result = replication.apply_remote(
                    fresh, request(remote=self.s1)
                )
                self.assertEqual(result["status"], "applied")
                self.assertEqual(
                    read_ledger(fresh)["state"],
                    {"clock": {"a": 1},
                     "records": {"k": ["v", False, {"a": 1}, "a"]}},
                )

    def test_original_exception_propagates_unchanged(self) -> None:
        sentinel = OSError("the one true error")
        for name, make_patch in self.failure_injectors(sentinel):
            with self.subTest(stage=name):
                with make_patch():
                    with self.assertRaises(OSError) as caught:
                        self.advance(
                            self.path, rid="e-" + name.replace(" ", "-")
                        )
                self.assertIs(caught.exception, sentinel)

    def test_dir_fsync_failure_after_install_restores_predecessor(self) -> None:
        # This is the window the old implementation got wrong: the new
        # bytes had already replaced the ledger when the directory sync
        # failed.  Rollback must publish the predecessor back.
        inode_before = os.stat(self.path).st_ino
        with mock.patch(
            "offline_coordination.storage._fsync_dir",
            side_effect=OSError("dir sync failed"),
        ):
            with self.assertRaises(OSError):
                self.advance(self.path)
        self.assertEqual(ledger_raw(self.path), self.before)
        self.assertEqual(os.stat(self.path).st_ino, inode_before)
        self.assert_no_artifacts(self.path)

    def test_recovery_itself_syncs_the_directory(self) -> None:
        for existed in (True, False):
            with self.subTest(existed=existed):
                path = self.path if existed else os.path.join(self.dir, "m.json")
                with mock.patch(
                    "offline_coordination.storage._fsync_dir",
                    side_effect=[OSError("first sync fails"), None],
                ) as synced:
                    with self.assertRaises(OSError):
                        self.advance(path, rid="d")
                # One sync attempt for the commit, one more for the rollback.
                self.assertGreaterEqual(synced.call_count, 2)
                if existed:
                    self.assertEqual(ledger_raw(path), self.before)
                else:
                    self.assertFalse(os.path.exists(path))
                self.assert_no_artifacts(path)

    def test_success_leaves_no_artifacts_and_syncs(self) -> None:
        with mock.patch(
            "offline_coordination.storage._fsync_dir",
            wraps=storage._fsync_dir,
        ) as synced:
            result = self.advance(self.path)
        self.assertEqual(result["status"], "applied")
        self.assert_no_artifacts(self.path)
        synced.assert_called()

    def test_stale_old_artifact_from_interrupted_call_is_swept(self) -> None:
        # Simulate garbage left by a killed process at both internal names.
        with open(self.path + ".old", "wb") as handle:
            handle.write(b"stale predecessor link\n")
        with open(self.path + ".tmp", "wb") as handle:
            handle.write(b"stale temporary file\n")
        result = self.advance(self.path)
        self.assertEqual(result["status"], "applied")
        self.assert_no_artifacts(self.path)
        # The current ledger is still a perfectly valid ledger.
        self.assertEqual(
            replication.apply_remote(
                self.path, request(rid="r2", base=self.s1, remote=self.s2)
            )["status"],
            "duplicate",
        )

    def test_stale_artifacts_swept_on_missing_path_too(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        with open(fresh + ".old", "wb") as handle:
            handle.write(b"x")
        with open(fresh + ".tmp", "wb") as handle:
            handle.write(b"y")
        result = replication.apply_remote(fresh, request(remote=self.s1))
        self.assertEqual(result["status"], "applied")
        self.assert_no_artifacts(fresh)

    # The two scenarios the previous test suite pinned, kept verbatim.
    def test_fsync_failure_keeps_missing_path_missing(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                replication.apply_remote(
                    fresh, request(remote=self.s1)
                )
        self.assertFalse(os.path.exists(fresh))
        self.assertFalse(os.path.exists(fresh + ".tmp"))

    def test_fsync_failure_preserves_existing_bytes(self) -> None:
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                self.advance(self.path)
        self.assertEqual(ledger_raw(self.path), self.before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))

    def test_replace_failure_preserves_existing_bytes(self) -> None:
        with mock.patch("os.replace", side_effect=OSError("rename failed")):
            with self.assertRaises(OSError):
                self.advance(self.path)
        self.assertEqual(ledger_raw(self.path), self.before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))


class ApplyRemoteNoWritesOnRejectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def artifacts(self):
        return sorted(
            name for name in os.listdir(self.dir)
            if name.startswith(os.path.basename(self.path))
        )

    def test_type_errors_create_no_files(self) -> None:
        with self.assertRaises(TypeError):
            replication.apply_remote(self.path, request(rid=1))
        with self.assertRaises(TypeError):
            replication.apply_remote(1, request())
        self.assertEqual(os.listdir(self.dir), [])

    def test_value_errors_create_no_files(self) -> None:
        with self.assertRaises(ValueError):
            replication.apply_remote(self.path, request(rid=""))
        # A business-level duplicate on a never-created ledger path (empty
        # remote against the base state) likewise writes nothing.
        result = replication.apply_remote(
            self.path, request(rid="e0", base=state(), remote=state())
        )
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(os.listdir(self.dir), [])
        # The rejected call left nothing a retry would recognise.
        s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        applied = replication.apply_remote(self.path, request(remote=s1))
        self.assertEqual(applied["status"], "applied")
        self.assertEqual(self.artifacts(), [os.path.basename(self.path)])


# ---------------------------------------------------------------------------
# apply_signed_remote: authenticated remote-state application
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402
import hmac  # noqa: E402

from offline_coordination.replication import AuthenticationError  # noqa: E402

SECRET_A = "a" * 64
SECRET_B = "b" * 64
NOW = 50


def sign(secret, node, key_version, request_obj):
    payload = json.dumps(
        {"keyVersion": key_version, "node": node, "request": request_obj},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(
        bytes.fromhex(secret), payload, hashlib.sha256
    ).hexdigest()


def key_entry(version=1, secret=SECRET_A, not_before=0, not_after=100,
              revoked=False):
    return {
        "version": version,
        "secret": secret,
        "notBefore": not_before,
        "notAfter": not_after,
        "revoked": revoked,
    }


def keyring(*entries, node="node-a"):
    return {node: list(entries)}


def signed_envelope(request_obj, node="node-a", key_version=1,
                    secret=SECRET_A):
    return {
        "node": node,
        "keyVersion": key_version,
        "request": request_obj,
        "signature": sign(secret, node, key_version, request_obj),
    }


class ApplySignedRemoteBasicTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.remote = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.req = request(source="node-a", remote=self.remote)

    def apply(self, req=None, ring=None, **envelope_overrides):
        env = signed_envelope(req if req is not None else self.req)
        env.update(envelope_overrides)
        return replication.apply_signed_remote(
            self.path, ring if ring is not None else keyring(key_entry()), env,
            NOW,
        )

    def test_applies_and_records_auth_on_audit_entry(self) -> None:
        result = self.apply()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(tuple(result.keys()), APPLY_RESULT_KEYS)
        self.assertIsNotNone(result["receipt"])
        ledger = read_ledger(self.path)
        self.assertEqual(ledger["audit"][0]["auth"],
                         {"keyVersion": 1, "node": "node-a"})
        self.assertEqual(
            tuple(ledger["audit"][0].keys()),
            ("after", "auth", "before", "id", "seq", "source"),
        )
        self.assertEqual(ledger["state"]["records"]["k"],
                         ["v", False, {"a": 1}, "a"])

    def test_ledger_stays_canonical_with_auth_entries(self) -> None:
        self.apply()
        raw = ledger_raw(self.path)
        decoded = json.loads(raw)
        self.assertEqual(
            raw,
            json.dumps(decoded, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode("utf-8") + b"\n",
        )

    def test_unicode_request_signs_and_applies(self) -> None:
        remote = state({"a": 1}, {"k": record("雪 ☃", False, {"a": 1}, "a")})
        result = self.apply(req=request(source="node-a", remote=remote))
        self.assertEqual(result["status"], "applied")
        self.assertIn("雪 ☃".encode("utf-8"), ledger_raw(self.path))

    def test_validity_bounds_are_inclusive(self) -> None:
        ring = keyring(key_entry(not_before=10, not_after=20))
        for moment in (10, 20):
            path = os.path.join(self.dir, f"m{moment}.json")
            env = signed_envelope(request(source="node-a", remote=self.remote))
            result = replication.apply_signed_remote(path, ring, env, moment)
            self.assertEqual(result["status"], "applied")

    def test_exact_key_version_selected_without_fallback(self) -> None:
        ring = keyring(key_entry(version=1, secret=SECRET_A),
                       key_entry(version=2, secret=SECRET_B))
        env = signed_envelope(self.req, key_version=2, secret=SECRET_B)
        result = replication.apply_signed_remote(self.path, ring, env, NOW)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_ledger(self.path)["audit"][0]["auth"],
                         {"keyVersion": 2, "node": "node-a"})

    def test_replay_with_still_valid_key_is_duplicate(self) -> None:
        self.apply()
        before = ledger_raw(self.path)
        again = self.apply()
        self.assertEqual(again["status"], "duplicate")
        self.assertIsNone(again["receipt"])
        self.assertEqual(ledger_raw(self.path), before)


class ApplySignedRemoteAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.remote = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.req = request(source="node-a", remote=self.remote)
        self.ring = keyring(key_entry(not_before=10, not_after=90))

    def apply(self, ring=None, env=None, moment=NOW):
        return replication.apply_signed_remote(
            self.path,
            ring if ring is not None else self.ring,
            env if env is not None else signed_envelope(self.req),
            moment,
        )

    def test_authentication_error_is_a_value_error(self) -> None:
        self.assertTrue(issubclass(AuthenticationError, ValueError))
        with self.assertRaises(ValueError):
            self.apply(env=signed_envelope(self.req, node="ghost"))

    def test_unknown_node_rejected(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.apply(env=signed_envelope(self.req, node="ghost"))

    def test_unknown_key_version_rejected(self) -> None:
        env = signed_envelope(self.req, key_version=2)
        with self.assertRaises(AuthenticationError):
            self.apply(env=env)

    def test_revoked_key_rejected(self) -> None:
        ring = keyring(key_entry(not_before=10, not_after=90, revoked=True))
        with self.assertRaises(AuthenticationError):
            self.apply(ring=ring)

    def test_not_yet_valid_key_rejected(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.apply(moment=9)

    def test_expired_key_rejected(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.apply(moment=91)

    def test_source_node_mismatch_rejected(self) -> None:
        req = request(source="node-b", remote=self.remote)
        env = signed_envelope(req)  # envelope node stays node-a
        with self.assertRaises(AuthenticationError):
            self.apply(env=env)

    def test_signature_mismatch_rejected(self) -> None:
        env = signed_envelope(self.req, secret=SECRET_B)
        with self.assertRaises(AuthenticationError):
            self.apply(env=env)

    def test_tampered_request_rejected(self) -> None:
        env = signed_envelope(self.req)
        env["request"] = request(rid="other", source="node-a",
                                 remote=self.remote)
        with self.assertRaises(AuthenticationError):
            self.apply(env=env)

    def test_wrong_version_secret_combination_rejected(self) -> None:
        # Signing with version 2's secret while claiming version 1 must not
        # fall back to any other key.
        ring = keyring(key_entry(version=1, secret=SECRET_A, not_before=10,
                                 not_after=90),
                       key_entry(version=2, secret=SECRET_B, not_before=10,
                                 not_after=90))
        env = signed_envelope(self.req, key_version=1, secret=SECRET_B)
        with self.assertRaises(AuthenticationError):
            self.apply(ring=ring, env=env)

    def test_auth_failure_creates_no_file(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.apply(env=signed_envelope(self.req, node="ghost"))
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(os.listdir(self.dir), [])

    def test_verification_precedes_ledger_read(self) -> None:
        # A corrupt ledger is a ValueError, but the authentication failure
        # must win: verification happens before any ledger read.
        with open(self.path, "wb") as handle:
            handle.write(b"not json\n")
        with self.assertRaises(AuthenticationError):
            self.apply(env=signed_envelope(self.req, node="ghost"))
        self.assertEqual(ledger_raw(self.path), b"not json\n")

    def test_auth_failure_performs_no_filesystem_reads(self) -> None:
        with mock.patch("builtins.open") as patched:
            with self.assertRaises(AuthenticationError):
                self.apply(env=signed_envelope(self.req, node="ghost"))
        patched.assert_not_called()

    def test_replay_rejected_after_revocation(self) -> None:
        self.apply()
        revoked_ring = keyring(
            key_entry(not_before=10, not_after=90, revoked=True)
        )
        with self.assertRaises(AuthenticationError):
            self.apply(ring=revoked_ring)

    def test_replay_rejected_after_expiry(self) -> None:
        self.apply()
        with self.assertRaises(AuthenticationError):
            self.apply(moment=91)

    def test_replay_accepted_with_rotated_keyring(self) -> None:
        # Rotation that keeps the used credential valid does not break the
        # historical binding.
        self.apply()
        rotated = keyring(key_entry(not_before=10, not_after=90),
                          key_entry(version=2, secret=SECRET_B))
        again = self.apply(ring=rotated)
        self.assertEqual(again["status"], "duplicate")


class ApplySignedRemoteValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.remote = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.req = request(source="node-a", remote=self.remote)
        self.env = signed_envelope(self.req)
        self.ring = keyring(key_entry())

    def call(self, path=None, ring=None, env=None, moment=NOW):
        return replication.apply_signed_remote(
            path if path is not None else self.path,
            ring if ring is not None else self.ring,
            env if env is not None else self.env,
            moment,
        )

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            self.call(path=1)

    def test_moment_must_be_non_negative_int(self) -> None:
        with self.assertRaises(TypeError):
            self.call(moment=True)
        with self.assertRaises(TypeError):
            self.call(moment=1.0)
        with self.assertRaises(TypeError):
            self.call(moment="50")
        with self.assertRaises(ValueError):
            self.call(moment=-1)

    def test_keyring_must_be_dict_with_str_nodes(self) -> None:
        with self.assertRaises(TypeError):
            self.call(ring=[])
        with self.assertRaises(TypeError):
            self.call(ring={1: [key_entry()]})
        with self.assertRaises(ValueError):
            self.call(ring={"": [key_entry()]})

    def test_keyring_entries_must_be_list_of_dicts(self) -> None:
        with self.assertRaises(TypeError):
            self.call(ring={"node-a": {}})
        with self.assertRaises(TypeError):
            self.call(ring={"node-a": ["x"]})

    def test_keyring_entry_key_set(self) -> None:
        entry = key_entry()
        del entry["revoked"]
        with self.assertRaises(ValueError):
            self.call(ring=keyring(entry))
        extra = dict(key_entry(), extra=1)
        with self.assertRaises(ValueError):
            self.call(ring=keyring(extra))

    def test_keyring_version_rules(self) -> None:
        with self.assertRaises(TypeError):
            self.call(ring=keyring(key_entry(version=True)))
        with self.assertRaises(TypeError):
            self.call(ring=keyring(key_entry(version=1.0)))
        with self.assertRaises(ValueError):
            self.call(ring=keyring(key_entry(version=0)))
        with self.assertRaises(ValueError):
            self.call(ring=keyring(key_entry(version=-2)))
        with self.assertRaises(ValueError):
            self.call(ring=keyring(key_entry(version=1),
                                   key_entry(version=1,
                                             secret=SECRET_B)))

    def test_keyring_secret_format(self) -> None:
        with self.assertRaises(TypeError):
            self.call(ring=keyring(key_entry(secret=1)))
        with self.assertRaises(ValueError):
            self.call(ring=keyring(key_entry(secret="A" * 64)))
        with self.assertRaises(ValueError):
            self.call(ring=keyring(key_entry(secret="a" * 63)))
        with self.assertRaises(ValueError):
            self.call(ring=keyring(key_entry(secret="g" * 64)))

    def test_keyring_validity_period_rules(self) -> None:
        with self.assertRaises(TypeError):
            self.call(ring=keyring(key_entry(not_before=True)))
        with self.assertRaises(TypeError):
            self.call(ring=keyring(key_entry(not_after="9")))
        with self.assertRaises(ValueError):
            self.call(ring=keyring(key_entry(not_before=-1)))
        with self.assertRaises(ValueError):
            self.call(ring=keyring(key_entry(not_before=10, not_after=9)))

    def test_keyring_revoked_must_be_bool(self) -> None:
        with self.assertRaises(TypeError):
            self.call(ring=keyring(key_entry(revoked=0)))

    def test_envelope_must_be_dict_with_exact_keys(self) -> None:
        with self.assertRaises(TypeError):
            self.call(env=[])
        env = signed_envelope(self.req)
        del env["signature"]
        with self.assertRaises(ValueError):
            self.call(env=env)
        with self.assertRaises(ValueError):
            self.call(env=dict(signed_envelope(self.req), extra=1))

    def test_envelope_node_rules(self) -> None:
        with self.assertRaises(TypeError):
            self.call(env=dict(self.env, node=1))
        with self.assertRaises(ValueError):
            self.call(env=dict(self.env, node=""))

    def test_envelope_key_version_rules(self) -> None:
        with self.assertRaises(TypeError):
            self.call(env=dict(self.env, keyVersion=True))
        with self.assertRaises(TypeError):
            self.call(env=dict(self.env, keyVersion="1"))
        with self.assertRaises(ValueError):
            self.call(env=dict(self.env, keyVersion=0))

    def test_envelope_signature_format(self) -> None:
        with self.assertRaises(TypeError):
            self.call(env=dict(self.env, signature=1))
        with self.assertRaises(ValueError):
            self.call(env=dict(self.env, signature="F" * 64))
        with self.assertRaises(ValueError):
            self.call(env=dict(self.env, signature="f" * 63))

    def test_request_contract_is_enforced(self) -> None:
        with self.assertRaises(TypeError):
            self.call(env=dict(self.env, request=[]))
        bad = dict(self.env)
        bad["request"] = {"id": "r", "source": "node-a", "base": state()}
        with self.assertRaises(ValueError):
            self.call(env=bad)

    def test_validation_creates_no_files(self) -> None:
        with self.assertRaises(TypeError):
            self.call(ring=[])
        with self.assertRaises(ValueError):
            self.call(env=dict(self.env, keyVersion=0))
        with self.assertRaises(ValueError):
            self.call(moment=-1)
        self.assertEqual(os.listdir(self.dir), [])


class ApplySignedRemoteLedgerCompatTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.s2 = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        self.ring = keyring(key_entry())

    def signed(self, req, **overrides):
        env = signed_envelope(req)
        env.update(overrides)
        return env

    def test_unsigned_then_signed_commit(self) -> None:
        replication.apply_remote(
            self.path, request(rid="r1", source="node-a", remote=self.s1)
        )
        result = replication.apply_signed_remote(
            self.path, self.ring,
            self.signed(request(rid="r2", source="node-a", base=self.s1,
                                remote=self.s2)),
            NOW,
        )
        self.assertEqual(result["status"], "applied")
        entries = read_ledger(self.path)["audit"]
        self.assertNotIn("auth", entries[0])
        self.assertEqual(entries[1]["auth"],
                         {"keyVersion": 1, "node": "node-a"})
        self.assertEqual(entries[1]["before"], entries[0]["after"])

    def test_signed_then_unsigned_commit_and_replay(self) -> None:
        req = request(rid="r1", source="node-a", remote=self.s1)
        replication.apply_signed_remote(
            self.path, self.ring, self.signed(req), NOW
        )
        # The unsigned entry point reads the auth-carrying ledger fine and
        # serves the replay from the saved binding.
        again = replication.apply_remote(self.path, req)
        self.assertEqual(again["status"], "duplicate")
        result = replication.apply_remote(
            self.path, request(rid="r2", source="node-a", base=self.s1,
                               remote=self.s2)
        )
        self.assertEqual(result["status"], "applied")
        entries = read_ledger(self.path)["audit"]
        self.assertEqual(entries[0]["auth"],
                         {"keyVersion": 1, "node": "node-a"})
        self.assertNotIn("auth", entries[1])

    def test_corrupt_auth_entry_rejected(self) -> None:
        replication.apply_signed_remote(
            self.path, self.ring,
            self.signed(request(rid="r1", source="node-a", remote=self.s1)),
            NOW,
        )
        good = ledger_raw(self.path)
        variants = []
        data = json.loads(good)
        data["audit"][0]["auth"] = {"node": "node-a"}
        variants.append(data)
        data = json.loads(good)
        data["audit"][0]["auth"]["keyVersion"] = 0
        variants.append(data)
        data = json.loads(good)
        data["audit"][0]["auth"]["keyVersion"] = True
        variants.append(data)
        data = json.loads(good)
        data["audit"][0]["auth"]["node"] = ""
        variants.append(data)
        for index, variant in enumerate(variants):
            path = os.path.join(self.dir, f"bad{index}.json")
            raw = json.dumps(variant, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8") + b"\n"
            with open(path, "wb") as handle:
                handle.write(raw)
            with self.assertRaises(ValueError):
                replication.apply_remote(
                    path, request(rid="x", source="node-a", base=self.s1,
                                  remote=self.s2)
                )
            self.assertEqual(ledger_raw(path), raw)


class TransactionArtifactResilienceTest(unittest.TestCase):
    """Fixed .tmp/.old leftovers never block a commit or get read.

    Commits reserve unique transaction file names, so a stale fixed-name
    leftover from a killed process cannot collide; sweeping the fixed
    leftovers is best-effort and must not turn into a raised error.
    """

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.s2 = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})

    def seed(self, path):
        replication.apply_remote(path, request(remote=self.s1))

    def advance(self, path, rid="r2"):
        return replication.apply_remote(
            path, request(rid=rid, base=self.s1, remote=self.s2)
        )

    def leave_fixed(self, path) -> None:
        with open(path + ".tmp", "wb") as handle:
            handle.write(b"stale temporary file\n")
        with open(path + ".old", "wb") as handle:
            handle.write(b"stale predecessor link\n")

    def test_fixed_leftovers_are_never_read_as_ledger(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        before = ledger_raw(path)
        self.leave_fixed(path)
        self.advance(path)
        # The ledger advanced normally; the garbage leftovers were not
        # consulted as predecessor or state.
        self.assertEqual(read_ledger(path)["state"], self.s2)
        self.assertNotEqual(ledger_raw(path), before)

    def test_sweep_failure_does_not_block_commit_on_missing_path(self) -> None:
        path = os.path.join(self.dir, "fresh.json")
        self.leave_fixed(path)
        with mock.patch("os.unlink", side_effect=OSError("immutable")):
            result = replication.apply_remote(path, request(remote=self.s1))
        self.assertEqual(result["status"], "applied")
        # The fixed leftovers could not be removed, but the ledger exists.
        self.assertTrue(os.path.exists(path))
        self.assertEqual(read_ledger(path)["state"], self.s1)

    def test_sweep_failure_does_not_block_commit_on_existing_path(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        self.leave_fixed(path)
        with mock.patch("os.unlink", side_effect=OSError("immutable")):
            result = self.advance(path)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_ledger(path)["state"], self.s2)

    def test_successful_commit_sweeps_fixed_leftovers(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        self.leave_fixed(path)
        self.advance(path)
        self.assertFalse(os.path.exists(path + ".tmp"))
        self.assertFalse(os.path.exists(path + ".old"))

    def test_transaction_files_use_unique_non_conflicting_names(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        seen = []

        real_token_hex = replication.secrets.token_hex

        def recording_token_hex(nbytes):
            value = real_token_hex(nbytes)
            seen.append(value)
            return value

        with mock.patch("offline_coordination.replication.secrets.token_hex",
                        side_effect=recording_token_hex):
            self.advance(path)
        self.assertTrue(seen)
        for value in seen:
            self.assertTrue(
                os.path.basename(path) + ".tmp-" + value
                != os.path.basename(path) + ".tmp"
            )
        # No internal artifacts survive success and the fixed slots were
        # never the transaction files.
        listing = os.listdir(self.dir)
        self.assertEqual(
            [n for n in listing if ".tmp-" in n or ".old-" in n],
            [],
        )

    def test_reservation_retries_on_name_collision(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        collision = os.path.join(
            self.dir, os.path.basename(path) + ".tmp-once"
        )
        with open(collision, "wb") as handle:
            handle.write(b"untouched")
        names = iter(["once", "twice", "thrice"])
        with mock.patch("offline_coordination.replication.secrets.token_hex",
                        side_effect=lambda n: next(names)):
            result = self.advance(path)
        self.assertEqual(result["status"], "applied")
        # O_EXCL reservation skipped the occupied name rather than
        # truncating it; the transaction used another name and cleaned it.
        with open(collision, "rb") as handle:
            self.assertEqual(handle.read(), b"untouched")
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, os.path.basename(path) + ".tmp-twice")
        ))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, os.path.basename(path) + ".old-thrice")
        ))

    def test_backup_link_name_is_unique_too(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        names = []
        real_link = os.link

        def recording_link(src, dst):
            names.append(os.path.basename(dst))
            return real_link(src, dst)

        with mock.patch("os.link", side_effect=recording_link):
            self.advance(path)
        self.assertEqual(len(names), 1)
        self.assertTrue(names[0].startswith(os.path.basename(path) + ".old-"))
        self.assertNotEqual(names[0], os.path.basename(path) + ".old")
        self.assertEqual(
            [n for n in os.listdir(self.dir) if n.endswith(".old")],
            [],
        )

    def test_repeated_commits_use_distinct_transaction_names(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        used = set()
        real_token_hex = replication.secrets.token_hex

        def tracking_token_hex(nbytes):
            value = real_token_hex(nbytes)
            used.add(value)
            return value

        s3 = state({"a": 3}, {"k": record("z", False, {"a": 3}, "a")})
        with mock.patch("offline_coordination.replication.secrets.token_hex",
                        side_effect=tracking_token_hex):
            self.advance(path, rid="r2")
            replication.apply_remote(
                path, request(rid="r3", base=self.s2, remote=s3)
            )
        self.assertGreaterEqual(len(used), 2)

    def test_write_failure_with_blocked_sweep_restores_and_reraises(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        before = ledger_raw(path)
        real_open = open

        class FailingFile:
            def __init__(self, *args, **kwargs):
                self._handle = real_open(*args, **kwargs)

            def write(self, data):
                raise OSError("write fail")

            def __getattr__(self, name):
                return getattr(self._handle, name)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self._handle.close()
                return False

        with mock.patch("os.unlink", side_effect=OSError("immutable")):
            with mock.patch("builtins.open",
                            side_effect=lambda *a, **k: FailingFile(*a, **k)):
                with self.assertRaises(OSError):
                    self.advance(path)
        self.assertEqual(ledger_raw(path), before)

    def test_leftovers_do_not_affect_replication_status_behaviour(self) -> None:
        path = os.path.join(self.dir, "ledger.json")
        self.seed(path)
        self.leave_fixed(path)
        # An exact replay is still a duplicate despite the leftovers.
        result = replication.apply_remote(path, request(remote=self.s1))
        self.assertEqual(result["status"], "duplicate")
        self.leave_fixed(path)
        # Advancing still applies.
        self.assertEqual(self.advance(path)["status"], "applied")


class ApplySignedRemoteAtomicityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.s2 = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        self.ring = keyring(key_entry())
        replication.apply_signed_remote(
            self.path, self.ring,
            signed_envelope(request(rid="r1", source="node-a",
                                    remote=self.s1)),
            NOW,
        )
        self.before = ledger_raw(self.path)

    def advance(self, path=None):
        return replication.apply_signed_remote(
            path if path is not None else self.path,
            self.ring,
            signed_envelope(request(rid="r2", source="node-a", base=self.s1,
                                    remote=self.s2)),
            NOW,
        )

    def test_fsync_failure_preserves_existing_bytes(self) -> None:
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                self.advance()
        self.assertEqual(ledger_raw(self.path), self.before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertFalse(os.path.exists(self.path + ".old"))

    def test_replace_failure_keeps_missing_path_missing(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        with mock.patch("os.replace", side_effect=OSError("rename failed")):
            with self.assertRaises(OSError):
                self.advance(path=fresh)
        self.assertFalse(os.path.exists(fresh))
        self.assertFalse(os.path.exists(fresh + ".tmp"))

    def test_commit_retries_cleanly_after_failure(self) -> None:
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                self.advance()
        result = self.advance()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_ledger(self.path)["audit"][1]["auth"],
                         {"keyVersion": 1, "node": "node-a"})


if __name__ == "__main__":
    unittest.main()
