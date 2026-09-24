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
        self.s1 = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        self.req = request(remote=self.s1)
        self.first = replication.apply_remote(self.path, self.req)

    def test_same_id_same_request_is_duplicate_with_unchanged_bytes(self) -> None:
        before = ledger_raw(self.path)
        again = replication.apply_remote(self.path, self.req)
        self.assertEqual(again["status"], "duplicate")
        self.assertEqual(
            again["items"],
            [{"key": "k", "decision": "duplicate", "need": {}}],
        )
        self.assertIsNone(again["receipt"])
        self.assertEqual(ledger_raw(self.path), before)

    def test_replay_finds_its_own_entry_after_later_applies(self) -> None:
        s2 = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        replication.apply_remote(self.path, request(rid="r2", base=self.s1, remote=s2))
        again = replication.apply_remote(self.path, self.req)
        self.assertEqual(again["status"], "duplicate")
        self.assertIsNone(again["receipt"])
        self.assertEqual(
            again["items"],
            [{"key": "k", "decision": "duplicate", "need": {}}],
        )

    def test_replay_after_advancing_state_never_turns_stale(self) -> None:
        # The replay's base is the empty state; once r2 commits the current
        # state has moved past it.  The verdict must still come solely from
        # the saved request binding, not from a fresh base comparison.
        s2 = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        replication.apply_remote(self.path, request(rid="r2", base=self.s1, remote=s2))
        before = ledger_raw(self.path)
        again = replication.apply_remote(self.path, self.req)
        self.assertEqual(again["status"], "duplicate")
        self.assertEqual(ledger_raw(self.path), before)

    def test_replay_items_are_sorted_by_remote_key_with_empty_need(self) -> None:
        path = os.path.join(self.dir, "multi.json")
        remote = state(
            {"a": 1},
            {
                "z": record("z", False, {"a": 1}, "a"),
                "a": record("a", False, {"a": 1}, "a"),
                "m": record("m", False, {"a": 1}, "a"),
            },
        )
        req = request(rid="multi", remote=remote)
        replication.apply_remote(path, req)
        before = ledger_raw(path)
        again = replication.apply_remote(path, req)
        self.assertEqual([item["key"] for item in again["items"]], ["a", "m", "z"])
        self.assertTrue(
            all(
                item["decision"] == "duplicate" and item["need"] == {}
                for item in again["items"]
            )
        )
        self.assertIsNone(again["receipt"])
        self.assertEqual(ledger_raw(path), before)

    def test_same_id_different_remote_raises_and_keeps_bytes(self) -> None:
        changed = request(
            remote=state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        )
        before = ledger_raw(self.path)
        with self.assertRaises(ValueError):
            replication.apply_remote(self.path, changed)
        self.assertEqual(ledger_raw(self.path), before)

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
        replication.apply_remote(self.path, request(remote=self.s1))

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
        before = ledger_raw(self.path)
        nxt = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                replication.apply_remote(
                    self.path, request(rid="r2", base=self.s1, remote=nxt)
                )
        self.assertEqual(ledger_raw(self.path), before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))

    def test_replace_failure_preserves_existing_bytes(self) -> None:
        before = ledger_raw(self.path)
        nxt = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        with mock.patch("os.replace", side_effect=OSError("rename failed")):
            with self.assertRaises(OSError):
                replication.apply_remote(
                    self.path, request(rid="r3", base=self.s1, remote=nxt)
                )
        self.assertEqual(ledger_raw(self.path), before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertFalse(os.path.exists(self.path + ".bak.apply"))

    def _failing_open(self, failing_method: str, message: str):
        """Patch builtins.open so the named tmp-file method raises OSError."""
        real_open = open

        class FailingFile:
            def __init__(self, *args, **kwargs):
                self._handle = real_open(*args, **kwargs)

            def __getattr__(self, name):
                if name == failing_method:
                    raise OSError(message)
                return getattr(self._handle, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._handle.close()
                return False

        return mock.patch(
            "builtins.open",
            side_effect=lambda *a, **k: FailingFile(*a, **k),
        )

    def test_write_failure_preserves_existing_bytes(self) -> None:
        before = ledger_raw(self.path)
        nxt = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        with self._failing_open("write", "write failed"):
            with self.assertRaisesRegex(OSError, "write failed"):
                replication.apply_remote(
                    self.path, request(rid="r4", base=self.s1, remote=nxt)
                )
        self.assertEqual(ledger_raw(self.path), before)
        self.assertEqual(os.listdir(self.dir), ["ledger.json"])

    def test_write_failure_keeps_missing_path_missing(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        with self._failing_open("write", "write failed"):
            with self.assertRaisesRegex(OSError, "write failed"):
                replication.apply_remote(fresh, request(remote=self.s1))
        self.assertFalse(os.path.exists(fresh))
        self.assertFalse(os.path.exists(fresh + ".tmp"))
        self.assertFalse(os.path.exists(fresh + ".bak.apply"))

    def test_flush_failure_preserves_existing_bytes(self) -> None:
        before = ledger_raw(self.path)
        nxt = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        with self._failing_open("flush", "flush failed"):
            with self.assertRaisesRegex(OSError, "flush failed"):
                replication.apply_remote(
                    self.path, request(rid="r5", base=self.s1, remote=nxt)
                )
        self.assertEqual(ledger_raw(self.path), before)
        self.assertEqual(os.listdir(self.dir), ["ledger.json"])

    def test_directory_sync_failure_after_replace_restores_existing_bytes(self) -> None:
        # The tmp-file sync (1st fsync) succeeds, so the replacement goes
        # through; the post-replace directory sync (2nd fsync) fails and the
        # whole transaction must roll back to the exact prior bytes.
        before = ledger_raw(self.path)
        nxt = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        calls = {"n": 0}
        real_fsync = os.fsync

        def failing_fsync(fd):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise OSError("dir sync gone")
            return real_fsync(fd)

        with mock.patch("os.fsync", side_effect=failing_fsync):
            with self.assertRaisesRegex(OSError, "dir sync gone"):
                replication.apply_remote(
                    self.path, request(rid="r6", base=self.s1, remote=nxt)
                )
        # Byte-identical destination, no leftovers, and the recovery itself
        # synced the directory (a third fsync was attempted).
        self.assertEqual(ledger_raw(self.path), before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertFalse(os.path.exists(self.path + ".bak.apply"))
        self.assertGreaterEqual(calls["n"], 3)
        # The restored ledger is still usable: the next commit succeeds.
        follow = replication.apply_remote(
            self.path, request(rid="r7", base=self.s1, remote=nxt)
        )
        self.assertEqual(follow["status"], "applied")

    def test_directory_sync_failure_keeps_missing_path_missing(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        calls = {"n": 0}
        real_fsync = os.fsync

        def failing_fsync(fd):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise OSError("dir sync gone")
            return real_fsync(fd)

        with mock.patch("os.fsync", side_effect=failing_fsync):
            with self.assertRaisesRegex(OSError, "dir sync gone"):
                replication.apply_remote(fresh, request(remote=self.s1))
        self.assertFalse(os.path.exists(fresh))
        self.assertFalse(os.path.exists(fresh + ".tmp"))
        self.assertFalse(os.path.exists(fresh + ".bak.apply"))
        # A later call must not mistake any remnant for a ledger.
        result = replication.apply_remote(fresh, request(remote=self.s1))
        self.assertEqual(result["status"], "applied")

    def test_second_replace_failure_restores_backup_bytes(self) -> None:
        # Rename-aside (1st replace) succeeds, tmp->path (2nd replace) fails;
        # the backup must be moved back byte-identically.
        before = ledger_raw(self.path)
        nxt = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        real_replace = os.replace
        calls = {"n": 0}

        def failing_replace(src, dst, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("final replace failed")
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch("os.replace", side_effect=failing_replace):
            with self.assertRaisesRegex(OSError, "final replace failed"):
                replication.apply_remote(
                    self.path, request(rid="r8", base=self.s1, remote=nxt)
                )
        self.assertEqual(ledger_raw(self.path), before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertFalse(os.path.exists(self.path + ".bak.apply"))

    def test_success_still_syncs_file_and_directory(self) -> None:
        nxt = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        with mock.patch("os.fsync", wraps=os.fsync) as synced:
            result = replication.apply_remote(
                self.path, request(rid="r9", base=self.s1, remote=nxt)
            )
        self.assertEqual(result["status"], "applied")
        # At least the tmp-file sync and the post-replace directory sync.
        self.assertGreaterEqual(synced.call_count, 2)
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertFalse(os.path.exists(self.path + ".bak.apply"))
        # The committed ledger remains valid on disk.
        s3 = state({"a": 3}, {"k": record("x", False, {"a": 3}, "a")})
        again = replication.apply_remote(
            self.path,
            request(
                rid="r10",
                base=state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")}),
                remote=s3,
            ),
        )
        self.assertEqual(again["status"], "applied")
