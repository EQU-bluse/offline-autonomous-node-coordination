import json
import hashlib
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import audit, storage
from offline_coordination.audit import CorruptAuditError, append
from offline_coordination.replication import export_batch, import_batch, apply_remote

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


# ---------------------------------------------------------------------------
# apply_remote
# ---------------------------------------------------------------------------

APPLY_RESULT_KEYS = ("items", "receipt", "status")
APPLY_ITEM_KEYS = ("key", "decision", "need")
RECEIPT_KEYS = ("after", "before", "id", "seq", "source")
LEDGER_KEYS = ("audit", "requests", "state", "version")


def mstate(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def mrecord(value, deleted, clock, writer):
    return [value, deleted, dict(clock), writer]


def areq(request_id="r1", source="node-a", base=None, remote=None):
    return {
        "id": request_id,
        "source": source,
        "base": mstate() if base is None else base,
        "remote": mstate() if remote is None else remote,
    }


def ledger_bytes(state, requests, audit_entries):
    ledger = {
        "audit": audit_entries,
        "requests": requests,
        "state": state,
        "version": 1,
    }
    return canonical(ledger) + b"\n"


def state_digest_of(state):
    clock, records = state["clock"], state["records"]
    return hashlib.sha256(storage._serialize(clock, records)).hexdigest()


def request_digest_of(request):
    summary = {
        "base": request["base"],
        "id": request["id"],
        "remote": request["remote"],
        "source": request["source"],
    }
    return hashlib.sha256(canonical(summary)).hexdigest()


class ApplyRemoteSuccessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def read_ledger(self):
        with open(self.path, "rb") as handle:
            return json.loads(handle.read())

    def test_applies_missing_key_and_creates_canonical_ledger(self) -> None:
        base = mstate()
        remote = mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")})
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(tuple(result.keys()), APPLY_RESULT_KEYS)
        self.assertEqual(
            result["items"],
            [{"key": "k", "decision": "apply", "need": {}}],
        )
        self.assertEqual(tuple(result["items"][0].keys()), APPLY_ITEM_KEYS)

        raw = open(self.path, "rb").read()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        ledger = json.loads(raw)
        self.assertEqual(tuple(ledger.keys()), LEDGER_KEYS)
        self.assertEqual(
            raw,
            json.dumps(ledger, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode("utf-8") + b"\n",
        )
        self.assertEqual(ledger["version"], 1)
        self.assertEqual(ledger["state"], remote)
        self.assertEqual(set(ledger["requests"]), {"r1"})
        self.assertEqual(len(ledger["audit"]), 1)

    def test_receipt_is_the_audit_entry(self) -> None:
        base = mstate()
        remote = mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")})
        result = apply_remote(self.path, areq(base=base, remote=remote))
        receipt = result["receipt"]
        self.assertEqual(tuple(receipt.keys()), RECEIPT_KEYS)
        self.assertEqual(receipt["id"], "r1")
        self.assertEqual(receipt["source"], "node-a")
        self.assertEqual(receipt["seq"], 1)
        self.assertEqual(receipt["before"], state_digest_of(base))
        self.assertEqual(receipt["after"], state_digest_of(remote))
        self.assertEqual(self.read_ledger()["audit"][0], receipt)

    def test_audit_seq_increments_and_chains_state_digests(self) -> None:
        s0 = mstate()
        r1 = mstate({"a": 1}, {"k1": mrecord("v1", False, {"a": 1}, "a")})
        first = apply_remote(self.path, areq("r1", "node-a", s0, r1))
        self.assertEqual(first["receipt"]["seq"], 1)
        r2 = mstate({"a": 2}, {
            "k1": mrecord("v1", False, {"a": 1}, "a"),
            "k2": mrecord("v2", False, {"a": 2}, "a"),
        })
        second = apply_remote(self.path, areq("r2", "node-b", r1, r2))
        self.assertEqual(second["status"], "applied")
        self.assertEqual(second["receipt"]["seq"], 2)
        self.assertEqual(second["receipt"]["before"], first["receipt"]["after"])
        self.assertEqual(second["receipt"]["after"], state_digest_of(r2))
        entries = self.read_ledger()["audit"]
        self.assertEqual([e["seq"] for e in entries], [1, 2])
        self.assertEqual([e["id"] for e in entries], ["r1", "r2"])
        self.assertEqual([e["source"] for e in entries], ["node-a", "node-b"])

    def test_apply_and_duplicate_mix_commits(self) -> None:
        base = mstate({"a": 4, "b": 3}, {
            "keep": mrecord("z", False, {"a": 1}, "a"),
        })
        remote = mstate({"a": 5, "b": 3}, {
            "keep": mrecord("z", False, {"a": 1}, "a"),
            "new": mrecord("n", False, {"a": 5, "b": 3}, "a"),
        })
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(
            [(i["key"], i["decision"]) for i in result["items"]],
            [("keep", "duplicate"), ("new", "apply")],
        )
        state = self.read_ledger()["state"]
        self.assertEqual(state["clock"], {"a": 5, "b": 3})

    def test_clock_promoted_from_applied_record_clocks(self) -> None:
        # The writer component may run exactly one past the local outer
        # clock (the prerequisite decrements it by one); other nodes stay.
        base = mstate({"a": 2, "b": 4}, {})
        remote = mstate({"a": 3, "b": 4}, {
            "one": mrecord("1", False, {"a": 3, "b": 4}, "a"),
            "two": mrecord("2", False, {"a": 3}, "a"),
        })
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(self.read_ledger()["state"]["clock"], {"a": 3, "b": 4})

    def test_deleted_record_applies_with_empty_value(self) -> None:
        base = mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")})
        remote = mstate({"a": 2}, {"k": mrecord("", True, {"a": 2}, "a")})
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(
            self.read_ledger()["state"]["records"]["k"],
            ["", True, {"a": 2}, "a"],
        )

    def test_items_sorted_by_key(self) -> None:
        remote = mstate({"a": 3}, {
            "zeta": mrecord("1", False, {"a": 1}, "a"),
            "alpha": mrecord("2", False, {"a": 2}, "a"),
            "mid": mrecord("3", False, {"a": 3}, "a"),
        })
        result = apply_remote(self.path, areq(remote=remote))
        self.assertEqual([i["key"] for i in result["items"]],
                         ["alpha", "mid", "zeta"])

    def test_unicode_preserved_un_escaped(self) -> None:
        remote = mstate({"a": 1}, {"k": mrecord("雪 ☃", False, {"a": 1}, "a")})
        apply_remote(self.path, areq(remote=remote))
        self.assertIn("雪 ☃".encode("utf-8"), open(self.path, "rb").read())


class ApplyRemoteReplayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.base = mstate()
        self.remote = mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")})
        self.request = areq(base=self.base, remote=self.remote)
        apply_remote(self.path, self.request)

    def bytes(self):
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_same_request_is_duplicate_with_unchanged_bytes(self) -> None:
        before = self.bytes()
        result = apply_remote(self.path, self.request)
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(result["receipt"], None)
        self.assertEqual(
            result["items"],
            [{"key": "k", "decision": "duplicate", "need": {}}],
        )
        self.assertEqual(self.bytes(), before)

    def test_semantically_equal_request_is_duplicate(self) -> None:
        # A fresh object with identical content binds the same digest.
        replay = {
            "id": "r1",
            "source": "node-a",
            "base": mstate(),
            "remote": mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")}),
        }
        before = self.bytes()
        result = apply_remote(self.path, replay)
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(self.bytes(), before)

    def test_same_id_different_request_raises_and_keeps_bytes(self) -> None:
        changed = dict(self.request, remote=mstate(
            {"a": 1}, {"k": mrecord("other", False, {"a": 1}, "a")}
        ))
        before = self.bytes()
        with self.assertRaises(ValueError):
            apply_remote(self.path, changed)
        self.assertEqual(self.bytes(), before)

    def test_replay_succeeds_even_when_state_no_longer_equals_base(self) -> None:
        # The duplicate gate precedes the stale gate.
        other = mstate({"a": 2}, {
            "k": mrecord("v", False, {"a": 1}, "a"),
            "k2": mrecord("w", False, {"a": 2}, "a"),
        })
        apply_remote(self.path, areq("r2", "node-a", self.remote, other))
        result = apply_remote(self.path, self.request)
        self.assertEqual(result["status"], "duplicate")


class ApplyRemoteRejectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.remote = mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")})

    def assert_no_file_written(self):
        self.assertFalse(os.path.exists(self.path))

    def test_stale_when_current_differs_from_base(self) -> None:
        first_remote = mstate({"b": 1}, {"x": mrecord("1", False, {"b": 1}, "b")})
        apply_remote(self.path, areq("first", "node-b", mstate(), first_remote))
        stale = areq("second", "node-c", mstate(), self.remote)
        before = open(self.path, "rb").read()
        result = apply_remote(self.path, stale)
        self.assertEqual(result["status"], "stale")
        self.assertEqual(result["items"], [])
        self.assertEqual(result["receipt"], None)
        self.assertEqual(open(self.path, "rb").read(), before)

    def test_missing_reports_need_intervals_without_writing(self) -> None:
        base = mstate({"a": 1})
        remote = mstate({"a": 1, "b": 3}, {
            "k": mrecord("v", False, {"a": 1, "b": 3}, "b"),
        })
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "missing")
        self.assertEqual(result["receipt"], None)
        self.assertEqual(result["items"][0]["decision"], "missing")
        # writer b component decremented: prerequisite b=2; local b=0.
        self.assertEqual(result["items"][0]["need"], {"b": [1, 2]})
        self.assert_no_file_written()

    def test_missing_need_zero_when_prerequisite_met(self) -> None:
        base = mstate({"a": 2})
        remote = mstate({"a": 3}, {"k": mrecord("v", False, {"a": 3}, "a")})
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["items"][0]["need"], {})

    def test_conflict_concurrent_records_not_written(self) -> None:
        base = mstate({"a": 1, "b": 1}, {
            "k": mrecord("local", False, {"a": 1}, "a"),
        })
        remote = mstate({"a": 1, "b": 1}, {
            "k": mrecord("remote", False, {"b": 1}, "b"),
        })
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(result["items"][0]["decision"], "conflict")
        self.assertEqual(result["items"][0]["need"], {})
        self.assert_no_file_written()

    def test_stale_item_when_local_dominates_remote(self) -> None:
        base = mstate({"a": 2}, {"k": mrecord("new", False, {"a": 2}, "a")})
        remote = mstate({"a": 2}, {"k": mrecord("old", False, {"a": 1}, "a")})
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "stale")
        self.assertEqual(result["items"][0]["decision"], "stale")
        self.assert_no_file_written()

    def test_all_equal_records_is_overall_duplicate(self) -> None:
        base = mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")})
        result = apply_remote(self.path, areq(base=base, remote=base))
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(result["items"][0]["decision"], "duplicate")
        self.assertEqual(result["receipt"], None)
        self.assert_no_file_written()

    def test_empty_remote_with_equal_state_is_duplicate(self) -> None:
        result = apply_remote(self.path, areq(remote=mstate()))
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(result["items"], [])
        self.assert_no_file_written()

    def test_overall_precedence_missing_beats_conflict(self) -> None:
        base = mstate({"a": 1, "b": 1}, {
            "c": mrecord("local", False, {"a": 1}, "a"),
        })
        remote = mstate({"a": 1, "b": 1, "d": 3}, {
            "c": mrecord("remote", False, {"b": 1}, "b"),       # conflict
            "m": mrecord("v", False, {"d": 3}, "d"),           # missing
        })
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "missing")
        decisions = {i["key"]: i["decision"] for i in result["items"]}
        self.assertEqual(decisions["c"], "conflict")
        self.assertEqual(decisions["m"], "missing")
        self.assert_no_file_written()

    def test_overall_precedence_conflict_beats_stale(self) -> None:
        base = mstate({"a": 2, "b": 1}, {
            "old": mrecord("new", False, {"a": 2}, "a"),
            "con": mrecord("local", False, {"a": 1}, "a"),
        })
        remote = mstate({"a": 2, "b": 1}, {
            "old": mrecord("x", False, {"a": 1}, "a"),          # stale
            "con": mrecord("remote", False, {"b": 1}, "b"),     # conflict
        })
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "conflict")
        self.assert_no_file_written()

    def test_stale_item_beats_duplicate(self) -> None:
        base = mstate({"a": 2}, {
            "old": mrecord("new", False, {"a": 2}, "a"),
            "dup": mrecord("d", False, {"a": 1}, "a"),
        })
        remote = mstate({"a": 2}, {
            "old": mrecord("x", False, {"a": 1}, "a"),
            "dup": mrecord("d", False, {"a": 1}, "a"),
        })
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "stale")

    def test_apply_alongside_stale_does_not_commit(self) -> None:
        base = mstate({"a": 2}, {
            "old": mrecord("new", False, {"a": 2}, "a"),
        })
        remote = mstate({"a": 2}, {
            "old": mrecord("x", False, {"a": 1}, "a"),          # stale
            "fresh": mrecord("f", False, {"a": 2}, "a"),        # apply
        })
        result = apply_remote(self.path, areq(base=base, remote=remote))
        self.assertEqual(result["status"], "stale")
        self.assert_no_file_written()


class ApplyRemoteLedgerValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.good_state = mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")})

    def write_ledger(self, state, requests=None, audit_entries=None,
                     payload=None):
        if payload is None:
            entry = {
                "after": state_digest_of(state),
                "before": state_digest_of(mstate()),
                "id": "r0",
                "seq": 1,
                "source": "node-a",
            }
            audit_entries = [entry] if audit_entries is None else audit_entries
            requests = {"r0": "0" * 64} if requests is None else requests
            payload = ledger_bytes(state, requests, audit_entries)
        with open(self.path, "wb") as handle:
            handle.write(payload)

    def valid_request(self):
        return areq(base=self.good_state, remote=mstate(
            {"a": 2}, {"k": mrecord("v2", False, {"a": 2}, "a")}
        ))

    def test_non_json_ledger_raises_value_error(self) -> None:
        self.write_ledger(None, payload=b"garbage\n")
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_missing_trailing_newline_raises_value_error(self) -> None:
        good = ledger_bytes(self.good_state, {"r0": "0" * 64}, [{
            "after": state_digest_of(self.good_state),
            "before": state_digest_of(mstate()),
            "id": "r0", "seq": 1, "source": "node-a",
        }])
        self.write_ledger(None, payload=good[:-1])
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_bad_top_level_keys_raise_value_error(self) -> None:
        self.write_ledger(None, payload=b'{"version":1}\n')
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_bad_version_raises_value_error(self) -> None:
        payload = ledger_bytes(self.good_state, {}, [])
        data = json.loads(payload)
        data["version"] = 2
        self.write_ledger(None, payload=canonical(data) + b"\n")
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_corrupt_state_raises_value_error(self) -> None:
        payload = ledger_bytes(self.good_state, {}, [])
        data = json.loads(payload)
        data["state"] = {"clock": {"a": -1}, "records": {}}
        self.write_ledger(None, payload=canonical(data) + b"\n")
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_state_shape_error_is_value_error_not_type_error(self) -> None:
        payload = ledger_bytes(self.good_state, {}, [])
        data = json.loads(payload)
        data["state"] = {"clock": [], "records": {}}
        self.write_ledger(None, payload=canonical(data) + b"\n")
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_bool_clock_count_raises_value_error(self) -> None:
        payload = ledger_bytes(self.good_state, {}, [])
        data = json.loads(payload)
        data["state"] = {"clock": {"a": True}, "records": {}}
        self.write_ledger(None, payload=canonical(data) + b"\n")
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_non_canonical_encoding_raises_value_error(self) -> None:
        payload = ledger_bytes(self.good_state, {}, [])
        data = json.loads(payload)
        self.write_ledger(
            None,
            payload=json.dumps(data, sort_keys=True, indent=1).encode("utf-8")
            + b"\n",
        )
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_bound_request_without_audit_entry_raises(self) -> None:
        self.write_ledger(self.good_state, requests={"ghost": "0" * 64},
                          audit_entries=[])
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_audit_entry_without_bound_request_raises(self) -> None:
        entry = {
            "after": state_digest_of(self.good_state),
            "before": state_digest_of(mstate()),
            "id": "ghost", "seq": 1, "source": "node-a",
        }
        self.write_ledger(self.good_state, requests={}, audit_entries=[entry])
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_duplicate_audit_id_raises(self) -> None:
        e1 = {
            "after": state_digest_of(self.good_state),
            "before": state_digest_of(mstate()),
            "id": "r0", "seq": 1, "source": "node-a",
        }
        e2 = dict(e1, seq=2)
        self.write_ledger(self.good_state, requests={"r0": "0" * 64},
                          audit_entries=[e1, e2])
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_gap_in_audit_seq_raises(self) -> None:
        entry = {
            "after": state_digest_of(self.good_state),
            "before": state_digest_of(mstate()),
            "id": "r0", "seq": 2, "source": "node-a",
        }
        self.write_ledger(self.good_state, requests={"r0": "0" * 64},
                          audit_entries=[entry])
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())

    def test_corrupt_ledger_never_written(self) -> None:
        self.write_ledger(None, payload=b"garbage\n")
        before = open(self.path, "rb").read()
        with self.assertRaises(ValueError):
            apply_remote(self.path, self.valid_request())
        self.assertEqual(open(self.path, "rb").read(), before)


class ApplyRemoteRequestValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def invoke(self, request):
        return apply_remote(self.path, request)

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            apply_remote(1, areq())

    def test_request_must_be_dict(self) -> None:
        with self.assertRaises(TypeError):
            self.invoke([])
        with self.assertRaises(TypeError):
            self.invoke(None)

    def test_request_key_set(self) -> None:
        request = areq()
        for key in ("id", "source", "base", "remote"):
            missing = dict(request)
            del missing[key]
            with self.assertRaises(ValueError):
                self.invoke(missing)
        extra = dict(request, extra="x")
        with self.assertRaises(ValueError):
            self.invoke(extra)

    def test_id_and_source_types(self) -> None:
        with self.assertRaises(TypeError):
            self.invoke(areq(request_id=1))
        with self.assertRaises(TypeError):
            self.invoke(areq(source=7))

    def test_id_and_source_non_empty(self) -> None:
        with self.assertRaises(ValueError):
            self.invoke(areq(request_id=""))
        with self.assertRaises(ValueError):
            self.invoke(areq(source=""))

    def test_base_and_remote_must_be_states(self) -> None:
        with self.assertRaises((TypeError, ValueError)):
            self.invoke(areq(base=[]))
        with self.assertRaises((TypeError, ValueError)):
            self.invoke(areq(remote={"clock": None, "records": {}}))
        with self.assertRaises(ValueError):
            self.invoke(areq(remote=mstate({"a": -1})))

    def test_clock_count_must_be_int_not_bool(self) -> None:
        with self.assertRaises(TypeError):
            self.invoke(areq(remote=mstate({"a": True})))
        with self.assertRaises(TypeError):
            self.invoke(areq(remote=mstate({"a": 1.0})))

    def test_deleted_value_must_be_empty(self) -> None:
        bad = mstate({"a": 1}, {"k": ["v", True, {"a": 1}, "a"]})
        with self.assertRaises(ValueError):
            self.invoke(areq(remote=bad))

    def test_record_clock_must_contain_writer(self) -> None:
        bad = mstate({"a": 1}, {"k": ["v", False, {"a": 1}, "b"]})
        with self.assertRaises(ValueError):
            self.invoke(areq(remote=bad))

    def test_record_clock_bounded_by_outer_clock(self) -> None:
        bad = mstate({"a": 1}, {"k": ["v", False, {"a": 2}, "a"]})
        with self.assertRaises(ValueError):
            self.invoke(areq(remote=bad))

    def test_invalid_request_never_touches_filesystem(self) -> None:
        with self.assertRaises(TypeError):
            apply_remote(self.path, areq(request_id=1))
        with self.assertRaises(ValueError):
            apply_remote(self.path, areq(request_id=""))
        self.assertFalse(os.path.exists(self.path))


class ApplyRemoteAtomicityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        apply_remote(self.path, areq(
            "r1", "node-a", mstate(),
            mstate({"a": 1}, {"k1": mrecord("v1", False, {"a": 1}, "a")}),
        ))

    def bytes(self):
        with open(self.path, "rb") as handle:
            return handle.read()

    def next_request(self):
        state = mstate({"a": 1}, {"k1": mrecord("v1", False, {"a": 1}, "a")})
        return areq("r2", "node-a", state,
                    mstate({"a": 2}, {
                        "k1": mrecord("v1", False, {"a": 1}, "a"),
                        "k2": mrecord("v2", False, {"a": 2}, "a"),
                    }))

    def test_fsync_failure_preserves_existing_bytes(self) -> None:
        before = self.bytes()
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                apply_remote(self.path, self.next_request())
        self.assertEqual(self.bytes(), before)

    def test_replace_failure_preserves_existing_bytes(self) -> None:
        before = self.bytes()
        with mock.patch("os.replace", side_effect=OSError("denied")):
            with self.assertRaises(OSError):
                apply_remote(self.path, self.next_request())
        self.assertEqual(self.bytes(), before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))

    def test_write_failure_keeps_bytes_for_new_ledger(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        real_open = open

        def opening(path, *args, **kwargs):
            if "w" in (args[0] if args else kwargs.get("mode", "r")):
                raise OSError("write failed")
            return real_open(path, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=opening):
            with self.assertRaises(OSError):
                apply_remote(fresh, areq(remote=mstate(
                    {"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")}
                )))
        self.assertFalse(os.path.exists(fresh))

    def test_oserror_propagates_unchanged_from_ledger_read(self) -> None:
        with mock.patch("builtins.open", side_effect=PermissionError("nope")):
            with self.assertRaises(PermissionError):
                apply_remote(self.path, self.next_request())

    def test_fsync_failure_keeps_new_ledger_missing(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                apply_remote(fresh, areq(remote=mstate(
                    {"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")}
                )))
        # The main ledger is never created; an orphaned .tmp is never read.
        self.assertFalse(os.path.exists(fresh))


class ApplyRemoteInputImmutabilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def test_apply_does_not_mutate_request(self) -> None:
        request = areq(remote=mstate(
            {"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")}
        ))
        snapshot = json.dumps(request, sort_keys=True)
        apply_remote(self.path, request)
        self.assertEqual(json.dumps(request, sort_keys=True), snapshot)

    def test_rejected_request_not_mutated(self) -> None:
        base = mstate({"a": 1}, {"k": mrecord("v", False, {"a": 1}, "a")})
        remote = mstate({"a": 1, "b": 1}, {
            "k": mrecord("w", False, {"b": 1}, "b"),
        })
        request = areq(base=base, remote=remote)
        snapshot = json.dumps(request, sort_keys=True)
        result = apply_remote(self.path, request)
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(json.dumps(request, sort_keys=True), snapshot)


if __name__ == "__main__":
    unittest.main()