import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import audit
from offline_coordination.audit import CorruptAuditError, append, read
from offline_coordination.storage import save_state

ZERO = "0" * 64
KEYS = ("detail", "hash", "kind", "prev", "seq", "source")


def event(source="node-a", kind="local", detail="did something"):
    return {"source": source, "kind": kind, "detail": detail}


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class AuditRoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")

    def write(self, data: bytes) -> None:
        with open(self.path, "wb") as handle:
            handle.write(data)

    def test_missing_and_empty_file_read_as_empty_list(self) -> None:
        self.assertEqual(read(self.path), [])
        self.write(b"")
        self.assertEqual(read(self.path), [])

    def test_append_returns_contiguous_seqs_starting_at_one(self) -> None:
        self.assertEqual(append(self.path, event(kind="local")), 1)
        self.assertEqual(append(self.path, event(kind="merge")), 2)
        self.assertEqual(append(self.path, event(kind="restore")), 3)

    def test_records_have_fixed_key_order_and_hash_chain(self) -> None:
        append(self.path, event(detail="first"))
        append(self.path, event(detail="second ☃"))
        append(self.path, event(kind="merge", detail="third"))
        records = read(self.path)
        for record in records:
            self.assertEqual(tuple(record.keys()), KEYS)
        self.assertEqual(records[0]["prev"], ZERO)
        self.assertEqual(records[1]["prev"], records[0]["hash"])
        self.assertEqual(records[2]["prev"], records[1]["hash"])

    def test_file_is_canonical_utf8_jsonl(self) -> None:
        append(self.path, event(detail="snowman ☃"))
        raw = open(self.path, "rb").read()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(len(raw.split(b"\n")), 2)
        line = raw[:-1]
        self.assertIn("☃".encode("utf-8"), line)
        obj = json.loads(line)
        without_hash = {k: obj[k] for k in ("detail", "kind", "prev", "seq", "source")}
        expected_hash = hashlib.sha256(canonical(without_hash)).hexdigest()
        self.assertEqual(obj["hash"], expected_hash)
        self.assertEqual(
            canonical({k: obj[k] for k in KEYS}), line
        )

    def test_first_creation_fsyncs_parent_directory(self) -> None:
        seen = []
        real_open = os.open

        def tracking_open(path_arg, flags, *args):
            fd = real_open(path_arg, flags, *args)
            seen.append((path_arg, fd))
            return fd

        with mock.patch("offline_coordination.audit.os.open", side_effect=tracking_open):
            append(self.path, event())
        parent = os.path.dirname(os.path.abspath(self.path))
        self.assertIn(parent, [path_arg for path_arg, _ in seen])

    def test_later_append_does_not_fsync_parent_directory(self) -> None:
        append(self.path, event())
        with mock.patch("offline_coordination.audit.os.open") as opened:
            append(self.path, event())
        opened.assert_not_called()

    def test_read_returns_deep_copy(self) -> None:
        append(self.path, event())
        first = read(self.path)
        first[0]["detail"] = "mutated"
        self.assertEqual(read(self.path)[0]["detail"], "did something")


class AuditValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            append(1, event())
        with self.assertRaises(TypeError):
            read(None)

    def test_event_must_be_dict(self) -> None:
        with self.assertRaises(TypeError):
            append(self.path, [])
        with self.assertRaises(TypeError):
            append(self.path, None)

    def test_event_fields_must_be_str(self) -> None:
        for key in ("source", "kind", "detail"):
            bad = event()
            bad[key] = 1
            with self.assertRaises(TypeError):
                append(self.path, bad)

    def test_event_key_set_must_match_exactly(self) -> None:
        with self.assertRaises(ValueError):
            append(self.path, {"source": "a", "kind": "local"})
        with self.assertRaises(ValueError):
            append(self.path, {**event(), "extra": "x"})

    def test_event_fields_must_be_nonempty(self) -> None:
        with self.assertRaises(ValueError):
            append(self.path, event(source=""))
        with self.assertRaises(ValueError):
            append(self.path, event(detail=""))
        with self.assertRaises(ValueError):
            append(self.path, event(kind=""))

    def test_kind_must_be_allowed(self) -> None:
        with self.assertRaises(ValueError):
            append(self.path, event(kind="bogus"))

    def test_corrupt_error_is_value_error(self) -> None:
        self.assertTrue(issubclass(CorruptAuditError, ValueError))


class AuditCorruptionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")
        append(self.path, event(detail="first"))
        append(self.path, event(detail="second"))
        self.good = open(self.path, "rb").read()

    def corrupt(self, data: bytes) -> None:
        with open(self.path, "wb") as handle:
            handle.write(data)

    def assertCorrupt(self, data: bytes) -> None:
        self.corrupt(data)
        with self.assertRaises(CorruptAuditError):
            read(self.path)
        with self.assertRaises(CorruptAuditError):
            append(self.path, event())

    def test_missing_final_newline(self) -> None:
        self.assertCorrupt(self.good[:-1])

    def test_trailing_blank_line(self) -> None:
        self.assertCorrupt(self.good + b"\n")

    def test_interior_blank_line(self) -> None:
        first, rest = self.good.split(b"\n", 1)
        self.assertCorrupt(first + b"\n\n" + rest)

    def test_non_canonical_whitespace(self) -> None:
        self.assertCorrupt(self.good.replace(b'"kind":"local"', b'"kind": "local"', 1))

    def test_non_canonical_unicode_escape(self) -> None:
        path = os.path.join(self.dir, "u.jsonl")
        append(path, event(detail="☃"))
        raw = open(path, "rb").read()
        with open(path, "wb") as handle:
            handle.write(raw.replace("☃".encode(), b"\\u2603"))
        with self.assertRaises(CorruptAuditError):
            read(path)

    def test_wrong_key_order(self) -> None:
        first = json.loads(self.good.split(b"\n", 1)[0])
        reordered = {k: first[k] for k in reversed(KEYS)}
        self.assertCorrupt(canonical(reordered) + b"\n")

    def test_extra_key(self) -> None:
        first = json.loads(self.good.split(b"\n", 1)[0])
        first["extra"] = 1
        self.assertCorrupt(canonical(first) + b"\n")

    def test_bad_hash(self) -> None:
        tampered = bytearray(self.good)
        tampered[40] = ord("1") if tampered[40] != ord("1") else ord("2")
        self.assertCorrupt(bytes(tampered))

    def test_seq_gap(self) -> None:
        first = self.good.split(b"\n", 1)[0]
        self.assertCorrupt(first + b"\n" + first + b"\n")

    def test_bad_prev(self) -> None:
        lines = self.good.split(b"\n")
        second = json.loads(lines[1])
        second["prev"] = ZERO
        without_hash = {k: second[k] for k in ("detail", "kind", "prev", "seq", "source")}
        second["hash"] = hashlib.sha256(canonical(without_hash)).hexdigest()
        self.assertCorrupt(lines[0] + b"\n" + canonical(second) + b"\n")

    def test_value_domain_rules_are_append_side(self) -> None:
        # A structurally valid, hash-correct line with an out-of-domain kind
        # is a byte/chain-valid record; enum rules are enforced on append's
        # event input, not when reading existing bytes.
        first = json.loads(self.good.split(b"\n", 1)[0])
        first["kind"] = "bogus"
        without_hash = {k: first[k] for k in ("detail", "kind", "prev", "seq", "source")}
        first["hash"] = hashlib.sha256(canonical(without_hash)).hexdigest()
        self.corrupt(canonical(first) + b"\n")
        records = read(self.path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["kind"], "bogus")

    def test_non_utf8(self) -> None:
        self.corrupt(b'{"detail":"\xff"}')
        with self.assertRaises(CorruptAuditError):
            read(self.path)

    def test_corrupt_append_does_not_write(self) -> None:
        self.corrupt(self.good[:-1])
        with self.assertRaises(CorruptAuditError):
            append(self.path, event())
        self.assertEqual(open(self.path, "rb").read(), self.good[:-1])

    def test_bool_seq_is_rejected(self) -> None:
        first = self.good.split(b"\n", 1)[0]
        self.assertCorrupt(first.replace(b',"seq":1,', b',"seq":true,') + b"\n")


class SaveStateFsyncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "state.json")
        self.state = {"clock": {}, "records": {}}

    def test_directory_open_failure_propagates_oserror(self) -> None:
        with mock.patch("offline_coordination.storage.os.open", side_effect=OSError):
            with self.assertRaises(OSError):
                save_state(self.path, self.state)

    def test_directory_fsync_failure_propagates_oserror(self) -> None:
        real_open = os.open
        real_close = os.close
        dir_fds = set()

        def tracking_open(path_arg, flags, *args):
            fd = real_open(path_arg, flags, *args)
            if path_arg == os.path.dirname(os.path.abspath(self.path)):
                dir_fds.add(fd)
            return fd

        def fsync(fd):
            if fd in dir_fds:
                raise OSError("dir fsync failed")

        with mock.patch("offline_coordination.storage.os.open", side_effect=tracking_open), \
                mock.patch("offline_coordination.storage.os.fsync", side_effect=fsync):
            with self.assertRaises(OSError):
                save_state(self.path, self.state)
        for fd in dir_fds:
            try:
                real_close(fd)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
