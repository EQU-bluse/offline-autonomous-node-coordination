import json
import os
import tempfile
import unittest

from offline_coordination import receipt
from offline_coordination.receipt import CorruptReceiptError, get, put

D1 = "a" * 64
D2 = "b" * 64
D_BAD_UPPER = "A" * 64
RECORD_KEYS = ("audit", "id", "state")


def rec(rid="x", state=D1, audit=D2):
    return {"id": rid, "state": state, "audit": audit}


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class ReceiptRoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "receipts.json")

    def write(self, data: bytes) -> None:
        with open(self.path, "wb") as handle:
            handle.write(data)

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_missing_file_is_empty_index(self) -> None:
        self.assertIsNone(get(self.path, "x"))

    def test_empty_file_is_corrupt(self) -> None:
        self.write(b"")
        with self.assertRaises(CorruptReceiptError):
            get(self.path, "x")
        with self.assertRaises(CorruptReceiptError):
            put(self.path, rec())

    def test_put_returns_fixed_key_order_dict(self) -> None:
        result = put(self.path, rec())
        self.assertEqual(tuple(result.keys()), RECORD_KEYS)
        self.assertEqual(result, {"audit": D2, "id": "x", "state": D1})

    def test_put_writes_canonical_empty_then_record_bytes(self) -> None:
        put(self.path, rec(rid="a"))
        raw = self.read_raw()
        self.assertEqual(raw, b'{"items":[{"audit":"' + D2.encode()
                         + b'","id":"a","state":"' + D1.encode()
                         + b'"}],"version":1}\n')
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))

    def test_get_returns_same_binding_in_fixed_order(self) -> None:
        put(self.path, rec())
        fetched = get(self.path, "x")
        self.assertEqual(tuple(fetched.keys()), RECORD_KEYS)
        self.assertEqual(fetched, {"audit": D2, "id": "x", "state": D1})

    def test_get_missing_id_returns_none(self) -> None:
        put(self.path, rec(rid="a"))
        self.assertIsNone(get(self.path, "b"))

    def test_put_and_get_return_fresh_copies(self) -> None:
        given = rec()
        result = put(self.path, given)
        result["state"] = "mutated"
        given["id"] = "mutated"
        fetched = get(self.path, "x")
        self.assertEqual(fetched, {"audit": D2, "id": "x", "state": D1})
        fetched["audit"] = "mutated"
        self.assertEqual(get(self.path, "x")["audit"], D2)

    def test_items_sorted_by_id_ascending(self) -> None:
        for rid in ("c", "a", "b.b", "a-1", "A", "0"):
            put(self.path, rec(rid=rid))
        index = json.loads(self.read_raw())
        ids = [item["id"] for item in index["items"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids, ["0", "A", "a", "a-1", "b.b", "c"])
        for item in index["items"]:
            self.assertEqual(tuple(item.keys()), RECORD_KEYS)
        self.assertEqual(tuple(index.keys()), ("items", "version"))
        self.assertEqual(index["version"], 1)
        self.assertIsInstance(index["version"], int)

    def test_top_level_key_order_and_trailing_lf(self) -> None:
        put(self.path, rec())
        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(raw[:9], b'{"items":')
        self.assertIn(b',"version":1}\n', raw)


class ReceiptIdempotenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "receipts.json")

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_same_id_same_content_is_idempotent(self) -> None:
        first = put(self.path, rec(rid="k"))
        raw_after_first = self.read_raw()
        second = put(self.path, rec(rid="k"))
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(self.read_raw(), raw_after_first)

    def test_same_id_same_content_accepts_input_in_any_key_order(self) -> None:
        put(self.path, rec(rid="k"))
        raw = self.read_raw()
        again = put(self.path, {"state": D1, "audit": D2, "id": "k"})
        self.assertEqual(tuple(again.keys()), RECORD_KEYS)
        self.assertEqual(self.read_raw(), raw)

    def test_same_id_different_state_rejected_and_file_untouched(self) -> None:
        put(self.path, rec(rid="k", state=D1, audit=D2))
        raw = self.read_raw()
        with self.assertRaises(ValueError):
            put(self.path, rec(rid="k", state=D2, audit=D2))
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(get(self.path, "k"),
                         {"audit": D2, "id": "k", "state": D1})

    def test_same_id_different_audit_rejected_and_file_untouched(self) -> None:
        put(self.path, rec(rid="k", state=D1, audit=D2))
        raw = self.read_raw()
        with self.assertRaises(ValueError):
            put(self.path, rec(rid="k", state=D1, audit=D1))
        self.assertEqual(self.read_raw(), raw)

    def test_conflict_does_not_block_other_ids(self) -> None:
        put(self.path, rec(rid="k"))
        with self.assertRaises(ValueError):
            put(self.path, rec(rid="k", state=D2, audit=D2))
        put(self.path, rec(rid="other"))
        self.assertIsNotNone(get(self.path, "other"))
        self.assertEqual(get(self.path, "k")["state"], D1)


class ReceiptValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "receipts.json")

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            put(1, rec())
        with self.assertRaises(TypeError):
            get(None, "x")

    def test_receipt_must_be_dict(self) -> None:
        with self.assertRaises(TypeError):
            put(self.path, [])
        with self.assertRaises(TypeError):
            put(self.path, None)

    def test_receipt_fields_must_be_str(self) -> None:
        for key in ("id", "state", "audit"):
            with self.assertRaises(TypeError):
                put(self.path, {**rec(), key: 1})

    def test_receipt_key_set_must_match_exactly(self) -> None:
        with self.assertRaises(ValueError):
            put(self.path, {"id": "x", "state": D1})
        with self.assertRaises(ValueError):
            put(self.path, {**rec(), "extra": "x"})

    def test_id_format(self) -> None:
        for good in ("a", "A", "0", ".", "_", "-", "x.y-z_0", "A" * 64):
            self.assertEqual(put(self.path, rec(rid=good))["id"], good)
        for bad in ("", "A" * 65, "a/b", "a b", "a:b", "☃", "a\n", ". "):
            with self.assertRaises(ValueError, msg=f"id={bad!r}"):
                put(self.path, rec(rid=bad))

    def test_digest_format(self) -> None:
        with self.assertRaises(ValueError):
            put(self.path, rec(state="a" * 63))
        with self.assertRaises(ValueError):
            put(self.path, rec(state="a" * 65))
        with self.assertRaises(ValueError):
            put(self.path, rec(state=D_BAD_UPPER))
        with self.assertRaises(ValueError):
            put(self.path, rec(state="g" * 64))
        with self.assertRaises(ValueError):
            put(self.path, rec(audit="a" * 63))
        with self.assertRaises(ValueError):
            put(self.path, rec(audit=D_BAD_UPPER))

    def test_get_id_type_and_format(self) -> None:
        with self.assertRaises(TypeError):
            get(self.path, 1)
        for bad in ("", "A" * 65, "a/b"):
            with self.assertRaises(ValueError):
                get(self.path, bad)

    def test_corrupt_error_is_value_error(self) -> None:
        self.assertTrue(issubclass(CorruptReceiptError, ValueError))


class ReceiptCorruptionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "receipts.json")
        put(self.path, rec(rid="a"))
        put(self.path, rec(rid="b"))
        self.good = self.read_raw()

    def write(self, data: bytes) -> None:
        with open(self.path, "wb") as handle:
            handle.write(data)

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def assertCorrupt(self, data: bytes) -> None:
        self.write(data)
        with self.assertRaises(CorruptReceiptError):
            get(self.path, "a")
        with self.assertRaises(CorruptReceiptError):
            put(self.path, rec(rid="c"))

    def test_missing_trailing_lf(self) -> None:
        self.assertCorrupt(self.good[:-1])

    def test_extra_trailing_lf(self) -> None:
        self.assertCorrupt(self.good + b"\n")

    def test_non_canonical_whitespace(self) -> None:
        self.assertCorrupt(self.good.replace(b',"version"', b', "version"', 1))

    def test_non_canonical_unicode_escape_in_id_is_invalid_anyway(self) -> None:
        # \\u0061 decodes to "a"; the re-encoded bytes differ, so corrupt.
        self.assertCorrupt(self.good.replace(b'"id":"a"', b'"id":"\\u0061"', 1))

    def test_wrong_top_level_key_order(self) -> None:
        index = json.loads(self.good)
        reordered = {"version": index["version"], "items": index["items"]}
        self.assertCorrupt(canonical(reordered) + b"\n")

    def test_wrong_record_key_order(self) -> None:
        index = json.loads(self.good)
        index["items"] = [
            {"id": item["id"], "state": item["state"], "audit": item["audit"]}
            for item in index["items"]
        ]
        self.assertCorrupt(canonical(index) + b"\n")

    def test_extra_top_level_key(self) -> None:
        index = json.loads(self.good)
        index["extra"] = 2
        self.assertCorrupt(canonical(index) + b"\n")

    def test_missing_top_level_key(self) -> None:
        self.assertCorrupt(b'{"items":[]}\n')
        self.assertCorrupt(b'{"version":1}\n')

    def test_bad_version_values(self) -> None:
        good_index = json.loads(self.good)
        for version in (0, 2, "1", 1.0, True, None):
            bad = dict(good_index)
            bad["version"] = version
            self.assertCorrupt(canonical(bad) + b"\n")

    def test_items_not_array(self) -> None:
        self.assertCorrupt(b'{"items":{},"version":1}\n')

    def test_item_not_object(self) -> None:
        self.assertCorrupt(b'{"items":[1],"version":1}\n')

    def test_extra_record_key(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["extra"] = "x"
        self.assertCorrupt(canonical(index) + b"\n")

    def test_missing_record_key(self) -> None:
        index = json.loads(self.good)
        del index["items"][0]["audit"]
        self.assertCorrupt(canonical(index) + b"\n")

    def test_bad_id_in_file(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["id"] = "a/b"
        self.assertCorrupt(canonical(index) + b"\n")

    def test_uppercase_digest_in_file(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["state"] = D_BAD_UPPER
        self.assertCorrupt(canonical(index) + b"\n")

    def test_short_digest_in_file(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["audit"] = "a" * 63
        self.assertCorrupt(canonical(index) + b"\n")

    def test_duplicate_ids(self) -> None:
        index = json.loads(self.good)
        index["items"][1]["id"] = index["items"][0]["id"]
        self.assertCorrupt(canonical(index) + b"\n")

    def test_unsorted_ids(self) -> None:
        index = json.loads(self.good)
        items = index["items"]
        index["items"] = list(reversed(items))
        self.assertCorrupt(canonical(index) + b"\n")

    def test_top_level_not_object(self) -> None:
        self.assertCorrupt(b"[]\n")
        self.assertCorrupt(b"42\n")

    def test_non_utf8(self) -> None:
        self.assertCorrupt(b"\xff\n")

    def test_json_garbage(self) -> None:
        self.assertCorrupt(b"not json\n")

    def test_put_against_corrupt_file_does_not_modify_it(self) -> None:
        bad = self.good[:-1]
        self.write(bad)
        with self.assertRaises(CorruptReceiptError):
            put(self.path, rec(rid="c"))
        self.assertEqual(self.read_raw(), bad)

    def test_put_removes_tmp_file_after_replace(self) -> None:
        put(self.path, rec(rid="z"))
        self.assertFalse(os.path.exists(self.path + ".tmp"))

    def test_duplicate_json_keys_are_corrupt(self) -> None:
        self.assertCorrupt(
            b'{"items":[],"items":[],"version":1}\n'
        )


if __name__ == "__main__":
    unittest.main()
