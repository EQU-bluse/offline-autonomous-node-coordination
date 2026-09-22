import json
import os
import tempfile
import unittest

from offline_coordination import transaction
from offline_coordination.transaction import (
    CorruptTransactionError,
    checkpoint,
)

D1 = "a" * 64
D2 = "b" * 64
D_BAD_UPPER = "A" * 64
RECORD_KEYS = ("audit", "id", "stage", "state")
STAGES = ("prepared", "state", "audit", "committed")


def req(rid="x", state=D1, audit=D2, stage="prepared"):
    return {"id": rid, "state": state, "audit": audit, "stage": stage}


def expected(rid="x", state=D1, audit=D2, stage="prepared"):
    return {"audit": audit, "id": rid, "stage": stage, "state": state}


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class CheckpointRoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "tx.json")

    def write(self, data: bytes) -> None:
        with open(self.path, "wb") as handle:
            handle.write(data)

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_missing_file_is_empty_index(self) -> None:
        self.assertEqual(checkpoint(self.path), [])
        self.assertEqual(checkpoint(self.path, None), [])

    def test_empty_file_is_corrupt(self) -> None:
        self.write(b"")
        with self.assertRaises(CorruptTransactionError):
            checkpoint(self.path)
        with self.assertRaises(CorruptTransactionError):
            checkpoint(self.path, req())

    def test_prepared_insert_returns_record_in_fixed_key_order(self) -> None:
        result = checkpoint(self.path, req())
        self.assertEqual(result, [expected()])
        self.assertEqual(tuple(result[0].keys()), RECORD_KEYS)

    def test_writes_canonical_bytes_with_single_trailing_lf(self) -> None:
        checkpoint(self.path, req(rid="a"))
        raw = self.read_raw()
        self.assertEqual(
            raw,
            b'{"items":[{"audit":"' + D2.encode()
            + b'","id":"a","stage":"prepared","state":"' + D1.encode()
            + b'"}],"version":1}\n',
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(raw[:9], b'{"items":')
        self.assertIn(b',"version":1}\n', raw)

    def test_query_returns_same_records_in_fixed_order(self) -> None:
        checkpoint(self.path, req())
        fetched = checkpoint(self.path)
        self.assertEqual(fetched, [expected()])
        self.assertEqual(tuple(fetched[0].keys()), RECORD_KEYS)

    def test_query_returns_fresh_list_and_dicts(self) -> None:
        checkpoint(self.path, req(rid="a"))
        first = checkpoint(self.path)
        first.append(None)
        first[0]["stage"] = "mutated"
        again = checkpoint(self.path)
        self.assertEqual(again, [expected(rid="a")])
        again[0]["id"] = "mutated"
        self.assertEqual(checkpoint(self.path)[0]["id"], "a")

    def test_insert_and_advance_return_full_updated_index(self) -> None:
        checkpoint(self.path, req(rid="a"))
        out = checkpoint(self.path, req(rid="b"))
        self.assertEqual([item["id"] for item in out], ["a", "b"])
        out = checkpoint(self.path, req(rid="a", stage="state"))
        self.assertEqual(
            [(item["id"], item["stage"]) for item in out],
            [("a", "state"), ("b", "prepared")],
        )
        for item in out:
            self.assertEqual(tuple(item.keys()), RECORD_KEYS)

    def test_items_sorted_by_id_ascending(self) -> None:
        for rid in ("c", "a", "b.b", "a-1", "A", "0"):
            checkpoint(self.path, req(rid=rid))
        index = json.loads(self.read_raw())
        ids = [item["id"] for item in index["items"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids, ["0", "A", "a", "a-1", "b.b", "c"])
        for item in index["items"]:
            self.assertEqual(tuple(item.keys()), RECORD_KEYS)
        self.assertEqual(tuple(index.keys()), ("items", "version"))
        self.assertIs(index["version"], 1)


class CheckpointStageFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "tx.json")

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_new_id_must_start_at_prepared(self) -> None:
        for stage in ("state", "audit", "committed"):
            with self.assertRaises(ValueError):
                checkpoint(self.path, req(rid="n" + stage, stage=stage))
        self.assertEqual(checkpoint(self.path), [])

    def test_adjacent_advances_succeed_in_order(self) -> None:
        checkpoint(self.path, req(rid="k"))
        for stage in ("state", "audit", "committed"):
            before = self.read_raw()
            out = checkpoint(self.path, req(rid="k", stage=stage))
            self.assertEqual(out[0]["stage"], stage)
            self.assertNotEqual(self.read_raw(), before)

    def test_stage_regression_rejected_and_untouched(self) -> None:
        checkpoint(self.path, req(rid="k"))
        for stage in ("state", "audit", "committed"):
            checkpoint(self.path, req(rid="k", stage=stage))
        raw = self.read_raw()
        for stage in ("prepared", "state", "audit"):
            with self.assertRaises(ValueError):
                checkpoint(self.path, req(rid="k", stage=stage))
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(checkpoint(self.path)[0]["stage"], "committed")

    def test_stage_skip_rejected_and_untouched(self) -> None:
        checkpoint(self.path, req(rid="k"))
        raw = self.read_raw()
        for stage in ("audit", "committed"):
            with self.assertRaises(ValueError):
                checkpoint(self.path, req(rid="k", stage=stage))
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(checkpoint(self.path)[0]["stage"], "prepared")

    def test_digest_change_rejected_and_untouched(self) -> None:
        checkpoint(self.path, req(rid="k"))
        checkpoint(self.path, req(rid="k", stage="state"))
        raw = self.read_raw()
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(rid="k", state=D2, stage="state"))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(rid="k", audit=D1, stage="state"))
        # A digest change is rejected even together with a legal advance.
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(rid="k", state=D2, stage="audit"))
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(
            checkpoint(self.path)[0],
            expected(rid="k", stage="state"),
        )

    def test_conflict_does_not_block_other_ids(self) -> None:
        checkpoint(self.path, req(rid="k"))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(rid="k", stage="audit"))
        checkpoint(self.path, req(rid="other"))
        self.assertEqual(
            [item["id"] for item in checkpoint(self.path)], ["k", "other"]
        )


class CheckpointIdempotenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "tx.json")
        checkpoint(self.path, req(rid="k"))
        for stage in ("state", "audit"):
            checkpoint(self.path, req(rid="k", stage=stage))
        self.raw = self.read_raw()

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_same_id_same_digests_same_stage_is_idempotent(self) -> None:
        first = checkpoint(self.path)
        second = checkpoint(self.path, req(rid="k", stage="audit"))
        self.assertEqual(second, first)
        self.assertIsNot(second, first)
        self.assertIsNot(second[0], first[0])
        self.assertEqual(self.read_raw(), self.raw)

    def test_idempotent_replay_accepts_any_input_key_order(self) -> None:
        again = checkpoint(
            self.path,
            {"stage": "audit", "id": "k", "audit": D2, "state": D1},
        )
        self.assertEqual(tuple(again[0].keys()), RECORD_KEYS)
        self.assertEqual(self.read_raw(), self.raw)

    def test_idempotent_replay_works_at_every_stage(self) -> None:
        for stage in STAGES:
            path = os.path.join(self.dir, f"id-{stage}.json")
            checkpoint(path, req(rid="k"))
            for reached in STAGES[1:STAGES.index(stage) + 1]:
                checkpoint(path, req(rid="k", stage=reached))
            raw = open(path, "rb").read()
            out = checkpoint(path, req(rid="k", stage=stage))
            self.assertEqual(out[0]["stage"], stage)
            self.assertEqual(open(path, "rb").read(), raw)


class CheckpointValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "tx.json")

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            checkpoint(1)
        with self.assertRaises(TypeError):
            checkpoint(None, req())

    def test_request_must_be_dict(self) -> None:
        for bad in ([], 42, "prepared"):
            with self.assertRaises(TypeError):
                checkpoint(self.path, bad)

    def test_request_fields_must_be_str(self) -> None:
        for key in ("id", "state", "audit", "stage"):
            with self.assertRaises(TypeError):
                checkpoint(self.path, {**req(), key: 1})

    def test_request_key_set_must_match_exactly(self) -> None:
        with self.assertRaises(ValueError):
            checkpoint(self.path, {"id": "x", "state": D1, "audit": D2})
        with self.assertRaises(ValueError):
            checkpoint(self.path, {**req(), "extra": "x"})

    def test_id_format(self) -> None:
        for good in ("a", "A", "0", ".", "_", "-", "x.y-z_0", "A" * 64):
            stored = {item["id"]: item for item in checkpoint(self.path, req(rid=good))}
            self.assertIn(good, stored)
        for bad in ("", "A" * 65, "a/b", "a b", "a:b", "☃", "a\n", ". "):
            with self.assertRaises(ValueError, msg=f"id={bad!r}"):
                checkpoint(self.path, req(rid=bad))

    def test_digest_format(self) -> None:
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(state="a" * 63))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(state="a" * 65))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(state=D_BAD_UPPER))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(state="g" * 64))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(audit="a" * 63))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(audit=D_BAD_UPPER))

    def test_stage_format(self) -> None:
        for bad in ("", "PREPARED", "done", "prepare", None):
            with self.assertRaises((TypeError, ValueError)):
                checkpoint(self.path, {**req("z"), "stage": bad})

    def test_corrupt_error_is_value_error(self) -> None:
        self.assertTrue(issubclass(CorruptTransactionError, ValueError))

    def test_bad_request_validated_before_corrupt_file(self) -> None:
        with open(self.path, "wb") as handle:
            handle.write(b"garbage\n")
        with self.assertRaises(ValueError):
            checkpoint(self.path, {"id": "x", "state": D1, "audit": D2})
        with self.assertRaises(TypeError):
            checkpoint(self.path, [])


class CheckpointCorruptionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "tx.json")
        checkpoint(self.path, req(rid="a"))
        checkpoint(self.path, req(rid="b"))
        self.good = self.read_raw()

    def write(self, data: bytes) -> None:
        with open(self.path, "wb") as handle:
            handle.write(data)

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def assertCorrupt(self, data: bytes) -> None:
        self.write(data)
        with self.assertRaises(CorruptTransactionError):
            checkpoint(self.path)
        with self.assertRaises(CorruptTransactionError):
            checkpoint(self.path, req(rid="c"))

    def test_missing_trailing_lf(self) -> None:
        self.assertCorrupt(self.good[:-1])

    def test_extra_trailing_lf(self) -> None:
        self.assertCorrupt(self.good + b"\n")

    def test_non_canonical_whitespace(self) -> None:
        self.assertCorrupt(self.good.replace(b',"version"', b', "version"', 1))

    def test_non_canonical_unicode_escape_in_id_is_invalid_anyway(self) -> None:
        self.assertCorrupt(
            self.good.replace(b'"id":"a"', b'"id":"\\u0061"', 1)
        )

    def test_wrong_top_level_key_order(self) -> None:
        index = json.loads(self.good)
        reordered = {"version": index["version"], "items": index["items"]}
        self.assertCorrupt(canonical(reordered) + b"\n")

    def test_wrong_record_key_order(self) -> None:
        index = json.loads(self.good)
        index["items"] = [
            {"id": item["id"], "state": item["state"],
             "audit": item["audit"], "stage": item["stage"]}
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

    def test_bad_digest_in_file(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["state"] = D_BAD_UPPER
        self.assertCorrupt(canonical(index) + b"\n")
        index = json.loads(self.good)
        index["items"][0]["audit"] = "a" * 63
        self.assertCorrupt(canonical(index) + b"\n")

    def test_bad_stage_in_file(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["stage"] = "done"
        self.assertCorrupt(canonical(index) + b"\n")
        index = json.loads(self.good)
        index["items"][0]["stage"] = "PREPARED"
        self.assertCorrupt(canonical(index) + b"\n")
        index = json.loads(self.good)
        index["items"][0]["stage"] = 1
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

    def test_duplicate_json_keys_are_corrupt(self) -> None:
        self.assertCorrupt(b'{"items":[],"items":[],"version":1}\n')

    def test_write_against_corrupt_file_does_not_modify_it(self) -> None:
        bad = self.good[:-1]
        self.write(bad)
        with self.assertRaises(CorruptTransactionError):
            checkpoint(self.path, req(rid="c"))
        self.assertEqual(self.read_raw(), bad)

    def test_tmp_file_removed_after_replace(self) -> None:
        checkpoint(self.path, req(rid="z"))
        self.assertFalse(os.path.exists(self.path + ".tmp"))


if __name__ == "__main__":
    unittest.main()
