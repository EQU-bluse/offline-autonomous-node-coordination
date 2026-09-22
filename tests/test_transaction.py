import json
import os
import tempfile
import unittest

from offline_coordination import transaction
from offline_coordination.transaction import CorruptTransactionError, checkpoint

D1 = "a" * 64
D2 = "b" * 64
D3 = "c" * 64
D_BAD_UPPER = "A" * 64
RECORD_KEYS = ("audit", "id", "stage", "state")


def req(rid="x", state=D1, audit=D2, stage="prepared"):
    return {"id": rid, "state": state, "audit": audit, "stage": stage}


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class CheckpointRoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "checkpoints.json")

    def write(self, data: bytes) -> None:
        with open(self.path, "wb") as handle:
            handle.write(data)

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_missing_file_queries_as_empty_index(self) -> None:
        self.assertEqual(checkpoint(self.path), [])

    def test_empty_file_is_corrupt(self) -> None:
        self.write(b"")
        with self.assertRaises(CorruptTransactionError):
            checkpoint(self.path)
        with self.assertRaises(CorruptTransactionError):
            checkpoint(self.path, req())

    def test_query_returns_fresh_list_with_fixed_key_order(self) -> None:
        checkpoint(self.path, req(rid="b"))
        checkpoint(self.path, req(rid="a"))
        result = checkpoint(self.path)
        self.assertEqual([item["id"] for item in result], ["a", "b"])
        for item in result:
            self.assertEqual(tuple(item.keys()), RECORD_KEYS)
        self.assertEqual(
            result[0], {"audit": D2, "id": "a", "stage": "prepared", "state": D1}
        )
        again = checkpoint(self.path)
        self.assertIsNot(result, again)
        self.assertIsNot(result[0], again[0])
        result[0]["stage"] = "mutated"
        self.assertEqual(checkpoint(self.path)[0]["stage"], "prepared")

    def test_write_returns_full_sorted_list(self) -> None:
        checkpoint(self.path, req(rid="b"))
        result = checkpoint(self.path, req(rid="a"))
        self.assertEqual([item["id"] for item in result], ["a", "b"])
        for item in result:
            self.assertEqual(tuple(item.keys()), RECORD_KEYS)

    def test_file_is_canonical_compact_json_with_single_lf(self) -> None:
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

    def test_non_ascii_id_charset_is_rejected_but_index_preserves_utf8(self) -> None:
        # ids cannot be non-ASCII, but the serializer must not escape any
        # non-ASCII that could appear in the file; check canonical bytes.
        checkpoint(self.path, req(rid="a"))
        raw = self.read_raw()
        self.assertNotIn(b"\\u", raw)

    def test_items_sorted_by_id_ascending(self) -> None:
        for rid in ("c", "a", "b.b", "a-1", "A", "0"):
            checkpoint(self.path, req(rid=rid))
        index = json.loads(self.read_raw())
        ids = [item["id"] for item in index["items"]]
        self.assertEqual(ids, ["0", "A", "a", "a-1", "b.b", "c"])
        for item in index["items"]:
            self.assertEqual(tuple(item.keys()), RECORD_KEYS)
        self.assertEqual(tuple(index.keys()), ("items", "version"))
        self.assertEqual(index["version"], 1)
        self.assertIsInstance(index["version"], int)

    def test_tmp_file_removed_after_write(self) -> None:
        checkpoint(self.path, req())
        self.assertFalse(os.path.exists(self.path + ".tmp"))


class CheckpointLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "checkpoints.json")

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_new_id_must_start_prepared(self) -> None:
        for stage in ("state", "audit", "committed"):
            with self.assertRaises(ValueError, msg=f"stage={stage}"):
                checkpoint(self.path, req(rid=f"new-{stage}", stage=stage))
        self.assertEqual(checkpoint(self.path), [])

    def test_adjacent_stages_advance_in_order(self) -> None:
        checkpoint(self.path, req(stage="prepared"))
        for stage in ("state", "audit", "committed"):
            result = checkpoint(self.path, req(stage=stage))
            self.assertEqual(result[0]["stage"], stage)
        self.assertEqual(checkpoint(self.path)[0]["stage"], "committed")

    def test_same_id_same_digests_same_stage_is_idempotent(self) -> None:
        checkpoint(self.path, req())
        raw = self.read_raw()
        result = checkpoint(self.path, req())
        self.assertEqual(result[0]["stage"], "prepared")
        self.assertEqual(self.read_raw(), raw)
        # Idempotent replay also holds at a later stage.
        checkpoint(self.path, req(stage="state"))
        raw = self.read_raw()
        checkpoint(self.path, req(stage="state"))
        self.assertEqual(self.read_raw(), raw)

    def test_idempotent_replay_accepts_input_in_any_key_order(self) -> None:
        checkpoint(self.path, req(rid="k"))
        raw = self.read_raw()
        again = checkpoint(
            self.path, {"stage": "prepared", "audit": D2, "id": "k", "state": D1}
        )
        self.assertEqual(tuple(again[0].keys()), RECORD_KEYS)
        self.assertEqual(self.read_raw(), raw)

    def test_same_id_different_state_rejected_and_file_untouched(self) -> None:
        checkpoint(self.path, req(state=D1))
        raw = self.read_raw()
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(state=D3))
        self.assertEqual(self.read_raw(), raw)

    def test_same_id_different_audit_rejected_and_file_untouched(self) -> None:
        checkpoint(self.path, req(audit=D2))
        raw = self.read_raw()
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(audit=D3))
        self.assertEqual(self.read_raw(), raw)

    def test_digest_change_rejected_even_with_valid_stage_advance(self) -> None:
        checkpoint(self.path, req())
        raw = self.read_raw()
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(state=D3, stage="state"))
        self.assertEqual(self.read_raw(), raw)

    def test_stage_regression_rejected_and_file_untouched(self) -> None:
        checkpoint(self.path, req())
        checkpoint(self.path, req(stage="state"))
        raw = self.read_raw()
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(stage="prepared"))
        self.assertEqual(self.read_raw(), raw)

    def test_stage_skip_rejected_and_file_untouched(self) -> None:
        checkpoint(self.path, req())
        raw = self.read_raw()
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(stage="audit"))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(stage="committed"))
        self.assertEqual(self.read_raw(), raw)

    def test_cannot_advance_past_committed(self) -> None:
        checkpoint(self.path, req())
        for stage in ("state", "audit", "committed"):
            checkpoint(self.path, req(stage=stage))
        raw = self.read_raw()
        # Same stage replays fine; there is no further stage to reach.
        checkpoint(self.path, req(stage="committed"))
        self.assertEqual(self.read_raw(), raw)

    def test_rejection_does_not_block_other_ids(self) -> None:
        checkpoint(self.path, req(rid="k"))
        with self.assertRaises(ValueError):
            checkpoint(self.path, req(rid="k", stage="committed"))
        checkpoint(self.path, req(rid="other"))
        self.assertEqual(
            [item["id"] for item in checkpoint(self.path)], ["k", "other"]
        )


class CheckpointValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "checkpoints.json")

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            checkpoint(1)
        with self.assertRaises(TypeError):
            checkpoint(None, req())

    def test_request_must_be_dict_or_none(self) -> None:
        for bad in ([], "x", 1, True):
            with self.assertRaises(TypeError, msg=f"request={bad!r}"):
                checkpoint(self.path, bad)

    def test_request_fields_must_be_str(self) -> None:
        for key in ("id", "state", "audit", "stage"):
            with self.assertRaises(TypeError, msg=f"key={key}"):
                checkpoint(self.path, {**req(), key: 1})

    def test_request_key_set_must_match_exactly(self) -> None:
        with self.assertRaises(ValueError):
            checkpoint(self.path, {"id": "x", "state": D1, "audit": D2})
        with self.assertRaises(ValueError):
            checkpoint(self.path, {**req(), "extra": "x"})

    def test_id_format(self) -> None:
        for good in ("a", "A", "0", ".", "_", "-", "x.y-z_0", "A" * 64):
            result = checkpoint(self.path, req(rid=good))
            self.assertEqual(
                next(item for item in result if item["id"] == good)["id"], good
            )
        for bad in ("", "A" * 65, "a/b", "a b", "a:b", "☃", "a\n", ". "):
            with self.assertRaises(ValueError, msg=f"id={bad!r}"):
                checkpoint(self.path, req(rid=bad))

    def test_digest_format(self) -> None:
        for key in ("state", "audit"):
            for bad in ("a" * 63, "a" * 65, D_BAD_UPPER, "g" * 64):
                with self.assertRaises(ValueError, msg=f"{key}={bad!r}"):
                    checkpoint(self.path, req(**{key: bad}))

    def test_stage_must_be_allowed(self) -> None:
        for bad in ("", "Prepared", "PREPARED", "commit", "done"):
            with self.assertRaises(ValueError, msg=f"stage={bad!r}"):
                checkpoint(self.path, req(stage=bad))

    def test_corrupt_error_is_value_error(self) -> None:
        self.assertTrue(issubclass(CorruptTransactionError, ValueError))


class CheckpointCorruptionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "checkpoints.json")
        checkpoint(self.path, req(rid="a"))
        checkpoint(self.path, req(rid="b", stage="prepared"))
        checkpoint(self.path, req(rid="b", stage="state"))
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

    def test_non_canonical_unicode_escape(self) -> None:
        self.assertCorrupt(self.good.replace(b'"id":"a"', b'"id":"\\u0061"', 1))

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
        del index["items"][0]["stage"]
        self.assertCorrupt(canonical(index) + b"\n")

    def test_bad_id_in_file(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["id"] = "a/b"
        self.assertCorrupt(canonical(index) + b"\n")

    def test_bad_stage_in_file(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["stage"] = "bogus"
        self.assertCorrupt(canonical(index) + b"\n")

    def test_non_str_stage_in_file(self) -> None:
        index = json.loads(self.good)
        index["items"][0]["stage"] = 1
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
        index["items"] = list(reversed(index["items"]))
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


if __name__ == "__main__":
    unittest.main()
