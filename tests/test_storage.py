import json
import os
import unittest

from offline_coordination.storage import CorruptStateError, load_state, save_state


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, deleted, clock, writer):
    return [value, deleted, dict(clock), writer]


SAMPLE = state({"a": 1, "b": 2}, {"k": record("v", False, {"a": 1}, "a")})
SAMPLE_BYTES = (
    b'{"clock":{"a":1,"b":2},"records":{"k":["v",false,{"a":1},"a"]}}\n'
)


class SaveFormatTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.path = os.path.join(self.dir, "state.json")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_save_returns_none(self) -> None:
        self.assertIsNone(save_state(self.path, SAMPLE))

    def test_exact_file_format(self) -> None:
        save_state(self.path, SAMPLE)
        with open(self.path, "rb") as handle:
            self.assertEqual(handle.read(), SAMPLE_BYTES)

    def test_record_fields_ordered_value_deleted_clock_writer(self) -> None:
        save_state(self.path, SAMPLE)
        with open(self.path, "rb") as handle:
            text = handle.read().decode("utf-8")
        self.assertIn('"k":["v",false,{"a":1},"a"]', text)

    def test_keys_are_sorted_and_separators_compact(self) -> None:
        data = state({"z": 1, "a": 1}, {"z": record("", True, {"a": 1, "z": 1}, "z")})
        save_state(self.path, data)
        with open(self.path, "rb") as handle:
            text = handle.read().decode("utf-8")
        self.assertEqual(
            text,
            '{"clock":{"a":1,"z":1},'
            '"records":{"z":["",true,{"a":1,"z":1},"z"]}}\n',
        )

    def test_non_ascii_value_is_written_raw_utf8(self) -> None:
        data = state({"a": 1}, {"k": record("日本語", False, {"a": 1}, "a")})
        save_state(self.path, data)
        with open(self.path, "rb") as handle:
            raw = handle.read()
        self.assertIn("日本語".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        self.assertEqual(json.loads(raw.decode("utf-8")), data)

    def test_no_tmp_left_after_successful_save(self) -> None:
        save_state(self.path, SAMPLE)
        self.assertEqual(sorted(os.listdir(self.dir)), ["state.json"])

    def test_input_state_is_not_mutated(self) -> None:
        import copy

        snapshot = copy.deepcopy(SAMPLE)
        save_state(self.path, SAMPLE)
        self.assertEqual(SAMPLE, snapshot)


class RoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "state.json")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_round_trip(self) -> None:
        save_state(self.path, SAMPLE)
        self.assertEqual(load_state(self.path), SAMPLE)

    def test_loaded_state_is_a_fresh_deep_copy(self) -> None:
        save_state(self.path, SAMPLE)
        first = load_state(self.path)
        second = load_state(self.path)
        self.assertIsNot(first, second)
        self.assertIsNot(first["clock"], second["clock"])
        self.assertIsNot(first["records"]["k"], second["records"]["k"])
        self.assertIsNot(first["records"]["k"][2], second["records"]["k"][2])
        first["clock"]["a"] = 99
        first["records"]["k"][0] = "mutated"
        first["records"]["k"][2]["a"] = 99
        self.assertEqual(second, SAMPLE)


class RotationTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "state.json")
        self.bak = self.path + ".bak"
        self.tmp = self.path + ".tmp"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_first_save_creates_no_backup(self) -> None:
        v1 = state({"a": 1})
        save_state(self.path, v1)
        self.assertFalse(os.path.exists(self.bak))
        self.assertEqual(load_state(self.path), v1)

    def test_backup_holds_most_recent_previous_state(self) -> None:
        v1 = state({"a": 1})
        v2 = state({"a": 2}, {"k": record("old", False, {"a": 2}, "a")})
        v3 = state({"a": 3}, {"k": record("new", False, {"a": 3}, "a")})
        save_state(self.path, v1)
        save_state(self.path, v2)
        with open(self.path, "rb") as handle:
            self.assertEqual(json.loads(handle.read()), v2)
        with open(self.bak, "rb") as handle:
            self.assertEqual(json.loads(handle.read()), v1)
        save_state(self.path, v3)
        with open(self.path, "rb") as handle:
            self.assertEqual(json.loads(handle.read()), v3)
        # Backup is the immediately previous state, not an older one.
        with open(self.bak, "rb") as handle:
            self.assertEqual(json.loads(handle.read()), v2)
        self.assertFalse(os.path.exists(self.tmp))

    def test_main_missing_loads_backup(self) -> None:
        v1 = state({"a": 1})
        v2 = state({"a": 2})
        save_state(self.path, v1)
        save_state(self.path, v2)
        os.remove(self.path)
        self.assertEqual(load_state(self.path), v1)

    def test_corrupt_main_falls_back_to_backup(self) -> None:
        v1 = state({"a": 1})
        save_state(self.path, v1)
        save_state(self.path, state({"a": 2}))
        with open(self.path, "wb") as handle:
            handle.write(b"{not json")
        self.assertEqual(load_state(self.path), v1)

    def test_valid_main_is_preferred_over_backup(self) -> None:
        v1 = state({"a": 1})
        v2 = state({"a": 2})
        save_state(self.path, v1)
        save_state(self.path, v2)
        with open(self.bak, "wb") as handle:
            handle.write(b"garbage")
        self.assertEqual(load_state(self.path), v2)

    def test_tmp_file_is_ignored(self) -> None:
        with open(self.tmp, "wb") as handle:
            handle.write(SAMPLE_BYTES)
        with self.assertRaises(FileNotFoundError):
            load_state(self.path)

        save_state(self.path, state({"a": 1}))
        with open(self.tmp, "wb") as handle:
            handle.write(b"interrupted write")
        # The stray tmp file must neither be read nor block a normal load.
        self.assertEqual(load_state(self.path), state({"a": 1}))


class CorruptionTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "state.json")
        self.bak = self.path + ".bak"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _corrupt(self, target, payload):
        with open(target, "wb") as handle:
            handle.write(payload)

    def test_missing_main_and_backup_raise_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_state(self.path)

    def test_corrupt_is_value_error_subclass(self) -> None:
        self.assertTrue(issubclass(CorruptStateError, ValueError))

    def test_bad_utf8_in_main_and_backup(self) -> None:
        self._corrupt(self.path, b"\xff\xfe")
        self._corrupt(self.bak, b"\xff")
        with self.assertRaises(CorruptStateError):
            load_state(self.path)

    def test_bad_json_in_main_missing_backup(self) -> None:
        self._corrupt(self.path, b"{broken")
        with self.assertRaises(CorruptStateError):
            load_state(self.path)

    def test_invalid_state_shape_in_both(self) -> None:
        self._corrupt(self.path, b"[1, 2, 3]\n")
        self._corrupt(self.bak, b"{}\n")  # valid JSON, wrong state shape
        with self.assertRaises(CorruptStateError):
            load_state(self.path)

    def test_state_validation_failure_is_corruption(self) -> None:
        # Valid JSON but record clock exceeds the state clock.
        bad = (
            b'{"clock":{},"records":{"k":["v",false,{"a":2},"a"]}}\n'
        )
        self._corrupt(self.path, bad)
        with self.assertRaises(CorruptStateError):
            load_state(self.path)

    def test_one_valid_candidate_recovers(self) -> None:
        save_state(self.path, state({"a": 1}))
        save_state(self.path, state({"a": 2}))
        self._corrupt(self.path, b"not json at all")
        self.assertEqual(load_state(self.path), state({"a": 1}))

    def test_other_os_error_propagates(self) -> None:
        os.mkdir(self.path)  # opening a directory as a file raises IsADirectoryError
        with self.assertRaises(OSError):
            load_state(self.path)


class ValidationBeforeWriteTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "state.json")
        self.bak = self.path + ".bak"
        self.tmp = self.path + ".tmp"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_non_str_path_save_raises_type_error(self) -> None:
        for bad in (123, b"x", None, ["x"]):
            with self.assertRaises(TypeError):
                save_state(bad, SAMPLE)

    def test_non_str_path_load_raises_type_error(self) -> None:
        for bad in (123, b"x", None, ["x"]):
            with self.assertRaises(TypeError):
                load_state(bad)

    def test_type_violation_does_not_touch_files(self) -> None:
        bad = state({"a": "1"})  # clock count must be an int
        with self.assertRaises(TypeError):
            save_state(self.path, bad)
        self.assertEqual(os.listdir(self._tmp.name), [])

    def test_value_violation_does_not_touch_files(self) -> None:
        bad = state({"a": -1})
        with self.assertRaises(ValueError):
            save_state(self.path, bad)
        self.assertEqual(os.listdir(self._tmp.name), [])

    def test_invalid_state_leaves_existing_main_and_backup_intact(self) -> None:
        v1 = state({"a": 1})
        v2 = state({"a": 2})
        save_state(self.path, v1)
        save_state(self.path, v2)
        with open(self.path, "rb") as handle:
            main_before = handle.read()
        with open(self.bak, "rb") as handle:
            bak_before = handle.read()
        with self.assertRaises(ValueError):
            save_state(self.path, state({"a": 1}, {"k": record("v", True, {"a": 1}, "a")}))
        with open(self.path, "rb") as handle:
            self.assertEqual(handle.read(), main_before)
        with open(self.bak, "rb") as handle:
            self.assertEqual(handle.read(), bak_before)
        self.assertFalse(os.path.exists(self.tmp))

    def test_filesystem_failure_leaves_existing_state_readable(self) -> None:
        save_state(self.path, SAMPLE)
        with open(self.path, "rb") as handle:
            main_before = handle.read()
        # Writing into a nonexistent directory fails when creating the tmp file.
        missing = os.path.join(self._tmp.name, "no-such-dir", "state.json")
        with self.assertRaises(OSError):
            save_state(missing, state({"a": 9}))
        with open(self.path, "rb") as handle:
            self.assertEqual(handle.read(), main_before)
        self.assertEqual(load_state(self.path), SAMPLE)


class CrashWindowTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "state.json")
        self.bak = self.path + ".bak"
        self.tmp = self.path + ".tmp"
        self.v1 = state({"a": 1})
        self.v2 = state({"a": 2})
        save_state(self.path, self.v1)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _arm_failure_at_publish(self, error):
        import offline_coordination.storage as storage

        real_replace = storage.os.replace
        armed = {"on": True}

        def fake_replace(src, dst):
            if armed["on"] and src == self.tmp and dst == self.path:
                armed["on"] = False
                raise error
            return real_replace(src, dst)

        storage.os.replace = fake_replace
        self.addCleanup(setattr, storage.os, "replace", real_replace)

    def test_publish_failure_rolls_back_to_previous_main(self) -> None:
        self._arm_failure_at_publish(OSError("boom"))
        with self.assertRaises(OSError):
            save_state(self.path, self.v2)
        self.assertEqual(load_state(self.path), self.v1)
        self.assertFalse(os.path.exists(self.tmp))

    def test_publish_interrupt_rolls_back_to_previous_main(self) -> None:
        self._arm_failure_at_publish(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            save_state(self.path, self.v2)
        self.assertEqual(load_state(self.path), self.v1)
        self.assertFalse(os.path.exists(self.tmp))

    def test_first_rename_failure_leaves_main_untouched(self) -> None:
        import offline_coordination.storage as storage

        real_replace = storage.os.replace

        def fake_replace(src, dst):
            if src == self.path and dst == self.bak:
                raise OSError("boom")
            return real_replace(src, dst)

        storage.os.replace = fake_replace
        try:
            with self.assertRaises(OSError):
                save_state(self.path, self.v2)
        finally:
            storage.os.replace = real_replace
        self.assertEqual(load_state(self.path), self.v1)
        self.assertFalse(os.path.exists(self.tmp))


if __name__ == "__main__":
    unittest.main()
