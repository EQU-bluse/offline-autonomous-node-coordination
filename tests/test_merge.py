import copy
import unittest

from offline_coordination.merge import merge_states


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, deleted, clock, writer):
    return [value, deleted, dict(clock), writer]


class MergeClockTest(unittest.TestCase):
    def test_clock_takes_per_node_maximum(self) -> None:
        left = state({"a": 2, "b": 5})
        right = state({"a": 7, "c": 3})
        merged = merge_states(left, right)
        self.assertEqual(merged["clock"], {"a": 7, "b": 5, "c": 3})

    def test_missing_node_counts_as_zero(self) -> None:
        left = state({"a": 0})
        right = state({"b": 4})
        merged = merge_states(left, right)
        self.assertEqual(merged["clock"], {"a": 0, "b": 4})

    def test_empty_clocks(self) -> None:
        merged = merge_states(state(), state())
        self.assertEqual(merged, {"clock": {}, "records": {}})


class MergeRecordsTest(unittest.TestCase):
    def test_record_only_on_left_is_kept(self) -> None:
        rec = record("v", False, {"a": 1}, "a")
        merged = merge_states(state({"a": 1}, {"k": rec}), state())
        self.assertEqual(merged["records"], {"k": ["v", False, {"a": 1}, "a"]})

    def test_record_only_on_right_is_kept(self) -> None:
        rec = record("v", False, {"b": 2}, "b")
        merged = merge_states(state({"b": 2}), state({"b": 2}, {"k": rec}))
        self.assertEqual(merged["records"], {"k": ["v", False, {"b": 2}, "b"]})

    def test_identical_records_are_kept(self) -> None:
        rec = record("v", False, {"a": 1}, "a")
        merged = merge_states(
            state({"a": 1}, {"k": rec}), state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        )
        self.assertEqual(merged["records"], {"k": ["v", False, {"a": 1}, "a"]})

    def test_dominant_clock_wins(self) -> None:
        old = record("old", False, {"a": 1, "b": 1}, "a")
        new = record("new", False, {"a": 2, "b": 1}, "a")
        merged = merge_states(
            state({"a": 2, "b": 1}, {"k": old}),
            state({"a": 2, "b": 1}, {"k": new}),
        )
        self.assertEqual(merged["records"]["k"], new)

        merged_reversed = merge_states(
            state({"a": 2, "b": 1}, {"k": new}),
            state({"a": 2, "b": 1}, {"k": old}),
        )
        self.assertEqual(merged_reversed["records"]["k"], new)

    def test_extra_component_counts_for_dominance(self) -> None:
        # {a:1, b:1} dominates {a:1} even though the writer is a.
        less = record("less", False, {"a": 1}, "a")
        more = record("more", False, {"a": 1, "b": 1}, "a")
        merged = merge_states(
            state({"a": 1, "b": 1}, {"k": less}),
            state({"a": 1, "b": 1}, {"k": more}),
        )
        self.assertEqual(merged["records"]["k"], more)

    def test_concurrent_clocks_compare_writer_component_first(self) -> None:
        # Concurrent: {a:1} vs {b:1}. clock[writer]: 1 vs 1 -> writer names.
        rec_a = record("x", False, {"a": 1}, "a")
        rec_b = record("x", False, {"b": 1}, "b")
        merged = merge_states(
            state({"a": 1, "b": 1}, {"k": rec_a}),
            state({"a": 1, "b": 1}, {"k": rec_b}),
        )
        self.assertEqual(merged["records"]["k"], rec_b)  # "b" > "a"

    def test_concurrent_writer_component_count_decides(self) -> None:
        low = record("x", False, {"a": 1, "b": 5}, "a")
        high = record("x", False, {"a": 9, "b": 2}, "a")
        merged = merge_states(
            state({"a": 9, "b": 5}, {"k": low}),
            state({"a": 9, "b": 5}, {"k": high}),
        )
        self.assertEqual(merged["records"]["k"], high)  # clock['a'] 9 > 1

    def test_concurrent_deleted_flag_decides(self) -> None:
        alive = record("", False, {"a": 1, "b": 1}, "a")
        dead = record("", True, {"a": 1, "b": 1}, "a")
        merged = merge_states(
            state({"a": 1, "b": 1}, {"k": alive}),
            state({"a": 1, "b": 1}, {"k": dead}),
        )
        self.assertEqual(merged["records"]["k"], dead)  # True > False

    def test_concurrent_value_decides(self) -> None:
        low = record("apple", False, {"a": 1, "b": 1}, "a")
        high = record("banana", False, {"a": 1, "b": 1}, "a")
        merged = merge_states(
            state({"a": 1, "b": 1}, {"k": low}),
            state({"a": 1, "b": 1}, {"k": high}),
        )
        self.assertEqual(merged["records"]["k"], high)

    def test_concurrent_full_clock_tuple_decides(self) -> None:
        # Same writer count, writer, deleted, value; clocks still differ and
        # neither dominates, so the sorted clock tuple breaks the tie.
        left_rec = record("v", False, {"a": 1, "b": 2, "c": 1}, "a")
        right_rec = record("v", False, {"a": 1, "b": 1, "c": 2}, "a")
        # tuples: (...,("b",2),("c",1)) vs (...,("b",1),("c",2)) -> left
        merged = merge_states(
            state({"a": 1, "b": 2, "c": 2}, {"k": left_rec}),
            state({"a": 1, "b": 2, "c": 2}, {"k": right_rec}),
        )
        self.assertEqual(merged["records"]["k"], left_rec)
        # Symmetry: swapping inputs must not change the outcome.
        swapped = merge_states(
            state({"a": 1, "b": 2, "c": 2}, {"k": right_rec}),
            state({"a": 1, "b": 2, "c": 2}, {"k": left_rec}),
        )
        self.assertEqual(swapped["records"]["k"], left_rec)

    def test_tombstone_record_round_trips(self) -> None:
        dead = record("", True, {"a": 3}, "a")
        merged = merge_states(state({"a": 3}), state({"a": 3}, {"k": dead}))
        self.assertEqual(merged["records"]["k"], ["", True, {"a": 3}, "a"])


class ImmutabilityTest(unittest.TestCase):
    def _sample(self):
        left = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        right = state({"a": 2}, {"k": record("w", False, {"a": 2}, "a")})
        left_snapshot = copy.deepcopy(left)
        right_snapshot = copy.deepcopy(right)
        merged = merge_states(left, right)
        return left, right, left_snapshot, right_snapshot, merged

    def test_inputs_not_modified(self) -> None:
        left, right, left_snapshot, right_snapshot, _ = self._sample()
        self.assertEqual(left, left_snapshot)
        self.assertEqual(right, right_snapshot)

    def test_result_is_deeply_independent(self) -> None:
        left, right, _, _, merged = self._sample()
        merged["clock"]["a"] = 99
        merged["clock"]["z"] = 99
        merged["records"]["k"][0] = "mutated"
        merged["records"]["k"][2]["a"] = 99
        merged["records"]["new"] = record("x", True, {"q": 1}, "q")
        self.assertEqual(left["clock"], {"a": 1})
        self.assertEqual(right["clock"], {"a": 2})
        self.assertEqual(left["records"]["k"], ["v", False, {"a": 1}, "a"])
        self.assertEqual(right["records"]["k"], ["w", False, {"a": 2}, "a"])

    def test_result_clock_and_record_clocks_are_copies(self) -> None:
        left = state({"a": 1}, {"k": record("v", False, {"a": 1}, "a")})
        right = state()
        merged = merge_states(left, right)
        self.assertIsNot(merged["clock"], left["clock"])
        self.assertIsNot(merged["records"]["k"], left["records"]["k"])
        self.assertIsNot(merged["records"]["k"][2], left["records"]["k"][2])


class ValidationTypeErrorTest(unittest.TestCase):
    def assertTypeError(self, left, right):
        with self.assertRaises(TypeError):
            merge_states(left, right)

    def test_state_must_be_dict(self) -> None:
        self.assertTypeError([], state())
        self.assertTypeError(state(), ())

    def test_clock_must_be_dict(self) -> None:
        bad = {"clock": [], "records": {}}
        self.assertTypeError(bad, state())

    def test_clock_node_must_be_str(self) -> None:
        self.assertTypeError({"clock": {1: 0}, "records": {}}, state())

    def test_clock_count_must_be_int(self) -> None:
        self.assertTypeError({"clock": {"a": "1"}, "records": {}}, state())
        self.assertTypeError({"clock": {"a": 1.0}, "records": {}}, state())

    def test_clock_count_must_not_be_bool(self) -> None:
        self.assertTypeError({"clock": {"a": True}, "records": {}}, state())

    def test_records_must_be_dict(self) -> None:
        self.assertTypeError({"clock": {}, "records": []}, state())

    def test_record_key_must_be_str(self) -> None:
        bad = {"clock": {"a": 1}, "records": {1: record("v", False, {"a": 1}, "a")}}
        self.assertTypeError(bad, state())

    def test_record_must_be_list(self) -> None:
        bad = state({"a": 1}, {"k": ("v", False, {"a": 1}, "a")})
        self.assertTypeError(bad, state())

    def test_value_must_be_str(self) -> None:
        bad = state({"a": 1}, {"k": record(1, False, {"a": 1}, "a")})
        self.assertTypeError(bad, state())

    def test_deleted_must_be_bool(self) -> None:
        bad = state({"a": 1}, {"k": record("", 0, {"a": 1}, "a")})
        self.assertTypeError(bad, state())
        bad = state({"a": 1}, {"k": record("", None, {"a": 1}, "a")})
        self.assertTypeError(bad, state())

    def test_record_clock_must_be_dict(self) -> None:
        bad = state({"a": 1}, {"k": ["v", False, [], "a"]})
        self.assertTypeError(bad, state())

    def test_record_clock_count_must_be_proper_int(self) -> None:
        bad = state({"a": 1}, {"k": record("v", False, {"a": False}, "a")})
        self.assertTypeError(bad, state())

    def test_writer_must_be_str(self) -> None:
        bad = state({"a": 1}, {"k": record("v", False, {"a": 1}, 1)})
        self.assertTypeError(bad, state())


class ValidationValueErrorTest(unittest.TestCase):
    def assertValueError(self, left, right=None):
        with self.assertRaises(ValueError):
            merge_states(left, state() if right is None else right)

    def test_state_key_set_must_match_exactly(self) -> None:
        self.assertValueError({"clock": {}})
        self.assertValueError({"records": {}})
        self.assertValueError({"clock": {}, "records": {}, "extra": 1})

    def test_clock_node_must_be_nonempty(self) -> None:
        self.assertValueError({"clock": {"": 1}, "records": {}})

    def test_clock_count_must_be_nonnegative(self) -> None:
        self.assertValueError({"clock": {"a": -1}, "records": {}})

    def test_record_key_must_be_nonempty(self) -> None:
        self.assertValueError(state({"a": 1}, {"": record("v", False, {"a": 1}, "a")}))

    def test_record_must_have_four_items(self) -> None:
        self.assertValueError(state({"a": 1}, {"k": ["v", False, {"a": 1}]}))
        self.assertValueError(
            state({"a": 1}, {"k": ["v", False, {"a": 1}, "a", "extra"]})
        )

    def test_deleted_requires_empty_value(self) -> None:
        self.assertValueError(state({"a": 1}, {"k": record("v", True, {"a": 1}, "a")}))

    def test_writer_must_be_nonempty(self) -> None:
        self.assertValueError(state({"a": 1}, {"k": record("v", False, {"a": 1}, "")}))

    def test_writer_must_appear_in_record_clock(self) -> None:
        self.assertValueError(state({"a": 1, "b": 1}, {"k": record("v", False, {"a": 1}, "b")}))

    def test_record_clock_must_not_exceed_state_clock(self) -> None:
        self.assertValueError(state({"a": 1}, {"k": record("v", False, {"a": 2}, "a")}))

    def test_record_clock_unknown_node_treated_as_zero_bound(self) -> None:
        # Node absent from the outer clock is bounded by 0: count 1 invalid...
        self.assertValueError(state({"a": 1}, {"k": record("v", False, {"a": 1, "b": 1}, "a")}))
        # ...but count 0 is allowed.
        merged = merge_states(
            state({"a": 1}, {"k": record("v", False, {"a": 1, "b": 0}, "a")}),
            state(),
        )
        self.assertEqual(merged["records"]["k"], ["v", False, {"a": 1, "b": 0}, "a"])


if __name__ == "__main__":
    unittest.main()
