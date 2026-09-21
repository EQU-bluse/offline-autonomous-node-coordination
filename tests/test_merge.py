import copy
import unittest

from offline_coordination.merge import merge_states


def state(clock, records):
    return {"clock": clock, "records": records}


class MergeStatesTest(unittest.TestCase):
    def test_clock_takes_per_node_max(self):
        left = state({"a": 1, "b": 3}, {})
        right = state({"a": 2, "c": 5}, {})
        merged = merge_states(left, right)
        self.assertEqual(merged["clock"], {"a": 2, "b": 3, "c": 5})

    def test_one_sided_and_identical_records_are_kept(self):
        left = state({"a": 1}, {"x": ["v", False, {"a": 1}, "a"]})
        right = state({"a": 1}, {"y": ["", True, {"a": 1}, "a"]})
        merged = merge_states(left, right)
        self.assertEqual(merged["records"]["x"], ["v", False, {"a": 1}, "a"])
        self.assertEqual(merged["records"]["y"], ["", True, {"a": 1}, "a"])
        self.assertEqual(merge_states(left, left)["records"], left["records"])

    def test_dominating_clock_wins(self):
        left = state({"a": 2, "b": 1}, {"k": ["new", False, {"a": 2, "b": 1}, "a"]})
        right = state({"a": 1, "b": 1}, {"k": ["old", False, {"a": 1, "b": 1}, "a"]})
        merged = merge_states(left, right)
        self.assertEqual(merged["records"]["k"][0], "new")

    def test_concurrent_records_use_tuple_order(self):
        left = state({"a": 1, "b": 1}, {"k": ["from-a", False, {"a": 1}, "a"]})
        right = state({"a": 1, "b": 1}, {"k": ["from-b", False, {"b": 1}, "b"]})
        merged = merge_states(left, right)
        # clock[writer] ties at 1; writer "b" > "a".
        self.assertEqual(merged["records"]["k"][0], "from-b")

    def test_concurrent_tombstone_beats_live_on_tie(self):
        left = state({"a": 1}, {"k": ["", True, {"a": 1}, "a"]})
        right = state({"a": 1}, {"k": ["v", False, {"a": 1}, "a"]})
        merged = merge_states(left, right)
        self.assertEqual(merged["records"]["k"], ["", True, {"a": 1}, "a"])

    def test_inputs_are_not_modified_and_output_is_fresh(self):
        left = state({"a": 1}, {"k": ["v", False, {"a": 1}, "a"]})
        right = state({"a": 2}, {})
        left_snapshot = copy.deepcopy(left)
        right_snapshot = copy.deepcopy(right)
        merged = merge_states(left, right)
        self.assertEqual(left, left_snapshot)
        self.assertEqual(right, right_snapshot)
        merged["clock"]["a"] = 99
        merged["records"]["k"][2]["a"] = 99
        self.assertEqual(left, left_snapshot)


class ValidationTest(unittest.TestCase):
    def valid(self):
        return state({"a": 1}, {"k": ["v", False, {"a": 1}, "a"]})

    def assert_type_error(self, left, right=None):
        with self.assertRaises(TypeError):
            merge_states(left, right if right is not None else self.valid())

    def assert_value_error(self, left, right=None):
        with self.assertRaises(ValueError):
            merge_states(left, right if right is not None else self.valid())

    def test_type_errors(self):
        self.assert_type_error([])
        self.assert_type_error(state([], {}))
        self.assert_type_error(state({1: 1}, {}))
        self.assert_type_error(state({"a": "1"}, {}))
        self.assert_type_error(state({"a": True}, {}))
        self.assert_type_error(state({"a": 1.0}, {}))
        self.assert_type_error(state({"a": 1}, []))
        self.assert_type_error(state({"a": 1}, {1: ["v", False, {"a": 1}, "a"]}))
        self.assert_type_error(state({"a": 1}, {"k": ("v", False, {"a": 1}, "a")}))
        self.assert_type_error(state({"a": 1}, {"k": [1, False, {"a": 1}, "a"]}))
        self.assert_type_error(state({"a": 1}, {"k": ["v", 0, {"a": 1}, "a"]}))
        self.assert_type_error(state({"a": 1}, {"k": ["v", False, [], "a"]}))
        self.assert_type_error(state({"a": 1}, {"k": ["v", False, {"a": 1}, 7]}))

    def test_value_errors(self):
        self.assert_value_error({})
        bad_keys = self.valid()
        bad_keys["extra"] = None
        self.assert_value_error(bad_keys)
        self.assert_value_error(state({"": 1}, {}))
        self.assert_value_error(state({"a": -1}, {}))
        self.assert_value_error(state({"a": 1}, {"": ["v", False, {"a": 1}, "a"]}))
        self.assert_value_error(state({"a": 1}, {"k": ["v", False, {"a": 1}]}))
        self.assert_value_error(
            state({"a": 1}, {"k": ["v", False, {"a": 1}, "a", "a"]})
        )
        self.assert_value_error(state({"a": 1}, {"k": ["x", True, {"a": 1}, "a"]}))
        self.assert_value_error(state({"a": 1}, {"k": ["v", False, {"a": 1}, ""]}))
        self.assert_value_error(state({"a": 1}, {"k": ["v", False, {"a": 1}, "b"]}))
        self.assert_value_error(state({"a": 1}, {"k": ["v", False, {"a": 2}, "a"]}))
        self.assert_value_error(state({"a": 1}, {"k": ["v", False, {"b": 1}, "b"]}))
        self.assert_value_error(state({"a": 1}, {"k": ["v", False, {"a": -1}, "a"]}))

    def test_right_side_is_validated_too(self):
        with self.assertRaises(ValueError):
            merge_states(self.valid(), state({"a": -1}, {}))
        with self.assertRaises(TypeError):
            merge_states(self.valid(), state({"a": True}, {}))


if __name__ == "__main__":
    unittest.main()
