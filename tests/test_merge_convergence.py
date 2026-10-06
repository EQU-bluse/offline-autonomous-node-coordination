"""Convergence and algebraic-law tests for merge_states/preview_changes.

The concurrent-record tie-break is a total order: clocks are compared
component by component over the ascending union of node names (missing
components count as 0), then writer, deleted and value.  Because the
order agrees with causal dominance, merge_states is commutative,
associative and idempotent on legal states, and preview_changes predicts
exactly the winner a merge would keep.
"""

import itertools
import random
import unittest

from offline_coordination.merge import merge_states, preview_changes


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, deleted, clock, writer):
    return [value, deleted, dict(clock), writer]


# The preference-cycle counterexample: three pairwise-mergeable records
# whose winners used to depend on the grouping order.
REC_A = record("v", False, {"a": 1, "b": 2}, "a")
REC_B = record("v", False, {"a": 1, "b": 1}, "b")
REC_C = record("v", False, {"ab": 1}, "ab")
STATE_A = state({"a": 1, "b": 2}, {"k": REC_A})
STATE_B = state({"a": 1, "b": 1}, {"k": REC_B})
STATE_C = state({"ab": 1}, {"k": REC_C})


class PreferenceCycleTest(unittest.TestCase):
    def test_cycle_counterexample_all_groupings_agree(self) -> None:
        # Over the ascending union [a, ab, b] the vectors are A=(1,0,2),
        # B=(1,0,1), C=(0,1,0); A is the unique maximum and must survive
        # every permutation, bracketing and repetition.
        states = [STATE_A, STATE_B, STATE_C]
        results = []
        for perm in itertools.permutations(states):
            left_first = merge_states(merge_states(perm[0], perm[1]), perm[2])
            right_first = merge_states(perm[0], merge_states(perm[1], perm[2]))
            self.assertEqual(left_first, right_first)
            results.append(left_first)
        for result in results[1:]:
            self.assertEqual(result, results[0])

    def test_cycle_counterexample_winner(self) -> None:
        merged = merge_states(merge_states(STATE_A, STATE_B), STATE_C)
        self.assertEqual(merged["records"]["k"], REC_A)
        self.assertEqual(merged["clock"], {"a": 1, "ab": 1, "b": 2})

    def test_cycle_counterexample_repeated_merges_are_stable(self) -> None:
        merged = merge_states(merge_states(STATE_B, STATE_C), STATE_A)
        again = merge_states(merged, merge_states(STATE_A, STATE_C))
        self.assertEqual(merge_states(merged, again), merged)
        self.assertEqual(merged["records"]["k"], REC_A)


class TotalOrderEdgeCasesTest(unittest.TestCase):
    def test_disjoint_node_name_sets(self) -> None:
        # {x:1} vs {y:1,z:1}: over [x, y, z] the vectors are (1,0,0) and
        # (0,1,1), so the x record wins regardless of input order.
        rec_x = record("v", False, {"x": 1}, "x")
        rec_yz = record("v", False, {"y": 1, "z": 1}, "y")
        left = state({"x": 1}, {"k": rec_x})
        right = state({"y": 1, "z": 1}, {"k": rec_yz})
        self.assertEqual(merge_states(left, right)["records"]["k"], rec_x)
        self.assertEqual(merge_states(right, left)["records"]["k"], rec_x)

    def test_zero_count_components_order_deterministically(self) -> None:
        # {a:1,b:0} and {a:1} are equal as vectors; with writer, deleted
        # and value also equal, the sorted clock items break the tie so
        # that both input orders yield byte-identical results.
        padded = record("v", False, {"a": 1, "b": 0}, "a")
        plain = record("v", False, {"a": 1}, "a")
        left = state({"a": 1}, {"k": padded})
        right = state({"a": 1}, {"k": plain})
        forward = merge_states(left, right)
        backward = merge_states(right, left)
        self.assertEqual(forward, backward)
        self.assertEqual(forward["records"]["k"], padded)

    def test_zero_counts_in_concurrent_vector_comparison(self) -> None:
        # {a:0, b:1} vs {b:1}: equal vectors, tie falls to writer name.
        rec_a = record("v", False, {"a": 0, "b": 1}, "a")
        rec_b = record("v", False, {"b": 1}, "b")
        left = state({"b": 1}, {"k": rec_a})
        right = state({"b": 1}, {"k": rec_b})
        self.assertEqual(merge_states(left, right)["records"]["k"], rec_b)
        self.assertEqual(merge_states(right, left)["records"]["k"], rec_b)

    def test_tombstone_beats_value_on_equal_clocks(self) -> None:
        alive = record("x", False, {"a": 1, "b": 1}, "a")
        dead = record("", True, {"a": 1, "b": 1}, "a")
        left = state({"a": 1, "b": 1}, {"k": alive})
        right = state({"a": 1, "b": 1}, {"k": dead})
        self.assertEqual(merge_states(left, right)["records"]["k"], dead)
        self.assertEqual(merge_states(right, left)["records"]["k"], dead)

    def test_dominant_value_beats_stale_tombstone(self) -> None:
        dead = record("", True, {"a": 1}, "a")
        alive = record("x", False, {"a": 2}, "a")
        left = state({"a": 2}, {"k": dead})
        right = state({"a": 2}, {"k": alive})
        self.assertEqual(merge_states(left, right)["records"]["k"], alive)

    def test_concurrent_tombstone_and_value_use_clock_order(self) -> None:
        # Concurrent clocks: tombstone {a:1,b:2} vs live {a:2,b:1}; the
        # b component never matters because a decides first (2 > 1).
        dead = record("", True, {"a": 1, "b": 2}, "a")
        alive = record("x", False, {"a": 2, "b": 1}, "a")
        left = state({"a": 2, "b": 2}, {"k": dead})
        right = state({"a": 2, "b": 2}, {"k": alive})
        self.assertEqual(merge_states(left, right)["records"]["k"], alive)
        self.assertEqual(merge_states(right, left)["records"]["k"], alive)


NODES = ["a", "ab", "b", "c"]
KEYS = ["k1", "k2", "k3"]
VALUES = ["", "v", "apple", "banana"]


def random_state(rng):
    clock = {}
    for node in NODES:
        if rng.random() < 0.7:
            clock[node] = rng.randint(0, 4)
    records = {}
    for key in KEYS:
        if rng.random() < 0.6:
            writer = rng.choice(NODES)
            rclock = {}
            for node in NODES:
                if rng.random() < 0.5:
                    # Zero counts are deliberate: they exercise the
                    # missing-component-is-zero comparisons.
                    rclock[node] = rng.randint(0, clock.get(node, 0))
            if writer not in rclock:
                rclock[writer] = rng.randint(0, clock.get(writer, 0))
            deleted = rng.random() < 0.3
            value = "" if deleted else rng.choice(VALUES)
            records[key] = record(value, deleted, rclock, writer)
    return state(clock, records)


class AlgebraicLawsTest(unittest.TestCase):
    def test_commutative_associative_idempotent(self) -> None:
        rng = random.Random(20261006)
        for _ in range(300):
            left = random_state(rng)
            right = random_state(rng)
            third = random_state(rng)

            # Commutativity.
            self.assertEqual(
                merge_states(left, right), merge_states(right, left)
            )
            # Idempotency.
            self.assertEqual(merge_states(left, left), left)
            # Associativity.
            self.assertEqual(
                merge_states(merge_states(left, right), third),
                merge_states(left, merge_states(right, third)),
            )

    def test_all_permutations_of_triples_converge(self) -> None:
        rng = random.Random(7)
        for _ in range(100):
            states = [random_state(rng) for _ in range(3)]
            merged = [
                merge_states(merge_states(p[0], p[1]), p[2])
                for p in itertools.permutations(states)
            ]
            for result in merged[1:]:
                self.assertEqual(result, merged[0])


class PreviewConsistencyTest(unittest.TestCase):
    def test_conflict_item_structure_and_winner(self) -> None:
        # Both outer clocks cover both record clocks so neither side is
        # reported missing; the records are concurrent.
        covering = {"a": 1, "ab": 1, "b": 1}
        local = state(covering, {"k": record("x", False, {"a": 1, "b": 1}, "b")})
        remote = state(covering, {"k": record("x", False, {"ab": 1}, "ab")})
        preview = preview_changes(local, remote)
        self.assertEqual(set(preview), {"items", "version"})
        self.assertEqual(preview["version"], 1)
        self.assertEqual(len(preview["items"]), 1)
        item = preview["items"][0]
        self.assertEqual(list(item), ["decision", "key", "need", "winner"])
        # Over [a, ab, b]: local (1,0,1) beats remote (0,1,0).
        self.assertEqual(
            item, {"decision": "conflict", "key": "k", "need": {}, "winner": "local"}
        )
        merged = merge_states(local, remote)
        self.assertEqual(merged["records"]["k"], local["records"]["k"])

        # Mirrored call: the same record wins, now reported as remote.
        mirror = preview_changes(remote, local)["items"][0]
        self.assertEqual(mirror["decision"], "conflict")
        self.assertEqual(mirror["winner"], "remote")

    def test_previewed_winners_match_merge(self) -> None:
        rng = random.Random(42)
        for _ in range(300):
            local = random_state(rng)
            remote = random_state(rng)
            preview = preview_changes(local, remote)
            merged = merge_states(local, remote)
            self.assertEqual(
                [item["key"] for item in preview["items"]],
                sorted(remote["records"]),
            )
            for item in preview["items"]:
                key = item["key"]
                winner = item["winner"]
                if winner == "remote":
                    self.assertIn(item["decision"], ("apply", "conflict"))
                    self.assertEqual(merged["records"][key], remote["records"][key])
                elif winner == "local":
                    self.assertIn(item["decision"], ("stale", "conflict"))
                    self.assertEqual(merged["records"][key], local["records"][key])
                elif winner == "equal":
                    self.assertEqual(item["decision"], "duplicate")
                    self.assertEqual(merged["records"][key], local["records"][key])
                else:
                    # "missing": the preview defers, no winner to check.
                    self.assertIsNone(winner)
                    self.assertEqual(item["decision"], "missing")
                    self.assertTrue(item["need"])

    def test_previewed_winner_matches_merge_for_cycle_records(self) -> None:
        # Every pair from the preference-cycle counterexample previews the
        # same winner the merge keeps (pairs whose outer clock is missing
        # prerequisites defer with "missing" and are skipped).
        states = {"a": STATE_A, "b": STATE_B, "c": STATE_C}
        for (left_name, left), (right_name, right) in itertools.permutations(
            states.items(), 2
        ):
            item = preview_changes(left, right)["items"][0]
            if item["winner"] is None:
                # The left outer clock is missing prerequisites; no winner.
                self.assertEqual(item["decision"], "missing")
                continue
            merged = merge_states(left, right)["records"]["k"]
            if item["winner"] == "local":
                self.assertEqual(merged, left["records"]["k"], (left_name, right_name))
            else:
                self.assertEqual(item["winner"], "remote")
                self.assertEqual(merged, right["records"]["k"], (left_name, right_name))


if __name__ == "__main__":
    unittest.main()
