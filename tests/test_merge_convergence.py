"""Convergence and algebraic-law tests for merge_states / preview_changes.

The concurrent-record arbitration is a total order: clocks are compared
component by component over the ascending union of node names (missing
components count as 0), then writer, deleted and value.  These tests pin
down the historical preference-cycle counterexample and prove that
merge_states is commutative, associative and idempotent on legal states,
and that preview_changes predicts the winners merge_states actually keeps.
"""

import itertools
import random
import unittest

from offline_coordination.merge import merge_states, preview_changes


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, deleted, clock, writer):
    return [value, deleted, dict(clock), writer]


def state_for(records, extra_clock=None):
    """Build a legal state whose outer clock covers every record clock."""
    outer = dict(extra_clock or {})
    for rec in records.values():
        for node, count in rec[2].items():
            outer[node] = max(outer.get(node, 0), count)
    return state(outer, records)


def all_bracketings(states):
    """Every binary parenthesization of every permutation of ``states``."""
    results = []
    for perm in itertools.permutations(states):
        acc = perm[0]
        for nxt in perm[1:]:
            acc = merge_states(acc, nxt)
        results.append(acc)
    if len(states) == 3:
        a, b, c = states
        results.append(merge_states(a, merge_states(b, c)))
        results.append(merge_states(merge_states(a, c), b))
        results.append(merge_states(b, merge_states(a, c)))
    return results


class PreferenceCycleTest(unittest.TestCase):
    """The boundary case: A > B, B > C, C > A under the old tuple rule."""

    def setUp(self) -> None:
        self.rec_a = record("v", False, {"a": 1, "b": 2}, "a")
        self.rec_b = record("v", False, {"a": 1, "b": 1}, "b")
        self.rec_c = record("v", False, {"ab": 1}, "ab")
        self.state_a = state({"a": 1, "b": 2}, {"k": self.rec_a})
        self.state_b = state({"a": 1, "b": 1}, {"k": self.rec_b})
        self.state_c = state({"ab": 1}, {"k": self.rec_c})

    def test_every_grouping_keeps_the_same_winner(self) -> None:
        states = [self.state_a, self.state_b, self.state_c]
        for merged in all_bracketings(states):
            self.assertEqual(merged["records"]["k"], self.rec_a)
            self.assertEqual(merged["clock"], {"a": 1, "ab": 1, "b": 2})

    def test_repeated_merges_do_not_change_the_outcome(self) -> None:
        merged = merge_states(merge_states(self.state_a, self.state_b), self.state_c)
        again = merge_states(merged, merge_states(self.state_b, self.state_c))
        self.assertEqual(again, merged)
        self.assertEqual(merge_states(again, self.state_a), merged)


class ConcurrentArbitrationTest(unittest.TestCase):
    def test_disjoint_node_sets_compare_by_ascending_name(self) -> None:
        # Union [x, y, z]: (2, 0, 0) vs (0, 1, 5) -> x decides, 2 > 0.
        left_rec = record("v", False, {"x": 2}, "x")
        right_rec = record("v", False, {"y": 1, "z": 5}, "y")
        merged = merge_states(
            state_for({"k": left_rec}), state_for({"k": right_rec})
        )
        self.assertEqual(merged["records"]["k"], left_rec)
        swapped = merge_states(
            state_for({"k": right_rec}), state_for({"k": left_rec})
        )
        self.assertEqual(swapped["records"]["k"], left_rec)

    def test_zero_count_component_counts_as_missing(self) -> None:
        # {a: 0, b: 1} is concurrent with {a: 1}; the a component (0 vs 1)
        # decides before b is ever consulted.
        zeroed = record("v", False, {"a": 0, "b": 1}, "b")
        plain = record("v", False, {"a": 1}, "a")
        merged = merge_states(
            state_for({"k": zeroed}), state_for({"k": plain})
        )
        self.assertEqual(merged["records"]["k"], plain)

    def test_zero_only_difference_picks_a_canonical_record(self) -> None:
        # Records differing only by an explicit zero component are
        # effectively equal; the survivor must not depend on the order.
        sparse = record("r", False, {"a": 1, "b": 1}, "b")
        padded = record("r", False, {"a": 1, "ab": 0, "b": 1}, "b")
        forward = merge_states(state_for({"k": sparse}), state_for({"k": padded}))
        backward = merge_states(state_for({"k": padded}), state_for({"k": sparse}))
        self.assertEqual(forward, backward)
        self.assertEqual(forward["records"]["k"], sparse)

    def test_tombstone_wins_equal_clock_against_any_value(self) -> None:
        alive = record("zzz", False, {"a": 1, "b": 1}, "a")
        dead = record("", True, {"a": 1, "b": 1}, "a")
        merged = merge_states(
            state_for({"k": alive}), state_for({"k": dead})
        )
        self.assertEqual(merged["records"]["k"], dead)

    def test_tombstone_competes_in_concurrent_arbitration(self) -> None:
        # Concurrent clocks; the tombstone's clock wins on component a.
        alive = record("v", False, {"a": 1, "b": 2}, "a")
        dead = record("", True, {"a": 2, "b": 1}, "a")
        merged = merge_states(
            state_for({"k": alive}), state_for({"k": dead})
        )
        self.assertEqual(merged["records"]["k"], dead)
        # And the plain value wins when its own clock is ahead.
        stronger = record("v", False, {"a": 3, "b": 0}, "a")
        merged = merge_states(
            state_for({"k": dead}), state_for({"k": stronger})
        )
        self.assertEqual(merged["records"]["k"], stronger)

    def test_equal_clocks_fall_back_to_writer_then_deleted_then_value(self) -> None:
        clock = {"a": 1, "b": 1}
        rec_b = record("v", False, clock, "b")
        rec_a = record("v", False, clock, "a")
        merged = merge_states(state_for({"k": rec_a}), state_for({"k": rec_b}))
        self.assertEqual(merged["records"]["k"], rec_b)  # writer "b" > "a"


def _random_clock(rng, nodes, hi=3):
    clock = {}
    for node in nodes:
        if rng.random() < 0.7:
            clock[node] = rng.randint(0, hi)
    return clock


def _random_state(rng, keys, nodes):
    records = {}
    for key in keys:
        if rng.random() < 0.8:
            writer = rng.choice(nodes)
            clock = _random_clock(rng, nodes)
            clock[writer] = max(clock.get(writer, 0), 1)
            deleted = rng.random() < 0.3
            value = "" if deleted else rng.choice(["p", "q", "r"])
            records[key] = record(value, deleted, clock, writer)
    return state_for(records, extra_clock=_random_clock(rng, nodes))


class AlgebraicLawsTest(unittest.TestCase):
    def setUp(self) -> None:
        rng = random.Random(20261006)
        self.pool = [
            _random_state(rng, ["k1", "k2"], ["a", "ab", "b"]) for _ in range(12)
        ]

    def test_idempotency(self) -> None:
        for s in self.pool:
            self.assertEqual(merge_states(s, s), s)

    def test_commutativity(self) -> None:
        for left, right in itertools.product(self.pool, repeat=2):
            self.assertEqual(merge_states(left, right), merge_states(right, left))

    def test_associativity(self) -> None:
        for a, b, c in itertools.product(self.pool, repeat=3):
            self.assertEqual(
                merge_states(merge_states(a, b), c),
                merge_states(a, merge_states(b, c)),
            )

    def test_all_groupings_of_four_states_agree(self) -> None:
        rng = random.Random(7)
        for _ in range(50):
            states = [rng.choice(self.pool) for _ in range(4)]
            results = [merge_states(merge_states(a, b), merge_states(c, d))
                       for a, b, c, d in itertools.permutations(states)]
            results.append(merge_states(
                merge_states(states[0], states[1]),
                merge_states(states[2], states[3]),
            ))
            first = results[0]
            for other in results[1:]:
                self.assertEqual(other, first)


class PreviewConsistencyTest(unittest.TestCase):
    def setUp(self) -> None:
        rng = random.Random(20261007)
        self.pool = [
            _random_state(rng, ["k1", "k2"], ["a", "ab", "b"]) for _ in range(10)
        ]

    def test_item_structure_and_ordering(self) -> None:
        local = state_for({"k2": record("v", False, {"a": 1}, "a")})
        remote = state_for({"k1": record("v", False, {"b": 1}, "b")})
        preview = preview_changes(local, remote)
        self.assertEqual(set(preview), {"items", "version"})
        self.assertEqual(preview["version"], 1)
        self.assertEqual([item["key"] for item in preview["items"]], ["k1"])
        self.assertEqual(
            list(preview["items"][0]), ["decision", "key", "need", "winner"]
        )

    def test_preview_winners_match_merge_outcome(self) -> None:
        for local, remote in itertools.product(self.pool, repeat=2):
            preview = preview_changes(local, remote)
            merged = merge_states(local, remote)
            self.assertEqual(
                [item["key"] for item in preview["items"]],
                sorted(remote["records"]),
            )
            for item in preview["items"]:
                key = item["key"]
                decision, winner = item["decision"], item["winner"]
                local_rec = local["records"].get(key)
                remote_rec = remote["records"][key]
                merged_rec = merged["records"].get(key)
                if decision == "missing":
                    self.assertTrue(item["need"])
                    self.assertIsNone(winner)
                elif decision == "apply":
                    self.assertEqual(winner, "remote")
                    self.assertEqual(merged_rec, remote_rec)
                elif decision == "duplicate":
                    self.assertEqual(winner, "equal")
                    self.assertEqual(merged_rec, local_rec)
                elif decision == "stale":
                    self.assertEqual(winner, "local")
                    self.assertEqual(merged_rec, local_rec)
                else:
                    self.assertEqual(decision, "conflict")
                    expected = local_rec if winner == "local" else remote_rec
                    self.assertEqual(merged_rec, expected)

    def test_conflict_winner_follows_component_order(self) -> None:
        # Concurrent clocks; remote wins because its a component is larger.
        local = state({"a": 2, "b": 2},
                      {"k": record("v", False, {"a": 1, "b": 2}, "a")})
        remote = state({"a": 2, "b": 2},
                       {"k": record("v", False, {"a": 2, "b": 1}, "a")})
        preview = preview_changes(local, remote)
        self.assertEqual(preview["items"][0]["decision"], "conflict")
        self.assertEqual(preview["items"][0]["winner"], "remote")
        # Swapping the roles flips the predicted side, not the record.
        flipped = preview_changes(remote, local)
        self.assertEqual(flipped["items"][0]["decision"], "conflict")
        self.assertEqual(flipped["items"][0]["winner"], "local")


if __name__ == "__main__":
    unittest.main()
