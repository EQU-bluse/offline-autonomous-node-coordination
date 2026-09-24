"""Tests for offline proof comparison (compare_proofs)."""

import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication as R
from offline_coordination.replication import (
    InvalidProofError,
    compare_proofs,
    export_proof,
)

REPORT_KEYS = (
    "common",
    "conflictSeq",
    "left",
    "overlap",
    "relation",
    "right",
    "version",
)
SIDE_KEYS = ("digest", "endSeq", "startSeq")


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def decoded(raw):
    return json.loads(raw)


def boundary(tag, seq):
    return hashlib.sha256(f"{tag}:{seq}".encode("utf-8")).hexdigest()


def synth_proof(start, end, tag="A", mutate=None):
    """Build a self-consistent valid proof for a synthetic chain.

    Entry at seq s chains boundary(tag, s-1) -> boundary(tag, s).  Two
    proofs with the same tag agree entry by entry at shared seqs; a
    different tag forks at every entry.
    """
    entries = []
    for seq in range(start, end + 1):
        entry = {
            "after": boundary(tag, seq),
            "before": boundary(tag, seq - 1),
            "id": f"{tag}-r{seq}",
            "seq": seq,
            "source": f"node-{tag}",
        }
        if mutate is not None:
            updated = mutate(seq, entry)
            if updated is not None:
                entry = updated
        entries.append(entry)
    data = {
        "endSeq": end,
        "entries": entries,
        "firstBefore": entries[0]["before"],
        "lastAfter": entries[-1]["after"],
        "startSeq": start,
        "version": 1,
    }
    data["digest"] = hashlib.sha256(canonical(data)).hexdigest()
    return canonical(data) + b"\n"


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, n, writer="node-a"):
    return [value, False, {writer: n}, writer]


def make_request(rid, base, remote, source="node-a"):
    return {"id": rid, "source": source, "base": base, "remote": remote}


def seed_ledger(path, n=4):
    cur = state()
    for i in range(1, n + 1):
        nxt = state({"node-a": i}, {"k": record(f"v{i}", i)})
        result = R.apply_remote(path, make_request(f"r{i}", cur, nxt))
        assert result["status"] == "applied", result["status"]
        cur = nxt
    return cur


class CompareShapeTest(unittest.TestCase):
    def test_report_is_canonical_compact_json_with_one_lf(self) -> None:
        raw = compare_proofs(synth_proof(1, 3), synth_proof(1, 3))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(raw, canonical(decoded(raw)) + b"\n")
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_top_level_keys_fixed_and_sorted(self) -> None:
        raw = compare_proofs(synth_proof(1, 2), synth_proof(3, 4))
        self.assertEqual(tuple(decoded(raw).keys()), REPORT_KEYS)

    def test_version_is_integer_1(self) -> None:
        report = decoded(compare_proofs(synth_proof(1, 2), synth_proof(1, 2)))
        self.assertEqual(report["version"], 1)
        self.assertIsInstance(report["version"], int)
        self.assertNotIsInstance(report["version"], bool)

    def test_sides_carry_digest_and_range(self) -> None:
        left = synth_proof(2, 4, "A")
        right = synth_proof(3, 5, "A")
        report = decoded(compare_proofs(left, right))
        self.assertEqual(tuple(report["left"].keys()), SIDE_KEYS)
        self.assertEqual(tuple(report["right"].keys()), SIDE_KEYS)
        self.assertEqual(report["left"]["startSeq"], 2)
        self.assertEqual(report["left"]["endSeq"], 4)
        self.assertEqual(report["left"]["digest"], decoded(left)["digest"])
        self.assertEqual(report["right"]["startSeq"], 3)
        self.assertEqual(report["right"]["endSeq"], 5)
        self.assertEqual(report["right"]["digest"], decoded(right)["digest"])

    def test_non_ascii_rule_uses_the_unescaped_encoder(self) -> None:
        # Every report value is a hex digest, an integer or a fixed ASCII
        # relation, so non-ASCII can never occur; the canonical encoder is
        # still the unescaped one, witnessed by no \\u escapes ever.
        left = synth_proof(1, 2, "A")
        right = synth_proof(2, 3, "B")
        self.assertNotIn(b"\\u", compare_proofs(left, right))
        self.assertNotIn(b"\\u", compare_proofs(left, left))

    def test_byte_stable_for_equal_inputs(self) -> None:
        left = synth_proof(1, 3, "A")
        right = synth_proof(2, 4, "A")
        self.assertEqual(
            compare_proofs(left, right), compare_proofs(bytes(left), bytes(right))
        )

    def test_inputs_are_not_modified(self) -> None:
        left = synth_proof(1, 3)
        right = synth_proof(1, 3)
        left_before, right_before = bytes(left), bytes(right)
        compare_proofs(left, right)
        self.assertEqual(left, left_before)
        self.assertEqual(right, right_before)

    def test_no_file_is_opened(self) -> None:
        with mock.patch("builtins.open") as patched:
            compare_proofs(synth_proof(1, 2), synth_proof(1, 2))
        patched.assert_not_called()


class CompareValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.good = synth_proof(1, 3)

    def test_non_bytes_arguments_raise_type_error(self) -> None:
        for bad in (self.good.decode("utf-8"), bytearray(self.good), None, 1, []):
            with self.assertRaises(TypeError):
                compare_proofs(bad, self.good)
            with self.assertRaises(TypeError):
                compare_proofs(self.good, bad)
            with self.assertRaises(TypeError):
                compare_proofs(bad, bad)

    def test_invalid_left_raises_invalid_proof_error(self) -> None:
        with self.assertRaises(InvalidProofError):
            compare_proofs(b"garbage\n", self.good)

    def test_invalid_right_raises_invalid_proof_error(self) -> None:
        with self.assertRaises(InvalidProofError):
            compare_proofs(self.good, b"garbage\n")

    def test_invalid_proof_rejected_even_when_disjoint(self) -> None:
        with self.assertRaises(InvalidProofError):
            compare_proofs(b"garbage\n", synth_proof(9, 10))


class DisjointTest(unittest.TestCase):
    def test_gap_between_ranges_is_disjoint_not_an_error(self) -> None:
        report = decoded(compare_proofs(synth_proof(1, 2), synth_proof(4, 5)))
        self.assertEqual(report["relation"], "disjoint")
        self.assertIsNone(report["overlap"])
        self.assertIsNone(report["common"])
        self.assertIsNone(report["conflictSeq"])

    def test_adjacent_but_not_shared_ranges_are_disjoint(self) -> None:
        report = decoded(compare_proofs(synth_proof(1, 3), synth_proof(4, 6)))
        self.assertEqual(report["relation"], "disjoint")
        self.assertIsNone(report["overlap"])
        # Both sides' ranges are retained.
        self.assertEqual(
            (report["left"]["startSeq"], report["left"]["endSeq"]), (1, 3)
        )
        self.assertEqual(
            (report["right"]["startSeq"], report["right"]["endSeq"]), (4, 6)
        )

    def test_reverse_order_ranges_still_disjoint(self) -> None:
        report = decoded(compare_proofs(synth_proof(8, 9), synth_proof(1, 2)))
        self.assertEqual(report["relation"], "disjoint")
        self.assertIsNone(report["overlap"])


class SameTest(unittest.TestCase):
    def test_identical_proof_bytes_are_same(self) -> None:
        proof = synth_proof(1, 4)
        report = decoded(compare_proofs(proof, bytes(proof)))
        self.assertEqual(report["relation"], "same")
        self.assertEqual(report["overlap"], [1, 4])
        self.assertIsNone(report["conflictSeq"])

    def test_same_common_is_last_entry_seq_and_after(self) -> None:
        proof = synth_proof(2, 5)
        report = decoded(compare_proofs(proof, bytes(proof)))
        self.assertEqual(
            report["common"], {"after": boundary("A", 5), "seq": 5}
        )
        self.assertEqual(tuple(report["common"].keys()), ("after", "seq"))

    def test_two_distinct_proofs_with_same_entries_are_same(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(1, 3, "A"), synth_proof(1, 3, "A"))
        )
        self.assertEqual(report["relation"], "same")
        self.assertEqual(report["overlap"], [1, 3])

    def test_real_ledger_full_proof_against_itself(self) -> None:
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "ledger.json")
        seed_ledger(path, n=4)
        proof = export_proof(path, 1)
        ledger = json.loads(open(path, "rb").read().decode("utf-8"))
        report = decoded(compare_proofs(proof, bytes(proof)))
        self.assertEqual(report["relation"], "same")
        self.assertEqual(
            report["common"],
            {"after": ledger["audit"][-1]["after"], "seq": 4},
        )


class PrefixTest(unittest.TestCase):
    def test_shorter_right_is_right_prefix(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(1, 4), synth_proof(1, 2))
        )
        self.assertEqual(report["relation"], "right-prefix")
        self.assertEqual(report["overlap"], [1, 2])
        self.assertEqual(
            report["common"], {"after": boundary("A", 2), "seq": 2}
        )
        self.assertIsNone(report["conflictSeq"])

    def test_shorter_left_is_left_prefix(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(1, 2), synth_proof(1, 4))
        )
        self.assertEqual(report["relation"], "left-prefix")
        self.assertEqual(report["overlap"], [1, 2])
        self.assertEqual(
            report["common"], {"after": boundary("A", 2), "seq": 2}
        )

    def test_swap_mirrors_prefix_direction(self) -> None:
        long = synth_proof(1, 4)
        short = synth_proof(1, 2)
        one = decoded(compare_proofs(long, short))
        two = decoded(compare_proofs(short, long))
        self.assertEqual(one["relation"], "right-prefix")
        self.assertEqual(two["relation"], "left-prefix")
        self.assertEqual(one["overlap"], two["overlap"])
        self.assertEqual(one["common"], two["common"])
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])

    def test_equal_lengths_are_not_prefix_even_with_same_start(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(1, 3), synth_proof(1, 3))
        )
        self.assertEqual(report["relation"], "same")

    def test_real_ledger_prefix(self) -> None:
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "ledger.json")
        seed_ledger(path, n=5)
        report = decoded(
            compare_proofs(export_proof(path, 1, 2), export_proof(path, 1))
        )
        self.assertEqual(report["relation"], "left-prefix")
        self.assertEqual(report["overlap"], [1, 2])
        self.assertEqual(report["common"]["seq"], 2)


class OverlapTest(unittest.TestCase):
    def test_partial_overlap_is_overlap(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(1, 3), synth_proof(3, 5))
        )
        self.assertEqual(report["relation"], "overlap")
        self.assertEqual(report["overlap"], [3, 3])
        self.assertEqual(
            report["common"], {"after": boundary("A", 3), "seq": 3}
        )
        self.assertIsNone(report["conflictSeq"])

    def test_interior_overlap_on_both_sides(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(2, 5), synth_proof(4, 7))
        )
        self.assertEqual(report["relation"], "overlap")
        self.assertEqual(report["overlap"], [4, 5])
        self.assertEqual(
            report["common"], {"after": boundary("A", 5), "seq": 5}
        )

    def test_overlap_swap_only_exchanges_sides(self) -> None:
        a = synth_proof(1, 3)
        b = synth_proof(3, 6)
        one = decoded(compare_proofs(a, b))
        two = decoded(compare_proofs(b, a))
        self.assertEqual(one["relation"], "overlap")
        self.assertEqual(two["relation"], "overlap")
        self.assertEqual(one["overlap"], two["overlap"])
        self.assertEqual(one["common"], two["common"])
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])

    def test_different_starts_same_end_is_not_prefix(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(1, 4), synth_proof(2, 4))
        )
        self.assertEqual(report["relation"], "overlap")
        self.assertEqual(report["overlap"], [2, 4])

    def test_real_ledger_partial_overlap(self) -> None:
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "ledger.json")
        seed_ledger(path, n=6)
        ledger = json.loads(open(path, "rb").read().decode("utf-8"))
        report = decoded(
            compare_proofs(export_proof(path, 1, 4), export_proof(path, 4, 6))
        )
        self.assertEqual(report["relation"], "overlap")
        self.assertEqual(report["overlap"], [4, 4])
        self.assertEqual(
            report["common"],
            {"after": ledger["audit"][3]["after"], "seq": 4},
        )


class ForkTest(unittest.TestCase):
    def test_fork_at_first_shared_seq_with_different_before_has_null_common(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(2, 4, "A"), synth_proof(2, 4, "B"))
        )
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 2)
        self.assertIsNone(report["common"])
        self.assertEqual(report["overlap"], [2, 4])

    def test_fork_at_seq_one_with_different_before_has_null_common(self) -> None:
        report = decoded(
            compare_proofs(synth_proof(1, 3, "A"), synth_proof(1, 3, "B"))
        )
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 1)
        self.assertIsNone(report["common"])

    def test_fork_at_first_shared_seq_with_same_before_uses_prior_boundary(self) -> None:
        # Same chain, but the left's entry at seq 1 carries a different id
        # while its before/after boundary is untouched.
        def change_id(seq, entry):
            if seq == 1:
                entry["id"] = "A-other"
            return entry

        forked = synth_proof(1, 4, "A", mutate=change_id)
        report = decoded(compare_proofs(synth_proof(1, 4, "A"), forked))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 1)
        # Prior boundary is state before seq 1: seq 0 with firstBefore.
        self.assertEqual(
            report["common"],
            {"after": boundary("A", 0), "seq": 0},
        )

    def test_interior_fork_with_matching_before_uses_previous_boundary(self) -> None:
        def change_id(seq, entry):
            if seq == 3:
                entry["id"] = "A-other"
            return entry

        forked = synth_proof(2, 5, "A", mutate=change_id)
        report = decoded(
            compare_proofs(synth_proof(2, 5, "A"), forked)
        )
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 3)
        self.assertEqual(
            report["common"],
            {"after": boundary("A", 2), "seq": 2},
        )

    def test_fork_after_equal_entries_uses_last_equal_entry(self) -> None:
        def change_id(seq, entry):
            if seq == 3:
                entry["id"] = "A-other"
            return entry

        forked = synth_proof(1, 5, "A", mutate=change_id)
        report = decoded(compare_proofs(synth_proof(1, 5, "A"), forked))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 3)
        self.assertEqual(
            report["common"],
            {"after": boundary("A", 2), "seq": 2},
        )

    def test_earliest_conflict_is_never_skipped(self) -> None:
        # Only seq 2 differs (an id-only change keeps the chain intact);
        # seq 3..5 are byte-identical again, yet the relation is a fork
        # at seq 2.
        def change_id(seq, entry):
            if seq == 2:
                entry["id"] = "A-other"
            return entry

        forked = synth_proof(1, 5, "A", mutate=change_id)
        report = decoded(compare_proofs(synth_proof(1, 5, "A"), forked))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 2)
        self.assertEqual(
            report["common"],
            {"after": boundary("A", 1), "seq": 1},
        )

    def test_compares_full_entries_not_boundary_digests(self) -> None:
        # An id-only fork has identical before/after on every entry: a
        # comparison that only looked at boundary digests would miss it.
        def change_source(seq, entry):
            if seq == 4:
                entry["source"] = "node-other"
            return entry

        forked = synth_proof(1, 5, "A", mutate=change_source)
        report = decoded(compare_proofs(synth_proof(1, 5, "A"), forked))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 4)

    def test_fork_swap_keeps_relation_conflict_and_common(self) -> None:
        a = synth_proof(1, 4, "A")
        b = synth_proof(1, 4, "B")
        one = decoded(compare_proofs(a, b))
        two = decoded(compare_proofs(b, a))
        for report in (one, two):
            self.assertEqual(report["relation"], "fork")
            self.assertEqual(report["conflictSeq"], 1)
            self.assertIsNone(report["common"])
            self.assertEqual(report["overlap"], [1, 4])
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])

    def test_fork_in_subrange_uses_first_shared_seq(self) -> None:
        # Overlap starts at seq 3; the id-only change there keeps its
        # before/after chain intact, so the prior boundary (seq 2) is
        # common even though seq 2 itself is outside the overlap.
        def change_id(seq, entry):
            if seq == 3:
                entry["id"] = "A-other"
            return entry

        right = synth_proof(3, 6, "A", mutate=change_id)
        report = decoded(compare_proofs(synth_proof(3, 6, "A"), right))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 3)
        self.assertEqual(
            report["common"],
            {"after": boundary("A", 2), "seq": 2},
        )


class ForkRealLedgerTest(unittest.TestCase):
    def test_divergent_ledgers_fork_at_first_different_entry(self) -> None:
        directory = tempfile.mkdtemp()
        left_path = os.path.join(directory, "left.json")
        right_path = os.path.join(directory, "right.json")
        seed_ledger(left_path, n=2)
        # Right shares the first commit, then commits a different request
        # at seq 2 (a new key written by a different node): the entry at
        # seq 2 differs while the entry at seq 1 is byte-identical.
        s1 = state({"node-a": 1}, {"k": record("v1", 1)})
        other = state(
            {"node-a": 1, "node-b": 1},
            {"k": record("v1", 1), "j": record("w1", 1, "node-b")},
        )
        R.apply_remote(right_path, make_request("r1", state(), s1))
        R.apply_remote(
            right_path, make_request("r-other", s1, other, source="node-b")
        )
        left_proof = export_proof(left_path, 1)
        right_proof = export_proof(right_path, 1)
        report = decoded(compare_proofs(left_proof, right_proof))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 2)
        self.assertEqual(report["common"]["seq"], 1)
        self.assertEqual(
            report["common"]["after"],
            json.loads(left_proof.decode("utf-8"))["entries"][0]["after"],
        )


if __name__ == "__main__":
    unittest.main()
