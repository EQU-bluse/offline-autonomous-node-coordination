"""Tests for offline comparison of audit-range proofs (compare_proofs)."""

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
COMMON_KEYS = ("after", "seq")


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def d(tag):
    """A distinct 64-lowercase-hex digest for a readable tag."""
    return hashlib.sha256(f"digest-{tag}".encode("utf-8")).hexdigest()


def make_entry(seq, before, after, rid=None, source="node-a", auth=None):
    entry = {
        "after": after,
        "before": before,
        "id": rid if rid is not None else f"r{seq}",
        "seq": seq,
        "source": source,
    }
    if auth is not None:
        entry["auth"] = auth
    return entry


def make_proof(start_seq, entries, first_before=None, last_after=None):
    """Build self-consistent, valid proof bytes from plain entry specs.

    ``entries`` are complete entry dicts; the chain between them is taken
    from their own before/after values.
    """
    if first_before is None:
        first_before = entries[0]["before"]
    if last_after is None:
        last_after = entries[-1]["after"]
    end_seq = start_seq + len(entries) - 1
    body = {
        "endSeq": end_seq,
        "entries": entries,
        "firstBefore": first_before,
        "lastAfter": last_after,
        "startSeq": start_seq,
        "version": 1,
    }
    data = dict(body)
    data["digest"] = hashlib.sha256(canonical(body)).hexdigest()
    return canonical(data) + b"\n"


def chain_entries(tag, start, end, auth_for=()):
    """Build chained complete entries for seqs ``start``..``end``.

    Digests come from one global per-tag chain -- boundary before seq 1 is
    ``d(tag + '0')`` and the after of seq ``i`` is ``d(tag + str(i))`` -- so
    two proofs cut from different ranges of the same tag carry byte
    identical entry objects at every shared seq.
    """
    entries = []
    for seq in range(start, end + 1):
        before = d(f"{tag}0") if seq == 1 else d(f"{tag}{seq - 1}")
        after = d(f"{tag}{seq}")
        auth = {"keyVersion": 1, "node": "node-a"} if seq in auth_for else None
        entries.append(make_entry(seq, before, after, auth=auth))
    return entries


def decoded_report(raw):
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    return json.loads(raw)


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, n, writer="node-a"):
    return [value, False, {writer: n}, writer]


def make_request(rid, base, remote, source="node-a"):
    return {"id": rid, "source": source, "base": base, "remote": remote}


class CompareEncodingTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        cur = state()
        for i in range(1, 5):
            nxt = state({"node-a": i}, {"k": record(f"v{i}", i)})
            result = R.apply_remote(self.path, make_request(f"r{i}", cur, nxt))
            assert result["status"] == "applied"
            cur = nxt
        self.proof = export_proof(self.path, 1)

    def test_report_shape_and_key_order(self):
        report = decoded_report(compare_proofs(self.proof, self.proof))
        self.assertEqual(tuple(report.keys()), REPORT_KEYS)
        self.assertEqual(report["version"], 1)
        self.assertEqual(tuple(report["left"].keys()), SIDE_KEYS)
        self.assertEqual(tuple(report["right"].keys()), SIDE_KEYS)

    def test_compact_canonical_bytes_with_one_lf(self):
        raw = compare_proofs(self.proof, self.proof)
        report = decoded_report(raw)
        self.assertEqual(raw, canonical(report) + b"\n")
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b", ", raw)

    def test_side_carries_digest_and_range(self):
        other = export_proof(self.path, 2, 3)
        report = decoded_report(compare_proofs(self.proof, other))
        self.assertEqual(
            report["left"],
            {"digest": json.loads(self.proof)["digest"],
             "startSeq": 1, "endSeq": 4},
        )
        self.assertEqual(
            report["right"],
            {"digest": json.loads(other)["digest"],
             "startSeq": 2, "endSeq": 3},
        )

    def test_identical_inputs_are_byte_stable(self):
        first = compare_proofs(self.proof, self.proof)
        second = compare_proofs(self.proof, self.proof)
        self.assertEqual(first, second)


class CompareRelationTest(unittest.TestCase):
    def proof(self, start, end, **kwargs):
        # One global chain a0 <- a1 <- ... shared by every proof.
        entries = chain_entries("a", start, end)
        return make_proof(start, entries, **kwargs)

    def test_same_when_ranges_and_entries_identical(self):
        left = self.proof(2, 4)
        right = self.proof(2, 4)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "same")
        self.assertEqual(report["overlap"], [2, 4])
        self.assertEqual(report["conflictSeq"], None)
        self.assertEqual(
            report["common"], {"seq": 4, "after": d("a4")}
        )
        self.assertEqual(tuple(report["common"].keys()), COMMON_KEYS)

    def test_single_entry_same(self):
        report = decoded_report(compare_proofs(self.proof(3, 3), self.proof(3, 3)))
        self.assertEqual(report["relation"], "same")
        self.assertEqual(report["overlap"], [3, 3])
        self.assertEqual(report["common"], {"seq": 3, "after": d("a3")})

    def test_left_prefix(self):
        left = self.proof(1, 2)
        right = self.proof(1, 4)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "left-prefix")
        self.assertEqual(report["overlap"], [1, 2])
        self.assertEqual(report["conflictSeq"], None)
        self.assertEqual(report["common"], {"seq": 2, "after": d("a2")})

    def test_right_prefix(self):
        left = self.proof(1, 4)
        right = self.proof(1, 2)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "right-prefix")
        self.assertEqual(report["overlap"], [1, 2])
        self.assertEqual(report["common"], {"seq": 2, "after": d("a2")})

    def test_overlap_with_different_starts(self):
        left = self.proof(1, 3)
        right = self.proof(2, 4)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "overlap")
        self.assertEqual(report["overlap"], [2, 3])
        self.assertEqual(report["conflictSeq"], None)
        self.assertEqual(report["common"], {"seq": 3, "after": d("a3")})

    def test_overlap_when_one_range_contains_the_other(self):
        left = self.proof(1, 5)
        right = self.proof(2, 3)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "overlap")
        self.assertEqual(report["overlap"], [2, 3])
        self.assertEqual(report["common"], {"seq": 3, "after": d("a3")})

    def test_distinct_proof_digests_with_same_entries_overlap_not_fork(self):
        # The proof digests differ (different ranges) but every shared
        # complete entry is identical: that is overlap, not fork.
        left = self.proof(1, 3)
        right = self.proof(2, 3)
        self.assertNotEqual(
            json.loads(left)["digest"], json.loads(right)["digest"]
        )
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "overlap")
        self.assertEqual(report["conflictSeq"], None)

    def test_disjoint_adjacent_ranges(self):
        left = self.proof(1, 2)
        right = self.proof(3, 4)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "disjoint")
        self.assertIsNone(report["overlap"])
        self.assertIsNone(report["common"])
        self.assertIsNone(report["conflictSeq"])
        self.assertEqual(report["left"]["startSeq"], 1)
        self.assertEqual(report["left"]["endSeq"], 2)
        self.assertEqual(report["right"]["startSeq"], 3)
        self.assertEqual(report["right"]["endSeq"], 4)

    def test_disjoint_with_left_range_higher(self):
        left = self.proof(5, 6)
        right = self.proof(1, 2)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "disjoint")
        self.assertIsNone(report["overlap"])


class CompareForkTest(unittest.TestCase):
    def test_fork_after_shared_prefix_uses_last_agreeing_entry(self):
        before = d("a0")
        a1 = d("a1")
        a2 = d("a2")
        left_entries = [
            make_entry(1, before, a1),
            make_entry(2, a1, a2),
            make_entry(3, a2, d("left-a3")),
        ]
        right_entries = [
            make_entry(1, before, a1),
            make_entry(2, a1, a2),
            make_entry(3, a2, d("right-a3")),
        ]
        left = make_proof(1, left_entries)
        right = make_proof(1, right_entries)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 3)
        self.assertEqual(report["overlap"], [1, 3])
        self.assertEqual(report["common"], {"seq": 2, "after": a2})

    def test_earliest_conflict_is_never_skipped(self):
        before = d("b0")
        a1 = d("b1")
        left_entries = [
            make_entry(1, before, a1),
            make_entry(2, a1, d("L2")),
            make_entry(3, d("L2"), d("L3")),
        ]
        right_entries = [
            make_entry(1, before, a1),
            make_entry(2, a1, d("R2")),
            make_entry(3, d("R2"), d("R3")),
        ]
        report = decoded_report(
            compare_proofs(make_proof(1, left_entries),
                           make_proof(1, right_entries))
        )
        self.assertEqual(report["relation"], "fork")
        # Seq 2 differs first even though seq 3 differs as well.
        self.assertEqual(report["conflictSeq"], 2)
        self.assertEqual(report["common"], {"seq": 1, "after": a1})

    def test_first_entry_conflict_with_shared_before_uses_boundary(self):
        before = d("c1")
        left = make_proof(2, [make_entry(2, before, d("L2"))])
        right = make_proof(2, [make_entry(2, before, d("R2"))])
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 2)
        self.assertEqual(report["overlap"], [2, 2])
        self.assertEqual(report["common"], {"seq": 1, "after": before})

    def test_first_shared_entry_conflict_with_agreed_before_mid_overlap(self):
        # Overlap starts at seq 3; both chains happen to reach the same
        # after at seq 2, so the boundary before the conflict is common.
        common_a2 = d("shared-a2")
        left = make_proof(1, [
            make_entry(1, d("L0"), d("L1")),
            make_entry(2, d("L1"), common_a2),
            make_entry(3, common_a2, d("L3")),
        ])
        right = make_proof(3, [
            make_entry(3, common_a2, d("R3")),
            make_entry(4, d("R3"), d("R4")),
        ])
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 3)
        self.assertEqual(report["overlap"], [3, 3])
        self.assertEqual(report["common"], {"seq": 2, "after": common_a2})

    def test_first_conflict_with_different_before_has_null_common(self):
        left = make_proof(1, [
            make_entry(1, d("L0"), d("L1")),
            make_entry(2, d("L1"), d("L2")),
            make_entry(3, d("L2"), d("L3")),
        ])
        right = make_proof(3, [
            make_entry(3, d("R2"), d("R3")),
        ])
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 3)
        self.assertIsNone(report["common"])

    def test_full_entry_compared_not_just_boundary_digests(self):
        # Same before AND same after at seq 2, but a different id: only a
        # complete-entry comparison can detect this fork.
        before = d("e0")
        a1 = d("e1")
        shared_after = d("e2-same")
        left = make_proof(1, [
            make_entry(1, before, a1),
            make_entry(2, a1, shared_after, rid="r2"),
        ])
        right = make_proof(1, [
            make_entry(1, before, a1),
            make_entry(2, a1, shared_after, rid="different-id"),
        ])
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 2)
        self.assertEqual(report["common"], {"seq": 1, "after": a1})

    def test_non_fork_relations_have_null_conflict_seq(self):
        p = make_proof(1, chain_entries("f", 1, 3))
        report = decoded_report(compare_proofs(p, p))
        self.assertEqual(report["relation"], "same")
        self.assertIsNone(report["conflictSeq"])


class CompareSwapTest(unittest.TestCase):
    def test_swap_only_exchanges_sides_for_overlap(self):
        left = make_proof(1, chain_entries("g", 1, 3))
        right = make_proof(2, chain_entries("g", 2, 4))
        forward = decoded_report(compare_proofs(left, right))
        backward = decoded_report(compare_proofs(right, left))
        self.assertEqual(forward["relation"], "overlap")
        self.assertEqual(backward["relation"], "overlap")
        self.assertEqual(forward["left"], backward["right"])
        self.assertEqual(forward["right"], backward["left"])
        self.assertEqual(forward["overlap"], backward["overlap"])
        self.assertEqual(forward["common"], backward["common"])
        self.assertEqual(forward["conflictSeq"], backward["conflictSeq"])

    def test_swap_flips_prefix_direction(self):
        short = make_proof(1, chain_entries("h", 1, 2))
        long = make_proof(1, chain_entries("h", 1, 4))
        forward = decoded_report(compare_proofs(short, long))
        backward = decoded_report(compare_proofs(long, short))
        self.assertEqual(forward["relation"], "left-prefix")
        self.assertEqual(backward["relation"], "right-prefix")
        self.assertEqual(forward["left"], backward["right"])
        self.assertEqual(forward["right"], backward["left"])
        self.assertEqual(forward["common"], backward["common"])

    def test_swap_keeps_fork_symmetric(self):
        before = d("i0")
        a1 = d("i1")
        left = make_proof(1, [
            make_entry(1, before, a1),
            make_entry(2, a1, d("iL2")),
        ])
        right = make_proof(1, [
            make_entry(1, before, a1),
            make_entry(2, a1, d("iR2")),
        ])
        forward = decoded_report(compare_proofs(left, right))
        backward = decoded_report(compare_proofs(right, left))
        self.assertEqual(forward["relation"], "fork")
        self.assertEqual(forward["conflictSeq"], 2)
        self.assertEqual(backward["conflictSeq"], 2)
        self.assertEqual(forward["common"], backward["common"])
        self.assertEqual(forward["left"], backward["right"])

    def test_swap_disjoint(self):
        low = make_proof(1, chain_entries("j", 1, 2))
        high = make_proof(3, chain_entries("j", 3, 4))
        forward = decoded_report(compare_proofs(low, high))
        backward = decoded_report(compare_proofs(high, low))
        self.assertEqual(forward["relation"], "disjoint")
        self.assertEqual(backward["relation"], "disjoint")
        self.assertEqual(forward["left"], backward["right"])


class CompareRealLedgerForkTest(unittest.TestCase):
    """Two independently built ledgers that genuinely diverge at seq 2."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.left_path = os.path.join(self.dir, "left.json")
        self.right_path = os.path.join(self.dir, "right.json")
        s1 = state({"node-a": 1}, {"k": record("v1", 1)})
        R.apply_remote(self.left_path, make_request("r1", state(), s1))
        R.apply_remote(self.right_path, make_request("r1", state(), s1))
        left_s2 = state({"node-a": 2}, {"k": record("v2-left", 2)})
        right_s2 = state({"node-a": 2}, {"k": record("v2-right", 2)})
        R.apply_remote(self.left_path, make_request("r2-left", s1, left_s2))
        R.apply_remote(self.right_path, make_request("r2-right", s1, right_s2))

    def test_exported_proofs_report_fork_with_real_state_digests(self):
        left = export_proof(self.left_path, 1)
        right = export_proof(self.right_path, 1)
        report = decoded_report(compare_proofs(left, right))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 2)
        with open(self.left_path, "rb") as handle:
            ledger = json.loads(handle.read())
        self.assertEqual(
            report["common"],
            {"seq": 1, "after": ledger["audit"][0]["after"]},
        )


class CompareValidationTest(unittest.TestCase):
    def setUp(self):
        before = d("k0")
        self.good = make_proof(1, [make_entry(1, before, d("k1"))])

    def test_non_bytes_left_or_right_raises_type_error(self):
        for bad in (self.good.decode("utf-8"), bytearray(self.good), None, 1, []):
            with self.assertRaises(TypeError):
                compare_proofs(bad, self.good)
            with self.assertRaises(TypeError):
                compare_proofs(self.good, bad)

    def test_invalid_left_proof_raises_invalid_proof_error(self):
        with self.assertRaises(InvalidProofError):
            compare_proofs(b"garbage\n", self.good)

    def test_invalid_right_proof_raises_invalid_proof_error(self):
        with self.assertRaises(InvalidProofError):
            compare_proofs(self.good, b"garbage\n")

    def test_tampered_proof_rejected(self):
        tampered = bytearray(self.good)
        position = tampered.find(b'"id":"r1"')
        self.assertGreater(position, 0)
        tampered[position + 7:position + 9] = b"xx"
        with self.assertRaises(InvalidProofError):
            compare_proofs(bytes(tampered), self.good)

    def test_comparison_touches_no_files(self):
        with mock.patch("builtins.open") as patched:
            report = compare_proofs(self.good, self.good)
        patched.assert_not_called()
        self.assertEqual(decoded_report(report)["relation"], "same")

    def test_inputs_are_not_modified(self):
        other_before = d("k0")
        other = make_proof(1, [
            make_entry(1, other_before, d("other-after"))
        ])
        left_before = bytes(self.good)
        right_before = bytes(other)
        compare_proofs(self.good, other)
        self.assertEqual(self.good, left_before)
        self.assertEqual(other, right_before)


if __name__ == "__main__":
    unittest.main()
