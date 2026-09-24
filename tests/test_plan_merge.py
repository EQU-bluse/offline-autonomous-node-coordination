"""Tests for read-only merge plans (plan_merge)."""

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
    plan_merge,
)

PLAN_KEYS = (
    "common",
    "left",
    "policy",
    "relation",
    "right",
    "steps",
    "unresolved",
    "version",
)
SIDE_KEYS = ("digest", "endSeq", "startSeq")
STEP_KEYS = ("action", "entry", "reason", "side")
REF_KEYS = ("seq", "side")

REASONS = ("extension", "manual", "rejected", "selected")
ACTIONS = ("accept", "manual", "reject")


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def decoded(raw):
    return json.loads(raw)


def boundary(tag, seq):
    import hashlib

    return hashlib.sha256(f"{tag}:{seq}".encode("utf-8")).hexdigest()


def synth_proof(start, end, tag="A", mutate=None, signed=()):
    """Build a self-consistent valid proof for a synthetic chain.

    Entry at seq s chains boundary(tag, s-1) -> boundary(tag, s).  Two
    proofs with the same tag agree entry by entry at shared seqs; a
    different tag forks at every entry.  Seqs in ``signed`` carry an
    auth binding.
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
        if seq in signed:
            entry["auth"] = {"keyVersion": 1, "node": f"node-{tag}"}
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
    import hashlib

    data["digest"] = hashlib.sha256(canonical(data)).hexdigest()
    return canonical(data) + b"\n"


def fork_id_at(conflict_seq, new_id="A-other"):
    def mutate(seq, entry):
        if seq == conflict_seq:
            entry["id"] = new_id
        return entry

    return mutate


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


def step_triples(plan):
    return [
        (s["side"], s["entry"]["seq"], s["action"], s["reason"])
        for s in plan["steps"]
    ]


class PlanShapeTest(unittest.TestCase):
    def test_canonical_compact_json_with_one_lf(self) -> None:
        raw = plan_merge(synth_proof(1, 2), synth_proof(1, 4), "manual")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(raw, canonical(decoded(raw)) + b"\n")
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b"\\u", raw)

    def test_top_level_keys_fixed_and_sorted(self) -> None:
        raw = plan_merge(synth_proof(1, 2), synth_proof(1, 4), "left")
        self.assertEqual(tuple(decoded(raw).keys()), PLAN_KEYS)

    def test_version_is_integer_1(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 2), synth_proof(1, 4), "left"))
        self.assertEqual(plan["version"], 1)
        self.assertIsInstance(plan["version"], int)
        self.assertNotIsInstance(plan["version"], bool)

    def test_policy_is_echoed(self) -> None:
        for policy in ("left", "right", "manual"):
            plan = decoded(plan_merge(synth_proof(1, 2), synth_proof(1, 4), policy))
            self.assertEqual(plan["policy"], policy)

    def test_sides_match_compare_report(self) -> None:
        left = synth_proof(1, 3)
        right = synth_proof(3, 5)
        plan = decoded(plan_merge(left, right, "manual"))
        report = decoded(compare_proofs(left, right))
        self.assertEqual(plan["left"], report["left"])
        self.assertEqual(plan["right"], report["right"])
        self.assertEqual(tuple(plan["left"].keys()), SIDE_KEYS)
        self.assertEqual(tuple(plan["right"].keys()), SIDE_KEYS)

    def test_common_and_relation_match_compare_report(self) -> None:
        def mut(seq, entry):
            if seq == 3:
                entry["id"] = "A-other"
            return entry

        for lrange, rrange, mutate in (
            ((1, 4), (1, 4), None),
            ((1, 2), (1, 5), None),
            ((1, 3), (3, 6), None),
            ((1, 5), (1, 5), mut),
        ):
            with self.subTest(lrange=lrange, rrange=rrange):
                left = synth_proof(*lrange)
                right = synth_proof(*rrange, mutate=mutate)
                plan = decoded(plan_merge(left, right, "manual"))
                report = decoded(compare_proofs(left, right))
                self.assertEqual(plan["relation"], report["relation"])
                self.assertEqual(plan["common"], report["common"])

    def test_step_keys_sorted_and_reason_values_fixed(self) -> None:
        plan = decoded(
            plan_merge(
                synth_proof(1, 4),
                synth_proof(1, 4, mutate=fork_id_at(3)),
                "manual",
            )
        )
        self.assertTrue(plan["steps"])
        for step in plan["steps"]:
            self.assertEqual(tuple(step.keys()), STEP_KEYS)
            self.assertIn(step["action"], ACTIONS)
            self.assertIn(step["reason"], REASONS)
            self.assertIn(step["side"], ("left", "right"))

    def test_unresolved_reference_keys_sorted(self) -> None:
        plan = decoded(
            plan_merge(
                synth_proof(1, 4),
                synth_proof(1, 4, mutate=fork_id_at(2)),
                "manual",
            )
        )
        self.assertTrue(plan["unresolved"])
        for ref in plan["unresolved"]:
            self.assertEqual(tuple(ref.keys()), REF_KEYS)
            self.assertNotIn("entry", ref)

    def test_byte_stable_for_equal_inputs(self) -> None:
        left = synth_proof(1, 3)
        right = synth_proof(2, 5)
        self.assertEqual(
            plan_merge(left, right, "manual"),
            plan_merge(bytes(left), bytes(right), "manual"),
        )


class PlanValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.good = synth_proof(1, 3)

    def test_non_bytes_arguments_raise_type_error(self) -> None:
        for bad in (self.good.decode("utf-8"), bytearray(self.good), None, 1, []):
            with self.assertRaises(TypeError):
                plan_merge(bad, self.good, "left")
            with self.assertRaises(TypeError):
                plan_merge(self.good, bad, "left")

    def test_non_str_policy_raises_type_error(self) -> None:
        for bad in (1, True, None, b"left", ("left",), ["left"]):
            with self.assertRaises(TypeError):
                plan_merge(self.good, self.good, bad)

    def test_type_error_not_masked_by_bad_proofs(self) -> None:
        garbage = b"garbage\n"
        # A bad proof must never shadow a non-bytes argument...
        with self.assertRaises(TypeError):
            plan_merge("nope", garbage, "left")
        with self.assertRaises(TypeError):
            plan_merge(garbage, 7, "left")
        # ...nor a non-str policy, even when both proofs are garbage.
        with self.assertRaises(TypeError):
            plan_merge(garbage, garbage, 9)
        with self.assertRaises(TypeError):
            plan_merge(self.good, garbage, True)

    def test_invalid_proof_raises_before_policy_is_judged(self) -> None:
        # The policy value is bad too, but an invalid proof is the
        # failure that surfaces first (InvalidProofError), exactly as for
        # compare_proofs.
        with self.assertRaises(InvalidProofError):
            plan_merge(b"garbage\n", self.good, "nonsense")
        with self.assertRaises(InvalidProofError):
            plan_merge(self.good, b"garbage\n", "nonsense")

    def test_unknown_policy_string_raises_value_error(self) -> None:
        for bad in ("", "LEFT", " left", "left\n", "both", "auto"):
            with self.assertRaises(ValueError):
                plan_merge(self.good, self.good, bad)

    def test_value_error_is_not_invalid_proof_error_for_bad_policy(self) -> None:
        with self.assertRaises(ValueError) as caught:
            plan_merge(self.good, self.good, "nope")
        self.assertNotIsInstance(caught.exception, InvalidProofError)

    def test_disjoint_ranges_raise_value_error(self) -> None:
        for policy in ("left", "right", "manual"):
            with self.subTest(policy=policy):
                with self.assertRaises(ValueError):
                    plan_merge(synth_proof(1, 2), synth_proof(4, 5), policy)
                with self.assertRaises(ValueError):
                    plan_merge(synth_proof(8, 9), synth_proof(1, 2), policy)

    def test_unanchored_fork_raises_value_error(self) -> None:
        # Different tags from the first shared seq with differing before
        # digests -> common is null; no boundary to extend from.
        for policy in ("left", "right", "manual"):
            with self.subTest(policy=policy):
                with self.assertRaises(ValueError):
                    plan_merge(
                        synth_proof(1, 4, "A"), synth_proof(1, 4, "B"), policy
                    )


class SameAndPrefixTest(unittest.TestCase):
    def test_same_history_has_no_steps(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 4), synth_proof(1, 4), "left"))
        self.assertEqual(plan["relation"], "same")
        self.assertEqual(plan["steps"], [])
        self.assertEqual(plan["unresolved"], [])

    def test_same_does_not_depend_on_policy(self) -> None:
        left = right = synth_proof(2, 5)
        plans = {
            p: decoded(plan_merge(left, right, p)) for p in ("left", "right", "manual")
        }
        for plan in plans.values():
            self.assertEqual(plan["steps"], [])
            self.assertEqual(plan["unresolved"], [])

    def test_longer_right_extension_is_accepted(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 2), synth_proof(1, 5), "manual"))
        self.assertEqual(plan["relation"], "left-prefix")
        self.assertEqual(
            step_triples(plan),
            [
                ("right", 3, "accept", "extension"),
                ("right", 4, "accept", "extension"),
                ("right", 5, "accept", "extension"),
            ],
        )
        self.assertEqual(plan["unresolved"], [])
        # The boundary record (seq 2) is not listed again.
        seqs = {s["entry"]["seq"] for s in plan["steps"]}
        self.assertNotIn(2, seqs)

    def test_longer_left_extension_is_accepted(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 5), synth_proof(1, 2), "manual"))
        self.assertEqual(plan["relation"], "right-prefix")
        self.assertEqual(
            step_triples(plan),
            [
                ("left", 3, "accept", "extension"),
                ("left", 4, "accept", "extension"),
                ("left", 5, "accept", "extension"),
            ],
        )

    def test_partial_overlap_extends_the_lagging_side(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 3), synth_proof(3, 6), "manual"))
        self.assertEqual(plan["relation"], "overlap")
        self.assertEqual(plan["common"]["seq"], 3)
        self.assertEqual(
            step_triples(plan),
            [
                ("right", 4, "accept", "extension"),
                ("right", 5, "accept", "extension"),
                ("right", 6, "accept", "extension"),
            ],
        )

    def test_extensions_identical_under_every_policy(self) -> None:
        left = synth_proof(2, 4)
        right = synth_proof(4, 7)
        # Only the echoed policy field differs; the planned steps are
        # identical because an un-forked history only ever extends.
        plans = {
            p: decoded(plan_merge(left, right, p))
            for p in ("left", "right", "manual")
        }
        for plan in plans.values():
            self.assertEqual(plan["relation"], "overlap")
        self.assertEqual(plans["left"]["steps"], plans["right"]["steps"])
        self.assertEqual(plans["left"]["steps"], plans["manual"]["steps"])
        self.assertEqual(
            plans["left"]["unresolved"], plans["manual"]["unresolved"]
        )


class ForkPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        # Shared prefix seqs 1-2, fork from seq 3.
        self.left = synth_proof(1, 5, "A")
        self.right = synth_proof(1, 5, "A", mutate=fork_id_at(3))

    def test_common_is_last_equal_boundary(self) -> None:
        plan = decoded(plan_merge(self.left, self.right, "left"))
        self.assertEqual(plan["relation"], "fork")
        self.assertEqual(plan["common"], {"after": boundary("A", 2), "seq": 2})

    def test_policy_left_selects_left_rejects_right(self) -> None:
        plan = decoded(plan_merge(self.left, self.right, "left"))
        self.assertEqual(
            step_triples(plan),
            [
                ("left", 3, "accept", "selected"),
                ("right", 3, "reject", "rejected"),
                ("left", 4, "accept", "selected"),
                ("right", 4, "reject", "rejected"),
                ("left", 5, "accept", "selected"),
                ("right", 5, "reject", "rejected"),
            ],
        )
        self.assertEqual(plan["unresolved"], [])

    def test_policy_right_is_symmetric(self) -> None:
        plan = decoded(plan_merge(self.left, self.right, "right"))
        self.assertEqual(
            step_triples(plan),
            [
                ("left", 3, "reject", "rejected"),
                ("right", 3, "accept", "selected"),
                ("left", 4, "reject", "rejected"),
                ("right", 4, "accept", "selected"),
                ("left", 5, "reject", "rejected"),
                ("right", 5, "accept", "selected"),
            ],
        )
        self.assertEqual(plan["unresolved"], [])

    def test_policy_manual_marks_both_tails_unresolved(self) -> None:
        plan = decoded(plan_merge(self.left, self.right, "manual"))
        triples = step_triples(plan)
        self.assertEqual({t[2] for t in triples}, {"manual"})
        self.assertEqual({t[3] for t in triples}, {"manual"})
        # Every candidate entry on both sides is present once.
        self.assertEqual(len(triples), 6)
        refs = [(r["seq"], r["side"]) for r in plan["unresolved"]]
        self.assertEqual(
            refs,
            [(s["entry"]["seq"], s["side"]) for s in plan["steps"]],
        )
        self.assertEqual(len(refs), len(set(refs)))

    def test_steps_sort_seq_then_left_first(self) -> None:
        plan = decoded(plan_merge(self.left, self.right, "manual"))
        order = [(s["entry"]["seq"], s["side"]) for s in plan["steps"]]
        self.assertEqual(
            order,
            [
                (3, "left"), (3, "right"),
                (4, "left"), (4, "right"),
                (5, "left"), (5, "right"),
            ],
        )

    def test_unresolved_follows_step_order_without_entries(self) -> None:
        plan = decoded(plan_merge(self.left, self.right, "manual"))
        for ref, step in zip(plan["unresolved"], plan["steps"]):
            self.assertEqual(ref, {"seq": step["entry"]["seq"], "side": step["side"]})
            self.assertEqual(set(ref.keys()), {"seq", "side"})

    def test_only_tail_after_boundary_is_listed(self) -> None:
        plan = decoded(plan_merge(self.left, self.right, "left"))
        seqs = [s["entry"]["seq"] for s in plan["steps"]]
        self.assertEqual(min(seqs), 3)
        self.assertNotIn(1, seqs)
        self.assertNotIn(2, seqs)

    def test_fork_at_first_entry_with_common_seq_zero(self) -> None:
        # Both chains start from the same before digest, fork at seq 1:
        # the common boundary is seq 0 and every entry is a candidate.
        right = synth_proof(1, 3, "A", mutate=fork_id_at(1))
        plan = decoded(plan_merge(synth_proof(1, 3, "A"), right, "manual"))
        self.assertEqual(plan["common"], {"after": boundary("A", 0), "seq": 0})
        self.assertEqual(len(plan["steps"]), 6)
        self.assertEqual(min(s["entry"]["seq"] for s in plan["steps"]), 1)

    def test_fork_in_subranges_uses_shared_prefix_outside_overlap(self) -> None:
        # Overlap starts at seq 3; the id-only fork there chains from the
        # shared boundary seq 2 even though seq 2 is not in either range.
        left = synth_proof(3, 5, "A")
        right = synth_proof(3, 5, "A", mutate=fork_id_at(3))
        plan = decoded(plan_merge(left, right, "left"))
        self.assertEqual(plan["common"], {"after": boundary("A", 2), "seq": 2})
        self.assertEqual(
            step_triples(plan),
            [
                ("left", 3, "accept", "selected"),
                ("right", 3, "reject", "rejected"),
                ("left", 4, "accept", "selected"),
                ("right", 4, "reject", "rejected"),
                ("left", 5, "accept", "selected"),
                ("right", 5, "reject", "rejected"),
            ],
        )


class EntryFidelityTest(unittest.TestCase):
    def test_entries_are_embedded_verbatim(self) -> None:
        left = synth_proof(1, 3, "A", signed=(2, 3))
        right = synth_proof(1, 5, "A", signed=(2, 3, 4, 5))
        plan = decoded(plan_merge(left, right, "manual"))
        embedded = {s["entry"]["seq"]: s["entry"] for s in plan["steps"]}
        original = {e["seq"]: e for e in decoded(right)["entries"]}
        for seq in (4, 5):
            self.assertEqual(embedded[seq], original[seq])
            # The auth binding is preserved, never rewritten or dropped.
            self.assertEqual(
                embedded[seq]["auth"], {"keyVersion": 1, "node": "node-A"}
            )

    def test_selected_entry_matches_proof_bytes_entry(self) -> None:
        left = synth_proof(1, 4, "A", signed=(4,))
        right = synth_proof(1, 4, "A", mutate=fork_id_at(3), signed=(3, 4))
        plan = decoded(plan_merge(left, right, "left"))
        chosen = {s["entry"]["seq"]: s["entry"] for s in plan["steps"] if s["side"] == "left"}
        source = {e["seq"]: e for e in decoded(left)["entries"]}
        for seq in (3, 4):
            self.assertEqual(chosen[seq], source[seq])


class SwapSymmetryTest(unittest.TestCase):
    def test_manual_swap_mirrors_sides_and_refs(self) -> None:
        left = synth_proof(1, 4, "A")
        right = synth_proof(1, 4, "A", mutate=fork_id_at(3))
        one = decoded(plan_merge(left, right, "manual"))
        two = decoded(plan_merge(right, left, "manual"))
        self.assertEqual(one["relation"], two["relation"])
        self.assertEqual(one["common"], two["common"])
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])

        def mirror(steps):
            mirrored = [
                {
                    **s,
                    "side": "right" if s["side"] == "left" else "left",
                }
                for s in steps
            ]
            mirrored.sort(
                key=lambda s: (
                    s["entry"]["seq"],
                    0 if s["side"] == "left" else 1,
                )
            )
            return mirrored

        self.assertEqual(one["steps"], mirror(two["steps"]))
        flipped = [
            (r["seq"], "right" if r["side"] == "left" else "left")
            for r in two["unresolved"]
        ]
        flipped.sort(key=lambda q: (q[0], 0 if q[1] == "left" else 1))
        self.assertEqual(
            [(r["seq"], r["side"]) for r in one["unresolved"]], flipped
        )

    def test_left_policy_equals_swapped_right_policy(self) -> None:
        left = synth_proof(1, 4, "A")
        right = synth_proof(1, 4, "A", mutate=fork_id_at(2))
        one = decoded(plan_merge(left, right, "left"))
        two = decoded(plan_merge(right, left, "right"))
        self.assertEqual(one["relation"], two["relation"])
        self.assertEqual(one["common"], two["common"])
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])

        def flip(side):
            return "right" if side == "left" else "left"

        # After the swap plus mirrored policy each (seq, side) keeps the
        # same decision: selected stays selected, rejected stays rejected.
        one_by = {(s["entry"]["seq"], s["side"]): s["reason"] for s in one["steps"]}
        for step in two["steps"]:
            key = (step["entry"]["seq"], flip(step["side"]))
            self.assertEqual(step["reason"], one_by[key])

    def test_plan_bytes_are_mirrored_not_equal(self) -> None:
        # Mirroring changes side labels, so bytes differ, but decoding the
        # swapped plan and flipping sides reconstructs the original shape.
        left = synth_proof(1, 4, "A")
        right = synth_proof(1, 4, "A", mutate=fork_id_at(3))
        one = decoded(plan_merge(left, right, "left"))
        two = decoded(plan_merge(right, left, "right"))
        self.assertEqual(
            sorted((s["entry"]["seq"], s["side"]) for s in one["steps"]),
            sorted(
                (s["entry"]["seq"], "right" if s["side"] == "left" else "left")
                for s in two["steps"]
            ),
        )


class PurityTest(unittest.TestCase):
    def test_inputs_are_not_modified(self) -> None:
        left = synth_proof(1, 3)
        right = synth_proof(1, 3, mutate=fork_id_at(2))
        lb, rb = bytes(left), bytes(right)
        plan_merge(left, right, "manual")
        self.assertEqual(left, lb)
        self.assertEqual(right, rb)

    def test_no_file_is_opened(self) -> None:
        with mock.patch("builtins.open") as patched:
            plan_merge(
                synth_proof(1, 3),
                synth_proof(1, 3, mutate=fork_id_at(2)),
                "left",
            )
        patched.assert_not_called()


class RealLedgerPlanTest(unittest.TestCase):
    def test_plan_from_divergent_real_ledgers(self) -> None:
        directory = tempfile.mkdtemp()
        left_path = os.path.join(directory, "left.json")
        right_path = os.path.join(directory, "right.json")
        seed_ledger(left_path, n=3)

        # The right ledger shares seq 1 (r1), then follows its own
        # coherent node-b chain through seq 2 and seq 3.
        s0 = state()
        s1 = state({"node-a": 1}, {"k": record("v1", 1)})
        other = state(
            {"node-a": 1, "node-b": 1},
            {"k": record("v1", 1), "j": record("w1", 1, "node-b")},
        )
        other2 = state(
            {"node-a": 1, "node-b": 2},
            {"k": record("v1", 1), "j": record("w2", 2, "node-b")},
        )
        self.assertEqual(
            R.apply_remote(right_path, make_request("r1", s0, s1))["status"],
            "applied",
        )
        self.assertEqual(
            R.apply_remote(
                right_path, make_request("r-other", s1, other, source="node-b")
            )["status"],
            "applied",
        )
        self.assertEqual(
            R.apply_remote(
                right_path,
                make_request("r-other-2", other, other2, source="node-b"),
            )["status"],
            "applied",
        )
        left_proof = export_proof(left_path, 1)
        right_proof = export_proof(right_path, 1)

        report = decoded(compare_proofs(left_proof, right_proof))
        self.assertEqual(report["relation"], "fork")
        self.assertEqual(report["conflictSeq"], 2)

        plan = decoded(plan_merge(left_proof, right_proof, "right"))
        self.assertEqual(plan["relation"], "fork")
        self.assertEqual(plan["common"], report["common"])
        self.assertEqual(plan["common"]["seq"], 1)
        # Tails are seq 2 and 3 on each side; right is selected, left rejected.
        self.assertEqual(
            step_triples(plan),
            [
                ("left", 2, "reject", "rejected"),
                ("right", 2, "accept", "selected"),
                ("left", 3, "reject", "rejected"),
                ("right", 3, "accept", "selected"),
            ],
        )
        self.assertEqual(plan["unresolved"], [])
        # The selected entries are byte-identical to the ledger proof entries.
        right_entries = {e["seq"]: e for e in decoded(right_proof)["entries"]}
        for step in plan["steps"]:
            if step["side"] == "right":
                self.assertEqual(step["entry"], right_entries[step["entry"]["seq"]])

    def test_manual_plan_from_divergent_real_ledgers(self) -> None:
        directory = tempfile.mkdtemp()
        left_path = os.path.join(directory, "left.json")
        right_path = os.path.join(directory, "right.json")
        seed_ledger(left_path, n=2)
        s1 = state({"node-a": 1}, {"k": record("v1", 1)})
        other = state(
            {"node-a": 1, "node-b": 1},
            {"k": record("v1", 1), "j": record("w1", 1, "node-b")},
        )
        R.apply_remote(right_path, make_request("r1", state(), s1))
        R.apply_remote(
            right_path, make_request("r-other", s1, other, source="node-b")
        )
        plan = decoded(
            plan_merge(export_proof(left_path, 1), export_proof(right_path, 1), "manual")
        )
        self.assertEqual(plan["relation"], "fork")
        self.assertEqual(
            step_triples(plan),
            [
                ("left", 2, "manual", "manual"),
                ("right", 2, "manual", "manual"),
            ],
        )
        self.assertEqual(
            plan["unresolved"],
            [{"seq": 2, "side": "left"}, {"seq": 2, "side": "right"}],
        )


if __name__ == "__main__":
    unittest.main()
