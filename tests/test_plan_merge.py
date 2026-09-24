"""Tests for read-only merge planning over audit proofs (plan_merge)."""

import hashlib
import hmac
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
UNRESOLVED_KEYS = ("side", "seq")

SECRET_A = "a" * 64


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


def fork_proof(start, end, fork_at, tag="A"):
    """A chain plus an id-only fork at ``fork_at`` sharing the prior boundary."""
    def change_id(seq, entry):
        if seq == fork_at:
            entry["id"] = f"{tag}-other"
        return entry

    return (
        synth_proof(start, end, tag),
        synth_proof(start, end, tag, mutate=change_id),
    )


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


def signed_envelope(request_obj, node="node-a", key_version=1, secret=SECRET_A):
    payload = json.dumps(
        {"keyVersion": key_version, "node": node, "request": request_obj},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(
        bytes.fromhex(secret), payload, hashlib.sha256
    ).hexdigest()
    return {
        "node": node,
        "keyVersion": key_version,
        "request": request_obj,
        "signature": signature,
    }


def keyring():
    return {
        "node-a": [
            {
                "version": 1,
                "secret": SECRET_A,
                "notBefore": 0,
                "notAfter": 100,
                "revoked": False,
            }
        ]
    }


class PlanShapeTest(unittest.TestCase):
    def test_plan_is_canonical_compact_json_with_one_lf(self) -> None:
        raw = plan_merge(synth_proof(1, 2), synth_proof(1, 3), "manual")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(raw, canonical(decoded(raw)) + b"\n")
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_top_level_keys_fixed_and_sorted(self) -> None:
        raw = plan_merge(synth_proof(1, 2), synth_proof(1, 3), "left")
        self.assertEqual(tuple(decoded(raw).keys()), PLAN_KEYS)

    def test_version_is_integer_1(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 2), synth_proof(1, 2), "right"))
        self.assertEqual(plan["version"], 1)
        self.assertIsInstance(plan["version"], int)
        self.assertNotIsInstance(plan["version"], bool)

    def test_policy_is_recorded_verbatim(self) -> None:
        for policy in ("left", "right", "manual"):
            plan = decoded(
                plan_merge(synth_proof(1, 2), synth_proof(1, 2), policy)
            )
            self.assertEqual(plan["policy"], policy)

    def test_sides_carry_digest_and_range(self) -> None:
        left = synth_proof(2, 4, "A")
        right = synth_proof(3, 5, "A")
        plan = decoded(plan_merge(left, right, "manual"))
        self.assertEqual(tuple(plan["left"].keys()), SIDE_KEYS)
        self.assertEqual(tuple(plan["right"].keys()), SIDE_KEYS)
        self.assertEqual(plan["left"]["startSeq"], 2)
        self.assertEqual(plan["left"]["endSeq"], 4)
        self.assertEqual(plan["left"]["digest"], decoded(left)["digest"])
        self.assertEqual(plan["right"]["startSeq"], 3)
        self.assertEqual(plan["right"]["endSeq"], 5)
        self.assertEqual(plan["right"]["digest"], decoded(right)["digest"])

    def test_common_keeps_the_boundary_shape(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 2), synth_proof(1, 4), "left"))
        self.assertEqual(
            plan["common"], {"after": boundary("A", 2), "seq": 2}
        )
        self.assertEqual(tuple(plan["common"].keys()), ("after", "seq"))

    def test_step_keys_fixed_and_sorted(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 2), synth_proof(1, 3), "left"))
        self.assertEqual(len(plan["steps"]), 1)
        self.assertEqual(tuple(plan["steps"][0].keys()), STEP_KEYS)

    def test_unresolved_items_carry_only_side_and_seq(self) -> None:
        left, right = fork_proof(1, 3, 1)
        plan = decoded(plan_merge(left, right, "manual"))
        self.assertTrue(plan["unresolved"])
        for ref in plan["unresolved"]:
            self.assertEqual(set(ref.keys()), set(UNRESOLVED_KEYS))

    def test_byte_stable_for_equal_inputs(self) -> None:
        left, right = fork_proof(1, 3, 2)
        for policy in ("left", "right", "manual"):
            self.assertEqual(
                plan_merge(left, right, policy),
                plan_merge(bytes(left), bytes(right), policy),
            )

    def test_inputs_are_not_modified(self) -> None:
        left, right = fork_proof(1, 3, 2)
        left_before, right_before = bytes(left), bytes(right)
        plan_merge(left, right, "manual")
        self.assertEqual(left, left_before)
        self.assertEqual(right, right_before)

    def test_no_file_is_opened(self) -> None:
        with mock.patch("builtins.open") as patched:
            plan_merge(synth_proof(1, 2), synth_proof(1, 3), "manual")
        patched.assert_not_called()

    def test_non_ascii_entries_stay_unescaped(self) -> None:
        def accent(seq, entry):
            entry["id"] = f"réq-{seq}"
            entry["source"] = "nœud-α"
            return entry

        left = synth_proof(1, 2, "A", mutate=accent)
        right = synth_proof(1, 3, "A", mutate=accent)
        raw = plan_merge(left, right, "manual")
        self.assertNotIn(b"\\u", raw)
        self.assertIn("réq-3".encode("utf-8"), raw)
        self.assertIn("nœud-α".encode("utf-8"), raw)

    def test_relation_common_and_sides_match_compare_proofs(self) -> None:
        scenarios = [
            (synth_proof(1, 3), synth_proof(1, 3)),
            (synth_proof(1, 2), synth_proof(1, 4)),
            (synth_proof(1, 4), synth_proof(1, 2)),
            (synth_proof(2, 5), synth_proof(4, 7)),
            (synth_proof(1, 4, "A"), synth_proof(1, 4, "B")),
        ]
        for left, right in scenarios:
            try:
                plan = decoded(plan_merge(left, right, "manual"))
            except ValueError:
                continue  # no planable boundary; compare_proofs still works
            report = decoded(compare_proofs(left, right))
            self.assertEqual(plan["relation"], report["relation"])
            self.assertEqual(plan["common"], report["common"])
            self.assertEqual(plan["left"], report["left"])
            self.assertEqual(plan["right"], report["right"])


class PlanValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.good = synth_proof(1, 3)

    def test_non_bytes_proofs_raise_type_error(self) -> None:
        for bad in (self.good.decode("utf-8"), bytearray(self.good), None, 1, []):
            with self.assertRaises(TypeError):
                plan_merge(bad, self.good, "manual")
            with self.assertRaises(TypeError):
                plan_merge(self.good, bad, "manual")
            with self.assertRaises(TypeError):
                plan_merge(bad, bad, "manual")

    def test_non_str_policy_raises_type_error(self) -> None:
        for bad in (None, 1, True, ["left"], b"left"):
            with self.assertRaises(TypeError):
                plan_merge(self.good, self.good, bad)

    def test_type_errors_are_not_masked_by_bad_proofs(self) -> None:
        with self.assertRaises(TypeError):
            plan_merge(b"garbage\n", self.good, None)
        with self.assertRaises(TypeError):
            plan_merge(self.good, b"garbage\n", 1)
        with self.assertRaises(TypeError):
            plan_merge(b"garbage\n", b"junk\n", ["left"])

    def test_invalid_left_raises_invalid_proof_error(self) -> None:
        with self.assertRaises(InvalidProofError):
            plan_merge(b"garbage\n", self.good, "manual")

    def test_invalid_right_raises_invalid_proof_error(self) -> None:
        with self.assertRaises(InvalidProofError):
            plan_merge(self.good, b"garbage\n", "manual")

    def test_unknown_policy_raises_value_error(self) -> None:
        for bad in ("", "LEFT", "auto", "manual ", "lef", "right\n"):
            with self.assertRaises(ValueError):
                plan_merge(self.good, self.good, bad)

    def test_disjoint_ranges_raise_value_error(self) -> None:
        for policy in ("left", "right", "manual"):
            with self.assertRaises(ValueError):
                plan_merge(synth_proof(1, 2), synth_proof(4, 5), policy)

    def test_fork_without_common_boundary_raises_value_error(self) -> None:
        # Different tags fork at every shared entry with different before
        # digests, so no common boundary can be confirmed.
        for policy in ("left", "right", "manual"):
            with self.assertRaises(ValueError):
                plan_merge(synth_proof(1, 3, "A"), synth_proof(1, 3, "B"), policy)

    def test_fork_without_boundary_at_subrange_raises_value_error(self) -> None:
        for policy in ("left", "right", "manual"):
            with self.assertRaises(ValueError):
                plan_merge(synth_proof(2, 4, "A"), synth_proof(2, 4, "B"), policy)


class UnforkedPlanTest(unittest.TestCase):
    def test_same_relation_has_no_steps(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 3), synth_proof(1, 3), "manual"))
        self.assertEqual(plan["relation"], "same")
        self.assertEqual(plan["steps"], [])
        self.assertEqual(plan["unresolved"], [])

    def test_left_prefix_accepts_right_tail_as_extension(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 2), synth_proof(1, 4), "left"))
        self.assertEqual(plan["relation"], "left-prefix")
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in plan["steps"]],
            [("right", "accept", "extension", 3),
             ("right", "accept", "extension", 4)],
        )
        self.assertEqual(plan["unresolved"], [])

    def test_right_prefix_accepts_left_tail_as_extension(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 4), synth_proof(1, 2), "right"))
        self.assertEqual(plan["relation"], "right-prefix")
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in plan["steps"]],
            [("left", "accept", "extension", 3),
             ("left", "accept", "extension", 4)],
        )

    def test_overlap_accepts_the_longer_tail(self) -> None:
        plan = decoded(plan_merge(synth_proof(2, 5), synth_proof(4, 7), "manual"))
        self.assertEqual(plan["relation"], "overlap")
        self.assertEqual(plan["common"], {"after": boundary("A", 5), "seq": 5})
        self.assertEqual(
            [(s["side"], s["entry"]["seq"]) for s in plan["steps"]],
            [("right", 6), ("right", 7)],
        )
        for step in plan["steps"]:
            self.assertEqual(step["action"], "accept")
            self.assertEqual(step["reason"], "extension")

    def test_overlap_ending_at_the_boundary_has_no_steps(self) -> None:
        plan = decoded(plan_merge(synth_proof(1, 4), synth_proof(2, 4), "left"))
        self.assertEqual(plan["relation"], "overlap")
        self.assertEqual(plan["steps"], [])
        self.assertEqual(plan["unresolved"], [])

    def test_boundary_entries_are_never_repeated(self) -> None:
        left = synth_proof(1, 2)
        right = synth_proof(1, 5)
        plan = decoded(plan_merge(left, right, "manual"))
        boundary_seq = plan["common"]["seq"]
        self.assertEqual(boundary_seq, 2)
        for step in plan["steps"]:
            self.assertGreater(step["entry"]["seq"], boundary_seq)
        covered = {step["entry"]["seq"] for step in plan["steps"]}
        self.assertEqual(covered, {3, 4, 5})

    def test_policy_does_not_discard_unforked_extensions(self) -> None:
        # With no fork there is nothing to select: every policy accepts
        # the longer side's tail.
        for policy in ("left", "right", "manual"):
            plan = decoded(plan_merge(synth_proof(1, 2), synth_proof(1, 3), policy))
            self.assertEqual(len(plan["steps"]), 1)
            self.assertEqual(plan["steps"][0]["action"], "accept")
            self.assertEqual(plan["steps"][0]["reason"], "extension")


class ForkPlanTest(unittest.TestCase):
    def forked(self, start, end, fork_at, tag="A"):
        return fork_proof(start, end, fork_at, tag)

    def test_left_policy_accepts_left_and_rejects_right(self) -> None:
        left, right = self.forked(1, 4, 2)
        plan = decoded(plan_merge(left, right, "left"))
        self.assertEqual(plan["relation"], "fork")
        self.assertEqual(plan["common"], {"after": boundary("A", 1), "seq": 1})
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in plan["steps"]],
            [("left", "accept", "selected", 2),
             ("right", "reject", "rejected", 2),
             ("left", "accept", "selected", 3),
             ("right", "reject", "rejected", 3),
             ("left", "accept", "selected", 4),
             ("right", "reject", "rejected", 4)],
        )
        self.assertEqual(plan["unresolved"], [])

    def test_right_policy_is_fully_symmetric(self) -> None:
        left, right = self.forked(1, 4, 2)
        plan = decoded(plan_merge(left, right, "right"))
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in plan["steps"]],
            [("left", "reject", "rejected", 2),
             ("right", "accept", "selected", 2),
             ("left", "reject", "rejected", 3),
             ("right", "accept", "selected", 3),
             ("left", "reject", "rejected", 4),
             ("right", "accept", "selected", 4)],
        )
        self.assertEqual(plan["unresolved"], [])

    def test_manual_marks_both_tails_without_selecting(self) -> None:
        left, right = self.forked(1, 3, 1)
        plan = decoded(plan_merge(left, right, "manual"))
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in plan["steps"]],
            [("left", "manual", "manual", 1),
             ("right", "manual", "manual", 1),
             ("left", "manual", "manual", 2),
             ("right", "manual", "manual", 2),
             ("left", "manual", "manual", 3),
             ("right", "manual", "manual", 3)],
        )

    def test_manual_unresolved_references_follow_step_order(self) -> None:
        left, right = self.forked(1, 3, 1)
        plan = decoded(plan_merge(left, right, "manual"))
        expected = [
            {"side": step["side"], "seq": step["entry"]["seq"]}
            for step in plan["steps"]
            if step["action"] == "manual"
        ]
        self.assertEqual(plan["unresolved"], expected)
        refs = [(ref["side"], ref["seq"]) for ref in plan["unresolved"]]
        self.assertEqual(len(refs), len(set(refs)))

    def test_steps_sorted_by_seq_with_left_first_on_ties(self) -> None:
        # Left covers 1..4, right 1..3, forking at seq 1 with a shared
        # prior boundary: the left tail is longer and still interleaves.
        left, right = self.forked(1, 4, 1)
        right = decoded(right)
        right["entries"] = right["entries"][:3]
        right["endSeq"] = 3
        right["lastAfter"] = right["entries"][-1]["after"]
        digestless = {k: v for k, v in right.items() if k != "digest"}
        right["digest"] = hashlib.sha256(canonical(digestless)).hexdigest()
        right = canonical(right) + b"\n"

        plan = decoded(plan_merge(left, right, "manual"))
        self.assertEqual(
            [(s["side"], s["entry"]["seq"]) for s in plan["steps"]],
            [("left", 1), ("right", 1),
             ("left", 2), ("right", 2),
             ("left", 3), ("right", 3),
             ("left", 4)],
        )

    def test_entries_are_carried_unchanged(self) -> None:
        left, right = self.forked(1, 4, 2)
        plan = decoded(plan_merge(left, right, "left"))
        left_entries = {e["seq"]: e for e in decoded(left)["entries"]}
        right_entries = {e["seq"]: e for e in decoded(right)["entries"]}
        for step in plan["steps"]:
            source = left_entries if step["side"] == "left" else right_entries
            self.assertEqual(step["entry"], source[step["entry"]["seq"]])

    def test_fork_in_subrange_plans_only_past_the_boundary(self) -> None:
        left, right = self.forked(3, 6, 3)
        plan = decoded(plan_merge(left, right, "left"))
        self.assertEqual(plan["common"], {"after": boundary("A", 2), "seq": 2})
        seqs = {step["entry"]["seq"] for step in plan["steps"]}
        self.assertEqual(seqs, {3, 4, 5, 6})


class MirrorTest(unittest.TestCase):
    def mirrored_steps(self, steps):
        """Steps with left/right labels flipped, back in canonical order."""
        flipped = [
            {
                "action": step["action"],
                "entry": step["entry"],
                "reason": step["reason"],
                "side": {"left": "right", "right": "left"}[step["side"]],
            }
            for step in steps
        ]
        flipped.sort(
            key=lambda step: (step["entry"]["seq"], step["side"] != "left")
        )
        return flipped

    def test_swap_with_mirrored_policy_mirrors_left_right(self) -> None:
        a, b = fork_proof(1, 4, 1)
        one = decoded(plan_merge(a, b, "left"))
        two = decoded(plan_merge(b, a, "right"))
        self.assertEqual(one["relation"], two["relation"])
        self.assertEqual(one["common"], two["common"])
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])
        self.assertEqual(self.mirrored_steps(one["steps"]), two["steps"])
        self.assertEqual(one["unresolved"], two["unresolved"])

    def test_manual_swap_only_exchanges_sides(self) -> None:
        a, b = fork_proof(1, 3, 2)
        one = decoded(plan_merge(a, b, "manual"))
        two = decoded(plan_merge(b, a, "manual"))
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])
        self.assertEqual(self.mirrored_steps(one["steps"]), two["steps"])
        mirrored_refs = sorted(
            (
                {
                    "side": {"left": "right", "right": "left"}[ref["side"]],
                    "seq": ref["seq"],
                }
                for ref in one["unresolved"]
            ),
            key=lambda ref: (ref["seq"], ref["side"] != "left"),
        )
        self.assertEqual(mirrored_refs, two["unresolved"])


class RealLedgerPlanTest(unittest.TestCase):
    def test_real_ledger_fork_left_policy(self) -> None:
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
        left_proof = export_proof(left_path, 1)
        right_proof = export_proof(right_path, 1)
        plan = decoded(plan_merge(left_proof, right_proof, "left"))
        self.assertEqual(plan["relation"], "fork")
        self.assertEqual(plan["common"]["seq"], 1)
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in plan["steps"]],
            [("left", "accept", "selected", 2),
             ("right", "reject", "rejected", 2)],
        )
        left_entry = decoded(left_proof)["entries"][1]
        right_entry = decoded(right_proof)["entries"][1]
        self.assertEqual(plan["steps"][0]["entry"], left_entry)
        self.assertEqual(plan["steps"][1]["entry"], right_entry)

    def test_real_ledger_prefix_extension(self) -> None:
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "ledger.json")
        seed_ledger(path, n=5)
        plan = decoded(
            plan_merge(export_proof(path, 1, 2), export_proof(path, 1), "right")
        )
        self.assertEqual(plan["relation"], "left-prefix")
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in plan["steps"]],
            [("right", "accept", "extension", 3),
             ("right", "accept", "extension", 4),
             ("right", "accept", "extension", 5)],
        )

    def test_auth_binding_is_carried_unchanged(self) -> None:
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "ledger.json")
        cur = state()
        for i in range(1, 3):
            nxt = state({"node-a": i}, {"k": record(f"v{i}", i)})
            envelope = signed_envelope(make_request(f"r{i}", cur, nxt))
            result = R.apply_signed_remote(path, keyring(), envelope, 10)
            assert result["status"] == "applied", result["status"]
            cur = nxt
        short = export_proof(path, 1, 1)
        full = export_proof(path, 1)
        plan = decoded(plan_merge(short, full, "manual"))
        self.assertEqual(plan["relation"], "left-prefix")
        self.assertEqual(len(plan["steps"]), 1)
        step = plan["steps"][0]
        self.assertEqual(step["entry"]["auth"], {"keyVersion": 1, "node": "node-a"})
        self.assertEqual(step["entry"], decoded(full)["entries"][1])


if __name__ == "__main__":
    unittest.main()
