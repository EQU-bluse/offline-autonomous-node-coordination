"""Tests for read-only manual merge resolution (resolve_merge)."""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication as R
from offline_coordination.replication import (
    InvalidPlanError,
    InvalidProofError,
    InvalidResolutionError,
    StalePlanError,
    export_proof,
    plan_merge,
    resolve_merge,
)

RESULT_KEYS = (
    "common",
    "left",
    "planDigest",
    "relation",
    "right",
    "steps",
    "unresolved",
    "version",
)
SIDE_KEYS = ("digest", "endSeq", "startSeq")
STEP_KEYS = ("action", "entry", "reason", "side")
DECISION_KEYS = ("side", "seq", "action")

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
    proofs with the same tag agree entry by entry at shared seqs.
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


def digest_fork_proof(start, end, fork_at, tag="A", other="B"):
    """A fork whose two sides also diverge in after/before digests."""
    def diverge(seq, entry):
        if seq >= fork_at:
            entry["id"] = f"{other}-r{seq}"
            entry["source"] = f"node-{other}"
            entry["after"] = boundary(other, seq)
            if seq == fork_at:
                entry["before"] = boundary(tag, seq - 1)
            else:
                entry["before"] = boundary(other, seq - 1)
        return entry

    return (
        synth_proof(start, end, tag),
        synth_proof(start, end, tag, mutate=diverge),
    )


def decide(side, seq, action):
    return {"side": side, "seq": seq, "action": action}


def manual_fork(start=1, end=4, fork_at=2):
    left, right = fork_proof(start, end, fork_at)
    return left, right, plan_merge(left, right, "manual")


def resolve_side(plan_left, plan_right, seqs, chosen):
    """Accept every ``chosen``-side tail seq, reject the other side."""
    other = "right" if chosen == "left" else "left"
    return (
        [decide(chosen, seq, "accept") for seq in seqs]
        + [decide(other, seq, "reject") for seq in seqs]
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


class ResultShapeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right, self.plan = manual_fork()
        self.decisions = resolve_side(self.left, self.right, (2, 3, 4), "left")

    def test_result_is_canonical_compact_json_with_one_lf(self) -> None:
        raw = resolve_merge(self.plan, self.left, self.right, self.decisions)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(raw, canonical(decoded(raw)) + b"\n")
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_top_level_keys_fixed_and_sorted(self) -> None:
        raw = resolve_merge(self.plan, self.left, self.right, self.decisions)
        self.assertEqual(tuple(decoded(raw).keys()), RESULT_KEYS)

    def test_version_is_integer_1(self) -> None:
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, self.decisions)
        )
        self.assertEqual(result["version"], 1)
        self.assertIsInstance(result["version"], int)
        self.assertNotIsInstance(result["version"], bool)

    def test_unresolved_is_empty(self) -> None:
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, self.decisions)
        )
        self.assertEqual(result["unresolved"], [])

    def test_step_keys_fixed_and_sorted(self) -> None:
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, self.decisions)
        )
        self.assertTrue(result["steps"])
        for step in result["steps"]:
            self.assertEqual(tuple(step.keys()), STEP_KEYS)

    def test_plan_digest_is_sha256_of_complete_plan_bytes(self) -> None:
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, self.decisions)
        )
        self.assertEqual(
            result["planDigest"], hashlib.sha256(self.plan).hexdigest()
        )
        self.assertRegex(result["planDigest"], r"[0-9a-f]{64}\Z")

    def test_relation_common_and_side_summaries_come_from_the_plan(self) -> None:
        plan = decoded(self.plan)
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, self.decisions)
        )
        self.assertEqual(result["relation"], plan["relation"])
        self.assertEqual(result["common"], plan["common"])
        self.assertEqual(result["left"], plan["left"])
        self.assertEqual(result["right"], plan["right"])

    def test_byte_stable_for_equal_inputs(self) -> None:
        once = resolve_merge(self.plan, self.left, self.right, self.decisions)
        again = resolve_merge(
            bytes(self.plan),
            bytes(self.left),
            bytes(self.right),
            [dict(decision) for decision in self.decisions],
        )
        self.assertEqual(once, again)

    def test_decision_input_order_does_not_change_output(self) -> None:
        once = resolve_merge(self.plan, self.left, self.right, self.decisions)
        shuffled = list(reversed(self.decisions))
        again = resolve_merge(self.plan, self.left, self.right, shuffled)
        self.assertEqual(once, again)

    def test_inputs_are_not_modified(self) -> None:
        plan_before = bytes(self.plan)
        left_before = bytes(self.left)
        right_before = bytes(self.right)
        decisions = [dict(decision) for decision in self.decisions]
        resolve_merge(self.plan, self.left, self.right, decisions)
        self.assertEqual(self.plan, plan_before)
        self.assertEqual(self.left, left_before)
        self.assertEqual(self.right, right_before)

    def test_no_file_is_opened(self) -> None:
        with mock.patch("builtins.open") as patched:
            resolve_merge(self.plan, self.left, self.right, self.decisions)
        patched.assert_not_called()

    def test_non_ascii_entries_stay_unescaped(self) -> None:
        def accent(seq, entry):
            entry["id"] = f"réq-{seq}"
            entry["source"] = "nœud-α"
            return entry

        left = synth_proof(1, 3, "A", mutate=accent)
        right = synth_proof(1, 3, "A", mutate=lambda seq, entry: (
            accent(seq, entry).__setitem__("id", f"autre-{seq}") or entry
        ) if seq >= 2 else entry)
        plan = plan_merge(left, right, "manual")
        decisions = [
            decide(side, seq, action)
            for seq in (1, 2, 3)
            for side, action in (("left", "accept"), ("right", "reject"))
        ]
        raw = resolve_merge(plan, left, right, decisions)
        self.assertNotIn(b"\\u", raw)
        self.assertIn("réq-".encode("utf-8"), raw)
        self.assertIn("nœud-α".encode("utf-8"), raw)


class ArgumentTypeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right, self.plan = manual_fork()
        self.good = resolve_side(self.left, self.right, (2, 3, 4), "left")

    def test_non_bytes_arguments_raise_type_error(self) -> None:
        for bad in (self.plan.decode("utf-8"), bytearray(self.plan), None, 1, []):
            with self.assertRaises(TypeError):
                resolve_merge(bad, self.left, self.right, self.good)
        for bad in (self.left.decode("utf-8"), bytearray(self.left), None, 1):
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, bad, self.right, self.good)
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, self.left, bad, self.good)

    def test_decisions_must_be_a_list(self) -> None:
        for bad in (None, True, (), {}, "accept"):
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, self.left, self.right, bad)

    def test_decision_must_be_a_dict(self) -> None:
        with self.assertRaises(TypeError):
            resolve_merge(self.plan, self.left, self.right, [None])
        with self.assertRaises(TypeError):
            resolve_merge(self.plan, self.left, self.right, [("left", 2, "accept")])

    def test_side_must_be_str(self) -> None:
        for bad in (None, 1, True, b"left"):
            with self.assertRaises(TypeError):
                resolve_merge(
                    self.plan, self.left, self.right,
                    [decide(bad, 2, "accept")] + self.good[1:],
                )

    def test_seq_must_be_a_non_bool_int(self) -> None:
        tail = self.good[1:]
        for bad in (True, False, "2", 2.0, None, b"2"):
            with self.assertRaises(TypeError):
                resolve_merge(
                    self.plan, self.left, self.right,
                    [decide("left", bad, "accept")] + tail,
                )

    def test_action_must_be_str(self) -> None:
        tail = self.good[1:]
        for bad in (None, 1, True, b"accept"):
            with self.assertRaises(TypeError):
                resolve_merge(
                    self.plan, self.left, self.right,
                    [decide("left", 2, bad)] + tail,
                )

    def test_type_errors_precede_proof_and_plan_parsing(self) -> None:
        with self.assertRaises(TypeError):
            resolve_merge(b"garbage\n", b"garbage\n", b"garbage\n", None)
        with self.assertRaises(TypeError):
            resolve_merge(b"garbage\n", self.left, self.right, None)
        with self.assertRaises(TypeError):
            resolve_merge(self.plan, b"garbage\n", self.right, None)


class ProofValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right, self.plan = manual_fork()

    def test_invalid_left_raises_invalid_proof_error(self) -> None:
        with self.assertRaises(InvalidProofError):
            resolve_merge(self.plan, b"garbage\n", self.right, [])

    def test_invalid_right_raises_invalid_proof_error(self) -> None:
        with self.assertRaises(InvalidProofError):
            resolve_merge(self.plan, self.left, b"garbage\n", [])

    def test_proof_errors_are_value_errors(self) -> None:
        self.assertTrue(issubclass(InvalidProofError, ValueError))


class PlanValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right, self.plan = manual_fork()
        self.good = resolve_side(self.left, self.right, (2, 3, 4), "left")

    def test_unparseable_plan_raises_invalid_plan_error(self) -> None:
        with self.assertRaises(InvalidPlanError):
            resolve_merge(b"garbage\n", self.left, self.right, [])

    def test_plan_must_end_in_exactly_one_lf(self) -> None:
        with self.assertRaises(InvalidPlanError):
            resolve_merge(self.plan[:-1], self.left, self.right, self.good)
        with self.assertRaises(InvalidPlanError):
            resolve_merge(self.plan + b"\n", self.left, self.right, self.good)

    def test_duplicate_object_keys_raise_invalid_plan_error(self) -> None:
        raw = self.plan.replace(b'"policy":"manual"', b'"policy":"manual","x":1', 1)
        with self.assertRaises(InvalidPlanError):
            resolve_merge(raw, self.left, self.right, self.good)

    def test_wrong_version_raises_invalid_plan_error(self) -> None:
        data = decoded(self.plan)
        data["version"] = 2
        with self.assertRaises(InvalidPlanError):
            resolve_merge(canonical(data) + b"\n", self.left, self.right, self.good)

    def test_bool_version_raises_invalid_plan_error(self) -> None:
        data = decoded(self.plan)
        data["version"] = True
        with self.assertRaises(InvalidPlanError):
            resolve_merge(canonical(data) + b"\n", self.left, self.right, self.good)

    def test_unknown_policy_field_raises_invalid_plan_error(self) -> None:
        data = decoded(self.plan)
        data["policy"] = "auto"
        with self.assertRaises(InvalidPlanError):
            resolve_merge(canonical(data) + b"\n", self.left, self.right, self.good)

    def test_unknown_relation_field_raises_invalid_plan_error(self) -> None:
        data = decoded(self.plan)
        data["relation"] = "mystery"
        with self.assertRaises(InvalidPlanError):
            resolve_merge(canonical(data) + b"\n", self.left, self.right, self.good)

    def test_wrong_top_level_key_set_raises_invalid_plan_error(self) -> None:
        data = decoded(self.plan)
        del data["policy"]
        with self.assertRaises(InvalidPlanError):
            resolve_merge(canonical(data) + b"\n", self.left, self.right, self.good)

    def test_unknown_step_reason_raises_invalid_plan_error(self) -> None:
        data = decoded(self.plan)
        data["steps"][0]["reason"] = "bogus"
        with self.assertRaises(InvalidPlanError):
            resolve_merge(canonical(data) + b"\n", self.left, self.right, self.good)

    def test_non_canonical_encoding_raises_invalid_plan_error(self) -> None:
        text = self.plan[:-1].decode("utf-8").replace('":"', '": "', 1)
        with self.assertRaises(InvalidPlanError):
            resolve_merge(text.encode("utf-8") + b"\n", self.left, self.right, self.good)

    def test_invalid_plan_error_is_a_value_error(self) -> None:
        self.assertTrue(issubclass(InvalidPlanError, ValueError))


class NonManualPlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right, _ = manual_fork()

    def test_left_policy_plan_is_rejected_as_stale(self) -> None:
        # A left/right policy plan is a structurally valid version-1 plan,
        # but it is not byte-identical to the manual plan regenerated for
        # these proofs (its steps differ), so it is rejected as stale and
        # never enters resolution.
        plan = plan_merge(self.left, self.right, "left")
        with self.assertRaises(StalePlanError):
            resolve_merge(plan, self.left, self.right, [])

    def test_right_policy_plan_is_rejected_as_stale(self) -> None:
        plan = plan_merge(self.right, self.left, "right")
        with self.assertRaises(StalePlanError):
            resolve_merge(plan, self.right, self.left, [])


class StalePlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right, self.plan = manual_fork()
        self.good = resolve_side(self.left, self.right, (2, 3, 4), "left")

    def test_plan_for_different_proofs_is_stale(self) -> None:
        other_left, other_right = fork_proof(1, 3, 2)
        other_plan = plan_merge(other_left, other_right, "manual")
        with self.assertRaises(StalePlanError):
            resolve_merge(other_plan, self.left, self.right, self.good)

    def test_swapped_proofs_make_the_plan_stale(self) -> None:
        with self.assertRaises(StalePlanError):
            resolve_merge(self.plan, self.right, self.left, self.good)

    def test_modified_manual_plan_is_stale(self) -> None:
        # A change that stays structurally valid but alters the content.
        data = decoded(self.plan)
        data["steps"][0]["reason"] = "selected"
        data["steps"][0]["action"] = "accept"
        with self.assertRaises(StalePlanError):
            resolve_merge(canonical(data) + b"\n", self.left, self.right, self.good)

    def test_tampered_unresolved_reference_is_stale(self) -> None:
        data = decoded(self.plan)
        data["unresolved"][0] = {"side": "left", "seq": 1}
        with self.assertRaises((InvalidPlanError, StalePlanError)):
            resolve_merge(canonical(data) + b"\n", self.left, self.right, self.good)

    def test_stale_plan_error_is_a_value_error(self) -> None:
        self.assertTrue(issubclass(StalePlanError, ValueError))

    def test_plan_for_now_unplanable_proofs_is_stale(self) -> None:
        # A genuine manual plan, presented with one proof shortened so that
        # regeneration no longer yields the same plan at all.
        shorter = synth_proof(1, 3, "A")
        with self.assertRaises(StalePlanError):
            resolve_merge(self.plan, self.left, shorter, self.good)


class ResolutionContentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right, self.plan = manual_fork()
        self.seqs = (2, 3, 4)

    def resolve(self, decisions):
        return resolve_merge(self.plan, self.left, self.right, decisions)

    def test_missing_reference_raises_invalid_resolution_error(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "left")
        with self.assertRaises(InvalidResolutionError):
            self.resolve(decisions[:-1])

    def test_duplicate_reference_raises_invalid_resolution_error(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "left")
        with self.assertRaises(InvalidResolutionError):
            self.resolve(decisions + [decisions[0]])

    def test_extra_out_of_range_reference_raises_invalid_resolution_error(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "left")
        with self.assertRaises(InvalidResolutionError):
            self.resolve(decisions + [decide("left", 1, "accept")])
        with self.assertRaises(InvalidResolutionError):
            self.resolve(decisions + [decide("left", 5, "reject")])

    def test_unknown_side_raises_invalid_resolution_error(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "left")
        decisions[0] = {"side": "top", "seq": 2, "action": "accept"}
        with self.assertRaises(InvalidResolutionError):
            self.resolve(decisions)

    def test_illegal_action_raises_invalid_resolution_error(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "left")
        for bad in ("manual", "selected", "", "ACCEPT", "accept "):
            changed = [dict(decision) for decision in decisions]
            changed[0]["action"] = bad
            with self.assertRaises(InvalidResolutionError):
                self.resolve(changed)

    def test_decision_wrong_key_set_raises_invalid_resolution_error(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "left")
        extra = [dict(decision, why="x") for decision in decisions]
        with self.assertRaises(InvalidResolutionError):
            self.resolve(extra)
        missing = [
            {"side": decision["side"], "seq": decision["seq"]}
            for decision in decisions
        ]
        with self.assertRaises(InvalidResolutionError):
            self.resolve(missing)

    def test_accepting_both_sides_at_one_seq_raises(self) -> None:
        decisions = [
            decide(side, seq, "accept")
            for seq in self.seqs
            for side in ("left", "right")
        ]
        with self.assertRaises(InvalidResolutionError):
            self.resolve(decisions)

    def test_resuming_past_an_all_rejected_seq_raises(self) -> None:
        decisions = [
            decide("left", 2, "reject"), decide("right", 2, "reject"),
            decide("left", 3, "accept"), decide("right", 3, "reject"),
            decide("left", 4, "reject"), decide("right", 4, "reject"),
        ]
        with self.assertRaises(InvalidResolutionError):
            self.resolve(decisions)

    def test_gap_in_the_accepted_seq_chain_raises(self) -> None:
        decisions = [
            decide("left", 2, "accept"), decide("right", 2, "reject"),
            decide("left", 3, "reject"), decide("right", 3, "reject"),
            decide("left", 4, "accept"), decide("right", 4, "reject"),
        ]
        with self.assertRaises(InvalidResolutionError):
            self.resolve(decisions)

    def test_digest_chain_break_raises(self) -> None:
        left, right = digest_fork_proof(1, 4, 2)
        plan = plan_merge(left, right, "manual")
        # right seq 2 chains from the common boundary, but left seq 3's
        # before does not equal right seq 2's after.
        decisions = [
            decide("right", 2, "accept"), decide("left", 2, "reject"),
            decide("left", 3, "accept"), decide("right", 3, "reject"),
            decide("left", 4, "reject"), decide("right", 4, "reject"),
        ]
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(plan, left, right, decisions)

    def test_error_is_a_value_error(self) -> None:
        self.assertTrue(issubclass(InvalidResolutionError, ValueError))


class ResolvedContentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right, self.plan = manual_fork()
        self.seqs = (2, 3, 4)

    def test_manual_steps_relabelled_with_fixed_reasons(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "left")
        result = decoded(resolve_merge(self.plan, self.left, self.right, decisions))
        self.assertEqual(
            [(step["side"], step["entry"]["seq"], step["action"], step["reason"])
             for step in result["steps"]],
            [("left", 2, "accept", "manual-accepted"),
             ("right", 2, "reject", "manual-rejected"),
             ("left", 3, "accept", "manual-accepted"),
             ("right", 3, "reject", "manual-rejected"),
             ("left", 4, "accept", "manual-accepted"),
             ("right", 4, "reject", "manual-rejected")],
        )

    def test_steps_keep_the_plan_step_order(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "right")
        plan_steps = decoded(self.plan)["steps"]
        result = decoded(resolve_merge(self.plan, self.left, self.right, decisions))
        self.assertEqual(
            [(step["side"], step["entry"]["seq"]) for step in result["steps"]],
            [(step["side"], step["entry"]["seq"]) for step in plan_steps],
        )

    def test_entries_are_carried_unchanged(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "left")
        left_entries = {e["seq"]: e for e in decoded(self.left)["entries"]}
        right_entries = {e["seq"]: e for e in decoded(self.right)["entries"]}
        result = decoded(resolve_merge(self.plan, self.left, self.right, decisions))
        for step in result["steps"]:
            source = left_entries if step["side"] == "left" else right_entries
            self.assertEqual(step["entry"], source[step["entry"]["seq"]])

    def test_accepting_the_other_side_chains(self) -> None:
        decisions = resolve_side(self.left, self.right, self.seqs, "right")
        result = decoded(resolve_merge(self.plan, self.left, self.right, decisions))
        self.assertEqual(
            [(step["side"], step["entry"]["seq"], step["action"])
             for step in result["steps"]],
            [("left", 2, "reject"), ("right", 2, "accept"),
             ("left", 3, "reject"), ("right", 3, "accept"),
             ("left", 4, "reject"), ("right", 4, "accept")],
        )

    def test_rejecting_everything_is_a_valid_prefix_chain(self) -> None:
        decisions = [
            decide(side, seq, "reject")
            for seq in self.seqs
            for side in ("left", "right")
        ]
        result = decoded(resolve_merge(self.plan, self.left, self.right, decisions))
        self.assertTrue(all(step["action"] == "reject" for step in result["steps"]))
        self.assertTrue(
            all(step["reason"] == "manual-rejected" for step in result["steps"])
        )

    def test_non_manual_steps_stay_unchanged(self) -> None:
        # An unforked prefix plan has only extension steps (non-manual) and
        # no unresolved references; resolving it changes nothing in steps.
        left = synth_proof(1, 2)
        right = synth_proof(1, 4)
        plan = plan_merge(left, right, "manual")
        result = decoded(resolve_merge(plan, left, right, []))
        self.assertEqual(
            [(step["side"], step["entry"]["seq"], step["action"], step["reason"])
             for step in result["steps"]],
            [("right", 3, "accept", "extension"),
             ("right", 4, "accept", "extension")],
        )
        self.assertEqual(result["unresolved"], [])

    def test_empty_plan_resolves_without_decisions(self) -> None:
        # same relation: no steps, no unresolved items.
        proof = synth_proof(1, 3)
        plan = plan_merge(proof, proof, "manual")
        result = decoded(resolve_merge(plan, proof, proof, []))
        self.assertEqual(result["steps"], [])
        self.assertEqual(result["unresolved"], [])
        self.assertEqual(result["relation"], "same")


class MirrorTest(unittest.TestCase):
    def test_swap_with_mirrored_decisions_mirrors_the_result(self) -> None:
        left, right = fork_proof(1, 4, 2)
        plan = plan_merge(left, right, "manual")
        seqs = (2, 3, 4)
        decisions = (
            [decide("left", seq, "accept") for seq in seqs]
            + [decide("right", seq, "reject") for seq in seqs]
        )
        one = decoded(resolve_merge(plan, left, right, decisions))

        swapped_plan = plan_merge(right, left, "manual")
        swapped_decisions = [
            {"side": {"left": "right", "right": "left"}[decision["side"]],
             "seq": decision["seq"], "action": decision["action"]}
            for decision in decisions
        ]
        two = decoded(resolve_merge(swapped_plan, right, left, swapped_decisions))

        self.assertEqual(one["relation"], two["relation"])
        self.assertEqual(one["common"], two["common"])
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])
        flipped = [
            {**step, "side": {"left": "right", "right": "left"}[step["side"]]}
            for step in two["steps"]
        ]
        flipped.sort(
            key=lambda step: (step["entry"]["seq"], step["side"] != "left")
        )
        self.assertEqual(one["steps"], flipped)
        self.assertEqual(one["unresolved"], two["unresolved"])
        # The plan digest records the actual resolved plan, so the two
        # (different) source plans legitimately carry different digests.
        self.assertNotEqual(one["planDigest"], two["planDigest"])
        self.assertEqual(one["planDigest"], hashlib.sha256(plan).hexdigest())
        self.assertEqual(two["planDigest"], hashlib.sha256(swapped_plan).hexdigest())


class RealLedgerResolveTest(unittest.TestCase):
    def test_real_ledger_fork_resolution(self) -> None:
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
        plan = plan_merge(left_proof, right_proof, "manual")
        decisions = [
            decide("left", 2, "reject"), decide("right", 2, "accept"),
        ]
        result = decoded(resolve_merge(plan, left_proof, right_proof, decisions))
        self.assertEqual(result["relation"], "fork")
        self.assertEqual(
            [(step["side"], step["entry"]["seq"], step["action"], step["reason"])
             for step in result["steps"]],
            [("left", 2, "reject", "manual-rejected"),
             ("right", 2, "accept", "manual-accepted")],
        )
        self.assertEqual(
            result["steps"][1]["entry"], decoded(right_proof)["entries"][1]
        )

    def test_auth_binding_survives_resolution(self) -> None:
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
        plan = plan_merge(short, full, "manual")
        result = decoded(resolve_merge(plan, short, full, []))
        self.assertEqual(len(result["steps"]), 1)
        step = result["steps"][0]
        self.assertEqual(step["entry"]["auth"], {"keyVersion": 1, "node": "node-a"})
        self.assertEqual(step["action"], "accept")
        self.assertEqual(step["reason"], "extension")


if __name__ == "__main__":
    unittest.main()
