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
    plan_merge,
    resolve_merge,
)

RESULT_KEYS = (
    "common",
    "left",
    "planDigest",
    "policy",
    "relation",
    "right",
    "steps",
    "unresolved",
    "version",
)

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
    """Build a self-consistent valid proof for a synthetic chain."""
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


def chain_fork_proof(start, end, fork_at):
    """A fork whose right side carries different state digests past fork_at."""
    def change(seq, entry):
        if seq >= fork_at:
            entry["id"] = f"B-r{seq}"
            entry["after"] = boundary("B", seq)
            if seq > fork_at:
                entry["before"] = boundary("B", seq - 1)
        return entry

    return synth_proof(start, end, "A"), synth_proof(start, end, "A", mutate=change)


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


def manual_plan(left, right):
    return plan_merge(left, right, "manual")


def decide(plan, choices):
    """One decision per unresolved ref of ``plan``; unlisted refs are rejected."""
    return [
        {
            "side": ref["side"],
            "seq": ref["seq"],
            "action": choices.get((ref["side"], ref["seq"]), "reject"),
        }
        for ref in decoded(plan)["unresolved"]
    ]


def accept_side(plan, side):
    return decide(plan, {(ref["side"], ref["seq"]): "accept"
                         for ref in decoded(plan)["unresolved"]
                         if ref["side"] == side})


def tamper(plan, **changes):
    """Re-encode a plan canonically with top-level changes applied."""
    data = decoded(plan)
    data.update(changes)
    return canonical(data) + b"\n"


class ResolveShapeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right = fork_proof(1, 3, 1)
        self.plan = manual_plan(self.left, self.right)

    def test_result_is_canonical_compact_json_with_one_lf(self) -> None:
        raw = resolve_merge(self.plan, self.left, self.right, accept_side(self.plan, "left"))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(raw, canonical(decoded(raw)) + b"\n")
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_top_level_keys_fixed_and_sorted(self) -> None:
        raw = resolve_merge(self.plan, self.left, self.right, accept_side(self.plan, "left"))
        self.assertEqual(tuple(decoded(raw).keys()), RESULT_KEYS)

    def test_version_is_integer_1(self) -> None:
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, accept_side(self.plan, "left"))
        )
        self.assertEqual(result["version"], 1)
        self.assertIsInstance(result["version"], int)
        self.assertNotIsInstance(result["version"], bool)

    def test_plan_digest_binds_the_exact_plan_bytes(self) -> None:
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, accept_side(self.plan, "left"))
        )
        self.assertEqual(result["planDigest"], hashlib.sha256(self.plan).hexdigest())

    def test_unresolved_is_emptied(self) -> None:
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, accept_side(self.plan, "left"))
        )
        self.assertEqual(result["unresolved"], [])

    def test_manual_steps_rewritten_in_original_order(self) -> None:
        plan = decoded(self.plan)
        decisions = accept_side(self.plan, "left")
        result = decoded(resolve_merge(self.plan, self.left, self.right, decisions))
        expected = []
        for step in plan["steps"]:
            action = "accept" if step["side"] == "left" else "reject"
            reason = "manual-accepted" if step["side"] == "left" else "manual-rejected"
            expected.append((step["side"], action, reason, step["entry"]["seq"]))
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in result["steps"]],
            expected,
        )

    def test_relation_common_policy_and_sides_carried_over(self) -> None:
        plan = decoded(self.plan)
        result = decoded(
            resolve_merge(self.plan, self.left, self.right, accept_side(self.plan, "left"))
        )
        for key in ("common", "left", "policy", "relation", "right"):
            self.assertEqual(result[key], plan[key])

    def test_all_reject_is_a_valid_resolution(self) -> None:
        result = decoded(resolve_merge(self.plan, self.left, self.right, decide(self.plan, {})))
        for step in result["steps"]:
            self.assertEqual(step["action"], "reject")
            self.assertEqual(step["reason"], "manual-rejected")

    def test_unforked_manual_plan_keeps_non_manual_steps(self) -> None:
        left, right = synth_proof(1, 2), synth_proof(1, 4)
        plan = manual_plan(left, right)
        self.assertEqual(decoded(plan)["unresolved"], [])
        result = decoded(resolve_merge(plan, left, right, []))
        self.assertEqual(result["steps"], decoded(plan)["steps"])
        self.assertEqual(result["steps"][0]["reason"], "extension")
        self.assertEqual(result["unresolved"], [])

    def test_same_relation_resolves_with_no_decisions(self) -> None:
        left, right = synth_proof(1, 3), synth_proof(1, 3)
        plan = manual_plan(left, right)
        result = decoded(resolve_merge(plan, left, right, []))
        self.assertEqual(result["steps"], [])
        self.assertEqual(result["relation"], "same")

    def test_decision_input_order_does_not_change_output(self) -> None:
        decisions = accept_side(self.plan, "left")
        shuffled = list(reversed(decisions))
        self.assertEqual(
            resolve_merge(self.plan, self.left, self.right, decisions),
            resolve_merge(self.plan, self.left, self.right, shuffled),
        )

    def test_byte_stable_for_equal_inputs(self) -> None:
        decisions = accept_side(self.plan, "left")
        self.assertEqual(
            resolve_merge(self.plan, self.left, self.right, decisions),
            resolve_merge(bytes(self.plan), bytes(self.left), bytes(self.right),
                          [dict(d) for d in decisions]),
        )

    def test_inputs_are_not_modified(self) -> None:
        decisions = accept_side(self.plan, "left")
        snapshot = (bytes(self.plan), bytes(self.left), bytes(self.right),
                    json.dumps(decisions, sort_keys=True))
        resolve_merge(self.plan, self.left, self.right, decisions)
        self.assertEqual(
            (self.plan, self.left, self.right,
             json.dumps(decisions, sort_keys=True)),
            snapshot,
        )

    def test_no_file_is_opened(self) -> None:
        with mock.patch("builtins.open") as patched:
            resolve_merge(self.plan, self.left, self.right, accept_side(self.plan, "left"))
        patched.assert_not_called()

    def test_non_ascii_entries_stay_unescaped(self) -> None:
        def accent(seq, entry):
            entry["id"] = f"réq-{seq}"
            entry["source"] = "nœud-α"
            return entry

        left = synth_proof(1, 2, "A", mutate=accent)
        right = synth_proof(1, 2, "A", mutate=lambda s, e: {**accent(s, e), "id": f"autre-{s}"})
        plan = manual_plan(left, right)
        raw = resolve_merge(plan, left, right, accept_side(plan, "left"))
        self.assertNotIn(b"\\u", raw)
        self.assertIn("réq-1".encode("utf-8"), raw)
        self.assertIn("nœud-α".encode("utf-8"), raw)


class ResolveValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right = fork_proof(1, 3, 1)
        self.plan = manual_plan(self.left, self.right)
        self.decisions = accept_side(self.plan, "left")

    def test_exceptions_are_value_errors(self) -> None:
        for exc in (InvalidPlanError, StalePlanError, InvalidResolutionError):
            self.assertTrue(issubclass(exc, ValueError))

    def test_non_bytes_arguments_raise_type_error(self) -> None:
        for bad in ("x", bytearray(b"x"), None, 1, []):
            with self.assertRaises(TypeError):
                resolve_merge(bad, self.left, self.right, self.decisions)
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, bad, self.right, self.decisions)
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, self.left, bad, self.decisions)

    def test_non_list_decisions_raise_type_error(self) -> None:
        for bad in (None, 1, "accept", {}, ()):
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, self.left, self.right, bad)

    def test_non_dict_decision_raises_type_error(self) -> None:
        for bad in (None, 1, "accept", ["side"], ("side", 1)):
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, self.left, self.right, [bad])

    def test_decision_field_type_faults_raise_type_error(self) -> None:
        base = {"side": "left", "seq": 1, "action": "accept"}
        for key, bad in (
            ("side", 1), ("side", None), ("side", b"left"),
            ("seq", "1"), ("seq", None), ("seq", 1.0),
            ("action", 1), ("action", None), ("action", b"accept"),
        ):
            decision = dict(base)
            decision[key] = bad
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, self.left, self.right, [decision])

    def test_bool_never_poses_as_seq(self) -> None:
        for bad in (True, False):
            decision = {"side": "left", "seq": bad, "action": "accept"}
            with self.assertRaises(TypeError):
                resolve_merge(self.plan, self.left, self.right, [decision])

    def test_type_errors_are_not_masked_by_bad_plan_or_proofs(self) -> None:
        bad_decision = [{"side": "left", "seq": True, "action": "accept"}]
        with self.assertRaises(TypeError):
            resolve_merge(b"garbage\n", self.left, self.right, bad_decision)
        with self.assertRaises(TypeError):
            resolve_merge(self.plan, b"garbage\n", self.right, bad_decision)
        with self.assertRaises(TypeError):
            resolve_merge(self.plan, self.left, b"garbage\n", bad_decision)
        with self.assertRaises(TypeError):
            resolve_merge(b"garbage\n", b"junk\n", b"junk\n", "nope")

    def test_invalid_plans_raise_invalid_plan_error(self) -> None:
        good = decoded(self.plan)
        bad_plans = [
            b"garbage\n",
            b"{}\n",
            b"\xff\n",
            self.plan[:-1],                 # missing the trailing LF
            self.plan + b"\n",              # double LF
            canonical({**good, "extra": 1}) + b"\n",
            canonical({k: v for k, v in good.items() if k != "steps"}) + b"\n",
            canonical({**good, "version": 2}) + b"\n",
            canonical({**good, "version": "1"}) + b"\n",
            canonical({**good, "version": True}) + b"\n",
            canonical({**good, "policy": 1}) + b"\n",
            canonical({**good, "common": None}) + b"\n",
            canonical({**good, "steps": {}}) + b"\n",
            canonical({**good, "unresolved": [{"side": "left"}]}) + b"\n",
        ]
        # A duplicate top-level key, only detectable before decoding.
        dup = b'{"common":null,"common":null,"left":null,"policy":"manual",' \
              b'"relation":"fork","right":null,"steps":[],"unresolved":[],' \
              b'"version":1}\n'
        bad_plans.append(dup)
        for bad in bad_plans:
            with self.assertRaises(InvalidPlanError, msg=bad[:60]):
                resolve_merge(bad, self.left, self.right, self.decisions)

    def test_non_canonical_plan_encoding_raises_invalid_plan_error(self) -> None:
        data = decoded(self.plan)
        # Re-encoded with the keys in a non-sorted order: valid JSON, valid
        # structure, but not the canonical byte form.
        shuffled = json.dumps(
            dict(reversed(list(data.items()))),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        with self.assertRaises(InvalidPlanError):
            resolve_merge(shuffled, self.left, self.right, self.decisions)

    def test_invalid_proofs_raise_invalid_proof_error(self) -> None:
        with self.assertRaises(InvalidProofError):
            resolve_merge(self.plan, b"garbage\n", self.right, self.decisions)
        with self.assertRaises(InvalidProofError):
            resolve_merge(self.plan, self.left, b"garbage\n", self.decisions)


class StalePlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right = fork_proof(1, 3, 1)
        self.plan = manual_plan(self.left, self.right)
        self.decisions = accept_side(self.plan, "left")

    def test_other_policies_never_enter_resolution(self) -> None:
        for policy in ("left", "right"):
            plan = plan_merge(self.left, self.right, policy)
            with self.assertRaises(StalePlanError):
                resolve_merge(plan, self.left, self.right, self.decisions)

    def test_tampered_contents_are_stale(self) -> None:
        plan = decoded(self.plan)
        variants = [
            tamper(self.plan, relation="same"),
            tamper(self.plan, common={"after": boundary("A", 1), "seq": 1}),
            tamper(self.plan, policy="left"),
            tamper(self.plan, left={**plan["left"], "endSeq": 4}),
            tamper(self.plan, right={**plan["right"], "digest": "0" * 64}),
            tamper(self.plan, unresolved=plan["unresolved"][:-1]),
            tamper(self.plan, steps=plan["steps"][:-1]),
        ]
        flipped = decoded(self.plan)
        flipped["steps"][0]["action"] = "accept"
        variants.append(canonical(flipped) + b"\n")
        for variant in variants:
            with self.assertRaises(StalePlanError):
                resolve_merge(variant, self.left, self.right, self.decisions)

    def test_plan_of_other_proofs_is_stale(self) -> None:
        other_left, other_right = fork_proof(1, 3, 2)
        plan = manual_plan(other_left, other_right)
        with self.assertRaises(StalePlanError):
            resolve_merge(plan, self.left, self.right, self.decisions)

    def test_swapped_proofs_make_the_plan_stale(self) -> None:
        with self.assertRaises(StalePlanError):
            resolve_merge(self.plan, self.right, self.left, self.decisions)

    def test_disjoint_proofs_admit_no_plan(self) -> None:
        with self.assertRaises(StalePlanError):
            resolve_merge(
                self.plan, synth_proof(1, 2), synth_proof(4, 5), self.decisions
            )

    def test_fork_without_common_boundary_admits_no_plan(self) -> None:
        with self.assertRaises(StalePlanError):
            resolve_merge(
                self.plan, synth_proof(1, 3, "A"), synth_proof(1, 3, "B"),
                self.decisions,
            )


class DecisionValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right = fork_proof(1, 3, 1)
        self.plan = manual_plan(self.left, self.right)

    def test_missing_reference_raises(self) -> None:
        decisions = accept_side(self.plan, "left")[:-1]
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(self.plan, self.left, self.right, decisions)
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(self.plan, self.left, self.right, [])

    def test_duplicate_reference_raises(self) -> None:
        decisions = accept_side(self.plan, "left")
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(self.plan, self.left, self.right, decisions + [decisions[0]])

    def test_extra_or_out_of_range_reference_raises(self) -> None:
        decisions = accept_side(self.plan, "left")
        for ref in (
            {"side": "left", "seq": 99, "action": "accept"},
            {"side": "right", "seq": 0, "action": "reject"},
            {"side": "up", "seq": 1, "action": "accept"},
        ):
            with self.assertRaises(InvalidResolutionError):
                resolve_merge(self.plan, self.left, self.right, decisions + [ref])

    def test_illegal_action_choice_raises(self) -> None:
        for bad in ("maybe", "", "ACCEPT", "manual"):
            decisions = accept_side(self.plan, "left")
            decisions[0]["action"] = bad
            with self.assertRaises(InvalidResolutionError):
                resolve_merge(self.plan, self.left, self.right, decisions)

    def test_wrong_decision_key_set_raises(self) -> None:
        decisions = accept_side(self.plan, "left")
        extra = dict(decisions[0])
        extra["note"] = "x"
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(self.plan, self.left, self.right, [extra] + decisions[1:])
        missing = {k: v for k, v in decisions[0].items() if k != "action"}
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(self.plan, self.left, self.right, [missing] + decisions[1:])

    def test_accepting_both_sides_of_one_seq_raises(self) -> None:
        decisions = accept_side(self.plan, "left")
        for decision in decisions:
            if decision["side"] == "right" and decision["seq"] == 1:
                decision["action"] = "accept"
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(self.plan, self.left, self.right, decisions)

    def test_accepting_past_a_rejected_break_raises(self) -> None:
        # Reject both sides at seq 1, then accept left at seq 2.
        decisions = decide(self.plan, {("left", 2): "accept"})
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(self.plan, self.left, self.right, decisions)

    def test_digest_chain_break_raises(self) -> None:
        left, right = chain_fork_proof(1, 3, 1)
        plan = manual_plan(left, right)
        # Accept left at seq 1, then the right chain at seq 2: the right
        # entry's before digest does not continue the left entry's after.
        decisions = decide(plan, {("left", 1): "accept", ("right", 2): "accept"})
        with self.assertRaises(InvalidResolutionError):
            resolve_merge(plan, left, right, decisions)

    def test_switching_sides_is_fine_while_the_digest_chain_holds(self) -> None:
        # The id-only fork shares state digests on both sides, so accepting
        # left at seq 1 and right at seq 2 keeps the chain intact.
        decisions = decide(self.plan, {("left", 1): "accept", ("right", 2): "accept"})
        result = decoded(resolve_merge(self.plan, self.left, self.right, decisions))
        accepted = [(s["side"], s["entry"]["seq"]) for s in result["steps"]
                    if s["action"] == "accept"]
        self.assertEqual(accepted, [("left", 1), ("right", 2)])


class ResolutionSemanticsTest(unittest.TestCase):
    def test_accepted_prefix_must_start_at_the_boundary(self) -> None:
        left, right = fork_proof(1, 4, 1)
        plan = manual_plan(left, right)
        # Accept left at seqs 1 and 2, reject everything else: the chain
        # simply stops after seq 2.
        decisions = decide(plan, {("left", 1): "accept", ("left", 2): "accept"})
        result = decoded(resolve_merge(plan, left, right, decisions))
        accepted = [s["entry"]["seq"] for s in result["steps"]
                    if s["action"] == "accept"]
        self.assertEqual(accepted, [1, 2])

    def test_entries_are_carried_unchanged(self) -> None:
        left, right = fork_proof(1, 3, 2)
        plan = manual_plan(left, right)
        result = decoded(resolve_merge(plan, left, right, accept_side(plan, "right")))
        left_entries = {e["seq"]: e for e in decoded(left)["entries"]}
        right_entries = {e["seq"]: e for e in decoded(right)["entries"]}
        for step in result["steps"]:
            source = left_entries if step["side"] == "left" else right_entries
            self.assertEqual(step["entry"], source[step["entry"]["seq"]])

    def test_mirror_symmetry(self) -> None:
        a, b = fork_proof(1, 3, 2)
        plan_ab = manual_plan(a, b)
        plan_ba = manual_plan(b, a)
        one = decoded(resolve_merge(plan_ab, a, b, accept_side(plan_ab, "left")))
        two = decoded(resolve_merge(plan_ba, b, a, accept_side(plan_ba, "right")))
        self.assertEqual(one["relation"], two["relation"])
        self.assertEqual(one["common"], two["common"])
        self.assertEqual(one["left"], two["right"])
        self.assertEqual(one["right"], two["left"])
        self.assertEqual(one["planDigest"], hashlib.sha256(plan_ab).hexdigest())
        self.assertEqual(two["planDigest"], hashlib.sha256(plan_ba).hexdigest())
        mirrored = [
            {**step, "side": {"left": "right", "right": "left"}[step["side"]]}
            for step in one["steps"]
        ]
        mirrored.sort(key=lambda step: (step["entry"]["seq"], step["side"] != "left"))
        self.assertEqual(mirrored, two["steps"])


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
        left_proof = R.export_proof(left_path, 1)
        right_proof = R.export_proof(right_path, 1)
        plan = manual_plan(left_proof, right_proof)
        result = decoded(
            resolve_merge(plan, left_proof, right_proof, accept_side(plan, "left"))
        )
        self.assertEqual(result["relation"], "fork")
        self.assertEqual(
            [(s["side"], s["action"], s["reason"], s["entry"]["seq"])
             for s in result["steps"]],
            [("left", "accept", "manual-accepted", 2),
             ("right", "reject", "manual-rejected", 2)],
        )
        self.assertEqual(result["steps"][0]["entry"], decoded(left_proof)["entries"][1])
        self.assertEqual(result["steps"][1]["entry"], decoded(right_proof)["entries"][1])

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
        # Fork the signed history with a plain one sharing the first entry.
        other_path = os.path.join(directory, "other.json")
        s1 = state({"node-a": 1}, {"k": record("v1", 1)})
        R.apply_remote(other_path, make_request("r1", state(), s1))
        R.apply_remote(
            other_path,
            make_request("r-alt", s1, state({"node-a": 2}, {"k": record("w", 2)})),
        )
        signed_proof = R.export_proof(path, 1)
        plain_proof = R.export_proof(other_path, 1)
        plan = manual_plan(signed_proof, plain_proof)
        result = decoded(
            resolve_merge(plan, signed_proof, plain_proof, accept_side(plan, "left"))
        )
        # The signed entries carry ``auth`` from the first commit on, so the
        # fork starts at seq 1 and the accepted left tail covers both seqs.
        accepted = [s for s in result["steps"] if s["action"] == "accept"]
        self.assertEqual([s["entry"]["seq"] for s in accepted], [1, 2])
        signed_entries = {e["seq"]: e for e in decoded(signed_proof)["entries"]}
        for step in accepted:
            self.assertEqual(step["entry"]["auth"],
                             {"keyVersion": 1, "node": "node-a"})
            self.assertEqual(step["entry"], signed_entries[step["entry"]["seq"]])


if __name__ == "__main__":
    unittest.main()
