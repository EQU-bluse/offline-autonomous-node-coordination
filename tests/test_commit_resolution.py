"""Tests for landing manual merge resolutions (commit_resolution)."""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication as R
from offline_coordination import storage
from offline_coordination.replication import (
    InvalidPlanError,
    InvalidProofError,
    InvalidResolutionError,
    StaleLedgerError,
    StalePlanError,
    commit_resolution,
    export_proof,
    plan_merge,
    resolve_merge,
)

SECRET_B = "b" * 64


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, n, writer="node-a"):
    return [value, False, {writer: n}, writer]


def make_request(rid, base, remote, source="node-a"):
    return {"id": rid, "source": source, "base": base, "remote": remote}


def signed_envelope(request_obj, node="node-b", key_version=1, secret=SECRET_B):
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
        "node-b": [
            {
                "version": 1,
                "secret": SECRET_B,
                "notBefore": 0,
                "notAfter": 100,
                "revoked": False,
            }
        ]
    }


def decide(side, seq, action):
    return {"side": side, "seq": seq, "action": action}


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def read_ledger(path):
    return R._parse_ledger(read_bytes(path))


S0 = state()
S1 = state({"node-a": 1}, {"k": record("v1", 1)})
S2 = state({"node-a": 2}, {"k": record("v2", 2)})
S3L = state({"node-a": 3}, {"k": record("v3l", 3)})
S3R = state(
    {"node-a": 2, "node-b": 1},
    {"k": record("v2", 2), "j": record("w1", 1, "node-b")},
)
S4R = state(
    {"node-a": 2, "node-b": 2},
    {"k": record("v2", 2), "j": record("w2", 2, "node-b")},
)
S5 = state(
    {"node-a": 3, "node-b": 2},
    dict(S4R["records"], z=record("v5", 3)),
)

RIGHT_DECISIONS = [
    decide("left", 3, "reject"),
    decide("right", 3, "accept"),
    decide("right", 4, "accept"),
]
LEFT_DECISIONS = [
    decide("left", 3, "accept"),
    decide("right", 3, "reject"),
    decide("right", 4, "reject"),
]
ALL_REJECT = [
    decide("left", 3, "reject"),
    decide("right", 3, "reject"),
    decide("right", 4, "reject"),
]


def apply(path, rid, base, nxt, source="node-a"):
    result = R.apply_remote(path, make_request(rid, base, nxt, source=source))
    assert result["status"] == "applied", (rid, result["status"])


class Fork:
    """Ledgers for a fork at seq 3 over a shared 2-entry prefix.

    ``target_path`` sits exactly at the common boundary (entries r1, r2);
    the left ledger adds r3l, the right ledger adds r3r and r4r
    (optionally signed by node-b).  The resolution is committed to the
    target ledger.
    """

    def __init__(self, directory, signed=False, tag=""):
        self.target_path = os.path.join(directory, "target.json")
        self.left_path = os.path.join(directory, "left.json")
        self.right_path = os.path.join(directory, "right.json")
        s1 = state({"node-a": 1}, {"k": record(f"v1{tag}", 1)})
        s2 = state({"node-a": 2}, {"k": record(f"v2{tag}", 2)})
        s3l = state({"node-a": 3}, {"k": record(f"v3l{tag}", 3)})
        s3r = state(
            {"node-a": 2, "node-b": 1},
            {"k": record(f"v2{tag}", 2), "j": record(f"w1{tag}", 1, "node-b")},
        )
        s4r = state(
            {"node-a": 2, "node-b": 2},
            {"k": record(f"v2{tag}", 2), "j": record(f"w2{tag}", 2, "node-b")},
        )
        for path in (self.target_path, self.left_path, self.right_path):
            apply(path, "r1", S0, s1)
            apply(path, "r2", s1, s2)
        apply(self.left_path, "r3l", s2, s3l)
        for rid, base, nxt in (("r3r", s2, s3r), ("r4r", s3r, s4r)):
            if signed:
                envelope = signed_envelope(make_request(rid, base, nxt, source="node-b"))
                result = R.apply_signed_remote(
                    self.right_path, keyring(), envelope, 10
                )
                assert result["status"] == "applied", result["status"]
            else:
                apply(self.right_path, rid, base, nxt, source="node-b")
        self.final_state = s4r
        self.left_proof = export_proof(self.left_path, 1)
        self.right_proof = export_proof(self.right_path, 1)
        self.plan = plan_merge(self.left_proof, self.right_proof, "manual")

    def resolve(self, decisions):
        return resolve_merge(self.plan, self.left_proof, self.right_proof, decisions)

    def material(self):
        _, requests, _ = read_ledger(self.right_path)
        return {
            "state": self.final_state,
            "requests": {"r3r": requests["r3r"], "r4r": requests["r4r"]},
        }


class CommitCase(unittest.TestCase):
    signed = False

    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp()
        self.fork = Fork(self.directory, signed=self.signed)
        self.resolution = self.fork.resolve(RIGHT_DECISIONS)
        self.material = self.fork.material()

    def commit(self, **overrides):
        args = {
            "path": self.fork.target_path,
            "resolution": self.resolution,
            "plan": self.fork.plan,
            "left": self.fork.left_proof,
            "right": self.fork.right_proof,
            "material": self.material,
        }
        args.update(overrides)
        return commit_resolution(**args)


class AppliedTest(CommitCase):
    def test_applied_result_shape(self) -> None:
        result = self.commit()
        self.assertEqual(list(result.keys()), ["next", "resolutionDigest", "status"])
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["next"], 4)
        self.assertEqual(
            result["resolutionDigest"],
            hashlib.sha256(self.resolution).hexdigest(),
        )
        self.assertRegex(result["resolutionDigest"], r"[0-9a-f]{64}\Z")

    def test_applied_ledger_contents(self) -> None:
        self.commit()
        stored_state, requests, entries = read_ledger(self.fork.target_path)
        self.assertEqual(
            R._digest(R._state_bytes(stored_state)),
            R._digest(R._state_bytes(S4R)),
        )
        self.assertEqual(
            [entry["id"] for entry in entries], ["r1", "r2", "r3r", "r4r"]
        )
        self.assertEqual([entry["seq"] for entry in entries], [1, 2, 3, 4])
        right_entries = json.loads(self.fork.right_proof)["entries"]
        # The accepted entries land unchanged; rejected ones never appear.
        self.assertEqual(entries[2:], right_entries[2:])
        self.assertNotIn("r3l", requests)
        self.assertEqual(requests["r3r"], self.material["requests"]["r3r"])
        self.assertEqual(requests["r4r"], self.material["requests"]["r4r"])

    def test_ledger_stays_exportable_after_commit(self) -> None:
        self.commit()
        proof = json.loads(export_proof(self.fork.target_path, 1))
        self.assertEqual(proof["endSeq"], 4)
        self.assertEqual(proof["lastAfter"], R._digest(R._state_bytes(S4R)))

    def test_duplicate_replay_returns_same_digest_and_touches_nothing(self) -> None:
        first = self.commit()
        before = read_bytes(self.fork.target_path)
        second = self.commit()
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(second["next"], first["next"])
        self.assertEqual(second["resolutionDigest"], first["resolutionDigest"])
        self.assertEqual(list(second.keys()), ["next", "resolutionDigest", "status"])
        self.assertEqual(read_bytes(self.fork.target_path), before)

    def test_duplicate_recognized_after_later_commits(self) -> None:
        first = self.commit()
        apply(self.fork.target_path, "r5", S4R, S5)
        second = self.commit()
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(second["next"], first["next"])
        self.assertEqual(second["resolutionDigest"], first["resolutionDigest"])

    def test_result_is_a_fresh_object_per_call(self) -> None:
        first = self.commit()
        second = self.commit()
        self.assertIsNot(first, second)


class UnchangedTest(CommitCase):
    def setUp(self) -> None:
        super().setUp()
        self.resolution = self.fork.resolve(ALL_REJECT)
        self.material = {"state": S2, "requests": {}}

    def test_nothing_accepted_returns_unchanged_and_writes_nothing(self) -> None:
        before = read_bytes(self.fork.target_path)
        result = self.commit()
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["next"], 2)
        self.assertEqual(
            result["resolutionDigest"],
            hashlib.sha256(self.resolution).hexdigest(),
        )
        self.assertEqual(read_bytes(self.fork.target_path), before)

    def test_nothing_accepted_requires_empty_requests(self) -> None:
        self.material = {"state": S2, "requests": {"r3r": "0" * 64}}
        with self.assertRaises(ValueError):
            self.commit()

    def test_nothing_accepted_requires_boundary_state(self) -> None:
        self.material = {"state": S3L, "requests": {}}
        with self.assertRaises(ValueError):
            self.commit()

    def test_unchanged_still_checks_the_boundary(self) -> None:
        apply(self.fork.target_path, "r9", S2, S3L)
        with self.assertRaises(StaleLedgerError):
            self.commit()


class StaleLedgerTest(CommitCase):
    def test_stale_ledger_error_is_a_value_error(self) -> None:
        self.assertTrue(issubclass(StaleLedgerError, ValueError))

    def test_boundary_moved_by_another_resolution_is_stale(self) -> None:
        _, requests, _ = read_ledger(self.fork.left_path)
        left_material = {"state": S3L, "requests": {"r3l": requests["r3l"]}}
        left_resolution = self.fork.resolve(LEFT_DECISIONS)
        self.commit()
        with self.assertRaises(StaleLedgerError):
            self.commit(resolution=left_resolution, material=left_material)

    def test_boundary_moved_by_apply_remote_is_stale(self) -> None:
        apply(self.fork.target_path, "r9", S2, S3L)
        with self.assertRaises(StaleLedgerError):
            self.commit()

    def test_partial_application_is_stale_and_writes_nothing(self) -> None:
        # Only the first accepted entry exists; the second never landed.
        apply(self.fork.target_path, "r3r", S2, S3R, source="node-b")
        before = read_bytes(self.fork.target_path)
        with self.assertRaises(StaleLedgerError):
            self.commit()
        self.assertEqual(read_bytes(self.fork.target_path), before)

    def test_conflicting_entries_at_accepted_positions_are_stale(self) -> None:
        # Same seqs committed with different ids than the resolution.
        apply(self.fork.target_path, "other3", S2, S3R, source="node-b")
        apply(self.fork.target_path, "other4", S3R, S4R, source="node-b")
        with self.assertRaises(StaleLedgerError):
            self.commit()


class SignedCommitTest(CommitCase):
    signed = True

    def test_auth_bindings_survive_the_commit(self) -> None:
        result = self.commit()
        self.assertEqual(result["status"], "applied")
        _, _, entries = read_ledger(self.fork.target_path)
        self.assertNotIn("auth", entries[0])
        self.assertNotIn("auth", entries[1])
        self.assertEqual(entries[2]["auth"], {"keyVersion": 1, "node": "node-b"})
        self.assertEqual(entries[3]["auth"], {"keyVersion": 1, "node": "node-b"})

    def test_changed_auth_binding_is_stale(self) -> None:
        # The same requests applied without signatures are not the
        # resolution's signed entries.
        apply(self.fork.target_path, "r3r", S2, S3R, source="node-b")
        apply(self.fork.target_path, "r4r", S3R, S4R, source="node-b")
        before = read_bytes(self.fork.target_path)
        with self.assertRaises(StaleLedgerError):
            self.commit()
        self.assertEqual(read_bytes(self.fork.target_path), before)


class LedgerFailureTest(CommitCase):
    def test_missing_ledger_raises_file_not_found(self) -> None:
        missing = os.path.join(self.directory, "missing.json")
        with self.assertRaises(FileNotFoundError):
            self.commit(path=missing)

    def test_corrupt_ledger_raises_value_error(self) -> None:
        with open(self.fork.target_path, "wb") as handle:
            handle.write(b"this is not a ledger\n")
        with self.assertRaises(ValueError):
            self.commit()

    def test_fsync_failure_propagates_and_restores_bytes(self) -> None:
        before = read_bytes(self.fork.target_path)
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                self.commit()
        self.assertEqual(read_bytes(self.fork.target_path), before)

    def test_replace_failure_propagates_and_restores_bytes(self) -> None:
        before = read_bytes(self.fork.target_path)
        with mock.patch("os.replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                self.commit()
        self.assertEqual(read_bytes(self.fork.target_path), before)

    def test_write_failure_propagates_and_restores_bytes(self) -> None:
        before = read_bytes(self.fork.target_path)
        real_open = open

        class FailingFile:
            def __init__(self, *args, **kwargs):
                self._handle = real_open(*args, **kwargs)

            def write(self, data):
                raise OSError("write failed")

            def __getattr__(self, name):
                return getattr(self._handle, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._handle.close()
                return False

        with mock.patch(
            "builtins.open", side_effect=lambda *a, **k: FailingFile(*a, **k)
        ):
            with self.assertRaises(OSError):
                self.commit()
        self.assertEqual(read_bytes(self.fork.target_path), before)


class DirectorySyncRollbackTest(CommitCase):
    """A directory-sync failure anywhere in the commit boundary rolls back."""

    def setUp(self) -> None:
        super().setUp()
        self.unrelated = os.path.join(self.directory, "unrelated.txt")
        with open(self.unrelated, "wb") as handle:
            handle.write(b"pre-existing, do not touch\n")

    def commit_with_fsync_dir_failures(self, fail_on):
        real_fsync_dir = storage._fsync_dir
        failure = OSError("directory sync failed")
        calls = []

        def flaky_fsync_dir(path):
            calls.append(path)
            if len(calls) in fail_on:
                raise failure
            return real_fsync_dir(path)

        with mock.patch.object(storage, "_fsync_dir", flaky_fsync_dir):
            with self.assertRaises(OSError) as caught:
                self.commit()
        return failure, caught.exception, calls

    def assert_full_rollback(self, failure, raised, before_bytes, before_ledger):
        # The exact injected exception propagates; no secondary rollback
        # error may replace it or turn the call into a business result.
        self.assertIs(raised, failure)
        # The ledger is back to its pre-call bytes, not merely parseable.
        self.assertEqual(read_bytes(self.fork.target_path), before_bytes)
        # Re-reading shows the original seq, state digest, request
        # bindings and auth information.
        self.assertEqual(read_ledger(self.fork.target_path), before_ledger)
        # No transaction residue, and the unrelated file is untouched.
        self.assertEqual(
            sorted(os.listdir(self.directory)),
            ["left.json", "right.json", "target.json", "unrelated.txt"],
        )
        self.assertEqual(
            read_bytes(self.unrelated), b"pre-existing, do not touch\n"
        )

    def assert_retry_applies(self):
        # After the rollback the same resolution applies as if the failed
        # commit never happened: not duplicate, not stale.
        result = self.commit()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["next"], 4)
        read_ledger(self.fork.target_path)
        self.assertEqual(
            sorted(os.listdir(self.directory)),
            ["left.json", "right.json", "target.json", "unrelated.txt"],
        )

    def test_first_directory_sync_failure_rolls_back(self) -> None:
        before_bytes = read_bytes(self.fork.target_path)
        before_ledger = read_ledger(self.fork.target_path)
        failure, raised, calls = self.commit_with_fsync_dir_failures({1})
        # The sync after the install failed; the rollback synced again.
        self.assertEqual(len(calls), 2)
        self.assert_full_rollback(failure, raised, before_bytes, before_ledger)
        self.assert_retry_applies()

    def test_cleanup_directory_sync_failure_rolls_back(self) -> None:
        before_bytes = read_bytes(self.fork.target_path)
        before_ledger = read_ledger(self.fork.target_path)
        failure, raised, calls = self.commit_with_fsync_dir_failures({2})
        # The install sync succeeded, the cleanup sync failed, the
        # rollback synced again.
        self.assertEqual(len(calls), 3)
        self.assert_full_rollback(failure, raised, before_bytes, before_ledger)
        self.assert_retry_applies()

    def test_successful_commit_leaves_no_transaction_residue(self) -> None:
        result = self.commit()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(
            sorted(os.listdir(self.directory)),
            ["left.json", "right.json", "target.json", "unrelated.txt"],
        )
        read_ledger(self.fork.target_path)


class SignedDirectorySyncRollbackTest(DirectorySyncRollbackTest):
    signed = True


class ArgumentTypeTest(CommitCase):
    def test_non_str_path_raises_type_error(self) -> None:
        for bad in (None, 1, b"path", True):
            with self.assertRaises(TypeError):
                self.commit(path=bad)

    def test_non_bytes_canonical_arguments_raise_type_error(self) -> None:
        for key in ("resolution", "plan", "left", "right"):
            for bad in ("text", bytearray(b"x"), None, 1, []):
                with self.assertRaises(TypeError):
                    self.commit(**{key: bad})

    def test_material_must_be_a_dict(self) -> None:
        for bad in (None, True, [], "material"):
            with self.assertRaises(TypeError):
                self.commit(material=bad)

    def test_material_state_type_faults_raise_type_error(self) -> None:
        with self.assertRaises(TypeError):
            self.commit(material={"state": [], "requests": {}})
        with self.assertRaises(TypeError):
            self.commit(
                material={"state": {"clock": [], "records": {}}, "requests": {}}
            )

    def test_material_requests_must_be_a_dict(self) -> None:
        with self.assertRaises(TypeError):
            self.commit(material={"state": S4R, "requests": []})

    def test_material_request_field_types(self) -> None:
        with self.assertRaises(TypeError):
            self.commit(material={"state": S4R, "requests": {1: "0" * 64}})
        with self.assertRaises(TypeError):
            self.commit(material={"state": S4R, "requests": {"r3r": 1}})

    def test_type_errors_precede_proof_and_plan_parsing(self) -> None:
        with self.assertRaises(TypeError):
            commit_resolution(
                self.fork.target_path, b"garbage\n", b"garbage\n",
                b"garbage\n", b"garbage\n", None,
            )


class MaterialValidationTest(CommitCase):
    def test_wrong_material_key_set_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.commit(material={"state": S4R})
        with self.assertRaises(ValueError):
            self.commit(material={"state": S4R, "requests": {}, "extra": 1})

    def test_bad_request_digest_raises_value_error(self) -> None:
        for bad in ("0" * 63, "0" * 65, "g" * 64):
            material = {"state": S4R, "requests": {"r3r": bad, "r4r": "0" * 64}}
            with self.assertRaises(ValueError):
                self.commit(material=material)

    def test_invalid_state_value_raises_value_error(self) -> None:
        bad = {"clock": {"node-a": -1}, "records": {}}
        with self.assertRaises(ValueError):
            self.commit(material={"state": bad, "requests": {}})

    def test_requests_must_bind_exactly_the_accepted_ids(self) -> None:
        _, requests, _ = read_ledger(self.fork.right_path)
        missing = {"state": S4R, "requests": {"r3r": requests["r3r"]}}
        with self.assertRaises(ValueError):
            self.commit(material=missing)
        extra = {
            "state": S4R,
            "requests": {
                "r3r": requests["r3r"],
                "r4r": requests["r4r"],
                "r5": "0" * 64,
            },
        }
        with self.assertRaises(ValueError):
            self.commit(material=extra)

    def test_state_must_hash_to_the_last_accepted_after(self) -> None:
        _, requests, _ = read_ledger(self.fork.right_path)
        material = {
            "state": S3R,
            "requests": {"r3r": requests["r3r"], "r4r": requests["r4r"]},
        }
        with self.assertRaises(ValueError):
            self.commit(material=material)


class ProofPlanResolutionTest(CommitCase):
    def test_invalid_proofs_raise_invalid_proof_error(self) -> None:
        with self.assertRaises(InvalidProofError):
            self.commit(left=b"garbage\n")
        with self.assertRaises(InvalidProofError):
            self.commit(right=b"garbage\n")

    def test_invalid_plan_raises_invalid_plan_error(self) -> None:
        with self.assertRaises(InvalidPlanError):
            self.commit(plan=b"garbage\n")
        with self.assertRaises(InvalidPlanError):
            self.commit(plan=self.fork.plan[:-1])

    def test_invalid_resolution_raises_invalid_resolution_error(self) -> None:
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=b"garbage\n")
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=self.resolution[:-1])
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=self.resolution + b"\n")

    def test_resolution_with_wrong_version_is_invalid(self) -> None:
        data = json.loads(self.resolution)
        data["version"] = 2
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=canonical(data) + b"\n")

    def test_resolution_with_pending_unresolved_is_invalid(self) -> None:
        data = json.loads(self.resolution)
        data["unresolved"] = [{"side": "left", "seq": 3}]
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=canonical(data) + b"\n")

    def test_non_canonical_resolution_is_invalid(self) -> None:
        text = self.resolution[:-1].decode("utf-8").replace('":"', '": "', 1)
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=text.encode("utf-8") + b"\n")

    def test_plan_for_other_proofs_is_stale(self) -> None:
        other = Fork(tempfile.mkdtemp(), tag="-other")
        with self.assertRaises(StalePlanError):
            self.commit(
                plan=other.plan, left=other.left_proof, right=other.right_proof
            )

    def test_swapped_proofs_make_the_plan_stale(self) -> None:
        with self.assertRaises(StalePlanError):
            self.commit(left=self.fork.right_proof, right=self.fork.left_proof)

    def test_non_manual_plan_is_stale(self) -> None:
        plan = plan_merge(self.fork.left_proof, self.fork.right_proof, "left")
        with self.assertRaises(StalePlanError):
            self.commit(plan=plan)

    def test_resolution_with_wrong_plan_digest_is_stale(self) -> None:
        data = json.loads(self.resolution)
        data["planDigest"] = "0" * 64
        with self.assertRaises(StalePlanError):
            self.commit(resolution=canonical(data) + b"\n")

    def test_resolution_with_mismatched_relation_is_stale(self) -> None:
        data = json.loads(self.resolution)
        data["relation"] = "same"
        with self.assertRaises(StalePlanError):
            self.commit(resolution=canonical(data) + b"\n")

    def test_stale_plan_never_touches_the_ledger(self) -> None:
        before = read_bytes(self.fork.target_path)
        with mock.patch("builtins.open", side_effect=AssertionError("opened")):
            with self.assertRaises(StalePlanError):
                self.commit(
                    left=self.fork.right_proof, right=self.fork.left_proof
                )
        self.assertEqual(read_bytes(self.fork.target_path), before)


class AcceptChainTest(CommitCase):
    def resolution_with_choices(self, choices):
        plan = json.loads(self.fork.plan)
        steps = []
        for step in plan["steps"]:
            action = choices[(step["side"], step["entry"]["seq"])]
            steps.append(
                {
                    "action": action,
                    "entry": step["entry"],
                    "reason": (
                        "manual-accepted" if action == "accept"
                        else "manual-rejected"
                    ),
                    "side": step["side"],
                }
            )
        data = {
            "common": plan["common"],
            "left": plan["left"],
            "planDigest": hashlib.sha256(self.fork.plan).hexdigest(),
            "relation": plan["relation"],
            "right": plan["right"],
            "steps": steps,
            "unresolved": [],
            "version": 1,
        }
        return canonical(data) + b"\n"

    def test_accepting_both_sides_at_one_seq_raises(self) -> None:
        resolution = self.resolution_with_choices(
            {("left", 3): "accept", ("right", 3): "accept", ("right", 4): "reject"}
        )
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=resolution)

    def test_gap_in_the_accepted_chain_raises(self) -> None:
        resolution = self.resolution_with_choices(
            {("left", 3): "reject", ("right", 3): "reject", ("right", 4): "accept"}
        )
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=resolution)

    def test_chain_break_writes_nothing(self) -> None:
        before = read_bytes(self.fork.target_path)
        resolution = self.resolution_with_choices(
            {("left", 3): "accept", ("right", 3): "accept", ("right", 4): "reject"}
        )
        with self.assertRaises(InvalidResolutionError):
            self.commit(resolution=resolution)
        self.assertEqual(read_bytes(self.fork.target_path), before)


if __name__ == "__main__":
    unittest.main()
