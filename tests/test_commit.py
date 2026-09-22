import hashlib
import json
import os
import pathlib
import tempfile
import unittest

from offline_coordination import audit as audit_mod
from offline_coordination import receipt as receipt_mod
from offline_coordination import storage as storage_mod
from offline_coordination.transaction import (
    CorruptTransactionError,
    checkpoint,
    commit,
)


def make_state(value="v"):
    return {
        "clock": {"n1": 1},
        "records": {"k": [value, False, {"n1": 1}, "n1"]},
    }


def make_event(kind="merge", source="n1", detail="did-a-thing"):
    return {"kind": kind, "source": source, "detail": detail}


def canonical_state_digest(state):
    text = (
        json.dumps(state, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"))
        + "\n"
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CommitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.paths = {
            "checkpoint": os.path.join(self.dir, "checkpoints.json"),
            "state": os.path.join(self.dir, "state.json"),
            "audit": os.path.join(self.dir, "audit.jsonl"),
            "receipt": os.path.join(self.dir, "receipts.json"),
        }
        self.state = make_state()
        self.event = make_event()
        self.request = {"id": "tx-1", "state": self.state,
                        "event": self.event}

    def read(self, key):
        with open(self.paths[key], "rb") as handle:
            return handle.read()

    def commit_once(self):
        return commit(self.paths, self.request)

    def test_first_commit_writes_all_artifacts_and_returns_record(self) -> None:
        result = self.commit_once()

        self.assertEqual(
            tuple(result.keys()), ("audit", "id", "stage", "state")
        )
        self.assertEqual(result["id"], "tx-1")
        self.assertEqual(result["stage"], "committed")
        self.assertEqual(
            result["state"], canonical_state_digest(self.state)
        )

        # State file holds the canonical bytes including one trailing LF.
        raw_state = self.read("state")
        self.assertTrue(raw_state.endswith(b"\n"))
        self.assertFalse(raw_state.endswith(b"\n\n"))
        self.assertEqual(
            result["state"], hashlib.sha256(raw_state).hexdigest()
        )
        self.assertEqual(storage_mod.load_state(self.paths["state"]),
                         self.state)

        # Exactly one audit record whose hash is the returned audit digest.
        records = audit_mod.read(self.paths["audit"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["hash"], result["audit"])
        self.assertEqual(records[0]["kind"], "merge")
        self.assertEqual(records[0]["source"], "n1")
        self.assertEqual(records[0]["detail"], "did-a-thing")
        self.assertEqual(records[0]["seq"], 1)

        # Receipt binds the id to both digests.
        self.assertEqual(
            receipt_mod.get(self.paths["receipt"], "tx-1"),
            {"audit": result["audit"], "id": "tx-1",
             "state": result["state"]},
        )

        # The checkpoint is committed with both digests.
        cp = next(c for c in checkpoint(self.paths["checkpoint"])
                  if c["id"] == "tx-1")
        self.assertEqual(cp["stage"], "committed")
        self.assertEqual(cp["state"], result["state"])
        self.assertEqual(cp["audit"], result["audit"])

    def test_result_is_a_fresh_dict_each_call(self) -> None:
        first = self.commit_once()
        second = commit(self.paths, self.request)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_replay_is_identical_and_has_no_extra_side_effects(self) -> None:
        first = self.commit_once()
        before = {key: self.read(key) for key in self.paths}
        # The first commit also produced a backup; capture it.
        backup = self.paths["state"] + ".bak"
        self.assertFalse(os.path.exists(backup))

        second = commit(self.paths, self.request)
        self.assertEqual(second, first)
        for key in self.paths:
            self.assertEqual(self.read(key), before[key], f"{key} changed")
        self.assertEqual(len(audit_mod.read(self.paths["audit"])), 1)

    def test_second_commit_chains_audit_and_overwrites_state(self) -> None:
        self.commit_once()
        state2 = make_state("w")
        event2 = make_event(kind="local", source="n2", detail="second")
        result2 = commit(
            self.paths, {"id": "tx-2", "state": state2, "event": event2}
        )

        records = audit_mod.read(self.paths["audit"])
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["seq"], 2)
        self.assertEqual(records[1]["prev"], records[0]["hash"])
        self.assertEqual(records[1]["hash"], result2["audit"])
        self.assertEqual(
            receipt_mod.get(self.paths["receipt"], "tx-2"),
            {"audit": result2["audit"], "id": "tx-2",
             "state": result2["state"]},
        )
        self.assertEqual(storage_mod.load_state(self.paths["state"]), state2)
        stages = {c["id"]: c["stage"]
                  for c in checkpoint(self.paths["checkpoint"])}
        self.assertEqual(stages, {"tx-1": "committed", "tx-2": "committed"})

    def test_state_digest_conflict_rejected_and_files_untouched(self) -> None:
        self.commit_once()
        before = {key: self.read(key) for key in self.paths}
        other = make_state("different")
        with self.assertRaises(ValueError):
            commit(self.paths, {"id": "tx-1", "state": other,
                                "event": self.event})
        for key in self.paths:
            self.assertEqual(self.read(key), before[key])
        self.assertEqual(len(audit_mod.read(self.paths["audit"])), 1)

    def test_receipt_conflict_rejected_before_any_write(self) -> None:
        # Pre-bind the id to foreign digests; commit must reject and append
        # nothing to the audit log.
        foreign = "f" * 64
        receipt_mod.put(
            self.paths["receipt"],
            {"id": "tx-1", "state": foreign, "audit": foreign},
        )
        with self.assertRaises(ValueError):
            self.commit_once()
        self.assertFalse(os.path.exists(self.paths["audit"]))
        self.assertFalse(os.path.exists(self.paths["state"]))
        self.assertFalse(os.path.exists(self.paths["checkpoint"]))


class CommitRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.paths = {
            "checkpoint": os.path.join(self.dir, "checkpoints.json"),
            "state": os.path.join(self.dir, "state.json"),
            "audit": os.path.join(self.dir, "audit.jsonl"),
            "receipt": os.path.join(self.dir, "receipts.json"),
        }
        self.state = make_state()
        self.event = make_event()
        self.state_digest = canonical_state_digest(self.state)

    def audit_digest(self):
        records = audit_mod.read(self.paths["audit"])
        seq = len(records) + 1
        prev = records[-1]["hash"] if records else "0" * 64
        return audit_mod._record_hash(
            {
                "detail": self.event["detail"],
                "kind": self.event["kind"],
                "prev": prev,
                "seq": seq,
                "source": self.event["source"],
            }
        )

    def resume_to(self, stage, persist_artifact=True):
        cp = self.paths["checkpoint"]
        ad = self.audit_digest()
        req = {"id": "c", "state": self.state_digest, "audit": ad}
        from offline_coordination.transaction import resume
        resume(cp, req)
        if stage == "prepared":
            return ad
        if persist_artifact:
            storage_mod.save_state(self.paths["state"], self.state)
        resume(cp, req, "state")
        if stage == "state":
            return ad
        if persist_artifact:
            audit_mod.append(self.paths["audit"], self.event)
        resume(cp, req, "audit")
        if stage == "audit":
            return ad
        if persist_artifact:
            receipt_mod.put(
                self.paths["receipt"],
                {"id": "c", "state": self.state_digest, "audit": ad},
            )
        resume(cp, req, "committed")
        return ad

    def request(self):
        return {"id": "c", "state": self.state, "event": self.event}

    def assert_committed_once(self, result, ad):
        self.assertEqual(result["stage"], "committed")
        self.assertEqual(result["state"], self.state_digest)
        self.assertEqual(result["audit"], ad)
        self.assertEqual(len(audit_mod.read(self.paths["audit"])), 1)

    def test_resume_from_prepared(self) -> None:
        ad = self.resume_to("prepared")
        result = commit(self.paths, self.request())
        self.assert_committed_once(result, ad)

    def test_resume_from_state_stage(self) -> None:
        ad = self.resume_to("state")
        result = commit(self.paths, self.request())
        self.assert_committed_once(result, ad)

    def test_resume_from_audit_stage(self) -> None:
        ad = self.resume_to("audit")
        result = commit(self.paths, self.request())
        self.assert_committed_once(result, ad)

    def test_recovering_committed_is_idempotent(self) -> None:
        ad = self.resume_to("committed")

        def snapshot():
            return {key: pathlib.Path(path).read_bytes()
                    for key, path in self.paths.items()}

        before = snapshot()
        result = commit(self.paths, self.request())
        self.assert_committed_once(result, ad)
        self.assertEqual(snapshot(), before)

    def test_state_artifact_missing_past_prepared_is_conflict(self) -> None:
        # Checkpoint at 'state' but the state file was lost.
        self.resume_to("state", persist_artifact=False)
        with self.assertRaises(ValueError):
            commit(self.paths, self.request())

    def test_audit_artifact_missing_past_audit_stage_is_conflict(self) -> None:
        # Checkpoint at 'audit' but the audit record was never appended.
        self.resume_to("audit", persist_artifact=False)
        with self.assertRaises(ValueError):
            commit(self.paths, self.request())

    def test_event_change_after_prepare_is_digest_conflict(self) -> None:
        self.resume_to("prepared")
        changed = dict(self.event)
        changed["detail"] = "tampered"
        with self.assertRaises(ValueError):
            commit(self.paths,
                   {"id": "c", "state": self.state, "event": changed})
        self.assertFalse(os.path.exists(self.paths["audit"]))


class CommitValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.paths = {
            "checkpoint": os.path.join(self.dir, "checkpoints.json"),
            "state": os.path.join(self.dir, "state.json"),
            "audit": os.path.join(self.dir, "audit.jsonl"),
            "receipt": os.path.join(self.dir, "receipts.json"),
        }
        self.request = {"id": "v", "state": make_state(),
                        "event": make_event()}

    def assertNothingWritten(self):
        for path in self.paths.values():
            self.assertFalse(os.path.exists(path))

    def test_paths_must_be_dict(self) -> None:
        for bad in ([], 1, "x", None):
            with self.assertRaises(TypeError, msg=f"paths={bad!r}"):
                commit(bad, self.request)

    def test_paths_key_set(self) -> None:
        missing = dict(self.paths)
        del missing["receipt"]
        with self.assertRaises(ValueError):
            commit(missing, self.request)
        with self.assertRaises(ValueError):
            commit({**self.paths, "extra": "p"}, self.request)

    def test_paths_values_must_be_str(self) -> None:
        for key in self.paths:
            bad = dict(self.paths)
            bad[key] = 1
            with self.assertRaises(TypeError, msg=f"key={key}"):
                commit(bad, self.request)

    def test_request_must_be_dict(self) -> None:
        for bad in ([], 1, "x", None):
            with self.assertRaises(TypeError, msg=f"request={bad!r}"):
                commit(self.paths, bad)

    def test_request_key_set(self) -> None:
        with self.assertRaises(ValueError):
            commit(self.paths, {"id": "v", "state": make_state()})
        with self.assertRaises(ValueError):
            commit(self.paths, {"id": "v", "event": make_event()})
        with self.assertRaises(ValueError):
            commit(self.paths, {**self.request, "extra": 1})

    def test_id_type_and_format(self) -> None:
        with self.assertRaises(TypeError):
            commit(self.paths, {**self.request, "id": 1})
        for bad in ("", "a/b", "x" * 65, "a b"):
            with self.assertRaises(ValueError, msg=f"id={bad!r}"):
                commit(self.paths, {**self.request, "id": bad})

    def test_state_contract(self) -> None:
        bad_deleted = {"clock": {"n1": 1},
                       "records": {"k": ["v", True, {"n1": 1}, "n1"]}}
        with self.assertRaises(ValueError):
            commit(self.paths, {**self.request, "state": bad_deleted})
        bad_type = ["not", "a", "state", "dict"]
        with self.assertRaises(TypeError):
            commit(self.paths, {**self.request, "state": bad_type})

    def test_event_contract(self) -> None:
        with self.assertRaises(ValueError):
            commit(self.paths, {
                **self.request,
                "event": {"kind": "bogus", "source": "n", "detail": "d"},
            })
        with self.assertRaises(TypeError):
            commit(self.paths, {
                **self.request,
                "event": {"kind": "merge", "source": "n", "detail": 1},
            })

    def test_validation_precedes_filesystem(self) -> None:
        with self.assertRaises(ValueError):
            commit(self.paths, {**self.request, "id": "bad/id"})
        self.assertNothingWritten()


class CommitCorruptionPropagationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.paths = {
            "checkpoint": os.path.join(self.dir, "checkpoints.json"),
            "state": os.path.join(self.dir, "state.json"),
            "audit": os.path.join(self.dir, "audit.jsonl"),
            "receipt": os.path.join(self.dir, "receipts.json"),
        }

    def corrupt(self, key, payload=b""):
        with open(self.paths[key], "wb") as handle:
            handle.write(payload)

    def test_corrupt_checkpoint_propagates(self) -> None:
        self.corrupt("checkpoint")
        with self.assertRaises(CorruptTransactionError):
            commit(self.paths,
                   {"id": "x", "state": make_state(), "event": make_event()})

    def test_corrupt_audit_propagates(self) -> None:
        self.corrupt("audit", b"not json\n")
        with self.assertRaises(audit_mod.CorruptAuditError):
            commit(self.paths,
                   {"id": "x", "state": make_state(), "event": make_event()})

    def test_corrupt_receipt_propagates(self) -> None:
        self.corrupt("receipt")
        with self.assertRaises(receipt_mod.CorruptReceiptError):
            commit(self.paths,
                   {"id": "x", "state": make_state(), "event": make_event()})


if __name__ == "__main__":
    unittest.main()
