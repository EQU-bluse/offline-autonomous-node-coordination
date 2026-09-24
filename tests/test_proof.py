"""Tests for offline audit-range proofs (export_proof/verify_proof)."""

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
    export_proof,
    verify_proof,
)

SECRET = "a" * 64
NOW = 50
RESULT_KEYS = (
    "startSeq",
    "endSeq",
    "firstBefore",
    "lastAfter",
    "signedEntries",
    "unsignedEntries",
)
PROOF_KEYS = (
    "digest",
    "endSeq",
    "entries",
    "firstBefore",
    "lastAfter",
    "startSeq",
    "version",
)
ENTRY_KEYS = ("after", "before", "id", "seq", "source")
AUTHED_ENTRY_KEYS = ("after", "auth", "before", "id", "seq", "source")


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


def keyring():
    return {
        "node-a": [
            {
                "version": 1,
                "secret": SECRET,
                "notBefore": 0,
                "notAfter": 1000,
                "revoked": False,
            }
        ]
    }


def sign(node, key_version, request_obj):
    payload = json.dumps(
        {"keyVersion": key_version, "node": node, "request": request_obj},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(bytes.fromhex(SECRET), payload, hashlib.sha256).hexdigest()


def seed_ledger(path, n=4, signed=()):
    """Apply n commits; seq numbers in ``signed`` go through signed flow."""
    states = []
    cur = state()
    for i in range(1, n + 1):
        nxt = state({"node-a": i}, {"k": record(f"v{i} ☃", i)})
        request_obj = make_request(f"r{i}", cur, nxt)
        if i in signed:
            envelope = {
                "node": "node-a",
                "keyVersion": 1,
                "request": request_obj,
                "signature": sign("node-a", 1, request_obj),
            }
            result = R.apply_signed_remote(path, keyring(), envelope, NOW)
        else:
            result = R.apply_remote(path, request_obj)
        assert result["status"] == "applied", result["status"]
        states.append(nxt)
        cur = nxt
    return cur


def read_ledger(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read())


def reencode(proof_obj):
    """Canonical proof bytes with the digest recomputed from the body."""
    body = {key: value for key, value in proof_obj.items() if key != "digest"}
    proof_obj = dict(proof_obj)
    proof_obj["digest"] = hashlib.sha256(canonical(body)).hexdigest()
    return canonical(proof_obj) + b"\n"


def decoded(proof_bytes):
    return json.loads(proof_bytes)


class ExportProofTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        seed_ledger(self.path, n=4, signed={3})

    def test_full_range_covers_all_entries(self) -> None:
        proof = decoded(export_proof(self.path, 1))
        ledger = read_ledger(self.path)
        self.assertEqual(proof["startSeq"], 1)
        self.assertEqual(proof["endSeq"], 4)
        self.assertEqual(proof["version"], 1)
        self.assertEqual(proof["firstBefore"], ledger["audit"][0]["before"])
        self.assertEqual(proof["lastAfter"], ledger["audit"][-1]["after"])
        self.assertEqual(
            [entry["id"] for entry in proof["entries"]],
            ["r1", "r2", "r3", "r4"],
        )

    def test_explicit_end_selects_prefix(self) -> None:
        proof = decoded(export_proof(self.path, 1, 2))
        self.assertEqual([e["seq"] for e in proof["entries"]], [1, 2])
        self.assertEqual(proof["startSeq"], 1)
        self.assertEqual(proof["endSeq"], 2)

    def test_interior_range(self) -> None:
        proof = decoded(export_proof(self.path, 2, 3))
        ledger = read_ledger(self.path)
        self.assertEqual([e["seq"] for e in proof["entries"]], [2, 3])
        self.assertEqual(proof["firstBefore"], ledger["audit"][1]["before"])
        self.assertEqual(proof["lastAfter"], ledger["audit"][2]["after"])

    def test_single_entry_range(self) -> None:
        proof = decoded(export_proof(self.path, 3, 3))
        self.assertEqual(len(proof["entries"]), 1)
        entry = proof["entries"][0]
        self.assertEqual(entry["seq"], 3)
        self.assertEqual(proof["firstBefore"], entry["before"])
        self.assertEqual(proof["lastAfter"], entry["after"])

    def test_entries_keep_original_values_and_auth_binding(self) -> None:
        proof = decoded(export_proof(self.path, 1))
        ledger_entries = read_ledger(self.path)["audit"]
        self.assertEqual(proof["entries"], ledger_entries)
        self.assertNotIn("auth", proof["entries"][0])
        self.assertEqual(
            proof["entries"][2]["auth"],
            {"keyVersion": 1, "node": "node-a"},
        )

    def test_top_level_keys_sorted_and_complete(self) -> None:
        raw = export_proof(self.path, 1)
        self.assertEqual(tuple(decoded(raw).keys()), PROOF_KEYS)

    def test_entry_keys_sorted(self) -> None:
        proof = decoded(export_proof(self.path, 1))
        self.assertEqual(tuple(proof["entries"][0].keys()), ENTRY_KEYS)
        self.assertEqual(tuple(proof["entries"][2].keys()), AUTHED_ENTRY_KEYS)

    def test_canonical_compact_utf8_with_one_lf(self) -> None:
        # Non-ASCII lives in entry ids/sources; use a unicode commit.
        uni_path = os.path.join(self.dir, "uni.json")
        nxt = state(
            {"node-雪": 1}, {"k": ["v", False, {"node-雪": 1}, "node-雪"]}
        )
        R.apply_remote(
            uni_path, make_request("r-雪", state(), nxt, source="node-雪")
        )
        raw = export_proof(uni_path, 1)
        data = decoded(raw)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(raw, canonical(data) + b"\n")
        self.assertIn("雪".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b': ', raw)

    def test_digest_binds_everything_except_itself(self) -> None:
        raw = export_proof(self.path, 2, 3)
        data = decoded(raw)
        body = {key: value for key, value in data.items() if key != "digest"}
        expected = hashlib.sha256(canonical(body)).hexdigest()
        self.assertEqual(data["digest"], expected)
        self.assertRegex(data["digest"], r"[0-9a-f]{64}")

    def test_export_is_deterministic_and_read_only(self) -> None:
        first = export_proof(self.path, 1)
        with open(self.path, "rb") as handle:
            before = handle.read()
        second = export_proof(self.path, 1)
        with open(self.path, "rb") as handle:
            after = handle.read()
        self.assertEqual(first, second)
        self.assertEqual(before, after)

    def test_fixed_artifacts_never_participate_in_reads(self) -> None:
        with open(self.path + ".tmp", "wb") as handle:
            handle.write(b"interrupted temporary bytes")
        with open(self.path + ".old", "wb") as handle:
            handle.write(b"interrupted predecessor bytes")
        proof = export_proof(self.path, 1)
        self.assertEqual(
            [e["id"] for e in decoded(proof)["entries"]],
            ["r1", "r2", "r3", "r4"],
        )

    def test_missing_ledger_raises_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            export_proof(os.path.join(self.dir, "missing.json"), 1)

    def test_corrupt_ledger_raises_value_error(self) -> None:
        corrupt = os.path.join(self.dir, "corrupt.json")
        with open(corrupt, "wb") as handle:
            handle.write(b"not a ledger\n")
        with self.assertRaises(ValueError):
            export_proof(corrupt, 1)

    def test_empty_audit_cannot_satisfy_request(self) -> None:
        empty_path = os.path.join(self.dir, "empty.json")
        with open(empty_path, "wb") as handle:
            handle.write(R._serialize_ledger(state(), {}, []))
        with self.assertRaises(ValueError):
            export_proof(empty_path, 1)

    def test_other_read_failures_propagate_as_oserror(self) -> None:
        with mock.patch("builtins.open", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                export_proof(self.path, 1)


class ExportProofValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        seed_ledger(self.path, n=3)

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            export_proof(1, 1)
        with self.assertRaises(TypeError):
            export_proof(None, 1)

    def test_start_must_be_int_not_bool(self) -> None:
        with self.assertRaises(TypeError):
            export_proof(self.path, True)
        with self.assertRaises(TypeError):
            export_proof(self.path, 1.0)
        with self.assertRaises(TypeError):
            export_proof(self.path, "1")

    def test_end_must_be_int_or_none_not_bool(self) -> None:
        with self.assertRaises(TypeError):
            export_proof(self.path, 1, True)
        with self.assertRaises(TypeError):
            export_proof(self.path, 1, 2.0)
        with self.assertRaises(TypeError):
            export_proof(self.path, 1, "2")
        # None is the documented default and explicitly allowed.
        export_proof(self.path, 1, None)

    def test_start_below_one_is_value_error(self) -> None:
        with self.assertRaises(ValueError):
            export_proof(self.path, 0)
        with self.assertRaises(ValueError):
            export_proof(self.path, -1)

    def test_inverted_range_is_value_error(self) -> None:
        with self.assertRaises(ValueError):
            export_proof(self.path, 3, 2)

    def test_range_must_lie_inside_audit_sequence(self) -> None:
        with self.assertRaises(ValueError):
            export_proof(self.path, 4)
        with self.assertRaises(ValueError):
            export_proof(self.path, 1, 4)
        with self.assertRaises(ValueError):
            export_proof(self.path, 2, 5)

    def test_validation_runs_before_filesystem(self) -> None:
        with mock.patch("builtins.open") as patched:
            with self.assertRaises(TypeError):
                export_proof(1, 1)
            with self.assertRaises(TypeError):
                export_proof(self.path, True)
            with self.assertRaises(ValueError):
                export_proof(self.path, 0)
            with self.assertRaises(ValueError):
                export_proof(self.path, 2, 1)
        patched.assert_not_called()


class VerifyProofRoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        seed_ledger(self.path, n=4, signed={2, 4})

    def test_full_range_verifies(self) -> None:
        result = verify_proof(export_proof(self.path, 1))
        ledger = read_ledger(self.path)
        self.assertEqual(tuple(result.keys()), RESULT_KEYS)
        self.assertEqual(result["startSeq"], 1)
        self.assertEqual(result["endSeq"], 4)
        self.assertEqual(result["firstBefore"], ledger["audit"][0]["before"])
        self.assertEqual(result["lastAfter"], ledger["audit"][-1]["after"])
        self.assertEqual(result["signedEntries"], 2)
        self.assertEqual(result["unsignedEntries"], 2)

    def test_interior_range_verifies(self) -> None:
        result = verify_proof(export_proof(self.path, 2, 3))
        self.assertEqual(result["startSeq"], 2)
        self.assertEqual(result["endSeq"], 3)
        self.assertEqual(result["signedEntries"], 1)
        self.assertEqual(result["unsignedEntries"], 1)

    def test_single_entry_classes(self) -> None:
        self.assertEqual(
            verify_proof(export_proof(self.path, 1, 1))["signedEntries"], 0
        )
        signed_only = verify_proof(export_proof(self.path, 2, 2))
        self.assertEqual(signed_only["signedEntries"], 1)
        self.assertEqual(signed_only["unsignedEntries"], 0)

    def test_all_unsigned_ledger(self) -> None:
        path = os.path.join(self.dir, "plain.json")
        seed_ledger(path, n=2)
        result = verify_proof(export_proof(path, 1))
        self.assertEqual(result["signedEntries"], 0)
        self.assertEqual(result["unsignedEntries"], 2)

    def test_verification_touches_no_files(self) -> None:
        proof = export_proof(self.path, 1)
        with mock.patch("builtins.open") as patched:
            result = verify_proof(proof)
        patched.assert_not_called()
        self.assertEqual(result["endSeq"], 4)

    def test_invalid_proof_error_is_value_error(self) -> None:
        self.assertTrue(issubclass(InvalidProofError, ValueError))


class VerifyProofRejectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        seed_ledger(self.path, n=4, signed={3})
        self.good = export_proof(self.path, 1)

    def reject(self, raw):
        with self.assertRaises(InvalidProofError):
            verify_proof(raw)

    def test_non_bytes_raises_type_error(self) -> None:
        for bad in (self.good.decode("utf-8"), bytearray(self.good), None, 1, []):
            with self.assertRaises(TypeError):
                verify_proof(bad)

    def test_missing_or_double_newline(self) -> None:
        self.reject(self.good[:-1])
        self.reject(self.good + b"\n")

    def test_garbage_and_empty(self) -> None:
        self.reject(b"garbage\n")
        self.reject(b"\n")
        self.reject(b"\xff\xfe\n")

    def test_not_an_object(self) -> None:
        self.reject(b"[]\n")
        self.reject(b"1\n")
        self.reject(b'"x"\n')

    def test_duplicate_top_level_key(self) -> None:
        text = self.good[:-1].decode("utf-8")
        self.reject(
            text.replace('"version":1', '"version":1,"version":1', 1).encode()
            + b"\n"
        )

    def test_duplicate_nested_key(self) -> None:
        data = decoded(self.good)
        entry = data["entries"][0]
        raw = canonical(data)[:-1]
        marker = canonical(entry)
        doubled = marker[:-1] + b',"source":"node-a"}'
        self.reject(raw.replace(marker, doubled, 1) + b"\n")

    def test_wrong_top_level_key_set(self) -> None:
        data = decoded(self.good)
        del data["digest"]
        self.reject(canonical(data) + b"\n")
        data = decoded(self.good)
        data["extra"] = 1
        self.reject(reencode(data))

    def test_version_faults(self) -> None:
        for bad_version in (2, True, 1.0, "1", None):
            data = decoded(self.good)
            data["version"] = bad_version
            self.reject(reencode(data))

    def test_range_int_type_faults(self) -> None:
        for field in ("startSeq", "endSeq"):
            for bad in (True, 1.0, "1", None):
                data = decoded(self.good)
                data[field] = bad
                self.reject(reencode(data))

    def test_range_value_faults(self) -> None:
        data = decoded(self.good)
        data["startSeq"] = 0
        self.reject(reencode(data))
        data = decoded(self.good)
        data["endSeq"] = 0
        self.reject(reencode(data))
        data = decoded(self.good)
        data["startSeq"], data["endSeq"] = 3, 2
        self.reject(reencode(data))

    def test_boundary_digest_shape(self) -> None:
        for field in ("firstBefore", "lastAfter"):
            for bad in ("", "z" * 64, "0" * 63, "0" * 65, 0, None):
                data = decoded(self.good)
                data[field] = bad
                self.reject(reencode(data))

    def test_entries_must_be_list_and_match_range_count(self) -> None:
        data = decoded(self.good)
        data["entries"] = {}
        self.reject(reencode(data))
        data = decoded(self.good)
        data["entries"] = data["entries"][:-1]  # missing item
        self.reject(reencode(data))
        data = decoded(self.good)
        data["entries"] = data["entries"] + [data["entries"][-1]]  # extra
        self.reject(reencode(data))
        data = decoded(self.good)
        data["startSeq"], data["endSeq"] = 1, 3
        self.reject(reencode(data))

    def test_entry_not_object_or_wrong_keys(self) -> None:
        data = decoded(self.good)
        data["entries"][0] = []
        self.reject(reencode(data))
        data = decoded(self.good)
        del data["entries"][0]["source"]
        self.reject(reencode(data))
        data = decoded(self.good)
        data["entries"][0]["extra"] = 1
        self.reject(reencode(data))

    def test_entry_field_types(self) -> None:
        data = decoded(self.good)
        data["entries"][0]["id"] = ""
        self.reject(reencode(data))
        data = decoded(self.good)
        data["entries"][0]["id"] = 7
        self.reject(reencode(data))
        data = decoded(self.good)
        data["entries"][0]["source"] = ""
        self.reject(reencode(data))
        data = decoded(self.good)
        data["entries"][0]["source"] = 9
        self.reject(reencode(data))

    def test_entry_digest_shapes(self) -> None:
        for field in ("before", "after"):
            data = decoded(self.good)
            data["entries"][0][field] = "Z" * 64
            self.reject(reencode(data))
            data = decoded(self.good)
            data["entries"][0][field] = 5
            self.reject(reencode(data))

    def test_seq_bool_and_type_faults(self) -> None:
        data = decoded(self.good)
        data["entries"][1]["seq"] = True
        self.reject(reencode(data))
        data = decoded(self.good)
        data["entries"][1]["seq"] = "2"
        self.reject(reencode(data))

    def test_missing_duplicate_and_reordered_seqs(self) -> None:
        # Gap (missing seq 2): 1,3,4,4 would also duplicate; craft 1,3,4,5.
        data = decoded(self.good)
        seqs = [entry["seq"] for entry in data["entries"]]
        for entry, new_seq in zip(data["entries"], [1, 3, 4, 5]):
            entry["seq"] = new_seq
        self.reject(reencode(data))
        # Duplicate seq.
        data = decoded(self.good)
        data["entries"][1]["seq"] = 1
        self.reject(reencode(data))
        # Reordered entries without changing seqs: position/seq mismatch.
        data = decoded(self.good)
        data["entries"][0], data["entries"][1] = (
            data["entries"][1],
            data["entries"][0],
        )
        self.reject(reencode(data))

    def test_broken_state_digest_chain(self) -> None:
        data = decoded(self.good)
        data["entries"][1]["before"] = "f" * 64
        self.reject(reencode(data))

    def test_first_boundary_must_match_first_entry(self) -> None:
        data = decoded(self.good)
        data["firstBefore"] = "e" * 64
        self.reject(reencode(data))

    def test_last_boundary_must_match_last_entry(self) -> None:
        data = decoded(self.good)
        data["lastAfter"] = "d" * 64
        self.reject(reencode(data))

    def test_tampered_id_detected_via_digest(self) -> None:
        # Mutate an id without recomputing the digest: pure tampering.
        raw = bytearray(self.good)
        position = raw.find(b'"id":"r2"')
        self.assertGreater(position, 0)
        raw[position + 7:position + 9] = b"xx"
        self.reject(bytes(raw))

    def test_digest_wrong_type(self) -> None:
        data = decoded(self.good)
        data["digest"] = 1
        self.reject(canonical(data) + b"\n")

    def test_digest_shape_faults_never_raise_type_error(self) -> None:
        # A 64-char non-ASCII/non-hex string is the case hmac.compare_digest
        # would reject with TypeError on two str inputs; it must surface as
        # InvalidProofError instead.
        for bad in ("z" * 64, "0" * 63, "雪" * 32, None, 1, True):
            data = decoded(self.good)
            data["digest"] = bad
            try:
                verify_proof(canonical(data) + b"\n")
            except InvalidProofError:
                pass
            else:
                self.fail(f"digest {bad!r} was accepted")

    def test_auth_binding_faults(self) -> None:
        signed_index = 2  # r3 is the signed entry

        def mutate(fn):
            data = decoded(self.good)
            fn(data["entries"][signed_index])
            self.reject(reencode(data))

        mutate(lambda e: e["auth"].pop("node"))
        mutate(lambda e: e["auth"].pop("keyVersion"))
        mutate(lambda e: e["auth"].update(extra=1))
        mutate(lambda e: e["auth"].update(node=""))
        mutate(lambda e: e["auth"].update(node=4))
        mutate(lambda e: e["auth"].update(keyVersion=0))
        mutate(lambda e: e["auth"].update(keyVersion=-1))
        mutate(lambda e: e["auth"].update(keyVersion=True))
        mutate(lambda e: e["auth"].update(keyVersion=1.0))
        mutate(lambda e: e.__setitem__("auth", []))

    def test_non_canonical_encoding_rejected(self) -> None:
        text = self.good[:-1].decode("utf-8")
        self.reject(text.replace('{"digest"', '{ "digest"', 1).encode() + b"\n")
        # A permuted top-level key order: the semantic digest still
        # matches, so only the canonical-byte check can reject it.
        data = decoded(self.good)
        reordered = {key: data[key] for key in reversed(PROOF_KEYS)}
        permuted = (
            json.dumps(reordered, ensure_ascii=False, separators=(",", ":"))
            .encode("utf-8")
            + b"\n"
        )
        self.reject(permuted)
        # Permuted entry keys are non-canonical as well.
        data = decoded(self.good)
        entry = data["entries"][0]
        data["entries"][0] = {
            key: entry[key] for key in reversed(ENTRY_KEYS)
        }
        self.reject(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
            + b"\n"
        )
        # Escaped non-ASCII is not the unescaped canonical form.
        self.reject(
            json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode()
            + b"\n"
        )


class ProofTransactionFileTest(unittest.TestCase):
    """The unique-transaction-file hardening behind ledger commits."""

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"node-a": 1}, {"k": record("v1", 1)})
        self.s2 = state({"node-a": 2}, {"k": record("v2", 2)})
        self.s3 = state({"node-a": 3}, {"k": record("v3", 3)})
        R.apply_remote(self.path, make_request("r1", state(), self.s1))

    def advance(self, rid="r2", base=None, remote=None):
        return R.apply_remote(
            self.path,
            make_request(rid, self.s1 if base is None else base,
                         self.s2 if remote is None else remote),
        )

    def artifacts(self):
        return sorted(
            name
            for name in os.listdir(self.dir)
            if name.startswith(os.path.basename(self.path))
        )

    def test_stale_fixed_artifacts_swept_and_commit_succeeds(self) -> None:
        with open(self.path + ".tmp", "wb") as handle:
            handle.write(b"stale temporary")
        with open(self.path + ".old", "wb") as handle:
            handle.write(b"stale predecessor")
        result = self.advance()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(self.artifacts(), [os.path.basename(self.path)])
        self.assertEqual(
            R.apply_remote(
                self.path, make_request("r2", self.s1, self.s2)
            )["status"],
            "duplicate",
        )

    def test_sweep_failure_cannot_block_a_valid_commit(self) -> None:
        with open(self.path + ".tmp", "wb") as handle:
            handle.write(b"stale temporary")
        with mock.patch("os.unlink", side_effect=OSError("denied")):
            result = self.advance()
        self.assertEqual(result["status"], "applied")
        with open(self.path, "rb") as handle:
            ledger = json.loads(handle.read())
        self.assertEqual([e["seq"] for e in ledger["audit"]], [1, 2])

    def test_stale_fixed_artifacts_on_missing_ledger(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        with open(fresh + ".tmp", "wb") as handle:
            handle.write(b"x")
        with open(fresh + ".old", "wb") as handle:
            handle.write(b"y")
        result = R.apply_remote(fresh, make_request("r1", state(), self.s1))
        self.assertEqual(result["status"], "applied")
        self.assertFalse(os.path.exists(fresh + ".tmp"))
        self.assertFalse(os.path.exists(fresh + ".old"))

    def test_concurrent_commits_use_distinct_transaction_names(self) -> None:
        used = set()
        real_open = open

        def watch_open(target, *args, **kwargs):
            if isinstance(target, str) and ".tmp." in os.path.basename(target):
                used.add(target)
            return real_open(target, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=watch_open):
            self.advance("r2", self.s1, self.s2)
            self.advance("r3", self.s2, self.s3)
        # Each commit reserves its own unique random temporary name rather
        # than the fixed path + ".tmp".
        self.assertEqual(len(used), 2)
        self.assertNotIn(self.path + ".tmp", used)

    def test_failure_still_restores_original_bytes(self) -> None:
        with open(self.path, "rb") as handle:
            before = handle.read()
        with mock.patch("os.replace", side_effect=OSError("rename failed")):
            with self.assertRaises(OSError):
                self.advance()
        with open(self.path, "rb") as handle:
            self.assertEqual(handle.read(), before)
        # Only the ledger itself remains: no random artifacts either.
        self.assertEqual(self.artifacts(), [os.path.basename(self.path)])


if __name__ == "__main__":
    unittest.main()
