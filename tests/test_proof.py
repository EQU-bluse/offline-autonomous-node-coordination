import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication
from offline_coordination import proof as proof_module
from offline_coordination.proof import InvalidProofError, export_proof, verify_proof

NOW = 50
SECRET_A = "a" * 64


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, clock, writer="node-a", deleted=False):
    return [value, deleted, dict(clock), writer]


def request(rid, source="node-a", base=None, remote=None):
    return {
        "id": rid,
        "source": source,
        "base": state() if base is None else base,
        "remote": state() if remote is None else remote,
    }


def sign(secret, node, key_version, request_obj):
    payload = json.dumps(
        {"keyVersion": key_version, "node": node, "request": request_obj},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(bytes.fromhex(secret), payload, hashlib.sha256).hexdigest()


def signed_envelope(request_obj, node="node-a", key_version=1, secret=SECRET_A):
    return {
        "node": node,
        "keyVersion": key_version,
        "request": request_obj,
        "signature": sign(secret, node, key_version, request_obj),
    }


def keyring_entry(version=1, secret=SECRET_A):
    return {
        "version": version,
        "secret": secret,
        "notBefore": 0,
        "notAfter": 100,
        "revoked": False,
    }


def read_ledger(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read())


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def body_digest(data: dict) -> str:
    body = {key: value for key, value in data.items() if key != "digest"}
    return hashlib.sha256(canonical(body)).hexdigest()


def redigest(data: dict) -> bytes:
    data["digest"] = body_digest(data)
    return canonical(data) + b"\n"


class ProofFixture(unittest.TestCase):
    """Builds a three-entry ledger: unsigned, authenticated, unsigned."""

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"node-a": 1}, {"k": record("v1", {"node-a": 1})})
        self.s2 = state({"node-a": 2}, {"k": record("v2", {"node-a": 2})})
        self.s3 = state({"node-a": 3}, {"k": record("v3", {"node-a": 3})})
        replication.apply_remote(self.path, request("r1", remote=self.s1))
        ring = {"node-a": [keyring_entry()]}
        replication.apply_signed_remote(
            self.path,
            ring,
            signed_envelope(request("r2", base=self.s1, remote=self.s2)),
            NOW,
        )
        replication.apply_remote(
            self.path, request("r3", base=self.s2, remote=self.s3)
        )
        self.entries = read_ledger(self.path)["audit"]

    def ledger_digests(self, seq):
        entry = self.entries[seq - 1]
        return entry["before"], entry["after"]


class ExportProofTest(ProofFixture):
    def test_default_end_covers_to_last_entry(self) -> None:
        data = json.loads(export_proof(self.path, 1))
        self.assertEqual((data["start"], data["end"]), (1, 3))
        self.assertEqual([e["seq"] for e in data["entries"]], [1, 2, 3])
        self.assertEqual(data["version"], 1)

    def test_explicit_partial_range(self) -> None:
        data = json.loads(export_proof(self.path, 2, 2))
        self.assertEqual((data["start"], data["end"]), (2, 2))
        self.assertEqual([e["id"] for e in data["entries"]], ["r2"])

    def test_start_minimum_is_one(self) -> None:
        data = json.loads(export_proof(self.path, 1))
        self.assertEqual(data["start"], 1)

    def test_entries_are_verbatim_ledger_entries(self) -> None:
        data = json.loads(export_proof(self.path, 1))
        self.assertEqual(data["entries"], self.entries)
        self.assertEqual(tuple(data["entries"][0].keys()),
                         ("after", "before", "id", "seq", "source"))
        self.assertEqual(
            tuple(data["entries"][1].keys()),
            ("after", "auth", "before", "id", "seq", "source"),
        )
        self.assertEqual(data["entries"][1]["auth"],
                         {"keyVersion": 1, "node": "node-a"})
        self.assertNotIn("auth", data["entries"][0])
        self.assertNotIn("auth", data["entries"][2])

    def test_proof_is_compact_sorted_json_with_one_lf(self) -> None:
        raw = export_proof(self.path, 1)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        data = json.loads(raw)
        self.assertEqual(
            tuple(data.keys()),
            ("after", "before", "digest", "end", "entries", "start",
             "version"),
        )
        self.assertEqual(raw, canonical(data) + b"\n")

    def test_declared_boundaries_match_entries(self) -> None:
        data = json.loads(export_proof(self.path, 2, 3))
        self.assertEqual(data["before"], self.entries[1]["before"])
        self.assertEqual(data["after"], self.entries[2]["after"])

    def test_non_ascii_is_preserved_unescaped(self) -> None:
        path = os.path.join(self.dir, "snow.json")
        replication.apply_remote(
            path,
            request("请求-雪", source="节点", remote=self.s1),
        )
        raw = export_proof(path, 1)
        self.assertIn("雪".encode("utf-8"), raw)
        self.assertIn("节点".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        self.assertEqual(verify_proof(raw)[1][0],
                         read_ledger(path)["audit"][0]["before"])

    def test_digest_binds_body_excluding_digest_and_no_newline(self) -> None:
        raw = export_proof(self.path, 2, 3)
        data = json.loads(raw)
        self.assertEqual(data["digest"], body_digest(data))
        # The hashed bytes are the body without the trailing newline:
        # including it must produce a different, rejected digest.
        body = {key: value for key, value in data.items() if key != "digest"}
        with_newline = hashlib.sha256(canonical(body) + b"\n").hexdigest()
        self.assertNotEqual(with_newline, data["digest"])

    def test_range_fully_inside_ledger(self) -> None:
        for start, end in ((1, 1), (1, 2), (2, 3), (3, 3)):
            data = json.loads(export_proof(self.path, start, end))
            self.assertEqual([e["seq"] for e in data["entries"]],
                             list(range(start, end + 1)))

    def test_is_strictly_read_only(self) -> None:
        with open(self.path, "rb") as handle:
            before = handle.read()
        mtime = os.stat(self.path).st_mtime_ns
        export_proof(self.path, 1, 3)
        export_proof(self.path, 1)
        with open(self.path, "rb") as handle:
            self.assertEqual(handle.read(), before)
        self.assertEqual(os.stat(self.path).st_mtime_ns, mtime)
        self.assertEqual(
            [n for n in os.listdir(self.dir) if n.endswith((".tmp", ".old"))
             or ".tmp-" in n or ".old-" in n],
            [],
        )

    def test_only_read_mode_is_used(self) -> None:
        real_open = open
        modes = []

        def recording_open(path, mode="r", *args, **kwargs):
            modes.append(mode)
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=recording_open):
            export_proof(self.path, 1)
        self.assertEqual(modes, ["rb"])

    def test_fixed_tmp_old_leftovers_are_ignored_and_untouched(self) -> None:
        with open(self.path + ".tmp", "wb") as handle:
            handle.write(b"stale temp\n")
        with open(self.path + ".old", "wb") as handle:
            handle.write(b"stale old\n")
        raw = export_proof(self.path, 1)
        self.assertEqual(verify_proof(raw)[0], (1, 3))
        with open(self.path + ".tmp", "rb") as handle:
            self.assertEqual(handle.read(), b"stale temp\n")
        with open(self.path + ".old", "rb") as handle:
            self.assertEqual(handle.read(), b"stale old\n")

    def test_missing_ledger_raises_filenotfound(self) -> None:
        missing = os.path.join(self.dir, "absent.json")
        with self.assertRaises(FileNotFoundError):
            export_proof(missing, 1)
        self.assertFalse(os.path.exists(missing))

    def test_empty_audit_cannot_satisfy_request(self) -> None:
        path = os.path.join(self.dir, "empty-audit.json")
        ledger = {
            "audit": [],
            "requests": {},
            "state": state(),
            "version": 1,
        }
        with open(path, "wb") as handle:
            handle.write(canonical(ledger) + b"\n")
        # Sanity: the bytes are a valid ledger, just one with no entries.
        with open(path, "rb") as handle:
            self.assertEqual(replication._parse_ledger(handle.read())[2], [])
        with self.assertRaises(ValueError):
            export_proof(path, 1)

    def test_corrupt_ledger_raises_value_error(self) -> None:
        path = os.path.join(self.dir, "corrupt.json")
        with open(path, "wb") as handle:
            handle.write(b"not json at all\n")
        with self.assertRaises(ValueError):
            export_proof(path, 1)

    def test_other_read_failure_propagates_as_oserror(self) -> None:
        with self.assertRaises(OSError):
            export_proof(self.dir, 1)


class ExportProofValidationTest(ProofFixture):
    def test_path_type(self) -> None:
        with self.assertRaises(TypeError):
            export_proof(1, 1)

    def test_start_types(self) -> None:
        for bad in (True, False, "1", 1.0, None):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    export_proof(self.path, bad)

    def test_end_types(self) -> None:
        for bad in (True, False, "1", 1.0):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    export_proof(self.path, 1, bad)

    def test_start_below_one(self) -> None:
        with self.assertRaises(ValueError):
            export_proof(self.path, 0)
        with self.assertRaises(ValueError):
            export_proof(self.path, -3)

    def test_end_before_start(self) -> None:
        with self.assertRaises(ValueError):
            export_proof(self.path, 3, 2)

    def test_range_beyond_ledger(self) -> None:
        with self.assertRaises(ValueError):
            export_proof(self.path, 4)
        with self.assertRaises(ValueError):
            export_proof(self.path, 1, 4)

    def test_validation_runs_before_filesystem(self) -> None:
        with mock.patch("builtins.open") as patched:
            with self.assertRaises(TypeError):
                export_proof(self.path, True)
            with self.assertRaises(ValueError):
                export_proof(self.path, 0)
        patched.assert_not_called()


class VerifyProofSuccessTest(ProofFixture):
    def test_full_range_result(self) -> None:
        result = verify_proof(export_proof(self.path, 1))
        self.assertEqual(result[0], (1, 3))
        fb1, la3 = self.ledger_digests(1)[0], self.ledger_digests(3)[1]
        self.assertEqual(result[1], (fb1, la3))
        self.assertEqual(result[2], (2, 1))

    def test_partial_range_result(self) -> None:
        result = verify_proof(export_proof(self.path, 2, 2))
        self.assertEqual(result[0], (2, 2))
        self.assertEqual(
            result[1], (self.entries[1]["before"], self.entries[1]["after"])
        )
        self.assertEqual(result[2], (0, 1))

    def test_unsigned_only_proof(self) -> None:
        path = os.path.join(self.dir, "plain.json")
        replication.apply_remote(path, request("q1", remote=self.s1))
        replication.apply_remote(
            path, request("q2", base=self.s1, remote=self.s2)
        )
        result = verify_proof(export_proof(path, 1))
        self.assertEqual(result[0], (1, 2))
        self.assertEqual(result[2], (2, 0))

    def test_does_not_read_any_file(self) -> None:
        raw = export_proof(self.path, 1)
        with mock.patch("builtins.open") as patched:
            result = verify_proof(raw)
        patched.assert_not_called()
        self.assertEqual(result[0], (1, 3))

    def test_invalid_proof_error_is_value_error(self) -> None:
        self.assertTrue(issubclass(InvalidProofError, ValueError))


class VerifyProofTypeTest(unittest.TestCase):
    def test_only_bytes_accepted(self) -> None:
        for bad in (None, "str", 1, 1.5, [], {}, bytearray(b"x")):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    verify_proof(bad)


class VerifyProofMalformedTest(ProofFixture):
    """Every byte/structure/content fault raises InvalidProofError."""

    def setUp(self) -> None:
        super().setUp()
        self.good = export_proof(self.path, 1)
        self.good_data = json.loads(self.good)

    def raw(self, data: dict, *, digest: bool = True) -> bytes:
        return redigest(data) if digest else canonical(data) + b"\n"

    def rehash(self, modified: bytes) -> bytes:
        """Recompute a consistent digest for already-modified proof bytes.

        The digest is taken over the sorted canonical body of the parsed
        content, so structural byte deviations (key permutations) remain
        detectable only by the canonical-encoding check.
        """
        parsed = json.loads(modified)
        old_hex = parsed["digest"]
        body = {key: value for key, value in parsed.items() if key != "digest"}
        new_hex = hashlib.sha256(canonical(body)).hexdigest()
        return modified.replace(
            ('"digest":"' + old_hex + '"').encode("utf-8"),
            ('"digest":"' + new_hex + '"').encode("utf-8"),
            1,
        )

    def assertInvalid(self, raw: bytes) -> None:  # noqa: N802
        with self.assertRaises(InvalidProofError):
            verify_proof(raw)

    def test_empty_and_terminator_faults(self) -> None:
        self.assertInvalid(b"")
        self.assertInvalid(self.good[:-1])
        self.assertInvalid(self.good + b"\n")

    def test_encoding_faults(self) -> None:
        self.assertInvalid(b"\xff\xfe\n")
        self.assertInvalid(b"[]\n")
        self.assertInvalid(b"null\n")
        self.assertInvalid(b'{"digest":1}\n')
        self.assertInvalid(self.good.replace(b'"digest":"', b'"digest2":"', 1))
        # Trailing content past the object.
        self.assertInvalid(self.good + b"x")
        # BOM is not part of the canonical form.
        self.assertInvalid(b"\xef\xbb\xbf" + self.good)

    def test_whitespace_and_noncompact_forms(self) -> None:
        text = self.good[:-1].decode("utf-8")
        self.assertInvalid((text[:1] + " " + text[1:] + "\n").encode("utf-8"))
        self.assertInvalid(self.good.replace(b":", b": ", 1))
        # Non-canonical ASCII escaping of a non-ASCII id.
        path = os.path.join(self.dir, "snow.json")
        replication.apply_remote(path, request("雪", remote=self.s1))
        raw = export_proof(path, 1)
        data = json.loads(raw)
        escaped = json.dumps(data, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        self.assertInvalid(escaped + b"\n")

    def test_duplicate_json_keys(self) -> None:
        text = self.good[:-1].decode("utf-8")
        self.assertInvalid(text.replace('"version":1', '"version":1,"version":1',
                                        1).encode("utf-8") + b"\n")

    def test_key_set_and_order_faults(self) -> None:
        data = json.loads(self.good)
        extra = dict(data)
        extra["bogus"] = 1
        self.assertInvalid(self.raw(extra))
        for key in ("after", "before", "end", "entries", "start", "version"):
            missing = {k: v for k, v in data.items() if k != key}
            self.assertInvalid(self.raw(missing))
        # A missing digest fails the key-set check before any hash math;
        # do not re-add one here.
        missing_digest = {k: v for k, v in data.items() if k != "digest"}
        self.assertInvalid(canonical(missing_digest) + b"\n")
        # Permuted top-level keys (re-digested so key order is the fault).
        self.assertInvalid(self._permuted(data))

    def _permuted(self, data: dict) -> bytes:
        # Insertion order deliberately deviates from the canonical order;
        # the digest stays consistent with the sorted canonical body so
        # key order is the only fault.
        out = {
            "version": data["version"],
            "start": data["start"],
            "end": data["end"],
            "before": data["before"],
            "after": data["after"],
            "digest": data["digest"],
            "entries": data["entries"],
        }
        body = {key: value for key, value in data.items() if key != "digest"}
        out["digest"] = hashlib.sha256(canonical(body)).hexdigest()
        return json.dumps(
            out, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8") + b"\n"

    def test_version_faults(self) -> None:
        for bad in (2, 0, "1", True, None, 1.0):
            data = json.loads(self.good)
            data["version"] = bad
            self.assertInvalid(self.raw(data))

    def test_boundary_faults(self) -> None:
        for field in ("start", "end"):
            for bad in ("1", True, 1.0, None):
                data = json.loads(self.good)
                data[field] = bad
                self.assertInvalid(self.raw(data))
        data = json.loads(self.good)
        data["start"] = 0
        self.assertInvalid(self.raw(data))
        data = json.loads(self.good)
        data["end"] = 0
        self.assertInvalid(self.raw(data))

    def test_digest_shape(self) -> None:
        for bad in ("A" * 64, "a" * 63, "g" * 64, 1, None):
            data = json.loads(self.good)
            data["digest"] = bad
            self.assertInvalid(self.raw(data, digest=False))

    def test_declared_boundary_shape(self) -> None:
        for field in ("before", "after"):
            for bad in ("A" * 64, "a" * 63, "g" * 64, 1, None):
                data = json.loads(self.good)
                data[field] = bad
                self.assertInvalid(self.raw(data))

    def test_declared_boundary_mismatch_even_when_re_digested(self) -> None:
        data = json.loads(self.good)
        data["before"] = "f" * 64
        self.assertInvalid(self.raw(data))
        data = json.loads(self.good)
        data["after"] = "e" * 64
        self.assertInvalid(self.raw(data))

    def test_entries_container_faults(self) -> None:
        data = json.loads(self.good)
        data["entries"] = []
        self.assertInvalid(self.raw(data))
        data = json.loads(self.good)
        data["entries"] = {}
        self.assertInvalid(self.raw(data))
        # Length must equal end - start + 1.
        data = json.loads(self.good)
        data["entries"] = data["entries"][:2]
        self.assertInvalid(self.raw(data))
        data = json.loads(self.good)
        data["end"] = 2
        self.assertInvalid(self.raw(data))

    def test_entry_key_set_faults(self) -> None:
        for index in range(3):
            data = json.loads(self.good)
            entry = data["entries"][index]
            extra = dict(entry)
            extra["x"] = 1
            data["entries"][index] = extra
            self.assertInvalid(self.raw(data))
            for key in ("after", "before", "id", "seq", "source"):
                data = json.loads(self.good)
                data["entries"][index] = {
                    k: v for k, v in data["entries"][index].items() if k != key
                }
                self.assertInvalid(self.raw(data))

    def test_entry_key_order_faults(self) -> None:
        entry = self.good_data["entries"][0]
        canonical_entry = canonical(entry)
        keys = list(entry.keys())
        reordered = {keys[1]: entry[keys[1]], keys[0]: entry[keys[0]]}
        for key in keys[2:]:
            reordered[key] = entry[key]
        permuted_entry = json.dumps(
            reordered, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        modified = self.good.replace(canonical_entry, permuted_entry, 1)
        self.assertInvalid(self.rehash(modified))

    def test_auth_key_order_faults(self) -> None:
        entry = self.good_data["entries"][1]
        canonical_auth = canonical(entry["auth"])
        permuted_auth = json.dumps(
            {"node": entry["auth"]["node"],
             "keyVersion": entry["auth"]["keyVersion"]},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        modified = self.good.replace(canonical_auth, permuted_auth, 1)
        self.assertInvalid(self.rehash(modified))

    def test_digest_shape_faults_on_entries(self) -> None:
        for field in ("before", "after"):
            for bad in ("A" * 64, "a" * 63, 1, None):
                data = json.loads(self.good)
                data["entries"][0][field] = bad
                self.assertInvalid(self.raw(data))

    def test_id_and_source_faults(self) -> None:
        for field in ("id", "source"):
            for bad in ("", 1, True, None, []):
                data = json.loads(self.good)
                data["entries"][0][field] = bad
                self.assertInvalid(self.raw(data))

    def test_seq_faults(self) -> None:
        for bad in ("1", True, 1.0, None):
            data = json.loads(self.good)
            data["entries"][1]["seq"] = bad
            self.assertInvalid(self.raw(data))
        # Gap in the sequence.
        data = json.loads(self.good)
        data["entries"][1]["seq"] = 9
        self.assertInvalid(self.raw(data))
        # Duplicate seq (chain adjusted, proof re-digested).
        data = json.loads(self.good)
        data["entries"][1]["seq"] = 1
        data["entries"][1]["before"] = data["entries"][0]["before"]
        self.assertInvalid(self.raw(data))
        # Declared range that does not match the entries' actual seqs:
        # two entries starting at seq 2 cannot be the range 1..2.
        data = json.loads(self.good)
        data["start"] = 1
        data["end"] = 2
        data["entries"] = data["entries"][1:]
        self.assertInvalid(self.raw(data))
        # Conversely a length/declaration mismatch without a seq change.
        data = json.loads(self.good)
        data["end"] = 2
        self.assertInvalid(self.raw(data))

    def test_chain_break_detected_even_when_re_digested(self) -> None:
        data = json.loads(self.good)
        data["entries"][1]["before"] = "f" * 64
        self.assertInvalid(self.raw(data))
        data = json.loads(self.good)
        data["entries"] = list(reversed(data["entries"]))
        self.assertInvalid(self.raw(data))

    def test_tampered_content_without_re_digest(self) -> None:
        data = json.loads(self.good)
        data["entries"][0]["id"] = "rewritten"
        self.assertInvalid(canonical(data) + b"\n")

    def test_auth_binding_faults(self) -> None:
        authed_index = 1

        def with_auth(auth):
            data = json.loads(self.good)
            data["entries"][authed_index]["auth"] = auth
            return self.raw(data)

        self.assertInvalid(with_auth({}))
        self.assertInvalid(with_auth({"node": "node-a"}))
        self.assertInvalid(with_auth({"keyVersion": 1}))
        self.assertInvalid(
            with_auth({"keyVersion": 1, "node": "node-a", "extra": 2})
        )
        self.assertInvalid(with_auth({"keyVersion": 1, "node": ""}))
        self.assertInvalid(with_auth({"keyVersion": 1, "node": 2}))
        for bad_version in (0, -1, True, "1", 1.0, None):
            self.assertInvalid(
                with_auth({"keyVersion": bad_version, "node": "node-a"})
            )

    def test_auth_must_be_object(self) -> None:
        data = json.loads(self.good)
        data["entries"][1]["auth"] = [1, "node-a"]
        self.assertInvalid(self.raw(data))

    def test_digest_over_body_without_newline(self) -> None:
        data = json.loads(self.good)
        body = {key: value for key, value in data.items() if key != "digest"}
        data["digest"] = hashlib.sha256(canonical(body) + b"\n").hexdigest()
        self.assertInvalid(canonical(data) + b"\n")


class ReplicationEntryPointTest(ProofFixture):
    def test_entry_points_round_trip(self) -> None:
        raw = replication.export_proof(self.path, 1, 2)
        self.assertEqual(
            replication.verify_proof(raw),
            ((1, 2),
             (self.entries[0]["before"], self.entries[1]["after"]),
             (1, 1)),
        )

    def test_entry_point_validation_matches(self) -> None:
        with self.assertRaises(InvalidProofError):
            replication.verify_proof(b"\x00\n")
        with self.assertRaises(TypeError):
            replication.verify_proof("not bytes")
        with self.assertRaises(ValueError):
            replication.export_proof(self.path, 0)

    def test_proof_module_uses_replication_ledger_contract(self) -> None:
        # The proof module shares the ledger constants/parser rather than
        # inventing a parallel wire format.
        self.assertIs(proof_module._DIGEST_RE, replication._DIGEST_RE)
        self.assertEqual(
            proof_module._ENTRY_UNAUTHED_ORDER,
            replication._LEDGER_ENTRY_KEY_ORDER,
        )


if __name__ == "__main__":
    unittest.main()
