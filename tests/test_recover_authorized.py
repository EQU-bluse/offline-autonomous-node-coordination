"""Tests for authorized recovery runs and the recovery audit chain.

Covers :func:`recover_authorized`, :mod:`offline_coordination.recovery_audit`
(the canonical JSONL hash chain and its paged export), the ticket
authentication rules, replay/resume semantics and the authorized
``recovery run`` / ``recovery audit`` module entry points.
"""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from offline_coordination import recovery_audit as RA
from offline_coordination import replication as R
from offline_coordination.replication import (
    AuthenticationError,
    CorruptRecoveryAuditError,
    ReplayError,
)

SECRET = "aa" * 32
OTHER_SECRET = "bb" * 32


def record(value, n, writer="node-a"):
    return [value, False, {writer: n}, writer]


S0 = {"clock": {}, "records": {}}
S1 = {"clock": {"node-a": 1}, "records": {"k": record("v1", 1)}}
S2 = {"clock": {"node-a": 2}, "records": {"k": record("v2", 2)}}


def make_request(rid, base, remote, source="node-a"):
    return {"id": rid, "source": source, "base": base, "remote": remote}


def keyring(secret=SECRET, version=1, revoked=False, nbf=0, naf=1000,
            issuer="node-a", extra=()):
    entry = {
        "version": version,
        "secret": secret,
        "notBefore": nbf,
        "notAfter": naf,
        "revoked": revoked,
    }
    return {issuer: [entry, *extra]}


def digest_of(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def ticket(payload, secret=SECRET, raw_signature=None):
    """Build (ticket_bytes, payload_bytes, ticket_digest) for a payload dict."""
    body = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    signature = raw_signature
    if signature is None:
        signature = hmac.new(
            bytes.fromhex(secret), body, hashlib.sha256
        ).hexdigest()
    obj = {"payload": payload, "signature": signature}
    raw = json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return raw, body, hashlib.sha256(body).hexdigest()


def make_payload(paths, nonce="nonce000000000001", issuer="node-a",
                 version=1, nbf=0, naf=1000):
    return {
        "issuer": issuer,
        "keyVersion": version,
        "nonce": nonce,
        "notBefore": nbf,
        "notAfter": naf,
        "paths": list(paths),
    }


def snapshot_dir(directory):
    snap = {}
    for name in os.listdir(directory):
        full = os.path.join(directory, name)
        if os.path.isfile(full):
            with open(full, "rb") as handle:
                snap[name] = handle.read()
    return snap


class CrashCapture:
    """Snapshot the commit directory at one exact interruption point."""

    def __init__(self, path, moment):
        self.path = path
        self.moment = moment
        self.directory = os.path.dirname(path)
        self.snapshot = None
        self._intent_publishes = 0

    def __enter__(self):
        self._real_replace = os.replace
        self._patch = mock.patch("os.replace", self._replace)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        return False

    def _snap(self):
        if self.snapshot is None:
            self.snapshot = snapshot_dir(self.directory)

    def _replace(self, src, dst):
        if dst == self.path + ".txn":
            self._intent_publishes += 1
        if self.moment == "before-install" and dst == self.path:
            self._snap()
        result = self._real_replace(src, dst)
        if (
            self.moment == "confirmed"
            and dst == self.path + ".txn"
            and self._intent_publishes == 2
        ):
            self._snap()
        return result


class AuthorizedCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def ledger_path(self, tag="ledger"):
        return os.path.join(self.dir, f"{tag}.json")

    def audit_path(self, tag="audit"):
        return os.path.join(self.dir, f"{tag}.jsonl")

    def committed_ledger(self, tag="ledger"):
        path = self.ledger_path(tag)
        R.apply_remote(path, make_request("r1", S0, S1))
        return path

    def crash_state(self, tag, moment):
        """A fresh directory holding exactly the files at the crash."""
        src_dir = tempfile.mkdtemp(dir=self.dir)
        src = os.path.join(src_dir, "ledger.json")
        R.apply_remote(src, make_request("r1", S0, S1))
        old = read_bytes(src)
        with CrashCapture(src, moment) as crash:
            R.apply_remote(src, make_request("r2", S1, S2))
        self.assertIsNotNone(crash.snapshot, f"no snapshot at {moment}")
        new = read_bytes(src)
        fresh = tempfile.mkdtemp(dir=self.dir)
        for name in os.listdir(fresh):
            os.unlink(os.path.join(fresh, name))
        for name, data in crash.snapshot.items():
            with open(os.path.join(fresh, name), "wb") as handle:
                handle.write(data)
        return os.path.join(fresh, "ledger.json"), old, new

    def authorize(self, paths, nonce="nonce000000000001", **ticket_kwargs):
        """Return (ticket_bytes, ticket_digest) for the given path list."""
        payload = make_payload(paths, nonce=nonce, **ticket_kwargs)
        raw, _body, digest = ticket(payload)
        return raw, digest

    def run_authorized(self, paths, raw=None, nonce="nonce000000000001",
                       kr=None, audit=None, moment=500, **ticket_kwargs):
        if raw is None:
            raw, _digest = self.authorize(paths, nonce=nonce, **ticket_kwargs)
        return R.recover_authorized(
            paths, kr if kr is not None else keyring(), raw,
            audit or self.audit_path(), moment,
        )


# --- recovery audit chain module ---------------------------------------------

class RecoveryAuditModuleTest(AuthorizedCase):
    def _line(self, kind, detail, seq, prev):
        without = {RA.DETAIL: detail, RA.KIND: kind, RA.PREV: prev, RA.SEQ: seq}
        record = dict(without)
        record[RA.HASH] = RA._record_hash(without)
        return RA._encode_line(record)

    def test_missing_or_empty_file_is_empty_chain(self):
        self.assertEqual(RA.read_chain(self.audit_path("missing")), [])
        open(self.audit_path("empty"), "wb").close()
        self.assertEqual(RA.read_chain(self.audit_path("empty")), [])

    def test_roundtrip_and_canonical_bytes(self):
        path = self.audit_path()
        batch = {
            RA.ISSUER: "node-a",
            RA.NONCE: "nonce000000000001",
            RA.PATHS: [self.ledger_path()],
            RA.TICKET_DIGEST: "a" * 64,
        }
        RA.append_record(path, RA.KIND_BATCH, batch)
        RA.append_record(
            path, RA.KIND_BEFORE,
            {RA.PATH: batch[RA.PATHS][0], RA.PHASE: RA.PHASE_PREPARED,
             RA.ACTION: RA.ACTION_ROLLBACK, RA.DIGEST: "b" * 64},
        )
        RA.append_record(
            path, RA.KIND_AFTER,
            {RA.PATH: batch[RA.PATHS][0], RA.STATUS: RA.STATUS_ROLLED_BACK,
             RA.ERROR: None, RA.DIGEST: "c" * 64},
        )
        records = RA.read_chain(path)
        self.assertEqual([r[RA.SEQ] for r in records], [1, 2, 3])
        self.assertEqual([r[RA.KIND] for r in records],
                         ["batch", "before", "after"])
        self.assertEqual(records[0][RA.PREV], RA.ZERO_HASH)
        self.assertEqual(records[1][RA.PREV], records[0][RA.HASH])
        self.assertEqual(records[2][RA.PREV], records[1][RA.HASH])
        raw = read_bytes(path)
        self.assertEqual(raw.count(b"\n"), 3)
        # Every line is the canonical compact encoding.
        for line in raw.splitlines():
            self.assertNotIn(b" ", line)

    def test_ordering_violations_are_corrupt(self):
        path = self.audit_path()
        before = {RA.PATH: "a", RA.PHASE: None, RA.ACTION: None,
                  RA.DIGEST: None}
        after = {RA.PATH: "a", RA.STATUS: RA.STATUS_CLEAN, RA.ERROR: None,
                 RA.DIGEST: "d" * 64}
        batch = {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a"],
                 RA.TICKET_DIGEST: "d" * 64}
        # before at the head needs a batch first.
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.append_record(path, RA.KIND_BEFORE, before)
        RA.append_record(path, RA.KIND_BATCH, batch)
        RA.append_record(path, RA.KIND_BEFORE, before)
        # a second before while an item is open is rejected.
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.append_record(path, RA.KIND_BEFORE, before)
        RA.append_record(path, RA.KIND_AFTER, after)
        # an after without its before is rejected.
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.append_record(path, RA.KIND_AFTER, after)

    def test_detail_domain_violations_are_corrupt(self):
        path = self.audit_path()
        good_batch = {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a"],
                      RA.TICKET_DIGEST: "d" * 64}
        bad_batches = [
            {RA.ISSUER: "", RA.NONCE: "n" * 16, RA.PATHS: ["a"],
             RA.TICKET_DIGEST: "d" * 64},
            {RA.ISSUER: "i", RA.NONCE: "short", RA.PATHS: ["a"],
             RA.TICKET_DIGEST: "d" * 64},
            {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: [],
             RA.TICKET_DIGEST: "d" * 64},
            {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a", "a"],
             RA.TICKET_DIGEST: "d" * 64},
            {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a"],
             RA.TICKET_DIGEST: "ABCDEF"},
        ]
        for detail in bad_batches:
            with self.subTest(detail=detail):
                with self.assertRaises(CorruptRecoveryAuditError):
                    RA.append_record(path, RA.KIND_BATCH, detail)
        RA.append_record(path, RA.KIND_BATCH, good_batch)
        bad_before = {
            RA.PATH: "a", RA.PHASE: RA.PHASE_PREPARED,
            RA.ACTION: RA.ACTION_COMPLETE, RA.DIGEST: None,
        }
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.append_record(path, RA.KIND_BEFORE, bad_before)
        # status/error mismatch and digest shape on after records.
        for bad_after in (
            {RA.PATH: "a", RA.STATUS: RA.STATUS_BLOCKED, RA.ERROR: None,
             RA.DIGEST: None},
            {RA.PATH: "a", RA.STATUS: RA.STATUS_FAILED,
             RA.ERROR: RA.ERROR_CORRUPT, RA.DIGEST: None},
            {RA.PATH: "a", RA.STATUS: "bogus", RA.ERROR: None,
             RA.DIGEST: None},
            {RA.PATH: "a", RA.STATUS: RA.STATUS_CLEAN, RA.ERROR: None,
             RA.DIGEST: "XYZ"},
        ):
            with self.subTest(bad_after=bad_after):
                with self.assertRaises(CorruptRecoveryAuditError):
                    RA._validate_detail(RA.KIND_AFTER, bad_after, "x")
        # A null digest on a clean/rolled-back item is valid (missing path).
        RA._validate_detail(
            RA.KIND_AFTER,
            {RA.PATH: "a", RA.STATUS: RA.STATUS_CLEAN, RA.ERROR: None,
             RA.DIGEST: None},
            "x",
        )

    def test_tampering_breaks_the_chain(self):
        path = self.audit_path()
        batch = {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a"],
                 RA.TICKET_DIGEST: "d" * 64}
        RA.append_record(path, RA.KIND_BATCH, batch)
        raw = bytearray(read_bytes(path))
        raw[50] = ord("z") if raw[50] != ord("z") else ord("y")
        with open(path, "wb") as handle:
            handle.write(bytes(raw))
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.read_chain(path)

    def test_corrupt_chain_is_never_extended(self):
        path = self.audit_path()
        with open(path, "wb") as handle:
            handle.write(b"not a json line\n")
        detail = {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a"],
                  RA.TICKET_DIGEST: "d" * 64}
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.append_record(path, RA.KIND_BATCH, detail)

    def test_hand_built_pair_path_mismatch_is_corrupt(self):
        # An after record naming a different path than its before is
        # rejected by the chain parser itself, so every reader sees the
        # corruption, not just a resume of that run.
        path = self.audit_path()
        payload = make_payload(["a"], nonce="n" * 16, issuer="i")
        raw, _b, real_digest = ticket(payload, secret=SECRET)
        batch = {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a"],
                 RA.TICKET_DIGEST: real_digest}
        line1 = self._line(RA.KIND_BATCH, batch, 1, RA.ZERO_HASH)
        h1 = json.loads(line1)[RA.HASH]
        before = {RA.PATH: "a", RA.PHASE: None, RA.ACTION: None,
                  RA.DIGEST: None}
        line2 = self._line(RA.KIND_BEFORE, before, 2, h1)
        h2 = json.loads(line2)[RA.HASH]
        after = {RA.PATH: "b", RA.STATUS: RA.STATUS_CLEAN, RA.ERROR: None,
                 RA.DIGEST: "d" * 64}
        line3 = self._line(RA.KIND_AFTER, after, 3, h2)
        with open(path, "wb") as handle:
            handle.write(line1 + line2 + line3)
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.read_chain(path)
        with self.assertRaises(CorruptRecoveryAuditError):
            R.recover_authorized(["a"], keyring(issuer="i"), raw, path, 500)

    def test_hand_built_path_order_violation_is_corrupt(self):
        # A before record whose path does not follow the batch's declared
        # ordered paths is corrupt even though each pair itself matches.
        path = self.audit_path()
        payload = make_payload(["a", "b"], nonce="n" * 16, issuer="i")
        raw, _b, real_digest = ticket(payload, secret=SECRET)
        batch = {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a", "b"],
                 RA.TICKET_DIGEST: real_digest}
        line1 = self._line(RA.KIND_BATCH, batch, 1, RA.ZERO_HASH)
        h1 = json.loads(line1)[RA.HASH]
        # First item already claims the second path.
        wrong = {RA.PATH: "b", RA.PHASE: None, RA.ACTION: None,
                 RA.DIGEST: None}
        line2 = self._line(RA.KIND_BEFORE, wrong, 2, h1)
        with open(path, "wb") as handle:
            handle.write(line1 + line2)
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.read_chain(path)
        with self.assertRaises(CorruptRecoveryAuditError):
            R.recover_authorized(["a", "b"], keyring(issuer="i"), raw, path, 500)


class ExportPageTest(AuthorizedCase):
    def _seed(self, path):
        batch = {RA.ISSUER: "i", RA.NONCE: "n" * 16, RA.PATHS: ["a", "b"],
                 RA.TICKET_DIGEST: "d" * 64}
        RA.append_record(path, RA.KIND_BATCH, batch)
        for name, phase, action in (
            ("a", None, None),
            ("b", RA.PHASE_INSTALLED, RA.ACTION_COMPLETE),
        ):
            RA.append_record(
                path, RA.KIND_BEFORE,
                {RA.PATH: name, RA.PHASE: phase, RA.ACTION: action,
                 RA.DIGEST: "1" * 64},
            )
            RA.append_record(
                path, RA.KIND_AFTER,
                {RA.PATH: name, RA.STATUS: RA.STATUS_CLEAN, RA.ERROR: None,
                 RA.DIGEST: "2" * 64},
            )

    def test_missing_audit_is_empty_chain_page(self):
        page = json.loads(RA.export_page(self.audit_path("missing"), 0, 10))
        self.assertEqual(
            page,
            {"after": 0, "complete": True, "next": 0, "records": [],
             "version": 1},
        )

    def test_paging_key_order_and_completeness(self):
        path = self.audit_path()
        self._seed(path)
        first = json.loads(RA.export_page(path, 0, 2))
        self.assertEqual(first["next"], 2)
        self.assertFalse(first["complete"])
        self.assertEqual([r[RA.SEQ] for r in first["records"]], [1, 2])
        self.assertEqual(
            list(first["records"][0].keys()),
            ["detail", "hash", "kind", "prev", "seq"],
        )
        rest = json.loads(RA.export_page(path, 2, 100))
        self.assertTrue(rest["complete"])
        self.assertEqual(rest["next"], 5)
        self.assertEqual([r[RA.SEQ] for r in rest["records"]], [3, 4, 5])
        # Canonical compact bytes with fixed key order, one trailing LF.
        raw = RA.export_page(path, 0, 10)
        self.assertTrue(raw.endswith(b"\n") and not raw.endswith(b"\n\n"))
        self.assertEqual(
            raw,
            json.dumps(json.loads(raw), ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8") + b"\n",
        )

    def test_validation(self):
        path = self.audit_path()
        with self.assertRaises(TypeError):
            RA.export_page(path, True)
        with self.assertRaises(TypeError):
            RA.export_page(path, 0, True)
        with self.assertRaises(ValueError):
            RA.export_page(path, -1)
        with self.assertRaises(ValueError):
            RA.export_page(path, 0, 0)
        with self.assertRaises(ValueError):
            RA.export_page(path, 0, 1001)
        with self.assertRaises(ValueError):
            RA.export_page(path, 1)

    def test_corrupt_chain_propagates(self):
        path = self.audit_path()
        with open(path, "wb") as handle:
            handle.write(b"{}\n")
        with self.assertRaises(CorruptRecoveryAuditError):
            RA.export_page(path)


# --- input validation ---------------------------------------------------------

class TicketValidationTest(AuthorizedCase):
    def setUp(self):
        super().setUp()
        self.paths = [self.committed_ledger("t")]
        self.audit = self.audit_path()

    def _call(self, raw, **kwargs):
        return R.recover_authorized(
            self.paths, kwargs.pop("kr", keyring()), raw, self.audit,
            kwargs.pop("moment", 500),
        )

    def test_ticket_must_be_bytes(self):
        for bad in ("str", None, 1, [], {}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self._call(bad)

    def test_malformed_bytes_are_value_errors(self):
        for bad in (
            b"",
            b"\xff\xfe not utf8",
            b"not json",
            b"[]",
            b'{"payload":{},"signature":"x"}',
            b'{"payload":{},"signature":"' + b"a" * 64 + b'"}',
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._call(bad)

    def test_field_type_faults_are_type_errors(self):
        def ticket_with(mutate):
            payload = make_payload(self.paths)
            mutate(payload)
            raw, _b, _d = ticket(payload)
            return raw

        cases = [
            lambda p: p.__setitem__("issuer", 1),
            lambda p: p.__setitem__("keyVersion", 1.5),
            lambda p: p.__setitem__("keyVersion", True),
            lambda p: p.__setitem__("nonce", 16),
            lambda p: p.__setitem__("notBefore", "0"),
            lambda p: p.__setitem__("notAfter", True),
            lambda p: p.__setitem__("paths", "a"),
            lambda p: p["paths"].__setitem__(0, 1),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                with self.assertRaises(TypeError):
                    self._call(ticket_with(mutate))
        sig_int = json.dumps(
            {"payload": make_payload(self.paths), "signature": 1}
        ).encode()
        with self.assertRaises(TypeError):
            self._call(sig_int)

    def test_value_domain_faults(self):
        def raw_for(payload, signature="a" * 64):
            return json.dumps(
                {"payload": payload, "signature": signature},
                sort_keys=True, separators=(",", ":"),
            ).encode()

        base = make_payload(self.paths)
        cases = [
            {**base, "issuer": ""},
            {**base, "keyVersion": 0},
            {**base, "nonce": "short"},
            {**base, "nonce": "n" * 15},
            {**base, "nonce": "n" * 65},
            {**base, "nonce": "n" * 64},  # 64 is fine; replaced below
            {**base, "nonce": "has space" * 2},
            {**base, "notBefore": 9, "notAfter": 2},
            {**base, "paths": []},
            {**base, "paths": [self.paths[0], self.paths[0]]},
            {**base, "paths": [""]},
        ]
        cases = cases[:-3] + [
            {**base, "notBefore": 9, "notAfter": 2},
            {**base, "paths": []},
            {**base, "paths": [self.paths[0], self.paths[0]]},
            {**base, "paths": [""]},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    self._call(raw_for(payload))
        # Signature shape.
        with self.assertRaises(ValueError):
            self._call(raw_for(base, signature="A" * 64))
        with self.assertRaises(ValueError):
            self._call(raw_for(base, signature="a" * 63))

    def test_nonce_length_boundaries_are_accepted(self):
        for length in (16, 64):
            raw, _b, _d = ticket(
                make_payload(self.paths, nonce="n" * length)
            )
            items = self._call(raw)
            self.assertEqual(items[0]["status"], "clean")

    def test_non_canonical_or_duplicate_keys_are_value_errors(self):
        payload = make_payload(self.paths)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(bytes.fromhex(SECRET), body, hashlib.sha256).hexdigest()
        # Pretty-printed (non-compact) outer encoding.
        pretty = json.dumps({"payload": payload, "signature": sig}, indent=2)
        with self.assertRaises(ValueError):
            self._call(pretty.encode())
        # Trailing newline.
        compact = json.dumps(
            {"payload": payload, "signature": sig}, sort_keys=True,
            separators=(",", ":"),
        )
        with self.assertRaises(ValueError):
            self._call((compact + "\n").encode())
        # Duplicate payload key.
        dup = compact.replace('"issuer":', '"issuer":"x","issuer":', 1)
        with self.assertRaises(ValueError):
            self._call(dup.encode())

    def test_extra_or_missing_ticket_keys(self):
        payload = make_payload(self.paths)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(bytes.fromhex(SECRET), body, hashlib.sha256).hexdigest()
        for raw in (
            json.dumps({"payload": payload}).encode(),
            json.dumps(
                {"payload": payload, "signature": sig, "extra": 1},
                sort_keys=True, separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"payload": {**payload, "extra": 1}, "signature": sig},
                sort_keys=True, separators=(",", ":"),
            ).encode(),
        ):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(ValueError):
                    self._call(raw)

    def test_argument_and_moment_types(self):
        raw, _b, _d = ticket(make_payload(self.paths))
        kr = keyring()
        with self.assertRaises(TypeError):
            R.recover_authorized("not-a-list", kr, raw, self.audit, 500)
        with self.assertRaises(TypeError):
            R.recover_authorized([self.paths[0], 1], kr, raw, self.audit, 500)
        with self.assertRaises(ValueError):
            R.recover_authorized([], kr, raw, self.audit, 500)
        with self.assertRaises(ValueError):
            R.recover_authorized(["a", "a"], kr, raw, self.audit, 500)
        with self.assertRaises(TypeError):
            R.recover_authorized(self.paths, kr, raw, 1, 500)
        with self.assertRaises(ValueError):
            R.recover_authorized(self.paths, kr, raw, "", 500)
        for bad_moment in (True, False, 1.5, "500", None):
            with self.subTest(bad_moment=bad_moment):
                with self.assertRaises(TypeError):
                    R.recover_authorized(self.paths, kr, raw, self.audit,
                                         bad_moment)
        with self.assertRaises(ValueError):
            R.recover_authorized(self.paths, kr, raw, self.audit, -1)

    def test_keyring_validation_is_reused(self):
        raw, _b, _d = ticket(make_payload(self.paths))
        with self.assertRaises(TypeError):
            self._call(raw, kr=[])
        bad_secret = keyring(secret="zz")
        with self.assertRaises(ValueError):
            self._call(raw, kr=bad_secret)
        dup_versions = {
            "node-a": [
                {"version": 1, "secret": SECRET, "notBefore": 0,
                 "notAfter": 10, "revoked": False},
                {"version": 1, "secret": SECRET, "notBefore": 0,
                 "notAfter": 10, "revoked": False},
            ]
        }
        with self.assertRaises(ValueError):
            self._call(raw, kr=dup_versions)
        bad_revoked = keyring()
        bad_revoked["node-a"][0]["revoked"] = "yes"
        with self.assertRaises(TypeError):
            self._call(raw, kr=bad_revoked)


# --- authentication -----------------------------------------------------------

class AuthenticationTest(AuthorizedCase):
    def setUp(self):
        super().setUp()
        self.ledger = self.committed_ledger("a")
        self.paths = [self.ledger]
        self.audit = self.audit_path()

    def _assert_unauthorized(self, raw, kr=None, moment=500):
        before = snapshot_dir(self.dir)
        listing = os.listdir(self.dir)
        with self.assertRaises(AuthenticationError):
            R.recover_authorized(
                self.paths, kr if kr is not None else keyring(), raw,
                self.audit, moment,
            )
        # No audit record, no consumed nonce, no leftover temporary file.
        self.assertEqual(os.listdir(self.dir), listing)
        self.assertEqual(snapshot_dir(self.dir), before)
        self.assertFalse(os.path.exists(self.audit))

    def test_unknown_issuer_and_version(self):
        raw, _b, _d = ticket(make_payload(self.paths, issuer="ghost"))
        self._assert_unauthorized(raw)
        raw, _b, _d = ticket(make_payload(self.paths, version=9))
        self._assert_unauthorized(raw)

    def test_revoked(self):
        raw, _b, _d = ticket(make_payload(self.paths))
        self._assert_unauthorized(raw, kr=keyring(revoked=True))

    def test_key_validity_window_inclusive(self):
        kr = keyring(nbf=10, naf=20)
        for moment in (9, 21):
            raw, _b, _d = ticket(make_payload(self.paths))
            with self.assertRaises(AuthenticationError):
                R.recover_authorized(self.paths, kr, raw, self.audit, moment)
        for moment in (10, 20):
            raw, _b, _d = ticket(make_payload(self.paths))
            items = R.recover_authorized(
                self.paths, kr, raw, self.audit, moment
            )
            self.assertEqual(items[0]["status"], "clean")
            os.unlink(self.audit)

    def test_ticket_validity_window(self):
        for moment, nbf, naf in (
            (500, 600, 900),
            (500, 100, 499),
        ):
            raw, _b, _d = ticket(
                make_payload(self.paths, nbf=nbf, naf=naf)
            )
            self._assert_unauthorized(raw, moment=moment)
        raw, _b, _d = ticket(make_payload(self.paths, nbf=500, naf=500))
        items = R.recover_authorized(
            self.paths, keyring(), raw, self.audit, 500
        )
        self.assertEqual(items[0]["status"], "clean")

    def test_bad_signature(self):
        raw, _b, _d = ticket(make_payload(self.paths),
                             raw_signature="0" * 64)
        self._assert_unauthorized(raw)

    def test_signature_is_over_payload_only_with_other_issuer_key(self):
        two_nodes = {
            "node-a": [{"version": 1, "secret": SECRET, "notBefore": 0,
                        "notAfter": 1000, "revoked": False}],
            "node-b": [{"version": 1, "secret": OTHER_SECRET, "notBefore": 0,
                        "notAfter": 1000, "revoked": False}],
        }
        good, _b, _d = ticket(
            make_payload(self.paths, issuer="node-b"), secret=OTHER_SECRET
        )
        items = R.recover_authorized(
            self.paths, two_nodes, good, self.audit, 500
        )
        self.assertEqual(items[0]["status"], "clean")
        os.unlink(self.audit)
        # Signed by node-a's key but claiming node-b: no fallback.
        forged, _b, _d = ticket(
            make_payload(self.paths, issuer="node-b"), secret=SECRET
        )
        self._assert_unauthorized(forged, kr=two_nodes)

    def test_command_paths_must_match_exactly(self):
        other = self.committed_ledger("b")
        # Extra command path the ticket does not authorize.
        raw, _b, _d = ticket(make_payload(self.paths))
        before = snapshot_dir(self.dir)
        with self.assertRaises(AuthenticationError):
            R.recover_authorized(
                [self.ledger, other], keyring(), raw, self.audit, 500
            )
        self.assertEqual(snapshot_dir(self.dir), before)
        # Ticket allows a superset the command does not exercise.
        raw, _b, _d = ticket(make_payload([self.ledger, other]))
        self._assert_unauthorized(raw)
        # Reordered.
        raw, _b, _d = ticket(make_payload([other, self.ledger]))
        before = snapshot_dir(self.dir)
        with self.assertRaises(AuthenticationError):
            R.recover_authorized(
                [self.ledger, other], keyring(), raw, self.audit, 500
            )
        self.assertEqual(snapshot_dir(self.dir), before)
        # No implicit normalization: an equivalent-looking different string.
        raw, _b, _d = ticket(make_payload(["./a"]))
        with self.assertRaises(AuthenticationError):
            R.recover_authorized(["a"], keyring(), raw, self.audit, 500)

    def test_duplicate_command_paths_rejected_before_auth(self):
        raw, _b, _d = ticket(make_payload([self.ledger, self.ledger]))
        with self.assertRaises(ValueError):
            R.recover_authorized(
                [self.ledger, self.ledger], keyring(), raw, self.audit, 500
            )


# --- first run ----------------------------------------------------------------

class FirstRunTest(AuthorizedCase):
    def test_full_run_statuses_in_order_and_shape(self):
        clean = self.committed_ledger("clean")
        prepared, old, _new = self.crash_state("p", "before-install")
        confirmed, _o, new = self.crash_state("c", "confirmed")
        missing = self.ledger_path("missing")
        paths = [clean, prepared, confirmed, missing]
        items = self.run_authorized(paths)
        self.assertEqual(
            [list(item.keys()) for item in items],
            [["path", "status", "digest", "error"]] * 4,
        )
        self.assertEqual(items[0], {
            "path": clean, "status": "clean",
            "digest": digest_of(read_bytes(clean)), "error": None,
        })
        self.assertEqual(items[1], {
            "path": prepared, "status": "rolled-back",
            "digest": digest_of(old), "error": None,
        })
        self.assertEqual(items[2], {
            "path": confirmed, "status": "completed",
            "digest": digest_of(new), "error": None,
        })
        self.assertEqual(items[3], {
            "path": missing, "status": "clean", "digest": None,
            "error": None,
        })

    def test_batch_header_precedes_any_ledger_read(self):
        ledger = self.committed_ledger("x")
        audit = self.audit_path()
        raw, _b, _d = ticket(make_payload([ledger]))
        real_inspect = R._inspect_one

        def inspect_then_check(path):
            records = RA.read_chain(audit)
            self.assertEqual([r[RA.KIND] for r in records], [RA.KIND_BATCH])
            return real_inspect(path)

        with mock.patch.object(R, "_inspect_one", side_effect=inspect_then_check):
            R.recover_authorized([ledger], keyring(), raw, audit, 500)

    def test_records_bind_ticket_digest_issuer_and_ordered_paths(self):
        ledger = self.committed_ledger("x")
        audit = self.audit_path()
        raw, body, expected_digest = ticket(
            make_payload([ledger], nonce="nonce000000000099", issuer="node-a")
        )
        R.recover_authorized([ledger], keyring(), raw, audit, 500)
        records = RA.read_chain(audit)
        header = records[0][RA.DETAIL]
        self.assertEqual(header[RA.TICKET_DIGEST], expected_digest)
        self.assertEqual(header[RA.TICKET_DIGEST],
                         hashlib.sha256(body).hexdigest())
        self.assertEqual(header[RA.ISSUER], "node-a")
        self.assertEqual(header[RA.NONCE], "nonce000000000099")
        self.assertEqual(header[RA.PATHS], [ledger])
        before, after = records[1][RA.DETAIL], records[2][RA.DETAIL]
        self.assertIsNone(before[RA.PHASE])
        self.assertIsNone(before[RA.ACTION])
        self.assertEqual(before[RA.DIGEST], digest_of(read_bytes(ledger)))
        self.assertEqual(after[RA.STATUS], "clean")
        self.assertIsNone(after[RA.ERROR])

    def test_before_record_carries_phase_and_planned_action(self):
        prepared, _old, _new = self.crash_state("p", "before-install")
        confirmed, _o, _n = self.crash_state("c", "confirmed")
        audit = self.audit_path()
        paths = [prepared, confirmed]
        raw, _b, _d = ticket(make_payload(paths))
        R.recover_authorized(paths, keyring(), raw, audit, 500)
        records = RA.read_chain(audit)
        details = [r[RA.DETAIL] for r in records if r[RA.KIND] == RA.KIND_BEFORE]
        self.assertEqual(details[0][RA.PHASE], "prepared")
        self.assertEqual(details[0][RA.ACTION], "rollback")
        self.assertEqual(details[1][RA.PHASE], "installed")
        self.assertEqual(details[1][RA.ACTION], "complete")

    def test_blocked_and_os_error_items_are_isolated_and_recorded(self):
        corrupt, _o, _n = self.crash_state("bad", "before-install")
        with open(corrupt + ".txn", "wb") as handle:
            handle.write(b"not json\n")
        osfail, _o2, _n2 = self.crash_state("io", "before-install")
        clean = self.committed_ledger("ok")
        paths = [corrupt, osfail, clean]
        audit = self.audit_path()
        raw, _b, _d = ticket(make_payload(paths))
        sentinel = OSError("sync denied")
        with mock.patch(
            "offline_coordination.storage._fsync_dir", side_effect=sentinel
        ):
            items = R.recover_authorized(paths, keyring(), raw, audit, 500)
        self.assertEqual(items[0]["status"], "blocked")
        self.assertEqual(items[0]["error"], "corrupt")
        self.assertIsNone(items[0]["digest"])
        self.assertEqual(items[1]["status"], "failed")
        self.assertEqual(items[1]["error"], "os-error")
        self.assertIsNone(items[1]["digest"])
        self.assertEqual(items[2]["status"], "clean")
        self.assertIsNone(items[2]["error"])
        # The blocking intent and the os-error ledger keep their material.
        self.assertTrue(os.path.exists(corrupt + ".txn"))
        self.assertTrue(os.path.exists(osfail + ".txn"))
        records = RA.read_chain(audit)
        afters = [r[RA.DETAIL] for r in records if r[RA.KIND] == RA.KIND_AFTER]
        self.assertEqual(
            [(a[RA.STATUS], a[RA.ERROR]) for a in afters],
            [("blocked", "corrupt"), ("failed", "os-error"), ("clean", None)],
        )

    def test_preexisting_corrupt_audit_is_rejected(self):
        ledger = self.committed_ledger("x")
        audit = self.audit_path()
        with open(audit, "wb") as handle:
            handle.write(b"garbage\n")
        before = snapshot_dir(self.dir)
        raw, _b, _d = ticket(make_payload([ledger]))
        with self.assertRaises(CorruptRecoveryAuditError):
            R.recover_authorized([ledger], keyring(), raw, audit, 500)
        self.assertEqual(snapshot_dir(self.dir), before)

    def test_audit_write_failure_leaves_retryable_prefix(self):
        ledger = self.committed_ledger("x")
        audit = self.audit_path()
        raw, _b, _d = ticket(make_payload([ledger]))
        sentinel = OSError("audit write denied")

        def fail_before_record(path, kind, detail):
            if kind == RA.KIND_BEFORE:
                raise sentinel
            return real_append(path, kind, detail)

        real_append = RA.append_record
        with mock.patch.object(RA, "append_record", side_effect=fail_before_record):
            with self.assertRaises(OSError) as caught:
                R.recover_authorized([ledger], keyring(), raw, audit, 500)
            self.assertIs(caught.exception, sentinel)
        # Only the batch header made it; a plain retry finishes the run.
        self.assertEqual(
            [r[RA.KIND] for r in RA.read_chain(audit)], [RA.KIND_BATCH]
        )
        items = R.recover_authorized([ledger], keyring(), raw, audit, 500)
        self.assertEqual(items[0]["status"], "clean")


# --- replay and resume --------------------------------------------------------

class ReplayAndResumeTest(AuthorizedCase):
    def test_completed_run_replays_from_audit_without_touching_ledger(self):
        ledger = self.committed_ledger("x")
        audit = self.audit_path()
        raw, _b, _d = ticket(make_payload([ledger]))
        first = R.recover_authorized([ledger], keyring(), raw, audit, 500)
        with mock.patch.object(R, "recover_ledger", side_effect=AssertionError):
            with mock.patch.object(R, "_inspect_one", side_effect=AssertionError):
                second = R.recover_authorized(
                    [ledger], keyring(), raw, audit, 500
                )
        self.assertEqual(second, first)

    def test_same_nonce_different_ticket_raises_replay_error_untouched(self):
        ledger = self.committed_ledger("x")
        audit = self.audit_path()
        first, _b, _d = ticket(make_payload([ledger], naf=1000))
        R.recover_authorized([ledger], keyring(), first, audit, 500)
        before = snapshot_dir(self.dir)
        second, _b, _d = ticket(make_payload([ledger], naf=999))
        with self.assertRaises(ReplayError) as caught:
            R.recover_authorized([ledger], keyring(), second, audit, 500)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertEqual(snapshot_dir(self.dir), before)

    def test_resume_only_settles_the_unrecorded_tail(self):
        first = self.committed_ledger("one")
        second = self.committed_ledger("two")
        third, _o, _n = self.crash_state("three", "before-install")
        paths = [first, second, third]
        audit = self.audit_path()
        raw, _b, _d = ticket(make_payload(paths))

        real_append = RA.append_record

        def stop_before_third(path, kind, detail):
            if kind == RA.KIND_BEFORE and detail[RA.PATH] == third:
                raise StopIteration
            return real_append(path, kind, detail)

        with mock.patch.object(RA, "append_record", side_effect=stop_before_third):
            try:
                R.recover_authorized(paths, keyring(), raw, audit, 500)
            except StopIteration:
                pass
        kinds = [r[RA.KIND] for r in RA.read_chain(audit)]
        self.assertEqual(kinds, ["batch", "before", "after", "before", "after"])
        # The third ledger is still interrupted: resuming settles only it.
        self.assertTrue(os.path.exists(third + ".txn"))
        items = R.recover_authorized(paths, keyring(), raw, audit, 500)
        self.assertEqual([i[RA.PATH if False else "status"] for i in items],
                         ["clean", "clean", "rolled-back"])
        self.assertEqual([i["path"] for i in items], paths)
        self.assertFalse(os.path.exists(third + ".txn"))

    def test_open_item_completed_from_recorded_plan_prepared(self):
        prepared, old, _new = self.crash_state("p", "before-install")
        self._open_item_resume(prepared, "rolled-back", digest_of(old))

    def test_open_item_completed_from_recorded_plan_installed(self):
        confirmed, _old, new = self.crash_state("c", "confirmed")
        self._open_item_resume(confirmed, "completed", digest_of(new))

    def _open_item_resume(self, path, expected_status, expected_digest):
        audit = self.audit_path()
        raw, _b, _d = ticket(make_payload([path]))
        real_recover = R.recover_ledger

        class KilledAfterSettle(Exception):
            pass

        def settle_then_die(target):
            result = real_recover(target)
            raise KilledAfterSettle

        with mock.patch.object(R, "recover_ledger", side_effect=settle_then_die):
            with self.assertRaises(KilledAfterSettle):
                R.recover_authorized([path], keyring(), raw, audit, 500)
        self.assertEqual(
            [r[RA.KIND] for r in RA.read_chain(audit)],
            ["batch", "before"],
        )
        # Resume: the side effect is not repeated; the plan fills the result.
        items = R.recover_authorized([path], keyring(), raw, audit, 500)
        self.assertEqual(items[0]["status"], expected_status)
        self.assertEqual(items[0]["digest"], expected_digest)
        # A second re-entry returns the recorded result, not a clean no-op.
        again = R.recover_authorized([path], keyring(), raw, audit, 500)
        self.assertEqual(again, items)
        self.assertEqual(again[0]["status"], expected_status)

    def test_new_ticket_cannot_start_while_prior_run_open(self):
        first = self.committed_ledger("one")
        second = self.committed_ledger("two")
        audit = self.audit_path()
        raw1, _b, _d = ticket(make_payload([first, second]))

        real_append = RA.append_record

        def stop_at_second_before(path, kind, detail):
            if kind == RA.KIND_BEFORE and detail[RA.PATH] == second:
                raise StopIteration
            return real_append(path, kind, detail)

        with mock.patch.object(RA, "append_record", side_effect=stop_at_second_before):
            try:
                R.recover_authorized([first, second], keyring(), raw1, audit, 500)
            except StopIteration:
                pass
        # The first run is open: one item closed, the second not started.
        self.assertEqual(len(RA.read_chain(audit)), 3)
        # A different ticket cannot append a batch over the open run.
        other = self.committed_ledger("other")
        raw2, _b, _d = ticket(
            make_payload([other], nonce="nonce000000000002")
        )
        with self.assertRaises(CorruptRecoveryAuditError):
            R.recover_authorized([other], keyring(), raw2, audit, 500)
        # Resuming the original run closes the chain and succeeds.
        items = R.recover_authorized([first, second], keyring(), raw1, audit, 500)
        self.assertEqual([i["status"] for i in items], ["clean", "clean"])
        # Only now may the second ticket start its own run.
        items = R.recover_authorized([other], keyring(), raw2, audit, 500)
        self.assertEqual(items[0]["status"], "clean")

    def test_distinct_tickets_share_one_chain_and_replay_independently(self):
        first = self.committed_ledger("one")
        second = self.committed_ledger("two")
        audit = self.audit_path()
        raw1, _b, _d = ticket(
            make_payload([first], nonce="nonce000000000001")
        )
        raw2, _b, _d = ticket(
            make_payload([second], nonce="nonce000000000002")
        )
        R.recover_authorized([first], keyring(), raw1, audit, 500)
        R.recover_authorized([second], keyring(), raw2, audit, 500)
        self.assertEqual(
            [r[RA.KIND] for r in RA.read_chain(audit)],
            ["batch", "before", "after", "batch", "before", "after"],
        )
        with mock.patch.object(R, "recover_ledger", side_effect=AssertionError):
            replay1 = R.recover_authorized(
                [first], keyring(), raw1, audit, 500
            )
            replay2 = R.recover_authorized(
                [second], keyring(), raw2, audit, 500
            )
        self.assertEqual(replay1[0]["path"], first)
        self.assertEqual(replay2[0]["path"], second)

    def test_recorded_order_mismatch_is_corrupt_audit(self):
        first = self.committed_ledger("one")
        second = self.committed_ledger("two")
        audit = self.audit_path()
        raw, _b, _d = ticket(make_payload([first, second]))
        # Build a chain whose single recorded item is for the second path.
        batch = {
            RA.ISSUER: "node-a", RA.NONCE: "nonce000000000001",
            RA.PATHS: [first, second], RA.TICKET_DIGEST: "d" * 64,
        }
        line1 = RA._encode_line({
            RA.DETAIL: batch, RA.HASH: RA._record_hash(
                {RA.DETAIL: batch, RA.KIND: RA.KIND_BATCH, RA.PREV: RA.ZERO_HASH,
                 RA.SEQ: 1}),
            RA.KIND: RA.KIND_BATCH, RA.PREV: RA.ZERO_HASH, RA.SEQ: 1,
        })
        # The genuine run fixes the real ticket digest, so run it then
        # truncate and rewrite a wrong-path prefix instead.
        R.recover_authorized([first, second], keyring(), raw, audit, 500)
        records = RA.read_chain(audit)
        real_digest = records[0][RA.DETAIL][RA.TICKET_DIGEST]

        def line(kind, detail, seq, prev):
            without = {RA.DETAIL: detail, RA.KIND: kind, RA.PREV: prev,
                       RA.SEQ: seq}
            record = dict(without)
            record[RA.HASH] = RA._record_hash(without)
            return RA._encode_line(record)

        batch2 = {**batch, RA.TICKET_DIGEST: real_digest}
        l1 = line(RA.KIND_BATCH, batch2, 1, RA.ZERO_HASH)
        h1 = json.loads(l1)[RA.HASH]
        l2 = line(RA.KIND_BEFORE,
                  {RA.PATH: second, RA.PHASE: None, RA.ACTION: None,
                   RA.DIGEST: None}, 2, h1)
        h2 = json.loads(l2)[RA.HASH]
        l3 = line(RA.KIND_AFTER,
                  {RA.PATH: second, RA.STATUS: "clean", RA.ERROR: None,
                   RA.DIGEST: "d" * 64}, 3, h2)
        with open(audit, "wb") as handle:
            handle.write(l1 + l2 + l3)
        with self.assertRaises(CorruptRecoveryAuditError):
            R.recover_authorized([first, second], keyring(), raw, audit, 500)


# --- module entry point -------------------------------------------------------

class AuthorizedCommandTest(AuthorizedCase):
    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "offline_coordination", *argv],
            capture_output=True, text=True,
        )

    def _write_material(self, name, obj):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle)
        return path

    def _write_ticket(self, name, payload, secret=SECRET):
        raw, _b, _d = ticket(payload, secret=secret)
        path = os.path.join(self.dir, name)
        with open(path, "wb") as handle:
            handle.write(raw)
        return path

    def _material(self, ledger, nonce="nonce000000000001"):
        keyring_path = self._write_material(
            "keyring.json", keyring()
        )
        ticket_path = self._write_ticket(
            "ticket.json", make_payload([ledger], nonce=nonce)
        )
        return keyring_path, ticket_path

    def test_authorized_run_outputs_one_sorted_line_exit_zero(self):
        ledger = self.committed_ledger("x")
        keyring_path, ticket_path = self._material(ledger)
        audit = self.audit_path()
        result = self.run_cli(
            "recovery", "run", ledger,
            "--keyring", keyring_path, "--ticket", ticket_path,
            "--audit", audit, "--moment", "500",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("\n"), 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload, [{
            "path": ledger, "status": "clean",
            "digest": digest_of(read_bytes(ledger)), "error": None,
        }])
        self.assertEqual(
            result.stdout.strip(),
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )

    def test_failure_item_exits_one(self):
        corrupt, _o, _n = self.crash_state("bad", "before-install")
        with open(corrupt + ".txn", "wb") as handle:
            handle.write(b"not json\n")
        keyring_path, ticket_path = self._material(corrupt)
        result = self.run_cli(
            "recovery", "run", corrupt,
            "--keyring", keyring_path, "--ticket", ticket_path,
            "--audit", self.audit_path(), "--moment", "500",
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)[0]["error"], "corrupt")

    def test_authentication_and_parameter_errors_exit_two(self):
        ledger = self.committed_ledger("x")
        keyring_path, ticket_path = self._material(ledger)
        bad_ticket = self._write_ticket(
            "bad.json", make_payload([ledger]), secret=OTHER_SECRET
        )
        base = [
            "recovery", "run", ledger, "--keyring", keyring_path,
            "--ticket", bad_ticket, "--audit", self.audit_path("x"),
            "--moment", "500",
        ]
        self.assertEqual(self.run_cli(*base).returncode, 2)
        # Bad moment.
        self.assertEqual(self.run_cli(*(base + ["--moment", "soon"])).returncode, 2)
        # Missing material file.
        self.assertEqual(
            self.run_cli(
                "recovery", "run", ledger, "--keyring",
                os.path.join(self.dir, "missing.json"),
                "--ticket", ticket_path, "--audit",
                self.audit_path("y"), "--moment", "500",
            ).returncode,
            2,
        )
        # Partial flags.
        result = self.run_cli(
            "recovery", "run", ledger, "--keyring", keyring_path
        )
        self.assertEqual(result.returncode, 2)

    def test_corrupt_audit_exits_one_for_run_and_audit(self):
        ledger = self.committed_ledger("x")
        keyring_path, ticket_path = self._material(ledger)
        corrupt_audit = self.audit_path("corrupt")
        with open(corrupt_audit, "wb") as handle:
            handle.write(b"garbage\n")
        result = self.run_cli(
            "recovery", "run", ledger,
            "--keyring", keyring_path, "--ticket", ticket_path,
            "--audit", corrupt_audit, "--moment", "500",
        )
        self.assertEqual(result.returncode, 1)
        result = self.run_cli("recovery", "audit", corrupt_audit)
        self.assertEqual(result.returncode, 1)

    def test_audit_command_pages_and_validates(self):
        ledger = self.committed_ledger("x")
        keyring_path, ticket_path = self._material(ledger)
        audit = self.audit_path()
        self.run_cli(
            "recovery", "run", ledger,
            "--keyring", keyring_path, "--ticket", ticket_path,
            "--audit", audit, "--moment", "500",
        )
        result = self.run_cli("recovery", "audit", audit)
        self.assertEqual(result.returncode, 0)
        page = json.loads(result.stdout)
        self.assertEqual(page["next"], 3)
        self.assertTrue(page["complete"])
        # Missing audit is an empty chain.
        result = self.run_cli(
            "recovery", "audit", self.audit_path("missing")
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["records"], [])
        self.assertEqual(
            self.run_cli("recovery", "audit", audit, "--after", "-1").returncode,
            2,
        )
        self.assertEqual(
            self.run_cli("recovery", "audit", audit, "--limit", "5000").returncode,
            2,
        )

    def test_unsigned_run_and_check_unchanged(self):
        prepared, old, _new = self.crash_state("p", "before-install")
        check = self.run_cli("recovery", "check", prepared)
        self.assertEqual(check.returncode, 0)
        self.assertEqual(json.loads(check.stdout)[0]["status"], "pending")
        run = self.run_cli("recovery", "run", prepared)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout)[0]["status"], "rolled-back")
        self.assertFalse(os.path.exists(self.audit_path()))


if __name__ == "__main__":
    unittest.main()
