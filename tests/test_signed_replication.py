"""Tests for the offline-verifiable signed replication entry point."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication as R
from offline_coordination import replication


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SECRET_A1 = "a1" * 32
SECRET_A2 = "a2" * 32
SECRET_B1 = "b1" * 32


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, clock, writer, deleted=False):
    return [value, deleted, dict(clock), writer]


def key_entry(version=1, secret=SECRET_A1, *, not_before=0, not_after=1000,
              revoked=False):
    return {
        "version": version,
        "secret": secret,
        "notBefore": not_before,
        "notAfter": not_after,
        "revoked": revoked,
    }


def keyring(*entries, node="node-a", extra=None):
    ring = {node: list(entries)}
    if extra:
        ring.update(extra)
    return ring


def canonical_signed(node, key_version, request):
    payload = {"keyVersion": key_version, "node": node, "request": request}
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign(node, key_version, secret, request):
    return hmac.new(
        bytes.fromhex(secret), canonical_signed(node, key_version, request),
        hashlib.sha256,
    ).hexdigest()


def make_request(rid="r1", source="node-a", base=None, remote=None):
    return {
        "id": rid,
        "source": source,
        "base": state() if base is None else base,
        "remote": state() if remote is None else remote,
    }


def envelope(request, node="node-a", key_version=1, secret=SECRET_A1,
             *, signature=None):
    return {
        "request": request,
        "node": node,
        "keyVersion": key_version,
        "signature": sign(node, key_version, secret, request)
        if signature is None else signature,
    }


def read_ledger(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read())


def ledger_raw(path):
    with open(path, "rb") as handle:
        return handle.read()


class SignedApplyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.remote = state({"a": 1}, {"k": record("v", {"a": 1}, "a")})
        self.request = make_request(remote=self.remote)
        self.keyring = keyring(key_entry())
        self.envelope = envelope(self.request)

    def signed(self, instant=500, path=None, env=None, ring=None):
        return R.apply_signed_remote(
            path or self.path, ring or self.keyring,
            env or self.envelope, instant,
        )

    # -- happy path ---------------------------------------------------------

    def test_applies_and_returns_same_result_contract(self) -> None:
        result = self.signed()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(tuple(result.keys()), ("items", "receipt", "status"))
        self.assertEqual(
            result["items"],
            [{"key": "k", "decision": "apply", "need": None}],
        )
        receipt = result["receipt"]
        self.assertEqual(
            tuple(receipt.keys()), ("id", "source", "before", "after", "seq")
        )
        self.assertEqual(receipt["id"], "r1")
        self.assertEqual(receipt["source"], "node-a")
        self.assertEqual(receipt["seq"], 1)

    def test_new_audit_entry_carries_verified_auth_record(self) -> None:
        self.signed()
        entry = read_ledger(self.path)["audit"][0]
        self.assertEqual(
            tuple(entry.keys()),
            ("after", "auth", "before", "id", "seq", "source"),
        )
        self.assertEqual(entry["auth"], {"keyVersion": 1, "node": "node-a"})

    def test_ledger_stays_canonical_compact_json(self) -> None:
        remote = state({"a": 1}, {"k": record("☃", {"a": 1}, "a")})
        request = make_request(remote=remote)
        env = envelope(request)
        R.apply_signed_remote(self.path, self.keyring, env, 500)
        raw = ledger_raw(self.path)
        decoded = json.loads(raw)
        self.assertEqual(
            raw,
            json.dumps(
                decoded, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n",
        )
        self.assertIn("☃".encode("utf-8"), raw)

    def test_successive_signed_entries_chain_and_keep_auth(self) -> None:
        self.signed()
        s2 = state({"a": 2}, {"k": record("w", {"a": 2}, "a")})
        request2 = make_request(rid="r2", base=self.remote, remote=s2)
        env2 = envelope(request2, secret=SECRET_A1)
        result = R.apply_signed_remote(self.path, self.keyring, env2, 500)
        self.assertEqual(result["status"], "applied")
        entries = read_ledger(self.path)["audit"]
        self.assertEqual([e["seq"] for e in entries], [1, 2])
        self.assertEqual(entries[1]["before"], entries[0]["after"])
        self.assertTrue(all(e["auth"] == {"keyVersion": 1, "node": "node-a"}
                            for e in entries))

    # -- canonical signing --------------------------------------------------

    def test_signature_is_over_sorted_compact_utf8_request(self) -> None:
        # Request object keys supplied out of order; the signature is still
        # over the recursively sorted compact encoding.
        request = {
            "remote": self.remote,
            "id": "r1",
            "base": state(),
            "source": "node-a",
        }
        env = envelope(request)
        self.assertEqual(self.signed(env=env)["status"], "applied")

    def test_nested_request_key_reordering_still_verifies(self) -> None:
        # Semantic equivalence under object key permutation: the signature
        # covers the recursively sorted compact encoding, so a request
        # whose keys arrive permuted verifies and applies identically.
        reordered = {
            "remote": {
                "records": self.remote["records"],
                "clock": self.remote["clock"],
            },
            "id": "r1",
            "base": state(),
            "source": "node-a",
        }
        self.assertEqual(
            canonical_signed("node-a", 1, reordered),
            canonical_signed("node-a", 1, self.request),
        )
        result = self.signed(env=envelope(reordered))
        self.assertEqual(result["status"], "applied")
        self.assertEqual(
            read_ledger(self.path)["state"],
            {"clock": {"a": 1},
             "records": {"k": ["v", False, {"a": 1}, "a"]}},
        )

    def test_signed_text_has_no_newline_and_keeps_unicode(self) -> None:
        text = canonical_signed("node-a", 1, self.request)
        self.assertNotIn(b"\n", text)
        remote = state({"a": 1}, {"k": record("雪 ☃", {"a": 1}, "a")})
        unicode_request = make_request(remote=remote)
        text = canonical_signed("node-a", 1, unicode_request)
        self.assertIn("雪".encode("utf-8"), text)
        self.assertNotIn(b"\\u", text)

    # -- credential selection and windows ----------------------------------

    def test_credential_selected_exactly_by_node_and_version(self) -> None:
        ring = keyring(
            key_entry(1, SECRET_A1, revoked=True),
            key_entry(2, SECRET_A2),
        )
        # keyVersion 2 with its own secret applies; version 1's status is
        # irrelevant and there is no fallback.
        env = envelope(self.request, key_version=2, secret=SECRET_A2)
        self.assertEqual(self.signed(ring=ring, env=env)["status"], "applied")

    def test_no_fallback_to_another_version(self) -> None:
        ring = keyring(
            key_entry(1, SECRET_A1, revoked=True),
            key_entry(2, SECRET_A2),
        )
        # Signed for version 1: the revoked credential must be selected
        # exactly -- version 2 must not silently take over.
        env = envelope(self.request, key_version=1, secret=SECRET_A1)
        with self.assertRaises(R.AuthenticationError):
            self.signed(ring=ring, env=env)
        self.assertFalse(os.path.exists(self.path))

    def test_unknown_node_and_unknown_version(self) -> None:
        env = envelope(self.request, node="node-z", secret=SECRET_A1)
        with self.assertRaisesRegex(R.AuthenticationError, "unknown node"):
            self.signed(ring=keyring(key_entry()), env=env)
        env = envelope(self.request, key_version=9, secret=SECRET_A1)
        with self.assertRaisesRegex(R.AuthenticationError, "unknown key version"):
            self.signed(ring=keyring(key_entry()), env=env)

    def test_empty_entry_list_is_unknown_credential(self) -> None:
        with self.assertRaises(R.AuthenticationError):
            self.signed(ring={"node-a": []})

    def test_validity_boundaries_are_inclusive(self) -> None:
        ring = keyring(key_entry(not_before=10, not_after=20))
        for instant, rid in ((10, "lo"), (15, "mid"), (20, "hi")):
            remote = state({"a": 1}, {f"k-{rid}": record("v", {"a": 1}, "a")})
            request = make_request(rid=rid, remote=remote)
            path = os.path.join(self.dir, f"b-{rid}.json")
            result = R.apply_signed_remote(
                path, ring, envelope(request), instant
            )
            self.assertEqual(result["status"], "applied", msg=f"at {instant}")

    def test_not_yet_valid_and_expired(self) -> None:
        ring = keyring(key_entry(not_before=10, not_after=20))
        with self.assertRaisesRegex(R.AuthenticationError, "not yet valid"):
            self.signed(instant=9, ring=ring)
        with self.assertRaisesRegex(R.AuthenticationError, "expired"):
            self.signed(instant=21, ring=ring)
        self.assertFalse(os.path.exists(self.path))

    def test_revoked_credential(self) -> None:
        ring = keyring(key_entry(revoked=True))
        with self.assertRaisesRegex(R.AuthenticationError, "revoked"):
            self.signed(ring=ring)
        self.assertFalse(os.path.exists(self.path))

    # -- identity and signature --------------------------------------------

    def test_source_must_equal_node(self) -> None:
        request = make_request(source="node-b")
        # Signature is valid for node-a over that request; the identity
        # claim inside the signed request still does not match.
        env = envelope(request, node="node-a", secret=SECRET_A1)
        with self.assertRaisesRegex(R.AuthenticationError, "source must equal"):
            self.signed(env=env)
        self.assertFalse(os.path.exists(self.path))

    def test_signature_mismatch_is_authentication_error(self) -> None:
        env = dict(self.envelope)
        env["signature"] = ("0" * 64 if env["signature"] != "0" * 64
                            else "1" * 64)
        with self.assertRaisesRegex(R.AuthenticationError, "signature"):
            self.signed(env=env)
        self.assertFalse(os.path.exists(self.path))

    def test_tampered_request_after_signing_fails(self) -> None:
        env = envelope(self.request)
        env["request"] = make_request(rid="forged", remote=self.remote)
        with self.assertRaises(R.AuthenticationError):
            self.signed(env=env)
        self.assertFalse(os.path.exists(self.path))

    def test_wrong_secret_fails(self) -> None:
        env = envelope(self.request, secret=SECRET_A2)
        with self.assertRaises(R.AuthenticationError):
            self.signed(env=env)

    def test_constant_time_comparison_is_used(self) -> None:
        with mock.patch(
            "offline_coordination.replication.hmac.compare_digest",
            wraps=hmac.compare_digest,
        ) as compared:
            self.signed()
        compared.assert_called()
        args = compared.call_args.args
        self.assertEqual(len(args[0]), len(args[1]))

    # -- replay re-authenticates against the *current* keyring -------------

    def test_replay_with_valid_credential_is_duplicate(self) -> None:
        self.signed()
        before = ledger_raw(self.path)
        again = self.signed()
        self.assertEqual(again["status"], "duplicate")
        self.assertIsNone(again["receipt"])
        self.assertEqual(
            again["items"],
            [{"key": "k", "decision": "duplicate", "need": {}}],
        )
        self.assertEqual(ledger_raw(self.path), before)

    def test_replay_after_revocation_is_rejected(self) -> None:
        self.signed(instant=100)
        revoked_ring = keyring(key_entry(revoked=True))
        # The historical binding must not let a revoked credential replay.
        with self.assertRaisesRegex(R.AuthenticationError, "revoked"):
            R.apply_signed_remote(self.path, revoked_ring, self.envelope, 100)

    def test_replay_after_expiry_is_rejected(self) -> None:
        ring = keyring(key_entry(not_before=0, not_after=100))
        R.apply_signed_remote(self.path, ring, self.envelope, 50)
        with self.assertRaisesRegex(R.AuthenticationError, "expired"):
            R.apply_signed_remote(self.path, ring, self.envelope, 101)

    def test_replay_with_rotated_version_requires_matching_signature(self) -> None:
        ring = keyring(
            key_entry(1, SECRET_A1), key_entry(2, SECRET_A2)
        )
        R.apply_signed_remote(self.path, ring, self.envelope, 50)
        # Replaying the original envelope (keyVersion 1) still verifies.
        again = R.apply_signed_remote(self.path, ring, self.envelope, 50)
        self.assertEqual(again["status"], "duplicate")
        # An envelope claiming version 2 without a version-2 signature is a
        # mismatch -- the original binding is not an authentication bypass.
        rotated = dict(self.envelope, keyVersion=2)
        with self.assertRaises(R.AuthenticationError):
            R.apply_signed_remote(self.path, ring, rotated, 50)

    # -- verification ordering ---------------------------------------------

    def test_authentication_runs_before_ledger_read(self) -> None:
        with open(self.path, "wb") as handle:
            handle.write(b"not a ledger\n")
        with mock.patch("builtins.open") as opened:
            with self.assertRaises(R.AuthenticationError):
                self.signed(env=dict(self.envelope, signature="f" * 64))
        opened.assert_not_called()

    def test_corrupt_ledger_with_valid_signature_is_value_error(self) -> None:
        with open(self.path, "wb") as handle:
            handle.write(b"not a ledger\n")
        # Authentication passes; only then is the corrupt ledger read.
        with self.assertRaises(ValueError):
            self.signed()

    def test_authentication_failure_creates_no_file(self) -> None:
        for make_env in (
            lambda: dict(self.envelope, signature="f" * 64),
            lambda: dict(self.envelope, node="node-zz"),
            lambda: envelope(make_request(source="node-b")),
        ):
            path = os.path.join(self.dir, "fresh.json")
            with self.assertRaises(R.AuthenticationError):
                R.apply_signed_remote(path, self.keyring, make_env(), 500)
            self.assertFalse(os.path.exists(path))
            self.assertFalse(os.path.exists(path + ".tmp"))
            self.assertFalse(os.path.exists(path + ".old"))
        self.assertEqual(os.listdir(self.dir), [])

    def test_request_contract_checked_only_after_authentication(self) -> None:
        # Valid signature, identity matches, but the request lacks 'base':
        # once authenticated, the existing flow rejects it with ValueError.
        request = {"id": "r1", "source": "node-a", "remote": self.remote}
        env = envelope(request)
        with self.assertRaises(ValueError):
            self.signed(env=env)
        self.assertFalse(os.path.exists(self.path))

    # -- only "applied" has a side effect ----------------------------------

    def test_non_applying_outcome_writes_nothing_and_has_no_auth(self) -> None:
        # Unknown id offered against the wrong base: verified, then stale.
        seeded = state({"a": 1}, {"k": record("v", {"a": 1}, "a")})
        R.apply_signed_remote(
            self.path, self.keyring,
            envelope(make_request(rid="seed", remote=seeded)), 500,
        )
        before = ledger_raw(self.path)
        request = make_request(rid="other", base=state(), remote=seeded)
        result = R.apply_signed_remote(
            self.path, self.keyring, envelope(request), 500
        )
        self.assertEqual(result["status"], "stale")
        self.assertIsNone(result["receipt"])
        self.assertEqual(ledger_raw(self.path), before)

    def test_empty_remote_duplicate_creates_no_file(self) -> None:
        path = os.path.join(self.dir, "empty.json")
        request = make_request(rid="e", base=state(), remote=state())
        result = R.apply_signed_remote(path, self.keyring, envelope(request), 500)
        self.assertEqual(result["status"], "duplicate")
        self.assertFalse(os.path.exists(path))

    # -- error taxonomy ------------------------------------------------------

    def test_authentication_error_is_value_error(self) -> None:
        self.assertTrue(issubclass(R.AuthenticationError, ValueError))
        with self.assertRaises(ValueError):
            self.signed(env=dict(self.envelope, signature="0" * 64))


class KeyringValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.remote = state({"a": 1}, {"k": record("v", {"a": 1}, "a")})
        self.request = make_request(remote=self.remote)

    def call(self, ring, instant=500, env=None):
        return R.apply_signed_remote(
            self.path, ring, env or envelope(self.request), instant
        )

    def test_keyring_must_be_dict(self) -> None:
        for bad in ([], None, "x"):
            with self.assertRaises(TypeError):
                self.call(bad)

    def test_node_name_must_be_nonempty_str(self) -> None:
        with self.assertRaises(TypeError):
            self.call({1: [key_entry()]})
        with self.assertRaises(ValueError):
            self.call({"": [key_entry()]})

    def test_entries_must_be_a_list(self) -> None:
        with self.assertRaises(TypeError):
            self.call({"node-a": key_entry()})

    def test_entry_must_be_dict_with_exact_keys(self) -> None:
        with self.assertRaises(TypeError):
            self.call({"node-a": [[]]})
        good = key_entry()
        with self.assertRaises(ValueError):
            self.call({"node-a": [dict(good, extra=1)]})
        without = dict(good)
        del without["revoked"]
        with self.assertRaises(ValueError):
            self.call({"node-a": [without]})

    def test_version_must_be_positive_nonbool_int(self) -> None:
        for bad in (True, 1.0, "1", None):
            with self.assertRaises(TypeError):
                self.call({"node-a": [key_entry(version=bad)]})
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                self.call({"node-a": [key_entry(version=bad)]})

    def test_duplicate_versions_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.call({"node-a": [key_entry(1, SECRET_A1),
                                  key_entry(1, SECRET_A2)]})

    def test_secret_must_be_64_lowercase_hex(self) -> None:
        for bad in (1, b"a" * 64, None):
            with self.assertRaises(TypeError):
                self.call({"node-a": [key_entry(secret=bad)]})
        for bad in ("a" * 63, "A" * 64, "g" * 64, "a1" * 31 + "A"):
            with self.assertRaises(ValueError):
                self.call({"node-a": [key_entry(secret=bad)]})

    def test_bounds_must_be_non_negative_nonbool_ints(self) -> None:
        for field in ("not_before", "not_after"):
            for bad in (True, 1.0, "5", None):
                with self.assertRaises(TypeError):
                    self.call({"node-a": [key_entry(**{field: bad})]})
            with self.assertRaises(ValueError):
                self.call({"node-a": [key_entry(**{field: -1})]})

    def test_not_before_must_not_exceed_not_after(self) -> None:
        with self.assertRaises(ValueError):
            self.call({"node-a": [key_entry(not_before=11, not_after=10)]})
        # Equal bounds are fine (a single-instant window).
        ring = keyring(key_entry(not_before=7, not_after=7))
        result = self.call(ring, instant=7)
        self.assertEqual(result["status"], "applied")

    def test_revoked_must_be_bool(self) -> None:
        for bad in (1, 0, "yes", None):
            with self.assertRaises(TypeError):
                self.call({"node-a": [key_entry(revoked=bad)]})

    def test_keyring_validation_precedes_filesystem(self) -> None:
        with mock.patch("builtins.open") as opened:
            with self.assertRaises((TypeError, ValueError)):
                self.call({"node-a": [key_entry(version=0)]})
        opened.assert_not_called()


class EnvelopeAndInstantValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.ring = keyring(key_entry())
        self.request = make_request()

    def call(self, env=None, instant=500, path=None):
        return R.apply_signed_remote(
            path or self.path, self.ring,
            env if env is not None else envelope(self.request), instant,
        )

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            R.apply_signed_remote(1, self.ring, envelope(self.request), 500)

    def test_envelope_must_be_dict_with_exact_keys(self) -> None:
        with self.assertRaises(TypeError):
            self.call([])
        good = envelope(self.request)
        with self.assertRaises(ValueError):
            self.call(dict(good, extra=1))
        missing = dict(good)
        del missing["node"]
        with self.assertRaises(ValueError):
            self.call(missing)

    def test_node_must_be_nonempty_str(self) -> None:
        good = envelope(self.request)
        for bad in (1, True, None):
            with self.assertRaises(TypeError):
                self.call(dict(good, node=bad))
        with self.assertRaises(ValueError):
            self.call(dict(good, node=""))

    def test_key_version_must_be_positive_nonbool_int(self) -> None:
        good = envelope(self.request)
        for bad in (True, 1.0, "1", None):
            with self.assertRaises(TypeError):
                self.call(dict(good, keyVersion=bad))
        for bad in (0, -3):
            with self.assertRaises(ValueError):
                self.call(dict(good, keyVersion=bad))

    def test_signature_must_be_64_lowercase_hex(self) -> None:
        good = envelope(self.request)
        for bad in (1, b"f" * 64, None):
            with self.assertRaises(TypeError):
                self.call(dict(good, signature=bad))
        for bad in ("f" * 63, "F" * 64, "g" * 64, "01" * 31 + "G"):
            with self.assertRaises(ValueError):
                self.call(dict(good, signature=bad))

    def test_request_must_be_dict(self) -> None:
        good = envelope(self.request)
        with self.assertRaises(TypeError):
            self.call(dict(good, request=[]))
        with self.assertRaises(TypeError):
            self.call(dict(good, request=None))

    def test_instant_must_be_non_negative_nonbool_int(self) -> None:
        for bad in (True, 1.0, "500", None):
            with self.assertRaises(TypeError):
                self.call(instant=bad)
        with self.assertRaises(ValueError):
            self.call(instant=-1)

    def test_validation_precedes_filesystem(self) -> None:
        good = envelope(self.request)
        with mock.patch("builtins.open") as opened:
            with self.assertRaises(TypeError):
                self.call(instant="now")
            with self.assertRaises(ValueError):
                self.call(dict(good, keyVersion=0))
        opened.assert_not_called()


class SignedLedgerCompatibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"a": 1}, {"k": record("v1", {"a": 1}, "a")})

    def test_legacy_unsigned_entries_remain_readable(self) -> None:
        replication.apply_remote(
            self.path, make_request(rid="u1", remote=self.s1)
        )
        raw = ledger_raw(self.path)
        self.assertNotIn(b'"auth"', raw)
        # A signed application chains onto the unsigned ledger.
        s2 = state({"a": 2}, {"k": record("v2", {"a": 2}, "a")})
        ring = keyring(key_entry(1, SECRET_A1))
        request = make_request(rid="s1", base=self.s1, remote=s2)
        result = R.apply_signed_remote(self.path, ring, envelope(request), 500)
        self.assertEqual(result["status"], "applied")
        entries = read_ledger(self.path)["audit"]
        self.assertNotIn("auth", entries[0])
        self.assertEqual(entries[1]["auth"],
                         {"keyVersion": 1, "node": "node-a"})

    def test_apply_remote_unchanged_after_signed_commit(self) -> None:
        ring = keyring(key_entry(1, SECRET_A1))
        R.apply_signed_remote(
            self.path, ring, envelope(make_request(rid="s1", remote=self.s1)),
            500,
        )
        # The unsigned entry point still behaves exactly as before and
        # writes entries without auth.
        s2 = state({"a": 2}, {"k": record("v2", {"a": 2}, "a")})
        result = replication.apply_remote(
            self.path, make_request(rid="u2", base=self.s1, remote=s2)
        )
        self.assertEqual(result["status"], "applied")
        entries = read_ledger(self.path)["audit"]
        self.assertEqual(entries[0]["auth"],
                         {"keyVersion": 1, "node": "node-a"})
        self.assertNotIn("auth", entries[1])

    def test_signed_replay_after_unsigned_commit_still_duplicate(self) -> None:
        ring = keyring(key_entry(1, SECRET_A1))
        env = envelope(make_request(rid="s1", remote=self.s1))
        R.apply_signed_remote(self.path, ring, env, 500)
        s2 = state({"a": 2}, {"k": record("v2", {"a": 2}, "a")})
        replication.apply_remote(
            self.path, make_request(rid="u2", base=self.s1, remote=s2)
        )
        # Judged against current state the signed record would be stale, but
        # the binding makes it a duplicate -- re-authentication permitting.
        result = R.apply_signed_remote(self.path, ring, env, 500)
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(
            result["items"],
            [{"key": "k", "decision": "duplicate", "need": {}}],
        )

    def test_corrupt_auth_record_is_rejected(self) -> None:
        ring = keyring(key_entry(1, SECRET_A1))
        R.apply_signed_remote(
            self.path, ring, envelope(make_request(rid="s1", remote=self.s1)),
            500,
        )

        def reject(mutated):
            path = os.path.join(self.dir, "corrupt.json")
            with open(path, "wb") as handle:
                handle.write(mutated)
            with self.assertRaises(ValueError):
                R.apply_signed_remote(
                    path, ring,
                    envelope(make_request(rid="x", base=self.s1,
                                          remote=self.s1)),
                    500,
                )

        data = json.loads(ledger_raw(self.path))
        good_entry = data["audit"][0]
        bad_key_set = json.dumps(
            {**data, "audit": [{**good_entry,
                                "auth": {"node": "node-a", "keyVersion": 1,
                                         "extra": 2}}]},
            sort_keys=True, separators=(",", ":"),
        ).encode() + b"\n"
        reject(bad_key_set)
        bad_version = json.dumps(
            {**data, "audit": [{**good_entry,
                                "auth": {"node": "node-a", "keyVersion": 0}}]},
            sort_keys=True, separators=(",", ":"),
        ).encode() + b"\n"
        reject(bad_version)
        bad_node = json.dumps(
            {**data, "audit": [{**good_entry,
                                "auth": {"node": "", "keyVersion": 1}}]},
            sort_keys=True, separators=(",", ":"),
        ).encode() + b"\n"
        reject(bad_node)

    def test_legacy_artifacts_never_participate_in_read(self) -> None:
        ring = keyring(key_entry(1, SECRET_A1))
        env = envelope(make_request(rid="s1", remote=self.s1))
        R.apply_signed_remote(self.path, ring, env, 500)
        with open(self.path + ".tmp", "wb") as handle:
            handle.write(b"stale temp\n")
        with open(self.path + ".old", "wb") as handle:
            handle.write(b"stale old\n")
        # Leftover artifacts neither block a valid replay nor are read.
        result = R.apply_signed_remote(self.path, ring, env, 500)
        self.assertEqual(result["status"], "duplicate")
        # And a follow-up commit sweeps them like the unsigned flow does.
        s2 = state({"a": 2}, {"k": record("v2", {"a": 2}, "a")})
        next_env = envelope(make_request(rid="s2", base=self.s1, remote=s2))
        committed = R.apply_signed_remote(self.path, ring, next_env, 500)
        self.assertEqual(committed["status"], "applied")
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertFalse(os.path.exists(self.path + ".old"))


class SignedAtomicityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")
        self.s1 = state({"a": 1}, {"k": record("v1", {"a": 1}, "a")})
        self.ring = keyring(key_entry(1, SECRET_A1))
        R.apply_signed_remote(
            self.path, self.ring,
            envelope(make_request(rid="s1", remote=self.s1)), 500,
        )
        self.before = ledger_raw(self.path)

    def test_replace_failure_preserves_bytes(self) -> None:
        s2 = state({"a": 2}, {"k": record("v2", {"a": 2}, "a")})
        env = envelope(make_request(rid="s2", base=self.s1, remote=s2))
        with mock.patch("os.replace", side_effect=OSError("rename failed")):
            with self.assertRaises(OSError):
                R.apply_signed_remote(self.path, self.ring, env, 500)
        self.assertEqual(ledger_raw(self.path), self.before)
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertFalse(os.path.exists(self.path + ".old"))
        # The credential-verified request commits cleanly on retry.
        self.assertEqual(
            R.apply_signed_remote(self.path, self.ring, env, 500)["status"],
            "applied",
        )

    def test_fsync_failure_keeps_missing_ledger_missing(self) -> None:
        fresh = os.path.join(self.dir, "fresh.json")
        env = envelope(make_request(rid="s9", remote=self.s1))
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                R.apply_signed_remote(fresh, self.ring, env, 500)
        self.assertFalse(os.path.exists(fresh))
        self.assertFalse(os.path.exists(fresh + ".tmp"))


if __name__ == "__main__":
    unittest.main()
