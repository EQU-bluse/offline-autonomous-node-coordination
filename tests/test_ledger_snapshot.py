"""Tests for trusted ledger snapshots (device replacement).

Covers :func:`export_ledger_snapshot`, :func:`verify_ledger_snapshot`
and :func:`restore_ledger_snapshot`: the signed self-contained export,
the fully offline verification and the reconciling restore that only
ever moves a target ledger forward.
"""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import replication as R
from offline_coordination.replication import (
    AuthenticationError,
    InvalidLedgerSnapshotError,
    LedgerSnapshotForkError,
    PendingRecoveryError,
    StaleLedgerSnapshotError,
    apply_remote,
    export_ledger_snapshot,
    restore_ledger_snapshot,
    verify_ledger_snapshot,
)

SECRET_B = "b" * 64
ISSUER = "node-b"
NOW = 10


def state(clock=None, records=None):
    return {"clock": dict(clock or {}), "records": dict(records or {})}


def record(value, n, writer="node-a"):
    return [value, False, {writer: n}, writer]


def make_request(rid, base, remote, source="node-a"):
    return {"id": rid, "source": source, "base": base, "remote": remote}


def keyring():
    return {
        ISSUER: [
            {
                "version": 1,
                "secret": SECRET_B,
                "notBefore": 0,
                "notAfter": 100,
                "revoked": False,
            }
        ]
    }


S0 = state()
S1 = state({"node-a": 1}, {"k": record("v1", 1)})
S2 = state({"node-a": 2}, {"k": record("v2", 2)})
S2ALT = state({"node-a": 2}, {"k": record("w2", 2)})

REQ1 = make_request("r1", S0, S1)
REQ2 = make_request("r2", S1, S2)
REQ2ALT = make_request("r2x", S1, S2ALT)


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def digest_of(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    return json.loads(data)


class LedgerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.json")

    def seed(self, requests, path=None):
        """Apply the given requests to a fresh ledger and return its path."""
        path = self.path if path is None else path
        for request in requests:
            result = apply_remote(path, request)
            self.assertEqual(result["status"], "applied")
        return path

    def seed_one(self, path=None):
        return self.seed([REQ1], path=path)

    def seed_two(self, path=None):
        return self.seed([REQ1, REQ2], path=path)

    def export(self, path=None, moment=NOW, ring=None):
        return export_ledger_snapshot(
            self.path if path is None else path,
            keyring() if ring is None else ring,
            ISSUER,
            1,
            moment,
        )


class ExportLedgerSnapshotTest(LedgerCase):
    def test_missing_ledger_raises_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.export()

    def test_pending_recovery_intent_raises(self) -> None:
        self.seed_one()
        with open(self.path + ".txn", "wb") as handle:
            handle.write(b"garbage")
        with self.assertRaises(PendingRecoveryError):
            self.export()
        with self.assertRaises(PendingRecoveryError):
            self.export()

    def test_pending_intent_without_ledger_raises(self) -> None:
        with open(self.path + ".txn", "wb") as handle:
            handle.write(b"garbage")
        with self.assertRaises(PendingRecoveryError):
            self.export()

    def test_corrupt_ledger_raises_value_error(self) -> None:
        self.seed_one()
        with open(self.path, "wb") as handle:
            handle.write(b'{"audit": [], "version": 1}\n')
        with self.assertRaises(ValueError):
            self.export()

    def test_top_level_shape_and_canonical_form(self) -> None:
        self.seed_two()
        snapshot = self.export()
        self.assertIsInstance(snapshot, bytes)
        self.assertFalse(snapshot.endswith(b"\n"))
        self.assertEqual(snapshot, canonical(decode(snapshot)))
        self.assertEqual(set(decode(snapshot)), {"payload", "signature"})

    def test_payload_binds_ledger_and_metadata(self) -> None:
        self.seed_two()
        raw = read_bytes(self.path)
        payload = decode(self.export())["payload"]
        self.assertEqual(
            set(payload),
            {
                "issuer",
                "keyVersion",
                "lastSeq",
                "ledger",
                "ledgerDigest",
                "requestCount",
                "signedAt",
                "stateDigest",
                "version",
            },
        )
        self.assertEqual(payload["ledger"], raw.hex())
        self.assertEqual(bytes.fromhex(payload["ledger"]), raw)
        self.assertEqual(payload["ledgerDigest"], digest_of(raw))
        self.assertEqual(payload["lastSeq"], 2)
        self.assertEqual(payload["requestCount"], 2)
        self.assertEqual(payload["issuer"], ISSUER)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["signedAt"], NOW)
        self.assertEqual(payload["version"], 1)
        state_digest = hashlib.sha256(
            R._state_bytes(decode(raw)["state"])
        ).hexdigest()
        self.assertEqual(payload["stateDigest"], state_digest)

    def test_signature_matches_canonical_payload(self) -> None:
        self.seed_one()
        snapshot = decode(self.export())
        expected = hmac.new(
            bytes.fromhex(SECRET_B),
            canonical(snapshot["payload"]),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(snapshot["signature"], expected)

    def test_export_is_read_only(self) -> None:
        self.seed_one()
        before = read_bytes(self.path)
        names_before = sorted(os.listdir(self.dir))
        self.export()
        self.assertEqual(read_bytes(self.path), before)
        self.assertEqual(sorted(os.listdir(self.dir)), names_before)

    def test_argument_validation(self) -> None:
        self.seed_one()
        with self.assertRaises(TypeError):
            export_ledger_snapshot(1, keyring(), ISSUER, 1, NOW)
        with self.assertRaises(TypeError):
            export_ledger_snapshot(self.path, keyring(), 1, 1, NOW)
        with self.assertRaises(TypeError):
            export_ledger_snapshot(self.path, keyring(), ISSUER, True, NOW)
        with self.assertRaises(TypeError):
            export_ledger_snapshot(self.path, keyring(), ISSUER, 1, 1.0)
        with self.assertRaises(ValueError):
            export_ledger_snapshot(self.path, keyring(), "", 1, NOW)
        with self.assertRaises(ValueError):
            export_ledger_snapshot(self.path, keyring(), ISSUER, 0, NOW)
        with self.assertRaises(ValueError):
            export_ledger_snapshot(self.path, keyring(), ISSUER, 1, -1)
        with self.assertRaises(TypeError):
            export_ledger_snapshot(self.path, [], ISSUER, 1, NOW)

    def test_credential_faults_raise_authentication_error(self) -> None:
        self.seed_one()
        with self.assertRaises(AuthenticationError):
            export_ledger_snapshot(self.path, keyring(), "node-c", 1, NOW)
        with self.assertRaises(AuthenticationError):
            export_ledger_snapshot(self.path, keyring(), ISSUER, 2, NOW)
        revoked = keyring()
        revoked[ISSUER][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            export_ledger_snapshot(self.path, revoked, ISSUER, 1, NOW)
        with self.assertRaises(AuthenticationError):
            export_ledger_snapshot(self.path, keyring(), ISSUER, 1, 101)


class VerifyLedgerSnapshotTest(LedgerCase):
    def verify(self, snapshot, moment=NOW, ring=None):
        return verify_ledger_snapshot(
            snapshot, keyring() if ring is None else ring, moment
        )

    def test_round_trip_returns_payload_metadata(self) -> None:
        self.seed_two()
        raw = read_bytes(self.path)
        snapshot = self.export()
        info = self.verify(snapshot)
        self.assertEqual(
            list(info.keys()),
            [
                "issuer",
                "keyVersion",
                "signedAt",
                "ledgerDigest",
                "stateDigest",
                "lastSeq",
                "requestCount",
            ],
        )
        self.assertEqual(
            info,
            {
                "issuer": ISSUER,
                "keyVersion": 1,
                "signedAt": NOW,
                "ledgerDigest": digest_of(raw),
                "stateDigest": decode(snapshot)["payload"]["stateDigest"],
                "lastSeq": 2,
                "requestCount": 2,
            },
        )

    def test_non_bytes_raises_type_error(self) -> None:
        self.seed_one()
        with self.assertRaises(TypeError):
            self.verify(decode(self.export()))
        with self.assertRaises(TypeError):
            self.verify(None)

    def test_trailing_byte_rejected(self) -> None:
        self.seed_one()
        with self.assertRaises(InvalidLedgerSnapshotError):
            self.verify(self.export() + b"\n")

    def test_duplicate_keys_rejected(self) -> None:
        self.seed_one()
        snapshot = self.export()
        payload = canonical(decode(snapshot)["payload"]).decode("utf-8")
        forged = (
            b'{"payload":'
            + payload.encode("utf-8")[:-1]
            + b',"issuer":"node-b"}'
            + b',"signature":"'
            + b"0" * 64
            + b'"}'
        )
        with self.assertRaises(InvalidLedgerSnapshotError):
            self.verify(forged)

    def test_added_or_removed_fields_rejected(self) -> None:
        self.seed_one()
        snapshot = decode(self.export())
        added = dict(snapshot["payload"])
        added["extra"] = 1
        with self.assertRaises(InvalidLedgerSnapshotError):
            self.verify(canonical({"payload": added, "signature": snapshot["signature"]}))
        removed = dict(snapshot["payload"])
        del removed["lastSeq"]
        with self.assertRaises(InvalidLedgerSnapshotError):
            self.verify(canonical({"payload": removed, "signature": snapshot["signature"]}))
        with self.assertRaises(InvalidLedgerSnapshotError):
            self.verify(canonical({"payload": snapshot["payload"]}))

    def test_noncanonical_encoding_rejected(self) -> None:
        self.seed_one()
        pretty = json.dumps(decode(self.export()), indent=2).encode("utf-8")
        with self.assertRaises(InvalidLedgerSnapshotError):
            self.verify(pretty)

    def test_unparseable_carried_ledger_rejected(self) -> None:
        self.seed_one()
        snapshot = decode(self.export())
        payload = dict(snapshot["payload"])
        payload["ledger"] = b"{}\n".hex()
        payload["ledgerDigest"] = digest_of(b"{}\n")
        forged = canonical({"payload": payload, "signature": snapshot["signature"]})
        with self.assertRaises(InvalidLedgerSnapshotError):
            self.verify(forged)

    def test_digest_and_statistics_mismatches_rejected(self) -> None:
        self.seed_two()
        snapshot = decode(self.export())
        other = digest_of(b"different")
        for key, value in (
            ("ledgerDigest", other),
            ("stateDigest", other),
            ("lastSeq", 1),
            ("requestCount", 7),
        ):
            payload = dict(snapshot["payload"])
            payload[key] = value
            forged = canonical(
                {"payload": payload, "signature": snapshot["signature"]}
            )
            with self.assertRaises(InvalidLedgerSnapshotError, msg=key):
                self.verify(forged)

    def test_future_signed_at_rejected(self) -> None:
        self.seed_one()
        snapshot = self.export(moment=NOW)
        with self.assertRaises(InvalidLedgerSnapshotError):
            self.verify(snapshot, moment=NOW - 1)

    def test_signature_mismatch_raises_authentication_error(self) -> None:
        self.seed_one()
        snapshot = decode(self.export())
        bad = dict(snapshot)
        signature = snapshot["signature"]
        bad["signature"] = ("1" if signature[0] != "1" else "2") + signature[1:]
        with self.assertRaises(AuthenticationError):
            self.verify(canonical(bad))

    def test_tampered_payload_raises_authentication_error(self) -> None:
        self.seed_one()
        snapshot = decode(self.export())
        payload = dict(snapshot["payload"])
        payload["signedAt"] = NOW - 1
        forged = canonical({"payload": payload, "signature": snapshot["signature"]})
        with self.assertRaises(AuthenticationError):
            self.verify(forged)

    def test_credential_faults_raise_authentication_error(self) -> None:
        self.seed_one()
        snapshot = self.export()
        with self.assertRaises(AuthenticationError):
            self.verify(snapshot, ring={})
        revoked = keyring()
        revoked[ISSUER][0]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.verify(snapshot, ring=revoked)
        with self.assertRaises(AuthenticationError):
            self.verify(snapshot, moment=101)
        expired = keyring()
        expired[ISSUER][0]["notAfter"] = NOW - 1
        with self.assertRaises(AuthenticationError):
            self.verify(snapshot, ring=expired)

    def test_argument_validation(self) -> None:
        self.seed_one()
        snapshot = self.export()
        with self.assertRaises(TypeError):
            verify_ledger_snapshot(snapshot, [], NOW)
        with self.assertRaises(TypeError):
            verify_ledger_snapshot(snapshot, keyring(), True)
        with self.assertRaises(ValueError):
            verify_ledger_snapshot(snapshot, keyring(), -1)


class RestoreLedgerSnapshotTest(LedgerCase):
    def restore(self, snapshot, path=None, moment=NOW, ring=None):
        return restore_ledger_snapshot(
            self.path if path is None else path,
            snapshot,
            keyring() if ring is None else ring,
            moment,
        )

    def test_missing_target_installs_snapshot(self) -> None:
        source = os.path.join(self.dir, "source.json")
        self.seed_two(path=source)
        raw = read_bytes(source)
        snapshot = self.export(path=source)

        result = self.restore(snapshot)
        self.assertEqual(list(result.keys()), ["status", "next", "ledgerDigest"])
        self.assertEqual(
            result,
            {"status": "applied", "next": 2, "ledgerDigest": digest_of(raw)},
        )
        self.assertEqual(read_bytes(self.path), raw)
        # No transaction artifacts survive a successful install.
        self.assertEqual(sorted(os.listdir(self.dir)), ["ledger.json", "source.json"])

    def test_identical_target_is_duplicate_without_write(self) -> None:
        self.seed_two()
        raw = read_bytes(self.path)
        snapshot = self.export()
        result = self.restore(snapshot)
        self.assertEqual(
            result,
            {"status": "duplicate", "next": 2, "ledgerDigest": digest_of(raw)},
        )
        self.assertEqual(read_bytes(self.path), raw)

    def test_prefix_target_advances(self) -> None:
        self.seed_one()
        source = os.path.join(self.dir, "source.json")
        self.seed_two(path=source)
        raw = read_bytes(source)
        snapshot = self.export(path=source)

        result = self.restore(snapshot)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["next"], 2)
        self.assertEqual(result["ledgerDigest"], digest_of(raw))
        self.assertEqual(read_bytes(self.path), raw)

    def test_empty_audit_target_with_matching_boundary_advances(self) -> None:
        # A genesis-state ledger with an empty audit is a valid prefix of
        # any ledger built from the same base state.
        empty = canonical(
            {"audit": [], "requests": {}, "state": S0, "version": 1}
        ) + b"\n"
        with open(self.path, "wb") as handle:
            handle.write(empty)
        source = os.path.join(self.dir, "source.json")
        self.seed_two(path=source)
        snapshot = self.export(path=source)
        result = self.restore(snapshot)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_bytes(self.path), read_bytes(source))

    def test_stale_snapshot_raises_and_keeps_target(self) -> None:
        self.seed_two()
        raw = read_bytes(self.path)
        source = os.path.join(self.dir, "source.json")
        self.seed_one(path=source)
        snapshot = self.export(path=source)
        with self.assertRaises(StaleLedgerSnapshotError):
            self.restore(snapshot)
        self.assertEqual(read_bytes(self.path), raw)

    def test_same_seq_divergence_raises_fork_and_keeps_target(self) -> None:
        self.seed([REQ1, REQ2])
        raw = read_bytes(self.path)
        source = os.path.join(self.dir, "source.json")
        self.seed([REQ1, REQ2ALT], path=source)
        snapshot = self.export(path=source)
        with self.assertRaises(LedgerSnapshotForkError):
            self.restore(snapshot)
        self.assertEqual(read_bytes(self.path), raw)

    def test_conflicting_request_binding_raises_fork(self) -> None:
        self.seed_one()
        raw = read_bytes(self.path)
        # A ledger with the identical audit entry but a different request
        # binding for the same id is a fork, not an advance.
        forged = decode(raw)
        forged["requests"]["r1"] = "0" * 64
        source = os.path.join(self.dir, "source.json")
        with open(source, "wb") as handle:
            handle.write(canonical(forged) + b"\n")
        snapshot = self.export(path=source)
        with self.assertRaises(LedgerSnapshotForkError):
            self.restore(snapshot)
        self.assertEqual(read_bytes(self.path), raw)

    def test_divergent_boundary_state_raises_fork(self) -> None:
        # An empty-audit target whose state is not the snapshot's genesis
        # state disagrees about the shared boundary.
        empty = canonical(
            {"audit": [], "requests": {}, "state": S1, "version": 1}
        ) + b"\n"
        with open(self.path, "wb") as handle:
            handle.write(empty)
        source = os.path.join(self.dir, "source.json")
        self.seed_one(path=source)
        snapshot = self.export(path=source)
        with self.assertRaises(LedgerSnapshotForkError):
            self.restore(snapshot)
        self.assertEqual(read_bytes(self.path), empty)

    def test_invalid_snapshot_never_touches_target(self) -> None:
        self.seed_one()
        raw = read_bytes(self.path)
        source = os.path.join(self.dir, "source.json")
        self.seed_two(path=source)
        snapshot = decode(self.export(path=source))
        snapshot["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.restore(canonical(snapshot))
        self.assertEqual(read_bytes(self.path), raw)

    def test_invalid_snapshot_never_creates_target(self) -> None:
        source = os.path.join(self.dir, "source.json")
        self.seed_one(path=source)
        snapshot = decode(self.export(path=source))
        snapshot["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.restore(canonical(snapshot))
        self.assertFalse(os.path.exists(self.path))

    def test_pending_transaction_is_settled_before_restore(self) -> None:
        self.seed_one()
        old_raw = read_bytes(self.path)
        source = os.path.join(self.dir, "source.json")
        self.seed_two(path=source)
        new_raw = read_bytes(source)
        snapshot = self.export(path=source)

        # Simulate a crash after the prepared intent was published but
        # before the replacement ran.
        candidate = "ledger.json.tmp.0123456789abcdef"
        predecessor = "ledger.json.old.0123456789abcdef"
        with open(os.path.join(self.dir, candidate), "wb") as handle:
            handle.write(new_raw)
        os.link(self.path, os.path.join(self.dir, predecessor))
        R._publish_intent(
            self.path,
            R._intent_payload(
                R.PHASE_PREPARED,
                digest_of(new_raw),
                digest_of(old_raw),
                candidate,
                predecessor,
            ),
        )

        result = self.restore(snapshot)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(read_bytes(self.path), new_raw)
        self.assertEqual(sorted(os.listdir(self.dir)), ["ledger.json", "source.json"])

    def test_corrupt_target_raises_and_is_left_untouched(self) -> None:
        source = os.path.join(self.dir, "source.json")
        self.seed_two(path=source)
        snapshot = self.export(path=source)
        with open(self.path, "wb") as handle:
            handle.write(b"not a ledger")
        with self.assertRaises(ValueError):
            self.restore(snapshot)
        self.assertEqual(read_bytes(self.path), b"not a ledger")

    def test_oserror_propagates_and_target_is_restored(self) -> None:
        self.seed_one()
        raw = read_bytes(self.path)
        source = os.path.join(self.dir, "source.json")
        self.seed_two(path=source)
        snapshot = self.export(path=source)

        real_replace = os.replace

        def failing_replace(src, dst):
            if dst == self.path:
                raise OSError("boom")
            return real_replace(src, dst)

        with mock.patch.object(os, "replace", side_effect=failing_replace):
            with self.assertRaises(OSError):
                self.restore(snapshot)
        self.assertEqual(read_bytes(self.path), raw)
        self.assertEqual(sorted(os.listdir(self.dir)), ["ledger.json", "source.json"])

    def test_argument_validation(self) -> None:
        self.seed_one()
        snapshot = self.export()
        with self.assertRaises(TypeError):
            restore_ledger_snapshot(1, snapshot, keyring(), NOW)
        with self.assertRaises(TypeError):
            restore_ledger_snapshot(self.path, "x", keyring(), NOW)
        with self.assertRaises(TypeError):
            restore_ledger_snapshot(self.path, snapshot, [], NOW)
        with self.assertRaises(TypeError):
            restore_ledger_snapshot(self.path, snapshot, keyring(), True)
        with self.assertRaises(ValueError):
            restore_ledger_snapshot(self.path, snapshot, keyring(), -1)

    def test_end_to_end_replacement_device(self) -> None:
        # Export from the old device, verify offline on the new one and
        # restore; a repeated restore is a side-effect-free duplicate.
        self.seed_two()
        snapshot = self.export()
        replacement = os.path.join(self.dir, "replacement.json")
        info = verify_ledger_snapshot(snapshot, keyring(), NOW)
        result = restore_ledger_snapshot(
            replacement, snapshot, keyring(), NOW
        )
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["ledgerDigest"], info["ledgerDigest"])
        self.assertEqual(read_bytes(replacement), read_bytes(self.path))
        again = restore_ledger_snapshot(replacement, snapshot, keyring(), NOW)
        self.assertEqual(again["status"], "duplicate")
        self.assertEqual(read_bytes(replacement), read_bytes(self.path))


if __name__ == "__main__":
    unittest.main()
