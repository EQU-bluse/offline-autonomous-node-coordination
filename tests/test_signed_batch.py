"""Tests for authenticated, byte-bounded signed audit batches."""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest import mock

from offline_coordination import audit, replication
from offline_coordination.audit import CorruptAuditError, append
from offline_coordination.replication import (
    AuthenticationError,
    InvalidSignedBatchError,
    export_signed_batch,
    import_signed_batch,
)

SECRET = "a" * 64
OTHER_SECRET = "b" * 64
ISSUER = "node-a"
SESSION = "transfer-1"
NOW = 100

RESULT_KEYS = ("status", "session", "next", "complete", "need", "fork")


def event(source=ISSUER, kind="local", detail="did something"):
    return {"source": source, "kind": kind, "detail": detail}


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def decode(data: bytes):
    return json.loads(data)


def key_entry(version=1, secret=SECRET, not_before=0, not_after=1000,
              revoked=False):
    return {
        "version": version,
        "secret": secret,
        "notBefore": not_before,
        "notAfter": not_after,
        "revoked": revoked,
    }


def keyring(*entries, issuer=ISSUER):
    return {issuer: list(entries)}


def sign_payload(payload: dict, secret: str = SECRET) -> str:
    return hmac.new(
        bytes.fromhex(secret), canonical(payload), hashlib.sha256
    ).hexdigest()


def resign(packet: dict, secret: str = SECRET) -> bytes:
    payload = packet["payload"]
    return canonical({"payload": payload, "signature": sign_payload(payload, secret)})


class ExportSignedBatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")
        self.ring = keyring(key_entry())

    def seed(self, n: int) -> None:
        for i in range(n):
            append(self.path, event(detail=f"event {i} ☃"))

    def export(self, after=0, max_bytes=10_000_000, session=SESSION,
               issuer=ISSUER, version=1, moment=NOW, ring=None):
        return export_signed_batch(
            self.path, after, max_bytes, session,
            ring if ring is not None else self.ring, issuer, version, moment,
        )

    def test_missing_log_yields_empty_complete_packet(self) -> None:
        data = self.export()
        packet = decode(data)
        self.assertEqual(set(packet.keys()), {"payload", "signature"})
        payload = packet["payload"]
        self.assertEqual(payload["after"], 0)
        self.assertEqual(payload["next"], 0)
        self.assertIs(payload["complete"], True)
        self.assertEqual(payload["records"], [])

    def test_payload_binds_every_required_field(self) -> None:
        self.seed(2)
        payload = decode(self.export(session="s-9", moment=77))["payload"]
        self.assertEqual(
            set(payload.keys()),
            {
                "after", "complete", "issuer", "keyVersion", "next",
                "records", "session", "signedAt", "version",
            },
        )
        self.assertEqual(payload["session"], "s-9")
        self.assertEqual(payload["issuer"], ISSUER)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["signedAt"], 77)
        self.assertEqual(payload["version"], 1)

    def test_compact_canonical_sorted_bytes_without_trailing_newline(self) -> None:
        self.seed(2)
        data = self.export()
        self.assertFalse(data.endswith(b"\n"))
        self.assertEqual(data, canonical(decode(data)))
        self.assertIn("☃".encode("utf-8"), data)

    def test_records_match_audit_log_exactly(self) -> None:
        self.seed(3)
        records = decode(self.export())["payload"]["records"]
        self.assertEqual([r["seq"] for r in records], [1, 2, 3])
        self.assertEqual(records, audit.read(self.path))
        self.assertEqual(
            tuple(records[0].keys()),
            ("detail", "hash", "kind", "prev", "seq", "source"),
        )

    def test_signature_is_hmac_of_canonical_payload(self) -> None:
        self.seed(2)
        data = self.export(moment=42)
        packet = decode(data)
        self.assertEqual(
            packet["signature"], sign_payload(packet["payload"])
        )

    def test_selection_starts_after_and_marks_complete(self) -> None:
        self.seed(5)
        packet = decode(self.export(after=2))["payload"]
        self.assertEqual([r["seq"] for r in packet["records"]], [3, 4, 5])
        self.assertEqual(packet["after"], 2)
        self.assertEqual(packet["next"], 5)
        self.assertIs(packet["complete"], True)

    def test_after_at_tail_gives_empty_complete_packet(self) -> None:
        self.seed(3)
        payload = decode(self.export(after=3))["payload"]
        self.assertEqual(payload["records"], [])
        self.assertEqual(payload["next"], 3)
        self.assertIs(payload["complete"], True)

    def test_empty_tail_packet_returned_even_when_budget_tiny(self) -> None:
        # At the tail no record is required, so the ValueError for a
        # non-fitting first record never applies.
        self.seed(1)
        data = self.export(after=1, max_bytes=1)
        payload = decode(data)["payload"]
        self.assertEqual(payload["records"], [])
        self.assertIs(payload["complete"], True)

    def test_budget_selects_maximal_prefix_and_never_exceeds_it(self) -> None:
        self.seed(6)
        full = self.export()
        # Exact full size carries every record; one byte fewer drops at
        # least the last one.
        self.assertEqual(decode(self.export(max_bytes=len(full)))["payload"]["next"], 6)
        self.assertLessEqual(
            decode(self.export(max_bytes=len(full) - 1))["payload"]["next"], 5
        )
        # Across every feasible budget the prefix is maximal and
        # monotonic, and the packet never exceeds its budget.  The first
        # budget that admits a prefix is exactly that packet's size;
        # budgets below the first record's packet raise ValueError.
        previous_next = -1
        for budget in range(1, len(full) + 1):
            try:
                data = self.export(max_bytes=budget)
            except ValueError:
                continue
            self.assertLessEqual(len(data), budget)
            nxt = decode(data)["payload"]["next"]
            self.assertGreaterEqual(nxt, previous_next)
            if nxt != previous_next:
                # Tight fit: the first budget admitting this prefix is
                # the exact packet size, so one byte fewer admitted one
                # record fewer (or no record at all for the first).
                self.assertEqual(
                    len(data), budget,
                    f"prefix of {nxt} records first fits at {budget} but "
                    f"the packet is only {len(data)} bytes",
                )
            previous_next = nxt
        self.assertEqual(previous_next, 6)

    def test_first_required_record_not_fitting_raises_value_error(self) -> None:
        self.seed(3)
        with self.assertRaises(ValueError):
            self.export(max_bytes=1)

    def test_does_not_modify_the_log(self) -> None:
        self.seed(2)
        with open(self.path, "rb") as handle:
            before = handle.read()
        self.export()
        self.export(max_bytes=10_000_000)
        with open(self.path, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_log_is_read_through_audit_read(self) -> None:
        self.seed(1)
        with mock.patch("offline_coordination.audit.read", wraps=audit.read) as p:
            self.export()
        p.assert_called_once_with(self.path)

    def test_corrupt_log_propagates(self) -> None:
        self.seed(2)
        good = open(self.path, "rb").read()
        with open(self.path, "wb") as handle:
            handle.write(good[:-1])
        with self.assertRaises(CorruptAuditError):
            self.export()

    def test_oserror_propagates(self) -> None:
        with mock.patch("offline_coordination.audit.read", side_effect=OSError):
            with self.assertRaises(OSError):
                self.export()


class ExportSignedBatchValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")
        append(self.path, event())
        self.ring = keyring(key_entry())

    def export(self, **overrides):
        kwargs = dict(
            path=self.path, after=0, max_bytes=10_000_000,
            session=SESSION, keyring=self.ring, issuer=ISSUER,
            version=1, moment=NOW,
        )
        kwargs.update(overrides)
        return export_signed_batch(**kwargs)

    def test_path_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            self.export(path=4)

    def test_after_must_be_int_not_bool(self) -> None:
        with self.assertRaises(TypeError):
            self.export(after=1.0)
        with self.assertRaises(TypeError):
            self.export(after=True)

    def test_max_bytes_must_be_int_not_bool(self) -> None:
        with self.assertRaises(TypeError):
            self.export(max_bytes=1.0)
        with self.assertRaises(TypeError):
            self.export(max_bytes=True)

    def test_session_and_issuer_must_be_str(self) -> None:
        with self.assertRaises(TypeError):
            self.export(session=7)
        with self.assertRaises(TypeError):
            self.export(issuer=7)

    def test_version_and_moment_reject_bool_and_float(self) -> None:
        with self.assertRaises(TypeError):
            self.export(version=1.0)
        with self.assertRaises(TypeError):
            self.export(version=True)
        with self.assertRaises(TypeError):
            self.export(moment=1.0)
        with self.assertRaises(TypeError):
            self.export(moment=False)

    def test_after_negative(self) -> None:
        with self.assertRaises(ValueError):
            self.export(after=-1)

    def test_max_bytes_non_positive(self) -> None:
        with self.assertRaises(ValueError):
            self.export(max_bytes=0)
        with self.assertRaises(ValueError):
            self.export(max_bytes=-10)

    def test_empty_session_and_issuer(self) -> None:
        with self.assertRaises(ValueError):
            self.export(session="")
        with self.assertRaises(ValueError):
            self.export(issuer="")

    def test_version_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            self.export(version=0)

    def test_moment_must_be_non_negative(self) -> None:
        with self.assertRaises(ValueError):
            self.export(moment=-1)

    def test_after_past_end_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.export(after=5)

    def test_bad_keyring_raises_value_error(self) -> None:
        bad = {ISSUER: [{"version": 1, "secret": "zzz",
                         "notBefore": 0, "notAfter": 1, "revoked": False}]}
        with self.assertRaises(ValueError):
            self.export(keyring=bad)

    def test_keyring_type_error(self) -> None:
        with self.assertRaises(TypeError):
            self.export(keyring=[])


class ExportSignedBatchAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.jsonl")
        append(self.path, event())

    def export(self, ring, moment=NOW, issuer=ISSUER, version=1):
        return export_signed_batch(
            self.path, 0, 10_000_000, SESSION, ring, issuer, version, moment,
        )

    def test_unknown_issuer(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.export(keyring(key_entry(), issuer="other"))

    def test_unknown_version(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.export(keyring(key_entry(version=1)), version=2)

    def test_revoked(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.export(keyring(key_entry(revoked=True)))

    def test_not_yet_valid_and_expired(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.export(keyring(key_entry(not_before=200)))
        with self.assertRaises(AuthenticationError):
            self.export(keyring(key_entry(not_after=50)))

    def test_validity_window_boundaries_accepted(self) -> None:
        ring = keyring(key_entry(not_before=50, not_after=150))
        # moment == notBefore and moment == notAfter both work.
        self.export(ring, moment=50)
        self.export(ring, moment=150)

    def test_exact_version_selected_no_fallback(self) -> None:
        ring = keyring(key_entry(version=2, secret=OTHER_SECRET))
        packet = decode(self.export(ring, version=2))
        self.assertEqual(packet["payload"]["keyVersion"], 2)
        self.assertEqual(
            packet["signature"],
            sign_payload(packet["payload"], OTHER_SECRET),
        )


class ImportSignedBatchBasicTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.source = os.path.join(self.dir, "source.jsonl")
        self.target = os.path.join(self.dir, "target.jsonl")
        self.ring = keyring(key_entry(not_after=1000))
        for i in range(5):
            append(self.source, event(detail=f"event {i}"))

    def export(self, path=None, after=0, session=SESSION, moment=NOW,
               ring=None, **kwargs):
        return export_signed_batch(
            path if path is not None else self.source, after,
            kwargs.pop("max_bytes", 10_000_000), session,
            ring if ring is not None else self.ring, ISSUER, 1, moment,
        )

    def import_(self, packet=None, target=None, moment=200, ring=None):
        return import_signed_batch(
            target if target is not None else self.target,
            packet if packet is not None else self.export(),
            ring if ring is not None else self.ring, moment,
        )

    def test_applied_result_shape_and_durable_file(self) -> None:
        result = self.import_()
        self.assertEqual(tuple(result.keys()), RESULT_KEYS)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["session"], SESSION)
        self.assertEqual(result["next"], 5)
        self.assertIs(result["complete"], True)
        self.assertIsNone(result["need"])
        self.assertIsNone(result["fork"])
        self.assertEqual(
            [r["seq"] for r in audit.read(self.target)], [1, 2, 3, 4, 5]
        )

    def test_repeated_import_is_duplicate_and_side_effect_free(self) -> None:
        self.import_()
        with open(self.target, "rb") as handle:
            once = handle.read()
        result = self.import_()
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(result["next"], 5)
        self.assertIsNone(result["need"])
        self.assertIsNone(result["fork"])
        third = self.import_()
        self.assertEqual(third["status"], "duplicate")
        with open(self.target, "rb") as handle:
            self.assertEqual(handle.read(), once)

    def test_incremental_append_onto_matching_prefix(self) -> None:
        first = self.export()
        def first_fit(target_next: int) -> int:
            for mb in range(1, len(first) + 1):
                try:
                    data = self.export(max_bytes=mb)
                except ValueError:
                    continue
                if decode(data)["payload"]["next"] == target_next:
                    return mb
            raise AssertionError("no feasible budget")

        three = export_signed_batch(
            self.source, 0, first_fit(3), SESSION, self.ring, ISSUER, 1, NOW,
        )
        self.assertEqual(decode(three)["payload"]["next"], 3)
        self.assertEqual(self.import_(packet=three)["status"], "applied")
        rest = self.export(after=3)
        result = self.import_(packet=rest)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["next"], 5)
        self.assertEqual(audit.read(self.source), audit.read(self.target))

    def test_empty_packet_at_tail_is_duplicate(self) -> None:
        self.import_()
        tail = self.export(after=5)
        result = self.import_(packet=tail)
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(result["next"], 5)

    def test_missing_reports_deterministic_need_interval(self) -> None:
        packet = self.export(after=3)
        result = self.import_(packet=packet)
        self.assertEqual(result["status"], "missing")
        self.assertEqual(result["need"], [1, 3])
        self.assertEqual(result["next"], 5)
        self.assertIs(result["complete"], True)
        self.assertIsNone(result["fork"])
        self.assertFalse(os.path.exists(self.target))

        # A target with some history gets the exact closed gap interval.
        partial = os.path.join(self.dir, "partial.jsonl")
        append(partial, event())
        result = import_signed_batch(partial, packet, self.ring, 200)
        self.assertEqual(result["status"], "missing")
        self.assertEqual(result["need"], [2, 3])
        self.assertEqual([r["seq"] for r in audit.read(partial)], [1])

    def test_fork_names_first_seq_and_both_hashes_without_writing(self) -> None:
        append(self.target, event(detail="totally different event"))
        for i in range(1, 3):
            append(self.target, event(detail=f"event {i}"))
        with open(self.target, "rb") as handle:
            before = handle.read()
        result = self.import_()
        self.assertEqual(result["status"], "fork")
        self.assertEqual(set(result["fork"].keys()), {"seq", "local", "remote"})
        self.assertEqual(result["fork"]["seq"], 1)
        local = audit.read(self.target)
        self.assertEqual(result["fork"]["local"], local[0]["hash"])
        remote = audit.read(self.source)
        self.assertEqual(result["fork"]["remote"], remote[0]["hash"])
        self.assertNotEqual(result["fork"]["local"], result["fork"]["remote"])
        with open(self.target, "rb") as handle:
            self.assertEqual(handle.read(), before)
        self.assertIsNone(result["need"])

    def test_fork_on_overlap_still_applies_nothing_even_with_suffix(self) -> None:
        # Local seq 2 differs; the batch also carries records 4..5 that
        # would otherwise be appended.
        append(self.target, event(detail="event 0"))
        append(self.target, event(detail="diverged"))
        append(self.target, event(detail="event 2"))
        before = open(self.target, "rb").read()
        result = self.import_(packet=self.export(after=1))
        self.assertEqual(result["status"], "fork")
        self.assertEqual(result["fork"]["seq"], 2)
        self.assertEqual(open(self.target, "rb").read(), before)

    def test_overlapping_match_then_suffix_applies(self) -> None:
        for i in range(2):
            append(self.target, event(detail=f"event {i}"))
        result = self.import_(packet=self.export(after=1))
        self.assertEqual(result["status"], "applied")
        self.assertEqual([r["seq"] for r in audit.read(self.target)],
                         [1, 2, 3, 4, 5])

    def test_input_bytes_are_not_modified(self) -> None:
        packet = self.export()
        original = bytes(packet)
        self.import_(packet=packet)
        self.assertEqual(packet, original)


class ImportSignedBatchAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.source = os.path.join(self.dir, "source.jsonl")
        self.target = os.path.join(self.dir, "target.jsonl")
        append(self.source, event())
        self.ring = keyring(key_entry(not_before=0, not_after=1000))
        self.packet = export_signed_batch(
            self.source, 0, 10_000_000, SESSION, self.ring, ISSUER, 1, NOW,
        )

    def import_(self, packet=None, ring=None, moment=200):
        return import_signed_batch(
            self.target,
            self.packet if packet is None else packet,
            self.ring if ring is None else ring,
            moment,
        )

    def test_valid_at_sign_and_verify_boundaries(self) -> None:
        ring = keyring(key_entry(not_before=NOW, not_after=200))
        result = import_signed_batch(self.target, self.packet, ring, 200)
        self.assertEqual(result["status"], "applied")

    def test_bad_signature(self) -> None:
        packet = decode(self.packet)
        packet["signature"] = "0" * 64
        with self.assertRaises(AuthenticationError):
            self.import_(packet=canonical(packet))

    def test_wrong_key_secret(self) -> None:
        wrong = keyring(key_entry(secret=OTHER_SECRET))
        with self.assertRaises(AuthenticationError):
            self.import_(ring=wrong)

    def test_unknown_credentials(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.import_(ring=keyring(key_entry(), issuer="other"))
        with self.assertRaises(AuthenticationError):
            self.import_(ring=keyring(key_entry(version=2)))

    def test_revoked_at_either_moment(self) -> None:
        ring = keyring(key_entry(revoked=True))
        with self.assertRaises(AuthenticationError):
            self.import_(ring=ring)

    def test_signed_at_in_future(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.import_(moment=NOW - 1)

    def test_key_expired_between_signing_and_verification(self) -> None:
        ring = keyring(key_entry(not_after=150))
        with self.assertRaises(AuthenticationError):
            self.import_(ring=ring, moment=200)

    def test_key_not_yet_valid_at_signing(self) -> None:
        ring = keyring(key_entry(not_before=150))
        with self.assertRaises(AuthenticationError):
            self.import_(ring=ring, moment=200)

    def test_authentication_runs_before_target_is_read(self) -> None:
        bad = keyring(key_entry(secret=OTHER_SECRET))
        with mock.patch("offline_coordination.audit.read") as patched:
            with self.assertRaises(AuthenticationError):
                import_signed_batch(self.target, self.packet, bad, 200)
        patched.assert_not_called()
        self.assertFalse(os.path.exists(self.target))

    def test_payload_re_signed_with_valid_key_but_altered_chain_rejected(
        self,
    ) -> None:
        packet = decode(self.packet)
        packet["payload"]["records"][0]["detail"] = "tampered"
        resigned = resign(packet)
        with self.assertRaises(InvalidSignedBatchError):
            self.import_(packet=resigned)
        self.assertFalse(os.path.exists(self.target))


class ImportSignedBatchStructureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.source = os.path.join(self.dir, "source.jsonl")
        self.target = os.path.join(self.dir, "target.jsonl")
        for i in range(3):
            append(self.source, event(detail=f"event {i}"))
        self.ring = keyring(key_entry())
        self.packet = export_signed_batch(
            self.source, 0, 10_000_000, SESSION, self.ring, ISSUER, 1, NOW,
        )

    def reject(self, raw, *types):
        with self.assertRaises(types) as caught:
            import_signed_batch(self.target, raw, self.ring, 200)
        self.assertFalse(os.path.exists(self.target))
        return caught.exception

    def altered(self, mutate, raw=None):
        packet = decode(self.packet if raw is None else raw)
        mutate(packet)
        return canonical(packet)

    def test_packet_must_be_bytes(self) -> None:
        with self.assertRaises(TypeError):
            import_signed_batch(self.target, decode(self.packet), self.ring, 200)

    def test_path_and_moment_types(self) -> None:
        with self.assertRaises(TypeError):
            import_signed_batch(4, self.packet, self.ring, 200)
        with self.assertRaises(TypeError):
            import_signed_batch(self.target, self.packet, self.ring, 1.0)
        with self.assertRaises(TypeError):
            import_signed_batch(self.target, self.packet, self.ring, True)

    def test_moment_negative_is_value_error(self) -> None:
        with self.assertRaises(ValueError):
            import_signed_batch(self.target, self.packet, self.ring, -1)

    def test_trailing_byte_rejected(self) -> None:
        self.reject(self.packet + b"\n", InvalidSignedBatchError)
        self.reject(self.packet + b" ", InvalidSignedBatchError)

    def test_bad_utf8_and_json_rejected(self) -> None:
        self.reject(b"\xff\xff", InvalidSignedBatchError)
        self.reject(b"[1,2]", TypeError)
        self.reject(b'{"a":1}', InvalidSignedBatchError)

    def test_duplicate_object_keys_rejected(self) -> None:
        dup = (
            b'{"payload":{"after":0,"after":0,"complete":true,'
            b'"issuer":"node-a","keyVersion":1,"next":0,"records":[],'
            b'"session":"s","signedAt":1,"version":1},'
            b'"signature":"' + b"0" * 64 + b'"}'
        )
        self.reject(dup, InvalidSignedBatchError)

    def test_top_level_and_payload_key_sets(self) -> None:
        self.reject(self.altered(lambda p: p.pop("signature")),
                    InvalidSignedBatchError)
        self.reject(self.altered(lambda p: p["payload"].pop("session")),
                    InvalidSignedBatchError)
        self.reject(self.altered(lambda p: p["payload"].update({"x": 1})),
                    InvalidSignedBatchError)

    def test_field_type_faults_are_type_errors(self) -> None:
        self.reject(self.altered(lambda p: p.update(signature=123)), TypeError)
        self.reject(self.altered(lambda p: p["payload"].update(session=9)),
                    TypeError)
        self.reject(self.altered(lambda p: p["payload"].update(issuer=9)),
                    TypeError)
        self.reject(
            self.altered(lambda p: p["payload"]["records"].append("nope")),
            TypeError,
        )

    def test_value_domain_faults_are_invalid_errors(self) -> None:
        self.reject(self.altered(lambda p: p.update(signature="zz")),
                    InvalidSignedBatchError)
        self.reject(self.altered(lambda p: p["payload"].update(session="")),
                    InvalidSignedBatchError)
        self.reject(self.altered(lambda p: p["payload"].update(issuer="")),
                    InvalidSignedBatchError)
        self.reject(self.altered(lambda p: p["payload"].update(version=2)),
                    InvalidSignedBatchError)
        self.reject(
            self.altered(lambda p: p["payload"].update(keyVersion=0)),
            InvalidSignedBatchError,
        )
        self.reject(
            self.altered(lambda p: p["payload"].update(signedAt=-1)),
            InvalidSignedBatchError,
        )

    def test_empty_records_without_complete_rejected(self) -> None:
        def mutate(p):
            records = p["payload"]["records"]
            records.clear()
            p["payload"]["complete"] = False
            p["payload"]["next"] = 0
            p["payload"]["after"] = 3
        self.reject(self.altered(mutate), InvalidSignedBatchError)

    def test_seq_gap_rejected(self) -> None:
        def mutate(p):
            p["payload"]["records"].pop(0)
            p["payload"]["next"] = 2
        self.reject(self.altered(mutate), InvalidSignedBatchError)

    def test_broken_prev_chain_rejected(self) -> None:
        def mutate(p):
            p["payload"]["records"][1]["prev"] = "0" * 64
        self.reject(self.altered(mutate), InvalidSignedBatchError)

    def test_bad_record_hash_rejected(self) -> None:
        def mutate(p):
            p["payload"]["records"][0]["hash"] = "0" * 64
        self.reject(self.altered(mutate), InvalidSignedBatchError)

    def test_next_must_match_records(self) -> None:
        self.reject(
            self.altered(lambda p: p["payload"].update(next=99)),
            InvalidSignedBatchError,
        )

    def test_non_canonical_encoding_rejected(self) -> None:
        spaced = self.packet.replace(b'":', b'" :', 1)
        self.reject(spaced, InvalidSignedBatchError)

    def test_unsigned_legacy_batch_rejected(self) -> None:
        from offline_coordination.replication import export_batch
        legacy = export_batch(self.source)
        self.reject(legacy, InvalidSignedBatchError)


class ImportSignedBatchMaxBytesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.source = os.path.join(self.dir, "source.jsonl")
        self.target = os.path.join(self.dir, "target.jsonl")
        self.ring = keyring(key_entry())
        for i in range(4):
            append(self.source, event(detail=f"event {i}"))
        self.packet = export_signed_batch(
            self.source, 0, 10_000_000, SESSION, self.ring, ISSUER, 1, NOW,
        )

    def test_default_budget_is_64_mib(self) -> None:
        self.assertEqual(
            replication.DEFAULT_IMPORTED_SIGNED_BATCH_MAX_BYTES, 67_108_864
        )

    def test_packet_just_over_default_budget_rejected_without_parsing(self) -> None:
        # Malformed bytes: with no budget gate these would be
        # InvalidSignedBatchError (bad UTF-8/JSON), but the default
        # budget rejects purely on length.
        overlong = b"{" * (67_108_864 + 1)
        with self.assertRaises(ValueError) as caught:
            import_signed_batch(self.target, overlong, self.ring, 200)
        self.assertEqual(str(caught.exception), "signed batch exceeds max_bytes")
        self.assertFalse(os.path.exists(self.target))

    def test_packet_exactly_at_custom_boundary_is_admitted(self) -> None:
        result = import_signed_batch(
            self.target, self.packet, self.ring, 200, len(self.packet)
        )
        self.assertEqual(result["status"], "applied")

    def test_packet_one_byte_over_custom_boundary_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            import_signed_batch(
                self.target, self.packet, self.ring, 200, len(self.packet) - 1
            )
        self.assertEqual(str(caught.exception), "signed batch exceeds max_bytes")
        self.assertFalse(os.path.exists(self.target))

    def test_boundary_does_not_change_any_result_kind(self) -> None:
        # applied
        applied = import_signed_batch(
            self.target, self.packet, self.ring, 200, len(self.packet)
        )
        self.assertEqual(applied["status"], "applied")
        # duplicate, still admitted at the exact packet length
        duplicate = import_signed_batch(
            self.target, self.packet, self.ring, 200, len(self.packet)
        )
        self.assertEqual(duplicate["status"], "duplicate")
        # missing, on a fresh target
        gap_target = os.path.join(self.dir, "gap.jsonl")
        gap_packet = export_signed_batch(
            self.source, 3, 10_000_000, SESSION, self.ring, ISSUER, 1, NOW,
        )
        missing = import_signed_batch(
            gap_target, gap_packet, self.ring, 200, len(gap_packet)
        )
        self.assertEqual(missing["status"], "missing")
        self.assertEqual(missing["need"], [1, 3])
        # fork
        fork_target = os.path.join(self.dir, "fork.jsonl")
        append(fork_target, event(detail="totally different event"))
        forked = import_signed_batch(
            fork_target, self.packet, self.ring, 200, len(self.packet)
        )
        self.assertEqual(forked["status"], "fork")
        self.assertEqual(forked["fork"]["seq"], 1)

    def test_explicit_default_budget_matches_omitted_argument(self) -> None:
        once = import_signed_batch(self.target, self.packet, self.ring, 200)
        other = os.path.join(self.dir, "other.jsonl")
        again = import_signed_batch(
            other, self.packet, self.ring, 200, 67_108_864
        )
        self.assertEqual(once, again)

    def test_four_argument_call_still_works(self) -> None:
        result = import_signed_batch(self.target, self.packet, self.ring, 200)
        self.assertEqual(tuple(result.keys()), RESULT_KEYS)
        self.assertEqual(result["status"], "applied")

    def test_max_bytes_rejects_bool_and_non_int_with_type_error(self) -> None:
        with self.assertRaises(TypeError):
            import_signed_batch(self.target, self.packet, self.ring, 200, True)
        with self.assertRaises(TypeError):
            import_signed_batch(self.target, self.packet, self.ring, 200, 1.0)
        with self.assertRaises(TypeError):
            import_signed_batch(self.target, self.packet, self.ring, 200, "100")

    def test_max_bytes_zero_or_negative_is_value_error(self) -> None:
        with self.assertRaises(ValueError):
            import_signed_batch(self.target, self.packet, self.ring, 200, 0)
        with self.assertRaises(ValueError):
            import_signed_batch(self.target, self.packet, self.ring, 200, -7)

    def test_overlong_malformed_packet_wins_over_parse_errors(self) -> None:
        # Invalid UTF-8, invalid JSON and a non-object respectively.
        for raw in (b"\xff" * 4096, b"[1,2]" + b" " * 4096, b"x" * 4096):
            with self.assertRaises(ValueError) as caught:
                import_signed_batch(self.target, raw, self.ring, 200, 1024)
            self.assertEqual(
                str(caught.exception), "signed batch exceeds max_bytes"
            )
            self.assertNotIsInstance(caught.exception,
                                     InvalidSignedBatchError)

    def test_overlong_packet_never_queries_keys_or_touches_files(self) -> None:
        # A structurally wrong keyring would TypeError inside
        # _validated_keyring if it were consulted; the budget must win.
        with mock.patch(
            "offline_coordination.replication._validated_keyring"
        ) as validate, mock.patch(
            "offline_coordination.replication._usable_checkpoint_key"
        ) as usable, mock.patch(
            "offline_coordination.audit.read"
        ) as read, mock.patch("builtins.open") as opened:
            with self.assertRaises(ValueError) as caught:
                import_signed_batch(
                    self.target, self.packet, [], 200, len(self.packet) - 1
                )
        self.assertEqual(str(caught.exception), "signed batch exceeds max_bytes")
        validate.assert_not_called()
        usable.assert_not_called()
        read.assert_not_called()
        opened.assert_not_called()
        self.assertFalse(os.path.exists(self.target))

    def test_overlong_authenticity_failure_still_reported_as_budget(self) -> None:
        packet = decode(self.packet)
        packet["signature"] = "0" * 64
        bad_signature = canonical(packet)
        with mock.patch("offline_coordination.audit.read") as read:
            with self.assertRaises(ValueError) as caught:
                import_signed_batch(
                    self.target, bad_signature, self.ring, 200,
                    len(bad_signature) - 1,
                )
        self.assertEqual(str(caught.exception), "signed batch exceeds max_bytes")
        self.assertNotIsInstance(caught.exception, AuthenticationError)
        read.assert_not_called()

    def test_overlong_missing_target_path_still_reported_as_budget(self) -> None:
        missing = os.path.join(self.dir, "does-not-exist.jsonl")
        with self.assertRaises(ValueError) as caught:
            import_signed_batch(
                missing, self.packet, self.ring, 200, len(self.packet) - 1
            )
        self.assertEqual(str(caught.exception), "signed batch exceeds max_bytes")
        self.assertFalse(os.path.exists(missing))

    def test_rejection_does_not_modify_input_or_existing_file(self) -> None:
        append(self.target, event())
        before = open(self.target, "rb").read()
        original = bytes(self.packet)
        with self.assertRaises(ValueError):
            import_signed_batch(
                self.target, self.packet, self.ring, 200, len(self.packet) - 1
            )
        self.assertEqual(self.packet, original)
        self.assertEqual(open(self.target, "rb").read(), before)

    def test_batch_must_still_be_bytes(self) -> None:
        with self.assertRaises(TypeError):
            import_signed_batch(
                self.target, decode(self.packet), self.ring, 200, 10_000_000
            )


class ImportSignedBatchSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.source = os.path.join(self.dir, "source.jsonl")
        self.target = os.path.join(self.dir, "target.jsonl")
        for i in range(4):
            append(self.source, event(detail=f"event {i}"))
        self.ring = keyring(key_entry())
        self.packet = export_signed_batch(
            self.source, 0, 10_000_000, SESSION, self.ring, ISSUER, 1, NOW,
        )

    def test_fsync_failure_on_new_file_leaves_no_file(self) -> None:
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                import_signed_batch(self.target, self.packet, self.ring, 200)
        self.assertFalse(os.path.exists(self.target))

    def test_fsync_failure_on_existing_file_restores_bytes(self) -> None:
        append(self.target, event(detail="event 0"))
        before = open(self.target, "rb").read()
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                import_signed_batch(self.target, self.packet, self.ring, 200)
        self.assertEqual(open(self.target, "rb").read(), before)

    def test_write_failure_restores_bytes(self) -> None:
        append(self.target, event(detail="event 0"))
        before = open(self.target, "rb").read()
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
            "builtins.open",
            side_effect=lambda *a, **k: FailingFile(*a, **k),
        ):
            with self.assertRaises(OSError):
                import_signed_batch(self.target, self.packet, self.ring, 200)
        self.assertEqual(open(self.target, "rb").read(), before)

    def test_corrupt_local_log_propagates_after_auth(self) -> None:
        append(self.target, event())
        good = open(self.target, "rb").read()
        with open(self.target, "wb") as handle:
            handle.write(good[:-1])
        with self.assertRaises(CorruptAuditError):
            import_signed_batch(self.target, self.packet, self.ring, 200)

    def test_repeated_applied_import_after_rollback_still_works(self) -> None:
        result = import_signed_batch(
            self.target, self.packet, self.ring, 200
        )
        self.assertEqual(result["status"], "applied")
        with open(self.target, "rb") as handle:
            first = handle.read()
        again = import_signed_batch(self.target, self.packet, self.ring, 200)
        self.assertEqual(again["status"], "duplicate")
        self.assertEqual(open(self.target, "rb").read(), first)


if __name__ == "__main__":
    unittest.main()
