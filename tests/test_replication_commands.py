"""CLI tests for ``replication export`` and ``replication import``."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

from offline_coordination import audit, replication

SECRET = "a" * 64
ISSUER = "node-a"
SESSION = "transfer-1"
MOMENT = 100


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring(secret=SECRET, not_before=0, not_after=1000, revoked=False):
    return {
        ISSUER: [
            {
                "version": 1,
                "secret": secret,
                "notBefore": not_before,
                "notAfter": not_after,
                "revoked": revoked,
            }
        ]
    }


def event(detail="did something", source=ISSUER, kind="local"):
    return {"source": source, "kind": kind, "detail": detail}


class ReplicationCommandCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.audit = os.path.join(self.dir, "audit.jsonl")
        self.target = os.path.join(self.dir, "target.jsonl")
        self.output = os.path.join(self.dir, "packet.json")
        self.keyring_path = os.path.join(self.dir, "keyring.json")
        with open(self.keyring_path, "wb") as handle:
            handle.write(compact(keyring()))

    def seed(self, path: str, n: int, detail="event") -> None:
        for i in range(n):
            audit.append(path, event(detail=f"{detail} {i} ☃"))

    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "offline_coordination", *argv],
            capture_output=True,
            text=True,
        )

    def export_args(self, audit_path=None, output=None, after="0",
                   max_bytes="10000000", session=SESSION, moment=str(MOMENT),
                   issuer=ISSUER):
        return (
            "replication", "export",
            audit_path if audit_path is not None else self.audit,
            output if output is not None else self.output,
            "--after", after,
            "--max-bytes", max_bytes,
            "--session", session,
            "--keyring", self.keyring_path,
            "--issuer", issuer,
            "--key-version", "1",
            "--moment", moment,
        )

    def import_args(self, audit_path=None, package=None, moment=str(MOMENT),
                    max_bytes=None):
        argv = [
            "replication", "import",
            audit_path if audit_path is not None else self.target,
            package if package is not None else self.output,
            "--keyring", self.keyring_path,
            "--moment", moment,
        ]
        if max_bytes is not None:
            argv.extend(("--max-bytes", max_bytes))
        return tuple(argv)


class ReplicationExportCommandTest(ReplicationCommandCase):
    def test_success_writes_canonical_packet_and_report(self) -> None:
        self.seed(self.audit, 3)
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.count("\n"), 1)
        report = json.loads(result.stdout)
        with open(self.output, "rb") as handle:
            packet = handle.read()
        self.assertEqual(
            set(report), {"status", "output", "bytes", "digest"}
        )
        self.assertEqual(report["status"], "exported")
        self.assertEqual(report["output"], self.output)
        self.assertEqual(report["bytes"], len(packet))
        self.assertEqual(
            report["digest"], hashlib.sha256(packet).hexdigest()
        )
        # One compact, recursively sorted JSON line.
        self.assertEqual(
            result.stdout.strip(),
            json.dumps(report, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")),
        )
        # The packet bytes are exactly what export_signed_batch produces.
        self.assertEqual(
            packet,
            replication.export_signed_batch(
                self.audit, 0, 10_000_000, SESSION, keyring(),
                ISSUER, 1, MOMENT,
            ),
        )

    def test_missing_audit_yields_empty_complete_packet(self) -> None:
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.exists(self.output))

    def test_existing_output_is_rejected_and_untouched(self) -> None:
        with open(self.output, "wb") as handle:
            handle.write(b"original contents")
        self.seed(self.audit, 1)
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 2)
        self.assertIn("already exists", result.stderr)
        with open(self.output, "rb") as handle:
            self.assertEqual(handle.read(), b"original contents")
        self.assertEqual(result.stdout, "")

    def test_failure_leaves_no_output_file(self) -> None:
        # Corrupt audit: generation fails and no packet path is created.
        with open(self.audit, "wb") as handle:
            handle.write(b"not json\n")
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 2)
        self.assertFalse(os.path.exists(self.output))
        # Output in a missing directory: no partial file anywhere.
        missing = os.path.join(self.dir, "no-such-dir", "packet.json")
        result = self.run_cli(*self.export_args(
            audit_path=self.audit, output=missing
        ))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(os.path.exists(missing))

    def test_missing_keyring_file_exits_two(self) -> None:
        os.remove(self.keyring_path)
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.strip())
        self.assertFalse(os.path.exists(self.output))

    def test_keyring_encoding_and_json_faults_exit_two(self) -> None:
        for payload in (b"\xff\xff not utf-8", b"{not json", b"[1, 2]"):
            with open(self.keyring_path, "wb") as handle:
                handle.write(payload)
            with self.subTest(payload=payload):
                result = self.run_cli(*self.export_args())
                self.assertEqual(result.returncode, 2)
                self.assertTrue(result.stderr.strip())
                self.assertFalse(os.path.exists(self.output))

    def test_protocol_validation_failure_exits_two(self) -> None:
        self.seed(self.audit, 2)
        # after past the last seq is a protocol ValueError.
        result = self.run_cli(*self.export_args(after="99"))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(os.path.exists(self.output))
        # max_bytes too small for the first record.
        result = self.run_cli(*self.export_args(max_bytes="10"))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(os.path.exists(self.output))

    def test_credential_failure_exits_two(self) -> None:
        with open(self.keyring_path, "wb") as handle:
            handle.write(compact(keyring(not_after=50)))
        self.seed(self.audit, 1)
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.strip())
        self.assertFalse(os.path.exists(self.output))

    def test_integer_arguments_are_type_checked(self) -> None:
        for argv in (
            self.export_args(after="1.5"),
            self.export_args(max_bytes="x"),
            self.export_args(moment="now"),
        ):
            with self.subTest(argv=argv):
                result = self.run_cli(*argv)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(os.path.exists(self.output))

    def test_secret_and_packet_body_are_not_echoed(self) -> None:
        self.seed(self.audit, 1, detail="private detail ☃")
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(SECRET, result.stdout)
        self.assertNotIn(SECRET, result.stderr)
        with open(self.output, "rb") as handle:
            packet = handle.read()
        # The packet body itself never reaches stdout (only its digest).
        self.assertNotIn(packet.decode("utf-8"), result.stdout)
        self.assertNotIn("private detail", result.stdout)

    def test_input_audit_is_not_modified(self) -> None:
        self.seed(self.audit, 2)
        with open(self.audit, "rb") as handle:
            before = handle.read()
        result = self.run_cli(*self.export_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.audit, "rb") as handle:
            self.assertEqual(handle.read(), before)


class ReplicationImportCommandTest(ReplicationCommandCase):
    def export_packet(self, audit_path=None, after=0, max_bytes=10_000_000,
                      ring=None):
        return replication.export_signed_batch(
            audit_path if audit_path is not None else self.audit,
            after, max_bytes, SESSION,
            ring if ring is not None else keyring(), ISSUER, 1, MOMENT,
        )

    def write_packet(self, packet: bytes) -> None:
        with open(self.output, "wb") as handle:
            handle.write(packet)

    def test_applied_exits_zero_with_verbatim_result(self) -> None:
        self.seed(self.audit, 2)
        self.write_packet(self.export_packet())
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.count("\n"), 1)
        report = json.loads(result.stdout)
        self.assertEqual(
            report,
            {
                "status": "applied",
                "session": SESSION,
                "next": 2,
                "complete": True,
                "need": None,
                "fork": None,
            },
        )
        self.assertEqual(
            result.stdout.strip(),
            compact(report).decode("utf-8"),
        )
        # The target now holds the two records.
        self.assertEqual(len(audit.read(self.target)), 2)

    def test_duplicate_exits_zero(self) -> None:
        self.seed(self.audit, 2)
        self.write_packet(self.export_packet())
        first = self.run_cli(*self.import_args())
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_cli(*self.import_args())
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout)["status"], "duplicate")

    def test_missing_exits_one_but_prints_result(self) -> None:
        self.seed(self.audit, 3)
        # Packet starts at seq 3; the empty target is missing 1..3.
        self.write_packet(self.export_packet(after=2))
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "missing")
        self.assertEqual(report["need"], [1, 2])
        self.assertFalse(os.path.exists(self.target))

    def test_fork_exits_one_with_fork_details(self) -> None:
        self.seed(self.audit, 2, detail="remote")
        self.seed(self.target, 2, detail="local")
        remote_hash = audit.read(self.audit)[0]["hash"]
        local_hash = audit.read(self.target)[0]["hash"]
        self.assertNotEqual(remote_hash, local_hash)
        self.write_packet(self.export_packet())
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "fork")
        self.assertEqual(
            report["fork"],
            {"seq": 1, "local": local_hash, "remote": remote_hash},
        )
        # A fork never writes.
        self.assertEqual(len(audit.read(self.target)), 2)

    def test_oversized_packet_rejected_before_anything_else(self) -> None:
        self.seed(self.audit, 1)
        self.write_packet(self.export_packet())
        size = os.path.getsize(self.output)
        # A nonexistent keyring and an existing target must not matter:
        # the strict length gate wins before parsing or key lookup.
        os.remove(self.keyring_path)
        with open(self.target, "wb") as handle:
            handle.write(b"must stay\n")
        result = self.run_cli(
            *self.import_args(max_bytes=str(size - 1))
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("max_bytes", result.stderr)
        with open(self.target, "rb") as handle:
            self.assertEqual(handle.read(), b"must stay\n")

    def test_packet_exactly_at_limit_is_accepted(self) -> None:
        self.seed(self.audit, 1)
        self.write_packet(self.export_packet())
        size = os.path.getsize(self.output)
        result = self.run_cli(*self.import_args(max_bytes=str(size)))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bad_signature_exits_two(self) -> None:
        self.seed(self.audit, 1)
        packet = json.loads(self.export_packet())
        packet["signature"] = "0" * 64
        self.write_packet(compact(packet))
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.strip())
        self.assertFalse(os.path.exists(self.target))

    def test_malformed_packet_exits_two(self) -> None:
        self.write_packet(b"{not json")
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 2)
        self.assertFalse(os.path.exists(self.target))

    def test_missing_package_or_keyring_exits_two(self) -> None:
        result = self.run_cli(*self.import_args(package=self.output))
        self.assertEqual(result.returncode, 2)
        self.write_packet(b"{}")
        os.remove(self.keyring_path)
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 2)

    def test_keyring_json_faults_exit_two(self) -> None:
        self.seed(self.audit, 1)
        self.write_packet(self.export_packet())
        for payload in (b"\xff", b"not json", b"{}"):
            with open(self.keyring_path, "wb") as handle:
                handle.write(payload)
            with self.subTest(payload=payload):
                result = self.run_cli(*self.import_args())
                self.assertEqual(result.returncode, 2)
                self.assertTrue(result.stderr.strip())

    def test_future_signed_at_exits_two(self) -> None:
        self.seed(self.audit, 1)
        self.write_packet(self.export_packet())
        result = self.run_cli(*self.import_args(moment=str(MOMENT - 1)))
        self.assertEqual(result.returncode, 2)

    def test_stdout_is_only_the_result_object(self) -> None:
        self.seed(self.audit, 1)
        self.write_packet(self.export_packet())
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        # Nothing but one JSON object line on stdout.
        payload = json.loads(result.stdout)
        self.assertEqual(
            result.stdout.strip(),
            compact(payload).decode("utf-8"),
        )

    def test_secret_and_packet_body_are_not_echoed(self) -> None:
        self.seed(self.audit, 1, detail="package secret ☃")
        self.write_packet(self.export_packet())
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(SECRET, result.stdout)
        self.assertNotIn(SECRET, result.stderr)
        self.assertNotIn("package secret", result.stdout)

    def test_input_materials_are_not_modified(self) -> None:
        self.seed(self.audit, 2)
        packet = self.export_packet()
        self.write_packet(packet)
        with open(self.keyring_path, "rb") as handle:
            ring_before = handle.read()
        result = self.run_cli(*self.import_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.output, "rb") as handle:
            self.assertEqual(handle.read(), packet)
        with open(self.keyring_path, "rb") as handle:
            self.assertEqual(handle.read(), ring_before)


if __name__ == "__main__":
    unittest.main()
