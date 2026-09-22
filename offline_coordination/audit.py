"""Append-only hash-chained audit log for offline coordination.

The audit file is UTF-8 JSONL, one JSON object per line.  Each object has
the fixed key set and key order::

    detail, hash, kind, prev, seq, source

``seq`` starts at 1 and is contiguous; the first record's ``prev`` is 64
zero characters and every later ``prev`` equals the previous record's
``hash``.  ``hash`` is the lowercase hex SHA-256 of the compact UTF-8 JSON
encoding (no whitespace, non-ASCII preserved, no trailing newline) of the
record with the ``hash`` key itself removed and the remaining keys in the
order above.  Each complete record line is encoded the same way and
terminated by ``\\n``.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

DETAIL = "detail"
HASH = "hash"
KIND = "kind"
PREV = "prev"
SEQ = "seq"
SOURCE = "source"

_EVENT_KEYS = (SOURCE, KIND, DETAIL)
_RECORD_KEYS = (DETAIL, HASH, KIND, PREV, SEQ, SOURCE)
_HASHED_KEYS = (DETAIL, KIND, PREV, SEQ, SOURCE)
_KINDS = ("local", "merge", "restore")
_ZERO_HASH = "0" * 64


class CorruptAuditError(ValueError):
    """The audit file exists but its contents are not a valid audit log."""


def _compact(obj: Any) -> bytes:
    # Same compact UTF-8 JSON rules used for state persistence in storage.py.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _validated_event(event: Any) -> dict[str, str]:
    if not isinstance(event, dict):
        raise TypeError("event must be a dict")
    if set(event.keys()) != set(_EVENT_KEYS):
        raise ValueError(
            "event must contain exactly the keys 'source', 'kind' and 'detail'"
        )
    result: dict[str, str] = {}
    for key in _EVENT_KEYS:
        value = event[key]
        if not isinstance(value, str):
            raise TypeError(f"event {key} must be a str")
        if value == "":
            raise ValueError(f"event {key} must be non-empty")
        result[key] = value
    if result[KIND] not in _KINDS:
        raise ValueError("event kind must be one of 'local', 'merge' or 'restore'")
    return result


def _record_hash(record_without_hash: dict[str, Any]) -> str:
    ordered = {key: record_without_hash[key] for key in _HASHED_KEYS}
    return hashlib.sha256(_compact(ordered)).hexdigest()


def _encode_line(record: dict[str, Any]) -> bytes:
    ordered = {key: record[key] for key in _RECORD_KEYS}
    return _compact(ordered) + b"\n"


def _parse_and_chain(raw: bytes) -> list[dict[str, Any]]:
    """Validate every byte of an audit log and return its records.

    Raises :class:`CorruptAuditError` for any UTF-8/JSON decoding failure,
    non-canonical byte encoding, wrong key set, seq/prev/hash chain break,
    or missing line terminator.  Value-domain rules (non-empty fields, the
    kind enum) are enforced on event input by :func:`append`.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorruptAuditError("audit file is not valid UTF-8") from exc

    records: list[dict[str, Any]] = []
    expected_seq = 1
    expected_prev = _ZERO_HASH

    if text == "":
        return records
    # Every record, including the last one, must be newline-terminated; the
    # trailing empty segment is the expected terminator.  Interior empty
    # segments are blank lines and fail canonical re-encoding below.
    lines = text.split("\n")
    if lines[-1] != "":
        raise CorruptAuditError("the last audit line is not terminated by a newline")
    for line_no, line in enumerate(lines[:-1], start=1):
        line_bytes = line.encode("utf-8")
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CorruptAuditError(
                f"audit line {line_no} is not valid JSON"
            ) from exc
        if not isinstance(data, dict):
            raise CorruptAuditError(f"audit line {line_no} is not a JSON object")
        if set(data.keys()) != set(_RECORD_KEYS):
            raise CorruptAuditError(
                f"audit line {line_no} must contain exactly the keys "
                "detail, hash, kind, prev, seq, source"
            )
        detail = data[DETAIL]
        kind = data[KIND]
        prev = data[PREV]
        seq = data[SEQ]
        source = data[SOURCE]
        digest = data[HASH]
        # seq must be a genuine JSON integer (a bool would compare equal to
        # 0/1 and slip past the chain check in Python).
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise CorruptAuditError(f"audit line {line_no} seq must be an int")
        if seq != expected_seq:
            raise CorruptAuditError(
                f"audit line {line_no} seq is {seq}, expected {expected_seq}"
            )
        if prev != expected_prev:
            raise CorruptAuditError(
                f"audit line {line_no} prev does not match the previous hash"
            )
        without_hash = {
            DETAIL: detail,
            KIND: kind,
            PREV: prev,
            SEQ: seq,
            SOURCE: source,
        }
        actual_hash = _record_hash(without_hash)
        if digest != actual_hash:
            raise CorruptAuditError(
                f"audit line {line_no} hash does not match its contents"
            )
        record = {key: None for key in _RECORD_KEYS}
        record[DETAIL] = detail
        record[KIND] = kind
        record[PREV] = prev
        record[SEQ] = seq
        record[SOURCE] = source
        record[HASH] = digest
        # The on-disk bytes must be the single canonical compact encoding:
        # this rejects stray whitespace, non-canonical escapes, and any key
        # order other than the fixed one.
        if _compact({key: record[key] for key in _RECORD_KEYS}) != line_bytes:
            raise CorruptAuditError(
                f"audit line {line_no} is not canonically encoded"
            )
        records.append(record)
        expected_seq += 1
        expected_prev = digest

    return records


def _read_all_records(path: str) -> list[dict[str, Any]]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    return _parse_and_chain(raw)


def append(path: str, event: dict[str, str]) -> int:
    """Append one audit event to the log at ``path`` and return its seq.

    Every existing line is verified before anything is written, so a corrupt
    log is never extended.  The new line is flushed and fsynced; when the
    file is newly created its parent directory is fsynced as well.

    Type violations raise :class:`TypeError`; invalid event contents raise
    :class:`ValueError`; a corrupt log raises :class:`CorruptAuditError`;
    other filesystem errors propagate as :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    event_fields = _validated_event(event)

    existed = os.path.exists(path)
    records = _read_all_records(path)
    seq = len(records) + 1
    prev = records[-1][HASH] if records else _ZERO_HASH

    without_hash = {
        DETAIL: event_fields[DETAIL],
        KIND: event_fields[KIND],
        PREV: prev,
        SEQ: seq,
        SOURCE: event_fields[SOURCE],
    }
    digest = _record_hash(without_hash)
    record = dict(without_hash)
    record[HASH] = digest
    line = _encode_line(record)

    with open(path, "ab") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())

    if not existed:
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    return seq


def read(path: str) -> list[dict[str, Any]]:
    """Return all audit records at ``path`` as a fresh deep-copied list.

    A missing or empty file yields an empty list.  A corrupt log raises
    :class:`CorruptAuditError`; other filesystem errors propagate as
    :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    return _read_all_records(path)
