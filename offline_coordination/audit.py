"""Append-only hash-chained audit log for offline coordination.

The log is a UTF-8 JSONL file.  Each line is one entry with the fixed key
order ``detail,hash,kind,prev,seq,source`` encoded with the same compact
UTF-8 JSON rules as :mod:`offline_coordination.storage`::

    json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\\n"

``seq`` starts at 1 and increases by one per line.  ``prev`` is 64 zeros
for the first entry and the previous entry's ``hash`` afterwards.  ``hash``
is the lowercase hexadecimal SHA-256 of the entry with the ``hash`` key
removed, the remaining keys kept in the fixed order above and encoded with
the same compact rules but without the trailing newline.

An event is a dict with exactly the keys ``source``, ``kind`` and
``detail``, all non-empty strings, where ``kind`` is one of ``local``,
``merge`` or ``restore``.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from .storage import _fsync_dir

SOURCE = "source"
KIND = "kind"
DETAIL = "detail"

_EVENT_KEYS = {SOURCE, KIND, DETAIL}
_ENTRY_KEYS = {DETAIL, "hash", KIND, "prev", "seq", SOURCE}
_KINDS = ("local", "merge", "restore")
_ZERO_PREV = "0" * 64


class CorruptAuditError(ValueError):
    """The audit log exists but does not decode to a valid event chain."""


def _encode(entry: dict[str, Any]) -> bytes:
    text = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8")


def _hash_entry(entry: dict[str, Any]) -> str:
    payload = {key: value for key, value in entry.items() if key != "hash"}
    return hashlib.sha256(_encode(payload)).hexdigest()


def _validated_event(event: Any) -> dict[str, str]:
    """Validate an event and return a fresh dict copy of its fields."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dict")
    if set(event.keys()) != _EVENT_KEYS:
        raise ValueError(
            "event must contain exactly the keys 'source', 'kind' and 'detail'"
        )
    source = event[SOURCE]
    kind = event[KIND]
    detail = event[DETAIL]
    for name, value in ((SOURCE, source), (KIND, kind), (DETAIL, detail)):
        if not isinstance(value, str):
            raise TypeError(f"event {name} must be a str")
        if value == "":
            raise ValueError(f"event {name} must be non-empty")
    if kind not in _KINDS:
        raise ValueError(f"event kind must be one of {', '.join(_KINDS)}")
    return {SOURCE: source, KIND: kind, DETAIL: detail}


_DECODE_FAILURES = (UnicodeDecodeError, json.JSONDecodeError)


def _decode_entries(raw: bytes) -> list[dict[str, Any]]:
    """Decode and validate the whole log, returning the full entry dicts."""
    if raw == b"":
        return []
    if not raw.endswith(b"\n"):
        raise CorruptAuditError("audit log does not end with a newline")
    entries: list[dict[str, Any]] = []
    expected_prev = _ZERO_PREV
    for index, line in enumerate(raw[:-1].split(b"\n")):
        where = f"audit entry {index + 1}"
        try:
            entry = json.loads(line.decode("utf-8"))
        except _DECODE_FAILURES as exc:
            raise CorruptAuditError(f"{where} is not valid UTF-8 JSON") from exc
        if not isinstance(entry, dict) or set(entry.keys()) != _ENTRY_KEYS:
            raise CorruptAuditError(f"{where} has the wrong key set")
        seq = entry["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool) or seq != index + 1:
            raise CorruptAuditError(f"{where} breaks the seq chain")
        if entry["prev"] != expected_prev:
            raise CorruptAuditError(f"{where} breaks the prev chain")
        if entry["hash"] != _hash_entry(entry):
            raise CorruptAuditError(f"{where} has a bad hash")
        if _encode(entry) != line:
            raise CorruptAuditError(f"{where} is not canonically encoded")
        expected_prev = entry["hash"]
        entries.append(entry)
    return entries


def _read_raw(path: str) -> tuple[bytes, bool]:
    """Return the log bytes and whether the file already existed."""
    try:
        with open(path, "rb") as handle:
            return handle.read(), True
    except FileNotFoundError:
        return b"", False


def append(path: str, event: dict[str, str]) -> int:
    """Append ``event`` to the log at ``path`` and return its seq number.

    The whole existing log is validated first; a corrupt log raises
    :class:`CorruptAuditError` and is left untouched.  The new line is
    flushed and fsynced, and when the file is created for the first time
    the parent directory is fsynced as well.  Type violations raise
    :class:`TypeError`; event key set, empty value and kind violations
    raise :class:`ValueError`; any other :class:`OSError` propagates.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    fields = _validated_event(event)

    raw, existed = _read_raw(path)
    entries = _decode_entries(raw)
    seq = len(entries) + 1
    prev = entries[-1]["hash"] if entries else _ZERO_PREV

    entry: dict[str, Any] = {
        DETAIL: fields[DETAIL],
        KIND: fields[KIND],
        "prev": prev,
        "seq": seq,
        SOURCE: fields[SOURCE],
    }
    entry["hash"] = _hash_entry(entry)
    line = _encode(entry) + b"\n"

    with open(path, "ab") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    if not existed:
        _fsync_dir(path)
    return seq


def read(path: str) -> list[dict[str, str]]:
    """Return the events logged at ``path`` as a fresh list of fresh dicts.

    A missing or empty log yields ``[]``.  A log that fails UTF-8/JSON
    decoding, canonical byte, key set, seq/prev/hash chain or line-ending
    validation raises :class:`CorruptAuditError`; any other
    :class:`OSError` propagates.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    raw, _ = _read_raw(path)
    return [
        {SOURCE: entry[SOURCE], KIND: entry[KIND], DETAIL: entry[DETAIL]}
        for entry in _decode_entries(raw)
    ]
