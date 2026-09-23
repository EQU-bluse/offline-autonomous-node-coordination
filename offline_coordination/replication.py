"""Read-only audit replication batches.

A batch is a single UTF-8 compact JSON object (non-ASCII preserved, no
whitespace) terminated by exactly one ``\\n``::

    {"after":...,"complete":...,"next":...,"records":[...],"version":1}

The top-level keys are fixed in the order ``after``, ``complete``,
``next``, ``records``, ``version`` and ``version`` is always the integer
1.  ``after`` echoes the request's ``after`` argument.  ``records`` holds
up to ``limit`` audit records whose ``seq`` is greater than ``after``, in
audit order, each preserving the audit record key order
``detail, hash, kind, prev, seq, source`` and its original values.
``next`` is the seq of the last record in the batch, or ``after`` itself
when the batch is empty; ``complete`` is true when no record follows the
batch.  Batches are generated solely through :func:`audit.read`, so the
audit log is never modified and :class:`~offline_coordination.audit.
CorruptAuditError` and :class:`OSError` propagate unchanged.

:func:`import_batch` validates a batch's full byte contract before
touching the local log.  When the batch starts past the local tail its
records are not written (status ``missing``); otherwise records already
present locally must match field-for-field and are skipped idempotently,
and only the contiguous newer suffix is appended (status ``applied``).
A batch that appends nothing is a ``duplicate``.
"""

from __future__ import annotations

import json
import os
from typing import Any

from offline_coordination import audit

AFTER = "after"
COMPLETE = "complete"
NEED = "need"
NEXT = "next"
RECORDS = "records"
STATUS = "status"
VERSION = "version"

STATUS_MISSING = "missing"
STATUS_APPLIED = "applied"
STATUS_DUPLICATE = "duplicate"

_BATCH_KEYS = (AFTER, COMPLETE, NEXT, RECORDS, VERSION)
_RESULT_KEYS = (NEED, NEXT, STATUS)
_RECORD_KEYS = (
    audit.DETAIL,
    audit.HASH,
    audit.KIND,
    audit.PREV,
    audit.SEQ,
    audit.SOURCE,
)
_BATCH_VERSION = 1
_MIN_LIMIT = 1
_MAX_LIMIT = 1000


def export_batch(path: str, after: int = 0, limit: int = 100) -> bytes:
    """Return one replication batch of audit records as UTF-8 JSON bytes.

    Selects the first ``limit`` records whose ``seq`` is greater than
    ``after``.  ``after`` must not exceed the log's last seq (an empty or
    missing log has last seq 0); otherwise :class:`ValueError` is raised.

    Type violations raise :class:`TypeError` (``bool`` is not accepted as
    an int); ``after < 0`` or a ``limit`` outside ``[1, 1000]`` raises
    :class:`ValueError`.  A corrupt log raises
    :class:`~offline_coordination.audit.CorruptAuditError` and filesystem
    errors propagate as :class:`OSError`.  The log is never modified.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if isinstance(after, bool) or not isinstance(after, int):
        raise TypeError("after must be an int")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an int")
    if after < 0:
        raise ValueError("after must be >= 0")
    if limit < _MIN_LIMIT or limit > _MAX_LIMIT:
        raise ValueError("limit must be in [1, 1000]")

    all_records = audit.read(path)
    last_seq = all_records[-1][audit.SEQ] if all_records else 0
    if after > last_seq:
        raise ValueError("after must not exceed the last audit seq")

    selected = [record for record in all_records if record[audit.SEQ] > after]
    selected = selected[:limit]
    batch_records = [
        {key: record[key] for key in _RECORD_KEYS} for record in selected
    ]

    next_seq = batch_records[-1][audit.SEQ] if batch_records else after
    batch = {
        AFTER: after,
        COMPLETE: next_seq == last_seq,
        NEXT: next_seq,
        RECORDS: batch_records,
        VERSION: _BATCH_VERSION,
    }
    ordered = {key: batch[key] for key in _BATCH_KEYS}
    text = json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n"
    return text.encode("utf-8")


def _is_int(value: Any) -> bool:
    # bool is a subclass of int, but no batch integer may be a bool.
    return isinstance(value, int) and not isinstance(value, bool)


def _result(need: Any, next_seq: int, status: str) -> dict[str, Any]:
    # Fixed key order need, next, status.
    return {NEED: need, NEXT: next_seq, STATUS: status}


def _validated_batch(batch: bytes) -> dict[str, Any]:
    """Validate every byte of a batch against the export_batch contract.

    Returns a fresh ordered dict built from the parsed values.  Never reads
    or writes the local audit log.  Any conformance failure raises
    :class:`ValueError`.
    """
    if not batch.endswith(b"\n") or batch.endswith(b"\n\n"):
        raise ValueError("batch must be one JSON object terminated by exactly one newline")
    payload = batch[:-1]
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("batch is not valid UTF-8 JSON") from exc

    if not isinstance(data, dict) or tuple(data.keys()) != _BATCH_KEYS:
        raise ValueError(
            "batch must contain exactly the keys after, complete, next, records, version"
        )
    after = data[AFTER]
    complete = data[COMPLETE]
    next_seq = data[NEXT]
    records = data[RECORDS]
    version = data[VERSION]

    if not _is_int(version) or version != _BATCH_VERSION:
        raise ValueError("batch version must be the integer 1")
    if not isinstance(complete, bool):
        raise ValueError("batch complete must be a bool")
    if not _is_int(after) or after < 0:
        raise ValueError("batch after must be a non-negative int")
    if not _is_int(next_seq) or next_seq < after:
        raise ValueError("batch next must be an int not less than after")
    if not isinstance(records, list):
        raise ValueError("batch records must be a list")

    checked: list[dict[str, Any]] = []
    expected_seq = after + 1
    expected_prev = audit._ZERO_HASH
    for index, record in enumerate(records):
        if not isinstance(record, dict) or tuple(record.keys()) != _RECORD_KEYS:
            raise ValueError(
                f"batch record {index} must contain exactly the keys "
                "detail, hash, kind, prev, seq, source"
            )
        detail = record[audit.DETAIL]
        kind = record[audit.KIND]
        prev = record[audit.PREV]
        seq = record[audit.SEQ]
        source = record[audit.SOURCE]
        digest = record[audit.HASH]
        for name, value in (
            (audit.DETAIL, detail),
            (audit.KIND, kind),
            (audit.PREV, prev),
            (audit.SOURCE, source),
            (audit.HASH, digest),
        ):
            if not isinstance(value, str):
                raise ValueError(f"batch record {index} {name} must be a str")
        if not _is_int(seq):
            raise ValueError(f"batch record {index} seq must be an int")
        if seq != expected_seq:
            raise ValueError(
                f"batch record {index} seq is {seq}, expected {expected_seq}"
            )
        if index == 0:
            if after == 0 and prev != audit._ZERO_HASH:
                raise ValueError("the first batch record prev must be the zero hash")
        elif prev != expected_prev:
            raise ValueError(
                f"batch record {index} prev does not match the previous record hash"
            )
        without_hash = {
            audit.DETAIL: detail,
            audit.KIND: kind,
            audit.PREV: prev,
            audit.SEQ: seq,
            audit.SOURCE: source,
        }
        if audit._record_hash(without_hash) != digest:
            raise ValueError(f"batch record {index} hash does not match its contents")
        checked.append({key: record[key] for key in _RECORD_KEYS})
        expected_seq += 1
        expected_prev = digest

    expected_next = checked[-1][audit.SEQ] if checked else after
    if next_seq != expected_next:
        raise ValueError("batch next must be the last record seq (after when empty)")

    # The on-disk bytes must be the single canonical compact encoding that
    # export_batch writes: this rejects stray whitespace, non-canonical
    # escapes and any key order other than the fixed one.
    canonical = {
        AFTER: after,
        COMPLETE: complete,
        NEXT: next_seq,
        RECORDS: checked,
        VERSION: version,
    }
    ordered = {key: canonical[key] for key in _BATCH_KEYS}
    if audit._compact(ordered) != payload:
        raise ValueError("batch is not canonically encoded")
    return ordered


def _append_records(path: str, records: list[dict[str, Any]]) -> None:
    """Append already validated records with the same durability as audit.append."""
    lines = b"".join(audit._encode_line(record) for record in records)
    existed = os.path.exists(path)
    with open(path, "ab") as handle:
        handle.write(lines)
        handle.flush()
        os.fsync(handle.fileno())
    if not existed:
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def import_batch(path: str, batch: bytes) -> dict[str, Any]:
    """Validate a replication batch and append its newer records to the log.

    The whole batch is verified against the :func:`export_batch` byte
    contract before the local audit log is read: ``version`` must be the
    integer 1, record seqs must run contiguously from ``after + 1``,
    ``next`` must be the last record seq (``after`` for an empty batch),
    and every hash and prev link must be correct.

    Let the local log's last seq be ``L`` (0 when it is empty):

    * If ``after > L`` nothing is written and the result is
      ``{"need": [L + 1, after], "next": L, "status": "missing"}``.
    * Otherwise every batch record with ``seq <= L`` must equal the local
      record with the same seq in every field, else :class:`ValueError`;
      matching records are skipped idempotently and only the contiguous
      suffix with ``seq > L`` is appended, after checking that its first
      record's ``prev`` equals the local tail hash.
    * ``need`` is then ``None``, ``next`` is ``max(L, batch next)`` and
      ``status`` is ``"applied"`` when records were appended, else
      ``"duplicate"``.

    Result keys are always ordered ``need, next, status``.  Type violations
    raise :class:`TypeError` and every other batch defect raises
    :class:`ValueError`; the log is not modified on failure.
    :class:`~offline_coordination.audit.CorruptAuditError` and
    :class:`OSError` propagate unchanged.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if not isinstance(batch, bytes):
        raise TypeError("batch must be bytes")

    ordered = _validated_batch(batch)
    after = ordered[AFTER]
    next_seq = ordered[NEXT]
    records = ordered[RECORDS]

    local = audit.read(path)
    last_seq = local[-1][audit.SEQ] if local else 0

    if after > last_seq:
        return _result([last_seq + 1, after], last_seq, STATUS_MISSING)

    suffix: list[dict[str, Any]] = []
    for record in records:
        seq = record[audit.SEQ]
        if seq <= last_seq:
            if record != local[seq - 1]:
                raise ValueError(
                    f"batch record {seq} conflicts with the local record {seq}"
                )
        else:
            suffix.append(record)

    if suffix:
        tail_hash = local[-1][audit.HASH] if local else audit._ZERO_HASH
        if suffix[0][audit.PREV] != tail_hash:
            raise ValueError("the first appended record prev must be the local last hash")
        _append_records(path, suffix)
        status = STATUS_APPLIED
    else:
        status = STATUS_DUPLICATE
    return _result(None, max(last_seq, next_seq), status)
