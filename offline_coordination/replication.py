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

:func:`import_batch` validates a batch against this byte contract and
appends its records to the local log.  It returns a dict with the fixed
key order ``need``, ``next``, ``status``.  When the batch starts beyond
the local log (``after`` greater than the local last seq ``L``) nothing is
written and ``status`` is ``"missing"`` with ``need`` holding the gap
``[L + 1, after]`` and ``next`` set to ``L``.  Otherwise records already
present locally must match field by field (a mismatch raises
:class:`ValueError`); the matching prefix is skipped idempotently and
only the contiguous suffix past ``L`` is appended, linked to the local
last hash.  ``need`` is then ``None``, ``next`` is ``max(L, batch.next)``
and ``status`` is ``"applied"`` when records were appended, else
``"duplicate"``.  Any failure leaves the log untouched.
"""

from __future__ import annotations

import json
import os
import re

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
_STRING_FIELDS = (audit.DETAIL, audit.KIND, audit.PREV, audit.SOURCE, audit.HASH)
_BATCH_VERSION = 1
_MIN_LIMIT = 1
_MAX_LIMIT = 1000
_HEX64 = re.compile(r"[0-9a-f]{64}")


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


def _invalid_batch(message: str) -> ValueError:
    return ValueError(f"invalid replication batch: {message}")


def _compact(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _parse_batch(batch: bytes) -> dict:
    """Validate a batch against the export byte contract and decode it."""
    if not batch.endswith(b"\n") or batch.endswith(b"\n\n"):
        raise _invalid_batch("must be a single JSON object terminated by one LF")
    try:
        data = json.loads(batch[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid_batch("is not valid UTF-8 JSON") from exc

    if not isinstance(data, dict) or tuple(data.keys()) != _BATCH_KEYS:
        raise _invalid_batch(
            "top-level object must have exactly the keys "
            "'after', 'complete', 'next', 'records', 'version' in order"
        )
    version = data[VERSION]
    if isinstance(version, bool) or not isinstance(version, int) or version != _BATCH_VERSION:
        raise _invalid_batch("version must be the integer 1")
    for key in (AFTER, NEXT):
        if isinstance(data[key], bool) or not isinstance(data[key], int):
            raise _invalid_batch(f"{key} must be an int")
        if data[key] < 0:
            raise _invalid_batch(f"{key} must be >= 0")
    if not isinstance(data[COMPLETE], bool):
        raise _invalid_batch("complete must be a bool")
    records = data[RECORDS]
    if not isinstance(records, list):
        raise _invalid_batch("records must be a list")

    expected_seq = data[AFTER]
    expected_prev = audit._ZERO_HASH if data[AFTER] == 0 else None
    for index, record in enumerate(records):
        if not isinstance(record, dict) or tuple(record.keys()) != _RECORD_KEYS:
            raise _invalid_batch(
                f"record {index} must have exactly the keys "
                "'detail', 'hash', 'kind', 'prev', 'seq', 'source' in order"
            )
        for field in _STRING_FIELDS:
            if not isinstance(record[field], str):
                raise _invalid_batch(f"record {index} {field} must be a str")
        if record[audit.DETAIL] == "" or record[audit.SOURCE] == "":
            raise _invalid_batch(f"record {index} detail and source must be non-empty")
        if record[audit.KIND] not in audit._KINDS:
            raise _invalid_batch(
                f"record {index} kind must be one of 'local', 'merge' or 'restore'"
            )
        prev = record[audit.PREV]
        digest = record[audit.HASH]
        if expected_prev is not None:
            if prev != expected_prev:
                raise _invalid_batch(
                    f"record {index} prev does not match the previous record hash"
                )
        elif not _HEX64.fullmatch(prev):
            # The first record's prev refers to the exporter's log and
            # cannot be checked against local state; require hash shape.
            raise _invalid_batch(f"record {index} prev must be 64 lowercase hex chars")
        seq = record[audit.SEQ]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _invalid_batch(f"record {index} seq must be an int")
        expected_seq += 1
        if seq != expected_seq:
            raise _invalid_batch(
                f"record {index} seq is {seq}, expected {expected_seq}"
            )
        without_hash = {
            audit.DETAIL: record[audit.DETAIL],
            audit.KIND: record[audit.KIND],
            audit.PREV: prev,
            audit.SEQ: seq,
            audit.SOURCE: record[audit.SOURCE],
        }
        if digest != audit._record_hash(without_hash):
            raise _invalid_batch(f"record {index} hash does not match its contents")
        expected_prev = digest

    expected_next = expected_seq if records else data[AFTER]
    if data[NEXT] != expected_next:
        raise _invalid_batch("next must be the last record seq, or after when empty")

    # The bytes must be the exact canonical compact encoding export_batch
    # produces: no whitespace, no non-canonical escapes, fixed key order.
    if _compact(data) + b"\n" != batch:
        raise _invalid_batch("encoding is not the canonical compact form")
    return data


def import_batch(path: str, batch: bytes) -> dict:
    """Validate a replication batch and append its suffix to the local log.

    See the module docstring for the byte contract.  A ``path`` that is not
    a str or a ``batch`` that is not bytes raises :class:`TypeError`; any
    contract violation raises :class:`ValueError`.  The local log is read
    solely through :func:`audit.read`, and a corrupt log or filesystem
    error propagates as :class:`~offline_coordination.audit.
    CorruptAuditError` or :class:`OSError`.  Nothing is written on any
    failure.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if not isinstance(batch, bytes):
        raise TypeError("batch must be bytes")

    data = _parse_batch(batch)
    after = data[AFTER]
    batch_records = data[RECORDS]

    local_records = audit.read(path)
    last_seq = local_records[-1][audit.SEQ] if local_records else 0

    if after > last_seq:
        return {NEED: [last_seq + 1, after], NEXT: last_seq, STATUS: STATUS_MISSING}

    # Records with seq <= last_seq must already exist locally and match the
    # batch record field by field; everything past last_seq is appended.
    suffix: list[dict] = []
    for record in batch_records:
        seq = record[audit.SEQ]
        if seq <= last_seq:
            local = local_records[seq - 1]
            if any(record[key] != local[key] for key in _RECORD_KEYS):
                raise _invalid_batch(
                    f"record {seq} conflicts with the local record of the same seq"
                )
        else:
            if seq != last_seq + 1 + len(suffix):
                raise _invalid_batch("records past the local last seq must be contiguous")
            suffix.append(record)

    if not suffix:
        return {NEED: None, NEXT: max(last_seq, data[NEXT]), STATUS: STATUS_DUPLICATE}

    # The first appended record must chain onto the local log's last hash
    # (or the zero hash for an empty log).
    local_last_hash = local_records[-1][audit.HASH] if local_records else audit._ZERO_HASH
    if suffix[0][audit.PREV] != local_last_hash:
        raise _invalid_batch(
            "first new record prev must match the local last record hash"
        )

    lines = b"".join(
        audit._encode_line({key: record[key] for key in _RECORD_KEYS})
        for record in suffix
    )
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

    return {NEED: None, NEXT: max(last_seq, data[NEXT]), STATUS: STATUS_APPLIED}
