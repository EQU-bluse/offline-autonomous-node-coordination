"""Read-only audit replication batches.

A batch is a single UTF-8 compact JSON object (non-ASCII preserved, no
whitespace) terminated by exactly one ``\\n``::

    {"after":...,"complete":...,"next":...,"records":[...],"version":1}

The top-level keys are fixed in the order ``after``, ``complete``,
``next``, ``records``, ``version`` and ``version`` is always the integer
1.  ``after`` echoes the request's ``after`` argument.  ``records`` holds
up to ``limit`` (at most 1000) audit records whose ``seq`` is greater
than ``after``, in audit order, each preserving the audit record key
order ``detail, hash, kind, prev, seq, source`` and its original values.
``next`` is the seq of the last record in the batch, or ``after`` itself
when the batch is empty; ``complete`` is true when no record follows the
batch, and an empty ``records`` list is only valid when ``complete`` is
true.  Batches are generated solely through :func:`audit.read`, so the
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

Batch records are checked only against the byte contract: canonical
encoding, key order, the seq/prev/hash chain and the stored values.
Value-domain rules enforced by :func:`audit.append` on event input (the
kind enum, non-empty string fields) are *not* re-enforced here, so every
log :func:`audit.read` accepts round-trips through
:func:`export_batch`/:func:`import_batch`.  The append itself is atomic:
when the write, flush or fsync step raises :class:`OSError` the error
propagates unchanged and the log is left byte-identical to its pre-call
state (still missing when it was missing).

:func:`apply_remote` adds persistent application of a remote state to a
version-one ledger.  The ledger is a single self-contained UTF-8 compact
JSON file (keys sorted lexicographically: ``audit``, ``requests``,
``state``, ``version``) terminated by exactly one ``\\n``; ``state`` is
the current merge state, ``requests`` binds processed request ids to the
digest of their request summary, and ``audit`` carries one entry per
committed request with its ``id``, ``source``, ``before``/``after`` state
digests and a one-based, strictly increasing ``seq``.  A missing ledger
starts from the request's ``base`` state; an existing file that violates
any byte, structure, state or index rule is rejected with
:class:`ValueError` and never modified.  See :func:`apply_remote` for the
idempotency, staleness, prerequisite and per-record decision rules and
the atomic replacement guarantees.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

from offline_coordination import audit, storage
from offline_coordination.merge import (
    CLOCK,
    RECORDS,
    _dominates,
    _remote_need,
    _validated_state,
)

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
STATUS_CONFLICT = "conflict"
STATUS_STALE = "stale"

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
    if len(records) > _MAX_LIMIT:
        raise _invalid_batch("records must contain at most 1000 items")
    if not records and not data[COMPLETE]:
        raise _invalid_batch("empty records require complete to be true")

    expected_seq = data[AFTER]
    expected_prev = audit._ZERO_HASH if data[AFTER] == 0 else None
    for index, record in enumerate(records):
        if not isinstance(record, dict) or tuple(record.keys()) != _RECORD_KEYS:
            raise _invalid_batch(
                f"record {index} must have exactly the keys "
                "'detail', 'hash', 'kind', 'prev', 'seq', 'source' in order"
            )
        # Only the byte contract is enforced here: key order, the
        # seq/prev/hash chain and the stored values.  Value-domain rules
        # (non-empty fields, the kind enum) belong to audit.append's event
        # input, so records from any log audit.read accepts stay importable.
        prev = record[audit.PREV]
        digest = record[audit.HASH]
        if expected_prev is not None:
            if prev != expected_prev:
                raise _invalid_batch(
                    f"record {index} prev does not match the previous record hash"
                )
        elif not isinstance(prev, str) or not _HEX64.fullmatch(prev):
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


def _restore_log(path: str, existed: bool, size: int) -> None:
    """Best-effort rollback of a failed append.

    Append-mode writes only ever extend the file, so truncating back to
    the pre-call size restores the exact prior bytes; a file the failed
    call newly created is unlinked again.  Rollback errors are swallowed
    so the original :class:`OSError` propagates unchanged.
    """
    try:
        if existed:
            with open(path, "r+b") as handle:
                handle.truncate(size)
                handle.flush()
                os.fsync(handle.fileno())
        else:
            os.unlink(path)
    except OSError:
        pass


def import_batch(path: str, batch: bytes) -> dict:
    """Validate a replication batch and append its suffix to the local log.

    See the module docstring for the byte contract.  A ``path`` that is not
    a str or a ``batch`` that is not bytes raises :class:`TypeError`; any
    contract violation raises :class:`ValueError`.  The local log is read
    solely through :func:`audit.read`, and a corrupt log or filesystem
    error propagates as :class:`~offline_coordination.audit.
    CorruptAuditError` or :class:`OSError`.  Any failure leaves the log
    byte-identical to its pre-call state (still missing when it was
    missing).
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
    original_size = os.path.getsize(path) if existed else 0
    dir_fd: int | None = None
    try:
        with open(path, "ab") as handle:
            handle.write(lines)
            handle.flush()
            os.fsync(handle.fileno())
        if not existed:
            dir_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
            os.fsync(dir_fd)
    except OSError:
        _restore_log(path, existed, original_size)
        raise
    finally:
        if dir_fd is not None:
            os.close(dir_fd)

    return {NEED: None, NEXT: max(last_seq, data[NEXT]), STATUS: STATUS_APPLIED}


# ---------------------------------------------------------------------------
# Persistent remote-state application (version 1 ledger)
# ---------------------------------------------------------------------------
#
# A version-one ledger is a single UTF-8 compact JSON object with keys
# sorted lexicographically (``audit``, ``requests``, ``state``,
# ``version``) terminated by exactly one ``\n``.  ``state`` holds the
# current merge state, ``requests`` binds each processed request id to
# the SHA-256 digest of its request summary, and ``audit`` lists one
# entry per applied request in append order.

APPLY_ID = "id"
APPLY_SOURCE = "source"
APPLY_BASE = "base"
APPLY_REMOTE = "remote"

_LEDGER_AUDIT = "audit"
_LEDGER_REQUESTS = "requests"
_LEDGER_STATE = "state"
_LEDGER_VERSION = "version"

_DECISION = "decision"
_KEY = "key"
_NEED = NEED
_RECEIPT = "receipt"
_ITEMS = "items"

_LEDGER_KEYS = (_LEDGER_AUDIT, _LEDGER_REQUESTS, _LEDGER_STATE, _LEDGER_VERSION)
_REQUEST_KEYS = (APPLY_BASE, APPLY_ID, APPLY_REMOTE, APPLY_SOURCE)
_AUDIT_ENTRY_KEYS = ("after", "before", APPLY_ID, "seq", APPLY_SOURCE)
_APPLY_RESULT_KEYS = (_ITEMS, _RECEIPT, STATUS)
_ITEM_KEYS = (_KEY, _DECISION, _NEED)

_LEDGER_VERSION_VALUE = 1

_DECISION_APPLY = "apply"
_DECISION_CONFLICT = STATUS_CONFLICT
_DECISION_DUPLICATE = STATUS_DUPLICATE
_DECISION_MISSING = STATUS_MISSING
_DECISION_STALE = STATUS_STALE


def _invalid_ledger(message: str) -> ValueError:
    return ValueError(f"invalid replication ledger: {message}")


def _compact_sorted(obj: object) -> bytes:
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _validated_apply_request(request: object) -> dict[str, object]:
    """Validate an apply_remote request and return a fresh dict copy."""
    if not isinstance(request, dict):
        raise TypeError("request must be a dict")
    if set(request.keys()) != set(_REQUEST_KEYS):
        raise ValueError(
            "request must contain exactly the keys 'id', 'source', 'base' "
            "and 'remote'"
        )
    request_id = request[APPLY_ID]
    source = request[APPLY_SOURCE]
    if not isinstance(request_id, str):
        raise TypeError("request id must be a str")
    if request_id == "":
        raise ValueError("request id must be non-empty")
    if not isinstance(source, str):
        raise TypeError("request source must be a str")
    if source == "":
        raise ValueError("request source must be non-empty")
    # _validated_state enforces the clock/records contract (genuine ints,
    # never bool; deleted values empty; record clocks containing their
    # writer and bounded by the outer clock) and returns fresh copies.
    base_clock, base_records = _validated_state(request[APPLY_BASE])
    remote_clock, remote_records = _validated_state(request[APPLY_REMOTE])
    return {
        APPLY_ID: request_id,
        APPLY_SOURCE: source,
        APPLY_BASE: {CLOCK: base_clock, RECORDS: base_records},
        APPLY_REMOTE: {CLOCK: remote_clock, RECORDS: remote_records},
    }


def _serialize_ledger(state: dict, requests: dict[str, str], entries: list) -> bytes:
    ledger = {
        _LEDGER_AUDIT: [
            {key: entry[key] for key in _AUDIT_ENTRY_KEYS} for entry in entries
        ],
        _LEDGER_REQUESTS: requests,
        _LEDGER_STATE: state,
        _LEDGER_VERSION: _LEDGER_VERSION_VALUE,
    }
    return _compact_sorted(ledger) + b"\n"


def _validated_audit_entry(entry: object, position: int, seq: int) -> dict:
    where = f"ledger audit entry {position}"
    if not isinstance(entry, dict):
        raise _invalid_ledger(f"{where} must be an object")
    if set(entry.keys()) != set(_AUDIT_ENTRY_KEYS):
        raise _invalid_ledger(
            f"{where} must contain exactly the keys 'after', 'before', "
            "'id', 'seq' and 'source'"
        )
    request_id = entry[APPLY_ID]
    source = entry[APPLY_SOURCE]
    before = entry["before"]
    after = entry["after"]
    entry_seq = entry["seq"]
    if not isinstance(request_id, str) or request_id == "":
        raise _invalid_ledger(f"{where} id must be a non-empty str")
    if not isinstance(source, str) or source == "":
        raise _invalid_ledger(f"{where} source must be a non-empty str")
    if not isinstance(before, str) or not isinstance(after, str):
        raise _invalid_ledger(f"{where} before/after must be str digests")
    if not re.fullmatch(r"[0-9a-f]{64}", before) or not re.fullmatch(
        r"[0-9a-f]{64}", after
    ):
        raise _invalid_ledger(f"{where} before/after must be 64 lowercase hex chars")
    if isinstance(entry_seq, bool) or not isinstance(entry_seq, int):
        raise _invalid_ledger(f"{where} seq must be an int")
    if entry_seq != seq:
        raise _invalid_ledger(f"{where} seq is {entry_seq}, expected {seq}")
    return {
        "after": after,
        "before": before,
        APPLY_ID: request_id,
        "seq": entry_seq,
        APPLY_SOURCE: source,
    }


def _parse_ledger(raw: bytes) -> tuple[dict, dict[str, str], list]:
    """Validate every byte of a version-one ledger.

    Returns the current state, the request digest index and the audit
    entries as fresh validated objects.  Any structural, byte-contract,
    state or index violation raises :class:`ValueError`.
    """
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise _invalid_ledger("must be a JSON object terminated by exactly one LF")
    try:
        data = json.loads(raw[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid_ledger("is not valid UTF-8 JSON") from exc

    if not isinstance(data, dict) or set(data.keys()) != set(_LEDGER_KEYS):
        raise _invalid_ledger(
            "top-level object must have exactly the keys 'audit', "
            "'requests', 'state' and 'version'"
        )
    version = data[_LEDGER_VERSION]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != _LEDGER_VERSION_VALUE
    ):
        raise _invalid_ledger("version must be the integer 1")

    # On disk a structurally bad state is an illegal ledger, never a
    # TypeError: _validated_state signals shape problems with TypeError.
    try:
        clock, records = _validated_state(data[_LEDGER_STATE])
    except TypeError as exc:
        raise _invalid_ledger(str(exc)) from exc
    state = {CLOCK: clock, RECORDS: records}

    raw_requests = data[_LEDGER_REQUESTS]
    if not isinstance(raw_requests, dict):
        raise _invalid_ledger("requests must be an object")
    requests: dict[str, str] = {}
    for request_id, digest in raw_requests.items():
        if not isinstance(request_id, str) or request_id == "":
            raise _invalid_ledger("request id must be a non-empty str")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise _invalid_ledger(
                f"request {request_id!r} must bind a 64 lowercase hex digest"
            )
        requests[request_id] = digest

    raw_entries = data[_LEDGER_AUDIT]
    if not isinstance(raw_entries, list):
        raise _invalid_ledger("audit must be a list")
    entries: list[dict] = []
    applied_ids: set[str] = set()
    for position, entry in enumerate(raw_entries):
        validated = _validated_audit_entry(entry, position, position + 1)
        if validated[APPLY_ID] in applied_ids:
            raise _invalid_ledger(
                f"audit entry {position} repeats a previously applied id"
            )
        if validated[APPLY_ID] not in requests:
            raise _invalid_ledger(
                f"audit entry {position} id is not bound in requests"
            )
        applied_ids.add(validated[APPLY_ID])
        entries.append(validated)
    for request_id in requests:
        if request_id not in applied_ids:
            raise _invalid_ledger(
                f"request {request_id!r} is bound but has no audit entry"
            )

    # The bytes must be the exact canonical compact form: sorted keys,
    # no whitespace, no non-canonical escapes, one trailing newline.
    if _serialize_ledger(state, requests, entries) != raw:
        raise _invalid_ledger("encoding is not the canonical compact form")
    return state, requests, entries


def _read_ledger(
    path: str, base: dict
) -> tuple[dict, dict[str, str], list, bool]:
    """Load the ledger at ``path``; a missing file starts from ``base``.

    Returns the current state, request index, audit entries and whether
    the ledger file existed.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        clock, records = _validated_state(base)
        return {CLOCK: clock, RECORDS: records}, {}, [], False
    state, requests, entries = _parse_ledger(raw)
    return state, requests, entries, True


def _request_summary(request: dict[str, object]) -> dict[str, object]:
    return {
        APPLY_BASE: request[APPLY_BASE],
        APPLY_ID: request[APPLY_ID],
        APPLY_REMOTE: request[APPLY_REMOTE],
        APPLY_SOURCE: request[APPLY_SOURCE],
    }


def _request_digest(request: dict[str, object]) -> str:
    return hashlib.sha256(_compact_sorted(_request_summary(request))).hexdigest()


def _state_digest(state: dict) -> str:
    return hashlib.sha256(storage._serialize(state[CLOCK], state[RECORDS])).hexdigest()


def _ledger_atomic_write(path: str, payload: bytes) -> None:
    """Atomically replace the ledger, propagating OSError unchanged."""
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def apply_remote(path: str, request: dict[str, object]) -> dict[str, object]:
    """Persist one remote state application against the ledger at ``path``.

    ``request`` contains exactly the keys ``id`` and ``source`` (both
    non-empty str) and ``base`` and ``remote`` (each a state obeying the
    :mod:`~offline_coordination.merge` contract: a ``clock`` mapping node
    names to genuine non-negative ints, never bool, and ``records`` whose
    entries are ``[value, deleted, clock, writer]`` with an empty value
    when deleted and a record clock containing ``writer`` and bounded by
    the outer clock).

    A missing ledger starts with current state ``base``; an existing
    ledger is read in full and must be a version-one compact ledger or
    :class:`ValueError` is raised and nothing is written.  The same id
    with the same request is ``duplicate`` with byte-identical ledger
    contents; the same id with a different request raises
    :class:`ValueError`.  An unrecorded id whose current state differs
    from ``base`` is ``stale``.

    Otherwise one item per remote record key (ascending) reports
    ``missing`` (with the per-node closed prerequisite intervals in
    ``need``), ``duplicate``, ``apply``, ``stale`` or ``conflict``.  The
    overall status follows missing, conflict, stale, duplicate, applied;
    every status other than ``applied`` has no side effects.  Only when
    at least one item is ``apply`` and all others are ``apply`` or
    ``duplicate`` are the records updated, the outer clock promoted per
    node from the applied record clocks, one audit entry appended and the
    request digest bound.

    The result has the key order ``items``, ``receipt``, ``status``; each
    item has the key order ``key``, ``decision``, ``need`` and ``receipt``
    is ``None`` unless the request committed.  On commit it is the appended
    audit entry in the key order ``after``, ``before``, ``id``, ``seq``,
    ``source``: ``before``/``after`` are SHA-256 digests of the canonical
    state bytes immediately before and after the change and ``seq`` is the
    entry's one-based, strictly increasing position.

    Type violations raise :class:`TypeError`; other format or value
    violations raise :class:`ValueError`; a failed atomic write, replace
    or sync propagates :class:`OSError` unchanged with the original
    ledger bytes preserved.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    validated = _validated_apply_request(request)

    request_id = validated[APPLY_ID]
    source = validated[APPLY_SOURCE]
    base = validated[APPLY_BASE]
    remote = validated[APPLY_REMOTE]
    digest = _request_digest(validated)

    state, bound, entries, _existed = _read_ledger(path, base)
    current_records = state[RECORDS]
    current_clock = state[CLOCK]

    if request_id in bound:
        if bound[request_id] != digest:
            raise ValueError(
                f"request id {request_id!r} is already bound to a different "
                "request"
            )
        items = [
            {
                _DECISION: _DECISION_DUPLICATE,
                _KEY: key,
                _NEED: {},
            }
            for key in sorted(remote[RECORDS])
        ]
        return {
            _ITEMS: [{key: item[key] for key in _ITEM_KEYS} for item in items],
            _RECEIPT: None,
            STATUS: STATUS_DUPLICATE,
        }

    if state != base:
        return {
            _ITEMS: [],
            _RECEIPT: None,
            STATUS: STATUS_STALE,
        }

    items: list[dict[str, object]] = []
    apply_keys: list[str] = []
    for key in sorted(remote[RECORDS]):
        remote_record = remote[RECORDS][key]
        local_record = current_records.get(key)
        need = _remote_need(remote_record, current_clock)

        if need:
            decision = _DECISION_MISSING
        elif local_record is None:
            decision = _DECISION_APPLY
        elif local_record == remote_record:
            decision = _DECISION_DUPLICATE
        elif _dominates(remote_record[2], local_record[2]):
            decision = _DECISION_APPLY
        elif _dominates(local_record[2], remote_record[2]):
            decision = _DECISION_STALE
        else:
            decision = _DECISION_CONFLICT

        if decision == _DECISION_APPLY:
            apply_keys.append(key)
        items.append(
            {
                _DECISION: decision,
                _KEY: key,
                _NEED: need,
            }
        )

    decisions = {item[_DECISION] for item in items}
    if _DECISION_MISSING in decisions:
        overall = STATUS_MISSING
    elif _DECISION_CONFLICT in decisions:
        overall = STATUS_CONFLICT
    elif _DECISION_STALE in decisions:
        overall = STATUS_STALE
    elif not apply_keys:
        # Every record was already present and equal: nothing to commit.
        overall = STATUS_DUPLICATE
    else:
        overall = STATUS_APPLIED

    result_items = [{key: item[key] for key in _ITEM_KEYS} for item in items]
    if overall != STATUS_APPLIED:
        return {_ITEMS: result_items, _RECEIPT: None, STATUS: overall}

    before_digest = _state_digest(state)

    # Apply the remote records and promote the outer clock per node from
    # each applied record's own clock (a componentwise maximum).
    for key in apply_keys:
        value, deleted, record_clock, writer = remote[RECORDS][key]
        current_records[key] = [value, deleted, dict(record_clock), writer]
        for node, count in record_clock.items():
            if count > current_clock.get(node, 0):
                current_clock[node] = count

    after_digest = _state_digest(state)
    seq = len(entries) + 1
    entry = {
        "after": after_digest,
        "before": before_digest,
        APPLY_ID: request_id,
        "seq": seq,
        APPLY_SOURCE: source,
    }
    entries.append(entry)
    bound = dict(bound)
    bound[request_id] = digest

    _ledger_atomic_write(path, _serialize_ledger(state, bound, entries))

    # The receipt is the appended audit entry: it names the id and source,
    # the before/after state digests and the entry's increasing seq.
    receipt = {key: entry[key] for key in _AUDIT_ENTRY_KEYS}
    return {_ITEMS: result_items, _RECEIPT: receipt, STATUS: overall}
