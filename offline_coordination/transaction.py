"""Replayable commit checkpoints for offline coordination.

A checkpoint names an ``id``, the two 64-char lowercase hex digests of the
state and audit bytes it binds, and the ``stage`` the commit has reached.
Stages advance in the fixed order::

    prepared -> state -> audit -> committed

Checkpoints are kept in an index stored as UTF-8 compact JSON::

    {"items":[{"audit":...,"id":...,"stage":...,"state":...},...],"version":1}\\n

The top-level keys are fixed in the order ``items`` then ``version`` and
``version`` is always the integer 1.  ``items`` is an array of records
sorted ascending by ``id`` (ids are unique); each record carries the str
keys ``audit``, ``id``, ``stage`` and ``state`` in that order.  Non-ASCII
characters are preserved unescaped and the file ends with exactly one
``\\n``.

A missing index file stands for an empty index.  An existing file is
corrupt unless it is one compact UTF-8 JSON encoding of a valid index:
no stray whitespace or non-canonical escapes and exactly one trailing
``\\n``.  The object *key order* carries no meaning, however, so an
otherwise identical compact encoding with the top-level or record keys
permuted is accepted as equivalent; files written by this module always
use the canonical key order described above.

A brand-new id may only be recorded at the ``prepared`` stage.  Replaying
the same id with identical digests at the same stage is idempotent and
leaves the file bytes untouched; the stage may then advance one step at a
time, each advance replacing the file atomically.  Changed digests, a
stage regression or a skipped stage are rejected and never touch the file.

:func:`resume` drives a single recovery step.  Its request carries only
the ``id``, ``state`` and ``audit`` digests and ``observed`` names the
stage the caller believes it has reached (``None`` for a fresh resume).
A new id is only accepted with ``observed=None`` and starts at
``prepared``.  For an existing id with identical digests, ``observed``
of ``None`` or the current stage only queries the index (leaving the
file bytes untouched), while the adjacent next stage advances it once;
a regression, a skipped stage or an illegal value is rejected without
touching the file.  The return value names the next action for the
processed stage: ``persist_state`` after ``prepared``,
``append_audit`` after ``state``, ``bind_receipt`` after ``audit`` and
``done`` after ``committed``.

:func:`inspect` is a read-only reconciliation of every checkpoint
against its state bytes, audit log and receipt index.  Its ``paths``
map has the same four keys as :func:`commit`.  A missing checkpoint
file yields an empty list; otherwise each checkpoint is classified as
``recoverable``, ``committed`` or ``conflict`` from whether the main
state's canonical bytes hash to the bound state digest (S), the valid
audit chain contains the bound audit record (A), and no receipt (R0)
or an exactly matching receipt (R1) is bound under the id:

    prepared   recoverable iff not A and R0
    state      recoverable iff S and R0
    audit      recoverable iff S and A and (R0 or R1)
    committed  committed    iff S and A and R1
    every other combination is a conflict.

:func:`commit` drives a whole commit to completion.  Its ``paths`` map
names the ``checkpoint``, ``state``, ``audit`` and ``receipt`` files and
its request carries the ``id``, the full merge ``state`` and one audit
``event``.  The state digest is the SHA-256 of the canonical state bytes
storage writes; the audit digest is the hash of the one appended audit
record.  A first commit persists the state, appends exactly one event,
binds a receipt for the id and both digests, and advances the checkpoint
through the stages in order.  Replaying the same call -- after an
interruption or once committed -- deterministically resumes at the
recorded stage and performs every remaining side effect at most once,
returning the same ``audit``, ``id``, ``stage`` (``committed``) and
``state`` dict.  A digest conflict, or a checkpoint stage whose
artifacts do not match it, raises :class:`ValueError` and leaves the
files unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from . import audit as _audit
from . import receipt as _receipt
from . import storage as _storage

AUDIT = "audit"
ID = "id"
STAGE = "stage"
STATE = "state"
STATUS = "status"

ITEMS = "items"
VERSION = "version"

PREPARED = "prepared"
STAGE_STATE = "state"
STAGE_AUDIT = "audit"
COMMITTED = "committed"

_REQUEST_KEYS = (ID, STATE, AUDIT, STAGE)
_RESUME_KEYS = (ID, STATE, AUDIT)
_COMMIT_KEYS = (ID, STATE, "event")
_PATH_KEYS = ("checkpoint", STATE, AUDIT, "receipt")
_RECORD_KEYS = (AUDIT, ID, STAGE, STATE)
_INDEX_KEYS = (ITEMS, VERSION)
_INDEX_VERSION = 1

_EVENT = "event"
_CHECKPOINT = "checkpoint"
_RECEIPT = "receipt"

_STAGES = (PREPARED, STAGE_STATE, STAGE_AUDIT, COMMITTED)
_STAGE_RANK = {stage: rank for rank, stage in enumerate(_STAGES)}

RECOVERABLE = "recoverable"
CONFLICT = "conflict"

# Action performed once the checkpoint for a stage has been durably
# recorded: persist state after prepared, append the audit entry after
# state, bind the receipt after audit, and nothing after committed.
_NEXT_ACTIONS = {
    PREPARED: "persist_state",
    STAGE_STATE: "append_audit",
    STAGE_AUDIT: "bind_receipt",
    COMMITTED: "done",
}

_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class CorruptTransactionError(ValueError):
    """The checkpoint index exists but its bytes are not a valid index."""


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _validated_request(request: Any) -> dict[str, str]:
    """Validate one checkpoint request and return a fresh dict in record order."""
    if not isinstance(request, dict):
        raise TypeError("request must be a dict")
    if set(request.keys()) != set(_REQUEST_KEYS):
        raise ValueError(
            "request must contain exactly the keys 'id', 'state', 'audit' "
            "and 'stage'"
        )
    for key in _REQUEST_KEYS:
        if not isinstance(request[key], str):
            raise TypeError(f"request {key} must be a str")
    checkpoint_id = request[ID]
    if _ID_RE.fullmatch(checkpoint_id) is None:
        raise ValueError("request id must match [A-Za-z0-9._-]{1,64}")
    if not _is_digest(request[STATE]):
        raise ValueError("request state must be 64 lowercase hex characters")
    if not _is_digest(request[AUDIT]):
        raise ValueError("request audit must be 64 lowercase hex characters")
    stage = request[STAGE]
    if stage not in _STAGE_RANK:
        raise ValueError(
            "request stage must be one of 'prepared', 'state', 'audit' or "
            "'committed'"
        )
    return {
        AUDIT: request[AUDIT],
        ID: checkpoint_id,
        STAGE: stage,
        STATE: request[STATE],
    }


def _validated_resume_request(request: Any) -> dict[str, str]:
    """Validate one resume request and return a fresh dict in record order."""
    if not isinstance(request, dict):
        raise TypeError("request must be a dict")
    if set(request.keys()) != set(_RESUME_KEYS):
        raise ValueError(
            "request must contain exactly the keys 'id', 'state' and 'audit'"
        )
    for key in _RESUME_KEYS:
        if not isinstance(request[key], str):
            raise TypeError(f"request {key} must be a str")
    checkpoint_id = request[ID]
    if _ID_RE.fullmatch(checkpoint_id) is None:
        raise ValueError("request id must match [A-Za-z0-9._-]{1,64}")
    if not _is_digest(request[STATE]):
        raise ValueError("request state must be 64 lowercase hex characters")
    if not _is_digest(request[AUDIT]):
        raise ValueError("request audit must be 64 lowercase hex characters")
    return {
        AUDIT: request[AUDIT],
        ID: checkpoint_id,
        STATE: request[STATE],
    }


def _serialize_index(records: list[dict[str, str]]) -> bytes:
    ordered = [
        {AUDIT: record[AUDIT], ID: record[ID], STAGE: record[STAGE],
         STATE: record[STATE]}
        for record in records
    ]
    index = {ITEMS: ordered, VERSION: _INDEX_VERSION}
    text = json.dumps(index, ensure_ascii=False, separators=(",", ":")) + "\n"
    return text.encode("utf-8")


def _parse_index(raw: bytes) -> list[dict[str, str]]:
    """Validate every byte of a checkpoint index and return its records.

    Raises :class:`CorruptTransactionError` for any UTF-8/JSON failure,
    non-canonical byte encoding, wrong key set, bad version, duplicate or
    unsorted ids, or a field that is not a well-formed str.  The order of
    object keys does not matter: a compact encoding whose only difference
    from the canonical form is key permutation is an equivalent index.
    """
    if raw == b"":
        raise CorruptTransactionError("checkpoint index is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorruptTransactionError("checkpoint index is not valid UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorruptTransactionError("checkpoint index is not valid JSON") from exc

    if not isinstance(data, dict):
        raise CorruptTransactionError("checkpoint index must be a JSON object")
    if set(data.keys()) != set(_INDEX_KEYS):
        raise CorruptTransactionError(
            "checkpoint index must contain exactly the keys 'items' and 'version'"
        )
    version = data[VERSION]
    # bool is a subclass of int; the version must be a genuine integer.
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise CorruptTransactionError("checkpoint index version must be the integer 1")
    raw_items = data[ITEMS]
    if not isinstance(raw_items, list):
        raise CorruptTransactionError("checkpoint index items must be an array")

    records: list[dict[str, str]] = []
    for position, item in enumerate(raw_items):
        where = f"checkpoint index item {position}"
        if not isinstance(item, dict):
            raise CorruptTransactionError(f"{where} must be a JSON object")
        if set(item.keys()) != set(_RECORD_KEYS):
            raise CorruptTransactionError(
                f"{where} must contain exactly the keys 'audit', 'id', 'stage' "
                "and 'state'"
            )
        audit_digest = item[AUDIT]
        record_id = item[ID]
        stage = item[STAGE]
        state_digest = item[STATE]
        if not isinstance(record_id, str) or _ID_RE.fullmatch(record_id) is None:
            raise CorruptTransactionError(f"{where} has an invalid id")
        if not isinstance(stage, str) or stage not in _STAGE_RANK:
            raise CorruptTransactionError(f"{where} has an invalid stage")
        if not isinstance(state_digest, str) or not _is_digest(state_digest):
            raise CorruptTransactionError(
                f"{where} state must be 64 lowercase hex characters"
            )
        if not isinstance(audit_digest, str) or not _is_digest(audit_digest):
            raise CorruptTransactionError(
                f"{where} audit must be 64 lowercase hex characters"
            )
        records.append(
            {AUDIT: audit_digest, ID: record_id, STAGE: stage, STATE: state_digest}
        )

    ids = [record[ID] for record in records]
    if any(left >= right for left, right in zip(ids, ids[1:])):
        raise CorruptTransactionError(
            "checkpoint index ids must be unique and sorted ascending"
        )

    # Reject stray whitespace, non-canonical escapes, duplicate keys and
    # any encoding that is not a single compact form of the validated
    # structure.  Re-serialising the parsed object while preserving its
    # parsed key order tolerates permuted object keys (a semantically
    # equivalent compact index) while still rejecting every other
    # byte-level deviation; writes always use the canonical key order of
    # _serialize_index.
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise CorruptTransactionError(
            "checkpoint index must end with exactly one newline"
        )
    compact = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    if compact != text[:-1]:
        raise CorruptTransactionError("checkpoint index is not canonically encoded")
    return records


def _read_index(path: str) -> list[dict[str, str]]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    return _parse_index(raw)


def _atomic_write(path: str, payload: bytes) -> None:
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


def _apply(
    path: str, records: list[dict[str, str]], record: dict[str, str]
) -> list[dict[str, str]]:
    """Apply ``record`` to ``records`` and return the resulting record list."""
    for position, existing in enumerate(records):
        if existing[ID] != record[ID]:
            continue
        if (
            existing[STATE] != record[STATE]
            or existing[AUDIT] != record[AUDIT]
        ):
            raise ValueError(
                f"checkpoint id {record[ID]!r} is already bound to different "
                "state or audit digests"
            )
        old_rank = _STAGE_RANK[existing[STAGE]]
        new_rank = _STAGE_RANK[record[STAGE]]
        if new_rank == old_rank:
            # Idempotent replay: no filesystem change.
            return records
        if new_rank < old_rank:
            raise ValueError(
                f"checkpoint id {record[ID]!r} cannot regress from stage "
                f"{existing[STAGE]!r} to {record[STAGE]!r}"
            )
        if new_rank > old_rank + 1:
            raise ValueError(
                f"checkpoint id {record[ID]!r} cannot skip from stage "
                f"{existing[STAGE]!r} to {record[STAGE]!r}"
            )
        updated = list(records)
        updated[position] = record
        _atomic_write(path, _serialize_index(updated))
        return updated

    if record[STAGE] != PREPARED:
        raise ValueError("a new checkpoint id must start at the 'prepared' stage")
    updated = sorted(records + [record], key=lambda entry: entry[ID])
    _atomic_write(path, _serialize_index(updated))
    return updated


def checkpoint(
    path: str, request: dict[str, str] | None = None
) -> list[dict[str, str]]:
    """Record or query a replayable commit checkpoint at ``path``.

    With ``request=None`` this is a pure query returning every checkpoint.
    Otherwise ``request`` must contain exactly the str keys ``id``,
    ``state``, ``audit`` and ``stage``: ``id`` matches
    ``[A-Za-z0-9._-]{1,64}``, ``state`` and ``audit`` are 64 lowercase hex
    characters, and ``stage`` is one of ``prepared``, ``state``, ``audit``
    or ``committed``.

    A new id is inserted at ``prepared``; an existing id with identical
    digests replays idempotently at the same stage or advances one adjacent
    stage.  Changed digests, a stage regression or a skipped stage raise
    :class:`ValueError` and leave the file unchanged.  In every case a
    brand-new list sorted ascending by ``id`` is returned, each element a
    fresh dict with the key order ``audit``, ``id``, ``stage``, ``state``.

    Type violations raise :class:`TypeError`; a bad key set, field format
    or stage migration raises :class:`ValueError`; a corrupt index raises
    :class:`CorruptTransactionError`; other filesystem errors propagate as
    :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")

    record = _validated_request(request) if request is not None else None
    records = _read_index(path)
    if record is not None:
        records = _apply(path, records, record)

    return [
        {
            AUDIT: record[AUDIT],
            ID: record[ID],
            STAGE: record[STAGE],
            STATE: record[STATE],
        }
        for record in records
    ]


def resume(
    path: str, request: dict[str, str], observed: str | None = None
) -> str:
    """Recover one commit step at ``path`` and return the next action.

    ``request`` must contain exactly the str keys ``id``, ``state`` and
    ``audit`` in the same format as the matching :func:`checkpoint`
    fields.  ``observed`` must be ``None`` or one of the stages
    ``prepared``, ``state``, ``audit`` or ``committed``; it names the
    stage the caller has observed for the id.

    A new id is only accepted with ``observed=None`` and is recorded at
    the ``prepared`` stage.  An existing id must be bound to the same
    ``state`` and ``audit`` digests; with ``observed=None`` or the
    current stage the call is a pure query and leaves the file bytes
    untouched, while ``observed`` naming the adjacent next stage
    advances the checkpoint exactly once.  A stage regression, a skipped
    stage or an illegal ``observed`` value raise :class:`ValueError` and
    leave the file unchanged.

    The return value is the next action for the processed stage:
    ``persist_state`` for ``prepared``, ``append_audit`` for ``state``,
    ``bind_receipt`` for ``audit`` and ``done`` for ``committed``.

    A non-str ``observed`` other than ``None`` raises :class:`TypeError`;
    the remaining type and value rules, :class:`CorruptTransactionError`
    and :class:`OSError` propagation match :func:`checkpoint`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")

    requested = _validated_resume_request(request)
    if observed is not None:
        if not isinstance(observed, str):
            raise TypeError(
                "observed must be None or one of 'prepared', 'state', "
                "'audit' or 'committed'"
            )
        if observed not in _STAGE_RANK:
            raise ValueError(
                "observed must be None or one of 'prepared', 'state', "
                "'audit' or 'committed'"
            )

    records = _read_index(path)
    existing = next(
        (record for record in records if record[ID] == requested[ID]), None
    )

    if existing is None:
        if observed is not None:
            raise ValueError(
                f"checkpoint id {requested[ID]!r} is new and may only be "
                "resumed with observed=None"
            )
        record = {
            AUDIT: requested[AUDIT],
            ID: requested[ID],
            STAGE: PREPARED,
            STATE: requested[STATE],
        }
        _apply(path, records, record)
        return _NEXT_ACTIONS[PREPARED]

    if (
        existing[STATE] != requested[STATE]
        or existing[AUDIT] != requested[AUDIT]
    ):
        raise ValueError(
            f"checkpoint id {requested[ID]!r} is already bound to different "
            "state or audit digests"
        )

    current_stage = existing[STAGE]
    if observed is None or observed == current_stage:
        # Pure query: no filesystem change.
        processed_stage = current_stage
    else:
        current_rank = _STAGE_RANK[current_stage]
        observed_rank = _STAGE_RANK[observed]
        if observed_rank < current_rank:
            raise ValueError(
                f"checkpoint id {requested[ID]!r} cannot regress from stage "
                f"{current_stage!r} to {observed!r}"
            )
        if observed_rank > current_rank + 1:
            raise ValueError(
                f"checkpoint id {requested[ID]!r} cannot skip from stage "
                f"{current_stage!r} to {observed!r}"
            )
        record = {
            AUDIT: requested[AUDIT],
            ID: requested[ID],
            STAGE: observed,
            STATE: requested[STATE],
        }
        _apply(path, records, record)
        processed_stage = observed

    return _NEXT_ACTIONS[processed_stage]



def _state_payload(state: dict[str, Any]) -> bytes:
    """The canonical storage bytes for a validated merge state."""
    clock, records = _storage._validated_state(state)
    return _storage._serialize(clock, records)


def _validated_paths(paths: Any) -> dict[str, str]:
    """Validate a ``paths`` map and return a fresh dict in path-key order."""
    if not isinstance(paths, dict):
        raise TypeError("paths must be a dict")
    if set(paths.keys()) != set(_PATH_KEYS):
        raise ValueError(
            "paths must contain exactly the keys 'checkpoint', 'state', "
            "'audit' and 'receipt'"
        )
    for key in _PATH_KEYS:
        if not isinstance(paths[key], str):
            raise TypeError(f"paths {key} must be a str")
    return {key: paths[key] for key in _PATH_KEYS}


def _validated_commit_inputs(
    paths: Any, request: Any
) -> tuple[dict[str, str], str, dict[str, Any], dict[str, str], bytes]:
    """Validate ``paths`` and a commit ``request`` before any file access.

    Returns the path map, id, the caller's state, a fresh validated event
    dict and the canonical state bytes.  The state is checked against the
    merge state contract and the event against the audit event contract,
    so their type/value errors propagate unchanged in kind.
    """
    path_map = _validated_paths(paths)

    if not isinstance(request, dict):
        raise TypeError("request must be a dict")
    if set(request.keys()) != set(_COMMIT_KEYS):
        raise ValueError(
            "request must contain exactly the keys 'id', 'state' and 'event'"
        )
    checkpoint_id = request[ID]
    if not isinstance(checkpoint_id, str):
        raise TypeError("request id must be a str")
    if _ID_RE.fullmatch(checkpoint_id) is None:
        raise ValueError("request id must match [A-Za-z0-9._-]{1,64}")

    payload = _state_payload(request[STATE])
    event = _audit._validated_event(request[_EVENT])

    return path_map, checkpoint_id, request[STATE], event, payload


def _planned_audit_digest(
    audit_records: list[dict[str, Any]], event: dict[str, str]
) -> str:
    """Hash the audit record the next :func:`audit.append` would write.

    Deterministic from the log's current tail: its seq is one past the
    last record and its prev is the last record's hash (or the zero hash
    for an empty log).
    """
    seq = len(audit_records) + 1
    prev = audit_records[-1][_audit.HASH] if audit_records else _audit._ZERO_HASH
    without_hash = {
        _audit.DETAIL: event[_audit.DETAIL],
        _audit.KIND: event[_audit.KIND],
        _audit.PREV: prev,
        _audit.SEQ: seq,
        _audit.SOURCE: event[_audit.SOURCE],
    }
    return _audit._record_hash(without_hash)


def _event_matches(record: dict[str, Any], event: dict[str, str]) -> bool:
    return (
        record[_audit.SOURCE] == event[_audit.SOURCE]
        and record[_audit.KIND] == event[_audit.KIND]
        and record[_audit.DETAIL] == event[_audit.DETAIL]
    )


def _advance(
    path: str,
    records: list[dict[str, str]],
    checkpoint_id: str,
    state_digest: str,
    audit_digest: str,
    stage: str,
) -> list[dict[str, str]]:
    """Advance (or insert at ``prepared``) the checkpoint for one stage."""
    record = {
        AUDIT: audit_digest,
        ID: checkpoint_id,
        STAGE: stage,
        STATE: state_digest,
    }
    return _apply(path, records, record)


def _read_state_bytes(path: str) -> bytes | None:
    """Return the raw main state file bytes, or None when it is absent.

    Only the main file is consulted; use :func:`_load_state_bytes` for
    main-then-backup resolution.  Every :class:`OSError` other than
    :class:`FileNotFoundError` propagates unchanged.
    """
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def _load_state_bytes(path: str) -> bytes:
    """Return canonical state bytes from the main file or its backup.

    Selects the state the same way :func:`storage.load_state` does --
    the first of ``path`` then ``path + ".bak"`` that decodes to a
    valid state -- and re-serialises it to canonical bytes (identical
    for the bytes storage itself writes).  Raises
    :class:`FileNotFoundError` when neither file exists and
    :class:`CorruptStateError` unchanged when at least one exists but
    neither holds a valid state; every other :class:`OSError`
    propagates unchanged as well.
    """
    state = _storage.load_state(path)
    clock, records = _storage._validated_state(state)
    return _storage._serialize(clock, records)


def _receipt_kind(
    bound: dict[str, str] | None, state_digest: str, audit_digest: str
) -> str | None:
    """Classify the receipt bound under one id as R0/R1/neither.

    Returns ``None`` for R0 (no receipt), ``"match"`` for R1 (both
    digests match) and ``"mismatch"`` for a bound but divergent receipt.
    """
    if bound is None:
        return None
    if bound[STATE] == state_digest and bound[AUDIT] == audit_digest:
        return "match"
    return "mismatch"


def _classify_status(
    stage: str, state_ok: bool, audit_ok: bool, receipt_kind: str | None
) -> str:
    """Classify one checkpoint from its S/A/R evidence.

    ``state_ok`` is S (the canonical main/backup state bytes hash to
    the bound state digest); ``audit_ok`` is A (the valid audit chain
    contains the bound audit digest); ``receipt_kind`` is ``None`` for
    R0, ``"match"`` for R1 and ``"mismatch"`` for a divergent receipt.
    """
    if stage == PREPARED:
        if not audit_ok and receipt_kind is None:
            return RECOVERABLE
    elif stage == STAGE_STATE:
        if state_ok and receipt_kind is None:
            return RECOVERABLE
    elif stage == STAGE_AUDIT:
        if state_ok and audit_ok and receipt_kind != "mismatch":
            return RECOVERABLE
    else:  # COMMITTED
        if state_ok and audit_ok and receipt_kind == "match":
            return COMMITTED
    return CONFLICT


def inspect(paths: dict[str, str]) -> list[dict[str, str]]:
    """Read-only reconciliation of every checkpoint against its artifacts.

    ``paths`` must contain exactly the str keys ``checkpoint``,
    ``state``, ``audit`` and ``receipt``, naming the checkpoint index,
    the main state file (its ``.bak`` is consulted the same way
    :func:`storage.load_state` does), the audit log and the receipt
    index.

    A missing checkpoint file yields ``[]``.  Otherwise a brand-new
    list sorted ascending by ``id`` is returned; each element is a
    fresh dict with the fixed key order ``audit``, ``id``, ``stage``,
    ``state``, ``status``, where the first four values are copied from
    the checkpoint record and ``status`` is ``recoverable``,
    ``committed`` or ``conflict``.

    For each checkpoint let S mean the complete canonical state bytes
    hash to its bound state digest, A mean the valid audit chain
    contains a record whose hash is its bound audit digest, R0 mean no
    receipt is bound under the id and R1 mean a receipt is bound whose
    two digests both match.  A ``prepared`` checkpoint with ``not A
    and R0``, a ``state`` checkpoint with ``S and R0`` and an
    ``audit`` checkpoint with ``S and A and (R0 or R1)`` are
    ``recoverable``; a ``committed`` checkpoint with ``S and A and
    R1`` is ``committed``; every other combination is ``conflict``.

    No file is created, replaced or modified.  When at least one of the
    main state file and its backup exists but neither holds a valid
    state, :class:`CorruptStateError` propagates unchanged; a corrupt
    checkpoint, audit log or receipt index propagates its matching
    ``Corrupt...Error`` and other filesystem errors propagate as
    :class:`OSError`.
    """
    path_map = _validated_paths(paths)
    checkpoint_path = path_map[_CHECKPOINT]
    state_path = path_map[STATE]
    audit_path = path_map[AUDIT]
    receipt_path = path_map[_RECEIPT]

    # A genuinely missing checkpoint index means there is nothing to
    # inspect and yields [] without touching the other artifacts.  An
    # index that merely exists with zero records is different: the
    # artifact gates below still run, so e.g. a state file that exists
    # but is corrupt raises CorruptStateError.
    try:
        with open(checkpoint_path, "rb") as handle:
            raw_index = handle.read()
    except FileNotFoundError:
        return []
    records = _parse_index(raw_index)

    # Read the state up front.  At least one of main/backup existing
    # without a single valid state is corruption, not a per-record
    # conflict, for both inspect and commit.
    canonical_state: bytes | None
    try:
        canonical_state = _load_state_bytes(state_path)
    except FileNotFoundError:
        canonical_state = None
    state_digest_on_disk = (
        hashlib.sha256(canonical_state).hexdigest()
        if canonical_state is not None
        else None
    )

    audit_records = _audit._read_all_records(audit_path)
    audit_hashes = {record[_audit.HASH] for record in audit_records}
    receipt_records = _receipt._read_index(receipt_path)
    receipts_by_id = {record[ID]: record for record in receipt_records}

    result: list[dict[str, str]] = []
    for record in records:
        stage = record[STAGE]
        state_ok = (
            state_digest_on_disk is not None
            and state_digest_on_disk == record[STATE]
        )
        audit_ok = record[AUDIT] in audit_hashes
        receipt_kind = _receipt_kind(
            receipts_by_id.get(record[ID]), record[STATE], record[AUDIT]
        )
        status = _classify_status(stage, state_ok, audit_ok, receipt_kind)

        result.append(
            {
                AUDIT: record[AUDIT],
                ID: record[ID],
                STAGE: stage,
                STATE: record[STATE],
                STATUS: status,
            }
        )
    return result


def commit(paths: dict[str, str], request: dict[str, Any]) -> dict[str, str]:
    """Run one replayable commit across storage, audit, receipt and checkpoint.

    ``paths`` must contain exactly the str keys ``checkpoint``, ``state``,
    ``audit`` and ``receipt``.  ``request`` must contain exactly the keys
    ``id`` (same format as :func:`checkpoint`), ``state`` (a state obeying
    the :mod:`~offline_coordination.merge` state contract) and ``event``
    (an event obeying the :mod:`~offline_coordination.audit` event
    contract).

    The state digest is the lowercase-hex SHA-256 of the complete
    canonical state bytes (including the trailing ``\\n``) that
    :mod:`~offline_coordination.storage` persists; the audit digest is
    the hash of the single audit record appended for this commit.  A
    first commit saves the state, appends exactly one audit event, binds
    a receipt carrying the id and both digests, and advances the
    checkpoint through ``prepared``, ``state``, ``audit`` and
    ``committed`` in that order.

    Replaying the same arguments -- or re-entering after an interruption
    -- resumes at the recorded stage and performs each remaining side
    effect at most once, so the result is identical and no effect is
    duplicated.  Every artifact is reconciled against the checkpoint
    stage before any file is touched, applying the same S/A/R test
    :func:`inspect` reports: a ``conflict`` checkpoint, a digest
    conflict, or a stage whose state file, audit record or receipt is
    missing, extra or mismatched, raises :class:`ValueError` and leaves
    the files unchanged, while a ``recoverable`` checkpoint resumes its
    remaining idempotent phases.  The state is resolved main-then-backup
    like :func:`storage.load_state`, so at least one of the two existing
    without a single valid state raises :class:`CorruptStateError`
    instead of being treated as a conflict.

    On success a brand-new dict is returned with the key order
    ``audit``, ``id``, ``stage``, ``state`` and ``stage`` equal to
    ``committed``.  Type violations raise :class:`TypeError`; bad key
    sets, formats, state/event values, digest conflicts and stage/
    artifact mismatches raise :class:`ValueError`;
    :class:`CorruptStateError`, :class:`CorruptAuditError`,
    :class:`CorruptReceiptError`, :class:`CorruptTransactionError` and
    :class:`OSError` propagate unchanged.
    """
    (
        path_map,
        checkpoint_id,
        state,
        event,
        payload,
    ) = _validated_commit_inputs(paths, request)
    checkpoint_path = path_map[_CHECKPOINT]
    state_path = path_map[STATE]
    audit_path = path_map[AUDIT]
    receipt_path = path_map[_RECEIPT]

    state_digest = hashlib.sha256(payload).hexdigest()

    # Read every artifact up front.  All reconciliation below happens
    # before any mutation, so a rejected commit changes nothing.  The
    # state is selected main-then-backup exactly like load_state: at
    # least one of the two existing without a single valid state raises
    # CorruptStateError unchanged.
    audit_records = _audit._read_all_records(audit_path)
    planned_audit_digest = _planned_audit_digest(audit_records, event)
    bound_receipt = _receipt.get(receipt_path, checkpoint_id)
    records = _read_index(checkpoint_path)
    existing = next(
        (record for record in records if record[ID] == checkpoint_id), None
    )
    try:
        state_on_disk = _load_state_bytes(state_path)
    except FileNotFoundError:
        state_on_disk = None
    # The persist step materialises the main file specifically, so the
    # save decision compares the request bytes against the raw main file
    # (not the backup the classification above may resolve from).
    main_state_on_disk = _read_state_bytes(state_path)

    need_save = False
    need_append = False
    need_receipt = False

    if existing is None:
        # An id absent from the checkpoint index cannot have produced any
        # artifact of its own yet; a receipt bound under it is a conflict.
        if bound_receipt is not None:
            raise ValueError(
                f"receipt id {checkpoint_id!r} is already bound but no "
                "checkpoint exists for it"
            )
        audit_digest = planned_audit_digest
        stage = PREPARED
        # The state save is the first artifact effect; it is pending
        # unless the main file already holds the committed bytes.
        need_save = main_state_on_disk != payload
        need_append = True
        need_receipt = True
    else:
        if existing[STATE] != state_digest:
            raise ValueError(
                f"checkpoint id {checkpoint_id!r} is already bound to a "
                "different state digest"
            )
        audit_digest = existing[AUDIT]
        stage = existing[STAGE]
        audit_record = next(
            (item for item in audit_records
             if item[_audit.HASH] == audit_digest),
            None,
        )

        # Apply the same read-only reconciliation inspect uses.  A
        # checkpoint the artifacts cannot recover from is a conflict and
        # is rejected before any file is touched; a recoverable (or
        # already committed) checkpoint falls through to the stage logic
        # below, which additionally pins the requested event and resumes
        # the remaining idempotent steps.
        state_ok = state_on_disk is not None and state_on_disk == payload
        receipt_kind = _receipt_kind(
            bound_receipt, state_digest, audit_digest
        )
        if _classify_status(
            stage, state_ok, audit_record is not None, receipt_kind
        ) == CONFLICT:
            raise ValueError(
                f"checkpoint id {checkpoint_id!r} at stage {stage!r} is in "
                "conflict with its state, audit or receipt artifacts"
            )

        if stage == PREPARED:
            # The event has not been appended yet, so its record hash must
            # still be derivable from the current log tail.
            if audit_digest != planned_audit_digest:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is already bound to a "
                    "different audit digest"
                )
            if audit_record is not None:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is at stage 'prepared' "
                    "but its audit record is already present"
                )
            if bound_receipt is not None:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is at stage 'prepared' "
                    "but a receipt is already bound"
                )
            # The save is pending unless the main file already holds the
            # committed bytes; save_state itself rotates any prior state.
            need_save = main_state_on_disk != payload
            need_append = True
            need_receipt = True
        elif stage == STAGE_STATE:
            if state_on_disk != payload:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is past stage "
                    "'prepared' but its state file is missing or mismatched"
                )
            if bound_receipt is not None:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is at stage 'state' but "
                    "a receipt is already bound"
                )
            if audit_record is None:
                # The append may still be pending; the log tail must still
                # derive the bound record for this event.
                if audit_digest != planned_audit_digest:
                    raise ValueError(
                        f"checkpoint id {checkpoint_id!r} is at stage 'state' "
                        "but its audit record is missing"
                    )
                need_append = True
            elif not _event_matches(audit_record, event):
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} audit record does not "
                    "match its committed event"
                )
            need_receipt = True
        elif stage == STAGE_AUDIT:
            if state_on_disk != payload:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is past stage "
                    "'prepared' but its state file is missing or mismatched"
                )
            if audit_record is None:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is past stage 'state' "
                    "but its audit record is missing"
                )
            if not _event_matches(audit_record, event):
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} audit record does not "
                    "match its committed event"
                )
            if bound_receipt is None:
                need_receipt = True
            elif (
                bound_receipt[STATE] != state_digest
                or bound_receipt[AUDIT] != audit_digest
            ):
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} receipt is bound to "
                    "different state or audit digests"
                )
        else:  # COMMITTED
            if state_on_disk != payload:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is past stage "
                    "'prepared' but its state file is missing or mismatched"
                )
            if audit_record is None:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is past stage 'state' "
                    "but its audit record is missing"
                )
            if not _event_matches(audit_record, event):
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} audit record does not "
                    "match its committed event"
                )
            if bound_receipt is None:
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} is committed but its "
                    "receipt is missing"
                )
            if (
                bound_receipt[STATE] != state_digest
                or bound_receipt[AUDIT] != audit_digest
            ):
                raise ValueError(
                    f"checkpoint id {checkpoint_id!r} receipt is bound to "
                    "different state or audit digests"
                )

    # Reconciliation succeeded; perform each remaining effect at most
    # once and advance the checkpoint after every durable step.
    if existing is None:
        records = _advance(
            checkpoint_path, records, checkpoint_id,
            state_digest, audit_digest, PREPARED,
        )

    if stage == PREPARED:
        if need_save:
            _storage.save_state(state_path, state)
        records = _advance(
            checkpoint_path, records, checkpoint_id,
            state_digest, audit_digest, STAGE_STATE,
        )
        stage = STAGE_STATE

    if stage == STAGE_STATE:
        if need_append:
            _audit.append(audit_path, event)
        records = _advance(
            checkpoint_path, records, checkpoint_id,
            state_digest, audit_digest, STAGE_AUDIT,
        )
        stage = STAGE_AUDIT

    if stage == STAGE_AUDIT:
        if need_receipt:
            _receipt.put(
                receipt_path,
                {AUDIT: audit_digest, ID: checkpoint_id, STATE: state_digest},
            )
        _advance(
            checkpoint_path, records, checkpoint_id,
            state_digest, audit_digest, COMMITTED,
        )

    return {
        AUDIT: audit_digest,
        ID: checkpoint_id,
        STAGE: COMMITTED,
        STATE: state_digest,
    }
