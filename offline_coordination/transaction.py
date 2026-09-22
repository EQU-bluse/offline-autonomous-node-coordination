"""Replayable commit checkpoints for offline coordination transactions.

A checkpoint names an ``id``, the two 64-char lowercase hex digests of the
state and audit it binds, and the ``stage`` the two-phase commit has reached.
Stages advance strictly one adjacent step at a time::

    prepared -> state -> audit -> committed

Checkpoints are kept in an index stored as UTF-8 compact JSON::

    {"items":[{"audit":...,"id":...,"stage":...,"state":...},...],"version":1}\\n

The top-level keys are fixed in the order ``items`` then ``version`` and
``version`` is always the integer 1.  ``items`` is an array of records
sorted ascending by ``id`` (ids are unique); each record carries the str
keys ``audit``, ``id``, ``stage`` and ``state`` in that fixed order.
Non-ASCII characters are preserved unescaped and the file ends with exactly
one ``\\n``.

A missing index file stands for an empty index; an existing file that
violates any byte, structure, order or field rule is corrupt.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

AUDIT = "audit"
ID = "id"
STAGE = "stage"
STATE = "state"

ITEMS = "items"
VERSION = "version"

PREPARED = "prepared"
STATE_STAGE = "state"
AUDIT_STAGE = "audit"
COMMITTED = "committed"

_REQUEST_KEYS = (ID, STATE, AUDIT, STAGE)
_RECORD_KEYS = (AUDIT, ID, STAGE, STATE)
_INDEX_KEYS = (ITEMS, VERSION)
_INDEX_VERSION = 1
_STAGES = (PREPARED, STATE_STAGE, AUDIT_STAGE, COMMITTED)

_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class CorruptTransactionError(ValueError):
    """The checkpoint index exists but its bytes are not a valid index."""


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _validated_request(request: Any) -> dict[str, str]:
    """Validate one checkpoint request and return a fresh record dict.

    The returned dict uses the on-disk record key order
    ``audit``, ``id``, ``stage``, ``state``.
    """
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
    transaction_id = request[ID]
    if _ID_RE.fullmatch(transaction_id) is None:
        raise ValueError("request id must match [A-Za-z0-9._-]{1,64}")
    if not _is_digest(request[STATE]):
        raise ValueError("request state must be 64 lowercase hex characters")
    if not _is_digest(request[AUDIT]):
        raise ValueError("request audit must be 64 lowercase hex characters")
    if request[STAGE] not in _STAGES:
        raise ValueError(
            "request stage must be one of 'prepared', 'state', 'audit' "
            "or 'committed'"
        )
    return {
        AUDIT: request[AUDIT],
        ID: transaction_id,
        STAGE: request[STAGE],
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
    non-canonical byte encoding, wrong key set or order, bad version,
    duplicate or unsorted ids, or a field that is not a well-formed str.
    """
    if raw == b"":
        raise CorruptTransactionError("checkpoint index is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorruptTransactionError(
            "checkpoint index is not valid UTF-8"
        ) from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorruptTransactionError(
            "checkpoint index is not valid JSON"
        ) from exc

    if not isinstance(data, dict):
        raise CorruptTransactionError("checkpoint index must be a JSON object")
    if set(data.keys()) != set(_INDEX_KEYS):
        raise CorruptTransactionError(
            "checkpoint index must contain exactly the keys 'items' and "
            "'version'"
        )
    if list(data.keys()) != list(_INDEX_KEYS):
        raise CorruptTransactionError(
            "checkpoint index keys must be in the order 'items', 'version'"
        )
    version = data[VERSION]
    # bool is a subclass of int; the version must be a genuine integer.
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise CorruptTransactionError(
            "checkpoint index version must be the integer 1"
        )
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
                f"{where} must contain exactly the keys 'audit', 'id', "
                "'stage' and 'state'"
            )
        if list(item.keys()) != list(_RECORD_KEYS):
            raise CorruptTransactionError(
                f"{where} keys must be in the order 'audit', 'id', 'stage', "
                "'state'"
            )
        audit_digest = item[AUDIT]
        transaction_id = item[ID]
        stage = item[STAGE]
        state_digest = item[STATE]
        if not isinstance(transaction_id, str) or (
            _ID_RE.fullmatch(transaction_id) is None
        ):
            raise CorruptTransactionError(f"{where} has an invalid id")
        if not _is_digest(state_digest):
            raise CorruptTransactionError(
                f"{where} state must be 64 lowercase hex characters"
            )
        if not _is_digest(audit_digest):
            raise CorruptTransactionError(
                f"{where} audit must be 64 lowercase hex characters"
            )
        if not isinstance(stage, str) or stage not in _STAGES:
            raise CorruptTransactionError(f"{where} has an invalid stage")
        records.append(
            {
                AUDIT: audit_digest,
                ID: transaction_id,
                STAGE: stage,
                STATE: state_digest,
            }
        )

    ids = [record[ID] for record in records]
    if any(left >= right for left, right in zip(ids, ids[1:])):
        raise CorruptTransactionError(
            "checkpoint index ids must be unique and sorted ascending"
        )

    # Reject stray whitespace, non-canonical escapes, and any encoding that
    # is not the single compact form of the validated structure.
    if _serialize_index(records) != raw:
        raise CorruptTransactionError(
            "checkpoint index is not canonically encoded"
        )
    return records


def _read_index(path: str) -> list[dict[str, str]]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    return _parse_index(raw)


def _fresh_list(records: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return a brand-new list of brand-new record dicts in fixed key order."""
    return [
        {AUDIT: record[AUDIT], ID: record[ID], STAGE: record[STAGE],
         STATE: record[STATE]}
        for record in records
    ]


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


def checkpoint(
    path: str, request: dict[str, str] | None = None
) -> list[dict[str, str]]:
    """Query or advance the replayable commit checkpoint index at ``path``.

    With ``request=None`` the index is queried: a fresh list of all records
    sorted ascending by id is returned, each with the fixed key order
    ``audit``, ``id``, ``stage``, ``state``.  A missing file yields an empty
    list.

    Otherwise ``request`` must contain exactly the str keys ``id``,
    ``state``, ``audit`` and ``stage``; ``id`` must match
    ``[A-Za-z0-9._-]{1,64}``, the two digests must be 64 lowercase hex
    characters, and ``stage`` must be one of ``prepared``, ``state``,
    ``audit`` or ``committed``.  Transition rules:

    * A previously unknown id may only be recorded at ``prepared``.
    * The same id with the same digests and the same stage is an idempotent
      replay: the file bytes are untouched.
    * The same id with different digests raises :class:`ValueError`.
    * A stage may advance exactly one adjacent step
      (``prepared -> state -> audit -> committed``) with unchanged digests;
      regressions and skips raise :class:`ValueError`.

    Every successful change is applied by atomic replacement, and the
    post-change index is returned as a fresh ascending list.  Rejected
    requests leave the file unchanged.

    Type violations raise :class:`TypeError`; bad key sets, formats and
    stage transitions raise :class:`ValueError`; a corrupt index raises
    :class:`CorruptTransactionError`; other filesystem errors propagate as
    :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")

    if request is None:
        return _fresh_list(_read_index(path))

    record = _validated_request(request)
    records = _read_index(path)

    new_stage = _STAGES.index(record[STAGE])
    for position, existing in enumerate(records):
        if existing[ID] != record[ID]:
            continue
        if (
            existing[STATE] != record[STATE]
            or existing[AUDIT] != record[AUDIT]
        ):
            raise ValueError(
                f"checkpoint id {record[ID]!r} is already bound to a "
                "different state or audit digest"
            )
        old_stage = _STAGES.index(existing[STAGE])
        if new_stage == old_stage:
            # Idempotent replay: brand-new copies, no filesystem change.
            return _fresh_list(records)
        if new_stage < old_stage:
            raise ValueError(
                f"checkpoint id {record[ID]!r} stage cannot regress from "
                f"{existing[STAGE]!r} to {record[STAGE]!r}"
            )
        if new_stage != old_stage + 1:
            raise ValueError(
                f"checkpoint id {record[ID]!r} stage cannot skip from "
                f"{existing[STAGE]!r} to {record[STAGE]!r}"
            )
        records[position] = record
        _atomic_write(path, _serialize_index(records))
        return _fresh_list(records)

    if record[STAGE] != PREPARED:
        raise ValueError(
            f"new checkpoint id {record[ID]!r} must start at 'prepared', "
            f"not {record[STAGE]!r}"
        )
    records.append(record)
    records.sort(key=lambda entry: entry[ID])
    _atomic_write(path, _serialize_index(records))
    return _fresh_list(records)
