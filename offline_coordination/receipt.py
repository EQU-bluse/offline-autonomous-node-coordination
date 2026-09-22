"""Idempotent receipts binding a state to an audit record.

A receipt only names an ``id`` and the two 64-char lowercase hex digests of
the state and audit record it binds; the state and audit bytes themselves
are never read or written here.  Receipts are kept in an index stored as
UTF-8 compact JSON::

    {"items":[{"audit":...,"id":...,"state":...},...],"version":1}\\n

The top-level keys are fixed in the order ``items`` then ``version`` and
``version`` is always the integer 1.  ``items`` is an array of records
sorted ascending by ``id`` (ids are unique); each record carries the str
keys ``id``, ``state`` and ``audit`` and is canonically encoded with the
key order ``audit``, ``id``, ``state``.  Non-ASCII characters are preserved
unescaped and the file ends with exactly one ``\\n``.

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
STATE = "state"

ITEMS = "items"
VERSION = "version"

_RECEIPT_KEYS = (ID, STATE, AUDIT)
_RECORD_KEYS = (AUDIT, ID, STATE)
_INDEX_KEYS = (ITEMS, VERSION)
_INDEX_VERSION = 1

_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class CorruptReceiptError(ValueError):
    """The receipt index exists but its bytes are not a valid index."""


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _validated_receipt(receipt: Any) -> dict[str, str]:
    """Validate one receipt and return a fresh dict in record key order."""
    if not isinstance(receipt, dict):
        raise TypeError("receipt must be a dict")
    if set(receipt.keys()) != set(_RECEIPT_KEYS):
        raise ValueError(
            "receipt must contain exactly the keys 'id', 'state' and 'audit'"
        )
    for key in _RECEIPT_KEYS:
        if not isinstance(receipt[key], str):
            raise TypeError(f"receipt {key} must be a str")
    receipt_id = receipt[ID]
    if _ID_RE.fullmatch(receipt_id) is None:
        raise ValueError("receipt id must match [A-Za-z0-9._-]{1,64}")
    if not _is_digest(receipt[STATE]):
        raise ValueError("receipt state must be 64 lowercase hex characters")
    if not _is_digest(receipt[AUDIT]):
        raise ValueError("receipt audit must be 64 lowercase hex characters")
    return {AUDIT: receipt[AUDIT], ID: receipt_id, STATE: receipt[STATE]}


def _serialize_index(records: list[dict[str, str]]) -> bytes:
    ordered = [
        {AUDIT: record[AUDIT], ID: record[ID], STATE: record[STATE]}
        for record in records
    ]
    index = {ITEMS: ordered, VERSION: _INDEX_VERSION}
    text = json.dumps(index, ensure_ascii=False, separators=(",", ":")) + "\n"
    return text.encode("utf-8")


def _parse_index(raw: bytes) -> list[dict[str, str]]:
    """Validate every byte of a receipt index and return its records.

    Raises :class:`CorruptReceiptError` for any UTF-8/JSON failure,
    non-canonical byte encoding, wrong key set or order, bad version,
    duplicate or unsorted ids, or a field that is not a well-formed str.
    """
    if raw == b"":
        raise CorruptReceiptError("receipt index is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorruptReceiptError("receipt index is not valid UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorruptReceiptError("receipt index is not valid JSON") from exc

    if not isinstance(data, dict):
        raise CorruptReceiptError("receipt index must be a JSON object")
    if set(data.keys()) != set(_INDEX_KEYS):
        raise CorruptReceiptError(
            "receipt index must contain exactly the keys 'items' and 'version'"
        )
    if list(data.keys()) != list(_INDEX_KEYS):
        raise CorruptReceiptError(
            "receipt index keys must be in the order 'items', 'version'"
        )
    version = data[VERSION]
    # bool is a subclass of int; the version must be a genuine integer.
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise CorruptReceiptError("receipt index version must be the integer 1")
    raw_items = data[ITEMS]
    if not isinstance(raw_items, list):
        raise CorruptReceiptError("receipt index items must be an array")

    records: list[dict[str, str]] = []
    for position, item in enumerate(raw_items):
        where = f"receipt index item {position}"
        if not isinstance(item, dict):
            raise CorruptReceiptError(f"{where} must be a JSON object")
        if set(item.keys()) != set(_RECORD_KEYS):
            raise CorruptReceiptError(
                f"{where} must contain exactly the keys 'audit', 'id' and 'state'"
            )
        if list(item.keys()) != list(_RECORD_KEYS):
            raise CorruptReceiptError(
                f"{where} keys must be in the order 'audit', 'id', 'state'"
            )
        audit_digest = item[AUDIT]
        record_id = item[ID]
        state_digest = item[STATE]
        if not isinstance(record_id, str) or _ID_RE.fullmatch(record_id) is None:
            raise CorruptReceiptError(f"{where} has an invalid id")
        if not _is_digest(state_digest):
            raise CorruptReceiptError(
                f"{where} state must be 64 lowercase hex characters"
            )
        if not _is_digest(audit_digest):
            raise CorruptReceiptError(
                f"{where} audit must be 64 lowercase hex characters"
            )
        records.append(
            {AUDIT: audit_digest, ID: record_id, STATE: state_digest}
        )

    ids = [record[ID] for record in records]
    if any(left >= right for left, right in zip(ids, ids[1:])):
        raise CorruptReceiptError(
            "receipt index ids must be unique and sorted ascending"
        )

    # Reject stray whitespace, non-canonical escapes, and any encoding that
    # is not the single compact form of the validated structure.
    if _serialize_index(records) != raw:
        raise CorruptReceiptError("receipt index is not canonically encoded")
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


def put(path: str, receipt: dict[str, str]) -> dict[str, str]:
    """Bind ``receipt``'s state and audit digests under its id in the index.

    A new id is added and the index is atomically replaced.  Putting the
    same id with identical state and audit digests is idempotent: a fresh
    dict is returned without touching the file bytes.  The same id with
    different digests raises :class:`ValueError` and leaves the file
    unchanged.  The returned dict always has the key order
    ``audit``, ``id``, ``state``.

    Type violations raise :class:`TypeError`; a bad key set, id or digest
    format raises :class:`ValueError`; a corrupt index raises
    :class:`CorruptReceiptError`; other filesystem errors propagate as
    :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    record = _validated_receipt(receipt)

    records = _read_index(path)
    for existing in records:
        if existing[ID] == record[ID]:
            if (
                existing[STATE] != record[STATE]
                or existing[AUDIT] != record[AUDIT]
            ):
                raise ValueError(
                    f"receipt id {record[ID]!r} is already bound to a "
                    "different state or audit record"
                )
            # Idempotent replay: brand-new copy, no filesystem change.
            return dict(record)

    records.append(record)
    records.sort(key=lambda entry: entry[ID])
    _atomic_write(path, _serialize_index(records))
    return dict(record)


def get(path: str, id: str) -> dict[str, str] | None:
    """Return a fresh copy of the receipt stored under ``id``, or None.

    A missing index file or an index without that id yields ``None``.
    Type violations raise :class:`TypeError`; a malformed ``id`` raises
    :class:`ValueError`; a corrupt index raises
    :class:`CorruptReceiptError`; other filesystem errors propagate as
    :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if not isinstance(id, str):
        raise TypeError("id must be a str")
    if _ID_RE.fullmatch(id) is None:
        raise ValueError("id must match [A-Za-z0-9._-]{1,64}")

    for record in _read_index(path):
        if record[ID] == id:
            return dict(record)
    return None
