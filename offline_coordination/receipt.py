"""Idempotent receipt index for offline coordination.

A receipt binds a state digest to an audit digest::

    {"id": <receipt id>, "state": <64 lowercase hex>, "audit": <64 lowercase hex>}

Receipts are kept in a single index file holding UTF-8 compact JSON
(non-ASCII preserved, no whitespace) terminated by exactly one ``\\n``::

    {"items": [<receipt>, ...], "version": 1}

The top-level key order is fixed to ``items, version`` and each receipt is
encoded with the fixed key order ``audit, id, state``.  ``items`` is sorted
by receipt id in ascending order.  A missing file reads as an empty index;
any existing file that deviates from these byte, structure, order, or field
rules is corrupt and reported as :class:`CorruptReceiptError`.

This module only stores the bindings; it never writes the state or audit
files the digests refer to.
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

_RECEIPT_KEYS = (AUDIT, ID, STATE)
_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


class CorruptReceiptError(ValueError):
    """The receipt index file exists but is not a valid receipt index."""


def _validated_id(receipt_id: Any) -> str:
    if not isinstance(receipt_id, str):
        raise TypeError("receipt id must be a str")
    if _ID_RE.fullmatch(receipt_id) is None:
        raise ValueError(f"invalid receipt id: {receipt_id!r}")
    return receipt_id


def _validated_receipt(receipt: Any) -> dict[str, str]:
    """Validate a receipt and return a fresh dict in canonical key order."""
    if not isinstance(receipt, dict):
        raise TypeError("receipt must be a dict")
    if set(receipt.keys()) != set(_RECEIPT_KEYS):
        raise ValueError(
            "receipt must contain exactly the keys 'id', 'state' and 'audit'"
        )
    receipt_id = _validated_id(receipt[ID])
    result: dict[str, str] = {AUDIT: "", ID: receipt_id, STATE: ""}
    for key in (STATE, AUDIT):
        value = receipt[key]
        if not isinstance(value, str):
            raise TypeError(f"receipt {key} must be a str")
        if _DIGEST_RE.fullmatch(value) is None:
            raise ValueError(
                f"receipt {key} must be 64 lowercase hexadecimal characters"
            )
        result[key] = value
    return result


def _serialize(records: list[dict[str, str]]) -> bytes:
    index = {ITEMS: records, VERSION: 1}
    text = json.dumps(index, ensure_ascii=False, separators=(",", ":")) + "\n"
    return text.encode("utf-8")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise CorruptReceiptError("duplicate key in receipt index")
    return dict(pairs)


def _decode_index(raw: bytes) -> list[dict[str, str]]:
    """Decode and strictly validate index bytes, returning fresh records."""
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorruptReceiptError("receipt index is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or set(data.keys()) != {ITEMS, VERSION}:
        raise CorruptReceiptError("receipt index must have exactly 'items' and 'version'")
    version = data[VERSION]
    if isinstance(version, bool) or version != 1:
        raise CorruptReceiptError("receipt index version must be the integer 1")
    items = data[ITEMS]
    if not isinstance(items, list):
        raise CorruptReceiptError("receipt index items must be an array")
    records: list[dict[str, str]] = []
    for item in items:
        try:
            records.append(_validated_receipt(item))
        except (TypeError, ValueError) as exc:
            raise CorruptReceiptError(f"invalid receipt in index: {exc}") from exc
    ids = [record[ID] for record in records]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise CorruptReceiptError("receipt index items must be unique and sorted by id")
    if _serialize(records) != raw:
        raise CorruptReceiptError("receipt index is not in canonical byte form")
    return records


def _load_records(path: str) -> list[dict[str, str]]:
    """Return the validated records stored at ``path``; missing means empty."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    return _decode_index(raw)


def _fsync_dir(path: str) -> None:
    """Fsync the directory containing ``path`` so a rename is durable."""
    fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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
    _fsync_dir(path)


def put(path: str, receipt: dict[str, str]) -> dict[str, str]:
    """Store ``receipt`` in the index at ``path`` and return a fresh copy of it.

    Adding a new id atomically replaces the index file.  Storing a receipt
    whose id is already present with identical content is a no-op that
    returns a new copy and leaves the file bytes unchanged; the same id with
    different content raises :class:`ValueError` and leaves the file
    unchanged.  A corrupt existing index raises :class:`CorruptReceiptError`
    and is never modified.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    record = _validated_receipt(receipt)
    records = _load_records(path)
    for existing in records:
        if existing[ID] == record[ID]:
            if existing == record:
                return dict(record)
            raise ValueError(
                f"receipt id {record[ID]!r} already stored with different content"
            )
    records.append(record)
    records.sort(key=lambda item: item[ID])
    _atomic_write(path, _serialize(records))
    return dict(record)


def get(path: str, receipt_id: str) -> dict[str, str] | None:
    """Return a fresh copy of the receipt stored under ``receipt_id``.

    Returns ``None`` when the id is not present (a missing index file counts
    as empty).  A corrupt existing index raises :class:`CorruptReceiptError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    receipt_id = _validated_id(receipt_id)
    for record in _load_records(path):
        if record[ID] == receipt_id:
            return dict(record)
    return None
