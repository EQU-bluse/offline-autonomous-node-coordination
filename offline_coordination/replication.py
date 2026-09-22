"""Read-only audit replication batches for offline coordination.

A batch is a UTF-8 JSON object, compactly encoded (no whitespace, non-ASCII
preserved) and terminated by a single ``\\n``::

    {"after":0,"complete":true,"next":2,"records":[...,"version":1}

``records`` holds the audit records whose ``seq`` is greater than ``after``,
up to ``limit``, each preserving the audit record key order
``detail, hash, kind, prev, seq, source``.  Batches never modify the audit
log; all reading goes through :func:`offline_coordination.audit.read`.
"""

from __future__ import annotations

import json
from typing import Any

from .audit import _RECORD_KEYS, read as _audit_read

VERSION = 1
_MIN_LIMIT = 1
_MAX_LIMIT = 1000


def export_batch(path: str, after: int = 0, limit: int = 100) -> bytes:
    """Return one replication batch of audit records at ``path``.

    Selects the first ``limit`` records whose ``seq`` is greater than
    ``after``.  ``next`` is the seq of the last returned record, or
    ``after`` when the batch is empty; ``complete`` is true when no record
    follows the batch.  ``after`` must not exceed the log's last seq (an
    empty log's last seq is 0).

    Type violations raise :class:`TypeError`; out-of-range arguments and an
    ``after`` past the log's end raise :class:`ValueError`; a corrupt log
    raises :class:`CorruptAuditError`; filesystem errors propagate as
    :class:`OSError`.  The log is never modified.
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
        raise ValueError(f"limit must be in [{_MIN_LIMIT}, {_MAX_LIMIT}]")

    records = _audit_read(path)
    last_seq = records[-1]["seq"] if records else 0
    if after > last_seq:
        raise ValueError(f"after ({after}) is past the last seq ({last_seq})")

    batch = [record for record in records if record["seq"] > after][:limit]
    ordered_batch = [
        {key: record[key] for key in _RECORD_KEYS} for record in batch
    ]

    next_seq = ordered_batch[-1]["seq"] if ordered_batch else after
    payload: dict[str, Any] = {
        "after": after,
        "complete": next_seq == last_seq,
        "next": next_seq,
        "records": ordered_batch,
        "version": VERSION,
    }
    return (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
