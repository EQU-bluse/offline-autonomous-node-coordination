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

Batches are checked only against the byte contract: canonical encoding, key
order, the seq/prev/hash chain and the stored values.  Value-domain rules
enforced by :func:`audit.append` on event input (the kind enum, non-empty
string fields) are *not* re-enforced here, so every log :func:`audit.read`
accepts round-trips through :func:`export_batch`/:func:`import_batch`.  The
append itself is atomic: when the write, flush or fsync step raises
:class:`OSError` the error propagates unchanged and the log is left
byte-identical to its pre-call state (still missing when it was missing).

:func:`apply_remote` persists remote state applications in a version-1
*ledger*: one UTF-8 compact JSON object (keys sorted lexicographically,
exactly one trailing ``\\n``) with the top-level keys ``audit``,
``requests``, ``state`` and ``version`` (``version`` is the integer 1).
``state`` holds the current :mod:`~offline_coordination.merge` state,
``requests`` binds each accepted request id to the digest of its request,
and ``audit`` lists one entry per successful application in order; each
entry carries ``after``/``before`` state digests, the request ``id`` and
``source`` and a contiguous ``seq`` starting at 1, every entry after the
first chaining its ``before`` to the previous entry's ``after`` and the
last ``after`` hashing the stored state.  A missing ledger stands for the
request's ``base`` state with empty indexes; any existing file that fails
the byte, structure, state or index rules is rejected with
:class:`ValueError` and left untouched.

Replaying a request whose ``id`` is already bound to exactly the same
request digest always yields ``duplicate`` from the saved binding alone,
immediately or after other commits: one item per remote record in
ascending key order, each already duplicate with an empty ``need`` map,
and no receipt; the ledger is never read for modification on a replay.
A bound ``id`` presented with a different request raises
:class:`ValueError`.  Every successful commit is one durable transaction:
write, flush, file sync, replacement and directory sync all lie inside
its boundary, and an :class:`OSError` at any stage propagates unchanged
with the file system restored to its pre-call state.

:func:`apply_signed_remote` adds an offline-verifiable authentication
boundary in front of the same application flow.  It receives the ledger
path, a keyring, an envelope and the current moment.  The envelope
carries exactly ``node``, ``keyVersion``, ``request`` and ``signature``;
the request follows the :func:`apply_remote` contract and its ``source``
must equal the envelope's ``node``.  The keyring maps node names to
credential entries, each holding exactly ``version`` (a positive integer,
unique per node), ``secret`` (64 lowercase hex characters decoding to the
32-byte HMAC key), ``notBefore``/``notAfter`` (non-negative integers
bounding the validity period, both bounds inclusive) and ``revoked``.
The signed payload is the canonical compact UTF-8 JSON encoding of
``node``, ``keyVersion`` and ``request`` with every object key
recursively sorted lexicographically and non-ASCII preserved; the
signature is the lowercase hex HMAC-SHA256 computed with the selected key
and compared in constant time.  Keys are selected by exact node and
version with no fallback: unknown credentials, a revoked, not-yet-valid
or expired key, a source/node identity mismatch and a signature mismatch
all raise :class:`AuthenticationError` (a :class:`ValueError`) before the
ledger is ever read, so a failed verification creates no file.  Replays
are authenticated against the *current* keyring, so a later revocation or
expiry cannot be bypassed through a historical request binding.  Audit
entries committed through :func:`apply_signed_remote` record the verified
credentials under ``auth``; entries without ``auth`` remain readable and
:func:`apply_remote` keeps its public behaviour and ledger format.

:func:`export_proof` and :func:`verify_proof` add offline audit-proof
exchange over the same ledger.  A proof is one version-1 UTF-8 compact
JSON object -- every object key recursively sorted lexicographically,
non-ASCII preserved, exactly one trailing ``\\n`` -- with the top-level
keys ``digest``, ``endSeq``, ``entries``, ``firstBefore``, ``lastAfter``,
``startSeq`` and ``version``.  ``startSeq``/``endSeq`` name the covered
audit range, ``firstBefore`` is the state digest before the first covered
entry and ``lastAfter`` the state digest after the last one; ``entries``
hold the ledger entries in range unchanged, each carrying ``after``/
``before`` state digests, ``id``, ``seq`` and ``source`` with the optional
``auth`` binding.  ``digest`` is the lowercase hex SHA-256 of the compact
canonical encoding (with no trailing newline) of the proof object with
the ``digest`` key itself removed.  :func:`verify_proof` is purely
offline: it reads neither the ledger nor the keyring.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from typing import BinaryIO

from offline_coordination import audit, merge, storage

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



# --- Persistent remote-state application (version-1 ledger) ----------------

APPLY = "apply"
CONFLICT = "conflict"
DECISION = "decision"
ITEMS = "items"
KEY = "key"
RECEIPT = "receipt"
STALE = "stale"

AUDIT = "audit"
AUTH = "auth"
BASE = "base"
BEFORE = "before"
ID = "id"
KEY_VERSION = "keyVersion"
NODE = "node"
REMOTE = "remote"
REQUESTS = "requests"
SOURCE = "source"
STATE_KEY = "state"

LEDGER_VERSION = 1
_LEDGER_TOP_KEYS = (AUDIT, REQUESTS, STATE_KEY, "version")
_LEDGER_ENTRY_KEY_ORDER = (AFTER, BEFORE, ID, "seq", SOURCE)
_LEDGER_ENTRY_KEY_SET = frozenset(_LEDGER_ENTRY_KEY_ORDER)
_LEDGER_ENTRY_AUTHED_SET = _LEDGER_ENTRY_KEY_SET | {AUTH}
_LEDGER_AUTH_KEYS = frozenset((KEY_VERSION, NODE))
_REQUEST_KEYS = (ID, SOURCE, BASE, REMOTE)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


def _ledger_invalid(message: str) -> ValueError:
    return ValueError(f"invalid replication ledger: {message}")


def _state_bytes(state: dict) -> bytes:
    """Canonical compact UTF-8 bytes (with one trailing LF) of a state."""
    clock, records = merge._validated_state(state)
    return storage._serialize(clock, records)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validated_apply_request(
    request: object,
) -> tuple[str, str, dict, dict]:
    """Validate an apply_remote request into (id, source, base, remote).

    The states come back as fresh copies obeying the merge state contract,
    so type errors raised while validating them stay :class:`TypeError`.
    """
    if not isinstance(request, dict):
        raise TypeError("request must be a dict")
    if set(request.keys()) != set(_REQUEST_KEYS):
        raise ValueError(
            "request must contain exactly the keys 'id', 'source', 'base' "
            "and 'remote'"
        )
    request_id = request[ID]
    source = request[SOURCE]
    if not isinstance(request_id, str):
        raise TypeError("request id must be a str")
    if request_id == "":
        raise ValueError("request id must be non-empty")
    if not isinstance(source, str):
        raise TypeError("request source must be a str")
    if source == "":
        raise ValueError("request source must be non-empty")
    base_clock, base_records = merge._validated_state(request[BASE])
    remote_clock, remote_records = merge._validated_state(request[REMOTE])
    base = {merge.CLOCK: base_clock, merge.RECORDS: base_records}
    remote = {merge.CLOCK: remote_clock, merge.RECORDS: remote_records}
    return request_id, source, base, remote


def _request_digest(request_id: str, source: str, base: dict, remote: dict) -> str:
    """SHA-256 of the canonical compact encoding of the logical request."""
    ordered = {
        BASE: {merge.CLOCK: base[merge.CLOCK], merge.RECORDS: base[merge.RECORDS]},
        ID: request_id,
        REMOTE: {
            merge.CLOCK: remote[merge.CLOCK],
            merge.RECORDS: remote[merge.RECORDS],
        },
        SOURCE: source,
    }
    payload = json.dumps(
        ordered, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _digest(payload)


def _serialize_entry(entry: dict) -> dict:
    """One audit entry as stored: the fixed keys plus ``auth`` when present."""
    out = {key: entry[key] for key in _LEDGER_ENTRY_KEY_ORDER}
    if AUTH in entry:
        out[AUTH] = {KEY_VERSION: entry[AUTH][KEY_VERSION], NODE: entry[AUTH][NODE]}
    return out


def _serialize_ledger(
    state: dict, requests: dict[str, str], entries: list[dict]
) -> bytes:
    """Canonical ledger bytes: compact JSON, sorted keys, one trailing LF."""
    ledger = {
        AUDIT: [_serialize_entry(entry) for entry in entries],
        REQUESTS: dict(requests),
        STATE_KEY: {
            merge.CLOCK: state[merge.CLOCK],
            merge.RECORDS: state[merge.RECORDS],
        },
        "version": LEDGER_VERSION,
    }
    text = json.dumps(
        ledger, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ) + "\n"
    return text.encode("utf-8")


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _parse_ledger(raw: bytes) -> tuple[dict, dict[str, str], list[dict]]:
    """Validate every byte of a ledger into (state, requests, audit).

    Any decoding, structural, state, index or chain violation raises
    :class:`ValueError`; in particular a type fault in the stored state is
    an on-disk corruption, not a :class:`TypeError`.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _ledger_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _ledger_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _ledger_invalid("must be a JSON object")
    if set(data.keys()) != set(_LEDGER_TOP_KEYS):
        raise _ledger_invalid(
            "must contain exactly the keys 'audit', 'requests', 'state' "
            "and 'version'"
        )
    version = data["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _ledger_invalid("version must be an int")
    if version != LEDGER_VERSION:
        raise _ledger_invalid("version must be the integer 1")

    try:
        clock, records = merge._validated_state(data[STATE_KEY])
    except (TypeError, ValueError) as exc:
        raise _ledger_invalid(f"state is invalid: {exc}") from exc
    state = {merge.CLOCK: clock, merge.RECORDS: records}

    raw_requests = data[REQUESTS]
    if not isinstance(raw_requests, dict):
        raise _ledger_invalid("requests must be a JSON object")
    requests: dict[str, str] = {}
    for bound_id, bound_digest in raw_requests.items():
        if not isinstance(bound_id, str) or bound_id == "":
            raise _ledger_invalid("requests keys must be non-empty str")
        if not _is_digest(bound_digest):
            raise _ledger_invalid(
                "requests values must be 64 lowercase hex characters"
            )
        requests[bound_id] = bound_digest

    raw_entries = data[AUDIT]
    if not isinstance(raw_entries, list):
        raise _ledger_invalid("audit must be an array")
    entries: list[dict] = []
    seen_ids: set[str] = set()
    expected_seq = 1
    expected_before: str | None = None
    for position, entry in enumerate(raw_entries):
        if not isinstance(entry, dict):
            raise _ledger_invalid(f"audit entry {position} must be an object")
        entry_keys = set(entry.keys())
        if entry_keys != _LEDGER_ENTRY_KEY_SET and entry_keys != _LEDGER_ENTRY_AUTHED_SET:
            raise _ledger_invalid(
                f"audit entry {position} must contain exactly the keys "
                "'after', 'before', 'id', 'seq' and 'source' with "
                "optional 'auth'"
            )
        after_digest = entry[AFTER]
        before_digest = entry[BEFORE]
        entry_id = entry[ID]
        seq = entry["seq"]
        entry_source = entry[SOURCE]
        if not _is_digest(after_digest):
            raise _ledger_invalid(
                f"audit entry {position} after must be 64 lowercase hex characters"
            )
        if not _is_digest(before_digest):
            raise _ledger_invalid(
                f"audit entry {position} before must be 64 lowercase hex characters"
            )
        if not isinstance(entry_id, str) or entry_id == "":
            raise _ledger_invalid(f"audit entry {position} id must be a non-empty str")
        if not isinstance(entry_source, str) or entry_source == "":
            raise _ledger_invalid(
                f"audit entry {position} source must be a non-empty str"
            )
        parsed_auth = None
        if AUTH in entry:
            # Entries committed through apply_signed_remote carry the
            # credentials they were verified against; entries written by
            # plain apply_remote have none and stay readable.
            auth = entry[AUTH]
            if not isinstance(auth, dict) or set(auth.keys()) != _LEDGER_AUTH_KEYS:
                raise _ledger_invalid(
                    f"audit entry {position} auth must contain exactly the "
                    "keys 'keyVersion' and 'node'"
                )
            auth_node = auth[NODE]
            auth_version = auth[KEY_VERSION]
            if not isinstance(auth_node, str) or auth_node == "":
                raise _ledger_invalid(
                    f"audit entry {position} auth node must be a non-empty str"
                )
            if (
                isinstance(auth_version, bool)
                or not isinstance(auth_version, int)
                or auth_version <= 0
            ):
                raise _ledger_invalid(
                    f"audit entry {position} auth keyVersion must be a "
                    "positive int"
                )
            parsed_auth = {KEY_VERSION: auth_version, NODE: auth_node}
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _ledger_invalid(f"audit entry {position} seq must be an int")
        if seq != expected_seq:
            raise _ledger_invalid(
                f"audit entry {position} seq is {seq}, expected {expected_seq}"
            )
        if entry_id in seen_ids:
            raise _ledger_invalid(
                f"audit entry {position} repeats the already applied id {entry_id!r}"
            )
        if entry_id not in requests:
            raise _ledger_invalid(
                f"audit entry {position} id {entry_id!r} is missing from requests"
            )
        if expected_before is not None and before_digest != expected_before:
            raise _ledger_invalid(
                f"audit entry {position} before does not chain to the previous after"
            )
        parsed_entry = {
            AFTER: after_digest,
            BEFORE: before_digest,
            ID: entry_id,
            "seq": seq,
            SOURCE: entry_source,
        }
        if parsed_auth is not None:
            parsed_entry[AUTH] = parsed_auth
        entries.append(parsed_entry)
        seen_ids.add(entry_id)
        expected_seq += 1
        expected_before = after_digest

    if seen_ids != set(requests):
        raise _ledger_invalid("requests and audit must bind the same ids")
    if entries and entries[-1][AFTER] != _digest(_state_bytes(state)):
        raise _ledger_invalid("last audit after must hash the stored state")

    # The bytes must be the single canonical compact encoding with sorted
    # keys and exactly one trailing newline.
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise _ledger_invalid("must end with exactly one newline")
    if _serialize_ledger(state, requests, entries) != raw:
        raise _ledger_invalid("encoding is not the canonical compact form")
    return state, requests, entries


def _read_ledger(
    path: str, base: dict
) -> tuple[dict, dict[str, str], list[dict]]:
    """Load the ledger at ``path``; a missing file stands for ``base``."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        clock, records = merge._validated_state(base)
        return {merge.CLOCK: clock, merge.RECORDS: records}, {}, []
    return _parse_ledger(raw)


def _record_decision(
    local_clock: dict,
    local_record: list | None,
    remote_record: list,
) -> tuple[str, dict | None]:
    """Classify one remote record against the current local state."""
    need = merge._remote_need(remote_record, local_clock)
    if need:
        return STATUS_MISSING, need
    if local_record is None:
        return APPLY, None
    if local_record == remote_record:
        return STATUS_DUPLICATE, None
    if merge._dominates(remote_record[2], local_record[2]):
        return APPLY, None
    if merge._dominates(local_record[2], remote_record[2]):
        return STALE, None
    return CONFLICT, None


def _overall_status(decisions: list[str]) -> str:
    """Overall outcome with missing > conflict > stale > applied > duplicate.

    Any ``missing``/``conflict``/``stale`` item dominates; otherwise the
    request applies as soon as at least one item applies (the rest being
    apply or duplicate), and a batch with nothing to do is duplicate.
    """
    for status in (STATUS_MISSING, CONFLICT, STALE):
        if status in decisions:
            return status
    return STATUS_APPLIED if APPLY in decisions else STATUS_DUPLICATE


def _rollback_ledger_write(
    path: str,
    tmp_path: str | None,
    backup_path: str | None,
    existed: bool,
    stage: str,
) -> None:
    """Best-effort rollback of a failed :func:`_atomic_write`.

    ``stage`` records how far the transaction got: ``write`` (temporary
    file written), ``link`` (predecessor hard-linked aside), ``install``
    (temporary moved into place) or ``sync`` (the directory sync after
    install).  The predecessor is retained as a hard link rather than
    rewritten, so renaming it back restores the original file
    byte-for-byte (indeed as the same inode) even with no working fsync
    or free space left.  The directory is synced last so the recovery is
    durable.  Every recovery error is swallowed so the original
    exception propagates unchanged.
    """
    try:
        if stage == "sync":
            if existed:
                os.replace(backup_path, path)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        elif stage == "install":
            # The replacement did not run: the predecessor at path is
            # untouched; the backup link and temporary file are internal
            # artifacts to remove.
            if backup_path is not None:
                try:
                    os.unlink(backup_path)
                except FileNotFoundError:
                    pass
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except FileNotFoundError:
                    pass
        else:
            # write/link stages leave the predecessor in place; the link
            # stage additionally leaves a backup link to remove.
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except FileNotFoundError:
                    pass
            if stage == "link" and backup_path is not None:
                try:
                    os.unlink(backup_path)
                except FileNotFoundError:
                    pass
        try:
            storage._fsync_dir(path)
        except OSError:
            pass
    except OSError:
        pass


def _remove_quietly(target: str) -> None:
    """Best-effort unlink that never lets cleanup block the caller."""
    try:
        os.unlink(target)
    except OSError:
        pass


def _reserve_tmp_file(path: str) -> tuple[BinaryIO, str]:
    """Open a fresh, uniquely named transaction file next to ``path``.

    Exclusive binary create (``"xb"``) atomically reserves a random name
    and gives the file the same mode a plain create would; a collision
    simply retries.  The returned open binary handle owns the file until
    the caller closes it.
    """
    last_error: OSError | None = None
    for _ in range(128):
        tmp_path = f"{path}.tmp.{os.urandom(8).hex()}"
        try:
            return open(tmp_path, "xb"), tmp_path
        except FileExistsError as exc:
            last_error = exc
    raise last_error if last_error is not None else OSError(
        "could not reserve a ledger temporary file name"
    )


def _link_predecessor_aside(path: str) -> str:
    """Hard-link the existing ledger to a unique backup name.

    ``os.link`` is atomic and fails with :class:`FileExistsError` when the
    candidate name already exists (for example as a leftover of a killed
    transaction), so the name can be reserved by the link itself without
    any create-then-link window.
    """
    last_error: OSError | None = None
    for _ in range(128):
        backup_path = f"{path}.old.{os.urandom(8).hex()}"
        try:
            os.link(path, backup_path)
        except FileExistsError as exc:
            last_error = exc
            continue
        return backup_path
    # Practically unreachable: 128 random 64-bit name collisions in a row.
    raise last_error if last_error is not None else OSError(
        "could not reserve a ledger backup file name"
    )


def _atomic_write(path: str, payload: bytes) -> None:
    """Durably replace ``path`` with ``payload`` as a single transaction.

    Every transaction uses *unique* file names (an exclusively created
    ``path + ".tmp.<random>"`` temporary and a random-suffixed hard link
    for the predecessor), so a fixed ``path + ".tmp"``/``path + ".old"``
    leftover from an older interrupted process never collides with a
    fresh commit.  Such fixed leftovers are internal artifacts: they are
    never read as a ledger and are swept best-effort before the
    transaction starts -- a sweep failure cannot block the commit, which
    never depends on those names.

    The temporary file's write, flush and file sync, the replacement and
    the following directory sync all lie inside the boundary.  An existing
    predecessor is retained as a hard link -- without ever removing
    ``path`` -- until the new file is installed and the directory has
    synced, so any :class:`OSError` rolls back by renaming that link back:
    the prior file returns byte-for-byte (as the same inode, with no
    rewriting and therefore no dependence on a working fsync or free
    space), and a path the call created is removed again.  The rollback
    syncs the directory as well.  The original :class:`OSError` propagates
    unchanged.  On success both the file and the directory have been
    synced; the unique backup link's removal (and the matching directory
    sync) is best-effort and never undoes a commit.
    """
    existed = os.path.exists(path)
    # Retained fixed-name artifacts from earlier interrupted calls are
    # internal, never read as a ledger, and must never stand in the way of
    # a fresh transaction; the transaction itself uses unique names.
    _remove_quietly(path + ".tmp")
    _remove_quietly(path + ".old")

    tmp_handle, tmp_path = _reserve_tmp_file(path)
    backup_path: str | None = None
    stage = "write"
    try:
        with tmp_handle as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if existed:
            backup_path = _link_predecessor_aside(path)
            stage = "link"
        stage = "install"
        os.replace(tmp_path, path)
        stage = "sync"
        storage._fsync_dir(path)
    except BaseException:
        _rollback_ledger_write(path, tmp_path, backup_path, existed, stage)
        raise

    # The new ledger is durable from this point on; the retained
    # predecessor link is internal cleanup only.  Its removal (and the
    # matching directory sync) is best-effort and never undoes a commit.
    if existed and backup_path is not None:
        _remove_quietly(backup_path)
        try:
            storage._fsync_dir(path)
        except OSError:
            pass


def apply_remote(path: str, request: dict) -> dict:
    """Persistently apply one remote state request to the ledger at ``path``.

    ``request`` must contain exactly the keys ``id`` and ``source`` (both
    non-empty str) and ``base`` and ``remote`` (states obeying the
    :mod:`~offline_coordination.merge` contract).  ``path`` is a version-1
    ledger; when it is missing the current state is taken to be ``base``
    with empty request/audit indexes, otherwise the stored ``state``,
    ``requests`` and ``audit`` are fully validated before anything else.

    An unknown ``id`` whose current state differs from ``base`` returns
    ``stale`` without touching the filesystem.  A known ``id`` whose bound
    request digest matches replays as ``duplicate``: the verdict comes from
    the saved binding alone, so the result is the same immediately or after
    later successful commits.  Its items list every remote record in
    ascending key order, each already ``duplicate`` with ``need`` an empty
    mapping, ``receipt`` is ``None`` and the ledger bytes are unchanged.  A
    known ``id`` presented with different contents raises
    :class:`ValueError`.

    Otherwise the remote records are examined in ascending key order.  A
    record whose prerequisite (its clock with the ``writer`` component
    decremented by one) is not covered by the local outer clock is
    ``missing`` and its item's ``need`` lists the closed intervals still
    required per node.  With prerequisites satisfied, an equal record is
    ``duplicate``, a remote-dominating record ``apply``, a local-dominating
    record ``stale`` and a concurrent record ``conflict``.

    The overall status follows the precedence ``missing``, ``conflict``,
    ``stale``, ``duplicate``, ``applied``; only an outcome of at least one
    ``apply`` with every other item ``apply`` or ``duplicate`` commits:
    those records are updated, the outer clock is raised per node, one
    chained audit entry (id, source, before/after state digests, seq) is
    appended and the request digest is bound in ``requests``, via one
    atomic replacement.

    The result has the key order ``items``, ``receipt``, ``status``; items
    have ``key``, ``decision``, ``need`` (``need`` is ``None`` except for
    ``missing`` items, which map the still-required intervals, and
    replayed duplicates, which carry an empty mapping) and ``receipt`` is
    ``None`` unless committed.  Type violations raise :class:`TypeError`
    without creating any file; every other contract or ledger violation
    raises :class:`ValueError` and an invalid existing ledger is never
    written.  A failure while writing, flushing, syncing, replacing or
    syncing the directory propagates unchanged as :class:`OSError` and the
    file system is restored to its pre-call state: an existing ledger keeps
    its exact prior bytes, a missing ledger stays missing (with no
    recognizable file or temporary artifact left behind), and the rollback
    syncs the directory itself.
    """
    return _apply(path, request, None)


def _apply(path: str, request: dict, auth: dict | None) -> dict:
    """Shared body of :func:`apply_remote` and :func:`apply_signed_remote`.

    ``auth`` is ``None`` for an unsigned application; otherwise it holds
    the verified ``node``/``keyVersion`` pair to record on the committed
    audit entry.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")

    request_id, source, base, remote = _validated_apply_request(request)

    state, requests, entries = _read_ledger(path, base)

    if request_id in requests:
        if requests[request_id] != _request_digest(request_id, source, base, remote):
            raise ValueError(
                f"request id {request_id!r} is already bound to a different request"
            )
        # The saved request binding is the whole replay verdict: regardless
        # of how far the ledger state has advanced since the original
        # commit, every record the replayed request carries is reported
        # already duplicate, with no receipt and no filesystem change.
        items = [
            {KEY: key, DECISION: STATUS_DUPLICATE, NEED: {}}
            for key in sorted(remote[merge.RECORDS])
        ]
        return {ITEMS: items, RECEIPT: None, STATUS: STATUS_DUPLICATE}

    current_bytes = _state_bytes(state)
    if current_bytes != _state_bytes(base):
        # An unseen id must be offered against exactly the state it claims
        # as its base; per-record examination happens only past this gate.
        return {ITEMS: [], RECEIPT: None, STATUS: STALE}

    remote_records = remote[merge.RECORDS]
    items: list[dict] = []
    decisions: list[str] = []
    for key in sorted(remote_records):
        remote_record = remote_records[key]
        decision, need = _record_decision(
            state[merge.CLOCK], state[merge.RECORDS].get(key), remote_record
        )
        items.append({KEY: key, DECISION: decision, NEED: need})
        decisions.append(decision)

    status = _overall_status(decisions)
    if status != STATUS_APPLIED:
        return {ITEMS: items, RECEIPT: None, STATUS: status}

    before_digest = _digest(current_bytes)
    new_clock = dict(state[merge.CLOCK])
    new_records = {
        key: [value, deleted, dict(clock), writer]
        for key, (value, deleted, clock, writer) in state[merge.RECORDS].items()
    }
    for item in items:
        if item[DECISION] != APPLY:
            continue
        value, deleted, clock, writer = remote_records[item[KEY]]
        new_records[item[KEY]] = [value, deleted, dict(clock), writer]
        for node, count in clock.items():
            if count > new_clock.get(node, 0):
                new_clock[node] = count
    new_state = {merge.CLOCK: new_clock, merge.RECORDS: new_records}

    after_digest = _digest(_state_bytes(new_state))
    seq = len(entries) + 1
    new_entry = {
        AFTER: after_digest,
        BEFORE: before_digest,
        ID: request_id,
        "seq": seq,
        SOURCE: source,
    }
    if auth is not None:
        new_entry[AUTH] = {KEY_VERSION: auth[KEY_VERSION], NODE: auth[NODE]}
    new_entries = entries + [new_entry]
    new_requests = dict(requests)
    new_requests[request_id] = _request_digest(request_id, source, base, remote)

    _atomic_write(path, _serialize_ledger(new_state, new_requests, new_entries))

    return {
        ITEMS: items,
        RECEIPT: {
            ID: request_id,
            SOURCE: source,
            BEFORE: before_digest,
            AFTER: after_digest,
            "seq": seq,
        },
        STATUS: STATUS_APPLIED,
    }


# --- Authenticated remote-state application (signed envelopes) --------------

REQUEST = "request"
REVOKED = "revoked"
SECRET = "secret"
SIGNATURE = "signature"
NOT_BEFORE = "notBefore"
NOT_AFTER = "notAfter"

_ENVELOPE_KEYS = frozenset((NODE, KEY_VERSION, REQUEST, SIGNATURE))
_KEYRING_ENTRY_KEYS = frozenset((VERSION, SECRET, NOT_BEFORE, NOT_AFTER, REVOKED))


class AuthenticationError(ValueError):
    """A signed replication envelope failed authentication."""


def _validated_keyring(keyring: object) -> dict[str, list[dict]]:
    """Validate a keyring into a fresh ``{node: [entry]}`` mapping.

    Type faults raise :class:`TypeError`; key sets, ranges, duplicate
    versions, secret formats and validity periods raise
    :class:`ValueError`.
    """
    if not isinstance(keyring, dict):
        raise TypeError("keyring must be a dict")
    result: dict[str, list[dict]] = {}
    for node, entries in keyring.items():
        if not isinstance(node, str):
            raise TypeError("keyring node names must be str")
        if node == "":
            raise ValueError("keyring node names must be non-empty")
        if not isinstance(entries, list):
            raise TypeError(f"keyring entries for node {node!r} must be a list")
        validated: list[dict] = []
        seen_versions: set[int] = set()
        for position, entry in enumerate(entries):
            where = f"keyring entry {position} for node {node!r}"
            if not isinstance(entry, dict):
                raise TypeError(f"{where} must be a dict")
            if set(entry.keys()) != _KEYRING_ENTRY_KEYS:
                raise ValueError(
                    f"{where} must contain exactly the keys 'version', "
                    "'secret', 'notBefore', 'notAfter' and 'revoked'"
                )
            version = entry[VERSION]
            if isinstance(version, bool) or not isinstance(version, int):
                raise TypeError(f"{where} version must be an int")
            if version <= 0:
                raise ValueError(f"{where} version must be positive")
            if version in seen_versions:
                raise ValueError(
                    f"{where} repeats key version {version} for node {node!r}"
                )
            seen_versions.add(version)
            secret = entry[SECRET]
            if not isinstance(secret, str):
                raise TypeError(f"{where} secret must be a str")
            if _HEX64.fullmatch(secret) is None:
                raise ValueError(
                    f"{where} secret must be 64 lowercase hex characters"
                )
            bounds: dict[str, int] = {}
            for bound_key in (NOT_BEFORE, NOT_AFTER):
                bound = entry[bound_key]
                if isinstance(bound, bool) or not isinstance(bound, int):
                    raise TypeError(f"{where} {bound_key} must be an int")
                if bound < 0:
                    raise ValueError(f"{where} {bound_key} must be non-negative")
                bounds[bound_key] = bound
            if bounds[NOT_BEFORE] > bounds[NOT_AFTER]:
                raise ValueError(
                    f"{where} notBefore must not exceed notAfter"
                )
            revoked = entry[REVOKED]
            if not isinstance(revoked, bool):
                raise TypeError(f"{where} revoked must be a bool")
            validated.append(
                {
                    VERSION: version,
                    SECRET: secret,
                    NOT_BEFORE: bounds[NOT_BEFORE],
                    NOT_AFTER: bounds[NOT_AFTER],
                    REVOKED: revoked,
                }
            )
        result[node] = validated
    return result


def _validated_envelope(envelope: object) -> tuple[str, int, object, str]:
    """Validate an envelope into (node, key_version, request, signature)."""
    if not isinstance(envelope, dict):
        raise TypeError("envelope must be a dict")
    if set(envelope.keys()) != _ENVELOPE_KEYS:
        raise ValueError(
            "envelope must contain exactly the keys 'node', 'keyVersion', "
            "'request' and 'signature'"
        )
    node = envelope[NODE]
    if not isinstance(node, str):
        raise TypeError("envelope node must be a str")
    if node == "":
        raise ValueError("envelope node must be non-empty")
    key_version = envelope[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("envelope keyVersion must be an int")
    if key_version <= 0:
        raise ValueError("envelope keyVersion must be positive")
    signature = envelope[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("envelope signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise ValueError(
            "envelope signature must be 64 lowercase hex characters"
        )
    return node, key_version, envelope[REQUEST], signature


def _signed_payload(node: str, key_version: int, request: object) -> bytes:
    """The signed bytes: canonical compact JSON of node/keyVersion/request."""
    ordered = {KEY_VERSION: key_version, NODE: node, REQUEST: request}
    return json.dumps(
        ordered, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _authenticate(
    keyring: dict[str, list[dict]],
    node: str,
    key_version: int,
    request: object,
    source: str,
    signature: str,
    moment: int,
) -> None:
    """Verify the envelope against the current keyring.

    The key is selected by exact node and version with no fallback and
    must be usable *now*: unknown credentials, a revoked, not-yet-valid or
    expired key, a request source other than the envelope node and a
    signature mismatch all raise :class:`AuthenticationError`.
    """
    entry = None
    for candidate in keyring.get(node, ()):
        if candidate[VERSION] == key_version:
            entry = candidate
            break
    if entry is None:
        raise AuthenticationError(
            f"no credentials for node {node!r} and key version {key_version}"
        )
    if entry[REVOKED]:
        raise AuthenticationError(
            f"credentials for node {node!r} key version {key_version} "
            "are revoked"
        )
    if moment < entry[NOT_BEFORE]:
        raise AuthenticationError(
            f"credentials for node {node!r} key version {key_version} "
            "are not yet valid"
        )
    if moment > entry[NOT_AFTER]:
        raise AuthenticationError(
            f"credentials for node {node!r} key version {key_version} "
            "have expired"
        )
    if source != node:
        raise AuthenticationError(
            f"request source {source!r} does not match envelope node {node!r}"
        )
    expected = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _signed_payload(node, key_version, request),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise AuthenticationError("signature does not match the envelope")


def apply_signed_remote(
    path: str, keyring: dict, envelope: dict, moment: int
) -> dict:
    """Verify a signed envelope, then apply it like :func:`apply_remote`.

    ``keyring`` maps node names to credential entries (see the module
    docstring), ``envelope`` carries exactly ``node``, ``keyVersion``,
    ``request`` and ``signature``, and ``moment`` is the current time as a
    non-negative integer.  The request inside the envelope follows the
    :func:`apply_remote` contract and its ``source`` must equal the
    envelope's ``node``.

    Authentication runs before the ledger is ever read, so a failed
    verification raises :class:`AuthenticationError` (a
    :class:`ValueError`) without creating or modifying any file; replays
    are authenticated against the current keyring, so a key revoked or
    expired since the original commit rejects the replay instead of
    serving the historical binding.  A verified envelope is applied by the
    exact :func:`apply_remote` flow with the same result shape; a commit
    additionally records the verified ``node`` and ``keyVersion`` under
    ``auth`` in the new audit entry.

    Type violations in any argument or field raise :class:`TypeError`;
    key sets, ranges, duplicate key versions, secret/signature formats
    and validity periods raise :class:`ValueError`.  Ledger corruption
    raises :class:`ValueError`, and a write, flush, sync or replacement
    failure propagates unchanged as :class:`OSError` with the file system
    restored to its pre-call state.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    validated_keyring = _validated_keyring(keyring)
    node, key_version, request, signature = _validated_envelope(envelope)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    _, source, _, _ = _validated_apply_request(request)
    _authenticate(
        validated_keyring, node, key_version, request, source, signature, moment
    )
    return _apply(path, request, {KEY_VERSION: key_version, NODE: node})


# --- Offline audit-range proofs ----------------------------------------------

PROOF_DIGEST = "digest"
PROOF_END_SEQ = "endSeq"
PROOF_ENTRIES = "entries"
PROOF_FIRST_BEFORE = "firstBefore"
PROOF_LAST_AFTER = "lastAfter"
PROOF_START_SEQ = "startSeq"

PROOF_VERSION = 1
_PROOF_TOP_KEYS = frozenset((
    PROOF_DIGEST,
    PROOF_END_SEQ,
    PROOF_ENTRIES,
    PROOF_FIRST_BEFORE,
    PROOF_LAST_AFTER,
    PROOF_START_SEQ,
    VERSION,
))
_PROOF_RESULT_KEYS = (
    PROOF_START_SEQ,
    PROOF_END_SEQ,
    PROOF_FIRST_BEFORE,
    PROOF_LAST_AFTER,
    "signedEntries",
    "unsignedEntries",
)


class InvalidProofError(ValueError):
    """An audit proof fails its offline byte, chain or digest contract."""


def _proof_invalid(message: str) -> InvalidProofError:
    return InvalidProofError(f"invalid audit proof: {message}")


def _proof_compact(obj: object) -> bytes:
    """Canonical compact sorted-key UTF-8 JSON of proof content."""
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate object keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _proof_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def export_proof(path: str, start_seq: int, end_seq: int | None = None) -> bytes:
    """Export a self-certifying audit-range proof from the ledger at ``path``.

    The proof covers the ledger's audit entries with ``startSeq <= seq <=
    endSeq``.  ``start_seq`` must be at least 1; when ``end_seq`` is
    omitted the range runs through the ledger's last entry.  The range
    must lie completely inside the existing, non-empty audit sequence.

    The result is canonical version-1 proof bytes: one compact UTF-8 JSON
    object with every object key recursively sorted lexicographically,
    non-ASCII preserved unescaped and exactly one trailing ``\\n``.  It
    declares ``version`` (the integer 1), the range, ``firstBefore`` (the
    before-digest of the first entry) and ``lastAfter`` (the after-digest
    of the last one), carries the unchanged ledger entries, and binds the
    whole content with ``digest``, the lowercase hex SHA-256 of the
    canonical encoding of the proof with its ``digest`` key removed.

    The ledger is opened read-only and never modified.  Type violations
    (including a :class:`bool` posing as an int or as ``path``) raise
    :class:`TypeError`; an inverted or out-of-range request, an empty
    audit and a corrupt ledger raise :class:`ValueError`; a missing
    ledger raises :class:`FileNotFoundError` and every other read failure
    propagates unchanged as :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if isinstance(start_seq, bool) or not isinstance(start_seq, int):
        raise TypeError("start_seq must be an int")
    if end_seq is not None and (
        isinstance(end_seq, bool) or not isinstance(end_seq, int)
    ):
        raise TypeError("end_seq must be an int or None")
    if start_seq < 1:
        raise ValueError("start_seq must be >= 1")
    if end_seq is not None and end_seq < start_seq:
        raise ValueError("end_seq must not be less than start_seq")

    with open(path, "rb") as handle:
        raw = handle.read()
    # A missing file propagates as FileNotFoundError; a corrupt ledger as
    # ValueError; any other read failure already propagated as OSError.
    _state, _requests, entries = _parse_ledger(raw)

    total = len(entries)
    if total == 0:
        raise ValueError("cannot export a proof from an empty audit")
    if start_seq > total:
        raise ValueError("start_seq must not exceed the last audit seq")
    if end_seq is None:
        end_seq = total
    elif end_seq > total:
        raise ValueError("end_seq must not exceed the last audit seq")

    selected = entries[start_seq - 1:end_seq]
    body = {
        PROOF_END_SEQ: end_seq,
        PROOF_ENTRIES: [_serialize_entry(entry) for entry in selected],
        PROOF_FIRST_BEFORE: selected[0][BEFORE],
        PROOF_LAST_AFTER: selected[-1][AFTER],
        PROOF_START_SEQ: start_seq,
        VERSION: PROOF_VERSION,
    }
    digest = hashlib.sha256(_proof_compact(body)).hexdigest()
    proof = dict(body)
    proof[PROOF_DIGEST] = digest
    return _proof_compact(proof) + b"\n"


def _parse_proof(raw: bytes) -> dict:
    """Validate every byte and link of a proof and return its decoded form."""
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise _proof_invalid("must be a single JSON object ending in one LF")
    try:
        text = raw[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _proof_invalid("is not valid UTF-8") from exc
    try:
        # The pairs hook raises directly on duplicate object keys, so a
        # ValueError raised here means that contract fault, not bad JSON.
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise _proof_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _proof_invalid("must be a JSON object")
    if set(data.keys()) != _PROOF_TOP_KEYS:
        raise _proof_invalid(
            "top-level object must contain exactly the keys 'digest', "
            "'endSeq', 'entries', 'firstBefore', 'lastAfter', 'startSeq' "
            "and 'version'"
        )
    version = data[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _proof_invalid("version must be an int")
    if version != PROOF_VERSION:
        raise _proof_invalid("version must be the integer 1")

    start = data[PROOF_START_SEQ]
    end = data[PROOF_END_SEQ]
    if isinstance(start, bool) or not isinstance(start, int):
        raise _proof_invalid("startSeq must be an int")
    if isinstance(end, bool) or not isinstance(end, int):
        raise _proof_invalid("endSeq must be an int")
    if start < 1:
        raise _proof_invalid("startSeq must be >= 1")
    if end < start:
        raise _proof_invalid("endSeq must not be less than startSeq")

    first_before = data[PROOF_FIRST_BEFORE]
    last_after = data[PROOF_LAST_AFTER]
    if not _is_digest(first_before):
        raise _proof_invalid("firstBefore must be 64 lowercase hex characters")
    if not _is_digest(last_after):
        raise _proof_invalid("lastAfter must be 64 lowercase hex characters")

    raw_entries = data[PROOF_ENTRIES]
    if not isinstance(raw_entries, list):
        raise _proof_invalid("entries must be an array")
    expected_count = end - start + 1
    if len(raw_entries) != expected_count:
        raise _proof_invalid(
            f"entries must contain exactly the {expected_count} items of the "
            "declared range"
        )

    signed = 0
    previous_after: str | None = None
    for position, entry in enumerate(raw_entries):
        where = f"entry {position}"
        if not isinstance(entry, dict):
            raise _proof_invalid(f"{where} must be a JSON object")
        keys = set(entry.keys())
        if keys != _LEDGER_ENTRY_KEY_SET and keys != _LEDGER_ENTRY_AUTHED_SET:
            raise _proof_invalid(
                f"{where} must contain exactly the keys 'after', 'before', "
                "'id', 'seq' and 'source' with optional 'auth'"
            )
        before = entry[BEFORE]
        after = entry[AFTER]
        entry_id = entry[ID]
        source = entry[SOURCE]
        seq = entry["seq"]
        if not _is_digest(before):
            raise _proof_invalid(f"{where} before must be 64 lowercase hex chars")
        if not _is_digest(after):
            raise _proof_invalid(f"{where} after must be 64 lowercase hex chars")
        if not isinstance(entry_id, str) or entry_id == "":
            raise _proof_invalid(f"{where} id must be a non-empty str")
        if not isinstance(source, str) or source == "":
            raise _proof_invalid(f"{where} source must be a non-empty str")
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _proof_invalid(f"{where} seq must be an int")
        expected_seq = start + position
        if seq != expected_seq:
            raise _proof_invalid(
                f"{where} seq is {seq}, expected {expected_seq}"
            )
        expected_before = first_before if position == 0 else previous_after
        if before != expected_before:
            raise _proof_invalid(
                f"{where} before does not chain to the previous after"
            )
        if AUTH in entry:
            auth = entry[AUTH]
            if not isinstance(auth, dict) or set(auth.keys()) != _LEDGER_AUTH_KEYS:
                raise _proof_invalid(
                    f"{where} auth must contain exactly the keys "
                    "'keyVersion' and 'node'"
                )
            node = auth[NODE]
            key_version = auth[KEY_VERSION]
            if not isinstance(node, str) or node == "":
                raise _proof_invalid(f"{where} auth node must be a non-empty str")
            if (
                isinstance(key_version, bool)
                or not isinstance(key_version, int)
                or key_version <= 0
            ):
                raise _proof_invalid(
                    f"{where} auth keyVersion must be a positive non-bool int"
                )
            signed += 1
        previous_after = after

    if previous_after != last_after:
        raise _proof_invalid("lastAfter must equal the last entry's after")

    claimed = data[PROOF_DIGEST]
    if not _is_digest(claimed):
        raise _proof_invalid("digest must be 64 lowercase hex characters")
    unsigned = expected_count - signed
    body = {key: value for key, value in data.items() if key != PROOF_DIGEST}
    actual = hashlib.sha256(_proof_compact(body)).hexdigest()
    if not hmac.compare_digest(actual, claimed):
        raise _proof_invalid("digest does not match the proof contents")

    # The bytes must be the single canonical compact form with sorted keys
    # and exactly one trailing newline: no whitespace, no non-canonical
    # escapes, no permuted keys, no escaped non-ASCII.
    if _proof_compact(data) + b"\n" != raw:
        raise _proof_invalid("encoding is not the canonical compact form")

    return {
        PROOF_START_SEQ: start,
        PROOF_END_SEQ: end,
        PROOF_FIRST_BEFORE: first_before,
        PROOF_LAST_AFTER: last_after,
        "signedEntries": signed,
        "unsignedEntries": unsigned,
    }


def verify_proof(proof: bytes) -> dict:
    """Verify an audit proof without consulting the ledger or any keyring.

    ``proof`` must be :class:`bytes` produced by :func:`export_proof`.
    Verification checks the canonical encoding, the unique key set, the
    integer version 1, the overall digest, the contiguous unique entry
    sequence and the before/after state-digest chain, and matches the
    declared range boundaries.

    On success a fresh dict is returned with the key order ``startSeq``,
    ``endSeq``, ``firstBefore``, ``lastAfter``, ``signedEntries`` and
    ``unsignedEntries``: the covered range, its boundary state digests and
    the counts of entries with and without an ``auth`` binding.  Any
    encoding, key-set, version, digest, gap, duplicate, reordering, chain,
    tamper or auth-binding fault raises :class:`InvalidProofError` (a
    :class:`ValueError`); a non-bytes argument raises :class:`TypeError`.
    """
    if not isinstance(proof, bytes):
        raise TypeError("proof must be bytes")
    result = _parse_proof(proof)
    return {key: result[key] for key in _PROOF_RESULT_KEYS}
