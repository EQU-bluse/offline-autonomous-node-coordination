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

:func:`apply_signed_remote` adds an offline-verifiable, replication-safe
front door to the same application flow.  It takes the ledger ``path``,
the same ``request`` object :func:`apply_remote` consumes (its ``source``
must equal the envelope's ``node``), a *keyring*, an *envelope* and the
current ``instant``.  The keyring maps non-empty node names to lists of
key entries, each carrying exactly ``version`` (a unique positive
non-bool int), ``secret`` (64 lowercase hex characters decoding to the
32-byte HMAC key), ``notBefore``/``notAfter`` (non-negative non-bool
ints, ``notBefore <= notAfter``; both bounds are inclusive and valid)
and ``revoked`` (a bool).  The envelope carries exactly ``request``,
``node``, ``keyVersion`` and ``signature``.

The signed text contains only ``node``, ``keyVersion`` and ``request``;
every object key is recursively encoded in lexicographic order as
compact UTF-8 JSON with non-ASCII preserved unescaped and no newline.
HMAC-SHA256 is computed with the 32-byte key decoded from the entry's
``secret`` and compared against ``signature`` (64 lowercase hex
characters) in constant time.  The key is selected exactly by the
envelope's node and version -- there is no fallback.  An unknown
credential, a key not yet valid, an expired key, a revoked key, a
``request`` whose ``source`` is not ``node`` or a signature mismatch
raises :class:`AuthenticationError` (a :class:`ValueError`).  The
current credential is always verified, including on a replay: a later
revocation or expiry can never be bypassed with the historical binding.
Verification finishes before the ledger is read, and a failed
verification creates no file.

Only the ``applied`` outcome gains a side effect: new audit entries
carry an ``auth`` record naming the verified ``node`` and
``keyVersion``.  Audit entries written by :func:`apply_remote` -- and
older ledgers -- have no ``auth`` record and stay readable, and
:func:`apply_remote`'s visible behaviour and existing ledgers remain
compatible.  Type faults in parameters or fields raise
:class:`TypeError`; bad key sets, ranges, duplicate versions, formats
or time windows raise :class:`ValueError`; a corrupt ledger raises
:class:`ValueError`; write, sync or replacement failures propagate
unchanged as :class:`OSError` with atomicity preserved.  Leftover
temporary artifacts never participate in reads and their cleanup never
blocks a valid request.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re

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
BASE = "base"
BEFORE = "before"
ID = "id"
REMOTE = "remote"
REQUESTS = "requests"
SOURCE = "source"
STATE_KEY = "state"

LEDGER_VERSION = 1
_LEDGER_TOP_KEYS = (AUDIT, REQUESTS, STATE_KEY, "version")
_AUTH = "auth"
_VERSION = "version"
_KEY_VERSION = "keyVersion"
_NODE = "node"
_SIGNATURE = "signature"
_SECRET = "secret"
_NOT_BEFORE = "notBefore"
_NOT_AFTER = "notAfter"
_REVOKED = "revoked"
# Canonical audit-entry key order; ``auth`` is omitted entirely for
# entries produced by apply_remote and for older ledgers.
_LEDGER_ENTRY_KEY_ORDER = (AFTER, _AUTH, BEFORE, ID, "seq", SOURCE)
_LEDGER_ENTRY_KEY_SET = frozenset(_LEDGER_ENTRY_KEY_ORDER)
_LEDGER_LEGACY_ENTRY_KEY_SET = _LEDGER_ENTRY_KEY_SET - {_AUTH}
_AUTH_KEY_ORDER = (_KEY_VERSION, _NODE)
_REQUEST_KEYS = (ID, SOURCE, BASE, REMOTE)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


def _ledger_invalid(message: str) -> ValueError:
    return ValueError(f"invalid replication ledger: {message}")


class AuthenticationError(ValueError):
    """A signed request could not be authenticated.

    Raised for an unknown credential, a key outside its validity window,
    a revoked key, a node/request identity mismatch or a bad signature.
    It is a :class:`ValueError`, so callers that already reject
    :class:`ValueError` keep working.
    """


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


def _serialize_ledger(
    state: dict, requests: dict[str, str], entries: list[dict]
) -> bytes:
    """Canonical ledger bytes: compact JSON, sorted keys, one trailing LF.

    Entries carrying an ``auth`` record include it; entries without one
    (those produced by :func:`apply_remote`) keep the legacy shape.
    """
    ledger = {
        AUDIT: [
            {key: entry[key] for key in _LEDGER_ENTRY_KEY_ORDER if key in entry}
            for entry in entries
        ],
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
        if entry_keys not in (
            _LEDGER_ENTRY_KEY_SET,
            _LEDGER_LEGACY_ENTRY_KEY_SET,
        ):
            raise _ledger_invalid(
                f"audit entry {position} must contain exactly the keys "
                "'after', 'before', 'id', 'seq' and 'source', optionally "
                "with 'auth'"
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
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _ledger_invalid(f"audit entry {position} seq must be an int")
        if seq != expected_seq:
            raise _ledger_invalid(
                f"audit entry {position} seq is {seq}, expected {expected_seq}"
            )
        # An optional auth record binds the entry to the verified signer:
        # exactly a non-empty node and a positive non-bool key version.
        auth_record = None
        if _AUTH in entry:
            raw_auth = entry[_AUTH]
            if not isinstance(raw_auth, dict) or set(raw_auth.keys()) != set(
                _AUTH_KEY_ORDER
            ):
                raise _ledger_invalid(
                    f"audit entry {position} auth must contain exactly the "
                    "keys 'keyVersion' and 'node'"
                )
            auth_node = raw_auth[_NODE]
            auth_version = raw_auth[_KEY_VERSION]
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
            auth_record = {
                _KEY_VERSION: auth_version,
                _NODE: auth_node,
            }
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
        if auth_record is not None:
            parsed_entry[_AUTH] = auth_record
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
    tmp_path: str,
    backup_path: str,
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
            try:
                os.unlink(backup_path)
            except FileNotFoundError:
                pass
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
        else:
            # write/link stages leave the predecessor in place.
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            if stage == "link":
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


def _atomic_write(path: str, payload: bytes) -> None:
    """Durably replace ``path`` with ``payload`` as a single transaction.

    The temporary file's write, flush and file sync, the replacement and
    the following directory sync all lie inside the boundary.  An existing
    predecessor is retained as a hard link at ``path + ".old"`` -- without
    ever removing ``path`` -- until the new file is installed and the
    directory has synced, so any :class:`OSError` rolls back by renaming
    that link back: the prior file returns byte-for-byte (as the same
    inode, with no rewriting and therefore no dependence on a working
    fsync or free space), and a path the call created is removed again.
    The rollback syncs the directory as well.  The original
    :class:`OSError` propagates unchanged, no ``.tmp``/``.old`` artifact is
    left behind and such artifacts (for example from a killed process) are
    never read as a ledger.  On success both the file and the directory
    have been synced.
    """
    tmp_path = path + ".tmp"
    backup_path = path + ".old"
    existed = os.path.exists(path)
    # Retained artifacts from earlier interrupted calls are internal and
    # must never stand in the way of a fresh transaction (the temporary
    # name is overwritten by the open below).
    try:
        os.unlink(backup_path)
    except FileNotFoundError:
        pass

    stage = "write"
    try:
        with open(tmp_path, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if existed:
            stage = "link"
            os.link(path, backup_path)
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
    if existed:
        try:
            os.unlink(backup_path)
            storage._fsync_dir(path)
        except OSError:
            pass


def _apply_remote_flow(path: str, request: dict, auth: dict | None) -> dict:
    """The application flow shared by :func:`apply_remote` and its signed
    counterpart.

    ``path`` has already been type-checked and ``request`` validated;
    ``auth`` is either ``None`` (the unsigned entry point, whose entries
    carry no ``auth`` record) or ``{"keyVersion": ..., "node": ...}``
    naming the credential the signature was verified against.
    """
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
        for node_name, count in clock.items():
            if count > new_clock.get(node_name, 0):
                new_clock[node_name] = count
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
        new_entry[_AUTH] = auth
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
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    return _apply_remote_flow(path, request, None)


# --- Offline-verifiable signed entry point ---------------------------------

_ENVELOPE_KEYS = ("request", _NODE, _KEY_VERSION, _SIGNATURE)
_KEY_ENTRY_KEYS = (
    _VERSION,
    _SECRET,
    _NOT_BEFORE,
    _NOT_AFTER,
    _REVOKED,
)


def _is_plain_int(value: object) -> bool:
    """True for genuine ints only (a bool is rejected)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _validated_keyring(keyring: object) -> dict[str, list[dict]]:
    """Validate a keyring into a fresh ``{node: [entry, ...]}`` mapping.

    Each node name is a non-empty str.  Each entry contains exactly
    ``version`` (a unique positive non-bool int), ``secret`` (64 lowercase
    hex characters), ``notBefore``/``notAfter`` (non-negative non-bool
    ints with ``notBefore <= notAfter``) and ``revoked`` (a bool).  Type
    faults raise :class:`TypeError`; bad key sets, ranges, duplicate
    versions, formats or time windows raise :class:`ValueError`.
    """
    if not isinstance(keyring, dict):
        raise TypeError("keyring must be a dict")
    result: dict[str, list[dict]] = {}
    for node_name, entries in keyring.items():
        if not isinstance(node_name, str):
            raise TypeError("keyring node name must be a str")
        if node_name == "":
            raise ValueError("keyring node name must be non-empty")
        if not isinstance(entries, list):
            raise TypeError(f"keyring entries for {node_name!r} must be a list")
        parsed_entries: list[dict] = []
        seen_versions: set[int] = set()
        for position, entry in enumerate(entries):
            where = f"keyring entry {position} for node {node_name!r}"
            if not isinstance(entry, dict):
                raise TypeError(f"{where} must be a dict")
            if set(entry.keys()) != set(_KEY_ENTRY_KEYS):
                raise ValueError(
                    f"{where} must contain exactly the keys 'version', "
                    "'secret', 'notBefore', 'notAfter' and 'revoked'"
                )
            version = entry[_VERSION]
            secret = entry[_SECRET]
            not_before = entry[_NOT_BEFORE]
            not_after = entry[_NOT_AFTER]
            revoked = entry[_REVOKED]
            if not _is_plain_int(version):
                raise TypeError(f"{where} version must be an int")
            if version <= 0:
                raise ValueError(f"{where} version must be a positive int")
            if version in seen_versions:
                raise ValueError(
                    f"{where} repeats the already used version {version}"
                )
            if not isinstance(secret, str):
                raise TypeError(f"{where} secret must be a str")
            if _HEX64.fullmatch(secret) is None:
                raise ValueError(
                    f"{where} secret must be 64 lowercase hex characters"
                )
            if not _is_plain_int(not_before):
                raise TypeError(f"{where} notBefore must be an int")
            if not _is_plain_int(not_after):
                raise TypeError(f"{where} notAfter must be an int")
            if not_before < 0 or not_after < 0:
                raise ValueError(f"{where} validity bounds must be non-negative")
            if not_before > not_after:
                raise ValueError(f"{where} notBefore must not exceed notAfter")
            if not isinstance(revoked, bool):
                raise TypeError(f"{where} revoked must be a bool")
            seen_versions.add(version)
            parsed_entries.append(
                {
                    _VERSION: version,
                    _SECRET: secret,
                    _NOT_BEFORE: not_before,
                    _NOT_AFTER: not_after,
                    _REVOKED: revoked,
                }
            )
        result[node_name] = parsed_entries
    return result


def _validated_envelope(envelope: object) -> tuple[dict, str, int, str]:
    """Validate an envelope's shape into ``(request, node, version, sig)``.

    The embedded ``request`` must be a dict obeying the apply_remote
    request contract (its full contents are checked by the shared flow
    only *after* the signature over its exact bytes has been verified);
    only its dict-ness is enforced here, since the signed identity is
    read from it.  The signed text is later built from this same object,
    never a copy.
    """
    if not isinstance(envelope, dict):
        raise TypeError("envelope must be a dict")
    if set(envelope.keys()) != set(_ENVELOPE_KEYS):
        raise ValueError(
            "envelope must contain exactly the keys 'request', 'node', "
            "'keyVersion' and 'signature'"
        )
    request = envelope["request"]
    node = envelope[_NODE]
    key_version = envelope[_KEY_VERSION]
    signature = envelope[_SIGNATURE]
    if not isinstance(request, dict):
        raise TypeError("envelope request must be a dict")
    if not isinstance(node, str):
        raise TypeError("envelope node must be a str")
    if node == "":
        raise ValueError("envelope node must be non-empty")
    if not _is_plain_int(key_version):
        raise TypeError("envelope keyVersion must be an int")
    if key_version <= 0:
        raise ValueError("envelope keyVersion must be a positive int")
    if not isinstance(signature, str):
        raise TypeError("envelope signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise ValueError(
            "envelope signature must be 64 lowercase hex characters"
        )
    return request, node, key_version, signature


def _canonical_signed_text(node: str, key_version: int, request: object) -> bytes:
    """The signed bytes: only node, keyVersion and request, all object keys
    recursively sorted lexicographically, non-ASCII unescaped, no newline.
    """
    payload = {
        _KEY_VERSION: key_version,
        _NODE: node,
        "request": request,
    }
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _select_credential(
    keyring: dict[str, list[dict]], node: str, key_version: int
) -> dict:
    """Return the exact (node, version) entry or raise AuthenticationError.

    Selection is exact: there is no fallback to another version, node or
    any default credential.
    """
    entries = keyring.get(node)
    if entries is None:
        raise AuthenticationError(f"unknown node {node!r}")
    for entry in entries:
        if entry[_VERSION] == key_version:
            return entry
    raise AuthenticationError(
        f"unknown key version {key_version} for node {node!r}"
    )


def _verify_signature(
    request: dict,
    node: str,
    key_version: int,
    signature: str,
    keyring: dict[str, list[dict]],
    instant: int,
) -> None:
    """Verify a signed request against the *current* credential.

    Raises :class:`AuthenticationError` for an unknown credential, a key
    not yet valid, an expired key, a revoked key, a request whose source
    is not the node, or a signature mismatch.  Runs entirely before the
    request contract is applied and before the ledger is read, so a
    failure has no filesystem effect.  The HMAC is always computed and
    compared in constant time alongside the identity check.
    """
    entry = _select_credential(keyring, node, key_version)
    if instant < entry[_NOT_BEFORE]:
        raise AuthenticationError(
            f"key version {key_version} for node {node!r} is not yet valid"
        )
    if instant > entry[_NOT_AFTER]:
        raise AuthenticationError(
            f"key version {key_version} for node {node!r} has expired"
        )
    if entry[_REVOKED]:
        raise AuthenticationError(
            f"key version {key_version} for node {node!r} is revoked"
        )
    signed = _canonical_signed_text(node, key_version, request)
    key = bytes.fromhex(entry[_SECRET])
    expected = hmac.new(key, signed, hashlib.sha256).hexdigest()
    signature_ok = hmac.compare_digest(expected, signature)
    identity_ok = request.get(SOURCE) == node
    if not identity_ok:
        raise AuthenticationError(
            "request source must equal the envelope node"
        )
    if not signature_ok:
        raise AuthenticationError("signature does not match")


def apply_signed_remote(
    path: str, keyring: dict, envelope: dict, instant: int
) -> dict:
    """Verify a signed request, then run the same flow as :func:`apply_remote`.

    The four arguments are the ledger ``path``, the ``keyring``, the
    ``envelope`` and the current ``instant``.  The envelope carries the
    :func:`apply_remote` ``request`` (its ``source`` must equal the
    envelope's ``node``) plus ``node``, ``keyVersion`` and ``signature``;
    the keyring maps node names to key entries (see the module docstring
    for their fields).  ``instant`` is always re-checked against the
    *current* keyring: the selected key must be known, within its
    inclusive ``[notBefore, notAfter]`` window and not revoked.  The
    HMAC-SHA256 over the canonical ``node``/``keyVersion``/``request``
    text is compared in constant time.

    Every replay is re-authenticated against the current keyring: a key
    that was later revoked or allowed to expire can never be reused
    merely because the request id is already bound.  Authentication
    finishes before the request contract is applied and before the
    ledger is read; a failure raises :class:`AuthenticationError` (a
    :class:`ValueError`) without creating any file.  On success the
    existing application flow runs unchanged; when the outcome is
    ``applied`` the new audit entry carries an ``auth`` record
    ``{"keyVersion": ..., "node": ...}`` naming the verified credential.

    Type faults in the parameters or their fields raise
    :class:`TypeError`; bad key sets, ranges, duplicate versions,
    formats, time windows or a corrupt ledger raise :class:`ValueError`;
    write, sync or replacement failures propagate unchanged as
    :class:`OSError` with the commit's atomicity preserved.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if isinstance(instant, bool) or not isinstance(instant, int):
        raise TypeError("instant must be an int")
    if instant < 0:
        raise ValueError("instant must be non-negative")

    validated_keyring = _validated_keyring(keyring)
    request, node, key_version, signature = _validated_envelope(envelope)

    # The signature is verified over the envelope's exact request object
    # before the request contract is applied and before any ledger read;
    # a failure here leaves the filesystem untouched.
    _verify_signature(
        request,
        node,
        key_version,
        signature,
        validated_keyring,
        instant,
    )

    return _apply_remote_flow(
        path, request, {_KEY_VERSION: key_version, _NODE: node}
    )
