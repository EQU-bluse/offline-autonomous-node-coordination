"""Offline, self-verifying proofs over a replication ledger's audit range.

A proof is a single UTF-8 compact JSON object with every object key, at
every level, sorted lexicographically (``json.dumps(..., sort_keys=True,
separators=(",", ":"))``), non-ASCII characters preserved unescaped and
exactly one trailing ``\\n``::

    {"after":"<last entry after>","before":"<first entry before>",
     "digest":"<64 lowercase hex>","end":<int>,"entries":[...],
     "start":<int>,"version":1}

``version`` is always the integer 1.  ``start``/``end`` name the covered
ledger audit seqs (both at least 1, ``start <= end``); ``before`` and
``after`` declare the range boundaries -- the ``before`` digest of the
first covered entry and the ``after`` digest of the last one.  ``entries``
copies the ledger's audit entries in that range verbatim, each preserving
the ledger key order ``after, before, id, seq, source`` with the optional
``auth`` of an authenticated entry (``keyVersion``/``node``).  ``digest``
binds the whole proof: it is the lowercase hex SHA-256 of the canonical
compact encoding of the proof with the ``digest`` key removed, *without*
the trailing newline.

:func:`export_proof` builds such a proof from a version-1 ledger written by
:mod:`offline_coordination.replication`.  It is strictly read-only: only
the main ledger path is opened (fixed ``.tmp``/``.old`` transaction
artifacts are never consulted), and nothing is ever created or modified.

:func:`verify_proof` checks proof bytes alone -- no ledger and no keyring
are read.  It verifies the encoding, the exact unique key sets at every
level, the version, the overall digest, the contiguous unique seq range,
the before/after state-digest chain and the declared boundaries, and on
success returns the range ``(start, end)``, the boundary digests
``(first_before, last_after)`` and the two entry counts
``(unsigned_entries, authenticated_entries)``.  Every structural or
content violation raises :class:`InvalidProofError`; bytes that are not
a :class:`bytes` instance raise :class:`TypeError`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from offline_coordination import replication

DIGEST = "digest"
END = "end"
ENTRIES = "entries"
START = "start"
VERSION = "version"

PROOF_VERSION = 1

_AFTER = replication.AFTER
_AUTH = replication.AUTH
_BEFORE = replication.BEFORE
_ID = replication.ID
_SEQ = "seq"
_SOURCE = replication.SOURCE
_KEY_VERSION = replication.KEY_VERSION
_NODE = replication.NODE

_PROOF_KEYS = frozenset(
    (_AFTER, _BEFORE, DIGEST, END, ENTRIES, START, VERSION)
)
_ENTRY_KEYS = frozenset((_AFTER, _BEFORE, _ID, _SEQ, _SOURCE))
_ENTRY_AUTHED_KEYS = _ENTRY_KEYS | {_AUTH}
_AUTH_KEYS = frozenset((_KEY_VERSION, _NODE))

# Canonical key order is supplied by sort_keys at serialization time;
# these tuples pin the parsed key order verified against the bytes.
_PROOF_KEY_ORDER = (_AFTER, _BEFORE, DIGEST, END, ENTRIES, START, VERSION)
_ENTRY_KEY_ORDER = (_AFTER, _AUTH, _BEFORE, _ID, _SEQ, _SOURCE)
_ENTRY_UNAUTHED_ORDER = (_AFTER, _BEFORE, _ID, _SEQ, _SOURCE)
_AUTH_KEY_ORDER = (_KEY_VERSION, _NODE)

_DIGEST_RE = replication._DIGEST_RE


class InvalidProofError(ValueError):
    """The proof bytes violate the proof byte or content contract."""


def _invalid(message: str) -> InvalidProofError:
    return InvalidProofError(f"invalid audit proof: {message}")


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _proof_body(
    start: int, end: int, before: str, after: str, entries: list[dict]
) -> dict:
    return {
        _AFTER: after,
        _BEFORE: before,
        END: end,
        ENTRIES: entries,
        START: start,
        VERSION: PROOF_VERSION,
    }


def _serialize_entry(entry: dict) -> dict:
    """One proof entry as copied from the parsed ledger entry."""
    out = {key: entry[key] for key in replication._LEDGER_ENTRY_KEY_ORDER}
    if _AUTH in entry:
        out[_AUTH] = {
            _KEY_VERSION: entry[_AUTH][_KEY_VERSION],
            _NODE: entry[_AUTH][_NODE],
        }
    return out


def export_proof(path: str, start: int, end: int | None = None) -> bytes:
    """Return canonical proof bytes for a ledger audit range.

    ``start`` is the first audit seq covered and must be at least 1.
    ``end`` is the last seq covered; when omitted (or ``None``) the
    ledger's last audit seq is used.  The requested range must fall
    entirely inside the existing audit sequence: an empty ledger cannot
    satisfy any request, and ``end`` must not exceed the last seq.

    The ledger is opened read-only through the same byte-level validation
    as :func:`replication.apply_remote`, so a missing ledger raises
    :class:`FileNotFoundError`, a corrupt ledger raises :class:`ValueError`
    and any other read failure propagates unchanged as :class:`OSError`.
    Type violations raise :class:`TypeError` -- in particular a :class:`bool`
    is not accepted as an int -- and an inverted, out-of-range or
    unsatisfiable range raises :class:`ValueError`.  No file is created,
    modified or deleted.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if isinstance(start, bool) or not isinstance(start, int):
        raise TypeError("start must be an int")
    if end is not None and (isinstance(end, bool) or not isinstance(end, int)):
        raise TypeError("end must be an int or None")
    if start < 1:
        raise ValueError("start must be >= 1")
    if end is not None and end < start:
        raise ValueError("end must not precede start")

    with open(path, "rb") as handle:
        raw = handle.read()
    _, _, ledger_entries = replication._parse_ledger(raw)

    last_seq = len(ledger_entries)
    if last_seq == 0:
        raise ValueError("cannot export a proof from a ledger with no audit entries")
    if start > last_seq:
        raise ValueError("start must not exceed the last audit seq")
    if end is None:
        end = last_seq
    elif end > last_seq:
        raise ValueError("end must not exceed the last audit seq")

    selected = [
        _serialize_entry(ledger_entries[seq - 1]) for seq in range(start, end + 1)
    ]
    before_digest = selected[0][_BEFORE]
    after_digest = selected[-1][_AFTER]
    body = _proof_body(start, end, before_digest, after_digest, selected)
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    proof = dict(body)
    proof[DIGEST] = digest
    return _canonical(proof) + b"\n"


def _parse_proof(proof: bytes) -> tuple[int, int, str, str, list[dict], int]:
    """Validate proof bytes against the full byte and content contract.

    Returns ``(start, end, first_before, last_after, entries,
    authenticated_count)`` with the entries in proof order.
    """
    if not proof.endswith(b"\n") or proof.endswith(b"\n\n"):
        raise _invalid("must be a single JSON object terminated by one LF")
    try:
        text = proof[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _invalid("must be a JSON object")
    if set(data.keys()) != _PROOF_KEYS:
        raise _invalid(
            "top-level object must contain exactly the keys "
            "'after', 'before', 'digest', 'end', 'entries', 'start' "
            "and 'version'"
        )
    if tuple(data.keys()) != _PROOF_KEY_ORDER:
        raise _invalid("top-level keys must be in lexicographic order")

    version = data[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _invalid("version must be an int")
    if version != PROOF_VERSION:
        raise _invalid("version must be the integer 1")

    start = data[START]
    end = data[END]
    if isinstance(start, bool) or not isinstance(start, int):
        raise _invalid("start must be an int")
    if isinstance(end, bool) or not isinstance(end, int):
        raise _invalid("end must be an int")
    if start < 1:
        raise _invalid("start must be >= 1")
    if end < start:
        raise _invalid("end must not precede start")

    digest = data[DIGEST]
    if not _is_digest(digest):
        raise _invalid("digest must be 64 lowercase hex characters")

    declared_before = data[_BEFORE]
    declared_after = data[_AFTER]
    if not _is_digest(declared_before):
        raise _invalid("before must be 64 lowercase hex characters")
    if not _is_digest(declared_after):
        raise _invalid("after must be 64 lowercase hex characters")

    raw_entries = data[ENTRIES]
    if not isinstance(raw_entries, list):
        raise _invalid("entries must be an array")
    if not raw_entries:
        raise _invalid("entries must not be empty")
    if len(raw_entries) != end - start + 1:
        raise _invalid("entries must cover exactly the declared range")

    entries: list[dict] = []
    authed_count = 0
    expected_seq = start - 1
    expected_before: str | None = None
    for position, entry in enumerate(raw_entries):
        if not isinstance(entry, dict):
            raise _invalid(f"entry {position} must be an object")
        key_set = set(entry.keys())
        if key_set != _ENTRY_KEYS and key_set != _ENTRY_AUTHED_KEYS:
            raise _invalid(
                f"entry {position} must contain exactly the keys "
                "'after', 'before', 'id', 'seq' and 'source' with "
                "optional 'auth'"
            )
        if tuple(entry.keys()) not in (_ENTRY_UNAUTHED_ORDER, _ENTRY_KEY_ORDER):
            raise _invalid(f"entry {position} keys must be in lexicographic order")

        before_digest = entry[_BEFORE]
        after_digest = entry[_AFTER]
        entry_id = entry[_ID]
        seq = entry[_SEQ]
        source = entry[_SOURCE]
        if not _is_digest(before_digest):
            raise _invalid(
                f"entry {position} before must be 64 lowercase hex characters"
            )
        if not _is_digest(after_digest):
            raise _invalid(
                f"entry {position} after must be 64 lowercase hex characters"
            )
        if not isinstance(entry_id, str) or entry_id == "":
            raise _invalid(f"entry {position} id must be a non-empty str")
        if not isinstance(source, str) or source == "":
            raise _invalid(f"entry {position} source must be a non-empty str")
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _invalid(f"entry {position} seq must be an int")

        expected_seq += 1
        if seq != expected_seq:
            raise _invalid(
                f"entry {position} seq is {seq}, expected {expected_seq}"
            )
        if expected_before is not None and before_digest != expected_before:
            raise _invalid(
                f"entry {position} before does not chain to the previous after"
            )

        parsed = {
            _AFTER: after_digest,
            _BEFORE: before_digest,
            _ID: entry_id,
            _SEQ: seq,
            _SOURCE: source,
        }
        if _AUTH in entry:
            auth = entry[_AUTH]
            if not isinstance(auth, dict):
                raise _invalid(f"entry {position} auth must be an object")
            if set(auth.keys()) != _AUTH_KEYS:
                raise _invalid(
                    f"entry {position} auth must contain exactly the keys "
                    "'keyVersion' and 'node'"
                )
            if tuple(auth.keys()) != _AUTH_KEY_ORDER:
                raise _invalid(
                    f"entry {position} auth keys must be in lexicographic order"
                )
            node = auth[_NODE]
            key_version = auth[_KEY_VERSION]
            if not isinstance(node, str) or node == "":
                raise _invalid(
                    f"entry {position} auth node must be a non-empty str"
                )
            if (
                isinstance(key_version, bool)
                or not isinstance(key_version, int)
                or key_version <= 0
            ):
                raise _invalid(
                    f"entry {position} auth keyVersion must be a positive int"
                )
            parsed[_AUTH] = {_KEY_VERSION: key_version, _NODE: node}
            authed_count += 1

        entries.append(parsed)
        expected_before = after_digest

    # The declared boundaries must match the first/last entries: the
    # declared range seqs and the before/after state digests.
    if entries[0][_SEQ] != start or entries[-1][_SEQ] != end:
        raise _invalid("declared range does not match the entry seqs")
    if entries[0][_BEFORE] != declared_before:
        raise _invalid("declared before does not match the first entry")
    if entries[-1][_AFTER] != declared_after:
        raise _invalid("declared after does not match the last entry")

    # The bytes must be the single canonical compact form with sorted
    # keys: this rejects stray whitespace, non-canonical escapes,
    # duplicate JSON keys and any key permutation or reordering.
    if _canonical(data) + b"\n" != proof:
        raise _invalid("encoding is not the canonical compact form")

    body = _proof_body(start, end, declared_before, declared_after, entries)
    if hashlib.sha256(_canonical(body)).hexdigest() != digest:
        raise _invalid("digest does not match the proof contents")

    return start, end, declared_before, declared_after, entries, authed_count


def verify_proof(proof: bytes) -> tuple[tuple[int, int], tuple[str, str], tuple[int, int]]:
    """Verify proof bytes without consulting any ledger or keyring.

    Returns ``((start, end), (first_before, last_after),
    (unsigned_entries, authenticated_entries))`` on success.  The
    boundary digests are the declared ``before`` of the first entry and
    the declared ``after`` of the last entry respectively.

    Every violation of the encoding, key sets, version, overall digest,
    seq continuity/uniqueness, state-digest chain or declared boundaries
    -- including an illegal ``auth`` binding -- raises
    :class:`InvalidProofError` (a :class:`ValueError`).  An argument that
    is not :class:`bytes` raises :class:`TypeError`.
    """
    if not isinstance(proof, bytes):
        raise TypeError("proof must be bytes")
    start, end, first_before, last_after, entries, authed_count = _parse_proof(proof)
    unsigned_count = len(entries) - authed_count
    return (
        (start, end),
        (first_before, last_after),
        (unsigned_count, authed_count),
    )
