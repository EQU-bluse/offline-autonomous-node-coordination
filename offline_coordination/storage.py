"""Atomic state persistence for offline coordination.

A state (see :mod:`offline_coordination.merge`) is stored as UTF-8 JSON::

    json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\\n"

with records kept as ``[value, deleted, clock, writer]`` lists.  Three paths
are used: the main file ``path``, a backup ``path + ".bak"`` holding the
previous most recent complete state, and a temporary file ``path + ".tmp"``
used for atomic replacement (and ignored when loading).
"""

from __future__ import annotations

import errno
import json
import os
from typing import Any

from .merge import CLOCK, RECORDS, _validated_state


class CorruptStateError(ValueError):
    """State files exist, but none of them holds a valid state."""


def _serialize(clock: dict[str, int], records: dict[str, list[Any]]) -> bytes:
    state = {CLOCK: clock, RECORDS: records}
    text = (
        json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    )
    return text.encode("utf-8")


def _decode_state(raw: bytes) -> dict[str, Any]:
    """Decode and validate state bytes, returning a fresh deep-copied state."""
    data = json.loads(raw.decode("utf-8"))
    clock, records = _validated_state(data)
    return {CLOCK: clock, RECORDS: records}


_DECODE_FAILURES = (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError)


def _read_valid_state(path: str) -> dict[str, Any] | None:
    """Return the validated state stored at ``path``, or None if absent/corrupt."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return None
    try:
        return _decode_state(raw)
    except _DECODE_FAILURES:
        return None


def _fsync_dir(path: str) -> None:
    """Fsync the directory containing ``path`` so a rename is durable.

    Any failure to open the directory or fsync it propagates as :class:`OSError`.
    """
    fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_state(path: str, state: dict[str, Any]) -> None:
    """Atomically persist ``state`` at ``path``, rotating the old state to backup.

    The state is validated with the same rules as
    :func:`offline_coordination.merge.merge_states` before anything touches
    the filesystem, so a rejected state leaves the existing files untouched.
    On success the main file holds the new state and the backup holds the
    previous most recent complete state (if there was one).  A crash at any
    point leaves at least one of the main and backup files readable.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    clock, records = _validated_state(state)
    payload = _serialize(clock, records)

    main_path = path
    backup_path = path + ".bak"
    tmp_path = path + ".tmp"

    with open(tmp_path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())

    try:
        # Rotate only a complete state into the backup slot; a missing or
        # corrupt main file must not clobber a still-valid backup.
        if _read_valid_state(main_path) is not None:
            os.replace(main_path, backup_path)
        os.replace(tmp_path, main_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    _fsync_dir(path)


def load_state(path: str) -> dict[str, Any]:
    """Load the state stored at ``path``, falling back to the backup file.

    The temporary file is never consulted.  Returns a brand-new deep-copied
    state dict.  Raises :class:`FileNotFoundError` when neither file exists,
    :class:`CorruptStateError` when files exist but none decodes to a valid
    state, and re-raises any other :class:`OSError` from the filesystem.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")

    saw_file = False
    for candidate in (path, path + ".bak"):
        try:
            with open(candidate, "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            continue
        saw_file = True
        try:
            return _decode_state(raw)
        except _DECODE_FAILURES:
            continue
    if saw_file:
        raise CorruptStateError(f"no valid state found at {path!r}")
    raise FileNotFoundError(errno.ENOENT, "no state file found", path)
