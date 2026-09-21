"""Durable state persistence for offline coordination.

A state is persisted as a single UTF-8 JSON document (see
:mod:`offline_coordination.merge` for the state shape). Writes are atomic:
the new document is first written to a temporary file in the same directory
and then renamed into place, while the previous document is retained as a
backup.

For a state file at ``path`` three paths are used:

* ``path``        -- the main (newest complete) state;
* ``path + ".bak"`` -- the most recent previous complete state, if any;
* ``path + ".tmp"`` -- the temporary file for an in-progress write.

A load never observes a half-written file: it tries the main file first and
falls back to the backup; the temporary file is ignored entirely.
"""

from __future__ import annotations

import json
import os
from typing import Any

from offline_coordination.merge import CLOCK, RECORDS, _validated_state

BACKUP_SUFFIX = ".bak"
TEMP_SUFFIX = ".tmp"


class CorruptStateError(ValueError):
    """Raised when a state file exists but contains no readable valid state."""


def _check_path(path: Any) -> str:
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    return path


def _rebuilt_state(clock: dict[str, int], records: dict[str, list[Any]]) -> dict[str, Any]:
    """Assemble a fresh state dict from validated clock/record copies."""
    rebuilt_records: dict[str, list[Any]] = {}
    for key, (value, deleted, record_clock, writer) in records.items():
        rebuilt_records[key] = [value, deleted, record_clock, writer]
    return {CLOCK: clock, RECORDS: rebuilt_records}


def _encode_state(state: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            state,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _fsync_directory(path: str) -> None:
    directory = os.path.dirname(path) or "."
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def save_state(path: Any, state: dict[str, Any]) -> None:
    """Atomically persist ``state`` to ``path``; return ``None``.

    The state is fully validated before any existing file is touched, so an
    invalid state or non-str path never modifies the main or backup file.
    On success the main file holds the new state and the backup holds the
    previous complete state (if one existed). Type violations raise
    :class:`TypeError`; all other validation failures raise
    :class:`ValueError`; other filesystem errors propagate as
    :class:`OSError`.
    """
    path = _check_path(path)
    # Validate first: a failure here must leave any existing files untouched.
    clock, records = _validated_state(state)
    payload = _encode_state(_rebuilt_state(clock, records))

    main_path = path
    backup_path = path + BACKUP_SUFFIX
    temp_path = path + TEMP_SUFFIX

    try:
        with open(temp_path, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        # Rotate the previous main file into the backup slot, then publish the
        # temporary file as the new main. A crash between the two renames
        # leaves only the backup, which load_state can still read.
        try:
            if os.path.exists(main_path):
                os.replace(main_path, backup_path)
            os.replace(temp_path, main_path)
        except BaseException:
            # Best-effort rollback so a failed or interrupted publish does
            # not hide the previous main state behind a missing main file.
            # If the rollback itself fails, the backup remains readable.
            if not os.path.exists(main_path) and os.path.exists(backup_path):
                try:
                    os.replace(backup_path, main_path)
                except OSError:
                    pass
            raise

        _fsync_directory(main_path)
    except BaseException:
        # Never leave a stray temporary file behind (success consumed it).
        try:
            os.remove(temp_path)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise


def _load_candidate(path: str) -> dict[str, Any] | None:
    """Return a validated state from one file, or None if it is corrupt.

    Raises FileNotFoundError (via open) when the file is absent; other
    OSError subclasses propagate unchanged.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        text = raw.decode("utf-8")
        data = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    try:
        clock, records = _validated_state(data)
    except (TypeError, ValueError):
        return None
    return _rebuilt_state(clock, records)


def load_state(path: Any) -> dict[str, Any]:
    """Load a state from ``path`` (falling back to its backup) as a fresh dict.

    The main file is tried first, then ``path + ".bak"``; the temporary
    file is ignored. A brand-new deep copy is returned. Raises
    :class:`FileNotFoundError` when neither file exists,
    :class:`CorruptStateError` when files exist but none contains a valid
    UTF-8 JSON state, and propagates any other :class:`OSError` unchanged.
    """
    path = _check_path(path)
    main_path = path
    backup_path = path + BACKUP_SUFFIX

    failures: list[str] = []
    for candidate in (main_path, backup_path):
        try:
            loaded = _load_candidate(candidate)
        except FileNotFoundError:
            continue
        if loaded is not None:
            return loaded
        failures.append(candidate)

    if not failures:
        raise FileNotFoundError(f"no state file at {main_path!r} or {backup_path!r}")
    raise CorruptStateError(
        "no readable valid state in " + " or ".join(repr(name) for name in failures)
    )
