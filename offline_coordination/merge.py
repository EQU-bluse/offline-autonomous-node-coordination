"""Merge replicated node states without mutating the inputs.

A state has the strict shape::

    {"clock": {node: int},
     "records": {key: [value, deleted, clock, writer]}}

where ``node``, ``key`` and ``writer`` are non-empty strings, every counter
is a non-negative ``int`` (never a ``bool``), ``value`` is a string,
``deleted`` is a bool, a deleted record carries an empty value, and each
record clock contains its writer and never exceeds the outer clock
(missing nodes count as zero).
"""

from __future__ import annotations

_STATE_KEYS = frozenset({"clock", "records"})


def _check_name(name: object, what: str) -> str:
    if not isinstance(name, str):
        raise TypeError(f"{what} must be a str, got {type(name).__name__}")
    if not name:
        raise ValueError(f"{what} must be a non-empty str")
    return name


def _check_count(count: object, what: str) -> int:
    if not isinstance(count, int) or isinstance(count, bool):
        raise TypeError(f"{what} must be an int, got {type(count).__name__}")
    if count < 0:
        raise ValueError(f"{what} must be non-negative, got {count}")
    return count


def _check_clock(clock: object, what: str) -> dict:
    if not isinstance(clock, dict):
        raise TypeError(f"{what} must be a dict, got {type(clock).__name__}")
    for node, count in clock.items():
        _check_name(node, f"{what} node")
        _check_count(count, f"{what}[{node!r}]")
    return clock


def _check_record(key: str, record: object, clock: dict) -> list:
    what = f"records[{key!r}]"
    if not isinstance(record, list):
        raise TypeError(f"{what} must be a list, got {type(record).__name__}")
    if len(record) != 4:
        raise ValueError(f"{what} must have exactly 4 items, got {len(record)}")
    value, deleted, record_clock, writer = record
    if not isinstance(value, str):
        raise TypeError(f"{what} value must be a str, got {type(value).__name__}")
    if not isinstance(deleted, bool):
        raise TypeError(f"{what} deleted must be a bool, got {type(deleted).__name__}")
    _check_clock(record_clock, f"{what} clock")
    _check_name(writer, f"{what} writer")
    if deleted and value != "":
        raise ValueError(f"{what} is deleted but value is not empty")
    if writer not in record_clock:
        raise ValueError(f"{what} clock is missing its writer {writer!r}")
    for node, count in record_clock.items():
        if count > clock.get(node, 0):
            raise ValueError(
                f"{what} clock[{node!r}]={count} exceeds state clock "
                f"{clock.get(node, 0)}"
            )
    return record


def _check_state(state: object, what: str) -> dict:
    if not isinstance(state, dict):
        raise TypeError(f"{what} must be a dict, got {type(state).__name__}")
    if set(state) != _STATE_KEYS:
        raise ValueError(
            f"{what} keys must be {sorted(_STATE_KEYS)}, got {sorted(state)}"
        )
    clock = _check_clock(state["clock"], f"{what} clock")
    records = state["records"]
    if not isinstance(records, dict):
        raise TypeError(
            f"{what} records must be a dict, got {type(records).__name__}"
        )
    for key, record in records.items():
        _check_name(key, f"{what} record key")
        _check_record(key, record, clock)
    return state


def _copy_record(record: list) -> list:
    value, deleted, record_clock, writer = record
    return [value, deleted, dict(record_clock), writer]


def _tiebreak_key(record: list) -> tuple:
    value, deleted, record_clock, writer = record
    return (
        record_clock[writer],
        writer,
        deleted,
        value,
        tuple(sorted(record_clock.items())),
    )


def _resolve(left_record: list, right_record: list) -> list:
    if left_record == right_record:
        return left_record
    left_clock, right_clock = left_record[2], right_record[2]
    nodes = set(left_clock) | set(right_clock)
    left_dominates = all(
        left_clock.get(node, 0) >= right_clock.get(node, 0) for node in nodes
    ) and any(left_clock.get(node, 0) > right_clock.get(node, 0) for node in nodes)
    if left_dominates:
        return left_record
    right_dominates = all(
        right_clock.get(node, 0) >= left_clock.get(node, 0) for node in nodes
    ) and any(right_clock.get(node, 0) > left_clock.get(node, 0) for node in nodes)
    if right_dominates:
        return right_record
    return max(left_record, right_record, key=_tiebreak_key)


def merge_states(left: dict, right: dict) -> dict:
    """Merge two states into a new deep-copied state dict.

    The output clock takes the per-node maximum. A record present on only
    one side, or identical on both sides, is kept as-is. Otherwise the
    record whose clock dominates wins; concurrent records are ordered by
    ``(clock[writer], writer, deleted, value, tuple(sorted(clock.items())))``
    and the larger one wins. Neither input is modified.

    Raises TypeError for values of the wrong type and ValueError for any
    other constraint violation (key sets, empty names, negative counts,
    malformed records, writer or clock bounds).
    """
    _check_state(left, "left")
    _check_state(right, "right")

    clock = {
        node: max(left["clock"].get(node, 0), right["clock"].get(node, 0))
        for node in set(left["clock"]) | set(right["clock"])
    }

    records = {}
    for key in set(left["records"]) | set(right["records"]):
        left_record = left["records"].get(key)
        right_record = right["records"].get(key)
        if left_record is None:
            records[key] = _copy_record(right_record)
        elif right_record is None:
            records[key] = _copy_record(left_record)
        else:
            records[key] = _copy_record(_resolve(left_record, right_record))

    return {"clock": clock, "records": records}
