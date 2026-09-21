"""State merging for offline coordination.

A state is a dict of the form::

    {"clock": {node: count}, "records": {key: [value, deleted, clock, writer]}}

``clock`` maps non-empty node names to non-negative integer counters.
Each record is a four-item list ``[value, deleted, clock, writer]`` where
``value`` is a str (always ``""`` for a deleted record), ``deleted`` is a
bool, ``clock`` is the record's vector clock (it must contain ``writer`` and
no component may exceed the outer state clock; missing nodes count as 0),
and ``writer`` is a non-empty str.

See :func:`merge_states` for the reconciliation rules.
"""

from __future__ import annotations

from typing import Any

CLOCK = "clock"
RECORDS = "records"


def _is_int(value: Any) -> bool:
    # bool is a subclass of int, but a counter must never be a bool.
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _validated_clock(
    clock: Any, *, where: str, bound: dict[str, int] | None = None
) -> dict[str, int]:
    """Validate a clock mapping and return a fresh dict copy.

    When ``bound`` is given, every component must be <= the corresponding
    bound value; nodes absent from the bound are treated as 0.
    """
    if not isinstance(clock, dict):
        raise TypeError(f"{where} clock must be a dict")
    result: dict[str, int] = {}
    for node, count in clock.items():
        if not isinstance(node, str):
            raise TypeError(f"{where} clock node must be a str")
        if node == "":
            raise ValueError(f"{where} clock node must be non-empty")
        if not _is_int(count):
            raise TypeError(f"{where} clock count for {node!r} must be an int")
        if count < 0:
            raise ValueError(f"{where} clock count for {node!r} must be non-negative")
        result[node] = count
    if bound is not None:
        for node, count in result.items():
            limit = bound.get(node, 0)
            if count > limit:
                raise ValueError(
                    f"{where} clock count for {node!r} ({count}) exceeds the "
                    f"state clock ({limit})"
                )
    return result


def _validated_record(
    entry: Any, *, key: str, state_clock: dict[str, int]
) -> list[Any]:
    """Validate one record and return a fresh list with a copied clock."""
    where = f"record for key {key!r}"
    if not isinstance(entry, list):
        raise TypeError(f"{where} must be a list")
    if len(entry) != 4:
        raise ValueError(f"{where} must have exactly four items")
    value, deleted, clock, writer = entry
    if not isinstance(value, str):
        raise TypeError(f"{where} value must be a str")
    if not isinstance(deleted, bool):
        raise TypeError(f"{where} deleted flag must be a bool")
    if deleted and value != "":
        raise ValueError(f"{where} is deleted but its value is not empty")
    clock_copy = _validated_clock(clock, where=where, bound=state_clock)
    if not isinstance(writer, str):
        raise TypeError(f"{where} writer must be a str")
    if writer == "":
        raise ValueError(f"{where} writer must be non-empty")
    if writer not in clock_copy:
        raise ValueError(f"{where} writer {writer!r} is missing from its clock")
    return [value, deleted, clock_copy, writer]


def _validated_state(state: Any) -> tuple[dict[str, int], dict[str, list[Any]]]:
    """Validate a whole state and return fresh copies of its contents."""
    if not isinstance(state, dict):
        raise TypeError("state must be a dict")
    if set(state.keys()) != {CLOCK, RECORDS}:
        raise ValueError("state must contain exactly the keys 'clock' and 'records'")
    clock = _validated_clock(state[CLOCK], where="state")
    raw_records = state[RECORDS]
    if not isinstance(raw_records, dict):
        raise TypeError("state records must be a dict")
    records: dict[str, list[Any]] = {}
    for key, entry in raw_records.items():
        if not isinstance(key, str):
            raise TypeError("record key must be a str")
        if key == "":
            raise ValueError("record key must be non-empty")
        records[key] = _validated_record(entry, key=key, state_clock=clock)
    return clock, records


def _dominates(winner: dict[str, int], loser: dict[str, int]) -> bool:
    """True iff every component of winner is >= and at least one is >.

    Nodes missing from either clock are treated as 0.
    """
    nodes = set(winner) | set(loser)
    return all(winner.get(node, 0) >= loser.get(node, 0) for node in nodes) and any(
        winner.get(node, 0) > loser.get(node, 0) for node in nodes
    )


def _record_sort_key(record: list[Any]) -> tuple[Any, ...]:
    value, deleted, clock, writer = record
    return (
        clock[writer],
        writer,
        deleted,
        value,
        tuple(sorted(clock.items())),
    )


def _resolve_record(left: list[Any], right: list[Any]) -> list[Any]:
    # Identical records simply survive.
    if left == right:
        return left
    left_clock = left[2]
    right_clock = right[2]
    if _dominates(left_clock, right_clock):
        return left
    if _dominates(right_clock, left_clock):
        return right
    # Concurrent updates: compare by the prescribed Python tuple order.
    return left if _record_sort_key(left) >= _record_sort_key(right) else right


def merge_states(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Merge two states and return a brand-new state without mutating inputs.

    Rules:

    * The output clock takes the per-node maximum (missing nodes count as 0).
    * A record present on only one side is kept as-is.
    * Identical records are kept.
    * If one record's clock has every component >= the other's with at least
      one strictly greater, that record wins.
    * Otherwise the record with the larger
      ``(clock[writer], writer, deleted, value, tuple(sorted(clock.items())))``
      Python tuple wins.

    Type violations raise :class:`TypeError`; all other constraint violations
    raise :class:`ValueError`.
    """
    left_clock, left_records = _validated_state(left)
    right_clock, right_records = _validated_state(right)

    merged_clock: dict[str, int] = {}
    for node in set(left_clock) | set(right_clock):
        merged_clock[node] = max(left_clock.get(node, 0), right_clock.get(node, 0))

    merged_records: dict[str, list[Any]] = {}
    for key in set(left_records) | set(right_records):
        left_record = left_records.get(key)
        right_record = right_records.get(key)
        if left_record is None:
            chosen = right_record
        elif right_record is None:
            chosen = left_record
        else:
            chosen = _resolve_record(left_record, right_record)
        value, deleted, record_clock, writer = chosen
        merged_records[key] = [value, deleted, dict(record_clock), writer]

    return {CLOCK: merged_clock, RECORDS: merged_records}
