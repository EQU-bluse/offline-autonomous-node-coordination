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


def _record_order_key(record: list[Any], nodes: list[str]) -> tuple[Any, ...]:
    """Total-order key for concurrent records over a fixed node list.

    The leading element is the record clock as a vector over ``nodes``
    (ascending node names, missing components counting as 0), compared
    lexicographically: the record with the larger count at the first
    differing component wins.  Because a causally dominating clock is
    greater at the first differing component, this order always agrees
    with dominance, so picking the maximum is associative, commutative
    and idempotent.  Fully equal clock vectors fall back, in order, to
    ``writer``, ``deleted`` and ``value`` (larger wins), and finally to
    the sorted clock items so that records whose clocks differ only in
    zero-count components still order deterministically.
    """
    value, deleted, clock, writer = record
    return (
        tuple(clock.get(node, 0) for node in nodes),
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
    # Concurrent updates: compare both clocks component by component over
    # the ascending union of their node names; components absent from a
    # clock count as 0.  Nodes absent from both clocks would contribute 0
    # to both sides, so the pairwise union decides exactly as any wider
    # node set would, and the winner is independent of merge grouping.
    nodes = sorted(set(left_clock) | set(right_clock))
    if _record_order_key(left, nodes) >= _record_order_key(right, nodes):
        return left
    return right


def _remote_need(
    remote_record: list[Any], local_clock: dict[str, int]
) -> dict[str, list[int]]:
    """Clock components the local state is missing before this record applies.

    The prerequisite vector is the remote record clock with its own writer
    component decremented by one.  Each component where the local outer clock
    is behind contributes the closed interval ``[local + 1, prerequisite]``.
    """
    _, _, remote_clock, writer = remote_record
    need: dict[str, list[int]] = {}
    for node in sorted(set(local_clock) | set(remote_clock)):
        prerequisite = remote_clock.get(node, 0) - (1 if node == writer else 0)
        local_count = local_clock.get(node, 0)
        if local_count < prerequisite:
            need[node] = [local_count + 1, prerequisite]
    return need


def preview_changes(local: dict[str, Any], remote: dict[str, Any]) -> dict[str, Any]:
    """Preview per-key decisions implied by merging ``remote`` into ``local``.

    The state contract is the same as for :func:`merge_states`.  Inputs are
    never modified and every call returns brand-new, deeply independent
    objects.

    The result is ``{"items": items, "version": 1}`` with one item per key of
    ``remote["records"]`` in ascending key order.  Each item has the key order
    ``decision, key, need, winner``:

    * ``need`` lists the outer-clock components missing locally for the
      remote record to be causally ready (its clock with the writer component
      decremented by one), nodes ascending, values as closed
      ``[start, end]`` intervals (missing components count as 0).
    * When ``need`` is non-empty, ``decision`` is ``"missing"`` and
      ``winner`` is ``None``.
    * Otherwise the decision is, in order: ``"apply"``/``"remote"`` when the
      local record is absent or the remote record dominates it,
      ``"duplicate"``/``"equal"`` for equal records, ``"stale"``/``"local"``
      when the local record dominates, and ``"conflict"`` with the
      :func:`merge_states` tie-break winner (``"remote"`` or ``"local"``)
      for concurrent records — the same total order over the ascending
      union of node names, so the previewed winner is exactly the record
      a merge would keep.

    Type violations raise :class:`TypeError`; all other constraint violations
    raise :class:`ValueError`.
    """
    local_clock, local_records = _validated_state(local)
    _, remote_records = _validated_state(remote)

    items: list[dict[str, Any]] = []
    for key in sorted(remote_records):
        remote_record = remote_records[key]
        local_record = local_records.get(key)
        need = _remote_need(remote_record, local_clock)

        if need:
            decision, winner = "missing", None
        elif local_record is None:
            decision, winner = "apply", "remote"
        elif local_record == remote_record:
            decision, winner = "duplicate", "equal"
        elif _dominates(remote_record[2], local_record[2]):
            decision, winner = "apply", "remote"
        elif _dominates(local_record[2], remote_record[2]):
            decision, winner = "stale", "local"
        else:
            # Concurrent updates: the same total-order arbitration as
            # merge_states, so the previewed winner matches the merge.
            nodes = sorted(set(remote_record[2]) | set(local_record[2]))
            if _record_order_key(remote_record, nodes) >= _record_order_key(
                local_record, nodes
            ):
                winner = "remote"
            else:
                winner = "local"
            decision = "conflict"

        items.append(
            {"decision": decision, "key": key, "need": need, "winner": winner}
        )

    return {"items": items, "version": 1}


def merge_states(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Merge two states and return a brand-new state without mutating inputs.

    Rules:

    * The output clock takes the per-node maximum (missing nodes count as 0).
    * A record present on only one side is kept as-is.
    * Identical records are kept.
    * If one record's clock has every component >= the other's with at least
      one strictly greater, that record wins.
    * Otherwise the clocks are concurrent and a total order decides:
      compare both clocks component by component over the ascending union
      of all node names (missing components count as 0) and the record
      with the larger count at the first differing component wins; only
      when the full clock vectors are equal do ``writer``, then
      ``deleted``, then ``value`` decide (larger wins), with the sorted
      clock items as the final tie-break.  This order agrees with causal
      dominance wherever clocks are comparable, so merging is
      commutative, associative and idempotent.

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
