"""Successor sealing and whole-chain verification over signed final fork
decision aggregate chain fork decision aggregates -- private
implementation module.

This module stacks one supersession-chain layer on top of the cross-site
aggregate boundary in :mod:`offline_coordination._ffdac_decision_aggregation`.
The root is one signed final fork decision aggregate chain fork decision
aggregate (``aggregate_final_fork_decision_aggregate_chain_fork_decisions``),
which binds six invariant policy digests (the original prune policy, the
site authorization policy, the fork-proof signer site policy, the
adjudication signer site policy, the issuing adjudication site policy and
the proof site policy) plus the root decision site policy.  A successor
appends a non-empty raw decision increment and may rotate only the
versioned **decision** site policy; every hop re-verifies the whole
prefix and the increment at the hop's effective moment and again at the
current verification moment, re-authorizes every vote under the policy
in force at that hop, re-tallies the complete stage and seals the
conclusion with a credential authorized by both the old and the new
decision site policy and usable at both moments.

The stage tally is exactly the aggregate boundary's tally: for one site
identical declarations count once and repeats are ``duplicate``, any
field difference is a ``contradiction``, distinct sites must agree on the
one complete declaration (the common fork edge set, the sorted per-item
conclusions, the term-by-term proof digest vector and the overall
status), cross-site disagreement is ``conflicted`` and no majority can
outvote it, and one unique declaration backed by at least the threshold
of distinct sites is ``accepted`` (short of it ``insufficient``, still
keeping the common declaration).  The verdict state machine lets
``insufficient`` stay or become ``accepted``/``conflicted``, an
``accepted`` head only keep the identical declaration or become
``conflicted``, and a ``conflicted`` head never recover.

This is an internal boundary, not a public entry point: the public
functions and the dedicated chain error are re-exported from
``offline_coordination.replication`` under their historical names, with
identical call signatures and class object identity.  Every shared rule
is imported from :mod:`offline_coordination.replication` or
:mod:`offline_coordination._ffdac_decision_aggregation` -- never copied.
"""

from __future__ import annotations

import copy
import hashlib

from offline_coordination.replication import (
    ADJ_CONCLUSION,
    ADJ_REASON,
    ADJ_SITES,
    ADJ_THRESHOLD,
    AuthenticationError,
    CP_DIGEST,
    DS_HEIGHT,
    DS_NEW_POLICY_DIGEST,
    DS_OLD_POLICY_DIGEST,
    DS_POLICY_VERSION,
    DS_PREDECESSOR_DIGEST,
    DS_ROOT_DIGEST,
    DS_EFFECTIVE_AT,
    FAC_HEAD_DIGEST,
    ID,
    ITEMS,
    KEY_VERSION,
    NOT_AFTER,
    NOT_BEFORE,
    PA_CONCLUSION_CONTRADICTION,
    PA_CONCLUSION_DUPLICATE,
    PA_CONCLUSION_INVALID,
    PA_CONCLUSION_VALID,
    PA_ITEMS,
    PA_STATUS_ACCEPTED,
    PA_STATUS_CONFLICTED,
    PA_STATUS_INSUFFICIENT,
    REASON_CONTRADICTION,
    REASON_DUPLICATE,
    REVOKED,
    SIGNATURE,
    STATUS,
    TICKET_PAYLOAD,
    VERSION,
    VD_ISSUER,
    _FACFDA_ADJUDICATION_SITE_POLICY_DIGEST,
    _FACFDA_AUTHORIZATION_POLICY_DIGEST,
    _FACFDA_DECLARATION,
    _FACFDA_INPUTS,
    _FACFDA_PRUNE_POLICY_DIGEST,
    _FACFDA_SIGNER_SITE_POLICY_DIGEST,
    _FACFDA_SITE_POLICY_DIGEST,
    _FFDAC_PACKET,
    _PA_STATUSES,
    _PFDA_INVALID_REASONS,
    _PFDA_ROW_KEYS,
    _cfca_tally_chain_rows,
    _fe_moment,
    _ffdac_assert_effective_monotonic,
    _ffdac_assert_payload_signature,
    _ffdac_bind_runtime,
    _ffdac_parse_envelope,
    _ffdac_payload_signature,
    _ffdac_validated_signer,
    _ffdacf_validated_decision_materials,
    _hex_bytes,
    _pac_plain_site_policy,
    _pac_policy_digest,
    _pac_policy_matches_root,
    _pac_sort_rows,
    _pac_validated_policy_sequence,
    _packet_payload_keys,
    _prune_batch_site_policy_bytes,
    _prune_compact,
    _prune_is_digest,
    _usable_checkpoint_key,
    _validated_cfd_decision_items,
    _validated_pac_site_policy,
    _validated_pfda_declaration,
)
from offline_coordination._ffdac_decision_aggregation import (
    InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError,
    _FFDACFDA_DECISION_SITE_POLICY_DIGEST,
    _FFDACFDA_PROOF_SITE_POLICY_DIGEST,
    _aggregate_ffdacfda_one,
    _ffdacfda_assert_policy_digests,
    _ffdacfda_invalid,
    _parse_ffdacfda,
    _reconcile_ffdacfda_aggregate,
    _reconcile_ffdacfda_declaration,
)


FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISION_AGGREGATE_CHAIN_VERSION = 1

_FFDACFDA_CHAIN_PACKET = _FFDAC_PACKET
_FFDACFDA_CHAIN_DECISIONS = "decisions"
_FFDACFDA_CHAIN_ROOT_DIGEST = DS_ROOT_DIGEST
_FFDACFDA_CHAIN_PREDECESSOR_DIGEST = DS_PREDECESSOR_DIGEST
_FFDACFDA_CHAIN_HEIGHT = DS_HEIGHT
_FFDACFDA_CHAIN_OLD_POLICY_DIGEST = DS_OLD_POLICY_DIGEST
_FFDACFDA_CHAIN_NEW_POLICY_DIGEST = DS_NEW_POLICY_DIGEST
_FFDACFDA_CHAIN_POLICY_VERSION = DS_POLICY_VERSION
_FFDACFDA_CHAIN_EFFECTIVE_AT = DS_EFFECTIVE_AT
_FFDACFDA_CHAIN_DECLARATION_DIGEST = "declarationDigest"

_FFDACFDA_CHAIN_INVARIANT_DIGEST_FIELDS = (
    _FACFDA_PRUNE_POLICY_DIGEST,
    _FACFDA_AUTHORIZATION_POLICY_DIGEST,
    _FACFDA_SITE_POLICY_DIGEST,
    _FACFDA_SIGNER_SITE_POLICY_DIGEST,
    _FACFDA_ADJUDICATION_SITE_POLICY_DIGEST,
    _FFDACFDA_PROOF_SITE_POLICY_DIGEST,
)

_FFDACFDA_CHAIN_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_FFDACFDA_CHAIN_SUCCESSOR_PAYLOAD_KEYS = frozenset((
    _FFDACFDA_CHAIN_ROOT_DIGEST,
    _FFDACFDA_CHAIN_PREDECESSOR_DIGEST,
    _FFDACFDA_CHAIN_HEIGHT,
    _FACFDA_INPUTS,
    ITEMS,
    _FACFDA_DECLARATION,
    STATUS,
    *_FFDACFDA_CHAIN_INVARIANT_DIGEST_FIELDS,
    _FFDACFDA_CHAIN_OLD_POLICY_DIGEST,
    _FFDACFDA_CHAIN_NEW_POLICY_DIGEST,
    _FFDACFDA_CHAIN_POLICY_VERSION,
    _FFDACFDA_CHAIN_EFFECTIVE_AT,
    _FFDACFDA_CHAIN_DECISIONS,
    VD_ISSUER,
    KEY_VERSION,
    VERSION,
))
_FFDACFDA_CHAIN_DECISION_ITEM_KEYS = frozenset(
    (ID, _FFDACFDA_CHAIN_PACKET)
)
_FFDACFDA_CHAIN_RESULT_KEYS = (
    _FFDACFDA_CHAIN_ROOT_DIGEST,
    FAC_HEAD_DIGEST,
    _FFDACFDA_CHAIN_HEIGHT,
    _FFDACFDA_CHAIN_POLICY_VERSION,
    STATUS,
    _FFDACFDA_CHAIN_DECLARATION_DIGEST,
)


class InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError(
    ValueError
):
    """A final fork decision aggregate chain fork decision aggregate
    successor or chain breaks its contract."""

    # The class keeps its historical public module path: it is re-exported
    # from ``offline_coordination.replication``.
    __module__ = "offline_coordination.replication"


def _chain_invalid(
    message: str,
) -> InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError:
    return (
        InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError(
            "invalid final fork decision aggregate chain fork decision "
            f"aggregate chain: {message}"
        )
    )


def _reject_duplicate_chain_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate successor keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _chain_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


# -- Shared materials -----------------------------------------------------------

def _validated_materials(
    prune_policy: object,
    authorization_policy: object,
    site_policy: object,
    signer_site_policy: object,
    adjudication_site_policy: object,
    proof_site_policy: object,
) -> dict:
    """Validate the six invariant policies once and bind their digests."""
    return _ffdacf_validated_decision_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy, proof_site_policy,
    )


# -- Stage views over a root aggregate or a successor packet -------------------

def _root_view(raw: bytes) -> dict:
    """Structurally parse a root aggregate predecessor."""
    payload, _signature = _parse_ffdacfda(raw)
    return {
        "kind": "root",
        _FFDACFDA_CHAIN_ROOT_DIGEST: hashlib.sha256(raw).hexdigest(),
        _FFDACFDA_CHAIN_HEIGHT: 0,
        STATUS: payload[STATUS],
        _FACFDA_DECLARATION: payload[_FACFDA_DECLARATION],
        _FACFDA_INPUTS: list(payload[_FACFDA_INPUTS]),
        PA_ITEMS: copy.deepcopy(payload[ITEMS]),
        **{
            field: payload[field]
            for field in _FFDACFDA_CHAIN_INVARIANT_DIGEST_FIELDS
        },
        "policy_digest": payload[_FFDACFDA_DECISION_SITE_POLICY_DIGEST],
        _FFDACFDA_CHAIN_POLICY_VERSION: 1,
        _FFDACFDA_CHAIN_EFFECTIVE_AT: None,
    }


def _successor_view(raw: bytes) -> dict:
    """Structurally parse a successor predecessor."""
    payload, _signature, _increment = _parse_successor(raw)
    return {
        "kind": "successor",
        _FFDACFDA_CHAIN_ROOT_DIGEST: payload[_FFDACFDA_CHAIN_ROOT_DIGEST],
        _FFDACFDA_CHAIN_HEIGHT: payload[_FFDACFDA_CHAIN_HEIGHT],
        STATUS: payload[STATUS],
        _FACFDA_DECLARATION: copy.deepcopy(payload[_FACFDA_DECLARATION]),
        _FACFDA_INPUTS: list(payload[_FACFDA_INPUTS]),
        PA_ITEMS: copy.deepcopy(payload[ITEMS]),
        **{
            field: payload[field]
            for field in _FFDACFDA_CHAIN_INVARIANT_DIGEST_FIELDS
        },
        "policy_digest": payload[_FFDACFDA_CHAIN_NEW_POLICY_DIGEST],
        _FFDACFDA_CHAIN_POLICY_VERSION: payload[
            _FFDACFDA_CHAIN_POLICY_VERSION
        ],
        _FFDACFDA_CHAIN_EFFECTIVE_AT: payload[
            _FFDACFDA_CHAIN_EFFECTIVE_AT
        ],
    }


def _predecessor_view(raw: object) -> dict:
    """Parse predecessor bytes (root aggregate or successor packet).

    The packet kind is chosen from the payload key set so a malformed
    root raises the root aggregate error while a malformed successor
    raises the chain error.
    """
    if not isinstance(raw, bytes):
        raise TypeError("predecessor must be bytes")
    keys = _packet_payload_keys(raw)
    if keys is not None and _FFDACFDA_CHAIN_ROOT_DIGEST in keys:
        return _successor_view(raw)
    return _root_view(raw)


# -- Recomputing one stage verdict from prefix plus decision increment ---------

def _reverify_prefix_rows(
    prefix_rows: list[dict],
    fork_threshold: int,
    decision_site_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> list[dict]:
    """Re-derive each prefix row purely from its bound authenticated data.

    Structurally rejected rows and non-counted rows keep their bound
    conclusion; a counted row has its credential window re-checked, its
    exact identity and key version re-authorized against the hop decision
    site policy and its complete declaration re-tallied through the final
    fork decision aggregate chain fork decision rules.  A credential that
    is no longer usable raises :class:`AuthenticationError`; every other
    failure raises the chain error.
    """
    verified: list[dict] = []
    for row in prefix_rows:
        if row[_FACFDA_DECLARATION] is None:
            verified.append(copy.deepcopy(row))
            continue
        site = row[VD_ISSUER]
        key_version = row[KEY_VERSION]
        key_entry = None
        for candidate in validated_keyring.get(site, ()):
            if candidate[VERSION] == key_version:
                key_entry = candidate
                break
        if key_entry is None or key_entry[REVOKED]:
            raise AuthenticationError(
                f"prefix decision from {site!r} version {key_version} is no "
                "longer usable at this hop's moment"
            )
        if moment < key_entry[NOT_BEFORE] or moment > key_entry[NOT_AFTER]:
            raise AuthenticationError(
                f"prefix decision from {site!r} version {key_version} is not "
                "usable at this hop's moment"
            )
        allowed_versions = decision_site_policy[ADJ_SITES].get(site)
        if allowed_versions is None or key_version not in allowed_versions:
            raise _chain_invalid(
                f"prefix decision from {site!r} version {key_version} is no "
                "longer authorized by the hop decision site policy"
            )
        _reconcile_ffdacfda_declaration(
            row[_FACFDA_DECLARATION], fork_threshold,
            f"prefix item {row[ID]!r} declaration",
        )
        verified.append(copy.deepcopy(row))
    return verified


def _recompute_stage(
    previous: dict,
    increment: list[dict],
    materials: dict,
    decision_site_policy: dict,
    moment: int,
) -> dict:
    """Recompute the complete stage verdict at one moment.

    Every decision of the full stage -- the whole predecessor prefix plus
    this hop's increment -- is re-verified, authenticated and authorized
    at ``moment`` under the hop's decision site policy against the
    current keyring, then re-tallied with the prefix statements always
    winning.
    """
    stage_materials = dict(materials)
    stage_materials["decision_site_policy"] = decision_site_policy
    stage_materials["moment"] = moment

    increment_rows: list[dict] = []
    increment_digests: list[str] = []
    for item in increment:
        raw = item[_FFDACFDA_CHAIN_PACKET]
        increment_digests.append(hashlib.sha256(raw).hexdigest())
        increment_rows.append(_aggregate_ffdacfda_one(item, stage_materials))

    prefix_rows_verified = _reverify_prefix_rows(
        previous[PA_ITEMS],
        materials["proof_site_policy"][ADJ_THRESHOLD],
        decision_site_policy,
        materials["keyring"],
        moment,
    )

    full_inputs = list(previous[_FACFDA_INPUTS]) + increment_digests
    working_rows = copy.deepcopy(prefix_rows_verified)
    working_rows.extend(copy.deepcopy(increment_rows))
    status, declaration = _cfca_tally_chain_rows(
        working_rows,
        len(prefix_rows_verified),
        decision_site_policy[ADJ_THRESHOLD],
    )
    return {
        _FACFDA_INPUTS: full_inputs,
        PA_ITEMS: _pac_sort_rows(working_rows),
        STATUS: status,
        _FACFDA_DECLARATION: declaration,
    }


def _assert_extends(
    previous: dict, full_inputs: list[str], increment: list[dict],
    unchanged: bool,
) -> None:
    """Enforce the append-only decision prefix and disjoint identities.

    The predecessor's decision digests must remain the ordered prefix of
    the stage -- nothing is deleted, changed or reordered -- and the
    non-empty increment adds only new packet digests and new item ids.
    """
    prefix_inputs = previous[_FACFDA_INPUTS]
    if unchanged and not increment:
        raise _chain_invalid("an unchanged policy requires new decisions")
    if len(full_inputs) < len(prefix_inputs):
        raise _chain_invalid(
            "the decision sequence must extend the predecessor"
        )
    if full_inputs[:len(prefix_inputs)] != prefix_inputs:
        raise _chain_invalid(
            "the decision sequence must keep the predecessor as an ordered "
            "prefix; history must not be deleted, changed or reordered"
        )
    prefix_digests = set(prefix_inputs)
    prefix_ids = {row[ID] for row in previous[PA_ITEMS]}
    seen_digests: set[str] = set()
    seen_ids: set[str] = set()
    for item in increment:
        digest = hashlib.sha256(
            item[_FFDACFDA_CHAIN_PACKET]
        ).hexdigest()
        if digest in prefix_digests or digest in seen_digests:
            raise _chain_invalid(
                "a decision packet already in the prefix must not be "
                "appended again"
            )
        seen_digests.add(digest)
        item_id = item[ID]
        if item_id in prefix_ids or item_id in seen_ids:
            raise _chain_invalid(
                f"decision item id {item_id!r} is already part of the chain"
            )
        seen_ids.add(item_id)


def _assert_transition(previous: dict, verdict: dict) -> None:
    """Enforce the per-hop verdict state machine.

    ``insufficient`` may stay insufficient or become ``accepted`` or
    ``conflicted``; an ``accepted`` head only keeps the identical common
    declaration or advances to ``conflicted``; a ``conflicted`` verdict
    can never be masked by a later majority.
    """
    prev_status = previous[STATUS]
    new_status = verdict[STATUS]
    if prev_status == PA_STATUS_CONFLICTED:
        if new_status != PA_STATUS_CONFLICTED:
            raise _chain_invalid(
                "a conflicted aggregate can never be outvoted or fall back"
            )
    elif prev_status == PA_STATUS_ACCEPTED:
        if new_status == PA_STATUS_INSUFFICIENT:
            raise _chain_invalid(
                "an accepted aggregate must not fall back to insufficient"
            )
        if new_status == PA_STATUS_ACCEPTED:
            if verdict[_FACFDA_DECLARATION] != previous[_FACFDA_DECLARATION]:
                raise _chain_invalid(
                    "an accepted aggregate may only keep the same common "
                    "declaration"
                )


def _assert_sealer_authorized(
    old_policy: dict, new_policy: dict, issuer: str, key_version: int
) -> None:
    """The successor sealer must be authorized under both site policies."""
    if key_version not in old_policy[ADJ_SITES].get(issuer, frozenset()):
        raise _chain_invalid(
            f"sealer {issuer!r} version {key_version} is not authorized by "
            "the previous site policy"
        )
    if key_version not in new_policy[ADJ_SITES].get(issuer, frozenset()):
        raise _chain_invalid(
            f"sealer {issuer!r} version {key_version} is not authorized by "
            "the rotated site policy"
        )


def _assert_invariants(
    payload: dict | None, materials: dict, previous: dict | None,
) -> None:
    """Bind the six invariant policy digests of one hop.

    With ``payload`` given (verification) each bound digest must equal
    the digest of the matching shared policy; the digests must also stay
    invariant along the whole chain.
    """
    bundle_fields = (
        "prune_policy_digest",
        "authorization_policy_digest",
        "site_policy_digest",
        "signer_site_policy_digest",
        "adjudication_site_policy_digest",
        "proof_site_policy_digest",
    )
    for field, bundle_key in zip(
        _FFDACFDA_CHAIN_INVARIANT_DIGEST_FIELDS, bundle_fields
    ):
        digest = materials[bundle_key]
        if payload is not None and payload[field] != digest:
            raise _chain_invalid(
                f"bound {field} does not match the invariant policy"
            )
        if previous is not None and digest != previous[field]:
            raise _chain_invalid(
                f"the policy behind {field} must stay invariant along the "
                "chain"
            )


def _assert_policy_transition(
    previous: dict, old_policy: dict, new_policy: dict,
    bound_old_digest: str | None, bound_new_digest: str | None,
    bound_version: int | None,
) -> tuple[bool, int]:
    """Validate the old/new decision policy step against the predecessor.

    Over a root the old policy's sites and threshold must match the root
    aggregate decision site policy and its version is 1; over a successor
    the old policy must be exactly the policy bound by the predecessor and
    carry its version.  An unchanged policy keeps its version; a content
    change increments the version by exactly one.  Bound successor fields,
    when given, must match the policies.  Returns ``(unchanged,
    new_version)``.
    """
    old_digest = _pac_policy_digest(old_policy)
    new_digest = _pac_policy_digest(new_policy)
    if previous["kind"] == "root":
        if not _pac_policy_matches_root(old_policy, previous):
            raise _chain_invalid(
                "oldPolicy sites and threshold must match the root aggregate "
                "decision site policy"
            )
        prior_version = 1
    else:
        if old_digest != previous["policy_digest"]:
            raise _chain_invalid(
                "oldPolicy must equal the policy bound by the predecessor"
            )
        prior_version = previous[_FFDACFDA_CHAIN_POLICY_VERSION]
    if old_policy[DS_POLICY_VERSION] != prior_version:
        raise _chain_invalid(
            "oldPolicy policyVersion must match the predecessor version"
        )
    if bound_old_digest is not None and bound_old_digest != old_digest:
        raise _chain_invalid("bound oldPolicyDigest does not match")
    if bound_new_digest is not None and bound_new_digest != new_digest:
        raise _chain_invalid("bound newPolicyDigest does not match")
    unchanged = (
        old_policy[ADJ_SITES] == new_policy[ADJ_SITES]
        and old_policy[ADJ_THRESHOLD] == new_policy[ADJ_THRESHOLD]
    )
    new_version = new_policy[DS_POLICY_VERSION]
    if unchanged:
        if new_version != old_policy[DS_POLICY_VERSION]:
            raise _chain_invalid(
                "an unchanged policy must keep its policy version"
            )
    elif new_version != old_policy[DS_POLICY_VERSION] + 1:
        raise _chain_invalid(
            "a changed policy must increment policyVersion by exactly one"
        )
    if bound_version is not None and bound_version != new_version:
        raise _chain_invalid(
            "bound policyVersion does not match the policy"
        )
    return unchanged, new_version


def _assert_same_conclusion(
    verdict: dict, verdict_now: dict, credential_message: str,
) -> None:
    """Require the two stage moments to reach the exact same conclusion."""
    if (
        verdict_now[STATUS] != verdict[STATUS]
        or verdict_now[PA_ITEMS] != verdict[PA_ITEMS]
        or verdict_now[_FACFDA_DECLARATION] != verdict[_FACFDA_DECLARATION]
    ):
        raise AuthenticationError(credential_message)


def _assert_verdict_payload(payload: dict, verdict: dict) -> None:
    """Bind the recomputed stage conclusion into a successor payload."""
    if payload[ITEMS] != verdict[PA_ITEMS]:
        raise _chain_invalid(
            "bound items do not match the recomputed stage conclusion"
        )
    if payload[STATUS] != verdict[STATUS]:
        raise _chain_invalid(
            "bound status does not match the recomputed stage conclusion"
        )
    if payload[_FACFDA_DECLARATION] != verdict[_FACFDA_DECLARATION]:
        raise _chain_invalid(
            "bound common declaration does not match the recomputed "
            "conclusion"
        )


# -- Successor packet shape ----------------------------------------------------

def _bound_decisions(raw_items: object, where: str) -> list[dict]:
    """Parse the raw decision increment bound inside a successor packet."""
    if not isinstance(raw_items, list):
        raise TypeError(f"{where} decisions must be a list")
    validated: list[dict] = []
    for position, item in enumerate(raw_items):
        item_where = f"{where} decision {position}"
        if not isinstance(item, dict):
            raise TypeError(f"{item_where} must be an object")
        if set(item.keys()) != _FFDACFDA_CHAIN_DECISION_ITEM_KEYS:
            raise _chain_invalid(
                f"{item_where} must contain exactly the keys 'decision' and "
                "'id'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{item_where} id must be a str")
        if item_id == "":
            raise _chain_invalid(f"{item_where} id must be non-empty")
        packet_hex = item[_FFDACFDA_CHAIN_PACKET]
        if not isinstance(packet_hex, str):
            raise TypeError(f"{item_where} decision must be a str")
        try:
            packet = _hex_bytes(packet_hex)
        except ValueError as exc:
            raise _chain_invalid(
                f"{item_where} decision must be non-empty even-length "
                "lowercase hex"
            ) from exc
        validated.append({ID: item_id, _FFDACFDA_CHAIN_PACKET: packet})
    return validated


def _validated_rows(raw_rows: object, where: str) -> list[dict]:
    """Validate the bound aggregate rows of a chain successor payload.

    The row contract is the one
    :func:`aggregate_final_fork_decision_aggregate_chain_fork_decisions`
    binds; a counted row's complete declaration keeps the term-by-term
    proof digest vector and may carry the empty common fork edge set.  A
    wrong JSON type raises :class:`TypeError` and every other structural
    fault raises the chain error.
    """
    if not isinstance(raw_rows, list):
        raise TypeError(f"{where} items must be a list")
    if not raw_rows:
        raise _chain_invalid(f"{where} items must be a non-empty list")
    parsed_rows: list[dict] = []
    seen_ids: set[str] = set()
    for position, row in enumerate(raw_rows):
        row_where = f"{where} item {position}"
        if not isinstance(row, dict):
            raise TypeError(f"{row_where} must be an object")
        if set(row.keys()) != _PFDA_ROW_KEYS:
            raise _chain_invalid(
                f"{row_where} must contain exactly the keys 'conclusion', "
                "'digest', 'id', 'issuer', 'keyVersion', 'reason' and "
                "'declaration'"
            )
        row_id = row[ID]
        if not isinstance(row_id, str):
            raise TypeError(f"{row_where} id must be a str")
        if row_id == "":
            raise _chain_invalid(f"{row_where} id must be non-empty")
        if row_id in seen_ids:
            raise _chain_invalid(f"{row_where} repeats an id")
        seen_ids.add(row_id)
        digest = row[CP_DIGEST]
        if not isinstance(digest, str):
            raise TypeError(f"{row_where} digest must be a str")
        if not _prune_is_digest(digest):
            raise _chain_invalid(
                f"{row_where} digest must be 64 lowercase hex characters"
            )
        site = row[VD_ISSUER]
        if site is not None and not isinstance(site, str):
            raise TypeError(f"{row_where} issuer must be a str or null")
        if site == "":
            raise _chain_invalid(f"{row_where} issuer must be non-empty")
        key_version = row[KEY_VERSION]
        if isinstance(key_version, bool) or not isinstance(key_version, int):
            if key_version is not None:
                raise TypeError(
                    f"{row_where} keyVersion must be an int or null"
                )
        elif key_version <= 0:
            raise _chain_invalid(f"{row_where} keyVersion must be positive")
        if (site is None) != (key_version is None):
            raise _chain_invalid(
                f"{row_where} issuer and keyVersion must be null together"
            )
        conclusion = row[ADJ_CONCLUSION]
        if not isinstance(conclusion, str):
            raise TypeError(f"{row_where} conclusion must be a str")
        reason = row[ADJ_REASON]
        if conclusion == PA_CONCLUSION_VALID:
            if reason is not None:
                raise _chain_invalid(
                    f"{row_where} reason must be null for a valid row"
                )
        elif conclusion == PA_CONCLUSION_INVALID:
            if reason not in _PFDA_INVALID_REASONS:
                raise _chain_invalid(
                    f"{row_where} reason must be one of 'invalid', "
                    "'unauthenticated' or 'unauthorized'"
                )
        elif conclusion in (
            PA_CONCLUSION_DUPLICATE, PA_CONCLUSION_CONTRADICTION
        ):
            expected = (
                REASON_DUPLICATE
                if conclusion == PA_CONCLUSION_DUPLICATE
                else REASON_CONTRADICTION
            )
            if reason != expected:
                raise _chain_invalid(
                    f"{row_where} reason must match its conclusion"
                )
        else:
            raise _chain_invalid(f"{row_where} conclusion is not known")
        identity_present = reason != PA_CONCLUSION_INVALID
        if identity_present:
            if site is None:
                raise _chain_invalid(
                    f"{row_where} an authenticated or authorized row must "
                    "carry its issuer"
                )
        elif site is not None:
            raise _chain_invalid(
                f"{row_where} an invalid row must carry no issuer"
            )
        if conclusion == PA_CONCLUSION_INVALID:
            if row[_FACFDA_DECLARATION] is not None:
                raise _chain_invalid(
                    f"{row_where} an invalid row must carry no declaration"
                )
            declaration = None
        else:
            try:
                declaration = _validated_pfda_declaration(
                    row[_FACFDA_DECLARATION], f"{row_where} declaration",
                    invalid=_ffdacfda_invalid, positional_proofs=True,
                    allow_empty_edges=True,
                )
            except (
                InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError
            ) as exc:
                raise _chain_invalid(str(exc)) from exc
            if declaration is None:
                raise _chain_invalid(
                    f"{row_where} a counted row must carry its declaration"
                )
        parsed_rows.append({
            ADJ_CONCLUSION: conclusion,
            CP_DIGEST: digest,
            ID: row_id,
            VD_ISSUER: site,
            KEY_VERSION: key_version,
            ADJ_REASON: reason,
            _FACFDA_DECLARATION: declaration,
        })
    return parsed_rows


def _parse_successor(raw: object) -> tuple[dict, str, list[dict]]:
    """Validate successor bytes into ``(payload, signature, increment)``.

    A non-bytes argument or a public field of the wrong type raises
    :class:`TypeError`; every encoding, key-set, version, digest, row or
    increment fault raises the chain error.  The predecessor, policy,
    moment, tally and signature bindings are checked by the chain
    verifier.
    """
    data, payload, signature = _ffdac_parse_envelope(
        raw, noun="successor packet", invalid=_chain_invalid,
        reject_duplicate=_reject_duplicate_chain_keys,
        payload_keys=_FFDACFDA_CHAIN_SUCCESSOR_PAYLOAD_KEYS,
        payload_keys_error=(
            "successor packet payload must contain exactly the bound keys"
        ),
        top_keys=_FFDACFDA_CHAIN_TOP_KEYS,
    )

    for key in (
        _FFDACFDA_CHAIN_ROOT_DIGEST,
        _FFDACFDA_CHAIN_PREDECESSOR_DIGEST,
        _FFDACFDA_CHAIN_OLD_POLICY_DIGEST,
        _FFDACFDA_CHAIN_NEW_POLICY_DIGEST,
        *_FFDACFDA_CHAIN_INVARIANT_DIGEST_FIELDS,
    ):
        value = payload[key]
        if not isinstance(value, str):
            raise TypeError(f"payload {key} must be a str")
        if not _prune_is_digest(value):
            raise _chain_invalid(
                f"payload {key} must be 64 lowercase hex characters"
            )
    height = payload[_FFDACFDA_CHAIN_HEIGHT]
    if isinstance(height, bool) or not isinstance(height, int):
        raise TypeError("payload height must be an int")
    if height < 1:
        raise _chain_invalid("payload height must be a positive integer")
    policy_version = payload[_FFDACFDA_CHAIN_POLICY_VERSION]
    if isinstance(policy_version, bool) or not isinstance(policy_version, int):
        raise TypeError("payload policyVersion must be an int")
    if policy_version <= 0:
        raise _chain_invalid("payload policyVersion must be positive")
    effective = payload[_FFDACFDA_CHAIN_EFFECTIVE_AT]
    if isinstance(effective, bool) or not isinstance(effective, int):
        raise TypeError("payload effectiveAt must be an int")
    if effective < 0:
        raise _chain_invalid("payload effectiveAt must be non-negative")
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _chain_invalid("payload issuer must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _chain_invalid("payload keyVersion must be positive")
    packet_version = payload[VERSION]
    if isinstance(packet_version, bool) or not isinstance(
        packet_version, int
    ):
        raise TypeError("payload version must be an int")
    if packet_version != (
        FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISION_AGGREGATE_CHAIN_VERSION
    ):
        raise _chain_invalid("payload version must be the integer 1")

    status = payload[STATUS]
    if not isinstance(status, str):
        raise TypeError("payload status must be a str")
    if status not in _PA_STATUSES:
        raise _chain_invalid("payload status is not known")

    inputs = payload[_FACFDA_INPUTS]
    if not isinstance(inputs, list):
        raise TypeError("payload inputs must be a list")
    if not inputs:
        raise _chain_invalid("payload inputs must be a non-empty list")
    for position, digest in enumerate(inputs):
        if not isinstance(digest, str):
            raise TypeError(f"payload input {position} digest must be a str")
        if not _prune_is_digest(digest):
            raise _chain_invalid(
                f"payload input {position} digest must be 64 lowercase hex "
                "characters"
            )

    rows = _validated_rows(payload[ITEMS], "payload")
    if len(rows) != len(inputs):
        raise _chain_invalid(
            "the items must cover every decision and vice versa"
        )
    raw_declaration = payload[_FACFDA_DECLARATION]
    if raw_declaration is None:
        declaration = None
    else:
        try:
            declaration = _validated_pfda_declaration(
                raw_declaration, "payload declaration",
                invalid=_ffdacfda_invalid, positional_proofs=True,
                allow_empty_edges=True,
            )
        except (
            InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError
        ) as exc:
            raise _chain_invalid(str(exc)) from exc
    if status == PA_STATUS_ACCEPTED and declaration is None:
        raise _chain_invalid(
            "an accepted verdict must keep the common declaration"
        )
    if status == PA_STATUS_CONFLICTED and declaration is not None:
        raise _chain_invalid(
            "a conflicted verdict must bind a null common declaration"
        )

    increment = _bound_decisions(
        payload[_FFDACFDA_CHAIN_DECISIONS], "payload"
    )
    if not increment:
        raise _chain_invalid(
            "payload decisions must be a non-empty increment"
        )

    normalized_payload = {
        _FFDACFDA_CHAIN_ROOT_DIGEST: payload[_FFDACFDA_CHAIN_ROOT_DIGEST],
        _FFDACFDA_CHAIN_PREDECESSOR_DIGEST:
            payload[_FFDACFDA_CHAIN_PREDECESSOR_DIGEST],
        _FFDACFDA_CHAIN_HEIGHT: height,
        _FACFDA_INPUTS: list(inputs),
        ITEMS: rows,
        _FACFDA_DECLARATION: declaration,
        STATUS: status,
        **{
            field: payload[field]
            for field in _FFDACFDA_CHAIN_INVARIANT_DIGEST_FIELDS
        },
        _FFDACFDA_CHAIN_OLD_POLICY_DIGEST:
            payload[_FFDACFDA_CHAIN_OLD_POLICY_DIGEST],
        _FFDACFDA_CHAIN_NEW_POLICY_DIGEST:
            payload[_FFDACFDA_CHAIN_NEW_POLICY_DIGEST],
        _FFDACFDA_CHAIN_POLICY_VERSION: policy_version,
        _FFDACFDA_CHAIN_EFFECTIVE_AT: effective,
        _FFDACFDA_CHAIN_DECISIONS: [
            {ID: item[ID], _FFDACFDA_CHAIN_PACKET:
                item[_FFDACFDA_CHAIN_PACKET].hex()}
            for item in increment
        ],
        VD_ISSUER: issuer,
        KEY_VERSION: key_version,
        VERSION: (
            FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISION_AGGREGATE_CHAIN_VERSION
        ),
    }
    if _prune_compact({TICKET_PAYLOAD: normalized_payload,
                       SIGNATURE: signature}) != raw:
        raise _chain_invalid(
            "successor packet encoding is not the canonical compact form"
        )
    return normalized_payload, signature, increment


# -- Sealing a successor -------------------------------------------------------

def supersede_final_fork_decision_aggregate_chain_fork_decision_aggregate(
    root, predecessor, increment, prune_policy, authorization_policy,
    site_policy, signer_site_policy, adjudication_site_policy,
    proof_site_policy, old_policy, new_policy, keyring, moment,
    effective_at, issuer, version,
):
    """Issue one signed successor over a final fork decision aggregate
    chain fork decision aggregate.

    ``root`` is the chain's root aggregate packet
    (:func:`aggregate_final_fork_decision_aggregate_chain_fork_decisions`);
    for the first hop ``predecessor`` is that same root packet, and
    afterwards it is the previous successor packet, whose bound root
    digest must equal the SHA-256 of ``root``.  ``increment`` is the
    hop's non-empty decision list in the exact shape of that aggregate's
    items -- each exactly a unique non-empty ``id`` and ``decision``
    bytes (an
    :func:`adjudicate_final_fork_decision_aggregate_chain_forks` packet).
    The stage keeps every predecessor decision verbatim as an ordered
    digest prefix and only appends the increment.  The six invariant
    policies (the original prune policy, the site authorization policy,
    the fork-proof signer site policy, the adjudication signer site
    policy, the issuing adjudication site policy and the proof site
    policy), the root and the existing statements are never deleted,
    changed or reordered.  Only the **decision** site policy may rotate:
    ``old_policy``/``new_policy`` carry exactly ``sites``, ``threshold``
    and a positive ``policyVersion`` -- unchanged sites and threshold
    keep the version, any content change increments the version by
    exactly one, and the first versioned policy over a root carries
    version 1 and must equal the root's decision site policy.
    ``effective_at`` is the hop's non-negative effective moment and
    never moves backwards; ``moment`` is the issuance moment and
    ``issuer``/``version`` name the successor sealing key, which must be
    authorized under both decision policies and usable at both moments.

    Every hop re-verifies the *whole* stage at ``effective_at`` -- every
    prefix decision and every increment decision through the exact
    :func:`verify_final_fork_decision_aggregate_chain_fork_decision`
    rules, its credential window in the current keyring and its
    authorization under the new decision site policy -- then re-tallies
    the complete row set with the prefix statements always winning:
    same-site identical declarations count once, differing same-site
    declarations contradict, distinct sites must agree on the one
    complete declaration and cross-site disagreement stays
    ``conflicted``.  Supplemental decisions may move ``insufficient`` to
    ``accepted`` or ``conflicted``; an ``accepted`` head only keeps the
    identical common declaration or advances to ``conflicted``; and a
    ``conflicted`` verdict can never be masked.

    Returns canonical compact UTF-8 JSON with exactly ``payload`` and
    ``signature``; the payload binds the root digest, predecessor
    digest, continuous height, the predecessor decision digest prefix
    plus this hop's raw increment (bytes as lowercase hex), the
    recomputed items, common declaration and status, the six invariant
    policy digests, the old/new decision policy digests, the increasing
    policy version, the effective moment and the sealing identity,
    signed with HMAC-SHA256 under the exact issuer/version key.  A
    parameter or public field type fault raises :class:`TypeError` (a
    :class:`bool` never poses as an int); an empty value, a duplicate
    increment id, an illegal version, a wrong policy count or a
    backwards moment raises :class:`ValueError`; a malformed root raises
    :class:`InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError`;
    a malformed successor or a broken chain, prefix, state-machine or
    policy-history rule raises
    :class:`InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError`;
    a credential or signature fault raises :class:`AuthenticationError`.
    No file is read or written and no input is modified.
    """
    validated_increment = _validated_cfd_decision_items(increment)
    materials = _validated_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy, proof_site_policy,
    )
    validated_old = _validated_pac_site_policy(old_policy)
    validated_new = _validated_pac_site_policy(new_policy)
    _ffdac_bind_runtime(materials, keyring, moment)
    sign_moment = materials["moment"]
    effective = _fe_moment(effective_at, "effectiveAt")
    issuer, version = _ffdac_validated_signer(issuer, version)
    if not isinstance(root, bytes):
        raise TypeError("root must be bytes")
    if not isinstance(predecessor, bytes):
        raise TypeError("predecessor must be bytes")

    root_view = _root_view(root)
    previous = _predecessor_view(predecessor)
    if (
        previous[_FFDACFDA_CHAIN_ROOT_DIGEST]
        != root_view[_FFDACFDA_CHAIN_ROOT_DIGEST]
    ):
        raise _chain_invalid(
            "the predecessor must extend the given chain root"
        )

    old_digest = _pac_policy_digest(validated_old)
    new_digest = _pac_policy_digest(validated_new)
    unchanged, new_version = _assert_policy_transition(
        previous, validated_old, validated_new, None, None, None,
    )

    if previous[_FFDACFDA_CHAIN_EFFECTIVE_AT] is not None and effective < (
        previous[_FFDACFDA_CHAIN_EFFECTIVE_AT]
    ):
        raise ValueError("effectiveAt must not move backwards")

    # Sealing binds no incoming payload, so only the chain-invariance
    # half of the shared rule applies.
    _assert_invariants(None, materials, previous)

    new_plain = _pac_plain_site_policy(validated_new)
    verdict = _recompute_stage(
        previous, validated_increment, materials, new_plain, effective
    )
    _assert_extends(
        previous, verdict[_FACFDA_INPUTS], validated_increment, unchanged
    )
    _assert_transition(previous, verdict)
    _assert_sealer_authorized(validated_old, validated_new, issuer, version)

    # The whole stage (all prefix decisions and the increment) must also
    # authenticate identically at the issuance moment.
    verdict_now = _recompute_stage(
        previous, validated_increment, materials, new_plain, sign_moment
    )
    _assert_same_conclusion(
        verdict, verdict_now,
        "decision credentials are not all usable at the issuance moment",
    )

    signing_entry = _usable_checkpoint_key(
        materials["keyring"], issuer, version, effective
    )
    _usable_checkpoint_key(
        materials["keyring"], issuer, version, sign_moment
    )

    payload = {
        _FFDACFDA_CHAIN_ROOT_DIGEST: root_view[_FFDACFDA_CHAIN_ROOT_DIGEST],
        _FFDACFDA_CHAIN_PREDECESSOR_DIGEST:
            hashlib.sha256(predecessor).hexdigest(),
        _FFDACFDA_CHAIN_HEIGHT: previous[_FFDACFDA_CHAIN_HEIGHT] + 1,
        _FACFDA_INPUTS: verdict[_FACFDA_INPUTS],
        ITEMS: verdict[PA_ITEMS],
        _FACFDA_DECLARATION: verdict[_FACFDA_DECLARATION],
        STATUS: verdict[STATUS],
        **{
            field: materials[bundle_key]
            for field, bundle_key in zip(
                _FFDACFDA_CHAIN_INVARIANT_DIGEST_FIELDS,
                (
                    "prune_policy_digest",
                    "authorization_policy_digest",
                    "site_policy_digest",
                    "signer_site_policy_digest",
                    "adjudication_site_policy_digest",
                    "proof_site_policy_digest",
                ),
            )
        },
        _FFDACFDA_CHAIN_OLD_POLICY_DIGEST: old_digest,
        _FFDACFDA_CHAIN_NEW_POLICY_DIGEST: new_digest,
        _FFDACFDA_CHAIN_POLICY_VERSION: new_version,
        _FFDACFDA_CHAIN_EFFECTIVE_AT: effective,
        _FFDACFDA_CHAIN_DECISIONS: [
            {
                ID: item[ID],
                _FFDACFDA_CHAIN_PACKET:
                    item[_FFDACFDA_CHAIN_PACKET].hex(),
            }
            for item in validated_increment
        ],
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        VERSION: (
            FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISION_AGGREGATE_CHAIN_VERSION
        ),
    }
    signature = _ffdac_payload_signature(signing_entry, payload)
    return _prune_compact({TICKET_PAYLOAD: payload, SIGNATURE: signature})


# -- Offline chain verification ------------------------------------------------

def _verify_chain_root(
    root: bytes, materials: dict, decision_site_policy: dict,
) -> dict:
    """Verify one chain root aggregate from materials, in full.

    Runs the exact root aggregate verification (seven policy bindings,
    tally recomputation, signature), so every root fault keeps the root
    aggregate's own error classification.
    """
    payload, signature = _parse_ffdacfda(root)
    root_materials = dict(materials)
    root_materials["decision_site_policy_digest"] = hashlib.sha256(
        _prune_batch_site_policy_bytes(decision_site_policy)
    ).hexdigest()
    _ffdacfda_assert_policy_digests(payload, root_materials)
    _reconcile_ffdacfda_aggregate(
        payload,
        materials["proof_site_policy"][ADJ_THRESHOLD],
        decision_site_policy[ADJ_THRESHOLD],
    )
    _ffdac_assert_payload_signature(
        materials["keyring"], payload[VD_ISSUER], payload[KEY_VERSION],
        materials["moment"], payload, signature,
        "final fork decision aggregate chain fork decision aggregate "
        "signature does not match",
    )
    return payload


def _verify_hop(
    successor: bytes,
    previous: dict,
    previous_digest: str,
    old_policy: dict,
    new_policy: dict,
    materials: dict,
) -> dict:
    """Verify one successor against its predecessor and both policies."""
    payload, signature, increment = _parse_successor(successor)
    verify_moment = materials["moment"]

    if (
        payload[_FFDACFDA_CHAIN_ROOT_DIGEST]
        != previous[_FFDACFDA_CHAIN_ROOT_DIGEST]
    ):
        raise _chain_invalid("root digest does not match the chain root")
    if payload[_FFDACFDA_CHAIN_PREDECESSOR_DIGEST] != previous_digest:
        raise _chain_invalid(
            "predecessor digest does not match the previous packet"
        )
    if payload[_FFDACFDA_CHAIN_HEIGHT] != (
        previous[_FFDACFDA_CHAIN_HEIGHT] + 1
    ):
        raise _chain_invalid("height must increase by exactly one")

    unchanged, _new_version = _assert_policy_transition(
        previous, old_policy, new_policy,
        payload[_FFDACFDA_CHAIN_OLD_POLICY_DIGEST],
        payload[_FFDACFDA_CHAIN_NEW_POLICY_DIGEST],
        payload[_FFDACFDA_CHAIN_POLICY_VERSION],
    )

    effective = payload[_FFDACFDA_CHAIN_EFFECTIVE_AT]
    _ffdac_assert_effective_monotonic(
        previous[_FFDACFDA_CHAIN_EFFECTIVE_AT], effective, _chain_invalid
    )

    _assert_invariants(payload, materials, previous)

    increment_digests = [
        hashlib.sha256(item[_FFDACFDA_CHAIN_PACKET]).hexdigest()
        for item in increment
    ]
    expected_inputs = list(previous[_FACFDA_INPUTS]) + increment_digests
    if payload[_FACFDA_INPUTS] != expected_inputs:
        raise _chain_invalid(
            "bound inputs must be the predecessor prefix plus the increment"
        )
    _assert_extends(
        previous, expected_inputs, increment, unchanged
    )

    new_plain = _pac_plain_site_policy(new_policy)
    verdict = _recompute_stage(
        previous, increment, materials, new_plain, effective
    )
    verdict_now = _recompute_stage(
        previous, increment, materials, new_plain, verify_moment
    )
    _assert_transition(previous, verdict)
    _assert_sealer_authorized(
        old_policy, new_policy, payload[VD_ISSUER], payload[KEY_VERSION]
    )

    _assert_verdict_payload(payload, verdict)
    _assert_same_conclusion(
        verdict, verdict_now,
        "decision credentials are not all usable at the verification moment",
    )

    _usable_checkpoint_key(
        materials["keyring"], payload[VD_ISSUER], payload[KEY_VERSION],
        effective,
    )
    _ffdac_assert_payload_signature(
        materials["keyring"], payload[VD_ISSUER], payload[KEY_VERSION],
        verify_moment, payload, signature,
        "final fork decision aggregate chain fork decision aggregate "
        "successor signature does not match",
    )

    return {
        "packet": successor,
        "view": _successor_view(successor),
    }


def _verify_chain(
    root: bytes,
    successors: list,
    materials: dict,
    validated_policies: list[dict],
) -> dict:
    """Verify one aggregate chain hop by hop."""
    _verify_chain_root(
        root, materials, _pac_plain_site_policy(validated_policies[0])
    )
    root_digest = hashlib.sha256(root).hexdigest()
    view = _root_view(root)
    head_packet = root
    head_status = view[STATUS]
    head_declaration = view[_FACFDA_DECLARATION]
    head_policy_version = validated_policies[0][DS_POLICY_VERSION]

    previous_packet = root
    for index, successor in enumerate(successors):
        hop = _verify_hop(
            successor, view,
            hashlib.sha256(previous_packet).hexdigest(),
            validated_policies[index], validated_policies[index + 1],
            materials,
        )
        view = hop["view"]
        previous_packet = successor
        head_packet = successor
        head_status = view[STATUS]
        head_declaration = view[_FACFDA_DECLARATION]
        head_policy_version = view[_FFDACFDA_CHAIN_POLICY_VERSION]

    declaration_digest = None
    if head_declaration is not None:
        declaration_digest = hashlib.sha256(
            _prune_compact(head_declaration)
        ).hexdigest()
    return {
        _FFDACFDA_CHAIN_ROOT_DIGEST: root_digest,
        FAC_HEAD_DIGEST: hashlib.sha256(head_packet).hexdigest(),
        _FFDACFDA_CHAIN_HEIGHT: view[_FFDACFDA_CHAIN_HEIGHT],
        _FFDACFDA_CHAIN_POLICY_VERSION: head_policy_version,
        STATUS: head_status,
        _FFDACFDA_CHAIN_DECLARATION_DIGEST: declaration_digest,
    }


def verify_final_fork_decision_aggregate_chain_fork_decision_aggregate_chain(
    root, successors, prune_policy, authorization_policy, site_policy,
    signer_site_policy, adjudication_site_policy, proof_site_policy,
    policies, keyring, moment,
):
    """Verify one final fork decision aggregate chain fork decision
    aggregate supersession chain hop by hop, entirely offline.

    ``root`` is the chain's root aggregate packet
    (:func:`aggregate_final_fork_decision_aggregate_chain_fork_decisions`)
    and ``successors`` the ordered successor packets (possibly empty for
    a height-zero chain).  The six invariant policies are the original
    prune policy, the site authorization policy, the fork-proof signer
    site policy, the adjudication signer site policy, the issuing
    adjudication site policy and the proof site policy; ``policies`` is
    the complete versioned **decision** site policy history -- one entry
    per stage (the root policy plus one per successor), so its length is
    ``len(successors) + 1`` and the first carries ``policyVersion`` 1.
    Only the root, the ordered successors, the six invariant policies,
    the policy history, the current keyring and the verification moment
    are consulted; no file is read or written and no argument is
    modified.

    An empty successor list still verifies the root in full and returns
    height zero.  For a non-empty chain every hop is re-checked: the
    root, predecessor and height links, the append-only ordered
    decision digest prefix, the old/new policy digests and single-step
    version rule, the non-decreasing effective moment, the six invariant
    policies, a full re-verification of *every* decision of the stage
    (the whole prefix plus the increment) at the hop's effective moment
    against its credentials, authorization and threshold and at the
    verification moment too, the full stage re-tally (same-site
    duplicates and contradictions, cross-site agreement and the
    threshold), the verdict state machine and dual-policy sealer
    authorization, and the exact-issuer/version HMAC with a credential
    usable at both moments.

    On success returns a fresh depth-independent mapping with the fixed
    keys ``rootDigest``, ``headDigest``, ``height`` (0 for a bare root),
    ``policyVersion`` (the head policy's version), ``status`` and
    ``declarationDigest`` (the SHA-256 of the canonical common
    declaration when one is bound, otherwise null).  A non-bytes argument
    or a public field of the wrong type raises :class:`TypeError`; an
    empty value, an illegal version, a wrong policy count or a backwards
    moment raises :class:`ValueError`; a bad root raises
    :class:`InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError`;
    a bad successor, link, prefix, state transition, policy history or
    recomputation raises
    :class:`InvalidFinalForkDecisionAggregateChainForkDecisionAggregateChainError`;
    a credential or signature fault raises :class:`AuthenticationError`.
    """
    if not isinstance(root, bytes):
        raise TypeError("root must be bytes")
    if not isinstance(successors, list):
        raise TypeError("successors must be a list")
    for index, successor in enumerate(successors):
        if not isinstance(successor, bytes):
            raise TypeError(f"successor {index} must be bytes")
    materials = _validated_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy, proof_site_policy,
    )
    validated_policies = _pac_validated_policy_sequence(policies)
    _ffdac_bind_runtime(materials, keyring, moment)
    if len(validated_policies) != len(successors) + 1:
        raise ValueError(
            "policies must provide one entry per chain stage (one more than "
            "the number of successors)"
        )
    if validated_policies[0][DS_POLICY_VERSION] != 1:
        raise ValueError("the root stage policy must carry policyVersion 1")

    return _verify_chain(root, successors, materials, validated_policies)
