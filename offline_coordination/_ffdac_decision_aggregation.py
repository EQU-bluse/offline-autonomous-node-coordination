"""Batch verification and cross-site aggregation of final fork decision
aggregate chain fork decisions -- private implementation module.

This module is the extracted home of the
:mod:`offline_coordination.replication` layer in which the single final
fork decision aggregate chain fork decision ruling
(``verify_final_fork_decision_aggregate_chain_fork_decision``, which binds
six policy digests) gets a batch re-check and a cross-site convergence
aggregate.  The batch verifier validates the decision list, the five
invariant policies, the proof site policy, the keyring and the moment in
full before any decision is parsed and reports each decision in input
order and in isolation.  The aggregate re-verifies, authenticates and
authorizes every decision against a new decision site policy, treats the
complete declaration (the common fork edge set -- empty for a fork-free
decision -- the stably sorted per-item conclusions, the term-by-term
proof digest vector and the overall status) as one site's vote, and seals
the threshold outcome with seven policy digest bindings.  The offline
aggregate review recomputes every binding from the aggregate bytes alone.

This is an internal boundary, not a public entry point: the public
functions and the dedicated aggregate error are re-exported from
``offline_coordination.replication`` under their historical names, with
identical call signatures and class object identity.

The shared responsibilities of the three entry points live in exactly one
component each: ``_ffdacf_validated_decision_materials`` (with
``_ffdac_bind_runtime`` and ``_ffdacfda_bind_decision_policy``) owns the
input pre-validation, ``_FFDACFDA_DIGEST_BINDINGS`` together with
``_ffdacfda_policy_digests``/``_ffdacfda_assert_policy_digests`` owns the
seven policy digest bindings, ``_ffdac_assert_payload_signature`` (raise
style) and ``_ffdacfd_key_entry_at`` (row style) own the signature
identity determination, ``_tally_pfda_rows`` with
``_ffdacfda_row_sort_key`` owns the deterministic site vote merging,
``_fac_chain_item_report`` owns the fixed-key-order batch item report,
``_reject_duplicate_pfda_keys`` owns the duplicate-key rejection, and
``_ffdac_parse_envelope``/``_prune_compact`` own the canonical encoding --
every one of them imported from ``offline_coordination.replication`` or
defined once below, never copied.
"""

from __future__ import annotations

import copy
import hashlib
import hmac

from offline_coordination.replication import (
    ADJ_CONCLUSION,
    ADJ_REASON,
    ADJ_SITES,
    ADJ_THRESHOLD,
    AuthenticationError,
    CP_DIGEST,
    ID,
    ITEMS,
    InvalidFinalForkDecisionAggregateChainForkDecisionError,
    KEY_VERSION,
    NOT_AFTER,
    NOT_BEFORE,
    PAFD_COMMON,
    PAFD_EDGES,
    PAFD_FORK_PROOF_DIGEST,
    PAFD_PROOFS,
    PA_CONCLUSION_CONTRADICTION,
    PA_CONCLUSION_DUPLICATE,
    PA_CONCLUSION_INVALID,
    PA_CONCLUSION_VALID,
    PA_REASON_UNAUTHENTICATED,
    PA_REASON_UNAUTHORIZED,
    PFDA_CONCLUSIONS,
    PFDA_PROOFS,
    REASON_CONTRADICTION,
    REASON_DUPLICATE,
    REVOKED,
    SIGNATURE,
    STATUS,
    TICKET_PAYLOAD,
    VD_ISSUER,
    VERSION,
    _FACFDA_ADJUDICATION_SITE_POLICY_DIGEST,
    _FACFDA_AGGREGATE_DIGEST,
    _FACFDA_AUTHORIZATION_POLICY_DIGEST,
    _FACFDA_DECISION_SITE_POLICY_DIGEST,
    _FACFDA_DECLARATION,
    _FACFDA_INPUTS,
    _FACFDA_PACKET,
    _FACFDA_PRUNE_POLICY_DIGEST,
    _FACFDA_SIGNER_SITE_POLICY_DIGEST,
    _FACFDA_SITE_POLICY_DIGEST,
    _FACFD_INVALID,
    _FACFD_UNAUTHENTICATED,
    _FACFD_VERIFIED,
    _FFDACF_PROOF_SITE_POLICY_DIGEST,
    _PA_STATUSES,
    _PFDA_INVALID_REASONS,
    _PFDA_ROW_KEYS,
    _fac_chain_item_report,
    _ffdac_assert_payload_signature,
    _ffdac_bind_runtime,
    _ffdac_parse_envelope,
    _ffdac_payload_signature,
    _ffdac_validated_signer,
    _ffdacf_assert_decision_payload,
    _ffdacf_decision_invalid,
    _ffdacf_validated_decision_materials,
    _parse_ffdacf_decision,
    _pfda_aggregate_row,
    _pfda_declaration,
    _prune_batch_site_policy_bytes,
    _prune_compact,
    _prune_is_digest,
    _reconcile_pafd,
    _reject_duplicate_pfda_keys,
    _tally_pfda_rows,
    _usable_checkpoint_key,
    _validated_cfd_decision_items,
    _validated_pfda_declaration,
    _validated_prune_batch_site_policy,
    _verify_ffdacf_decision_core,
)


FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISIONS_VERSION = 1
FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISION_AGGREGATE_VERSION = 1

_FFDACFD_VERIFIED = _FACFD_VERIFIED
_FFDACFD_INVALID = _FACFD_INVALID
_FFDACFD_UNAUTHENTICATED = _FACFD_UNAUTHENTICATED

_FFDACFDA_PACKET = _FACFDA_PACKET
_FFDACFDA_PROOF_SITE_POLICY_DIGEST = _FFDACF_PROOF_SITE_POLICY_DIGEST
_FFDACFDA_DECISION_SITE_POLICY_DIGEST = _FACFDA_DECISION_SITE_POLICY_DIGEST

# The seven policy digest bindings of one aggregate payload, each field
# paired with its key in the shared materials bundle, in payload order.
_FFDACFDA_DIGEST_BINDINGS = (
    (_FACFDA_PRUNE_POLICY_DIGEST, "prune_policy_digest"),
    (_FACFDA_AUTHORIZATION_POLICY_DIGEST, "authorization_policy_digest"),
    (_FACFDA_SITE_POLICY_DIGEST, "site_policy_digest"),
    (_FACFDA_SIGNER_SITE_POLICY_DIGEST, "signer_site_policy_digest"),
    (_FACFDA_ADJUDICATION_SITE_POLICY_DIGEST,
     "adjudication_site_policy_digest"),
    (_FFDACFDA_PROOF_SITE_POLICY_DIGEST, "proof_site_policy_digest"),
    (_FFDACFDA_DECISION_SITE_POLICY_DIGEST, "decision_site_policy_digest"),
)
_FFDACFDA_DIGEST_FIELDS = tuple(
    field for field, _ in _FFDACFDA_DIGEST_BINDINGS
)

_FFDACFDA_PAYLOAD_KEYS = frozenset((
    _FACFDA_INPUTS,
    VD_ISSUER,
    ITEMS,
    KEY_VERSION,
    _FACFDA_PRUNE_POLICY_DIGEST,
    _FACFDA_AUTHORIZATION_POLICY_DIGEST,
    _FACFDA_SITE_POLICY_DIGEST,
    _FACFDA_SIGNER_SITE_POLICY_DIGEST,
    _FACFDA_ADJUDICATION_SITE_POLICY_DIGEST,
    _FFDACFDA_PROOF_SITE_POLICY_DIGEST,
    _FFDACFDA_DECISION_SITE_POLICY_DIGEST,
    _FACFDA_DECLARATION,
    STATUS,
    VERSION,
))
_FFDACFDA_RESULT_KEYS = (
    _FACFDA_AGGREGATE_DIGEST,
    _FACFDA_INPUTS,
    VD_ISSUER,
    ITEMS,
    KEY_VERSION,
    _FACFDA_PRUNE_POLICY_DIGEST,
    _FACFDA_AUTHORIZATION_POLICY_DIGEST,
    _FACFDA_SITE_POLICY_DIGEST,
    _FACFDA_SIGNER_SITE_POLICY_DIGEST,
    _FACFDA_ADJUDICATION_SITE_POLICY_DIGEST,
    _FFDACFDA_PROOF_SITE_POLICY_DIGEST,
    _FFDACFDA_DECISION_SITE_POLICY_DIGEST,
    _FACFDA_DECLARATION,
    STATUS,
    VERSION,
)


class InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError(
    ValueError
):
    """A final fork decision aggregate chain fork decision aggregate
    breaks its contract."""

    # The class keeps its historical public module path: it is re-exported
    # from ``offline_coordination.replication``.
    __module__ = "offline_coordination.replication"


def _ffdacfda_invalid(
    message: str,
) -> InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError:
    return (
        InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError(
            "invalid final fork decision aggregate chain fork decision "
            f"aggregate: {message}"
        )
    )


def _reject_duplicate_ffdacfda_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate aggregate keys into an
    error.

    The duplicate-key rule itself lives in exactly one place:
    :func:`_reject_duplicate_pfda_keys`.
    """
    return _reject_duplicate_pfda_keys(pairs, _ffdacfda_invalid)


# -- Shared components of the batch/aggregate boundary ------------------------

def _ffdacfda_bind_decision_policy(
    materials: dict, decision_site_policy: object
) -> dict:
    """Validate the seventh (decision site) policy into the bundle."""
    validated = _validated_prune_batch_site_policy(decision_site_policy)
    materials["decision_site_policy"] = validated
    materials["decision_site_policy_digest"] = hashlib.sha256(
        _prune_batch_site_policy_bytes(validated)
    ).hexdigest()
    return materials


def _ffdacfda_policy_digests(materials: dict) -> dict:
    """The seven bound policy digest fields of one aggregate payload."""
    return {
        field: materials[bundle_key]
        for field, bundle_key in _FFDACFDA_DIGEST_BINDINGS
    }


def _ffdacfda_assert_policy_digests(
    payload: dict, materials: dict
) -> None:
    """Bind every aggregate payload policy digest to the materials."""
    for field, expected in _ffdacfda_policy_digests(materials).items():
        if payload[field] != expected:
            raise _ffdacfda_invalid(
                f"{field} does not match its expected policy"
            )


def _ffdacfd_key_entry_at(
    keyring: dict[str, list[dict]], issuer: str, key_version: int,
    moment: int,
) -> dict | None:
    """The exact issuer/version key usable at ``moment``, or ``None``.

    The row-style counterpart of :func:`_usable_checkpoint_key` for the
    isolated per-decision aggregation rows: unknown, revoked,
    not-yet-valid or expired credentials yield ``None`` -- never a
    fallback to another version -- so one decision's credential fault
    rejects just its own row.
    """
    entry = None
    for candidate in keyring.get(issuer, ()):
        if candidate[VERSION] == key_version:
            entry = candidate
            break
    if entry is None or entry[REVOKED]:
        return None
    if moment < entry[NOT_BEFORE] or moment > entry[NOT_AFTER]:
        return None
    return entry


def _ffdacfda_row_sort_key(row: dict) -> tuple:
    """Stable per-decision row order: issuer then id, with the rows
    carrying no authenticated identity first."""
    return (row[VD_ISSUER] is not None, row[VD_ISSUER] or "", row[ID])


def _verify_ffdacfd_decision_item(item: dict, materials: dict) -> dict:
    """Verify one final fork decision aggregate chain fork decision in
    isolation.

    Unknown, revoked, not-yet-valid or expired credentials and a wrong
    signature make the item ``unauthenticated``; every encoding,
    key-set, digest, ordering, tally or binding fault makes it
    ``invalid-decision``; a passing decision is ``verified``.
    """
    item_id = item[ID]
    try:
        result = _verify_ffdacf_decision_core(
            item[_FFDACFDA_PACKET], materials
        )
    except AuthenticationError as exc:
        return _fac_chain_item_report(
            item_id, _FFDACFD_UNAUTHENTICATED, str(exc), None
        )
    except (InvalidFinalForkDecisionAggregateChainForkDecisionError,
            TypeError) as exc:
        # A TypeError here can only come from a wrong JSON field type
        # *inside* the decision bytes; the public argument types were
        # all validated before the batch ran.
        return _fac_chain_item_report(
            item_id, _FFDACFD_INVALID, str(exc), None
        )
    return _fac_chain_item_report(
        item_id, _FFDACFD_VERIFIED, None, result
    )


def verify_final_fork_decision_aggregate_chain_fork_decisions(
    items, prune_policy, authorization_policy, site_policy,
    signer_site_policy, adjudication_site_policy, proof_site_policy,
    keyring, moment,
):
    """Verify a batch of final fork decision aggregate chain fork
    decisions offline.

    ``items`` is a non-empty list; each item is a dict with exactly the
    keys ``id`` (a non-empty str, unique across the batch) and
    ``decision`` (the canonical signed decision bytes
    :func:`adjudicate_final_fork_decision_aggregate_chain_forks`
    produced).  The whole batch structure, the five invariant policies
    (the original prune policy, the site authorization policy, the
    fork-proof signer site policy, the adjudication signer site policy
    and the issuing adjudication site policy), the proof site policy,
    the keyring and the moment are validated in full before any decision
    is parsed, so a batch-level fault never yields a partial report:
    container, element or field type faults raise :class:`TypeError` (a
    :class:`bool` never poses as an int) and an empty list, an empty or
    duplicate id or a wrong item key set raises :class:`ValueError` (the
    shared materials keep their single-decision classification).  Only
    these batch-level faults raise.

    Each decision is then verified independently, in strict input
    order, through the exact
    :func:`verify_final_fork_decision_aggregate_chain_fork_decision`
    rules: one decision's failure never stops a later decision or alters
    an earlier report.  A structural or binding fault makes the item
    ``invalid-decision``; unknown, revoked, not-yet-valid or expired
    credentials or a wrong signature make it ``unauthenticated``; a
    passing decision is ``verified``.

    The top-level result is a fresh dict with the fixed keys ``items``
    and ``version`` (the integer 1); each item report preserves input
    order and carries, in this key order, ``error`` (null exactly when
    verified, otherwise a definite non-empty message), ``id``,
    ``result`` (a fresh independent copy of the single-decision result
    when verified, otherwise null -- the identity of an unauthenticated
    payload never enters a result) and ``status``.  Repeated calls
    return equal but mutually independent results.  No file is read or
    written and no input is modified.
    """
    validated_items = _validated_cfd_decision_items(items)
    materials = _ffdacf_validated_decision_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy, proof_site_policy,
    )
    _ffdac_bind_runtime(materials, keyring, moment)
    return {
        ITEMS: [
            _verify_ffdacfd_decision_item(item, materials)
            for item in validated_items
        ],
        VERSION:
            FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISIONS_VERSION,
    }


def _aggregate_ffdacfda_one(item: dict, materials: dict) -> dict:
    """Re-verify, authenticate and authorize one decision in isolation.

    The decision bytes first pass the exact final fork decision
    aggregate chain fork decision structural, positional-proof and
    six-policy binding rules, then the HMAC is checked against the
    current keyring, and finally the exact payload issuer and key
    version are authorized against the decision site policy with no
    fallback.  Any failure rejects just this row with one fixed reason
    (``invalid``, ``unauthenticated`` or ``unauthorized``) and never
    affects the other items.
    """
    item_id = item[ID]
    raw = item[_FFDACFDA_PACKET]
    decision_digest = hashlib.sha256(raw).hexdigest()

    def invalid_row() -> dict:
        return _pfda_aggregate_row(
            item_id, decision_digest, None, None, None,
            PA_CONCLUSION_INVALID, PA_CONCLUSION_INVALID,
        )

    try:
        payload, signature = _parse_ffdacf_decision(raw)
    except (TypeError, ValueError):
        return invalid_row()

    site = payload[VD_ISSUER]
    key_version = payload[KEY_VERSION]

    try:
        _ffdacf_assert_decision_payload(payload, materials)
    except InvalidFinalForkDecisionAggregateChainForkDecisionError:
        return invalid_row()

    def unauthenticated_row() -> dict:
        return _pfda_aggregate_row(
            item_id, decision_digest, site, key_version, None,
            PA_CONCLUSION_INVALID, PA_REASON_UNAUTHENTICATED,
        )

    key_entry = _ffdacfd_key_entry_at(
        materials["keyring"], site, key_version, materials["moment"]
    )
    if key_entry is None or not hmac.compare_digest(
        _ffdac_payload_signature(key_entry, payload), signature
    ):
        return unauthenticated_row()

    # The exact-issuer HMAC established the site/version identity, so an
    # authorized-policy miss may carry that identity.
    allowed_versions = materials["decision_site_policy"][ADJ_SITES].get(site)
    if allowed_versions is None or key_version not in allowed_versions:
        return _pfda_aggregate_row(
            item_id, decision_digest, site, key_version, None,
            PA_CONCLUSION_INVALID, PA_REASON_UNAUTHORIZED,
        )

    return _pfda_aggregate_row(
        item_id, decision_digest, site, key_version,
        _pfda_declaration(payload), PA_CONCLUSION_VALID, None,
    )


def aggregate_final_fork_decision_aggregate_chain_fork_decisions(
    items, prune_policy, authorization_policy, site_policy,
    signer_site_policy, adjudication_site_policy, proof_site_policy,
    decision_site_policy, keyring, moment, issuer, version,
):
    """Aggregate multi-site final fork decision aggregate chain fork
    decisions into one signed cross-site aggregate offline.

    ``items`` is a non-empty list; each item contains exactly a unique,
    non-empty str ``id`` and ``decision`` bytes produced by
    :func:`adjudicate_final_fork_decision_aggregate_chain_forks`; the
    whole batch structure is validated before any decision is parsed.
    ``prune_policy`` is the shared invariant original pruning policy,
    ``authorization_policy`` the invariant site authorization policy,
    ``site_policy`` the invariant fork-proof signer site policy,
    ``signer_site_policy`` the invariant adjudication signer site
    policy, ``adjudication_site_policy`` the invariant issuing
    adjudication site policy and ``proof_site_policy`` the proof signer
    site policy the decisions were issued against;
    ``decision_site_policy`` carries exactly ``sites`` (a non-empty
    mapping of each decision site authorized to hand over decisions to
    its non-empty set of allowed positive key versions) and
    ``threshold`` (a positive integer no greater than the site count).
    ``keyring`` follows the existing rules, ``moment`` is the current
    time and ``issuer``/``version`` name the aggregate signing identity
    and key version.  No file is read or written and no input is
    modified.

    Every decision is first re-verified on its own through the exact
    :func:`verify_final_fork_decision_aggregate_chain_fork_decision`
    rules -- canonical structure, all six decision policy digest
    bindings, the term-by-term proof digest bindings and a full
    re-tally of the bound per-proof rows -- then authenticated against
    the current keyring by its exact payload issuer and key version,
    and finally authorized precisely against ``decision_site_policy``
    with no fallback: a structurally illegal decision or one with a
    broken binding is recorded ``invalid`` with reason ``invalid`` (and
    carries no identity), unknown, revoked, not-yet-valid or expired
    credentials or a wrong signature ``unauthenticated``, and an
    authenticated but unauthorized site or key version
    ``unauthorized``, each rejecting only that item while the others
    continue.  A valid decision counts as the issuing site's complete
    declaration: the common fork edge set (empty for a fork-free
    decision), the per-item conclusions (stably sorted by site then id,
    each entry carrying its conclusion, proof digest, authenticated
    fork edges or null, id, reason and site), the term-by-term proof
    digest vector and the overall status.  For one site, declarations
    fully identical on every field count once and exact repeats are
    ``duplicate``; any field difference is a ``contradiction``.
    Distinct sites must agree on that same complete declaration -- any
    difference makes the aggregate ``conflicted``, the common
    declaration is bound null and no majority can outvote the
    disagreement.  One unique declaration backed by at least the
    threshold of distinct sites is ``accepted``; short of the
    threshold it stays ``insufficient`` but still carries that common
    declaration; with no valid vote the declaration is null.

    The result is one canonical compact UTF-8 JSON object with
    recursively sorted keys, non-ASCII preserved and no trailing byte,
    carrying exactly ``payload`` and ``signature``.  The payload binds
    exactly ``inputs`` (each input decision's SHA-256 in the original
    input order), ``issuer``, ``items`` (the rows stably sorted by
    issuer then id, each carrying ``conclusion``, the decision
    ``digest``, ``id``, ``issuer``, ``keyVersion``, ``reason`` and the
    authenticated ``declaration`` or null), ``keyVersion``,
    ``prunePolicyDigest``, ``authorizationPolicyDigest``,
    ``sitePolicyDigest``, ``signerSitePolicyDigest``,
    ``adjudicationSitePolicyDigest``, ``proofSitePolicyDigest``,
    ``decisionSitePolicyDigest``, ``declaration`` (the one common
    complete declaration, or null), ``status`` and ``version`` (the
    integer 1) -- seven policy digests in total.  The signature is the
    lowercase hex HMAC-SHA256 of the canonical compact payload bytes
    under the exact issuer/version key.

    A parameter, container or public field type fault raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    empty list, an empty or duplicate id or an illegal policy,
    threshold, moment, site, version or issuer raises
    :class:`ValueError`; unknown, revoked, not-yet-valid or expired
    aggregate credentials raise :class:`AuthenticationError`.
    """
    validated_items = _validated_cfd_decision_items(items)
    materials = _ffdacf_validated_decision_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy, proof_site_policy,
    )
    _ffdacfda_bind_decision_policy(materials, decision_site_policy)
    _ffdac_bind_runtime(materials, keyring, moment)
    issuer, version = _ffdac_validated_signer(issuer, version)

    rows = [
        _aggregate_ffdacfda_one(item, materials)
        for item in validated_items
    ]
    input_digests = [row[CP_DIGEST] for row in rows]
    status, common_declaration = _tally_pfda_rows(
        rows, materials["decision_site_policy"][ADJ_THRESHOLD]
    )
    rows.sort(key=_ffdacfda_row_sort_key)

    signing_entry = _usable_checkpoint_key(
        materials["keyring"], issuer, version, materials["moment"]
    )
    payload = {
        _FACFDA_INPUTS: input_digests,
        VD_ISSUER: issuer,
        ITEMS: rows,
        KEY_VERSION: version,
        **_ffdacfda_policy_digests(materials),
        _FACFDA_DECLARATION: common_declaration,
        STATUS: status,
        VERSION:
            FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISION_AGGREGATE_VERSION,
    }
    signature = _ffdac_payload_signature(signing_entry, payload)
    return _prune_compact({TICKET_PAYLOAD: payload, SIGNATURE: signature})


def _parse_ffdacfda(raw: object) -> tuple[dict, str]:
    """Validate final fork decision aggregate chain fork decision
    aggregate bytes structurally.

    A non-bytes argument or a public field of the wrong JSON type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, digest, ordering, row-shape or
    declaration-shape fault raises
    :class:`InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError`.
    The seven policy digests, the tally and the credential bindings are
    checked by
    :func:`verify_final_fork_decision_aggregate_chain_fork_decision_aggregate`.
    A counted declaration may carry the empty common fork edge set (a
    fork-free decision).
    """
    data, payload, signature = _ffdac_parse_envelope(
        raw, noun="aggregate packet", invalid=_ffdacfda_invalid,
        reject_duplicate=_reject_duplicate_ffdacfda_keys,
        payload_keys=_FFDACFDA_PAYLOAD_KEYS,
        payload_keys_error=(
            "aggregate packet payload must contain exactly the keys "
            "'inputs', 'issuer', 'items', 'keyVersion', "
            "'prunePolicyDigest', 'authorizationPolicyDigest', "
            "'sitePolicyDigest', 'signerSitePolicyDigest', "
            "'adjudicationSitePolicyDigest', 'proofSitePolicyDigest', "
            "'decisionSitePolicyDigest', 'declaration', 'status' and "
            "'version'"
        ),
        invalid_noun="aggregate packet",
    )

    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("aggregate payload issuer must be a str")
    if issuer == "":
        raise _ffdacfda_invalid(
            "aggregate payload issuer must be a non-empty str"
        )
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("aggregate payload keyVersion must be an int")
    if key_version <= 0:
        raise _ffdacfda_invalid(
            "aggregate payload keyVersion must be positive"
        )
    for field in _FFDACFDA_DIGEST_FIELDS:
        digest = payload[field]
        if not isinstance(digest, str):
            raise TypeError(f"aggregate payload {field} must be a str")
        if not _prune_is_digest(digest):
            raise _ffdacfda_invalid(
                f"aggregate payload {field} must be 64 lowercase hex "
                "characters"
            )
    status = payload[STATUS]
    if not isinstance(status, str):
        raise TypeError("aggregate status must be a str")
    if status not in _PA_STATUSES:
        raise _ffdacfda_invalid("aggregate status is not a known status")
    aggregate_version = payload[VERSION]
    if isinstance(aggregate_version, bool) or not isinstance(
        aggregate_version, int
    ):
        raise TypeError("aggregate payload version must be an int")
    if aggregate_version != (
        FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISION_AGGREGATE_VERSION
    ):
        raise _ffdacfda_invalid(
            "aggregate payload version must be the integer 1"
        )

    inputs = payload[_FACFDA_INPUTS]
    if not isinstance(inputs, list):
        raise TypeError("aggregate inputs must be a list")
    if not inputs:
        raise _ffdacfda_invalid("aggregate inputs must be a non-empty list")
    for position, digest in enumerate(inputs):
        if not isinstance(digest, str):
            raise TypeError(f"aggregate input {position} digest must be a str")
        if not _prune_is_digest(digest):
            raise _ffdacfda_invalid(
                f"aggregate input {position} digest must be 64 lowercase "
                "hex characters"
            )

    rows = payload[ITEMS]
    if not isinstance(rows, list):
        raise TypeError("aggregate items must be a list")
    if not rows:
        raise _ffdacfda_invalid("aggregate items must be a non-empty list")
    if len(rows) != len(inputs):
        raise _ffdacfda_invalid(
            "the items must cover every input and vice versa"
        )
    seen_row_ids: set[str] = set()
    parsed_rows: list[dict] = []
    for position, row in enumerate(rows):
        where = f"aggregate item {position}"
        if not isinstance(row, dict):
            raise TypeError(f"{where} must be an object")
        if set(row.keys()) != _PFDA_ROW_KEYS:
            raise _ffdacfda_invalid(
                f"{where} must contain exactly the keys 'conclusion', "
                "'digest', 'id', 'issuer', 'keyVersion', 'reason' and "
                "'declaration'"
            )
        row_id = row[ID]
        if not isinstance(row_id, str):
            raise TypeError(f"{where} id must be a str")
        if row_id == "":
            raise _ffdacfda_invalid(f"{where} id must be non-empty")
        if row_id in seen_row_ids:
            raise _ffdacfda_invalid(f"{where} repeats an id")
        seen_row_ids.add(row_id)
        digest = row[CP_DIGEST]
        if not isinstance(digest, str):
            raise TypeError(f"{where} digest must be a str")
        if not _prune_is_digest(digest):
            raise _ffdacfda_invalid(
                f"{where} digest must be 64 lowercase hex characters"
            )
        row_site = row[VD_ISSUER]
        if row_site is not None and not isinstance(row_site, str):
            raise TypeError(f"{where} issuer must be a str or null")
        if row_site == "":
            raise _ffdacfda_invalid(f"{where} issuer must be non-empty")
        row_key_version = row[KEY_VERSION]
        if isinstance(row_key_version, bool) or not isinstance(
            row_key_version, int
        ):
            if row_key_version is not None:
                raise TypeError(f"{where} keyVersion must be an int or null")
        elif row_key_version <= 0:
            raise _ffdacfda_invalid(f"{where} keyVersion must be positive")
        if (row_site is None) != (row_key_version is None):
            raise _ffdacfda_invalid(
                f"{where} issuer and keyVersion must be null together"
            )
        conclusion = row[ADJ_CONCLUSION]
        if not isinstance(conclusion, str):
            raise TypeError(f"{where} conclusion must be a str")
        reason = row[ADJ_REASON]
        if conclusion == PA_CONCLUSION_VALID:
            if reason is not None:
                raise _ffdacfda_invalid(
                    f"{where} reason must be null for a valid row"
                )
        elif conclusion == PA_CONCLUSION_INVALID:
            if reason not in _PFDA_INVALID_REASONS:
                raise _ffdacfda_invalid(
                    f"{where} reason must be one of 'invalid', "
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
                raise _ffdacfda_invalid(
                    f"{where} reason must match its conclusion"
                )
        else:
            raise _ffdacfda_invalid(f"{where} conclusion is not known")
        identity_present = reason != PA_CONCLUSION_INVALID
        if identity_present:
            if row_site is None:
                raise _ffdacfda_invalid(
                    f"{where} an authenticated or authorized row must carry "
                    "its issuer"
                )
        elif row_site is not None:
            raise _ffdacfda_invalid(
                f"{where} an invalid row must carry no issuer"
            )
        raw_declaration = row[_FACFDA_DECLARATION]
        if conclusion == PA_CONCLUSION_INVALID:
            if raw_declaration is not None:
                raise _ffdacfda_invalid(
                    f"{where} an invalid row must carry no declaration"
                )
            parsed_declaration = None
        else:
            parsed_declaration = _validated_pfda_declaration(
                raw_declaration, f"{where} declaration",
                invalid=_ffdacfda_invalid, positional_proofs=True,
                allow_empty_edges=True,
            )
            if parsed_declaration is None:
                raise _ffdacfda_invalid(
                    f"{where} a counted row must carry its declaration"
                )
        parsed_rows.append({
            ADJ_CONCLUSION: conclusion,
            CP_DIGEST: digest,
            ID: row_id,
            VD_ISSUER: row_site,
            KEY_VERSION: row_key_version,
            ADJ_REASON: reason,
            _FACFDA_DECLARATION: parsed_declaration,
        })

    common_declaration = _validated_pfda_declaration(
        payload[_FACFDA_DECLARATION], "aggregate declaration",
        invalid=_ffdacfda_invalid, positional_proofs=True,
        allow_empty_edges=True,
    )

    normalized_payload = {
        _FACFDA_INPUTS: list(inputs),
        VD_ISSUER: issuer,
        ITEMS: parsed_rows,
        KEY_VERSION: key_version,
        _FACFDA_PRUNE_POLICY_DIGEST: payload[_FACFDA_PRUNE_POLICY_DIGEST],
        _FACFDA_AUTHORIZATION_POLICY_DIGEST: payload[
            _FACFDA_AUTHORIZATION_POLICY_DIGEST
        ],
        _FACFDA_SITE_POLICY_DIGEST: payload[_FACFDA_SITE_POLICY_DIGEST],
        _FACFDA_SIGNER_SITE_POLICY_DIGEST: payload[
            _FACFDA_SIGNER_SITE_POLICY_DIGEST
        ],
        _FACFDA_ADJUDICATION_SITE_POLICY_DIGEST: payload[
            _FACFDA_ADJUDICATION_SITE_POLICY_DIGEST
        ],
        _FFDACFDA_PROOF_SITE_POLICY_DIGEST: payload[
            _FFDACFDA_PROOF_SITE_POLICY_DIGEST
        ],
        _FFDACFDA_DECISION_SITE_POLICY_DIGEST: payload[
            _FFDACFDA_DECISION_SITE_POLICY_DIGEST
        ],
        _FACFDA_DECLARATION: common_declaration,
        STATUS: status,
        VERSION:
            FINAL_FORK_DECISION_AGGREGATE_CHAIN_FORK_DECISION_AGGREGATE_VERSION,
    }
    if _prune_compact({TICKET_PAYLOAD: normalized_payload,
                       SIGNATURE: signature}) != raw:
        raise _ffdacfda_invalid(
            "aggregate packet encoding is not the canonical compact form"
        )
    return normalized_payload, signature


def _reconcile_ffdacfda_declaration(
    declaration: dict, fork_threshold: int, where: str
) -> None:
    """Re-tally one bound declaration as the decision it claims to be.

    The declaration's per-item conclusion entries and term-by-term proof
    digest vector are re-tallied through the exact final fork decision
    aggregate chain fork decision rules against the proof site policy
    threshold, so a reordered entry, a reordered proof summary, a wrong
    duplicate or contradiction marking, a tampered common set or a
    mis-stated status cannot hide inside a counted declaration.  Any
    mismatch raises
    :class:`InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError`.
    """
    synthetic_payload = {
        PAFD_COMMON: declaration[PAFD_COMMON],
        ITEMS: [
            {
                ADJ_CONCLUSION: entry[ADJ_CONCLUSION],
                PAFD_EDGES: entry[PAFD_EDGES],
                ID: entry[ID],
                KEY_VERSION: None,
                PAFD_FORK_PROOF_DIGEST: entry[CP_DIGEST],
                ADJ_REASON: entry[ADJ_REASON],
                VD_ISSUER: entry[VD_ISSUER],
            }
            for entry in declaration[PFDA_CONCLUSIONS]
        ],
        PAFD_PROOFS: declaration[PFDA_PROOFS],
        STATUS: declaration[STATUS],
    }
    try:
        _reconcile_pafd(
            synthetic_payload, fork_threshold,
            invalid=_ffdacf_decision_invalid, positional_proofs=True,
        )
    except InvalidFinalForkDecisionAggregateChainForkDecisionError as exc:
        raise _ffdacfda_invalid(f"{where}: {exc}") from exc


def _reconcile_ffdacfda_aggregate(
    payload: dict, fork_threshold: int, decision_threshold: int
) -> None:
    """Re-derive every binding of a parsed decision aggregate payload.

    Re-tallies the per-decision rows the signature covers -- the
    original-order input digest bindings, row ordering, same-site
    duplicate and contradiction markings, cross-site complete
    declaration agreement, the threshold acceptance and the claimed
    common declaration and status -- and re-tallies every counted
    declaration against the proof site policy threshold, without seeing
    any decision bytes.  Any mismatch raises
    :class:`InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError`.
    """
    rows = payload[ITEMS]
    inputs = payload[_FACFDA_INPUTS]

    expected_order = sorted(rows, key=_ffdacfda_row_sort_key)
    if [row[ID] for row in expected_order] != [row[ID] for row in rows]:
        raise _ffdacfda_invalid("items must be sorted by issuer then id")
    if sorted(row[CP_DIGEST] for row in rows) != sorted(inputs):
        raise _ffdacfda_invalid(
            "the bound input digests must equal the per-item digests"
        )

    # Deep-copy the parsed rows before the tally mutates their
    # conclusion/reason markings; the signed payload itself is compared
    # through freshly derived structures only.
    working_rows = copy.deepcopy(rows)
    derived_status, derived_declaration = _tally_pfda_rows(
        working_rows, decision_threshold
    )

    for expected_row, bound_row in zip(working_rows, rows):
        if expected_row[ADJ_CONCLUSION] != bound_row[ADJ_CONCLUSION]:
            raise _ffdacfda_invalid(
                f"item {bound_row[ID]!r} has the wrong conclusion"
            )
        if expected_row[ADJ_REASON] != bound_row[ADJ_REASON]:
            raise _ffdacfda_invalid(
                f"item {bound_row[ID]!r} has the wrong reason"
            )

    if payload[STATUS] != derived_status:
        raise _ffdacfda_invalid(
            "the bound status does not match the tallied items"
        )
    bound_declaration = payload[_FACFDA_DECLARATION]
    if derived_declaration is None:
        if bound_declaration is not None:
            raise _ffdacfda_invalid(
                "the common declaration must be null when no unique "
                "conflict-free declaration was tallied"
            )
    else:
        if bound_declaration is None:
            raise _ffdacfda_invalid(
                "an aggregate over one unique conflict-free declaration "
                "must carry the common declaration"
            )
        if bound_declaration != derived_declaration:
            raise _ffdacfda_invalid(
                "the bound common declaration does not match the tallied "
                "decisions"
            )

    for row in rows:
        declaration = row[_FACFDA_DECLARATION]
        if declaration is None:
            continue
        _reconcile_ffdacfda_declaration(
            declaration, fork_threshold, f"aggregate item {row[ID]!r}"
        )
    if bound_declaration is not None:
        _reconcile_ffdacfda_declaration(
            bound_declaration, fork_threshold, "aggregate declaration"
        )


def verify_final_fork_decision_aggregate_chain_fork_decision_aggregate(
    aggregate, prune_policy, authorization_policy, site_policy,
    signer_site_policy, adjudication_site_policy, proof_site_policy,
    decision_site_policy, keyring, moment,
):
    """Verify a signed final fork decision aggregate chain fork
    decision aggregate entirely offline.

    Only the aggregate bytes, the seven expected policies (the original
    prune policy, the site authorization policy, the fork-proof signer
    site policy, the adjudication signer site policy, the issuing
    adjudication site policy, the proof site policy and the decision
    site policy), the current ``keyring`` and the verification
    ``moment`` are consulted -- no file is read or written and no
    argument is modified.  Verification validates the canonical
    encoding and every key set, recomputes all seven policy digests,
    and re-tallies the bound per-decision rows purely from the signed
    payload: the original-order input digest bindings, the issuer/id
    row ordering, same-site duplicate and contradiction markings,
    cross-site complete declaration agreement (the common fork edge
    set -- empty for a fork-free consensus -- the per-item conclusions,
    the term-by-term proof digest vector and the overall status
    together), the threshold outcome and the claimed common
    declaration, together with a full re-tally of every counted
    declaration against the proof site policy threshold.  It then
    checks the HMAC-SHA256 against the key the *current* keyring binds
    to the payload's exact issuer and version, usable at the
    verification moment, so a later revocation or expiry rejects the
    aggregate with no fallback.

    On success a fresh, depth-independent result equal to the
    authenticated payload plus ``aggregateDigest`` (the SHA-256 of the
    aggregate bytes) is returned with the fixed keys
    ``aggregateDigest``, ``inputs``, ``issuer``, ``items``,
    ``keyVersion``, ``prunePolicyDigest``,
    ``authorizationPolicyDigest``, ``sitePolicyDigest``,
    ``signerSitePolicyDigest``, ``adjudicationSitePolicyDigest``,
    ``proofSitePolicyDigest``, ``decisionSitePolicyDigest``,
    ``declaration``, ``status`` and ``version`` (the integer 1) --
    repeated calls return equal but mutually independent objects
    sharing no mutable structure, and unauthenticated identities never
    enter a result.  A non-bytes aggregate or a field of the wrong type
    raises :class:`TypeError` (a :class:`bool` never poses as an int);
    a null value, a duplicate id, a wrong key set or an illegal policy,
    threshold, moment or other value raises :class:`ValueError`; an
    illegal aggregate structure, binding or recomputation raises
    :class:`InvalidFinalForkDecisionAggregateChainForkDecisionAggregateError`
    (a :class:`ValueError` subclass, distinct from the proof, the
    single-decision and every other aggregate error class); unknown,
    revoked, not-yet-valid or expired credentials or a signature
    mismatch raise :class:`AuthenticationError`.
    """
    if not isinstance(aggregate, bytes):
        raise TypeError("aggregate packet must be bytes")
    materials = _ffdacf_validated_decision_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy, proof_site_policy,
    )
    _ffdacfda_bind_decision_policy(materials, decision_site_policy)
    _ffdac_bind_runtime(materials, keyring, moment)

    payload, signature = _parse_ffdacfda(aggregate)
    _ffdacfda_assert_policy_digests(payload, materials)
    _reconcile_ffdacfda_aggregate(
        payload,
        materials["proof_site_policy"][ADJ_THRESHOLD],
        materials["decision_site_policy"][ADJ_THRESHOLD],
    )
    _ffdac_assert_payload_signature(
        materials["keyring"], payload[VD_ISSUER], payload[KEY_VERSION],
        materials["moment"], payload, signature,
        "final fork decision aggregate chain fork decision aggregate "
        "signature does not match",
    )

    authenticated = copy.deepcopy(payload)
    return {
        key: (
            hashlib.sha256(aggregate).hexdigest()
            if key == _FACFDA_AGGREGATE_DIGEST
            else authenticated[key]
        )
        for key in _FFDACFDA_RESULT_KEYS
    }
