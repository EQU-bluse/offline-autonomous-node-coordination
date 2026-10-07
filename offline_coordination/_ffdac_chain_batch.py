"""Batch verification of final fork decision aggregate supersession chains
and stable head anchors -- private implementation module.

This module is the extracted home of the
:mod:`offline_coordination.replication` layer that batches
:func:`verify_final_fork_decision_aggregate_chain` exactly the way the
final aggregate chain layer batches :func:`verify_final_aggregate_chain`:
the six materials (the five invariant policies plus the per-stage decision
site policy history carried inside each item), keyring and moment are
shared by every chain and validated in full before any chain runs; each
item is then isolated, failures keep the single-chain
root/chain/credential taxonomy, and verified chains sharing one root
digest are checked for successor forks.  An anchor seals only a verified,
accepted, unforked chain head and binds its root and head digests, height,
final stage policy digest, policy version and declaration digest.

This is an internal boundary, not a public entry point: the public
functions and the dedicated anchor error are re-exported from
``offline_coordination.replication`` under their historical names, with
identical call signatures and class object identity.

The shared rules this layer relies on keep exactly one authoritative home:
the batch container validation (``_validated_fac_chain_batch``), the
canonical compact encoding (``_prune_compact`` and
``_ffdac_parse_envelope``), the signature wrapping
(``_ffdac_payload_signature`` and ``_ffdac_assert_payload_signature``),
the credential window rule (``_usable_checkpoint_key``), the
fixed-key-order batch item report (``_fac_chain_item_report``) and the
duplicate-key rejection (``_reject_duplicate_pfda_keys``) all live in
``offline_coordination.replication``; the deterministic fork
reclassification (``_ffdac_reclassify_forks``) and the batch engine
(``_ffdac_batch_report``) live here as the single implementation behind
all three entry points.
"""

from __future__ import annotations

import hashlib

from offline_coordination.replication import (
    AuthenticationError,
    CHAINS_FORKS,
    CHECKPOINT_ITEM_ERROR,
    FAC_ANCHOR_DIGEST,
    FAC_HEAD_DIGEST,
    FAC_POLICY_DIGEST,
    FAC_POLICY_VERSION,
    FINAL_FORK_DECISION_AGGREGATE_CHAIN_VERSION,
    FINAL_FORK_DECISION_AGGREGATE_CHAINS_VERSION,
    ID,
    ITEMS,
    InvalidFinalAggregateChainForkDecisionAggregateError,
    InvalidFinalForkDecisionAggregateChainError,
    KEY_VERSION,
    PAC_BATCH_POLICIES,
    PAC_BATCH_ROOT,
    PAC_BATCH_SUCCESSORS,
    PAC_CHAINS_CONFLICTED,
    PAC_CHAINS_INVALID_CHAIN,
    PAC_CHAINS_INVALID_ROOT,
    PAC_CHAINS_UNAUTHENTICATED,
    PAC_CHAINS_VERIFIED,
    PAC_PREDECESSOR_DIGEST,
    PAC_ROOT_DIGEST,
    PA_STATUS_ACCEPTED,
    SIGNATURE,
    STATUS,
    TICKET_PAYLOAD,
    VD_ISSUER,
    VERDICT_ITEM_RESULT,
    VERSION,
    _FAG_SEALED_AT,
    _FFDAC_CHAIN_ITEM_ERROR,
    _FFDAC_DECLARATION_DIGEST,
    _FFDAC_HEIGHT,
    _FFDAC_ROOT_DIGEST,
    _FFDAC_TOP_KEYS,
    _FORK_IDS,
    _fac_chain_item_report,
    _ffdac_assert_payload_signature,
    _ffdac_bind_runtime,
    _ffdac_parse_envelope,
    _ffdac_payload_signature,
    _ffdac_sealed_chain,
    _ffdac_validated_materials,
    _ffdac_validated_signer,
    _pac_chain_edge_nodes,
    _pac_policy_digest,
    _validated_pac_site_policy,
    _pac_validated_policy_sequence,
    _prune_compact,
    _prune_is_digest,
    _reject_duplicate_pfda_keys,
    _usable_checkpoint_key,
    _validated_fac_chain_batch,
)


_FFDAC_ANCHOR_SEALED_AT = _FAG_SEALED_AT
_FFDAC_ANCHOR_DIGEST = FAC_ANCHOR_DIGEST

_FFDAC_ANCHOR_TOP_KEYS = _FFDAC_TOP_KEYS
_FFDAC_ANCHOR_PAYLOAD_KEYS = frozenset((
    _FFDAC_ROOT_DIGEST,
    FAC_HEAD_DIGEST,
    _FFDAC_HEIGHT,
    FAC_POLICY_DIGEST,
    FAC_POLICY_VERSION,
    _FFDAC_DECLARATION_DIGEST,
    _FFDAC_ANCHOR_SEALED_AT,
    VD_ISSUER,
    KEY_VERSION,
    VERSION,
))


def _verify_ffdac_chain_item(item: dict, materials: dict) -> dict:
    """Verify one batch chain in isolation and report its outcome.

    The root aggregate is verified on its own first through the shared
    engine, so a root fault is reported ``invalid-root`` while a
    successor or chain-binding fault is ``invalid-chain``; credential and
    signature faults are ``unauthenticated`` and a passing chain is
    ``verified``.
    """
    item_id = item[ID]
    root = item[PAC_BATCH_ROOT]
    successors = item[PAC_BATCH_SUCCESSORS]
    # The batch container already validated the policy history; the
    # sequence is re-normalized here purely to feed the shared engine.
    validated_policies = _pac_validated_policy_sequence(
        item[PAC_BATCH_POLICIES]
    )
    try:
        _ffdac_sealed_chain(root, [], materials, validated_policies[:1])
    except AuthenticationError as exc:
        return _fac_chain_item_report(
            item_id, PAC_CHAINS_UNAUTHENTICATED, str(exc), None
        )
    except (InvalidFinalAggregateChainForkDecisionAggregateError,
            TypeError, ValueError) as exc:
        return _fac_chain_item_report(
            item_id, PAC_CHAINS_INVALID_ROOT, str(exc), None
        )
    try:
        result = _ffdac_sealed_chain(
            root, successors, materials, validated_policies
        )
    except AuthenticationError as exc:
        return _fac_chain_item_report(
            item_id, PAC_CHAINS_UNAUTHENTICATED, str(exc), None
        )
    except (InvalidFinalAggregateChainForkDecisionAggregateError,
            InvalidFinalForkDecisionAggregateChainError,
            TypeError, ValueError) as exc:
        return _fac_chain_item_report(
            item_id, PAC_CHAINS_INVALID_CHAIN, str(exc), None
        )
    return _fac_chain_item_report(
        item_id, PAC_CHAINS_VERIFIED, None, result
    )


def _ffdac_reclassify_forks(
    validated_items: list[dict], reports: list[dict], results: list,
) -> list[dict]:
    """Spot successor forks among verified chains and reclassify them.

    Only successor trajectories under the same root digest are compared:
    the same predecessor digest pointing at two distinct successor
    digests is a fork, while a plain prefix extension is not.  Every
    verified chain crossing a forking edge becomes ``conflicted`` with its
    verified result kept and the fixed fork error; failed chains never
    move.  Returns the forks sorted by root then predecessor.
    """
    groups: dict[str, dict[str, set[str]]] = {}
    for item, result in zip(validated_items, results):
        if result is None:
            continue
        nodes = _pac_chain_edge_nodes(item)
        edges = groups.setdefault(nodes[0], {})
        for upstream, downstream in zip(nodes, nodes[1:]):
            edges.setdefault(upstream, set()).add(downstream)
    fork_edges: dict[tuple[str, str], list[str]] = {}
    for root_digest, edges in groups.items():
        for upstream, digests in edges.items():
            if len(digests) > 1:
                fork_edges[(root_digest, upstream)] = sorted(digests)
    edge_ids: dict[tuple[str, str], set[str]] = {
        edge: set() for edge in fork_edges
    }
    if fork_edges:
        for item, report, result in zip(validated_items, reports, results):
            if result is None:
                continue
            nodes = _pac_chain_edge_nodes(item)
            crosses_fork = False
            for upstream in nodes[:-1]:
                edge = (nodes[0], upstream)
                if edge in fork_edges:
                    edge_ids[edge].add(item[ID])
                    crosses_fork = True
            if crosses_fork:
                report[STATUS] = PAC_CHAINS_CONFLICTED
                report[CHECKPOINT_ITEM_ERROR] = _FFDAC_CHAIN_ITEM_ERROR

    return [
        {
            PAC_ROOT_DIGEST: root_digest,
            PAC_PREDECESSOR_DIGEST: predecessor,
            PAC_BATCH_SUCCESSORS: fork_edges[(root_digest, predecessor)],
            _FORK_IDS: sorted(edge_ids[(root_digest, predecessor)]),
        }
        for root_digest, predecessor in sorted(fork_edges)
    ]


def _ffdac_batch_report(
    validated_items: list[dict], materials: dict,
) -> dict:
    """Run every validated chain against a shared materials bundle.

    This is the one batch engine behind
    :func:`verify_final_fork_decision_aggregate_chains` and both head
    anchor entry points: each chain is isolated and reported in input
    order, then verified chains are fork-reclassified by the single
    :func:`_ffdac_reclassify_forks` rule.
    """
    reports: list[dict] = []
    results: list[dict | None] = []
    for item in validated_items:
        report = _verify_ffdac_chain_item(item, materials)
        reports.append(report)
        results.append(report[VERDICT_ITEM_RESULT])

    forks = _ffdac_reclassify_forks(validated_items, reports, results)
    return {
        CHAINS_FORKS: forks,
        ITEMS: reports,
        VERSION: FINAL_FORK_DECISION_AGGREGATE_CHAINS_VERSION,
    }


def verify_final_fork_decision_aggregate_chains(
    items, prune_policy, authorization_policy, site_policy,
    signer_site_policy, adjudication_site_policy, keyring, moment,
):
    """Verify a batch of final fork decision aggregate chains and spot
    successor forks.

    Each item holds exactly a unique non-empty ``id``, its ``root``
    final aggregate chain fork decision aggregate packet
    (:func:`aggregate_final_aggregate_chain_fork_decisions`), its
    ordered ``successors`` packets and its per-stage ``policies``
    history; ``prune_policy`` is the invariant original pruning policy,
    ``authorization_policy`` the invariant site authorization policy,
    ``site_policy`` the invariant fork-proof signer site policy,
    ``signer_site_policy`` the invariant adjudication signer site
    policy and ``adjudication_site_policy`` the invariant issuing
    adjudication site policy shared by every chain, and ``keyring`` and
    ``moment`` keep their single-chain meaning.  The whole batch
    structure -- every key set, element type, policy count and the
    shared materials -- is validated before any chain is verified, so
    only batch-level faults raise (container, element or field type
    faults :class:`TypeError`, a :class:`bool` never posing as an int;
    an empty list, an empty or duplicate id, a wrong key set, a wrong
    policy count or an illegal moment :class:`ValueError`).

    Each chain is then verified independently, in strict input order,
    through the exact :func:`verify_final_fork_decision_aggregate_chain`
    rules: one chain's failure never stops a later chain or changes an
    earlier report.  A root fault reports ``invalid-root``, a successor
    or chain-binding fault ``invalid-chain`` and a credential or
    signature fault ``unauthenticated``, each with a null ``result`` and
    a non-empty ``error``; a passing chain reports ``verified``.

    The verified chains are grouped by their ``rootDigest`` and only
    successor trajectories under the same root are compared: the same
    predecessor digest pointing at two distinct successor digests is a
    fork, while a plain prefix extension (one chain growing longer along
    the same packets) is not.  Every verified chain crossing a forking
    edge is reclassified ``conflicted`` with its verified result kept
    and its ``error`` fixed to
    ``"forked-final-fork-decision-aggregate-chain"``; failed chains are
    never reclassified.

    Returns a fresh dict with the fixed keys ``forks``, ``items`` and
    ``version`` (the integer 1).  ``forks`` is sorted stably by
    ``rootDigest`` then ``predecessorDigest``; each entry carries
    exactly ``rootDigest``, ``predecessorDigest``, ``successors`` (the
    forking successor digests, ascending) and ``ids`` (the ascending
    ids of the chains crossing the edge).  Each item report preserves
    the input order and carries, in this key order, ``error``, ``id``,
    ``result`` and ``status``.  No file is read or written and no input
    is modified.
    """
    validated_items = _validated_fac_chain_batch(items)
    materials = _ffdac_validated_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy,
    )
    _ffdac_bind_runtime(materials, keyring, moment)
    return _ffdac_batch_report(validated_items, materials)


# -- Stable head anchors for verified, accepted, unforked chains ---------------

class InvalidFinalForkDecisionAggregateAnchorError(ValueError):
    """A final fork decision aggregate head anchor breaks its contract."""

    # The class keeps its historical public module path: it is re-exported
    # from ``offline_coordination.replication``.
    __module__ = "offline_coordination.replication"


def _ffdac_anchor_invalid(
    message: str,
) -> InvalidFinalForkDecisionAggregateAnchorError:
    return InvalidFinalForkDecisionAggregateAnchorError(
        f"invalid final fork decision aggregate anchor: {message}"
    )


def _reject_duplicate_ffdac_anchor_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate anchor keys into an error.

    The duplicate-key rule itself lives in exactly one place:
    :func:`_reject_duplicate_pfda_keys`.
    """
    return _reject_duplicate_pfda_keys(pairs, _ffdac_anchor_invalid)


def _ffdac_parse_anchor(raw: object) -> tuple[dict, str]:
    """Validate anchor bytes structurally into ``(payload, signature)``."""
    data, payload, signature = _ffdac_parse_envelope(
        raw, noun="anchor", invalid=_ffdac_anchor_invalid,
        reject_duplicate=_reject_duplicate_ffdac_anchor_keys,
        payload_keys=_FFDAC_ANCHOR_PAYLOAD_KEYS,
        payload_keys_error=(
            "payload must contain exactly the keys 'rootDigest', "
            "'headDigest', 'height', 'policyDigest', 'policyVersion', "
            "'declarationDigest', 'sealedAt', 'issuer', 'keyVersion' and "
            "'version'"
        ),
        top_keys=_FFDAC_ANCHOR_TOP_KEYS,
    )
    for key in (_FFDAC_ROOT_DIGEST, FAC_HEAD_DIGEST, FAC_POLICY_DIGEST):
        value = payload[key]
        if not isinstance(value, str):
            raise TypeError(f"payload {key} must be a str")
        if not _prune_is_digest(value):
            raise _ffdac_anchor_invalid(
                f"payload {key} must be 64 lowercase hex characters"
            )
    declaration_digest = payload[_FFDAC_DECLARATION_DIGEST]
    if declaration_digest is not None:
        if not isinstance(declaration_digest, str):
            raise TypeError(
                "payload declarationDigest must be a str or null"
            )
        if not _prune_is_digest(declaration_digest):
            raise _ffdac_anchor_invalid(
                "payload declarationDigest must be null or 64 lowercase "
                "hex characters"
            )
    height = payload[_FFDAC_HEIGHT]
    if isinstance(height, bool) or not isinstance(height, int):
        raise TypeError("payload height must be an int")
    if height < 0:
        raise _ffdac_anchor_invalid("payload height must be non-negative")
    policy_version = payload[FAC_POLICY_VERSION]
    if isinstance(policy_version, bool) or not isinstance(policy_version, int):
        raise TypeError("payload policyVersion must be an int")
    if policy_version <= 0:
        raise _ffdac_anchor_invalid("payload policyVersion must be positive")
    sealed_at = payload[_FFDAC_ANCHOR_SEALED_AT]
    if isinstance(sealed_at, bool) or not isinstance(sealed_at, int):
        raise TypeError("payload sealedAt must be an int")
    if sealed_at < 0:
        raise _ffdac_anchor_invalid("payload sealedAt must be non-negative")
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _ffdac_anchor_invalid("payload issuer must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _ffdac_anchor_invalid("payload keyVersion must be positive")
    anchor_version = payload[VERSION]
    if isinstance(anchor_version, bool) or not isinstance(
        anchor_version, int
    ):
        raise TypeError("payload version must be an int")
    if anchor_version != FINAL_FORK_DECISION_AGGREGATE_CHAIN_VERSION:
        raise _ffdac_anchor_invalid("payload version must be the integer 1")
    if _prune_compact(data) != raw:
        raise _ffdac_anchor_invalid(
            "encoding is not the canonical compact form"
        )
    return payload, signature


def _ffdac_target_index(validated_items: list[dict], target: object) -> int:
    """Locate the unique target id of an anchor batch or raise."""
    if not isinstance(target, str):
        raise TypeError("target must be a str")
    if target == "":
        raise ValueError("target must be non-empty")
    for position, item in enumerate(validated_items):
        if item[ID] == target:
            return position
    raise ValueError(f"unknown target id {target!r}")


def _ffdac_target_failure(target_report: dict, anchor: bool) -> Exception:
    """Recreate the failure a target chain reported, with the right class."""
    target_status = target_report[STATUS]
    message = target_report[CHECKPOINT_ITEM_ERROR]
    if target_status == PAC_CHAINS_INVALID_ROOT:
        return InvalidFinalAggregateChainForkDecisionAggregateError(message)
    if target_status == PAC_CHAINS_INVALID_CHAIN:
        # The report message already carries the chain-error prefix.
        return InvalidFinalForkDecisionAggregateChainError(message)
    if target_status == PAC_CHAINS_UNAUTHENTICATED:
        return AuthenticationError(message)
    if anchor:
        return _ffdac_anchor_invalid(
            "the anchored target no longer verifies without a fork"
        )
    return ValueError("an anchor seals only a verified target with no fork")


def _ffdac_head_binding(target_item: dict) -> tuple[bytes, dict, str]:
    """Resolve a verified target's head packet, final policy and digest."""
    head_packet = (
        target_item[PAC_BATCH_SUCCESSORS][-1]
        if target_item[PAC_BATCH_SUCCESSORS] else target_item[PAC_BATCH_ROOT]
    )
    head_policy = _validated_pac_site_policy(
        target_item[PAC_BATCH_POLICIES][-1]
    )
    return head_packet, head_policy, _pac_policy_digest(head_policy)


def seal_final_fork_decision_aggregate_head(
    items, target, prune_policy, authorization_policy, site_policy,
    signer_site_policy, adjudication_site_policy, keyring, moment,
    issuer, version,
):
    """Seal a stable anchor over one target head within the batch.

    The batch is first run through the exact
    :func:`verify_final_fork_decision_aggregate_chains` rules.  An
    anchor is sealed only for the ``target`` chain when it is
    ``verified`` -- never conflicted by a fork in this batch, invalid
    or unauthenticated -- and its head is ``accepted``; otherwise
    sealing raises :class:`ValueError`.  Other chains' failures never
    stop the target's anchor, though a fork it shares still
    reclassifies it.  The anchor binds that chain's root digest, head
    digest and height together with the final stage decision policy
    digest, the head policy version, the head declaration digest and
    the sealing moment, and is signed with HMAC-SHA256 under the exact
    ``issuer``/``version`` key usable at ``moment``.

    Returns canonical compact UTF-8 JSON with exactly ``payload`` and
    ``signature``.  A parameter or public field type fault raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    empty value, an unknown or duplicate target id, an illegal version
    or a wrong policy count raises :class:`ValueError`; a chain fault
    raises the underlying
    :class:`InvalidFinalAggregateChainForkDecisionAggregateError` or
    :class:`InvalidFinalForkDecisionAggregateChainError`; a signing
    credential fault raises :class:`AuthenticationError`.  No file is
    read or written and no input is modified.
    """
    validated_items = _validated_fac_chain_batch(items)
    target_index = _ffdac_target_index(validated_items, target)
    materials = _ffdac_validated_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy,
    )
    _ffdac_bind_runtime(materials, keyring, moment)
    seal_moment = materials["moment"]
    issuer, version = _ffdac_validated_signer(issuer, version)

    report = _ffdac_batch_report(validated_items, materials)
    target_report = report[ITEMS][target_index]
    target_status = target_report[STATUS]
    if target_status != PAC_CHAINS_VERIFIED:
        raise _ffdac_target_failure(target_report, anchor=False)
    result = target_report[VERDICT_ITEM_RESULT]
    if result[STATUS] != PA_STATUS_ACCEPTED:
        raise ValueError("an anchor seals only an accepted head")
    target_item = validated_items[target_index]
    head_packet, head_policy, _head_policy_digest = _ffdac_head_binding(
        target_item
    )
    if result[FAC_HEAD_DIGEST] != hashlib.sha256(head_packet).hexdigest():
        raise ValueError("the sealed head digest does not match its packet")
    signing_entry = _usable_checkpoint_key(
        materials["keyring"], issuer, version, seal_moment
    )
    payload = {
        _FFDAC_ROOT_DIGEST: result[_FFDAC_ROOT_DIGEST],
        FAC_HEAD_DIGEST: result[FAC_HEAD_DIGEST],
        _FFDAC_HEIGHT: result[_FFDAC_HEIGHT],
        FAC_POLICY_DIGEST: _pac_policy_digest(head_policy),
        FAC_POLICY_VERSION: result[FAC_POLICY_VERSION],
        _FFDAC_DECLARATION_DIGEST: result[_FFDAC_DECLARATION_DIGEST],
        _FFDAC_ANCHOR_SEALED_AT: seal_moment,
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        VERSION: FINAL_FORK_DECISION_AGGREGATE_CHAIN_VERSION,
    }
    signature = _ffdac_payload_signature(signing_entry, payload)
    return _prune_compact({TICKET_PAYLOAD: payload, SIGNATURE: signature})


def verify_final_fork_decision_aggregate_head(
    anchor, items, target, prune_policy, authorization_policy, site_policy,
    signer_site_policy, adjudication_site_policy, keyring, moment,
):
    """Re-verify a sealed final fork decision aggregate anchor entirely
    offline.

    The anchor is checked structurally and its HMAC verified against the
    current keyring key bound to its exact issuer and version, usable at
    the verification ``moment``; its sealing moment must not be later
    than the verification moment.  The original batch (with ``target``
    naming the anchored chain) is then recomputed in full through
    :func:`verify_final_fork_decision_aggregate_chains`; the target must
    again verify with no fork and an accepted head, and its root digest,
    head digest, height, final stage policy digest, policy version and
    declaration digest must still match the anchor bindings.

    Returns a fresh mapping with fixed keys ``rootDigest``,
    ``headDigest``, ``height``, ``policyDigest``, ``policyVersion``,
    ``declarationDigest`` and ``anchorDigest`` (the SHA-256 of the
    anchor bytes).  A non-bytes or wrong-type argument raises
    :class:`TypeError`; an empty value, a duplicate or unknown target
    id, an illegal version or a wrong policy count raises
    :class:`ValueError`; a malformed root raises
    :class:`InvalidFinalAggregateChainForkDecisionAggregateError`; a
    bad anchor structure or binding raises
    :class:`InvalidFinalForkDecisionAggregateAnchorError`; a bad
    successor or chain binding raises
    :class:`InvalidFinalForkDecisionAggregateChainError`; a signature or
    credential fault raises :class:`AuthenticationError`.  No file is
    read or written and no input is modified.
    """
    if not isinstance(anchor, bytes):
        raise TypeError("anchor must be bytes")
    payload, signature = _ffdac_parse_anchor(anchor)
    validated_items = _validated_fac_chain_batch(items)
    target_index = _ffdac_target_index(validated_items, target)
    materials = _ffdac_validated_materials(
        prune_policy, authorization_policy, site_policy,
        signer_site_policy, adjudication_site_policy,
    )
    _ffdac_bind_runtime(materials, keyring, moment)
    verify_moment = materials["moment"]

    _ffdac_assert_payload_signature(
        materials["keyring"], payload[VD_ISSUER], payload[KEY_VERSION],
        verify_moment, payload, signature,
        "final fork decision aggregate anchor signature does not match",
    )
    if payload[_FFDAC_ANCHOR_SEALED_AT] > verify_moment:
        raise _ffdac_anchor_invalid(
            "the anchor sealing moment is later than the verification "
            "moment"
        )

    report = _ffdac_batch_report(validated_items, materials)
    target_report = report[ITEMS][target_index]
    if target_report[STATUS] != PAC_CHAINS_VERIFIED:
        raise _ffdac_target_failure(target_report, anchor=True)
    result = target_report[VERDICT_ITEM_RESULT]
    if result[STATUS] != PA_STATUS_ACCEPTED:
        raise _ffdac_anchor_invalid("the anchored head is no longer accepted")
    target_item = validated_items[target_index]
    _head_packet, _head_policy, head_policy_digest = _ffdac_head_binding(
        target_item
    )
    if result[_FFDAC_ROOT_DIGEST] != payload[_FFDAC_ROOT_DIGEST]:
        raise _ffdac_anchor_invalid("root digest does not match the anchor")
    if result[FAC_HEAD_DIGEST] != payload[FAC_HEAD_DIGEST]:
        raise _ffdac_anchor_invalid("head digest does not match the anchor")
    if result[_FFDAC_HEIGHT] != payload[_FFDAC_HEIGHT]:
        raise _ffdac_anchor_invalid("height does not match the anchor")
    if result[FAC_POLICY_VERSION] != payload[FAC_POLICY_VERSION]:
        raise _ffdac_anchor_invalid(
            "policy version does not match the anchor"
        )
    if head_policy_digest != payload[FAC_POLICY_DIGEST]:
        raise _ffdac_anchor_invalid("policy digest does not match the anchor")
    if result[_FFDAC_DECLARATION_DIGEST] != payload[_FFDAC_DECLARATION_DIGEST]:
        raise _ffdac_anchor_invalid(
            "declaration digest does not match the anchor"
        )
    return {
        _FFDAC_ROOT_DIGEST: payload[_FFDAC_ROOT_DIGEST],
        FAC_HEAD_DIGEST: payload[FAC_HEAD_DIGEST],
        _FFDAC_HEIGHT: payload[_FFDAC_HEIGHT],
        FAC_POLICY_DIGEST: head_policy_digest,
        FAC_POLICY_VERSION: payload[FAC_POLICY_VERSION],
        _FFDAC_DECLARATION_DIGEST: payload[_FFDAC_DECLARATION_DIGEST],
        _FFDAC_ANCHOR_DIGEST: hashlib.sha256(anchor).hexdigest(),
    }
