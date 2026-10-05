"""Differential golden-vector capture for the final fork decision aggregate
boundary refactor.

Run against the baseline to dump every public success value and every
public failure (exception class + message) to JSON, then run again after
the refactor and diff.  Covers the nine entry points from
``supersede_final_fork_decision_aggregate`` through
``verify_final_fork_decision_aggregate_chain_fork_decision``.

Usage:
    python3 tests/_golden_capture.py /tmp/golden.json
    python3 tests/_golden_capture.py --diff /tmp/golden.json
"""

import copy
import hashlib
import hmac
import json
import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _TESTS_DIR)
sys.path.insert(0, os.path.dirname(_TESTS_DIR))

from offline_coordination.replication import (  # noqa: E402
    SECRET,
    _prune_compact,
    _usable_checkpoint_key,
    _validated_keyring,
    adjudicate_final_fork_decision_aggregate_chain_forks,
    seal_final_fork_decision_aggregate_head,
    sign_final_fork_decision_aggregate_chain_fork_proof,
    supersede_final_fork_decision_aggregate,
    verify_final_fork_decision_aggregate_chain,
    verify_final_fork_decision_aggregate_chain_fork_decision,
    verify_final_fork_decision_aggregate_chain_fork_proofs,
    verify_final_fork_decision_aggregate_chains,
    verify_final_fork_decision_aggregate_head,
)

from test_final_fork_decision_aggregate_chain_fork_proofs import (  # noqa: E402
    FinalForkDecisionAggregateChainForkFixtures,
)
from test_adjudicate_prune_aggregate_forks import proof_item  # noqa: E402
from test_aggregate_prune_fork_decisions import decision_item  # noqa: E402
from test_fork_convergence import entry  # noqa: E402
from test_prune_attestations import JUDGE, SITE_A, SITE_B, SITE_C  # noqa: E402


def make_fixture():
    fx = FinalForkDecisionAggregateChainForkFixtures()
    fx.setUp()
    return fx


def resign_successor(fx, raw, mutate):
    data = json.loads(raw.decode())
    mutate(data["payload"])
    payload = data["payload"]
    key = _usable_checkpoint_key(
        _validated_keyring(fx.ring), payload["issuer"],
        payload["keyVersion"], fx.fm + 10)
    signature = hmac.new(
        bytes.fromhex(key[SECRET]), _prune_compact(payload),
        hashlib.sha256).hexdigest()
    return _prune_compact({"payload": payload, "signature": signature})


def ring_with(fx, site, version, **changes):
    ring = copy.deepcopy(fx.ring)
    ring[site] = [dict(ring[site][0], **changes)]
    return ring


def collect():
    fx = make_fixture()
    vectors = {}

    def success(name, value):
        vectors[name] = {"ok": True, "value": encode(value)}

    def failure(name, fn):
        try:
            value = fn()
        except Exception as exc:  # every public failure is recorded
            vectors[name] = {
                "ok": False,
                "exc": type(exc).__qualname__,
                "msg": str(exc),
            }
        else:
            vectors[name] = {"ok": True, "unexpected": encode(value)}

    pol = (fx.policy, fx.auth, fx.ssp, fx.fsignerp, fx.adjp)

    # ---- Success: issuance, roots, hops, rotation ---------------------
    grow = fx.ffdsucc(
        fx.froot_one, fx.froot_one,
        [decision_item("two", fx.decision_jb)])
    success("supersede_grow_bytes", grow)
    rotate = fx.ffdsucc(
        fx.froot_one, grow, [], old=fx.pv1, new=fx.pv2_t1,
        moment=fx.fm + 20, effective=fx.fm + 5)
    success("supersede_rotate_bytes", rotate)
    # accepted-root rotation with empty increment
    success("supersede_rotate_accepted_bytes",
            fx.ffdsucc(fx.froot_two, fx.froot_two, [],
                       old=fx.pv1, new=fx.pv2_t1))
    # conflicted extension
    success("supersede_conflicted_bytes",
            fx.ffdsucc(fx.froot_two, fx.froot_two,
                       [decision_item("c", fx.free_c)],
                       old=fx.pv1, new=fx.pv2_3))
    # invalid increment decision stays in the sealed verdict
    success("supersede_invalid_increment_bytes",
            fx.ffdsucc(fx.froot_one, fx.froot_one,
                       [decision_item("bad", b"{}")]))

    # ---- Success: chain verification summaries -----------------------
    success("chain_bare_accepted",
            verify_final_fork_decision_aggregate_chain(
                fx.froot_two, [], *pol, [fx.pv1], fx.ring, fx.vmoment))
    success("chain_bare_insufficient",
            verify_final_fork_decision_aggregate_chain(
                fx.froot_one, [], *pol, [fx.pv1], fx.ring, fx.vmoment))
    success("chain_bare_conflicted",
            verify_final_fork_decision_aggregate_chain(
                fx.froot_conf, [], *pol, [fx.pv1], fx.ring, fx.vmoment))
    success("chain_single_hop",
            verify_final_fork_decision_aggregate_chain(
                fx.froot_one, [grow], *pol, [fx.pv1, fx.pv1],
                fx.ring, fx.fm + 10))
    success("chain_multi_hop_rotation",
            verify_final_fork_decision_aggregate_chain(
                fx.froot_one, [grow, rotate], *pol,
                [fx.pv1, fx.pv1, fx.pv2_t1], fx.ring, fx.fm + 30))
    success("chain_fork_free_declaration",
            verify_final_fork_decision_aggregate_chain(
                fx.froot_free, [], *pol, [fx.pv1], fx.ring, fx.vmoment))

    # ---- Success: batch reports (clean / fork / prefix) --------------
    clean_batch = [fx.bare_one("a"), fx.grow_item("b")]
    success("batch_clean_report", fx.ffreport(clean_batch))
    fork_items = [
        fx.ffitem("b", fx.froot_one, [fx.s_grow], [fx.pv1, fx.pv1]),
        fx.ffitem("a", fx.froot_one, [fx.s_t1], [fx.pv1, fx.pv2_t1]),
    ]
    success("batch_fork_report", fx.ffreport(fork_items))
    prefix_items = [
        fx.ffitem("long", fx.froot_one, [fx.s_grow, fx.sec_t1],
                  [fx.pv1, fx.pv1, fx.pv2_t1]),
        fx.ffitem("short", fx.froot_one, [fx.s_grow], [fx.pv1, fx.pv1]),
        fx.ffitem("bare", fx.froot_one),
    ]
    success("batch_prefix_extension_report", fx.ffreport(prefix_items))
    distinct_roots = [
        fx.ffitem("a", fx.froot_one, [fx.s_grow], [fx.pv1, fx.pv1]),
        fx.ffitem("b", fx.froot_two, [fx.t_rot], [fx.pv1, fx.pv2_t1]),
    ]
    success("batch_distinct_roots_report", fx.ffreport(distinct_roots))
    # batch with per-item failures of every kind, mixed with success
    tampered_root = json.loads(fx.froot_two.decode())
    tampered_root["signature"] = "00" * 32
    bad_sig_root = _prune_compact(tampered_root)
    mixed_items = [
        fx.ffitem("root", b"{}", [], [fx.pv1]),
        fx.ffitem("chain", fx.froot_two, [b"{}"], [fx.pv1, fx.pv1]),
        fx.ffitem("auth", bad_sig_root, [], [fx.pv1]),
        fx.grow_item("ok"),
    ]
    success("batch_mixed_failures_report", fx.ffreport(mixed_items))
    # failed chain sharing a successor never creates a fork
    fail_no_fork = [
        fx.ffitem("ok", fx.froot_one, [fx.s_grow], [fx.pv1, fx.pv1]),
        fx.ffitem("bad", fx.froot_one, [fx.s_t1, b"{}"],
                  [fx.pv1, fx.pv2_t1, fx.pv2_t1]),
    ]
    success("batch_failed_chain_no_fork_report", fx.ffreport(fail_no_fork))

    # ---- Success: head anchors ---------------------------------------
    anchor = fx.ffseal(clean_batch, "a")
    success("anchor_seal_bytes", anchor)
    success("anchor_verify_result", fx.ffverify(anchor, clean_batch, "a"))
    anchor_later = fx.ffseal(clean_batch, "a", moment=fx.vmoment + 10)
    success("anchor_seal_later_bytes", anchor_later)
    success("anchor_verify_later_result",
            fx.ffverify(anchor_later, clean_batch, "a",
                        moment=fx.vmoment + 10))
    multihop_item = fx.ffitem(
        "h", fx.froot_one, [fx.s_grow, fx.sec_t1],
        [fx.pv1, fx.pv1, fx.pv2_t1])
    anchor_multi = fx.ffseal([multihop_item], "h")
    success("anchor_multi_hop_bytes", anchor_multi)
    success("anchor_multi_hop_verify",
            fx.ffverify(anchor_multi, [multihop_item], "h"))
    # other chains' failures do not block the target
    success("anchor_seal_with_bad_neighbor",
            fx.ffseal([fx.bare_one("a"), fx.ffitem("bad", b"{}")], "a"))

    # ---- Success: fork proof signing / batch verification ------------
    proof_a = fx.ffdacf_proof(issuer=SITE_A)
    proof_b = fx.ffdacf_proof(issuer=SITE_B)
    success("forkproof_fork_bytes_a", proof_a)
    success("forkproof_fork_bytes_b", proof_b)
    success("forkproof_clean_bytes",
            fx.ffdacf_proof(fx.clean_items, issuer=SITE_A))
    success("forkproof_badchain_bytes",
            fx.ffdacf_proof(fx.bad_items, issuer=SITE_A))
    success("forkproof_verify_clean",
            fx.ffdacf_report([proof_item("a", proof_a)]))
    success("forkproof_verify_mixed",
            fx.ffdacf_report([
                proof_item("a", proof_a),
                proof_item("b", b"{}"),
                proof_item("c", proof_b),
            ]))
    # future-dated proof, verified at earlier moment -> invalid-proof
    future_proof = fx.ffdacf_proof(moment=fx.m + 10)
    success("forkproof_future_bytes", future_proof)
    success("forkproof_verify_future_report",
            fx.ffdacf_report([proof_item("a", future_proof)],
                             moment=fx.m))
    # missing signer key -> isolated unauthenticated report
    success("forkproof_verify_unauth_report",
            fx.ffdacf_report(
                [proof_item("a", proof_a)],
                ring={s: keys for s, keys in fx.ring.items()
                      if s != SITE_A}))

    # ---- Success: cross-site adjudication and decision ---------------
    accepted_items = [
        proof_item("x", fx.ffdacf_proof(issuer=SITE_A)),
        proof_item("y", fx.ffdacf_proof(issuer=SITE_B)),
    ]
    decision_accepted = fx.ffdacf_judge(accepted_items)
    success("decision_accepted_bytes", decision_accepted)
    success("decision_accepted_verify",
            fx.ffdacf_verify(decision_accepted))
    # fork-free consensus binds empty common
    clean_proofs = [
        proof_item("x", fx.ffdacf_proof(fx.clean_items, issuer=SITE_A)),
        proof_item("y", fx.ffdacf_proof(fx.clean_items, issuer=SITE_B)),
    ]
    decision_clean = fx.ffdacf_judge(clean_proofs)
    success("decision_forkfree_bytes", decision_clean)
    success("decision_forkfree_verify",
            fx.ffdacf_verify(decision_clean))
    # below threshold keeps declaration; invalid-only binds null
    decision_ins = fx.ffdacf_judge(
        [proof_item("x", fx.ffdacf_proof(issuer=SITE_A))])
    success("decision_insufficient_verify",
            fx.ffdacf_verify(decision_ins))
    decision_novotes = fx.ffdacf_judge(
        [proof_item("x", b"{}"), proof_item("y", b"{")])
    success("decision_no_votes_verify",
            fx.ffdacf_verify(decision_novotes))
    # duplicate and contradiction rows
    decision_dup = fx.ffdacf_judge([
        proof_item("first", proof_a), proof_item("second", proof_a)])
    success("decision_duplicate_verify",
            fx.ffdacf_verify(decision_dup))
    decision_contra = fx.ffdacf_judge([
        proof_item("fork", fx.ffdacf_proof(fx.fork_items, issuer=SITE_A)),
        proof_item("clean", fx.ffdacf_proof(fx.clean_items, issuer=SITE_A)),
    ])
    success("decision_contradiction_verify",
            fx.ffdacf_verify(decision_contra))
    # input-order independence: reversed inputs seal identical bytes
    success("decision_reversed_inputs_bytes",
            fx.ffdacf_judge(list(reversed(accepted_items))))
    # per-item fixed reasons inside the verified decision
    ghost_ring = dict(fx.ring)
    from test_fork_convergence import SECRET_COORD
    ghost_ring["ghost"] = [
        entry(1, SECRET_COORD, not_after=10 ** 9)]
    ghost_proof = fx.ffdacf_sign(issuer="ghost", ring=ghost_ring)
    decision_rows = fx.ffdacf_judge([
        proof_item("ghost", ghost_proof),
        proof_item("good", fx.ffdacf_proof(fx.clean_items, issuer=SITE_A)),
        proof_item("bad", b"{}"),
    ])
    success("decision_mixed_rows_verify",
            fx.ffdacf_verify(decision_rows, ring=ghost_ring))

    # ================= FAILURES =======================================
    # ---- supersede ----------------------------------------------------
    failure("fail_supersede_unchanged_empty",
            lambda: fx.ffdsucc(fx.froot_two, fx.froot_two, [],
                               old=fx.pv1, new=fx.pv1))
    failure("fail_supersede_skip_version",
            lambda: fx.ffdsucc(fx.froot_two, fx.froot_two, [],
                               old=fx.pv1,
                               new=__import__(
                                   "test_supersede_chain_fork_aggregate",
                                   fromlist=["vpol"]).vpol(3, threshold=1)))
    failure("fail_supersede_backwards_effective",
            lambda: fx.ffdsucc(
                fx.froot_two,
                fx.ffdsucc(fx.froot_two, fx.froot_two, [],
                           old=fx.pv1, new=fx.pv2_t1,
                           effective=fx.fm + 5),
                [decision_item("c", fx.free_c)],
                old=fx.pv2_t1, new=fx.pv2_t1,
                effective=fx.fm + 4, moment=fx.fm + 10))
    failure("fail_supersede_repeated_packet",
            lambda: fx.ffdsucc(
                fx.froot_one, fx.froot_one,
                [decision_item("nine", fx.decision_ja)]))
    failure("fail_supersede_repeated_id",
            lambda: fx.ffdsucc(
                fx.froot_one, fx.froot_one,
                [decision_item("one", fx.decision_jb)]))
    failure("fail_supersede_wrong_root_policy",
            lambda: fx.ffdsucc(
                fx.froot_two, fx.froot_two, [],
                old=__import__(
                    "test_supersede_chain_fork_aggregate",
                    fromlist=["vpol"]).vpol(1, sites=(JUDGE,),
                                            threshold=1),
                new=fx.pv2_t1))
    failure("fail_supersede_sealer_not_authorized",
            lambda: fx.ffdsucc(
                fx.froot_two, fx.froot_two, [],
                old=fx.pv1,
                new=__import__(
                    "test_supersede_chain_fork_aggregate",
                    fromlist=["vpol"]).vpol(2, sites=(SITE_C,),
                                            threshold=1),
                issuer=JUDGE))
    failure("fail_supersede_predecessor_root",
            lambda: fx.ffdsucc(
                fx.fmake_aggregate([decision_item("zz", fx.decision_ja)]),
                fx.froot_one, [decision_item("two", fx.decision_jb)]))
    failure("fail_supersede_bad_root_bytes",
            lambda: fx.ffdsucc(b"not-a-packet", b"not-a-packet", []))
    failure("fail_supersede_type_increment",
            lambda: fx.ffdsucc(fx.froot_two, fx.froot_two, "x"))
    failure("fail_supersede_type_moment",
            lambda: supersede_final_fork_decision_aggregate(
                fx.froot_two, fx.froot_two, [], *pol, fx.pv1, fx.pv2_t1,
                fx.ring, True, fx.fm, JUDGE, 1))
    failure("fail_supersede_negative_moment",
            lambda: supersede_final_fork_decision_aggregate(
                fx.froot_two, fx.froot_two, [], *pol, fx.pv1, fx.pv2_t1,
                fx.ring, -1, fx.fm, JUDGE, 1))
    failure("fail_supersede_type_issuer",
            lambda: fx.ffdsucc(fx.froot_two, fx.froot_two, [], issuer=7))
    failure("fail_supersede_empty_issuer",
            lambda: fx.ffdsucc(fx.froot_two, fx.froot_two, [], issuer=""))
    failure("fail_supersede_type_version",
            lambda: fx.ffdsucc(fx.froot_two, fx.froot_two, [], version=True))
    failure("fail_supersede_zero_version",
            lambda: fx.ffdsucc(fx.froot_two, fx.froot_two, [], version=0))
    failure("fail_supersede_type_root",
            lambda: supersede_final_fork_decision_aggregate(
                "x", fx.froot_one, [], *pol, fx.pv1, fx.pv2_t1,
                fx.ring, fx.fm + 10, fx.fm, JUDGE, 1))
    failure("fail_supersede_unknown_sealer",
            lambda: supersede_final_fork_decision_aggregate(
                fx.froot_two, fx.froot_two, [], *pol, fx.pv1, fx.pv2_t1,
                {s: fx.ring[s] for s in fx.ring if s != JUDGE},
                fx.fm + 10, fx.fm, JUDGE, 1))
    failure("fail_supersede_revoked_prefix",
            lambda: fx.ffdsucc(
                grow, ring_with(fx, SITE_C, 1, revoked=True),
                fx.fm + 20, fx.fm + 5, old=None, new=None)
            if False else
            supersede_final_fork_decision_aggregate(
                fx.froot_one, grow, [], *pol, fx.pv1, fx.pv2_t1,
                ring_with(fx, SITE_C, 1, revoked=True),
                fx.fm + 20, fx.fm + 5, JUDGE, 1))
    future_ring = copy.deepcopy(fx.ring)
    future_ring[SITE_C] = [
        entry(1, fx.ring[SITE_C][0]["secret"],
              not_before=fx.fm + 5, not_after=10 ** 9)]
    decision_jb_packet = fx.facf_decision(fx.ffork_proofs, SITE_C)
    failure("fail_supersede_increment_future_key",
            lambda: supersede_final_fork_decision_aggregate(
                fx.froot_one, fx.froot_one,
                [decision_item("two", decision_jb_packet)],
                *pol, fx.pv1, fx.pv1, future_ring,
                fx.fm + 20, fx.fm, JUDGE, 1))

    # ---- chain verification ------------------------------------------
    failure("fail_chain_bad_root",
            lambda: fx.ffdchain(b"{}", []))
    failure("fail_chain_garbage_root_ff",
            lambda: fx.ffdchain(b"\xff", []))
    failure("fail_chain_tampered_height",
            lambda: fx.ffdchain(
                fx.froot_one,
                [resign_successor(fx, grow, lambda p: p.__setitem__(
                    "height", 9))],
                policies=[fx.pv1, fx.pv1]))
    failure("fail_chain_tampered_root_digest",
            lambda: fx.ffdchain(
                fx.froot_one,
                [resign_successor(fx, grow, lambda p: p.__setitem__(
                    "rootDigest", "0" * 64))],
                policies=[fx.pv1, fx.pv1]))
    failure("fail_chain_tampered_invariant",
            lambda: fx.ffdchain(
                fx.froot_one,
                [resign_successor(fx, grow, lambda p: p.__setitem__(
                    "sitePolicyDigest", "9" * 64))],
                policies=[fx.pv1, fx.pv1]))
    failure("fail_chain_tampered_status",
            lambda: fx.ffdchain(
                fx.froot_one,
                [resign_successor(fx, grow, lambda p: p.__setitem__(
                    "status", "insufficient"))],
                policies=[fx.pv1, fx.pv1]))
    failure("fail_chain_tampered_policy_version",
            lambda: fx.ffdchain(
                fx.froot_one,
                [resign_successor(fx, grow, lambda p: p.__setitem__(
                    "policyVersion", 2))],
                policies=[fx.pv1, fx.pv1]))
    failure("fail_chain_backwards_effective",
            lambda: fx.ffdchain(
                fx.froot_one,
                [grow, resign_successor(
                    fx, rotate,
                    lambda p: p.__setitem__("effectiveAt", fx.fm - 1))],
                policies=[fx.pv1, fx.pv1, fx.pv2_t1]))
    failure("fail_chain_noncanonical",
            lambda: fx.ffdchain(
                fx.froot_one,
                [(grow.decode("utf-8") + "\n").encode()],
                policies=[fx.pv1, fx.pv1]))
    bad_sig = json.loads(grow.decode())
    bad_sig["signature"] = "0" * 64
    failure("fail_chain_bad_signature",
            lambda: fx.ffdchain(
                fx.froot_one, [_prune_compact(bad_sig)],
                policies=[fx.pv1, fx.pv1]))
    failure("fail_chain_wrong_policy_count",
            lambda: verify_final_fork_decision_aggregate_chain(
                fx.froot_one, [grow], *pol, [fx.pv1], fx.ring, fx.fm + 10))
    failure("fail_chain_root_policy_version",
            lambda: verify_final_fork_decision_aggregate_chain(
                fx.froot_one, [grow], *pol,
                [__import__("test_supersede_chain_fork_aggregate",
                            fromlist=["vpol"]).vpol(2), fx.pv1],
                fx.ring, fx.fm + 10))
    failure("fail_chain_type_root",
            lambda: verify_final_fork_decision_aggregate_chain(
                "x", [], *pol, [fx.pv1], fx.ring, fx.fm))
    failure("fail_chain_type_successors",
            lambda: verify_final_fork_decision_aggregate_chain(
                fx.froot_two, "x", *pol, [fx.pv1], fx.ring, fx.fm))
    failure("fail_chain_type_successor_element",
            lambda: verify_final_fork_decision_aggregate_chain(
                fx.froot_two, ["x"], *pol, [fx.pv1, fx.pv1],
                fx.ring, fx.fm))
    failure("fail_chain_type_moment",
            lambda: verify_final_fork_decision_aggregate_chain(
                fx.froot_two, [], *pol, [fx.pv1], fx.ring, True))
    failure("fail_chain_negative_moment",
            lambda: verify_final_fork_decision_aggregate_chain(
                fx.froot_two, [], *pol, [fx.pv1], fx.ring, -1))
    failure("fail_chain_revoked_key",
            lambda: fx.ffdchain(
                fx.froot_two, [],
                ring=ring_with(fx, JUDGE, 1, revoked=True)))
    failure("fail_chain_future_key",
            lambda: fx.ffdchain(
                fx.froot_two, [],
                ring=ring_with(fx, JUDGE, 1, notBefore=fx.vmoment + 1,
                               notAfter=10 ** 9), moment=fx.vmoment))
    failure("fail_chain_expired_key",
            lambda: fx.ffdchain(
                fx.froot_two, [],
                ring=ring_with(fx, JUDGE, 1, notBefore=0,
                               notAfter=fx.vmoment - 1), moment=fx.vmoment))
    failure("fail_chain_unknown_issuer",
            lambda: fx.ffdchain(
                fx.froot_two, [], ring={"else": [entry(1, "22" * 32)]}))
    failure("fail_chain_expired_prefix_late_moment",
            lambda: fx.ffdchain(
                fx.froot_one, [grow],
                ring=ring_with(fx, SITE_C, 1, notAfter=fx.fm + 15),
                moment=fx.fm + 100))
    failure("fail_chain_foreign_adjudication_policy",
            lambda: fx.ffdchain(
                fx.froot_two, [],
                adjp={"sites": {SITE_A: {1}}, "threshold": 1}))

    # ---- batch --------------------------------------------------------
    failure("fail_batch_type_items",
            lambda: fx.ffreport((fx.bare_one(),)))
    failure("fail_batch_empty", lambda: fx.ffreport([]))
    failure("fail_batch_type_id",
            lambda: fx.ffreport([fx.ffitem(1, fx.froot_two)]))
    failure("fail_batch_empty_id",
            lambda: fx.ffreport([fx.ffitem("", fx.froot_two)]))
    failure("fail_batch_duplicate_id",
            lambda: fx.ffreport([fx.bare_one("a"), fx.grow_item("a")]))
    failure("fail_batch_type_root",
            lambda: fx.ffreport([fx.ffitem("a", fx.froot_two.hex())]))
    failure("fail_batch_type_successors",
            lambda: fx.ffreport(
                _mutate_item(fx, fx.bare_one(), "successors",
                             (fx.s_grow,))))
    failure("fail_batch_type_successor",
            lambda: fx.ffreport([fx.ffitem(
                "a", fx.froot_one, [fx.s_grow.hex()], [fx.pv1, fx.pv1])]))
    failure("fail_batch_policy_count",
            lambda: fx.ffreport([fx.ffitem(
                "a", fx.froot_one, [fx.s_grow], [fx.pv1])]))
    failure("fail_batch_root_policy_v2",
            lambda: fx.ffreport([fx.ffitem(
                "a", fx.froot_two, [],
                [__import__("test_supersede_chain_fork_aggregate",
                            fromlist=["vpol"]).vpol(2)])]))
    failure("fail_batch_type_moment",
            lambda: fx.ffreport([fx.bare_one()], moment=True))
    failure("fail_batch_negative_moment",
            lambda: fx.ffreport([fx.bare_one()], moment=-1))
    failure("fail_batch_bad_policy",
            lambda: fx.ffreport(
                [fx.bare_one()],
                adjp={"sites": {}, "threshold": 1}))
    failure("fail_batch_type_keyring",
            lambda: fx.ffreport([fx.bare_one()], ring={"x": "nope"}))

    # ---- anchors ------------------------------------------------------
    failure("fail_anchor_seal_conflicted",
            lambda: fx.ffseal(fork_items, "a"))
    failure("fail_anchor_seal_insufficient",
            lambda: fx.ffseal([fx.ffitem("a", fx.froot_one)], "a"))
    failure("fail_anchor_seal_unknown_target",
            lambda: fx.ffseal([fx.bare_one("a")], "missing"))
    failure("fail_anchor_seal_type_target",
            lambda: fx.ffseal([fx.bare_one("a")], 7))
    failure("fail_anchor_seal_empty_target",
            lambda: fx.ffseal([fx.bare_one("a")], ""))
    failure("fail_anchor_seal_type_issuer",
            lambda: fx.ffseal(clean_batch, "a", issuer=7))
    failure("fail_anchor_seal_empty_issuer",
            lambda: fx.ffseal(clean_batch, "a", issuer=""))
    failure("fail_anchor_seal_type_version",
            lambda: fx.ffseal(clean_batch, "a", version=True))
    failure("fail_anchor_seal_zero_version",
            lambda: fx.ffseal(clean_batch, "a", version=0))
    failure("fail_anchor_seal_type_moment",
            lambda: fx.ffseal(clean_batch, "a", moment=True))
    failure("fail_anchor_seal_negative_moment",
            lambda: fx.ffseal(clean_batch, "a", moment=-1))
    failure("fail_anchor_seal_bad_root_target",
            lambda: fx.ffseal([fx.ffitem("a", b"{}")], "a"))
    failure("fail_anchor_seal_bad_chain_target",
            lambda: fx.ffseal([
                fx.ffitem("a", fx.froot_two, [b"{}"], [fx.pv1, fx.pv1])],
                "a"))
    failure("fail_anchor_seal_revoked",
            lambda: seal_final_fork_decision_aggregate_head(
                [fx.bare_one("a")], "a", *pol,
                ring_with(fx, JUDGE, 1, revoked=True),
                fx.vmoment, JUDGE, 1))
    failure("fail_anchor_seal_unknown_signer",
            lambda: fx.ffseal([fx.bare_one("a")], "a",
                              issuer="nobody", version=1))
    failure("fail_anchor_verify_type_anchor",
            lambda: fx.ffverify("bytes", clean_batch, "a"))
    failure("fail_anchor_verify_type_target",
            lambda: fx.ffverify(anchor, clean_batch, 7))
    failure("fail_anchor_verify_empty_target",
            lambda: fx.ffverify(anchor, clean_batch, ""))
    failure("fail_anchor_verify_unknown_target",
            lambda: fx.ffverify(anchor, clean_batch, "missing"))
    failure("fail_anchor_verify_type_moment",
            lambda: fx.ffverify(anchor, clean_batch, "a", moment=True))
    failure("fail_anchor_verify_negative_moment",
            lambda: fx.ffverify(anchor, clean_batch, "a", moment=-1))
    failure("fail_anchor_verify_bad_sig",
            lambda: fx.ffverify(
                _prune_compact(_tamper(json.loads(anchor.decode()),
                                       sig=True)),
                clean_batch, "a"))
    failure("fail_anchor_verify_unknown_signer",
            lambda: fx.ffverify(
                anchor, clean_batch, "a",
                ring={s: fx.ring[s] for s in fx.ring if s != JUDGE}))
    failure("fail_anchor_verify_revoked",
            lambda: fx.ffverify(
                anchor, clean_batch, "a",
                ring=ring_with(fx, JUDGE, 1, revoked=True)))
    failure("fail_anchor_verify_expired",
            lambda: fx.ffverify(
                anchor, clean_batch, "a",
                ring=ring_with(fx, JUDGE, 1, notAfter=fx.vmoment - 1)))
    failure("fail_anchor_verify_future_sealed",
            lambda: fx.ffverify(anchor_later, clean_batch, "a",
                                moment=fx.vmoment))
    failure("fail_anchor_verify_garbage_empty",
            lambda: fx.ffverify(b"", clean_batch, "a"))
    failure("fail_anchor_verify_garbage_ff",
            lambda: fx.ffverify(b"\xff", clean_batch, "a"))
    failure("fail_anchor_verify_json_array",
            lambda: fx.ffverify(b"[]", clean_batch, "a"))
    failure("fail_anchor_verify_trailing_newline",
            lambda: fx.ffverify(anchor + b"\n", clean_batch, "a"))
    failure("fail_anchor_verify_tampered_height",
            lambda: fx.ffverify(
                fx.ffrewrap(_tamper(json.loads(anchor.decode())["payload"],
                                    height=5)),
                clean_batch, "a"))
    failure("fail_anchor_verify_tampered_root",
            lambda: fx.ffverify(
                fx.ffrewrap(_tamper(json.loads(anchor.decode())["payload"],
                                    rootDigest="2" * 64)),
                clean_batch, "a"))
    failure("fail_anchor_verify_tampered_head",
            lambda: fx.ffverify(
                fx.ffrewrap(_tamper(json.loads(anchor.decode())["payload"],
                                    headDigest="3" * 64)),
                clean_batch, "a"))
    failure("fail_anchor_verify_tampered_policy_digest",
            lambda: fx.ffverify(
                fx.ffrewrap(_tamper(json.loads(anchor.decode())["payload"],
                                    policyDigest="4" * 64)),
                clean_batch, "a"))
    failure("fail_anchor_verify_tampered_policy_version",
            lambda: fx.ffverify(
                fx.ffrewrap(_tamper(json.loads(anchor.decode())["payload"],
                                    policyVersion=2)),
                clean_batch, "a"))
    failure("fail_anchor_verify_tampered_declaration",
            lambda: fx.ffverify(
                fx.ffrewrap(_tamper(json.loads(anchor.decode())["payload"],
                                    declarationDigest="5" * 64)),
                clean_batch, "a"))
    failure("fail_anchor_verify_tampered_version",
            lambda: fx.ffverify(
                fx.ffrewrap(_tamper(json.loads(anchor.decode())["payload"],
                                    version=2)),
                clean_batch, "a"))
    failure("fail_anchor_verify_drifted_head",
            lambda: fx.ffverify(
                anchor,
                [fx.ffitem("a", fx.froot_two, [fx.t_rot],
                           [fx.pv1, fx.pv2_t1])], "a"))
    failure("fail_anchor_verify_bad_root_target",
            lambda: fx.ffverify(anchor, [fx.ffitem("a", b"{}")], "a"))

    # ---- fork proof signing / batch verification ---------------------
    failure("fail_proof_sign_empty_items",
            lambda: fx.ffdacf_sign([]))
    failure("fail_proof_sign_duplicate_ids",
            lambda: fx.ffdacf_sign(fx.fork_items + fx.fork_items))
    failure("fail_proof_sign_type_issuer",
            lambda: fx.ffdacf_sign(issuer=9))
    failure("fail_proof_sign_empty_issuer",
            lambda: fx.ffdacf_sign(issuer=""))
    failure("fail_proof_sign_type_version",
            lambda: fx.ffdacf_sign(version=True))
    failure("fail_proof_sign_zero_version",
            lambda: fx.ffdacf_sign(version=0))
    failure("fail_proof_sign_type_moment",
            lambda: fx.ffdacf_sign(moment=True))
    failure("fail_proof_sign_negative_moment",
            lambda: fx.ffdacf_sign(moment=-1))
    failure("fail_proof_sign_unknown_credential",
            lambda: fx.ffdacf_sign(issuer="ghost"))
    failure("fail_proof_sign_bad_prune_policy",
            lambda: fx.ffdacf_sign(prune_policy={"batch": "x"}))
    failure("fail_proof_sign_bad_auth_policy",
            lambda: fx.ffdacf_sign(
                auth={"sites": {SITE_A: {1}}, "threshold": 2}))
    failure("fail_proofs_verify_type_items",
            lambda: fx.ffdacf_report("x"))
    failure("fail_proofs_verify_empty",
            lambda: fx.ffdacf_report([]))
    failure("fail_proofs_verify_duplicate_ids",
            lambda: fx.ffdacf_report(
                [proof_item("a", proof_a), proof_item("a", proof_a)]))
    failure("fail_proofs_verify_wrong_keys",
            lambda: fx.ffdacf_report(
                [{"id": "a", "proof": proof_a, "x": 1}]))
    failure("fail_proofs_verify_type_id",
            lambda: fx.ffdacf_report([proof_item(1, proof_a)]))
    failure("fail_proofs_verify_type_proof",
            lambda: fx.ffdacf_report([proof_item("a", "x")]))
    failure("fail_proofs_verify_type_moment",
            lambda: verify_final_fork_decision_aggregate_chain_fork_proofs(
                [proof_item("a", proof_a)], *pol, fx.ring, True))
    # proof byte faults surface as isolated invalid-proof reports, but
    # verify_core direct faults (via adjudication path) record classes:
    proof_trail = proof_a + b"\n"
    failure("fail_proof_trailing_newline_direct",
            lambda: _direct_proof_parse(fx, proof_trail))
    failure("fail_proof_garbage_direct",
            lambda: _direct_proof_parse(fx, b"not-json"))
    failure("fail_proof_empty_direct",
            lambda: _direct_proof_parse(fx, b""))

    # ---- adjudication -------------------------------------------------
    failure("fail_adjudicate_type_items",
            lambda: fx.ffdacf_judge("x"))
    failure("fail_adjudicate_empty_items",
            lambda: fx.ffdacf_judge([]))
    failure("fail_adjudicate_empty_id",
            lambda: fx.ffdacf_judge([proof_item("", proof_a)]))
    failure("fail_adjudicate_duplicate_id",
            lambda: fx.ffdacf_judge(
                [proof_item("a", proof_a), proof_item("a", proof_a)]))
    failure("fail_adjudicate_threshold",
            lambda: fx.ffdacf_judge(
                [proof_item("a", proof_a)],
                proofp={"sites": {SITE_A: {1}}, "threshold": 2}))
    failure("fail_adjudicate_type_moment",
            lambda: fx.ffdacf_judge([proof_item("a", proof_a)], moment=True))
    failure("fail_adjudicate_negative_moment",
            lambda: fx.ffdacf_judge([proof_item("a", proof_a)], moment=-1))
    failure("fail_adjudicate_type_issuer",
            lambda: fx.ffdacf_judge([proof_item("a", proof_a)], issuer=7))
    failure("fail_adjudicate_empty_issuer",
            lambda: fx.ffdacf_judge([proof_item("a", proof_a)], issuer=""))
    failure("fail_adjudicate_type_version",
            lambda: fx.ffdacf_judge([proof_item("a", proof_a)], version=True))
    failure("fail_adjudicate_zero_version",
            lambda: fx.ffdacf_judge([proof_item("a", proof_a)], version=0))
    failure("fail_adjudicate_unknown_credential",
            lambda: fx.ffdacf_judge([proof_item("a", proof_a)],
                                   issuer="nobody"))
    failure("fail_adjudicate_wrong_version",
            lambda: fx.ffdacf_judge([proof_item("a", proof_a)],
                                   issuer=JUDGE, version=2))
    failure("fail_adjudicate_bad_prune_policy",
            lambda: adjudicate_final_fork_decision_aggregate_chain_forks(
                [proof_item("a", proof_a)], {"batch": "x"}, fx.auth,
                fx.ssp, fx.fsignerp, fx.adjp, fx.proofp, fx.ring,
                fx.m, JUDGE, 1))
    failure("fail_adjudicate_bad_auth_policy",
            lambda: adjudicate_final_fork_decision_aggregate_chain_forks(
                [proof_item("a", proof_a)], fx.policy, {"sites": {}},
                fx.ssp, fx.fsignerp, fx.adjp, fx.proofp, fx.ring,
                fx.m, JUDGE, 1))

    # ---- decision verification ---------------------------------------
    failure("fail_decision_type_decision",
            lambda: verify_final_fork_decision_aggregate_chain_fork_decision(
                "x", *pol, fx.proofp, fx.ring, fx.m))
    failure("fail_decision_type_moment",
            lambda: verify_final_fork_decision_aggregate_chain_fork_decision(
                decision_accepted, *pol, fx.proofp, fx.ring, True))
    failure("fail_decision_bad_proofp",
            lambda: fx.ffdacf_verify(
                decision_accepted,
                proofp={"sites": {SITE_A: {1}}, "threshold": 1}))
    failure("fail_decision_bad_sp",
            lambda: fx.ffdacf_verify(
                decision_accepted,
                sp={"sites": {SITE_A: {1}, SITE_B: {1}}, "threshold": 1}))
    failure("fail_decision_bad_prune",
            lambda: fx.ffdacf_verify(
                decision_accepted,
                prune_policy={"batch": "other",
                              "sites": {s: {1} for s in fx.policy["sites"]},
                              "threshold": fx.policy["threshold"]}))
    failure("fail_decision_trailing_newline",
            lambda: fx.ffdacf_verify(decision_accepted + b"\n"))
    failure("fail_decision_empty_bytes",
            lambda: fx.ffdacf_verify(b""))
    failure("fail_decision_json_array",
            lambda: fx.ffdacf_verify(b"[]"))
    failure("fail_decision_bad_sig",
            lambda: fx.ffdacf_verify(
                _prune_compact(_tamper(json.loads(decision_accepted.decode()),
                                       sig=True))))
    failure("fail_decision_revoked",
            lambda: fx.ffdacf_verify(
                decision_accepted,
                ring={**fx.ring,
                      JUDGE: [entry(1, SECRET_COORD, revoked=True)]}))
    failure("fail_decision_future_key",
            lambda: fx.ffdacf_verify(
                decision_accepted,
                ring={**fx.ring,
                      JUDGE: [entry(1, SECRET_COORD,
                                    not_before=fx.m + 1)]}))
    failure("fail_decision_expired_key",
            lambda: fx.ffdacf_verify(
                decision_accepted,
                ring={**fx.ring,
                      JUDGE: [entry(1, SECRET_COORD,
                                    not_after=fx.m - 1)]}))
    # tampered and re-signed: tally/binding faults
    failure("fail_decision_tampered_status",
            lambda: fx.ffdacf_verify(_decision_rewrap(
                decision_accepted, lambda p: p.__setitem__(
                    "status", "insufficient"))))
    failure("fail_decision_tampered_common",
            lambda: fx.ffdacf_verify(_decision_rewrap(
                decision_accepted, lambda p: p.__setitem__("common", []))))
    failure("fail_decision_tampered_row",
            lambda: fx.ffdacf_verify(_decision_rewrap(
                decision_accepted,
                lambda p: (p["items"][0].__setitem__("conclusion",
                                                     "duplicate"),
                           p["items"][0].__setitem__("reason",
                                                     "duplicate")))))
    failure("fail_decision_reordered_proofs",
            lambda: fx.ffdacf_verify(_decision_rewrap(
                decision_accepted,
                lambda p: p.__setitem__("proofs",
                                        list(reversed(p["proofs"]))))))
    failure("fail_decision_foreign_proof_digest",
            lambda: fx.ffdacf_verify(_decision_rewrap(
                decision_accepted,
                lambda p: p["proofs"].__setitem__(0, "dd" * 32))))
    failure("fail_decision_reordered_rows",
            lambda: fx.ffdacf_verify(_decision_rewrap(
                decision_accepted,
                lambda p: p.__setitem__("items",
                                        list(reversed(p["items"]))))))

    return vectors


def _mutate_item(fx, item, key, value):
    item[key] = value
    return [item]


def _tamper(obj, sig=False, **changes):
    if sig:
        obj["signature"] = "0" * 64
    for key, value in changes.items():
        obj[key] = value
    return obj


def _decision_rewrap(raw, mutate):
    from test_supersede_decision_aggregate import rewrap
    data = json.loads(raw.decode())
    mutate(data["payload"])
    return rewrap(data["payload"])


def _direct_proof_parse(fx, raw):
    # Go through the public batch verifier path but force the structural
    # fault class to surface by parsing through the package private core
    # is unnecessary: instead call the single-proof sign verification
    # core indirectly through adjudication's structural row, which keeps
    # the fault isolated. Here we surface the raw parse class.
    from offline_coordination.replication import _parse_ffdacf_fork_proof
    return _parse_ffdacf_fork_proof(raw)


def encode(value):
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"cannot encode {type(value)}")


def main(argv):
    if len(argv) == 2:
        vectors = collect()
        with open(argv[1], "w", encoding="utf-8") as handle:
            json.dump(vectors, handle, indent=1, sort_keys=True)
        print(f"captured {len(vectors)} vectors -> {argv[1]}")
        return 0
    if len(argv) == 3 and argv[1] == "--diff":
        with open(argv[2], encoding="utf-8") as handle:
            expected = json.load(handle)
        current = collect()
        mismatches = []
        missing = sorted(set(expected) - set(current))
        extra = sorted(set(current) - set(expected))
        for name in missing:
            mismatches.append(f"MISSING {name}")
        for name in extra:
            mismatches.append(f"EXTRA   {name}")
        for name in sorted(set(expected) & set(current)):
            if expected[name] != current[name]:
                mismatches.append(
                    f"DIFF    {name}\n      expected={expected[name]}\n      "
                    f"current ={current[name]}")
        if mismatches:
            print("\n".join(mismatches))
            print(f"\n{len(mismatches)} mismatches")
            return 1
        print(f"all {len(expected)} vectors match")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
