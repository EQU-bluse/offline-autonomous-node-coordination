"""Differential golden-vector capture for the final fork decision
aggregate chain fork decision batch/aggregate boundary refactor.

Run against the baseline to dump every public success value and every
public failure (exception class + message) of
``verify_final_fork_decision_aggregate_chain_fork_decisions``,
``aggregate_final_fork_decision_aggregate_chain_fork_decisions`` and
``verify_final_fork_decision_aggregate_chain_fork_decision_aggregate``
to JSON, then run again after the refactor and diff.

Usage:
    python3 tests/_golden_capture_fork_decision_aggregates.py /tmp/golden.json
    python3 tests/_golden_capture_fork_decision_aggregates.py --diff /tmp/golden.json
"""

import copy
import json
import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _TESTS_DIR)
sys.path.insert(0, os.path.dirname(_TESTS_DIR))

from offline_coordination.replication import (  # noqa: E402
    _prune_compact,
    aggregate_final_fork_decision_aggregate_chain_fork_decisions,
    verify_final_fork_decision_aggregate_chain_fork_decisions,
    verify_final_fork_decision_aggregate_chain_fork_decision_aggregate,
)

from _golden_capture import encode  # noqa: E402
from test_final_fork_decision_aggregate_chain_fork_decision_aggregates import (  # noqa: E402
    FinalForkDecisionAggregateChainForkDecisionFixtures,
    parse,
)
from test_aggregate_prune_fork_decisions import decision_item  # noqa: E402
from test_fork_convergence import entry  # noqa: E402
from test_prune_attestations import JUDGE, SITE_A, SITE_B  # noqa: E402

JUDGE_B = "site-c"
SECRET_V2_A = "22" * 32
SECRET_V2_B = "33" * 32


def make_fixture():
    fx = FinalForkDecisionAggregateChainForkDecisionFixtures()
    fx.setUp()
    return fx


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

    items = fx.fdecision_items()
    free_items = [
        decision_item("one", fx.free_ja),
        decision_item("two", fx.free_jb),
    ]

    # ---- Success: batch reports ---------------------------------------
    success("batch_two_verified", fx.cfd_batch_report(items))
    success("batch_reversed_order",
            fx.cfd_batch_report(list(reversed(items))))
    success("batch_fork_free", fx.cfd_batch_report(free_items))
    tampered = parse(fx.decision_ja)["payload"]
    tampered["status"] = "insufficient"
    success("batch_mixed_isolation", fx.cfd_batch_report([
        decision_item("garbage", b"{"),
        decision_item("tampered", fx.rewrap(tampered)),
        decision_item("ok", fx.decision_jb),
    ]))
    revoked = copy.deepcopy(fx.ring)
    revoked[JUDGE][0]["revoked"] = True
    success("batch_one_site_revoked",
            fx.cfd_batch_report(items, ring=revoked))
    rotated = copy.deepcopy(fx.ring)
    rotated[JUDGE] = rotated[JUDGE] + [entry(2, SECRET_V2_A)]
    rotated[JUDGE_B] = rotated[JUDGE_B] + [entry(2, SECRET_V2_B)]
    decision_v2 = fx.ffdacf_judge(
        fx.fork_proof_items, ring=rotated, issuer=JUDGE, version=2)
    success("batch_rotated_key",
            fx.cfd_batch_report(
                [decision_item("v2", decision_v2)], ring=rotated))
    expired = copy.deepcopy(rotated)
    expired[JUDGE] = [entry(2, SECRET_V2_A, not_after=fx.m - 1)]
    success("batch_expired_rotated_key",
            fx.cfd_batch_report(
                [decision_item("v2", decision_v2)], ring=expired))

    # ---- Success: aggregate packets and their offline reviews ---------
    dsp2 = {"sites": {JUDGE: {2}, JUDGE_B: {2}}, "threshold": 2}
    dsp3 = {"sites": {JUDGE: {1}, JUDGE_B: {1}, SITE_A: {1}},
            "threshold": 2}
    free_c = fx.ffdacf_judge(fx.free_proof_items, issuer=SITE_A)
    rotated_items = [
        decision_item("one", fx.ffdacf_judge(
            fx.fork_proof_items, ring=rotated, issuer=JUDGE, version=2)),
        decision_item("two", fx.ffdacf_judge(
            fx.fork_proof_items, ring=rotated, issuer=JUDGE_B, version=2)),
    ]
    aggregates = {
        "accepted": (fx.cfd_make_aggregate(items), {}),
        "insufficient": (
            fx.cfd_make_aggregate([decision_item("one", fx.decision_ja)]),
            {}),
        "no_votes": (fx.cfd_make_aggregate(
            [decision_item("bad", b"{}")]), {}),
        "duplicate": (fx.cfd_make_aggregate([
            decision_item("a", fx.decision_ja),
            decision_item("b", fx.decision_ja)]), {}),
        "contradiction": (fx.cfd_make_aggregate([
            decision_item("a", fx.decision_ja),
            decision_item("b", fx.free_ja)]), {}),
        "conflicted": (fx.cfd_make_aggregate([
            decision_item("a", fx.decision_ja),
            decision_item("b", fx.decision_jb),
            decision_item("c", free_c)], dsp=dsp3), {"dsp": dsp3}),
        "fork_free": (fx.cfd_make_aggregate(free_items), {}),
        "mixed_bad_item": (fx.cfd_make_aggregate([
            decision_item("bad", b"{"),
            decision_item("one", fx.decision_ja),
            decision_item("two", fx.decision_jb)]), {}),
        "reversed_inputs": (
            fx.cfd_make_aggregate(list(reversed(items))), {}),
        "rotated": (fx.cfd_make_aggregate(
            rotated_items, dsp=dsp2, ring=rotated,
            issuer=JUDGE, version=2),
            {"dsp": dsp2, "ring": rotated}),
    }
    for name, (raw, verify_kwargs) in aggregates.items():
        success(f"aggregate_{name}_bytes", raw)
        success(f"aggregate_{name}_verify",
                fx.cfd_verify_aggregate(raw, **verify_kwargs))

    # ================= FAILURES ========================================
    # ---- batch ---------------------------------------------------------
    failure("fail_batch_type_items",
            lambda: fx.cfd_batch_report((items[0],)))
    failure("fail_batch_empty", lambda: fx.cfd_batch_report([]))
    failure("fail_batch_type_item",
            lambda: fx.cfd_batch_report(["nope"]))
    failure("fail_batch_wrong_keys",
            lambda: fx.cfd_batch_report(
                [{"id": "one", "decision": fx.decision_ja, "x": 1}]))
    failure("fail_batch_type_id",
            lambda: fx.cfd_batch_report(
                [{"id": 1, "decision": fx.decision_ja}]))
    failure("fail_batch_empty_id",
            lambda: fx.cfd_batch_report(
                [{"id": "", "decision": fx.decision_ja}]))
    failure("fail_batch_duplicate_id",
            lambda: fx.cfd_batch_report([
                decision_item("one", fx.decision_ja),
                decision_item("one", fx.decision_jb)]))
    failure("fail_batch_type_decision",
            lambda: fx.cfd_batch_report([{"id": "one", "decision": "x"}]))
    failure("fail_batch_type_moment",
            lambda: fx.cfd_batch_report(items, moment=True))
    failure("fail_batch_negative_moment",
            lambda: fx.cfd_batch_report(items, moment=-1))
    failure("fail_batch_bad_invariant_policy",
            lambda: verify_final_fork_decision_aggregate_chain_fork_decisions(
                items, fx.policy, fx.auth, fx.ssp,
                {"sites": {}, "threshold": 1}, fx.adjp, fx.proofp,
                fx.ring, fx.m))
    failure("fail_batch_bad_proof_policy",
            lambda: fx.cfd_batch_report(
                items, proofp={"sites": {}, "threshold": 1}))
    failure("fail_batch_type_keyring",
            lambda: fx.cfd_batch_report(items, ring={"x": "nope"}))

    # ---- aggregate sealing ---------------------------------------------
    failure("fail_aggregate_type_items",
            lambda: fx.cfd_make_aggregate((items[0],)))
    failure("fail_aggregate_empty", lambda: fx.cfd_make_aggregate([]))
    failure("fail_aggregate_duplicate_id",
            lambda: fx.cfd_make_aggregate([
                decision_item("one", fx.decision_ja),
                decision_item("one", fx.decision_jb)]))
    failure("fail_aggregate_bad_dsp",
            lambda: fx.cfd_make_aggregate(
                items, dsp={"sites": {}, "threshold": 1}))
    failure("fail_aggregate_type_moment",
            lambda: fx.cfd_make_aggregate(items, moment=True))
    failure("fail_aggregate_negative_moment",
            lambda: fx.cfd_make_aggregate(items, moment=-1))
    failure("fail_aggregate_type_issuer",
            lambda: fx.cfd_make_aggregate(items, issuer=7))
    failure("fail_aggregate_empty_issuer",
            lambda: fx.cfd_make_aggregate(items, issuer=""))
    failure("fail_aggregate_type_version",
            lambda: fx.cfd_make_aggregate(items, version=True))
    failure("fail_aggregate_zero_version",
            lambda: fx.cfd_make_aggregate(items, version=0))
    failure("fail_aggregate_unknown_signer",
            lambda: fx.cfd_make_aggregate(items, issuer="nobody"))
    failure("fail_aggregate_wrong_version",
            lambda: fx.cfd_make_aggregate(items, issuer=JUDGE, version=2))
    failure("fail_aggregate_revoked_signer",
            lambda: fx.cfd_make_aggregate(items, ring=revoked))
    future = copy.deepcopy(fx.ring)
    future[JUDGE] = [entry(1, fx.ring[JUDGE][0]["secret"],
                           not_before=fx.m + 1)]
    failure("fail_aggregate_future_signer",
            lambda: fx.cfd_make_aggregate(items, ring=future))
    expired_signer = copy.deepcopy(fx.ring)
    expired_signer[JUDGE] = [entry(1, fx.ring[JUDGE][0]["secret"],
                                   not_after=fx.m - 1)]
    failure("fail_aggregate_expired_signer",
            lambda: fx.cfd_make_aggregate(items, ring=expired_signer))

    # ---- aggregate review ----------------------------------------------
    raw = aggregates["accepted"][0]

    def rewrapped(mutate):
        payload = parse(raw)["payload"]
        mutate(payload)
        return fx.rewrap(payload)

    failure("fail_verify_type_aggregate",
            lambda: fx.cfd_verify_aggregate("bytes"))
    failure("fail_verify_empty", lambda: fx.cfd_verify_aggregate(b""))
    failure("fail_verify_trailing_newline",
            lambda: fx.cfd_verify_aggregate(raw + b"\n"))
    failure("fail_verify_noncanonical",
            lambda: fx.cfd_verify_aggregate(raw.replace(b":", b": ", 1)))
    failure("fail_verify_json_array",
            lambda: fx.cfd_verify_aggregate(b"[]"))
    failure("fail_verify_bad_signature",
            lambda: fx.cfd_verify_aggregate(_prune_compact(
                {**parse(raw), "signature": "00" * 32})))
    for field in (
        "prunePolicyDigest", "authorizationPolicyDigest",
        "sitePolicyDigest", "signerSitePolicyDigest",
        "adjudicationSitePolicyDigest", "proofSitePolicyDigest",
        "decisionSitePolicyDigest",
    ):
        failure(f"fail_verify_tampered_{field}",
                lambda field=field: fx.cfd_verify_aggregate(rewrapped(
                    lambda p: p.__setitem__(field, "9" * 64))))
    failure("fail_verify_tampered_status",
            lambda: fx.cfd_verify_aggregate(rewrapped(
                lambda p: p.__setitem__("status", "insufficient"))))
    failure("fail_verify_tampered_declaration",
            lambda: fx.cfd_verify_aggregate(rewrapped(
                lambda p: p["declaration"].__setitem__(
                    "status", "insufficient"))))
    failure("fail_verify_tampered_row",
            lambda: fx.cfd_verify_aggregate(rewrapped(
                lambda p: (p["items"][0].__setitem__(
                               "conclusion", "duplicate"),
                           p["items"][0].__setitem__(
                               "reason", "duplicate")))))
    failure("fail_verify_reordered_rows",
            lambda: fx.cfd_verify_aggregate(rewrapped(
                lambda p: p.__setitem__(
                    "items", list(reversed(p["items"]))))))
    failure("fail_verify_tampered_input_digest",
            lambda: fx.cfd_verify_aggregate(rewrapped(
                lambda p: p["inputs"].__setitem__(0, "ab" * 32))))
    failure("fail_verify_tampered_declaration_proofs",
            lambda: fx.cfd_verify_aggregate(rewrapped(
                lambda p: p["items"][0]["declaration"].__setitem__(
                    "proofs",
                    list(reversed(
                        p["items"][0]["declaration"]["proofs"]))))))
    failure("fail_verify_wrong_version",
            lambda: fx.cfd_verify_aggregate(rewrapped(
                lambda p: p.__setitem__("version", 2))))
    failure("fail_verify_foreign_dsp",
            lambda: fx.cfd_verify_aggregate(
                raw, dsp={"sites": {JUDGE: {1}, JUDGE_B: {1}},
                          "threshold": 1}))
    failure("fail_verify_foreign_proofp",
            lambda: fx.cfd_verify_aggregate(
                raw, proofp={"sites": {SITE_A: {1}, SITE_B: {1}},
                             "threshold": 1}))
    failure("fail_verify_revoked", lambda: fx.cfd_verify_aggregate(
        raw, ring=revoked))
    failure("fail_verify_future", lambda: fx.cfd_verify_aggregate(
        raw, ring=future))
    failure("fail_verify_expired", lambda: fx.cfd_verify_aggregate(
        raw, ring=expired_signer))
    failure("fail_verify_unknown_signer", lambda: fx.cfd_verify_aggregate(
        raw, ring={s: fx.ring[s] for s in fx.ring if s != JUDGE}))
    failure("fail_verify_type_moment",
            lambda: fx.cfd_verify_aggregate(raw, moment=True))
    failure("fail_verify_negative_moment",
            lambda: fx.cfd_verify_aggregate(raw, moment=-1))
    failure("fail_verify_bad_dsp_value",
            lambda: fx.cfd_verify_aggregate(
                raw, dsp={"sites": {}, "threshold": 1}))

    return vectors


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
