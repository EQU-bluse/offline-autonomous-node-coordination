"""Tests for the multi-chain batch summary and delegation fork detection.

Covers :func:`verify_batch_receipt_chains`: the whole-batch upfront
validation and exception taxonomy, the strict input-order reports and
per-item isolation, the ``invalid-receipt``/``invalid-delegation``/
``unauthenticated`` failure classes, fork detection by
``receiptDigest``/``upstream`` next-hop audiences, prefix-extension
non-forks, cross-receipt isolation, the fixed result key orders and the
freshness of verified results.
"""

import copy
import hashlib
import hmac
import json
import unittest

from offline_coordination.replication import (
    verify_batch_receipt_chain,
    verify_batch_receipt_chains,
)

SECRET_COORD = "11" * 32
SECRET_ALPHA = "22" * 32
SECRET_BETA = "33" * 32
SECRET_GAMMA = "44" * 32
SECRET_DELTA = "55" * 32

ISSUER = "coord"
ALPHA = "alpha"
BETA = "beta"
GAMMA = "gamma"
DELTA = "delta"

POLICY = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
MOMENT = 100
VERIFY_MOMENT = 200


def compact(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def keyring(**overrides):
    ring = {
        ISSUER: [entry(1, SECRET_COORD)],
        ALPHA: [entry(1, SECRET_ALPHA)],
        BETA: [entry(1, SECRET_BETA)],
        GAMMA: [entry(1, SECRET_GAMMA)],
        DELTA: [entry(1, SECRET_DELTA)],
    }
    for node, entries in overrides.items():
        ring[node] = entries
    return ring


def entry(version, secret, not_before=0, not_after=10 ** 9, revoked=False):
    return {
        "version": version,
        "secret": secret,
        "notBefore": not_before,
        "notAfter": not_after,
        "revoked": revoked,
    }


def sign(payload, secret):
    return hmac.new(
        bytes.fromhex(secret), compact(payload), hashlib.sha256
    ).hexdigest()


def make_report(item_id="item-1"):
    return {
        "error": "boom",
        "id": item_id,
        "result": None,
        "status": "invalid-proof",
    }


def make_item(item_id="item-1"):
    return {
        "id": item_id,
        "digest": "aa" * 32,
        "report": make_report(item_id),
    }


def make_receipt(items=None, issuer=ISSUER, secret=SECRET_COORD,
                 key_version=1, moment=MOMENT, policy=POLICY):
    if items is None:
        items = [make_item()]
    canonical_policy = {
        "batch": policy["batch"],
        "sites": {
            site: sorted(policy["sites"][site])
            for site in sorted(policy["sites"])
        },
        "threshold": policy["threshold"],
    }
    payload = {
        "issuer": issuer,
        "keyVersion": key_version,
        "moment": moment,
        "policy": hashlib.sha256(compact(canonical_policy)).hexdigest(),
        "items": items,
        "version": 1,
    }
    return compact(
        {"payload": payload, "signature": sign(payload, secret)}
    )


def make_hop(issuer, secret, audience, upstream_bytes, moment,
             key_version=1):
    payload = {
        "issuer": issuer,
        "keyVersion": key_version,
        "moment": moment,
        "audience": audience,
        "upstream": hashlib.sha256(upstream_bytes).hexdigest(),
        "version": 1,
    }
    return compact(
        {"payload": payload, "signature": sign(payload, secret)}
    )


def tamper_signature(data):
    mutated = bytearray(data)
    mutated[-3] = ord("0") if mutated[-3] != ord("0") else ord("1")
    return bytes(mutated)


SECRETS = {
    ISSUER: SECRET_COORD,
    ALPHA: SECRET_ALPHA,
    BETA: SECRET_BETA,
    GAMMA: SECRET_GAMMA,
    DELTA: SECRET_DELTA,
}


def chain(receipt, path, moments=()):
    """Build hops for receipt -> path[0] -> path[1] ...; return hops."""
    hops = []
    upstream = receipt
    domains = [ISSUER] + list(path)
    for index, audience in enumerate(path):
        moment = moments[index] if moments else 110 + index
        hops.append(
            make_hop(
                domains[index], SECRETS[domains[index]], audience,
                upstream, moment,
            )
        )
        upstream = hops[-1]
    return hops


def chain_item(item_id, receipt, path, target=None, moments=()):
    path = list(path)
    return {
        "id": item_id,
        "receipt": receipt,
        "hops": chain(receipt, path, moments),
        "target": target if target is not None else path[-1],
    }


class BatchStructureValidationTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.receipt = make_receipt()

    def good(self, item_id="c-1"):
        return chain_item(item_id, self.receipt, [ALPHA, BETA])

    def test_items_must_be_a_non_empty_list(self):
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains((), POLICY, self.ring, VERIFY_MOMENT)
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains([], POLICY, self.ring, VERIFY_MOMENT)

    def test_element_must_be_a_dict_with_exact_keys(self):
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                ["x"], POLICY, self.ring, VERIFY_MOMENT
            )
        bad = self.good()
        del bad["target"]
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [bad], POLICY, self.ring, VERIFY_MOMENT
            )
        bad = self.good()
        bad["extra"] = 1
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [bad], POLICY, self.ring, VERIFY_MOMENT
            )

    def test_id_rules(self):
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [chain_item(1, self.receipt, [ALPHA])],
                POLICY, self.ring, VERIFY_MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [chain_item("", self.receipt, [ALPHA])],
                POLICY, self.ring, VERIFY_MOMENT,
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [self.good("dup"), self.good("dup")],
                POLICY, self.ring, VERIFY_MOMENT,
            )

    def test_receipt_must_be_bytes(self):
        bad = self.good()
        bad["receipt"] = "x"
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [bad], POLICY, self.ring, VERIFY_MOMENT
            )

    def test_hops_rules(self):
        bad = self.good()
        bad["hops"] = ("x",)
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [bad], POLICY, self.ring, VERIFY_MOMENT
            )
        bad = self.good()
        bad["hops"] = []
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [bad], POLICY, self.ring, VERIFY_MOMENT
            )
        bad = self.good()
        bad["hops"] = ["x"]
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [bad], POLICY, self.ring, VERIFY_MOMENT
            )

    def test_target_rules(self):
        bad = self.good()
        bad["target"] = 1
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [bad], POLICY, self.ring, VERIFY_MOMENT
            )
        bad = self.good()
        bad["target"] = ""
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [bad], POLICY, self.ring, VERIFY_MOMENT
            )

    def test_shared_policy_keyring_moment_rules(self):
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [self.good()], {"batch": "x"}, self.ring, VERIFY_MOMENT
            )
        with self.assertRaises(TypeError):
            verify_batch_receipt_chains(
                [self.good()], POLICY, self.ring, True
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [self.good()], POLICY, self.ring, -1
            )
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [self.good()], POLICY, {"": []},
                VERIFY_MOMENT,
            )

    def test_whole_batch_validated_before_any_chain_runs(self):
        # The first item's receipt is invalid; the second item's
        # structural fault must still surface as a batch-level error
        # before either chain is processed.
        bad_receipt_item = chain_item("a", b"{}", [ALPHA])
        structurally_bad = chain_item("b", self.receipt, [ALPHA])
        del structurally_bad["target"]
        with self.assertRaises(ValueError):
            verify_batch_receipt_chains(
                [bad_receipt_item, structurally_bad],
                POLICY, self.ring, VERIFY_MOMENT,
            )


class BatchVerificationTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.receipt = make_receipt()

    def test_single_verified_chain_report(self):
        item = chain_item("c-1", self.receipt, [ALPHA, BETA])
        report = verify_batch_receipt_chains(
            [item], POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(list(report.keys()), ["forks", "items", "version"])
        self.assertEqual(report["version"], 1)
        self.assertIsInstance(report["version"], int)
        self.assertNotIsInstance(report["version"], bool)
        self.assertEqual(report["forks"], [])
        entry_report = report["items"][0]
        self.assertEqual(
            list(entry_report.keys()), ["error", "id", "result", "status"]
        )
        self.assertEqual(entry_report["id"], "c-1")
        self.assertEqual(entry_report["status"], "verified")
        self.assertIsNone(entry_report["error"])
        expected = verify_batch_receipt_chain(
            self.receipt, item["hops"], POLICY, self.ring,
            VERIFY_MOMENT, BETA,
        )
        self.assertEqual(entry_report["result"], expected)

    def test_verified_result_is_a_fresh_independent_copy(self):
        item = chain_item("c-1", self.receipt, [ALPHA, BETA])
        first = verify_batch_receipt_chains(
            [item], POLICY, self.ring, VERIFY_MOMENT
        )
        first["items"][0]["result"]["hops"][0]["audience"] = "tampered"
        first["items"][0]["result"]["receipt"]["issuer"] = "tampered"
        second = verify_batch_receipt_chains(
            [item], POLICY, self.ring, VERIFY_MOMENT
        )
        result = second["items"][0]["result"]
        self.assertEqual(result["hops"][0]["audience"], ALPHA)
        self.assertEqual(result["receipt"]["issuer"], ISSUER)

    def test_failure_classes_and_isolation_in_input_order(self):
        invalid_receipt = chain_item("a", b"{}", [ALPHA])
        bad_hop = chain_item("b", self.receipt, [ALPHA])
        bad_hop["hops"][0] = bad_hop["hops"][0] + b"\n"
        bad_signature = chain_item("c", self.receipt, [ALPHA])
        bad_signature["hops"][0] = tamper_signature(bad_signature["hops"][0])
        good = chain_item("d", self.receipt, [ALPHA, BETA])
        wrong_target = chain_item(
            "e", self.receipt, [ALPHA, BETA], target=GAMMA
        )

        report = verify_batch_receipt_chains(
            [invalid_receipt, bad_hop, bad_signature, good, wrong_target],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual([r["id"] for r in report["items"]],
                         ["a", "b", "c", "d", "e"])
        statuses = {r["id"]: r["status"] for r in report["items"]}
        self.assertEqual(statuses, {
            "a": "invalid-receipt",
            "b": "invalid-delegation",
            "c": "unauthenticated",
            "d": "verified",
            "e": "invalid-delegation",
        })
        for row in report["items"]:
            if row["status"] == "verified":
                self.assertIsNone(row["error"])
                self.assertIsNotNone(row["result"])
            else:
                self.assertIsInstance(row["error"], str)
                self.assertNotEqual(row["error"], "")
                self.assertIsNone(row["result"])
        # The delegation failure names the first failing hop.
        self.assertIn("hop 0", report["items"][1]["error"])

    def test_revoked_credentials_are_unauthenticated(self):
        ring = keyring(**{ALPHA: [entry(1, SECRET_ALPHA, revoked=True)]})
        item = chain_item("c-1", self.receipt, [ALPHA, BETA])
        report = verify_batch_receipt_chains(
            [item], POLICY, ring, VERIFY_MOMENT
        )
        self.assertEqual(report["items"][0]["status"], "unauthenticated")

    def test_inputs_are_not_modified(self):
        item = chain_item("c-1", self.receipt, [ALPHA, BETA])
        snapshot = copy.deepcopy(item)
        policy = {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1}
        verify_batch_receipt_chains([item], policy, self.ring, VERIFY_MOMENT)
        self.assertEqual(item, snapshot)
        self.assertEqual(
            policy,
            {"batch": "batch-1", "sites": {"a": {1}}, "threshold": 1},
        )


class ForkDetectionTest(unittest.TestCase):
    def setUp(self):
        self.ring = keyring()
        self.receipt = make_receipt()
        self.digest = hashlib.sha256(self.receipt).hexdigest()

    def test_diverging_next_hops_from_one_upstream_is_a_fork(self):
        # coord -> alpha -> beta versus coord -> gamma -> delta: the
        # first hop forks on the base receipt upstream.
        item_a = chain_item("a", self.receipt, [ALPHA, BETA],
                            moments=(110, 120))
        item_b = chain_item("b", self.receipt, [GAMMA, DELTA],
                            moments=(111, 121))
        report = verify_batch_receipt_chains(
            [item_a, item_b], POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(len(report["forks"]), 1)
        fork = report["forks"][0]
        self.assertEqual(list(fork.keys()),
                         ["receiptDigest", "upstream", "audiences", "ids"])
        self.assertEqual(fork["receiptDigest"], self.digest)
        self.assertEqual(fork["upstream"], self.digest)
        self.assertEqual(fork["audiences"], [ALPHA, GAMMA])
        self.assertEqual(fork["ids"], ["a", "b"])
        for row in report["items"]:
            self.assertEqual(row["status"], "conflicted")
            self.assertEqual(row["error"], "forked-delegation")
            self.assertIsNotNone(row["result"])
        # The retained result is still the single-chain result.
        self.assertEqual(
            report["items"][0]["result"],
            verify_batch_receipt_chain(
                self.receipt, item_a["hops"], POLICY, self.ring,
                VERIFY_MOMENT, BETA,
            ),
        )

    def test_prefix_extension_is_not_a_fork(self):
        short = chain_item("short", self.receipt, [ALPHA])
        long = chain_item("long", self.receipt, [ALPHA, BETA])
        report = verify_batch_receipt_chains(
            [short, long], POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]], ["verified", "verified"]
        )

    def test_second_level_fork_is_recorded_separately(self):
        # Three chains share the coord -> alpha edge; two then
        # diverge at the digest of that shared hop.
        to_beta = chain_item("to-beta", self.receipt, [ALPHA, BETA],
                             moments=(110, 120))
        to_gamma = chain_item("to-gamma", self.receipt, [GAMMA, DELTA],
                              moments=(111, 121))
        to_epsilon = chain_item(
            "to-epsilon", self.receipt, [ALPHA, "epsilon"],
            moments=(110, 122),
        )
        self.ring["epsilon"] = [entry(1, "66" * 32)]
        report = verify_batch_receipt_chains(
            [to_beta, to_gamma, to_epsilon],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual(len(report["forks"]), 2)
        by_upstream = {fork["upstream"]: fork for fork in report["forks"]}
        base_fork = by_upstream[self.digest]
        self.assertEqual(base_fork["audiences"], [ALPHA, GAMMA])
        self.assertEqual(base_fork["ids"],
                         ["to-beta", "to-epsilon", "to-gamma"])
        shared_hop_digest = hashlib.sha256(to_beta["hops"][0]).hexdigest()
        second_fork = by_upstream[shared_hop_digest]
        self.assertEqual(second_fork["receiptDigest"], self.digest)
        self.assertEqual(second_fork["audiences"], [BETA, "epsilon"])
        self.assertEqual(second_fork["ids"], ["to-beta", "to-epsilon"])
        # The forks are sorted stably on their first two fields.
        ordered = [
            (fork["receiptDigest"], fork["upstream"])
            for fork in report["forks"]
        ]
        self.assertEqual(ordered, sorted(ordered))
        statuses = {r["id"]: r["status"] for r in report["items"]}
        self.assertEqual(statuses["to-gamma"], "conflicted")
        self.assertEqual(statuses["to-beta"], "conflicted")
        self.assertEqual(statuses["to-epsilon"], "conflicted")

    def test_forks_under_different_base_receipts_are_distinct(self):
        receipt_one = make_receipt(items=[make_item("one")])
        receipt_two = make_receipt(items=[make_item("two")])
        item_a = chain_item("a", receipt_one, [ALPHA])
        item_b = chain_item("b", receipt_one, [BETA])
        item_c = chain_item("c", receipt_two, [ALPHA])
        item_d = chain_item("d", receipt_two, [BETA])
        report = verify_batch_receipt_chains(
            [item_a, item_b, item_c, item_d],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        digests = {fork["receiptDigest"] for fork in report["forks"]}
        self.assertEqual(
            digests,
            {hashlib.sha256(receipt_one).hexdigest(),
             hashlib.sha256(receipt_two).hexdigest()},
        )
        for fork in report["forks"]:
            self.assertEqual(fork["audiences"], [ALPHA, BETA])

    def test_same_next_hop_under_two_receipts_is_no_fork(self):
        receipt_one = make_receipt(items=[make_item("one")])
        receipt_two = make_receipt(items=[make_item("two")])
        item_a = chain_item("a", receipt_one, [ALPHA])
        item_b = chain_item("b", receipt_two, [ALPHA])
        report = verify_batch_receipt_chains(
            [item_a, item_b], POLICY, self.ring, VERIFY_MOMENT
        )
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]], ["verified", "verified"]
        )

    def test_failed_chains_never_join_fork_detection(self):
        item_a = chain_item("a", self.receipt, [ALPHA])
        item_b = chain_item("b", self.receipt, [GAMMA, DELTA])
        item_b["hops"][0] = tamper_signature(item_b["hops"][0])
        report = verify_batch_receipt_chains(
            [item_a, item_b], POLICY, self.ring, VERIFY_MOMENT
        )
        # The unauthenticated chain provides no valid next hop, so the
        # sole verified chain cannot fork.
        self.assertEqual(report["forks"], [])
        self.assertEqual(
            [r["status"] for r in report["items"]],
            ["verified", "unauthenticated"],
        )

    def test_only_chains_crossing_the_fork_edge_are_conflicted(self):
        # Fork at the shared alpha hop: to-beta vs to-epsilon diverge
        # there; a chain ending at alpha crosses neither the base edge
        # (single audience) nor the shared-hop edge.
        to_beta = chain_item("to-beta", self.receipt, [ALPHA, BETA],
                             moments=(110, 120))
        to_epsilon = chain_item(
            "to-epsilon", self.receipt, [ALPHA, "epsilon"],
            moments=(110, 122),
        )
        self.ring["epsilon"] = [entry(1, "66" * 32)]
        ending = chain_item("ending", self.receipt, [ALPHA])
        report = verify_batch_receipt_chains(
            [to_beta, to_epsilon, ending],
            POLICY, self.ring, VERIFY_MOMENT,
        )
        self.assertEqual(len(report["forks"]), 1)
        self.assertEqual(report["forks"][0]["ids"],
                         ["to-beta", "to-epsilon"])
        statuses = {r["id"]: r["status"] for r in report["items"]}
        self.assertEqual(statuses["to-beta"], "conflicted")
        self.assertEqual(statuses["to-epsilon"], "conflicted")
        self.assertEqual(statuses["ending"], "verified")

    def test_fork_ids_list_each_chain_once_per_edge(self):
        # Two items carrying byte-identical chains both cross the same
        # edge; both ids are listed, ascending.
        item_a = chain_item("a", self.receipt, [ALPHA])
        item_b = chain_item("b", self.receipt, [ALPHA])
        item_c = chain_item("c", self.receipt, [BETA])
        report = verify_batch_receipt_chains(
            [item_c, item_a, item_b], POLICY, self.ring, VERIFY_MOMENT
        )
        fork = report["forks"][0]
        self.assertEqual(fork["ids"], ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
