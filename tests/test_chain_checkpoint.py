"""Tests for chain checkpoints and offline suffix verification.

Covers :func:`seal_chain_checkpoint`, :func:`verify_chain_suffix` and
:func:`verify_chain_suffixes`: the canonical signed checkpoint packet
and every binding (root, stable head, height, status, settlement and
plan digests, head policy, effective moment, ordered packet digests,
policy history, evidence prefix digests and sealing moment), the
accepted/verified/unforked target rule, offline continuation from a
pruned prefix (empty suffix returns the stable head, first-hop
predecessor and evidence-prefix bindings, per-hop policy/version/
effective-moment/state-machine rules, version-regression rejection),
the batch wrapper's upfront validation, per-item isolation with
deterministic error text, the fixed statuses and fork detection with
the prefix-extension exception.
"""

import copy
import hashlib
import hmac
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from offline_coordination.replication import (
    AuthenticationError,
    InvalidChainError,
    InvalidCheckpointError,
    seal_chain_checkpoint,
    verify_chain_suffix,
    verify_chain_suffixes,
)

from test_fork_convergence import (
    BETA,
    COORD,
    RING,
    SECRET_COORD,
    compact,
    entry,
    parse,
    rewrap,
)
from test_supersede_decision import (
    EFFECTIVE_MOMENT,
    SIGN_MOMENT,
    VERIFY_MOMENT,
    SupersedeFixtures,
    versioned_policy,
)

CHECKPOINT_PAYLOAD_KEYS = {
    "rootDigest", "headDigest", "height", "status", "commonDigest",
    "planDigest", "policyDigest", "policyVersion", "effectiveAt",
    "packets", "policies", "evidence", "moment", "issuer", "keyVersion",
    "version",
}
RESULT_KEYS = {
    "rootDigest", "headDigest", "height", "policyVersion", "status",
    "checkpointDigest",
}


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


class CheckpointFixtures(SupersedeFixtures):
    """Chains, checkpoints and suffix builders over the shared fixtures."""

    def setUp(self):  # noqa: D102
        super().setUp()
        from offline_coordination.replication import certify_fork_convergence
        self.cert_coord_4 = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, 273, COORD, 1
        )
        self.cert_coord_5 = certify_fork_convergence(
            self.rounds, self.decision, self.pol, RING, 274, COORD, 1
        )
        self.root, self.successors, self.policies = self.accepted_chain()
        self.items = [self.chain_item(
            "x", self.root, self.successors, self.policies
        )]

    def seal(self, items, target="x", ring=RING, issuer=COORD, version=1):
        return seal_chain_checkpoint(
            items, target, self.decision, self.pol, ring, SIGN_MOMENT,
            issuer, version,
        )

    def checkpoint(self):
        return self.seal(self.items)

    def verify_suffix(self, checkpoint, successors, policies, ring=RING,
                      moment=VERIFY_MOMENT):
        return verify_chain_suffix(
            checkpoint, successors, policies, self.decision, self.pol,
            ring, moment,
        )

    def verify_suffixes(self, items, ring=RING, moment=VERIFY_MOMENT):
        return verify_chain_suffixes(
            items, self.decision, self.pol, ring, moment
        )

    def suffix_item(self, item_id, checkpoint, successors, policies):
        return {
            "id": item_id,
            "checkpoint": checkpoint,
            "successors": successors,
            "policies": policies,
        }

    def continuation(self, count=2):
        """Valid successors past the two-hop head; returns packets."""
        evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
            self.item(self.cert_coord_3, "c3"),
        ]
        packets = []
        predecessor = self.successors[-1]
        for extra, item_id, moment in (
            (self.cert_coord_4, "c4", EFFECTIVE_MOMENT + 2),
            (self.cert_coord_5, "c5", EFFECTIVE_MOMENT + 4),
        )[:count]:
            evidence = evidence + [self.item(extra, item_id)]
            predecessor = self.supersede(
                predecessor, evidence, effective=moment
            )
            packets.append(predecessor)
        return packets

    def fork_branches(self):
        """One shared first hop with two diverging accepted branches."""
        root = self.accepted_root()
        first_evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ]
        first = self.supersede(root, first_evidence)
        branch_a = self.supersede(
            first, first_evidence + [self.item(self.cert_coord_3, "c3")],
            effective=EFFECTIVE_MOMENT + 4,
        )
        branch_b = self.supersede(
            first, first_evidence + [self.item(self.cert_coord_4, "c4")],
            effective=EFFECTIVE_MOMENT + 5,
        )
        return root, first, branch_a, branch_b


class SealChainCheckpointTest(CheckpointFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.checkpoint = self.checkpoint()
        self.data = parse(self.checkpoint)

    def test_canonical_compact_encoding_without_trailing_byte(self):
        self.assertTrue(self.checkpoint.endswith(b"}"))
        self.assertEqual(compact(self.data), self.checkpoint)
        self.assertEqual(set(self.data.keys()), {"payload", "signature"})

    def test_payload_key_set(self):
        self.assertEqual(set(self.data["payload"].keys()),
                         CHECKPOINT_PAYLOAD_KEYS)

    def test_payload_bindings(self):
        payload = self.data["payload"]
        self.assertEqual(payload["rootDigest"], sha256(self.root))
        self.assertEqual(payload["headDigest"], sha256(self.successors[-1]))
        self.assertEqual(payload["height"], 2)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["policyVersion"], 1)
        self.assertEqual(payload["effectiveAt"], EFFECTIVE_MOMENT)
        self.assertEqual(payload["moment"], SIGN_MOMENT)
        self.assertEqual(payload["issuer"], COORD)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(
            payload["packets"],
            [sha256(self.root)] + [sha256(s) for s in self.successors],
        )
        head = parse(self.successors[-1])["payload"]
        self.assertEqual(payload["commonDigest"], head["commonDigest"])
        self.assertEqual(payload["planDigest"], head["planDigest"])
        self.assertEqual(payload["evidence"], head["certificates"])
        self.assertEqual(len(payload["policies"]), 3)
        self.assertEqual(
            payload["policies"],
            [payload["policyDigest"]] * 3,
        )

    def test_checkpoint_drops_certificates_and_rounds(self):
        payload = self.data["payload"]
        self.assertNotIn("common", payload)
        self.assertNotIn("items", payload)
        for digest in payload["evidence"]:
            self.assertIsInstance(digest, str)
            self.assertEqual(len(digest), 64)

    def test_signature_is_the_payload_hmac(self):
        expected = hmac.new(
            bytes.fromhex(SECRET_COORD),
            compact(self.data["payload"]),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(self.data["signature"], expected)

    def test_bare_root_checkpoint(self):
        root = self.accepted_root()
        items = [self.chain_item("z", root, [], [self.policy_v1])]
        checkpoint = self.seal(items, target="z")
        payload = parse(checkpoint)["payload"]
        self.assertEqual(payload["height"], 0)
        self.assertIsNone(payload["effectiveAt"])
        self.assertEqual(payload["packets"], [sha256(root)])
        self.assertEqual(payload["rootDigest"], payload["headDigest"])

    def test_seal_requires_a_verified_accepted_unforked_target(self):
        insufficient = self.insufficient_root()
        items = [self.chain_item("z", insufficient, [], [self.policy_v1])]
        with self.assertRaises(ValueError):
            self.seal(items, target="z")
        # A forked target is conflicted and cannot be sealed.
        root, first, branch_a, branch_b = self.fork_branches()
        forked = [
            self.chain_item("A", root, [first, branch_a],
                            [self.policy_v1] * 3),
            self.chain_item("B", root, [first, branch_b],
                            [self.policy_v1] * 3),
        ]
        with self.assertRaises(ValueError):
            self.seal(forked, target="A")
        # An invalid target chain cannot be sealed either.
        broken = [self.chain_item("z", self.root, [b"{}"],
                                  [self.policy_v1] * 2)]
        with self.assertRaises(ValueError):
            self.seal(broken, target="z")

    def test_an_unrelated_failing_chain_does_not_stop_the_target(self):
        items = self.items + [
            {"id": "bad", "roots": b"{}", "successors": [],
             "policies": [self.policy_v1]},
        ]
        checkpoint = self.seal(items, target="x")
        self.assertEqual(
            parse(checkpoint)["payload"]["headDigest"],
            sha256(self.successors[-1]),
        )

    def test_unknown_target_is_a_value_error(self):
        with self.assertRaises(ValueError):
            self.seal(self.items, target="missing")

    def test_argument_faults(self):
        with self.assertRaises(TypeError):
            self.seal(self.items, target=1)
        with self.assertRaises(ValueError):
            self.seal(self.items, target="")
        with self.assertRaises(TypeError):
            seal_chain_checkpoint(
                self.items, "x", "decision", self.pol, RING, SIGN_MOMENT,
                COORD, 1,
            )
        with self.assertRaises(TypeError):
            self.seal(self.items, ring=RING, issuer=COORD, version=True)
        with self.assertRaises(ValueError):
            self.seal(self.items, issuer="")
        with self.assertRaises(ValueError):
            self.seal(self.items, version=0)
        with self.assertRaises(ValueError):
            seal_chain_checkpoint(
                self.items, "x", self.decision, self.pol, RING, -1,
                COORD, 1,
            )

    def test_unknown_or_revoked_signing_key_is_authentication_error(self):
        with self.assertRaises(AuthenticationError):
            self.seal(self.items, issuer="nobody")
        # The chain still verifies; only the sealer credential is bad.
        revoked = {
            **RING, "sealer": [entry(1, "66" * 32, revoked=True)]
        }
        with self.assertRaises(AuthenticationError):
            self.seal(self.items, ring=revoked, issuer="sealer")

    def test_inputs_are_not_modified(self):
        items = copy.deepcopy(self.items)
        snapshot = copy.deepcopy(items)
        self.seal(items)
        self.assertEqual(items, snapshot)


class VerifyChainSuffixTest(CheckpointFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.checkpoint = self.checkpoint()
        self.suffix = self.continuation()

    def test_empty_suffix_returns_the_stable_head(self):
        result = self.verify_suffix(
            self.checkpoint, [], [self.policy_v1]
        )
        self.assertEqual(set(result.keys()), RESULT_KEYS)
        self.assertEqual(result["rootDigest"], sha256(self.root))
        self.assertEqual(
            result["headDigest"], sha256(self.successors[-1])
        )
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["policyVersion"], 1)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["checkpointDigest"], sha256(self.checkpoint))

    def test_suffix_matches_the_full_chain_verification(self):
        result = self.verify_suffix(
            self.checkpoint, self.suffix, [self.policy_v1] * 3
        )
        full = self.verify_chain(
            self.root, self.successors + self.suffix, [self.policy_v1] * 5
        )
        for key in ("rootDigest", "headDigest", "height", "policyVersion",
                    "status"):
            self.assertEqual(result[key], full[key])
        self.assertEqual(result["height"], 4)
        self.assertEqual(result["headDigest"], sha256(self.suffix[-1]))

    def test_bare_root_checkpoint_continues_from_height_zero(self):
        root = self.accepted_root()
        checkpoint = self.seal(
            [self.chain_item("z", root, [], [self.policy_v1])], target="z"
        )
        first = self.supersede(root, [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
            self.item(self.cert_coord_2, "c2"),
        ])
        result = self.verify_suffix(
            checkpoint, [first], [self.policy_v1, self.policy_v1]
        )
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["headDigest"], sha256(first))
        self.assertEqual(result["status"], "accepted")

    def test_first_packet_predecessor_must_equal_the_checkpoint_head(self):
        # The second continuation hop does not descend from the head.
        with self.assertRaises(InvalidChainError):
            self.verify_suffix(
                self.checkpoint, [self.suffix[1]], [self.policy_v1] * 2
            )

    def test_first_packet_evidence_prefix_must_match_the_checkpoint(self):
        # Reordering the bound evidence breaks the prefix digests even
        # with a valid sealer signature.
        data = parse(self.suffix[0])
        evidence = data["payload"]["evidence"]
        evidence[0], evidence[1] = evidence[1], evidence[0]
        forged = rewrap(data["payload"])
        with self.assertRaises(InvalidChainError):
            self.verify_suffix(
                self.checkpoint, [forged], [self.policy_v1] * 2
            )

    def test_dropped_prefix_evidence_is_rejected(self):
        data = parse(self.suffix[0])
        del data["payload"]["evidence"][0]
        forged = rewrap(data["payload"])
        with self.assertRaises(InvalidChainError):
            self.verify_suffix(
                self.checkpoint, [forged], [self.policy_v1] * 2
            )

    def test_effective_moment_must_not_move_backwards(self):
        data = parse(self.suffix[0])
        data["payload"]["effectiveAt"] = EFFECTIVE_MOMENT - 1
        forged = rewrap(data["payload"])
        with self.assertRaises(InvalidChainError):
            self.verify_suffix(
                self.checkpoint, [forged], [self.policy_v1] * 2
            )

    def test_policy_sequence_must_start_at_the_checkpoint_head_policy(self):
        other = versioned_policy((COORD, BETA), 2, 1)
        with self.assertRaises(InvalidCheckpointError):
            self.verify_suffix(
                self.checkpoint, [], [other]
            )
        bumped = versioned_policy(
            (COORD, "alpha", "gamma"), 2, 2
        )
        with self.assertRaises(InvalidCheckpointError):
            self.verify_suffix(
                self.checkpoint, self.suffix, [bumped] + [self.policy_v1] * 2
            )

    def test_policy_version_regression_is_rejected(self):
        # Rotate the chain to a version-2 policy and seal there.
        rotated = versioned_policy((COORD, "alpha", "gamma", BETA), 2, 2)
        root = self.accepted_root()
        evidence = [
            copy.deepcopy(self.item_coord),
            copy.deepcopy(self.item_alpha),
        ]
        first = self.supersede(
            root, evidence, old_policy=self.policy_v1, new_policy=rotated
        )
        checkpoint = self.seal(
            [self.chain_item("z", root, [first],
                             [self.policy_v1, rotated])],
            target="z",
        )
        regressed = versioned_policy((COORD, "alpha", "gamma", BETA), 2, 1)
        grown = self.supersede(
            first, evidence + [self.item(self.cert_coord_2, "c2")],
            old_policy=rotated, new_policy=rotated,
            effective=EFFECTIVE_MOMENT + 2,
        )
        with self.assertRaises(InvalidChainError):
            self.verify_suffix(
                checkpoint, [grown], [rotated, regressed]
            )
        # The same hop with the held version verifies.
        result = self.verify_suffix(
            checkpoint, [grown], [rotated, rotated]
        )
        self.assertEqual(result["policyVersion"], 2)
        self.assertEqual(result["status"], "accepted")

    def test_bad_checkpoint_structure_is_invalid_checkpoint(self):
        data = parse(self.checkpoint)
        del data["payload"]["height"]
        with self.assertRaises(InvalidCheckpointError):
            self.verify_suffix(
                compact(data), [], [self.policy_v1]
            )
        with self.assertRaises(InvalidCheckpointError):
            self.verify_suffix(
                self.checkpoint + b"\n", [], [self.policy_v1]
            )
        with self.assertRaises(InvalidCheckpointError):
            self.verify_suffix(b"{}", [], [self.policy_v1])

    def test_checkpoint_cross_bindings_are_checked(self):
        data = parse(self.checkpoint)
        data["payload"]["packets"] = data["payload"]["packets"][1:]
        with self.assertRaises(InvalidCheckpointError):
            self.verify_suffix(compact(data), [], [self.policy_v1])
        data = parse(self.checkpoint)
        data["payload"]["status"] = "insufficient"
        with self.assertRaises(InvalidCheckpointError):
            self.verify_suffix(compact(data), [], [self.policy_v1])

    def test_rebound_checkpoint_value_is_an_authentication_error(self):
        # Rebinding a structurally valid value keeps the old signature
        # and fails the HMAC check rather than the structural check.
        data = parse(self.checkpoint)
        data["payload"]["moment"] = SIGN_MOMENT + 1
        with self.assertRaises(AuthenticationError):
            self.verify_suffix(compact(data), [], [self.policy_v1])

    def test_wrong_checkpoint_signature_is_authentication_error(self):
        data = parse(self.checkpoint)
        data["signature"] = "00" * 32
        with self.assertRaises(AuthenticationError):
            self.verify_suffix(compact(data), [], [self.policy_v1])

    def test_revoked_checkpoint_key_is_authentication_error(self):
        revoked = {**RING, COORD: [entry(1, SECRET_COORD, revoked=True)]}
        with self.assertRaises(AuthenticationError):
            self.verify_suffix(
                self.checkpoint, [], [self.policy_v1], ring=revoked
            )

    def test_bad_suffix_packet_is_invalid_chain(self):
        with self.assertRaises(InvalidChainError):
            self.verify_suffix(
                self.checkpoint, [b"{}"], [self.policy_v1] * 2
            )

    def test_argument_faults(self):
        with self.assertRaises(TypeError):
            self.verify_suffix("checkpoint", [], [self.policy_v1])
        with self.assertRaises(TypeError):
            self.verify_suffix(self.checkpoint, "x", [self.policy_v1])
        with self.assertRaises(TypeError):
            self.verify_suffix(self.checkpoint, [1], [self.policy_v1] * 2)
        with self.assertRaises(TypeError):
            self.verify_suffix(self.checkpoint, [], self.policy_v1)
        with self.assertRaises(ValueError):
            self.verify_suffix(self.checkpoint, [], [])
        with self.assertRaises(ValueError):
            self.verify_suffix(
                self.checkpoint, self.suffix, [self.policy_v1]
            )

    def test_result_is_fresh_and_inputs_untouched(self):
        successors = list(self.suffix)
        policies = [self.policy_v1] * 3
        snapshot = copy.deepcopy(policies)
        first = self.verify_suffix(self.checkpoint, successors, policies)
        second = self.verify_suffix(self.checkpoint, successors, policies)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["status"] = "tampered"
        self.assertEqual(
            self.verify_suffix(self.checkpoint, successors, policies)
            ["status"],
            "accepted",
        )
        self.assertEqual(policies, snapshot)


class VerifyChainSuffixesTest(CheckpointFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.checkpoint = self.checkpoint()

    def test_single_verified_item(self):
        report = self.verify_suffixes([
            self.suffix_item("a", self.checkpoint, [], [self.policy_v1])
        ])
        self.assertEqual(set(report.keys()), {"items", "version"})
        self.assertEqual(report["version"], 1)
        item = report["items"][0]
        self.assertEqual(list(item.keys()), ["error", "id", "result", "status"])
        self.assertEqual(item["status"], "verified")
        self.assertIsNone(item["error"])
        self.assertEqual(item["result"]["height"], 2)
        self.assertEqual(
            item["result"]["checkpointDigest"], sha256(self.checkpoint)
        )

    def test_batch_structure_faults(self):
        good = self.suffix_item("a", self.checkpoint, [], [self.policy_v1])
        with self.assertRaises(TypeError):
            self.verify_suffixes("x")
        with self.assertRaises(ValueError):
            self.verify_suffixes([])
        with self.assertRaises(TypeError):
            self.verify_suffixes([dict(good, id=1)])
        with self.assertRaises(ValueError):
            self.verify_suffixes([dict(good, id="")])
        with self.assertRaises(ValueError):
            self.verify_suffixes([good, dict(good)])
        with self.assertRaises(ValueError):
            self.verify_suffixes([
                {"id": "a", "checkpoint": self.checkpoint,
                 "successors": []},
            ])
        with self.assertRaises(TypeError):
            self.verify_suffixes([dict(good, checkpoint="x")])
        with self.assertRaises(TypeError):
            self.verify_suffixes([dict(good, successors="x")])
        with self.assertRaises(TypeError):
            self.verify_suffixes([dict(good, successors=[1],
                                       policies=[self.policy_v1] * 2)])
        with self.assertRaises(ValueError):
            self.verify_suffixes([dict(good, policies=[])])
        with self.assertRaises(ValueError):
            self.verify_suffixes([
                dict(good, policies=[self.policy_v1] * 2)
            ])

    def test_items_are_isolated_in_input_order(self):
        bad_checkpoint = compact({
            "payload": parse(self.checkpoint)["payload"],
            "signature": "00" * 32,
        })
        report = self.verify_suffixes([
            self.suffix_item("ok", self.checkpoint, [], [self.policy_v1]),
            self.suffix_item("bad-cp", b"{}", [], [self.policy_v1]),
            self.suffix_item("bad-suffix", self.checkpoint, [b"{}"],
                             [self.policy_v1] * 2),
            self.suffix_item("bad-sig", bad_checkpoint, [],
                             [self.policy_v1]),
            self.suffix_item("ok2", self.checkpoint, self.continuation(1),
                             [self.policy_v1] * 2),
        ])
        self.assertEqual(
            [item["id"] for item in report["items"]],
            ["ok", "bad-cp", "bad-suffix", "bad-sig", "ok2"],
        )
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses, {
            "ok": "verified",
            "bad-cp": "invalid-checkpoint",
            "bad-suffix": "invalid-suffix",
            "bad-sig": "unauthenticated",
            "ok2": "verified",
        })
        for item in report["items"]:
            if item["status"] == "verified":
                self.assertIsNone(item["error"])
                self.assertIsNotNone(item["result"])
            else:
                self.assertIsInstance(item["error"], str)
                self.assertTrue(item["error"])
                self.assertIsNone(item["result"])

    def test_error_text_is_deterministic(self):
        items = [
            self.suffix_item("bad", b"{}", [], [self.policy_v1]),
            self.suffix_item("ok", self.checkpoint, [], [self.policy_v1]),
        ]
        first = self.verify_suffixes(items)
        second = self.verify_suffixes(items)
        self.assertEqual(first, second)
        self.assertIsNot(first["items"][1]["result"],
                         second["items"][1]["result"])

    def test_shared_predecessor_with_distinct_successors_is_a_fork(self):
        root, first, branch_a, branch_b = self.fork_branches()
        checkpoint_a = self.seal(
            [self.chain_item("A", root, [first, branch_a],
                             [self.policy_v1] * 3)],
            target="A",
        )
        checkpoint_b = self.seal(
            [self.chain_item("B", root, [first, branch_b],
                             [self.policy_v1] * 3)],
            target="B",
        )
        report = self.verify_suffixes([
            self.suffix_item("A", checkpoint_a, [], [self.policy_v1]),
            self.suffix_item("B", checkpoint_b, [], [self.policy_v1]),
        ])
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses, {"A": "conflicted", "B": "conflicted"})
        # The verified results are retained on a conflicted item.
        for item in report["items"]:
            self.assertIsNotNone(item["result"])
            self.assertEqual(item["error"], "forked-successor")

    def test_diverging_suffixes_of_one_checkpoint_are_a_fork(self):
        root, first, branch_a, branch_b = self.fork_branches()
        checkpoint = self.seal(
            [self.chain_item("C", root, [first], [self.policy_v1] * 2)],
            target="C",
        )
        report = self.verify_suffixes([
            self.suffix_item("a", checkpoint, [branch_a],
                             [self.policy_v1] * 2),
            self.suffix_item("b", checkpoint, [branch_b],
                             [self.policy_v1] * 2),
        ])
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses, {"a": "conflicted", "b": "conflicted"})

    def test_prefix_extension_is_not_a_fork(self):
        root, first, branch_a, _branch_b = self.fork_branches()
        short = self.seal(
            [self.chain_item("C", root, [first], [self.policy_v1] * 2)],
            target="C",
        )
        long = self.seal(
            [self.chain_item("A", root, [first, branch_a],
                             [self.policy_v1] * 3)],
            target="A",
        )
        report = self.verify_suffixes([
            self.suffix_item("short", short, [branch_a],
                             [self.policy_v1] * 2),
            self.suffix_item("long", long, [], [self.policy_v1]),
        ])
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses, {"short": "verified", "long": "verified"})

    def test_failed_items_are_never_reclassified(self):
        root, first, branch_a, branch_b = self.fork_branches()
        checkpoint_a = self.seal(
            [self.chain_item("A", root, [first, branch_a],
                             [self.policy_v1] * 3)],
            target="A",
        )
        checkpoint_b = self.seal(
            [self.chain_item("B", root, [first, branch_b],
                             [self.policy_v1] * 3)],
            target="B",
        )
        report = self.verify_suffixes([
            self.suffix_item("A", checkpoint_a, [], [self.policy_v1]),
            self.suffix_item("bad", checkpoint_b, [b"{}"],
                             [self.policy_v1] * 2),
        ])
        statuses = {item["id"]: item["status"] for item in report["items"]}
        # The failing item never joins fork detection, so no fork edge
        # is recorded and the verified item keeps its status.
        self.assertEqual(statuses, {"A": "verified", "bad": "invalid-suffix"})

    def test_inputs_are_not_modified(self):
        items = [
            self.suffix_item("a", self.checkpoint, self.continuation(1),
                             [self.policy_v1] * 2),
        ]
        snapshot = copy.deepcopy(items)
        self.verify_suffixes(items)
        self.assertEqual(items, snapshot)


if __name__ == "__main__":
    unittest.main()
