"""Before/after differential acceptance tests for the final fork decision
aggregate boundary refactor.

The golden snapshot (``_golden_baseline.json``) was captured against the
pre-refactor baseline by ``_golden_capture.py`` and pins, for every public
entry point from
:func:`offline_coordination.replication.supersede_final_fork_decision_aggregate`
through
:func:`offline_coordination.replication.verify_final_fork_decision_aggregate_chain_fork_decision`:

* every success value -- canonical compact JSON bytes, result fields,
  field ordering, digests, signature-bearing payloads, statuses, fork
  edges and batch/anchor/decision reports (root, single-hop and
  multi-hop chains, policy rotation, prefix extension vs real fork,
  fork-free consensus, duplicate/contradiction tallies and mixed
  batches);
* every failure -- the exact exception class and message for illegal
  structures, broken links, failed authentication and ordinary
  parameter faults, including expired, revoked and not-yet-valid
  credentials, tampered canonical bytes, anchor expiry and the fork
  proof/decision adjudications.

Refactoring the shared internals must leave all of these byte-for-byte
and class-for-class identical.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _golden_capture  # noqa: E402

_GOLDEN_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "_golden_baseline.json"
)


class FinalForkDecisionAggregateDifferentialTest(unittest.TestCase):
    """The current boundary is indistinguishable from the baseline."""

    @classmethod
    def setUpClass(cls):  # noqa: D102
        with open(_GOLDEN_PATH, encoding="utf-8") as handle:
            cls.expected = json.load(handle)
        cls.current = _golden_capture.collect()

    def test_vector_sets_are_identical(self):
        self.assertEqual(
            sorted(self.current), sorted(self.expected)
        )

    def test_successes_are_field_for_field_identical(self):
        names = [
            name for name, vector in self.expected.items()
            if vector["ok"] and "unexpected" not in vector
        ]
        self.assertTrue(names)
        for name in names:
            self.assertEqual(
                self.current[name], self.expected[name], name
            )

    def test_failures_keep_their_exception_class_and_message(self):
        names = [
            name for name, vector in self.expected.items()
            if not vector["ok"]
        ]
        self.assertTrue(names)
        for name in names:
            self.assertEqual(
                self.current[name], self.expected[name], name
            )

    def test_no_failure_case_accidentally_succeeds(self):
        for name, vector in self.current.items():
            if not self.expected[name]["ok"]:
                self.assertFalse(
                    vector["ok"],
                    f"{name} no longer raises: {vector!r}",
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
