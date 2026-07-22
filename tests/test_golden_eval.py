"""Regression test for the complete offline golden evaluation corpus.

Ensures every curated behavioral and safety scenario passes as one quality
gate through the public golden-suite runner.
"""

from provenance_agent.golden import run_golden_suite


def test_golden_suite_passes_offline():
    result = run_golden_suite()

    assert result["success"] is True
    assert result["passed"] == 10
    assert result["failed"] == 0
