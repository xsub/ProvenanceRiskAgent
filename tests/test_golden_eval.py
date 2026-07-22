from provenance_agent.golden import run_golden_suite


def test_golden_suite_passes_offline():
    result = run_golden_suite()

    assert result["success"] is True
    assert result["passed"] == 10
    assert result["failed"] == 0
