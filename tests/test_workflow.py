from provenance_agent.workflow import build_graph


def test_suspicious_build_requires_review():
    graph = build_graph()
    result = graph.invoke({"input_path": "examples/suspicious-build.json"})
    assert result["risk_score"] == 93
    assert result["risk_level"] == "critical"
    assert result["requires_review"] is True
    assert "BUILDER_NOT_ALLOWED" in result["report"]
    assert "SIGNATURE_MISSING" in result["report"]


def test_clean_build_has_zero_score():
    graph = build_graph()
    result = graph.invoke({"input_path": "examples/clean-build.json"})
    assert result["risk_score"] == 0
    assert result["risk_level"] == "none"
    assert result["requires_review"] is False
