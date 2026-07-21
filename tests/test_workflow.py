from pathlib import Path

import pytest

from provenance_agent.workflow import build_graph


SOFTWARE_SUPPLY_CHAIN = Path("/Users/pawel/_DEV/SoftwareSupplyChain")
ALBS_EXPLORER = Path("/Users/pawel/_DEV/ALBS-provenance/albs-provenance-explorer")


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


def test_combined_albs_edgp_fixture_uses_both_source_engines():
    graph = build_graph()
    result = graph.invoke({"input_path": "examples/albs-edgp-risk-case.json"})

    observation_codes = {item["code"] for item in result["observations"]}
    evidence_codes = {item["code"] for item in result["evidence"]}

    assert result["export"]["source_schema"] == "provenance-risk-agent.combined.v1"
    assert result["risk_score"] == 85
    assert result["risk_level"] == "critical"
    assert result["requires_review"] is True
    assert "COMBINED_SOURCE_COVERAGE" in observation_codes
    assert "ALBS_TRUST_COVERAGE" in observation_codes
    assert "EDGP_RPM_ALBS_COVERAGE" in observation_codes
    assert "ALBS_SIGNATURE_MISSING" in evidence_codes
    assert "EDGP_RPM_ALBS_UNMATCHED_PACKAGES" in evidence_codes


def test_real_edgp_rpm_albs_provenance_fixture_is_supported():
    path = SOFTWARE_SUPPLY_CHAIN / "tests/fixtures/rpm-albs-provenance.json"
    if not path.exists():
        pytest.skip(f"Missing external EDGP fixture: {path}")

    graph = build_graph()
    result = graph.invoke({"input_path": str(path)})

    assert result["export"]["source_schema"] == "edgp.rpm.albs_provenance.v1"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "none"
    assert "nginx-core" in result["report"]
    assert result["observations"][0]["code"] == "EDGP_RPM_ALBS_COVERAGE"


def test_real_edgp_albs_inventory_fixture_is_supported():
    path = SOFTWARE_SUPPLY_CHAIN / "tests/fixtures/albs-artifact-inventory.json"
    if not path.exists():
        pytest.skip(f"Missing external EDGP fixture: {path}")

    graph = build_graph()
    result = graph.invoke({"input_path": str(path)})

    assert result["export"]["source_schema"] == "edgp.albs.artifact_inventory.v1"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "none"
    assert "nginx" in result["report"]
    assert result["observations"][0]["code"] == "EDGP_ALBS_INVENTORY_COVERAGE"


def test_real_albs_provenance_graph_trust_export_is_supported():
    path = (
        ALBS_EXPLORER
        / "examples/demo-nginx-core/nginx-core-x86_64-trust.json"
    )
    if not path.exists():
        pytest.skip(f"Missing external ALBS fixture: {path}")

    graph = build_graph()
    result = graph.invoke({"input_path": str(path)})

    assert result["export"]["source_schema"] == "albs-provenance-explorer/v1"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "none"
    assert "nginx-core" in result["report"]
    assert result["observations"][0]["code"] == "ALBS_TRUST_COVERAGE"
