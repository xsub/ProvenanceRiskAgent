from fastapi.testclient import TestClient

from provenance_agent.api import create_app


def test_api_evaluate_returns_traceable_result(tmp_path):
    client = TestClient(create_app(db_path=tmp_path / "api.sqlite3"))

    health = client.get("/healthz")
    ready = client.get("/readyz")
    examples = client.get("/api/v1/examples")

    assert health.status_code == 200
    assert ready.status_code == 200
    assert examples.status_code == 200
    example_paths = {item["path"] for item in examples.json()}
    assert "examples/albs-edgp-risk-case.json" in example_paths
    assert "examples/suspicious-build.json" in example_paths

    response = client.post(
        "/api/v1/evaluate",
        json={"input_path": "examples/suspicious-build.json"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision_state"] == "REVIEW"
    assert payload["risk_score"] == 93
    assert payload["events"][0]["event_type"] == "investigation_started"


def test_api_investigation_can_be_loaded_by_id(tmp_path):
    client = TestClient(create_app(db_path=tmp_path / "investigations.sqlite3"))

    created = client.post(
        "/api/v1/investigations",
        json={"input_path": "examples/suspicious-build.json"},
    )

    assert created.status_code == 200
    investigation_id = created.json()["investigation_id"]

    summary = client.get(f"/api/v1/investigations/{investigation_id}")
    events = client.get(f"/api/v1/investigations/{investigation_id}/events")
    evidence = client.get(f"/api/v1/investigations/{investigation_id}/evidence")

    assert summary.status_code == 200
    assert summary.json()["result"]["decision_state"] == "REVIEW"
    assert events.status_code == 200
    assert len(events.json()) >= 5
    assert evidence.status_code == 200
    assert any(item["code"] == "SIGNATURE_MISSING" for item in evidence.json())


def test_api_unknown_investigation_returns_404(tmp_path):
    client = TestClient(create_app(db_path=tmp_path / "missing.sqlite3"))

    response = client.get("/api/v1/investigations/not-found")

    assert response.status_code == 404
