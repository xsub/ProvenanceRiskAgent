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


def test_api_can_resume_a_persisted_review(tmp_path):
    client = TestClient(create_app(db_path=tmp_path / "review.sqlite3"))
    waiting = client.post(
        "/api/v1/investigations",
        json={
            "input_path": "examples/suspicious-build.json",
            "pause_before_review": True,
        },
    )

    assert waiting.status_code == 200
    payload = waiting.json()
    assert payload["status"] == "awaiting_review"
    investigation_id = payload["investigation_id"]

    reviewed = client.post(
        f"/api/v1/investigations/{investigation_id}/resume",
        json={
            "decision": "DENY",
            "reviewer": "api-test",
            "rationale": "Evidence confirms denial.",
        },
    )
    findings = client.get(
        f"/api/v1/investigations/{investigation_id}/findings"
    )

    assert reviewed.status_code == 200
    assert reviewed.json()["decision_state"] == "DENY"
    assert findings.status_code == 200
    assert all(item["kind"] != "verified_fact" for item in findings.json())


def test_api_rejects_a_second_review_of_completed_investigation(tmp_path):
    client = TestClient(create_app(db_path=tmp_path / "single-review.sqlite3"))
    waiting = client.post(
        "/api/v1/investigations",
        json={
            "input_path": "examples/suspicious-build.json",
            "pause_before_review": True,
        },
    ).json()
    investigation_id = waiting["investigation_id"]
    review = {
        "decision": "DENY",
        "reviewer": "api-test",
        "rationale": "Deterministic findings confirmed.",
    }

    first = client.post(
        f"/api/v1/investigations/{investigation_id}/resume",
        json=review,
    )
    second = client.post(
        f"/api/v1/investigations/{investigation_id}/resume",
        json=review,
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["detail"] == "Investigation is not awaiting human review."


def test_api_records_invalid_input_as_error_without_retry(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{not-json", encoding="utf-8")
    client = TestClient(create_app(db_path=tmp_path / "invalid.sqlite3"))

    response = client.post(
        "/api/v1/evaluate",
        json={"input_path": str(invalid)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["decision_state"] == "ERROR"
    event_types = [event["event_type"] for event in payload["events"]]
    assert "investigation_failed" in event_types
    assert "execution_attempt_failed" not in event_types
