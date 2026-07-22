from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from provenance_agent.completeness import assess_completeness
from provenance_agent.contracts import AdapterTrace, LiveArtifactRequest
from provenance_agent.live import (
    HttpJsonClient,
    JsonCommandRunner,
    LiveAcquirer,
    LiveAcquisitionError,
    _validate_errata_feed,
)
from provenance_agent.normalization import normalize_payload
from provenance_agent.tools import expand_tool_exports, inspect_vulnerabilities


def test_json_command_runner_never_uses_a_shell(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=b'{"schema":"ok"}', stderr=b"")

    monkeypatch.setattr("provenance_agent.live.subprocess.run", fake_run)
    payload, trace = JsonCommandRunner(timeout_seconds=5, max_output_bytes=1024).run(
        adapter="test",
        operation="read",
        source_uri="https://example.test/source",
        argv=["adapter", "--format", "json"],
    )

    assert payload == {"schema": "ok"}
    assert captured["argv"] == ["adapter", "--format", "json"]
    assert "shell" not in captured["kwargs"]
    assert trace.response_sha256


def test_live_acquisition_uses_inferred_official_feed_and_normalizes_osv(
    tmp_path,
    monkeypatch,
):
    sbom = tmp_path / "artifact.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "nginx-core"}],
            }
        ),
        encoding="utf-8",
    )
    calls = []

    def fake_command(self, *, adapter, operation, source_uri, argv):
        calls.append(argv)
        trace = AdapterTrace(
            adapter=adapter,
            operation=operation,
            source_uri=source_uri,
            status="succeeded",
            duration_ms=1,
            response_sha256="a" * 64,
        )
        if operation == "albs-artifact-inventory":
            return _inventory(), trace
        if operation == "trust-path":
            graph = _albs_graph()
            graph["nodes"][1]["metadata"]["source_path"] = str(sbom.resolve())
            return graph, trace
        return _advisory_report(), trace

    def fake_http(self, url, *, payload=None):
        if "errata.almalinux.org" in url:
            return _errata_feed(), "d" * 64
        if url.endswith("/v1/query"):
            return {"vulns": [{"id": "ALSA-2026:0001"}]}, "b" * 64
        return _osv_record(), "c" * 64

    monkeypatch.setattr(JsonCommandRunner, "run", fake_command)
    monkeypatch.setattr(HttpJsonClient, "request", fake_http)

    export = LiveAcquirer(albs_executable="albs-graph", edgp_executable="edgp").acquire(
        LiveArtifactRequest(
            build_id=57810,
            package="nginx-core",
            arch="x86_64",
            sbom_path=str(sbom),
        ),
        advisory_max_age_seconds=3600,
    )

    assert export["source_schema"] == "provenance-risk-agent.combined.v1"
    assert export["artifact"]["name"] == "nginx-core"
    assert [
        item["artifactArch"] for item in export["source"]["sources"][1]["items"]
    ] == ["x86_64"]
    assert len(export["acquisition"]) == 7
    trust_argv = next(argv for argv in calls if "trust-path" in argv)
    inventory_argv = next(argv for argv in calls if "albs-artifact-inventory" in argv)
    assert "--errata-feed" in trust_argv
    errata_trace = next(
        trace for trace in export["acquisition"] if trace["adapter"] == "almalinux-errata"
    )
    assert errata_trace["source_uri"] == (
        "https://errata.almalinux.org/9/errata.full.json"
    )
    assert errata_trace["response_sha256"] == "d" * 64
    assert inventory_argv[inventory_argv.index("--task-limit") + 1] == "5000"
    assert inventory_argv[inventory_argv.index("--artifact-limit") + 1] == "5000"
    advisory = export["source"]["sources"][2]
    assert advisory["query"]["status"] == "complete"
    assert advisory["advisories"][0]["severity"] == "high"

    advisory_export = expand_tool_exports(export)[3]
    evidence = inspect_vulnerabilities.invoke(
        {"export_json": json.dumps(advisory_export)}
    )
    assert len(evidence) == 1
    assert evidence[0]["code"] == "EDGP_ADVISORY_AFFECTS_ARTIFACT"
    assert evidence[0]["severity"] == "high"


def test_failed_osv_query_is_incomplete_instead_of_clean(monkeypatch):
    def fake_command(self, *, adapter, operation, source_uri, argv):
        trace = AdapterTrace(
            adapter=adapter,
            operation=operation,
            source_uri=source_uri,
            status="succeeded",
            duration_ms=1,
        )
        return (_inventory() if operation == "albs-artifact-inventory" else _albs_graph()), trace

    def unavailable(self, url, *, payload=None):
        raise ConnectionError("OSV unavailable")

    monkeypatch.setattr(JsonCommandRunner, "run", fake_command)
    monkeypatch.setattr(HttpJsonClient, "request", unavailable)
    export = LiveAcquirer(albs_executable="albs-graph", edgp_executable="edgp").acquire(
        LiveArtifactRequest(build_id=57810, package="nginx-core"),
        advisory_max_age_seconds=3600,
    )
    completeness = assess_completeness(export, [])

    assert export["source"]["sources"][2]["query"]["status"] == "failed"
    assert "vulnerability_coverage" in completeness.missing_categories
    assert "advisory_freshness" in completeness.missing_categories


def test_sbom_must_be_nonempty_cyclonedx(tmp_path):
    invalid = tmp_path / "empty.json"
    invalid.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")

    with pytest.raises(LiveAcquisitionError, match="no package/component"):
        LiveAcquirer(albs_executable="albs-graph", edgp_executable="edgp").acquire(
            LiveArtifactRequest(build_id=1, sbom_path=str(invalid)),
            advisory_max_age_seconds=3600,
        )


def test_errata_snapshot_requires_advisory_and_package_coordinates():
    with pytest.raises(LiveAcquisitionError, match="invalid package coordinates"):
        _validate_errata_feed(
            {
                "schema_version": "1.0",
                "data": [{"id": "ALSA-2026:0001", "packages": [{"name": "nginx"}]}],
            }
        )


def test_live_source_hosts_are_allowlisted(monkeypatch):
    with pytest.raises(ValueError, match="live-source allowlist"):
        LiveArtifactRequest(build_id=1, osv_api_url="https://127.0.0.1")

    monkeypatch.setenv("PROVENANCE_AGENT_ALLOWED_LIVE_HOSTS", "mirror.example.test")
    request = LiveArtifactRequest(
        build_id=1,
        errata_url="https://mirror.example.test/errata.full.json",
    )

    assert request.errata_url == "https://mirror.example.test/errata.full.json"


def test_advisory_coverage_requires_exact_artifact_and_valid_freshness():
    report = _advisory_report()
    report["query"] = {
        "status": "complete",
        "package": "different-package",
        "version": "1.24.0-1.el9",
        "fresh": True,
        "retrieved_at": "2099-01-01T00:00:00+00:00",
        "max_age_seconds": 3600,
        "truncated": False,
    }
    export = normalize_payload(report, "test://advisory")
    export["artifact"] = {
        "name": "nginx-core",
        "version": "1.24.0-1.el9",
        "digest": "",
    }

    completeness = assess_completeness(export, [])

    assert "vulnerability_coverage" in completeness.missing_categories
    assert "advisory_freshness" in completeness.missing_categories


def _inventory():
    return {
        "schema": "edgp.albs.artifact_inventory.v1",
        "summary": {"artifacts": 1, "binaryRpms": 1},
        "items": [
            {
                "artifactKind": "binary",
                "packageName": "nginx-core",
                "version": "1.24.0",
                "release": "1.el9",
                "artifactArch": "i686",
                "casHash": "different-arch-cas",
                "buildTaskId": 76,
            },
            {
                "artifactKind": "binary",
                "packageName": "nginx-core",
                "version": "1.24.0",
                "release": "1.el9",
                "artifactArch": "x86_64",
                "casHash": "abc123",
                "buildTaskId": 77,
            }
        ],
    }


def _albs_graph():
    return {
        "schema": "albs-provenance-explorer/v1",
        "nodes": [
            {
                "id": "rpm:1",
                "type": "binary_rpm",
                "label": "nginx-core",
                "metadata": {
                    "name": "nginx-core",
                    "version": "1.24.0",
                    "release": "1.el9",
                    "arch": "x86_64",
                    "cas_hash": "abc123",
                    "errata_status": "confirmed_clean",
                },
            },
            {
                "id": "sbom:test",
                "type": "sbom",
                "label": "artifact.cdx.json",
                "metadata": {"source_path": ""},
            },
        ],
        "edges": [
            {
                "source": "rpm:1",
                "target": "sbom:test",
                "relation": "described_by",
                "metadata": {},
            }
        ],
    }


def _advisory_report():
    return {
        "schema": "edgp.public.advisory_feed.v1",
        "ecosystem": "AlmaLinux:9",
        "summary": {"advisories": 1, "packages": 1, "severities": 0},
        "packages": ["nginx-core"],
        "severities": [],
        "advisories": [
            {
                "id": "ALSA-2026:0001",
                "package": "nginx-core",
                "versions": ["1.24.0-1.el9"],
                "severity": "",
            },
            {
                "id": "ALSA-2026:0001",
                "package": "nginx-core",
                "versions": ["1.24.0-1.el9"],
                "severity": "",
            },
        ],
        "overlay": {"schema": "edgp.advisory.overlay.v1", "advisories": []},
    }


def _osv_record():
    return {
        "id": "ALSA-2026:0001",
        "database_specific": {"severity": "Important"},
        "affected": [
            {
                "package": {"name": "nginx-core", "ecosystem": "AlmaLinux:9"},
                "versions": ["1.24.0-1.el9"],
            }
        ],
    }


def _errata_feed():
    return {
        "schema_version": "1.0",
        "data": [
            {
                "id": "ALSA-2026:0001",
                "packages": [
                    {
                        "name": "nginx-core",
                        "version": "1.24.0",
                        "release": "1.el9",
                        "arch": "x86_64",
                    }
                ],
            }
        ],
    }
