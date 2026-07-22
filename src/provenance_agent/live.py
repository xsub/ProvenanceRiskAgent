from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .contracts import AdapterTrace, LiveArtifactRequest, utc_now
from .execution import RetryExhaustedError, RetryPolicy, run_with_retry
from .normalization import (
    ALBS_GRAPH_SCHEMA,
    COMBINED_SCHEMA,
    EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA,
    EDGP_PUBLIC_ADVISORY_FEED_SCHEMA,
    normalize_payload,
)


class LiveAcquisitionError(RuntimeError):
    pass


class JsonCommandRunner:
    def __init__(self, *, timeout_seconds: float, max_output_bytes: int) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def run(
        self,
        *,
        adapter: str,
        operation: str,
        source_uri: str,
        argv: list[str],
    ) -> tuple[dict[str, Any], AdapterTrace]:
        started = perf_counter()
        try:
            process = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"{adapter} {operation} exceeded {self.timeout_seconds:g}s"
            ) from exc
        except FileNotFoundError as exc:
            raise LiveAcquisitionError(
                f"Required live adapter executable not found: {argv[0]}"
            ) from exc

        stderr = process.stderr.decode("utf-8", errors="replace").strip()
        if process.returncode != 0:
            detail = stderr[-1000:] or f"exit status {process.returncode}"
            error_type = ConnectionError if _looks_transient(detail) else LiveAcquisitionError
            raise error_type(f"{adapter} {operation} failed: {detail}")
        if len(process.stdout) > self.max_output_bytes:
            raise LiveAcquisitionError(
                f"{adapter} {operation} exceeded the output size limit"
            )
        try:
            payload = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise LiveAcquisitionError(
                f"{adapter} {operation} returned invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise LiveAcquisitionError(
                f"{adapter} {operation} must return a JSON object"
            )
        digest = hashlib.sha256(process.stdout).hexdigest()
        return payload, AdapterTrace(
            adapter=adapter,
            operation=operation,
            source_uri=source_uri,
            status="succeeded",
            duration_ms=round((perf_counter() - started) * 1000, 3),
            response_sha256=digest,
            detail=stderr[-1000:] or None,
        )


class HttpJsonClient:
    def __init__(self, *, timeout_seconds: float, max_output_bytes: int) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def request(
        self,
        url: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str]:
        body = None
        headers = {
            "Accept": "application/json",
            "User-Agent": "provenance-risk-agent/0.2",
        }
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(url, data=body, headers=headers, method="POST" if body else "GET")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_output_bytes + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"Live advisory request failed for {url}: {exc}") from exc
        if len(raw) > self.max_output_bytes:
            raise LiveAcquisitionError("Live advisory response exceeded the size limit")
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LiveAcquisitionError("Live advisory endpoint returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise LiveAcquisitionError("Live advisory endpoint must return a JSON object")
        return decoded, hashlib.sha256(raw).hexdigest()


class LiveAcquirer:
    def __init__(
        self,
        *,
        albs_executable: str,
        edgp_executable: str | None,
    ) -> None:
        self.albs_executable = albs_executable
        self.edgp_executable = edgp_executable

    @classmethod
    def from_environment(cls) -> LiveAcquirer:
        return cls(
            albs_executable=os.environ.get("PROVENANCE_AGENT_ALBS_GRAPH", "albs-graph"),
            edgp_executable=os.environ.get("PROVENANCE_AGENT_EDGP"),
        )

    def acquire(
        self,
        request: LiveArtifactRequest,
        *,
        advisory_max_age_seconds: int,
    ) -> dict[str, Any]:
        runner = JsonCommandRunner(
            timeout_seconds=request.command_timeout_seconds,
            max_output_bytes=request.max_output_bytes,
        )
        traces: list[AdapterTrace] = []
        sbom_trace = _validate_sbom(request.sbom_path, request.max_output_bytes)
        if sbom_trace:
            traces.append(sbom_trace)

        inventory, trace = runner.run(
            adapter="edgp",
            operation="albs-artifact-inventory",
            source_uri=f"{request.albs_base_url}/build/{request.build_id}",
            argv=self._edgp_inventory_args(request),
        )
        _require_schema(
            inventory,
            EDGP_ALBS_ARTIFACT_INVENTORY_SCHEMA,
            "EDGP ALBS inventory",
        )
        traces.append(trace)
        inventory_artifact = normalize_payload(
            inventory,
            f"live://albs/build/{request.build_id}/inventory",
        )["artifact"]
        ecosystem = request.osv_ecosystem or _infer_osv_ecosystem(
            inventory,
            inventory_artifact,
        )

        errata_url = request.errata_url or _default_errata_url(ecosystem)
        with TemporaryDirectory(prefix="provenance-agent-errata-") as directory:
            errata_feed, errata_trace = _acquire_errata_snapshot(
                request,
                errata_url,
                Path(directory),
            )
            traces.append(errata_trace)
            albs, trace = runner.run(
                adapter="albs-provenance-explorer",
                operation="trust-path",
                source_uri=f"{request.albs_base_url}/build/{request.build_id}",
                argv=self._albs_args(request, errata_feed=errata_feed),
            )
        _require_schema(albs, ALBS_GRAPH_SCHEMA, "ALBS trust path")
        traces.append(trace)
        linkage_trace = _validate_sbom_linkage(albs, request.sbom_path)
        if linkage_trace:
            traces.append(linkage_trace)
        artifact = normalize_payload(
            albs,
            f"live://albs/build/{request.build_id}/trust-path",
        )["artifact"]
        inventory = _scope_inventory(
            inventory,
            artifact,
            arch=request.arch or _selected_albs_arch(albs),
        )

        advisory, advisory_traces = self._advisory_report(
            request,
            runner,
            artifact=artifact,
            ecosystem=ecosystem,
            max_age_seconds=advisory_max_age_seconds,
        )
        traces.extend(advisory_traces)

        return normalize_payload(
            {
                "schema": COMBINED_SCHEMA,
                "artifact": artifact,
                "sources": [albs, inventory, advisory],
                "acquisition": [trace.model_dump(mode="json") for trace in traces],
            },
            f"live://albs/build/{request.build_id}",
        )

    def _albs_args(
        self,
        request: LiveArtifactRequest,
        *,
        errata_feed: Path | None,
    ) -> list[str]:
        args = [self.albs_executable, "trust-path"]
        if request.package:
            args.append(request.package)
        args.extend(
            [
                "--build-id",
                str(request.build_id),
                "--format",
                "json",
                "--base-url",
                request.albs_base_url,
            ]
        )
        if errata_feed is not None:
            args.extend(
                ["--errata-source", "http", "--errata-feed", str(errata_feed)]
            )
        if request.arch:
            args.extend(["--arch", request.arch])
        if request.sbom_path:
            args.extend(["--build-sbom", request.sbom_path])
        else:
            args.append("--no-auto-sbom")
        if request.refresh:
            args.append("--refresh-cache")
        return args

    def _edgp_inventory_args(self, request: LiveArtifactRequest) -> list[str]:
        return [
            *self._edgp_command(),
            "albs-artifact-inventory",
            "--build-id",
            str(request.build_id),
            "--base-url",
            request.albs_base_url,
            "--task-limit",
            str(request.inventory_task_limit),
            "--artifact-limit",
            str(request.inventory_artifact_limit),
            "--format",
            "json",
        ]

    def _edgp_command(self) -> list[str]:
        if self.edgp_executable:
            return [self.edgp_executable]
        return [sys.executable, "-m", "provenance_agent.edgp_bridge"]

    def _advisory_report(
        self,
        request: LiveArtifactRequest,
        runner: JsonCommandRunner,
        *,
        artifact: dict[str, str],
        ecosystem: str,
        max_age_seconds: int,
    ) -> tuple[dict[str, Any], list[AdapterTrace]]:
        started = perf_counter()
        endpoint = f"{request.osv_api_url}/v1/query"
        http = HttpJsonClient(
            timeout_seconds=request.command_timeout_seconds,
            max_output_bytes=request.max_output_bytes,
        )
        traces: list[AdapterTrace] = []
        try:
            query_result, query_digest = run_with_retry(
                lambda: http.request(
                    endpoint,
                    payload={
                        "version": artifact.get("version", ""),
                        "package": {
                            "name": artifact.get("name", ""),
                            "ecosystem": ecosystem,
                        },
                    },
                ),
                policy=RetryPolicy(max_attempts=3, base_delay_seconds=0.1),
            )
            vulnerabilities = query_result.get("vulns") or []
            ids = [str(item.get("id")) for item in vulnerabilities if item.get("id")]
            truncated = len(ids) > request.advisory_limit
            ids = ids[: request.advisory_limit]
            records = []
            for advisory_id in ids:
                record, _ = run_with_retry(
                    lambda advisory_id=advisory_id: http.request(
                        f"{request.osv_api_url}/v1/vulns/{quote(advisory_id, safe='')}"
                    ),
                    policy=RetryPolicy(max_attempts=3, base_delay_seconds=0.1),
                )
                records.append(record)
            traces.append(
                AdapterTrace(
                    adapter="osv",
                    operation="query-package-version",
                    source_uri=endpoint,
                    status="succeeded",
                    duration_ms=round((perf_counter() - started) * 1000, 3),
                    response_sha256=query_digest,
                    records=len(records),
                )
            )
        except (ConnectionError, LiveAcquisitionError, RetryExhaustedError) as exc:
            traces.append(
                AdapterTrace(
                    adapter="osv",
                    operation="query-package-version",
                    source_uri=endpoint,
                    status="failed",
                    duration_ms=round((perf_counter() - started) * 1000, 3),
                    detail=str(exc)[:1000],
                )
            )
            return _failed_advisory_report(
                artifact,
                ecosystem,
                endpoint,
                str(exc),
            ), traces

        with TemporaryDirectory(prefix="provenance-agent-osv-") as directory:
            path = Path(directory) / "osv.json"
            path.write_text(json.dumps({"vulns": records}), encoding="utf-8")
            report, trace = runner.run(
                adapter="edgp",
                operation="public-advisory-feed",
                source_uri=endpoint,
                argv=[
                    *self._edgp_command(),
                    "public-advisory-feed",
                    "--path",
                    str(path),
                    "--ecosystem",
                    ecosystem,
                    "--format",
                    "report",
                ],
            )
        _require_schema(report, EDGP_PUBLIC_ADVISORY_FEED_SCHEMA, "EDGP advisory feed")
        traces.append(trace)
        retrieved_at = utc_now()
        report["query"] = {
            "provider": "OSV",
            "endpoint": endpoint,
            "package": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "ecosystem": ecosystem,
            "status": "complete",
            "retrieved_at": retrieved_at.isoformat(),
            "max_age_seconds": max_age_seconds,
            "fresh": True,
            "truncated": truncated,
        }
        _enrich_advisory_severities(report, records)
        return report, traces


def _validate_sbom(path_value: str | None, max_bytes: int) -> AdapterTrace | None:
    if path_value is None:
        return None
    path = Path(path_value)
    started = perf_counter()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LiveAcquisitionError(f"Unable to read SBOM {path}: {exc}") from exc
    if len(raw) > max_bytes:
        raise LiveAcquisitionError("SBOM exceeded the configured size limit")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LiveAcquisitionError("SBOM is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise LiveAcquisitionError("SBOM must be a JSON object")
    if payload.get("bomFormat") != "CycloneDX":
        raise LiveAcquisitionError("Live ALBS SBOM must declare CycloneDX")
    records = payload.get("components")
    standard = "CycloneDX"
    if not isinstance(records, list) or not records:
        raise LiveAcquisitionError("SBOM contains no package/component inventory")
    return AdapterTrace(
        adapter="sbom-validator",
        operation=f"validate-{standard.lower()}",
        source_uri=str(path.resolve()),
        status="succeeded",
        duration_ms=round((perf_counter() - started) * 1000, 3),
        response_sha256=hashlib.sha256(raw).hexdigest(),
        records=len(records),
    )


def _acquire_errata_snapshot(
    request: LiveArtifactRequest,
    url: str,
    directory: Path,
) -> tuple[Path | None, AdapterTrace]:
    started = perf_counter()
    http = HttpJsonClient(
        timeout_seconds=request.command_timeout_seconds,
        max_output_bytes=request.max_output_bytes,
    )
    try:
        payload, digest = run_with_retry(
            lambda: http.request(url),
            policy=RetryPolicy(max_attempts=3, base_delay_seconds=0.1),
        )
        records = _validate_errata_feed(payload)
        path = directory / "errata.full.json"
        path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        return path, AdapterTrace(
            adapter="almalinux-errata",
            operation="fetch-snapshot",
            source_uri=url,
            status="succeeded",
            duration_ms=round((perf_counter() - started) * 1000, 3),
            response_sha256=digest,
            records=len(records),
        )
    except (ConnectionError, LiveAcquisitionError, RetryExhaustedError) as exc:
        return None, AdapterTrace(
            adapter="almalinux-errata",
            operation="fetch-snapshot",
            source_uri=url,
            status="failed",
            duration_ms=round((perf_counter() - started) * 1000, 3),
            detail=str(exc)[:1000],
        )


def _validate_errata_feed(payload: dict[str, Any]) -> list[dict[str, Any]]:
    records = payload.get("data")
    if not payload.get("schema_version") or not isinstance(records, list) or not records:
        raise LiveAcquisitionError(
            "AlmaLinux errata snapshot must contain schema_version and non-empty data"
        )
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not record.get("id"):
            raise LiveAcquisitionError(
                f"AlmaLinux errata record {index} has no advisory identity"
            )
        packages = record.get("packages")
        if not isinstance(packages, list):
            raise LiveAcquisitionError(
                f"AlmaLinux errata record {record['id']} has no package list"
            )
        for package_index, package in enumerate(packages):
            if not isinstance(package, dict) or not all(
                package.get(field) for field in ("name", "version", "release", "arch")
            ):
                raise LiveAcquisitionError(
                    f"AlmaLinux errata record {record['id']} has invalid package "
                    f"coordinates at index {package_index}"
                )
    return records


def _validate_sbom_linkage(
    graph: dict[str, Any],
    path_value: str | None,
) -> AdapterTrace | None:
    if path_value is None:
        return None
    started = perf_counter()
    expected = Path(path_value).resolve()
    sbom_ids = {
        str(node.get("id"))
        for node in graph.get("nodes", [])
        if node.get("type") == "sbom"
        and _same_path((node.get("metadata") or {}).get("source_path"), expected)
    }
    linked = [
        edge
        for edge in graph.get("edges", [])
        if edge.get("relation") == "described_by"
        and str(edge.get("target")) in sbom_ids
    ]
    if not sbom_ids or not linked:
        raise LiveAcquisitionError(
            "ALBS did not link the supplied SBOM to the selected artifact"
        )
    return AdapterTrace(
        adapter="sbom-linkage-validator",
        operation="verify-albs-described-by",
        source_uri=str(expected),
        status="succeeded",
        duration_ms=round((perf_counter() - started) * 1000, 3),
        records=len(linked),
    )


def _same_path(value: Any, expected: Path) -> bool:
    if not value:
        return False
    try:
        return Path(str(value)).resolve() == expected
    except OSError:
        return False


def _infer_osv_ecosystem(
    source: dict[str, Any],
    artifact: dict[str, str],
) -> str:
    for node in source.get("nodes", []):
        platform = str((node.get("metadata") or {}).get("platform") or "")
        if platform.lower().startswith("almalinux-"):
            return f"AlmaLinux:{platform.rsplit('-', 1)[-1]}"
    version = artifact.get("version", "")
    for major in ("10", "9", "8"):
        if f".el{major}" in version:
            return f"AlmaLinux:{major}"
    raise LiveAcquisitionError(
        "Unable to infer OSV ecosystem; provide live.osv_ecosystem explicitly."
    )


def _selected_albs_arch(graph: dict[str, Any]) -> str | None:
    for node in graph.get("nodes", []):
        if node.get("type") == "binary_rpm":
            arch = (node.get("metadata") or {}).get("arch")
            if arch:
                return str(arch)
    return None


def _scope_inventory(
    inventory: dict[str, Any],
    artifact: dict[str, str],
    *,
    arch: str | None,
) -> dict[str, Any]:
    name = artifact.get("name", "")
    version = artifact.get("version", "")
    matches = []
    for item in inventory.get("items") or []:
        item_version = _version_release(item.get("version"), item.get("release"))
        if str(item.get("packageName") or "") != name or item_version != version:
            continue
        if arch and str(item.get("artifactArch") or "") != arch:
            continue
        matches.append(item)
    if not matches:
        target = f"{name}-{version}" + (f".{arch}" if arch else "")
        raise LiveAcquisitionError(
            f"EDGP inventory does not contain the selected ALBS artifact: {target}"
        )

    summary = dict(inventory.get("summary") or {})
    summary.update(
        {
            "artifacts": len(matches),
            "binaryRpms": sum(
                1 for item in matches if item.get("artifactKind") == "binary"
            ),
            "sourceRpms": sum(
                1 for item in matches if item.get("artifactKind") == "srpm"
            ),
            "architectures": len(
                {item.get("artifactArch") for item in matches if item.get("artifactArch")}
            ),
            "packages": len(
                {item.get("packageName") for item in matches if item.get("packageName")}
            ),
        }
    )
    return {
        **inventory,
        "summary": summary,
        "items": matches,
        "scope": {"name": name, "version": version, "arch": arch},
    }


def _version_release(version: Any, release: Any) -> str:
    version_text = str(version or "")
    release_text = str(release or "")
    return f"{version_text}-{release_text}" if version_text and release_text else version_text


def _default_errata_url(ecosystem: str) -> str:
    major = ecosystem.rsplit(":", 1)[-1]
    if major not in {"8", "9", "10"}:
        raise LiveAcquisitionError(
            "Unable to infer AlmaLinux errata feed; provide live.errata_url."
        )
    return f"https://errata.almalinux.org/{major}/errata.full.json"


def _failed_advisory_report(
    artifact: dict[str, str],
    ecosystem: str,
    endpoint: str,
    error: str,
) -> dict[str, Any]:
    return {
        "schema": EDGP_PUBLIC_ADVISORY_FEED_SCHEMA,
        "ecosystem": ecosystem,
        "summary": {"advisories": 0, "packages": 0, "severities": 0},
        "packages": [],
        "severities": [],
        "advisories": [],
        "overlay": {"schema": "edgp.advisory.overlay.v1", "advisories": []},
        "query": {
            "provider": "OSV",
            "endpoint": endpoint,
            "package": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "ecosystem": ecosystem,
            "status": "failed",
            "fresh": False,
            "error": error[:1000],
        },
    }


def _enrich_advisory_severities(
    report: dict[str, Any],
    records: list[dict[str, Any]],
) -> None:
    by_id = {str(record.get("id") or ""): record for record in records}
    for advisory in report.get("advisories", []):
        record = by_id.get(str(advisory.get("id") or ""), {})
        level, raw = _severity(record, advisory.get("severity"))
        advisory["severity"] = level
        advisory["rawSeverity"] = raw


def _severity(record: dict[str, Any], fallback: Any) -> tuple[str, str]:
    candidates: list[str] = []
    database = record.get("database_specific")
    if isinstance(database, dict):
        candidates.append(str(database.get("severity") or ""))
    for affected in record.get("affected", []) if isinstance(record.get("affected"), list) else []:
        ecosystem = affected.get("ecosystem_specific") if isinstance(affected, dict) else None
        if isinstance(ecosystem, dict):
            candidates.append(str(ecosystem.get("severity") or ""))
    candidates.append(str(fallback or ""))
    raw = next((value for value in candidates if value), "unknown")
    normalized = raw.lower()
    if "critical" in normalized:
        return "critical", raw
    if "important" in normalized or "high" in normalized:
        return "high", raw
    if "moderate" in normalized or "medium" in normalized:
        return "medium", raw
    if "low" in normalized:
        return "low", raw
    return "unknown", raw


def _require_schema(payload: dict[str, Any], expected: str, label: str) -> None:
    if payload.get("schema") != expected:
        raise LiveAcquisitionError(
            f"{label} returned schema {payload.get('schema')!r}; expected {expected!r}"
        )


def _looks_transient(detail: str) -> bool:
    lowered = detail.lower()
    return any(
        token in lowered
        for token in (
            "connection",
            "temporar",
            "timed out",
            "timeout",
            "urlopen",
            "http 429",
            "http 500",
            "http 502",
            "http 503",
            "http 504",
        )
    )
