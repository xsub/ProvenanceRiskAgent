from __future__ import annotations

from html import escape
import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from .contracts import (
    DEFAULT_QUESTION,
    EvidenceRecord,
    InvestigationEvent,
    InvestigationRequest,
    InvestigationResult,
    InvestigationSummary,
    ReviewDecision,
)
from .service import InvestigationService
from .store import InvestigationStore


def create_app(db_path: str | Path | None = None) -> FastAPI:
    app = FastAPI(
        title="Enterprise Linux Provenance Risk Agent",
        version="0.1.0",
        summary="Evidence-first software supply-chain investigation service.",
    )
    database_path = db_path or os.environ.get(
        "PROVENANCE_AGENT_DB",
        "/tmp/provenance-agent.sqlite3",
    )
    app.state.service = InvestigationService(InvestigationStore(database_path))

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index(service: InvestigationService = Depends(get_service)) -> HTMLResponse:
        return HTMLResponse(_render_index(service.list_examples()))

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz(service: InvestigationService = Depends(get_service)) -> dict[str, str]:
        service.store.initialize()
        return {"status": "ready"}

    @app.get("/api/v1/examples")
    def examples(
        service: InvestigationService = Depends(get_service),
    ) -> list[dict[str, str]]:
        return service.list_examples()

    @app.post("/api/v1/evaluate")
    def evaluate(
        request: InvestigationRequest,
        service: InvestigationService = Depends(get_service),
    ) -> InvestigationResult:
        return service.run_investigation(request)

    @app.post("/api/v1/investigations")
    def create_investigation(
        request: InvestigationRequest,
        service: InvestigationService = Depends(get_service),
    ) -> InvestigationResult:
        return service.run_investigation(request)

    @app.get("/api/v1/investigations/{investigation_id}")
    def get_investigation(
        investigation_id: str,
        service: InvestigationService = Depends(get_service),
    ) -> InvestigationSummary:
        summary = service.get_investigation(investigation_id)
        if summary is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return summary

    @app.get("/api/v1/investigations/{investigation_id}/events")
    def get_events(
        investigation_id: str,
        service: InvestigationService = Depends(get_service),
    ) -> list[InvestigationEvent]:
        _require_investigation(service, investigation_id)
        return service.list_events(investigation_id)

    @app.get("/api/v1/investigations/{investigation_id}/evidence")
    def get_evidence(
        investigation_id: str,
        service: InvestigationService = Depends(get_service),
    ) -> list[EvidenceRecord]:
        _require_investigation(service, investigation_id)
        return service.list_evidence(investigation_id)

    @app.get("/api/v1/investigations/{investigation_id}/findings")
    def get_findings(
        investigation_id: str,
        service: InvestigationService = Depends(get_service),
    ) -> list[EvidenceRecord]:
        _require_investigation(service, investigation_id)
        return [
            record
            for record in service.list_evidence(investigation_id)
            if record.kind != "verified_fact"
        ]

    @app.post("/api/v1/investigations/{investigation_id}/review")
    @app.post("/api/v1/investigations/{investigation_id}/resume")
    def review_investigation(
        investigation_id: str,
        review: ReviewDecision,
        service: InvestigationService = Depends(get_service),
    ) -> InvestigationResult:
        _require_investigation(service, investigation_id)
        try:
            return service.resume_investigation(investigation_id, review)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    return app


def get_service(request: Request) -> InvestigationService:
    return request.app.state.service


def _require_investigation(
    service: InvestigationService,
    investigation_id: str,
) -> InvestigationSummary:
    summary = service.get_investigation(investigation_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return summary


def _render_index(examples: list[dict[str, str]]) -> str:
    options = "\n".join(
        (
            f'<option value="{escape(example["path"], quote=True)}">'
            f'{escape(example["label"])}</option>'
        )
        for example in examples
    )
    default_input = examples[0]["path"] if examples else "examples/suspicious-build.json"
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Provenance Risk Agent</title>
    <style>
      :root {{
        color-scheme: light;
        --bg: #f7f8fb;
        --panel: #ffffff;
        --ink: #172033;
        --muted: #667085;
        --line: #d9dee8;
        --blue: #2563eb;
        --green: #16a34a;
        --amber: #d97706;
        --red: #dc2626;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        background: var(--bg);
        color: var(--ink);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
          "Segoe UI", sans-serif;
      }}
      header {{
        border-bottom: 1px solid var(--line);
        background: var(--panel);
      }}
      .shell {{
        max-width: 1180px;
        margin: 0 auto;
        padding: 22px 24px;
      }}
      h1 {{
        margin: 0;
        font-size: 24px;
        line-height: 1.2;
      }}
      main.shell {{
        display: grid;
        grid-template-columns: minmax(280px, 360px) 1fr;
        gap: 18px;
      }}
      section, aside {{
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 8px;
        padding: 16px;
      }}
      label {{
        display: block;
        margin-bottom: 6px;
        color: var(--muted);
        font-size: 13px;
        font-weight: 650;
      }}
      select, textarea, button {{
        width: 100%;
        border-radius: 6px;
        border: 1px solid var(--line);
        font: inherit;
      }}
      select, textarea {{
        background: #ffffff;
        color: var(--ink);
        padding: 10px;
      }}
      textarea {{
        min-height: 132px;
        resize: vertical;
      }}
      button {{
        margin-top: 14px;
        border-color: var(--blue);
        background: var(--blue);
        color: #ffffff;
        cursor: pointer;
        font-weight: 700;
        padding: 11px 12px;
      }}
      button:disabled {{
        cursor: progress;
        opacity: .72;
      }}
      .check {{
        display: flex;
        gap: 8px;
        align-items: center;
        margin-top: 14px;
        color: var(--ink);
      }}
      .check input {{
        width: 16px;
        height: 16px;
      }}
      .review-form {{
        border-top: 1px solid var(--line);
        margin-top: 18px;
        padding-top: 16px;
      }}
      .review-form input {{
        width: 100%;
        border: 1px solid var(--line);
        border-radius: 6px;
        padding: 10px;
        font: inherit;
      }}
      .metrics {{
        display: grid;
        grid-template-columns: repeat(4, minmax(120px, 1fr));
        gap: 10px;
        margin-bottom: 14px;
      }}
      .metric {{
        border: 1px solid var(--line);
        border-radius: 8px;
        padding: 12px;
        min-height: 82px;
      }}
      .metric strong {{
        display: block;
        margin-top: 6px;
        font-size: 22px;
      }}
      .decision {{
        color: var(--amber);
      }}
      .decision.ALLOW {{
        color: var(--green);
      }}
      .decision.ERROR, .decision.UNKNOWN {{
        color: var(--red);
      }}
      h2 {{
        margin: 0 0 10px;
        font-size: 16px;
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 18px;
      }}
      th, td {{
        border-bottom: 1px solid var(--line);
        padding: 9px 6px;
        text-align: left;
        vertical-align: top;
        font-size: 13px;
      }}
      th {{
        color: var(--muted);
        font-weight: 700;
      }}
      code {{
        word-break: break-word;
      }}
      pre {{
        white-space: pre-wrap;
        word-break: break-word;
        margin: 0;
        color: #273449;
        font-size: 13px;
      }}
      .empty {{
        color: var(--muted);
        padding: 20px 0;
      }}
      @media (max-width: 860px) {{
        main.shell {{
          grid-template-columns: 1fr;
        }}
        .metrics {{
          grid-template-columns: repeat(2, minmax(120px, 1fr));
        }}
      }}
    </style>
  </head>
  <body>
    <header>
      <div class="shell">
        <h1>Enterprise Linux Provenance Risk Agent</h1>
      </div>
    </header>
    <main class="shell">
      <aside>
        <form id="investigation-form">
          <label for="artifact">Artifact</label>
          <select id="artifact" name="input_path">
            {options}
          </select>
          <label for="question" style="margin-top:14px">Question</label>
          <textarea id="question" name="question">{escape(DEFAULT_QUESTION)}</textarea>
          <label class="check" for="pause-before-review">
            <input id="pause-before-review" name="pause_before_review" type="checkbox">
            Pause for human review
          </label>
          <button id="submit" type="submit">Run investigation</button>
        </form>
      </aside>
      <section>
        <div id="result" class="empty">No investigation yet.</div>
      </section>
    </main>
    <script>
      const form = document.getElementById("investigation-form");
      const result = document.getElementById("result");
      const submit = document.getElementById("submit");

      function text(value) {{
        return String(value ?? "").replace(/[&<>"']/g, (char) => ({{
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#039;"
        }}[char]));
      }}

      function renderRows(items, columns) {{
        if (!items.length) {{
          return "<tr><td colspan='" + columns.length + "'>None</td></tr>";
        }}
        return items.map((item) => "<tr>" + columns.map((column) => {{
          const value = item[column] ?? "";
          return "<td><code>" + text(value) + "</code></td>";
        }}).join("") + "</tr>").join("");
      }}

      function renderList(items) {{
        if (!items.length) return "<p class='empty'>None</p>";
        return "<ul>" + items.map((item) => "<li><code>" + text(item) + "</code></li>").join("") + "</ul>";
      }}

      function reviewPanel(data) {{
        if (data.status !== "awaiting_review") return "";
        return `
          <form id="review-form" class="review-form">
            <h2>Human Review</h2>
            <label for="review-decision">Decision</label>
            <select id="review-decision" name="decision">
              <option value="DENY">Deny</option>
              <option value="ALLOW">Allow</option>
              <option value="UNKNOWN">Unknown</option>
              <option value="REVIEW">Keep in review</option>
            </select>
            <label for="reviewer" style="margin-top:10px">Reviewer</label>
            <input id="reviewer" name="reviewer" required value="local-reviewer">
            <label for="rationale" style="margin-top:10px">Rationale</label>
            <textarea id="rationale" name="rationale" required></textarea>
            <button type="submit">Submit decision</button>
          </form>`;
      }}

      function render(data) {{
        const reliability = data.reliability ?? {{}};
        result.className = "";
        result.innerHTML = `
          <div class="metrics">
            <div class="metric"><span>Decision</span><strong class="decision ${{text(data.decision_state)}}">${{text(data.decision_state)}}</strong></div>
            <div class="metric"><span>Risk</span><strong>${{text(data.risk_level)}} / ${{text(data.risk_score)}}</strong></div>
            <div class="metric"><span>Completeness</span><strong>${{text(reliability.completeness_score)}}%</strong></div>
            <div class="metric"><span>Confidence</span><strong>${{text(reliability.confidence_score)}}%</strong></div>
          </div>
          <h2>Artifact</h2>
          <table><tbody>
            <tr><th>Name</th><td>${{text(data.artifact?.name)}}</td></tr>
            <tr><th>Version</th><td>${{text(data.artifact?.version)}}</td></tr>
            <tr><th>Digest</th><td><code>${{text(data.artifact?.digest)}}</code></td></tr>
            <tr><th>Schema</th><td><code>${{text(data.source_schema)}}</code></td></tr>
            <tr><th>Status</th><td><code>${{text(data.status)}}</code></td></tr>
          </tbody></table>
          <h2>Risk Evidence</h2>
          <table>
            <thead><tr><th>Evidence ID</th><th>Code</th><th>Finding</th><th>Weight</th></tr></thead>
            <tbody>${{renderRows(data.evidence ?? [], ["evidence_id", "code", "finding", "weight"])}}</tbody>
          </table>
          <h2>Verified Facts</h2>
          <table>
            <thead><tr><th>Evidence ID</th><th>Code</th><th>Finding</th></tr></thead>
            <tbody>${{renderRows(data.observations ?? [], ["evidence_id", "code", "finding"])}}</tbody>
          </table>
          <h2>Contradictions</h2>
          <table>
            <thead><tr><th>ID</th><th>Code</th><th>Message</th><th>Severity</th></tr></thead>
            <tbody>${{renderRows(data.contradictions ?? [], ["contradiction_id", "code", "message", "severity"])}}</tbody>
          </table>
          <h2>Missing Evidence</h2>
          ${{renderList(data.missing_evidence ?? [])}}
          <h2>Policy Rules</h2>
          <table>
            <thead><tr><th>Rule</th><th>Status</th><th>Message</th></tr></thead>
            <tbody>${{renderRows(data.policy_evaluation?.rule_results ?? [], ["rule_id", "status", "message"])}}</tbody>
          </table>
          <h2>Trace</h2>
          <table>
            <thead><tr><th>#</th><th>Event</th><th>Message</th></tr></thead>
            <tbody>${{renderRows(data.events ?? [], ["sequence", "event_type", "message"])}}</tbody>
          </table>
          <h2>Explanation</h2>
          <pre>${{text(data.explanation)}}</pre>
          ${{reviewPanel(data)}}
        `;
        const reviewForm = document.getElementById("review-form");
        if (reviewForm) {{
          reviewForm.addEventListener("submit", async (event) => {{
            event.preventDefault();
            const reviewResponse = await fetch(`/api/v1/investigations/${{data.investigation_id}}/review`, {{
              method: "POST",
              headers: {{"content-type": "application/json"}},
              body: JSON.stringify({{
                decision: reviewForm.decision.value,
                reviewer: reviewForm.reviewer.value,
                rationale: reviewForm.rationale.value
              }})
            }});
            const reviewed = await reviewResponse.json();
            if (!reviewResponse.ok) throw new Error(reviewed.detail ?? reviewResponse.statusText);
            render(reviewed);
          }});
        }}
      }}

      form.addEventListener("submit", async (event) => {{
        event.preventDefault();
        submit.disabled = true;
        result.className = "empty";
        result.textContent = "Investigation running...";
        const body = {{
          input_path: form.input_path.value || "{escape(default_input, quote=True)}",
          question: form.question.value,
          pause_before_review: form.pause_before_review.checked
        }};
        try {{
          const response = await fetch("/api/v1/investigations", {{
            method: "POST",
            headers: {{"content-type": "application/json"}},
            body: JSON.stringify(body)
          }});
          const data = await response.json();
          if (!response.ok) {{
            throw new Error(data.detail ?? response.statusText);
          }}
          render(data);
        }} catch (error) {{
          result.className = "empty";
          result.textContent = error.message;
        }} finally {{
          submit.disabled = false;
        }}
      }});
    </script>
  </body>
</html>
"""


app = create_app()
