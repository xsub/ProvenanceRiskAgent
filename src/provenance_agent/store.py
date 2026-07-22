"""SQLite persistence for investigation lifecycle data.

Stores requests, summaries, events, adapter traces, review state, and complete
results while providing typed reconstruction and transactional updates.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import (
    EvidenceRecord,
    InvestigationEvent,
    InvestigationResult,
    InvestigationStatus,
    InvestigationSummary,
    utc_now,
)


def _dt(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


class InvestigationStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent != Path("."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                create table if not exists investigations (
                    id text primary key,
                    status text not null,
                    question text not null,
                    input_path text not null,
                    result_json text,
                    created_at text not null,
                    updated_at text not null
                );

                create table if not exists investigation_events (
                    id integer primary key autoincrement,
                    investigation_id text not null,
                    sequence integer not null,
                    event_type text not null,
                    message text not null,
                    details_json text not null,
                    created_at text not null,
                    foreign key(investigation_id) references investigations(id)
                );

                create table if not exists evidence_records (
                    id integer primary key autoincrement,
                    evidence_id text not null,
                    investigation_id text not null,
                    kind text not null,
                    code text not null,
                    finding text not null,
                    source text not null,
                    weight integer not null default 0,
                    source_pointers_json text not null default '[]',
                    foreign key(investigation_id) references investigations(id)
                );
                """
            )
            columns = {
                row["name"]
                for row in connection.execute(
                    "pragma table_info(evidence_records)"
                ).fetchall()
            }
            if "evidence_id" not in columns:
                connection.execute(
                    "alter table evidence_records add column evidence_id text"
                )
            if "source_pointers_json" not in columns:
                connection.execute(
                    "alter table evidence_records "
                    "add column source_pointers_json text not null default '[]'"
                )
            connection.execute(
                """
                update evidence_records
                set evidence_id = 'legacy_' || id
                where evidence_id is null or evidence_id = ''
                """
            )
            connection.execute(
                """
                create unique index if not exists evidence_records_identity
                on evidence_records(investigation_id, evidence_id)
                """
            )

    def create_investigation(
        self,
        *,
        investigation_id: str,
        question: str,
        input_path: str,
    ) -> None:
        now = _dt(utc_now())
        with self.connect() as connection:
            connection.execute(
                """
                insert into investigations
                    (id, status, question, input_path, created_at, updated_at)
                values (?, ?, ?, ?, ?, ?)
                """,
                (investigation_id, "pending", question, input_path, now, now),
            )

    def set_status(
        self,
        investigation_id: str,
        status: InvestigationStatus,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                update investigations
                set status = ?, updated_at = ?
                where id = ?
                """,
                (status, _dt(utc_now()), investigation_id),
            )

    def add_event(
        self,
        investigation_id: str,
        event_type: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> InvestigationEvent:
        details = details or {}
        with self.connect() as connection:
            row = connection.execute(
                """
                select coalesce(max(sequence), 0) + 1 as next_sequence
                from investigation_events
                where investigation_id = ?
                """,
                (investigation_id,),
            ).fetchone()
            sequence = int(row["next_sequence"])
            created_at = utc_now()
            cursor = connection.execute(
                """
                insert into investigation_events
                    (investigation_id, sequence, event_type, message,
                     details_json, created_at)
                values (?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    sequence,
                    event_type,
                    message,
                    json.dumps(details, sort_keys=True),
                    _dt(created_at),
                ),
            )
            connection.execute(
                "update investigations set updated_at = ? where id = ?",
                (_dt(created_at), investigation_id),
            )
        return InvestigationEvent(
            id=int(cursor.lastrowid),
            investigation_id=investigation_id,
            sequence=sequence,
            event_type=event_type,
            message=message,
            details=details,
            created_at=created_at,
        )

    def add_evidence(self, record: EvidenceRecord) -> EvidenceRecord:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                insert or ignore into evidence_records
                    (evidence_id, investigation_id, kind, code, finding, source,
                     weight, source_pointers_json)
                values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.evidence_id,
                    record.investigation_id,
                    record.kind,
                    record.code,
                    record.finding,
                    record.source,
                    record.weight,
                    json.dumps(
                        [
                            pointer.model_dump(mode="json")
                            for pointer in record.source_pointers
                        ],
                        sort_keys=True,
                    ),
                ),
            )
            record_id = cursor.lastrowid
            if not record_id:
                row = connection.execute(
                    """
                    select id from evidence_records
                    where investigation_id = ? and evidence_id = ?
                    """,
                    (record.investigation_id, record.evidence_id),
                ).fetchone()
                record_id = row["id"]
        return record.model_copy(update={"id": int(record_id)})

    def save_result(self, result: InvestigationResult) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                update investigations
                set status = ?, result_json = ?, updated_at = ?
                where id = ?
                """,
                (
                    result.status,
                    result.model_dump_json(),
                    _dt(utc_now()),
                    result.investigation_id,
                ),
            )

    def get_investigation(self, investigation_id: str) -> InvestigationSummary | None:
        with self.connect() as connection:
            row = connection.execute(
                "select * from investigations where id = ?",
                (investigation_id,),
            ).fetchone()
        if row is None:
            return None
        result = (
            InvestigationResult.model_validate_json(row["result_json"])
            if row["result_json"]
            else None
        )
        return InvestigationSummary(
            investigation_id=row["id"],
            status=row["status"],
            question=row["question"],
            input_path=row["input_path"],
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
            result=result,
        )

    def list_events(self, investigation_id: str) -> list[InvestigationEvent]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                select * from investigation_events
                where investigation_id = ?
                order by sequence asc
                """,
                (investigation_id,),
            ).fetchall()
        return [
            InvestigationEvent(
                id=row["id"],
                investigation_id=row["investigation_id"],
                sequence=row["sequence"],
                event_type=row["event_type"],
                message=row["message"],
                details=json.loads(row["details_json"]),
                created_at=_parse_dt(row["created_at"]),
            )
            for row in rows
        ]

    def list_evidence(self, investigation_id: str) -> list[EvidenceRecord]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                select * from evidence_records
                where investigation_id = ?
                order by id asc
                """,
                (investigation_id,),
            ).fetchall()
        return [
            EvidenceRecord(
                id=row["id"],
                evidence_id=row["evidence_id"],
                investigation_id=row["investigation_id"],
                kind=row["kind"],
                code=row["code"],
                finding=row["finding"],
                source=row["source"],
                weight=row["weight"],
                source_pointers=json.loads(row["source_pointers_json"]),
            )
            for row in rows
        ]
