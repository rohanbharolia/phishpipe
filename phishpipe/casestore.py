"""Stage 5 - Case management backed by SQLite.

The brief calls for an open-source IR platform such as TheHive or IRIS. Neither
can run here (no container runtime), so this module provides the same core
value with zero infrastructure: every investigation is persisted as a queryable
row plus the full structured case as JSON, with the columns needed for the
dashboard's filters and metrics.

The schema is deliberately simple so it can be swapped for TheHive/IRIS
adapters later without touching the pipeline.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from phishpipe.config import CASES_DB_FILE, Settings, load_settings
from phishpipe.models import Case

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'new',
    classification  TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      INTEGER NOT NULL,
    sender          TEXT NOT NULL DEFAULT '',
    subject         TEXT NOT NULL DEFAULT '',
    indicator_count INTEGER NOT NULL DEFAULT 0,
    signals_matched INTEGER NOT NULL DEFAULT 0,
    offline         INTEGER NOT NULL DEFAULT 1,
    total_ms        INTEGER NOT NULL DEFAULT 0,
    needs_review    INTEGER NOT NULL DEFAULT 0,
    payload         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cases_created   ON cases (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_class     ON cases (classification);
CREATE INDEX IF NOT EXISTS idx_cases_severity  ON cases (severity);
"""

LIST_COLUMNS = (
    "id, created_at, title, status, classification, severity, confidence, "
    "sender, subject, indicator_count, signals_matched, offline, total_ms, needs_review"
)


class CaseStore:
    """Thin, thread-safe-enough wrapper over a SQLite file."""

    def __init__(self, db_path: Path | None = None, settings: Settings | None = None) -> None:
        settings = settings or load_settings()
        self.db_path = Path(db_path or settings.cases_db_file)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # -- connection helpers -------------------------------------------------
    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # -- CRUD ---------------------------------------------------------------
    def save(self, case: Case) -> str:
        payload = json.dumps(case.to_public_dict(), ensure_ascii=False)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO cases (
                    id, created_at, title, status, classification, severity, confidence,
                    sender, subject, indicator_count, signals_matched, offline,
                    total_ms, needs_review, payload
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    status=excluded.status,
                    classification=excluded.classification,
                    severity=excluded.severity,
                    confidence=excluded.confidence,
                    sender=excluded.sender,
                    subject=excluded.subject,
                    indicator_count=excluded.indicator_count,
                    signals_matched=excluded.signals_matched,
                    offline=excluded.offline,
                    total_ms=excluded.total_ms,
                    needs_review=excluded.needs_review,
                    payload=excluded.payload
                """,
                (
                    case.id,
                    case.created_at.isoformat(),
                    case.title,
                    case.status,
                    case.verdict.classification,
                    case.verdict.severity,
                    case.verdict.confidence,
                    case.email.from_address,
                    case.email.subject,
                    len(case.indicators),
                    case.verdict.signals_matched,
                    1 if case.metrics.offline else 0,
                    case.metrics.total_ms,
                    1 if case.verdict.needs_human_review else 0,
                    payload,
                ),
            )
        return case.id

    def get(self, case_id: str) -> Case | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload, status FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
        if not row:
            return None
        case = Case.model_validate(json.loads(row["payload"]))
        # `status` is the only mutable column and is edited in place, so the
        # column value must override whatever was frozen into the payload.
        case.status = row["status"]
        return case

    @staticmethod
    def _where(
        classification: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if classification:
            clauses.append("classification = ?")
            params.append(classification)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if search:
            clauses.append("(subject LIKE ? OR sender LIKE ? OR title LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        classification: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return lightweight case summaries (payload excluded) for listings."""
        where, params = self._where(classification, severity, status, search)
        sql = f"SELECT {LIST_COLUMNS} FROM cases {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [max(1, min(limit, 500)), max(0, offset)]

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["offline"] = bool(item["offline"])
            item["needs_review"] = bool(item["needs_review"])
            out.append(item)
        return out

    def count(
        self,
        classification: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> int:
        """Count cases, honouring the same filters as :meth:`list`."""
        where, params = self._where(classification, severity, status, search)
        with self._conn() as conn:
            return int(conn.execute(f"SELECT COUNT(*) AS n FROM cases {where}", params).fetchone()["n"])

    def update_status(self, case_id: str, status: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("UPDATE cases SET status = ? WHERE id = ?", (status, case_id))
        return cur.rowcount > 0

    def delete(self, case_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        return cur.rowcount > 0

    def stats(self) -> dict[str, Any]:
        """Aggregate metrics for the dashboard header."""
        with self._conn() as conn:
            total = int(conn.execute("SELECT COUNT(*) AS n FROM cases").fetchone()["n"])
            by_class = {
                r["classification"]: r["n"]
                for r in conn.execute(
                    "SELECT classification, COUNT(*) AS n FROM cases GROUP BY classification"
                )
            }
            by_severity = {
                r["severity"]: r["n"]
                for r in conn.execute("SELECT severity, COUNT(*) AS n FROM cases GROUP BY severity")
            }
            avg_conf = conn.execute("SELECT AVG(confidence) AS a FROM cases").fetchone()["a"]
            avg_ms = conn.execute("SELECT AVG(total_ms) AS a FROM cases").fetchone()["a"]
            needs_review = int(
                conn.execute("SELECT COUNT(*) AS n FROM cases WHERE needs_review = 1").fetchone()["n"]
            )
            total_ms = int(conn.execute("SELECT COALESCE(SUM(total_ms),0) AS s FROM cases").fetchone()["s"])

        baseline_minutes = 45
        try:
            from phishpipe.config import MANUAL_INVESTIGATION_MINUTES

            baseline_minutes = MANUAL_INVESTIGATION_MINUTES
        except Exception:  # pragma: no cover
            pass

        automated_minutes = total_ms / 60000
        manual_minutes = total * baseline_minutes
        return {
            "total_cases": total,
            "by_classification": by_class,
            "by_severity": by_severity,
            "avg_confidence": round(float(avg_conf), 1) if avg_conf is not None else 0,
            "avg_processing_ms": round(float(avg_ms), 1) if avg_ms is not None else 0,
            "needs_human_review": needs_review,
            "automated_minutes": round(automated_minutes, 2),
            "manual_baseline_minutes": manual_minutes,
            "minutes_saved": round(manual_minutes - automated_minutes, 1),
            "db_path": str(self.db_path),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def clear(self) -> int:
        """Delete every case (used by tests / demo reset)."""
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM cases")
        return cur.rowcount


def default_store() -> CaseStore:
    return CaseStore(CASES_DB_FILE)
