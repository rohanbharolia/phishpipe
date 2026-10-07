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

CREATE TABLE IF NOT EXISTS case_notes (
    id         TEXT PRIMARY KEY,
    case_id    TEXT NOT NULL,
    author     TEXT NOT NULL DEFAULT 'analyst',
    text       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_case ON case_notes (case_id);

CREATE TABLE IF NOT EXISTS case_tags (
    case_id TEXT NOT NULL,
    tag     TEXT NOT NULL,
    PRIMARY KEY (case_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_tags_case ON case_tags (case_id);

CREATE TABLE IF NOT EXISTS case_actions (
    id          TEXT PRIMARY KEY,
    case_id     TEXT NOT NULL,
    action      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'success',
    detail      TEXT NOT NULL DEFAULT '',
    executed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_case ON case_actions (case_id);

CREATE TABLE IF NOT EXISTS case_clicks (
    id                    TEXT PRIMARY KEY,
    case_id               TEXT NOT NULL,
    timestamp             TEXT NOT NULL,
    url                   TEXT NOT NULL,
    user_email            TEXT NOT NULL DEFAULT '',
    client_ip             TEXT,
    user_agent            TEXT,
    source                TEXT NOT NULL DEFAULT 'web_proxy',
    outcome               TEXT NOT NULL DEFAULT 'allowed',
    credentials_submitted INTEGER NOT NULL DEFAULT 0,
    details               TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_clicks_case ON case_clicks (case_id);
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
        if not case.indicators and case.email:
            try:
                from phishpipe.extract import extract_indicators
                case.indicators = extract_indicators(case.email)
            except Exception:
                pass
        if case.click_telemetry and case.click_telemetry.events:
            from phishpipe.models import Indicator
            from phishpipe.extract import host_from_url, registrable_domain
            existing_vals = {i.value.strip().lower() for i in case.indicators}
            for evt in case.click_telemetry.events:
                if evt.url and evt.url.strip().lower() not in existing_vals:
                    case.indicators.append(
                        Indicator(
                            type="url",
                            value=evt.url.strip(),
                            source="click_telemetry",
                            context=f"Confirmed click by {evt.user_email or 'user'}",
                        )
                    )
                    existing_vals.add(evt.url.strip().lower())
                    host = host_from_url(evt.url.strip())
                    dom = registrable_domain(host) if host else None
                    if dom and dom.lower() not in existing_vals:
                        case.indicators.append(
                            Indicator(
                                type="domain",
                                value=dom,
                                source="click_telemetry",
                                context=f"Domain in confirmed click {evt.url.strip()}",
                            )
                        )
                        existing_vals.add(dom.lower())
                if evt.client_ip and evt.client_ip.strip().lower() not in existing_vals:
                    case.indicators.append(
                        Indicator(
                            type="ip",
                            value=evt.client_ip.strip(),
                            source="click_telemetry",
                            context="Client IP recorded in gateway click event",
                        )
                    )
                    existing_vals.add(evt.client_ip.strip().lower())
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
        from phishpipe.models import CaseNote
        case.notes = [CaseNote(**n) for n in self.list_notes(case_id)]
        case.tags = self.get_tags(case_id)
        case.playbook_actions_taken = self.list_actions(case_id)
        click_events = self.list_clicks(case_id)
        if click_events:
            case.click_telemetry.events = click_events
            case.click_telemetry.has_positive_click = True
            case.click_telemetry.click_count = len(click_events)
            case.click_telemetry.first_click_at = click_events[0].timestamp
            case.click_telemetry.last_click_at = click_events[-1].timestamp
            case.click_telemetry.credentials_compromised = any(
                e.credentials_submitted or e.outcome == "credentials_submitted" for e in click_events
            )
            from phishpipe.models import Indicator
            from phishpipe.extract import host_from_url, registrable_domain
            existing_vals = {i.value.strip().lower() for i in case.indicators}
            for evt in click_events:
                if evt.url and evt.url.strip().lower() not in existing_vals:
                    case.indicators.append(
                        Indicator(
                            type="url",
                            value=evt.url.strip(),
                            source="click_telemetry",
                            context=f"Confirmed click by {evt.user_email or 'user'}",
                        )
                    )
                    existing_vals.add(evt.url.strip().lower())
                    host = host_from_url(evt.url.strip())
                    dom = registrable_domain(host) if host else None
                    if dom and dom.lower() not in existing_vals:
                        case.indicators.append(
                            Indicator(
                                type="domain",
                                value=dom,
                                source="click_telemetry",
                                context=f"Domain in confirmed click {evt.url.strip()}",
                            )
                        )
                        existing_vals.add(dom.lower())
                if evt.client_ip and evt.client_ip.strip().lower() not in existing_vals:
                    case.indicators.append(
                        Indicator(
                            type="ip",
                            value=evt.client_ip.strip(),
                            source="click_telemetry",
                            context="Client IP recorded in gateway click event",
                        )
                    )
                    existing_vals.add(evt.client_ip.strip().lower())
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

    # -- Notes & Tagging & Playbooks ----------------------------------------
    def add_note(self, case_id: str, text: str, author: str = "analyst") -> dict[str, Any]:
        import uuid
        note_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO case_notes (id, case_id, author, text, created_at) VALUES (?,?,?,?,?)",
                (note_id, case_id, author, text, now),
            )
        return {"id": note_id, "case_id": case_id, "author": author, "text": text, "created_at": now}

    def list_notes(self, case_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, case_id, author, text, created_at FROM case_notes WHERE case_id = ? ORDER BY created_at ASC",
                (case_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_note(self, case_id: str, note_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM case_notes WHERE case_id = ? AND id = ?", (case_id, note_id))
        return cur.rowcount > 0

    def add_tag(self, case_id: str, tag: str) -> list[str]:
        clean_tag = tag.strip().lower()
        if not clean_tag:
            return self.get_tags(case_id)
        with self._conn() as conn:
            conn.execute("INSERT OR IGNORE INTO case_tags (case_id, tag) VALUES (?,?)", (case_id, clean_tag))
        return self.get_tags(case_id)

    def remove_tag(self, case_id: str, tag: str) -> list[str]:
        with self._conn() as conn:
            conn.execute("DELETE FROM case_tags WHERE case_id = ? AND tag = ?", (case_id, tag.strip().lower()))
        return self.get_tags(case_id)

    def set_tags(self, case_id: str, tags: list[str]) -> list[str]:
        with self._conn() as conn:
            conn.execute("DELETE FROM case_tags WHERE case_id = ?", (case_id,))
            for t in tags:
                clean = t.strip().lower()
                if clean:
                    conn.execute("INSERT OR IGNORE INTO case_tags (case_id, tag) VALUES (?,?)", (case_id, clean))
        return self.get_tags(case_id)

    def get_tags(self, case_id: str) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT tag FROM case_tags WHERE case_id = ? ORDER BY tag ASC", (case_id,)).fetchall()
        return [r["tag"] for r in rows]

    def record_action(self, case_id: str, action: str, detail: str = "", status: str = "success") -> dict[str, Any]:
        import uuid
        action_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO case_actions (id, case_id, action, status, detail, executed_at) VALUES (?,?,?,?,?,?)",
                (action_id, case_id, action, status, detail, now),
            )
        return {"id": action_id, "case_id": case_id, "action": action, "status": status, "detail": detail, "executed_at": now}

    def list_actions(self, case_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, case_id, action, status, detail, executed_at FROM case_actions WHERE case_id = ? ORDER BY executed_at ASC",
                (case_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def record_click(self, case_id: str, click_event: Any) -> Case | None:
        """Record positive click confirmation telemetry, escalating the case to Critical compromise."""
        import uuid
        from phishpipe.models import ClickEvent, Signal, MitreTechnique

        if not isinstance(click_event, ClickEvent):
            click_event = ClickEvent(**click_event)

        if not click_event.id:
            click_event.id = f"CLK-{str(uuid.uuid4())[:8]}"
        click_event.case_id = case_id
        now_iso = click_event.timestamp.isoformat() if hasattr(click_event.timestamp, "isoformat") else str(click_event.timestamp)

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO case_clicks (
                    id, case_id, timestamp, url, user_email, client_ip, user_agent, source, outcome, credentials_submitted, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    click_event.id,
                    case_id,
                    now_iso,
                    click_event.url,
                    click_event.user_email,
                    click_event.client_ip,
                    click_event.user_agent,
                    click_event.source,
                    click_event.outcome,
                    1 if click_event.credentials_submitted else 0,
                    click_event.details,
                ),
            )

        case = self.get(case_id)
        if case is None:
            return None

        # Update aggregated telemetry
        case.click_telemetry.has_positive_click = True
        case.click_telemetry.click_count = len(case.click_telemetry.events)
        if click_event.credentials_submitted or click_event.outcome == "credentials_submitted":
            case.click_telemetry.credentials_compromised = True

        # Escalate triage status and severity
        case.verdict.severity = "critical"
        case.verdict.needs_human_review = True
        if case.verdict.classification == "false_positive":
            case.verdict.classification = "suspicious"

        # Signal injection for explainable audit
        sig_id = "SIGNAL_CONFIRMED_USER_CLICK"
        existing = [s for s in case.signals if s.id == sig_id]
        if not existing:
            user_label = click_event.user_email or (case.email.to[0] if case.email.to else "recipient")
            outcome_label = click_event.outcome.upper()
            sig = Signal(
                id=sig_id,
                title="Positive User Click Confirmed (Gateway/EDR Telemetry)",
                description="Web gateway, DNS, or proxy logs confirm recipient clicked a link in this lure.",
                weight=30,
                matched=True,
                severity="critical",
                evidence=f"Confirmed navigation by '{user_label}' to '{click_event.url}' (Outcome: {outcome_label}, IP: {click_event.client_ip or 'unknown'}).",
                category="click_telemetry",
                mitre=["T1204.001", "T1566.002"],
            )
            case.signals.insert(0, sig)
            case.verdict.signals_matched += 1
            if not any(m.id == "T1204.001" for m in case.verdict.mitre):
                case.verdict.mitre.append(
                    MitreTechnique(
                        id="T1204.001",
                        name="User Execution: Malicious Link",
                        tactic="Execution",
                        url="https://attack.mitre.org/techniques/T1204/001/",
                    )
                )

        # Tags
        self.add_tag(case_id, "positive-click")
        if case.click_telemetry.credentials_compromised:
            self.add_tag(case_id, "credentials-compromised")
        else:
            self.add_tag(case_id, "potential-compromise")
        case.tags = self.get_tags(case_id)

        # Emergency recommended actions
        emergency_action = "EMERGENCY: Force immediate Okta/AzureAD password reset and revoke active OAuth sessions."
        if emergency_action not in case.verdict.recommended_actions:
            case.verdict.recommended_actions.insert(0, emergency_action)
        edr_action = f"EDR CONTAINMENT: Isolate host ({click_event.client_ip or 'endpoint'}) from internal subnet."
        if edr_action not in case.verdict.recommended_actions:
            case.verdict.recommended_actions.insert(1, edr_action)

        # Record action in audit log
        self.record_action(
            case_id,
            "positive_click_registered",
            detail=f"Click confirmed on {click_event.url} from {click_event.client_ip or 'client'} (Outcome: {click_event.outcome})",
        )
        case.playbook_actions_taken = self.list_actions(case_id)

        # Ensure click URL, domain, and client IP are captured as IOCs
        from phishpipe.models import Indicator
        from phishpipe.extract import host_from_url, registrable_domain
        existing_vals = {i.value.strip().lower() for i in case.indicators}
        if click_event.url and click_event.url.strip().lower() not in existing_vals:
            case.indicators.append(
                Indicator(
                    type="url",
                    value=click_event.url.strip(),
                    source="click_telemetry",
                    context=f"Confirmed click by {click_event.user_email or 'user'}",
                )
            )
            existing_vals.add(click_event.url.strip().lower())
            host = host_from_url(click_event.url.strip())
            dom = registrable_domain(host) if host else None
            if dom and dom.lower() not in existing_vals:
                case.indicators.append(
                    Indicator(
                        type="domain",
                        value=dom,
                        source="click_telemetry",
                        context=f"Domain in confirmed click {click_event.url.strip()}",
                    )
                )
                existing_vals.add(dom.lower())
        if click_event.client_ip and click_event.client_ip.strip().lower() not in existing_vals:
            case.indicators.append(
                Indicator(
                    type="ip",
                    value=click_event.client_ip.strip(),
                    source="click_telemetry",
                    context="Client IP recorded in gateway click event",
                )
            )
            existing_vals.add(click_event.client_ip.strip().lower())

        # Ensure timeline and report reflect confirmed click and containment actions
        from phishpipe.models import TimelineEntry
        from phishpipe.report import build_report

        user_lbl = click_event.user_email or (case.email.to[0] if (case.email and case.email.to) else "recipient")
        outcome_lbl = (click_event.outcome or "allowed").upper()
        click_time = click_event.timestamp if hasattr(click_event.timestamp, "isoformat") else datetime.now(timezone.utc)
        
        # Add click telemetry stage to timeline if not already recorded
        if not any(t.stage == "click_telemetry" for t in case.timeline):
            case.timeline.append(
                TimelineEntry(
                    stage="click_telemetry",
                    started_at=click_time,
                    duration_ms=4,
                    detail=f"Confirmed click by '{user_lbl}' on {click_event.url} (Outcome: {outcome_lbl}, IP: {click_event.client_ip or 'unknown'}) -> Escalated to CRITICAL",
                )
            )
        if not any(t.stage == "containment" for t in case.timeline):
            case.timeline.append(
                TimelineEntry(
                    stage="containment",
                    started_at=datetime.now(timezone.utc),
                    duration_ms=2,
                    detail="Automated containment playbook: emergency credential reset and host isolation flagged.",
                )
            )
        case.metrics.total_ms = sum(t.duration_ms for t in case.timeline)
        case.report_markdown = build_report(case)

        # Persist updated case
        self.save(case)
        return case

    def list_clicks(self, case_id: str) -> list[Any]:
        from phishpipe.models import ClickEvent

        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, case_id, timestamp, url, user_email, client_ip, user_agent, source, outcome, credentials_submitted, details
                FROM case_clicks WHERE case_id = ? ORDER BY timestamp ASC
                """,
                (case_id,),
            ).fetchall()
        events = []
        for r in rows:
            events.append(
                ClickEvent(
                    id=r["id"],
                    case_id=r["case_id"],
                    timestamp=r["timestamp"],
                    url=r["url"],
                    user_email=r["user_email"],
                    client_ip=r["client_ip"],
                    user_agent=r["user_agent"],
                    source=r["source"],
                    outcome=r["outcome"],
                    credentials_submitted=bool(r["credentials_submitted"]),
                    details=r["details"],
                )
            )
        return events

    def get_campaigns(self) -> list[dict[str, Any]]:
        """Cluster cases into threat campaigns based on shared sender domain or target subject."""
        cases = self.list(limit=500)
        from collections import defaultdict
        groups: dict[str, list[dict]] = defaultdict(list)

        for c in cases:
            sender = c.get("sender") or ""
            domain = sender.split("@")[-1].lower() if "@" in sender else "unknown"
            if domain and domain != "unknown":
                groups[domain].append(c)
            else:
                subj = (c.get("subject") or "generic")[:30].strip()
                groups[f"subject:{subj}"].append(c)

        campaigns = []
        for key, members in groups.items():
            tp_count = sum(1 for m in members if m.get("classification") == "true_positive")
            su_count = sum(1 for m in members if m.get("classification") == "suspicious")
            worst_sev = "critical" if any(m.get("severity") == "critical" for m in members) else ("high" if any(m.get("severity") == "high" for m in members) else "medium")
            campaigns.append({
                "id": f"CAMP-{abs(hash(key)) % 1000000:06d}",
                "name": f"Campaign: {key}",
                "cluster_key": key,
                "case_count": len(members),
                "true_positives": tp_count,
                "suspicious": su_count,
                "severity": worst_sev,
                "first_seen": min(m.get("created_at", "") for m in members),
                "last_seen": max(m.get("created_at", "") for m in members),
                "cases": members,
            })

        campaigns.sort(key=lambda x: (x["true_positives"], x["case_count"]), reverse=True)
        return campaigns

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
