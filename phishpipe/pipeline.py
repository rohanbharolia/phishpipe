"""Pipeline orchestrator - ties stages 1-6 together and records a timeline.

Every investigation produces a complete :class:`Case`: parsed message, extracted
indicators, enrichment results, scored signals, MITRE mapping, an incident
report and a ready-to-send user notification. The orchestrator times each stage
so the report can show where the seconds went.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from phishpipe import config
from phishpipe.analyze import build_verdict, evaluate_signals
from phishpipe.casestore import CaseStore
from phishpipe.detections import Detections, load_detections
from phishpipe.extract import (
    AttachmentObservation,
    ContentProfile,
    build_content_profile,
    build_received_chain,
    extract_indicators,
)
from phishpipe.models import (
    Case,
    EnrichmentBundle,
    LinkDetail,
    ParsedEmail,
    PipelineMetrics,
    TimelineEntry,
    utcnow,
)
from phishpipe.narrative import build_notification, generate_narrative
from phishpipe.report import build_report
from phishpipe.enrich import run_enrichment

STAGES = ("ingest", "extract", "enrich", "analyze", "reason", "report")


class _Timer:
    """Context manager that records a stage's duration and detail."""

    def __init__(self, stage: str, timeline: list[TimelineEntry]) -> None:
        self.stage = stage
        self.timeline = timeline
        self.started_at: datetime = datetime.now(timezone.utc)
        self.start = 0.0
        self.detail = ""

    def __enter__(self) -> "_Timer":
        self.start = time.perf_counter()
        self.started_at = datetime.now(timezone.utc)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        duration = int((time.perf_counter() - self.start) * 1000)
        self.timeline.append(
            TimelineEntry(
                stage=self.stage,
                started_at=self.started_at,
                duration_ms=duration,
                detail=self.detail,
            )
        )


def _case_id(email: ParsedEmail) -> str:
    """Stable, human-citable case ID: PHI-YYYYMMDD-<8 hex>."""
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    seed = f"{email.message_id}|{email.from_address}|{email.subject}|{email.raw_size_bytes}"
    digest = hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"PHI-{day}-{digest}"


def _case_title(email: ParsedEmail, classification: str) -> str:
    subject = (email.subject or "").strip() or "(no subject)"
    prefix = {
        "true_positive": "Phishing",
        "suspicious": "Suspicious email",
        "false_positive": "Reported email - benign",
    }[classification]
    return f"{prefix}: {subject[:80]}"


class InvestigationPipeline:
    """Runs the full ingest -> notify chain for a single message."""

    def __init__(
        self,
        settings: config.Settings | None = None,
        store: CaseStore | None = None,
        detections: Detections | None = None,
        persist: bool = True,
    ) -> None:
        self.settings = settings or config.load_settings()
        self.detections = detections or load_detections(self.settings.detections_file)
        self.persist = persist
        self.store = store if store is not None else (CaseStore(settings=self.settings) if persist else None)

    # -- public entry points ------------------------------------------------
    def investigate_bytes(self, raw: bytes | str, source: str = "upload", name: str = "") -> Case:
        from phishpipe.ingest import parse_raw_email

        with _Timer("ingest", (timeline := [])) as timer:
            email = parse_raw_email(raw, source=source, source_name=name)
            timer.detail = (
                f"parsed {email.raw_size_bytes} bytes, {len(email.attachments)} attachment(s), "
                f"{len(email.urls)} raw URL(s)"
            )
        return self._run(email, timeline)

    def investigate_email(self, email: ParsedEmail, timeline: list[TimelineEntry] | None = None) -> Case:
        return self._run(email, timeline or [])

    def investigate_file(self, path: str | Path) -> Case:
        from phishpipe.ingest import parse_email_file

        p = Path(path)
        with _Timer("ingest", (timeline := [])) as timer:
            email = parse_email_file(p)
            timer.detail = f"parsed {p.name} ({email.raw_size_bytes} bytes)"
        return self._run(email, timeline)

    def investigate_upload(self, filename: str, content: bytes) -> Case:
        from phishpipe.ingest import parse_email_upload

        with _Timer("ingest", (timeline := [])) as timer:
            email = parse_email_upload(filename, content)
            timer.detail = (
                f"uploaded {filename or 'pasted text'}: {len(email.attachments)} attachment(s), "
                f"{len(email.urls)} raw URL(s)"
            )
        return self._run(email, timeline)

    # -- internals ----------------------------------------------------------
    def _run(self, email: ParsedEmail, timeline: list[TimelineEntry]) -> Case:
        started = time.perf_counter()

        # --- Stage 2: extraction ------------------------------------------
        with _Timer("extract", timeline) as timer:
            profile = build_content_profile(email, self.detections)
            indicators = extract_indicators(email, profile, self.detections)
            chain = build_received_chain(email.received_hops)
            timer.detail = (
                f"{len(indicators)} indicator(s), {len(profile.links)} link(s), "
                f"{len(chain.hops)} Received hop(s)"
            )

        # --- Stage 3: enrichment -------------------------------------------
        with _Timer("enrich", timeline) as timer:
            enrichment = run_enrichment(indicators, self.settings)
            timer.detail = (
                f"providers {', '.join(enrichment.providers_used) or 'none'}; "
                f"{enrichment.indicators_checked} indicator(s) checked in {enrichment.duration_ms} ms"
            )

        # --- Stage 4: analysis ---------------------------------------------
        with _Timer("analyze", timeline) as timer:
            signals = evaluate_signals(email, profile, indicators, enrichment, self.detections)
            verdict = build_verdict(signals, profile, enrichment, self.detections)
            timer.detail = (
                f"{verdict.signals_matched}/{verdict.signals_total} signals matched -> "
                f"{verdict.classification} @ {verdict.confidence}/100"
            )

        attachment_flags = [
            {
                "dangerous_ext": a.dangerous_ext,
                "double_extension": a.double_extension,
                "macro_ext": a.macro_ext,
                "content_type_mismatch": a.content_type_mismatch,
            }
            for a in profile.attachments
        ]

        link_details = [
            LinkDetail(
                url=obs.url,
                host=obs.host,
                is_ip_host=obs.is_ip_host,
                is_shortener=obs.is_shortener,
                is_suspicious_tld=obs.is_suspicious_tld,
                is_punycode=obs.is_punycode,
                has_credential_token=obs.has_credential_token,
                anchor_text=obs.anchor_text,
                mismatched=obs.mismatched,
                typosquatting=obs.typosquatting,
            )
            for obs in profile.links
        ]

        case_id = _case_id(email)
        case = Case(
            id=case_id,
            title=_case_title(email, verdict.classification),
            email=email,
            indicators=indicators,
            signals=signals,
            enrichment=enrichment,
            verdict=verdict,
            timeline=timeline,
            attachment_flags=attachment_flags,
            detected_brands=list(profile.brands_mentioned),
            links=link_details,
            received_chain=chain,
            typosquatting=profile.typosquatting_hits,
            quishing=profile.quishing_hit,
        )

        # --- Stage 5: reasoning + narrative --------------------------------
        with _Timer("reason", timeline) as timer:
            narrative, notification_body = generate_narrative(case, self.settings)
            case.narrative = narrative
            case.notification = build_notification(case, notification_body)
            timer.detail = f"narrative via {self._narrative_mode()}"

        # --- Stage 6: report ------------------------------------------------
        with _Timer("report", timeline) as timer:
            case.report_markdown = build_report(case, self.detections.version)
            timer.detail = f"report {len(case.report_markdown)} chars"

        total_ms = int((time.perf_counter() - started) * 1000)
        case.timeline = timeline
        case.metrics = PipelineMetrics(
            total_ms=total_ms,
            baseline_minutes=config.MANUAL_INVESTIGATION_MINUTES,
            estimated_minutes=round(total_ms / 60000, 3),
            minutes_saved=round(
                max(0.0, config.MANUAL_INVESTIGATION_MINUTES - total_ms / 60000), 2
            ),
            enrichment_calls=len(enrichment.results),
            offline=all(r.offline for r in enrichment.results) if enrichment.results else True,
        )
        case.status = "escalated" if verdict.needs_human_review else "new"

        if self.persist and self.store is not None:
            # Re-serialise the report now that metrics/timeline are final.
            case.report_markdown = build_report(case, self.detections.version)
            self.store.save(case)

        return case

    def _narrative_mode(self) -> str:
        from phishpipe.narrative import llm_status

        return llm_status()["mode"]


# ---------------------------------------------------------------------------
# Convenience API used by the CLI, tests and ``python -m phishpipe``
# ---------------------------------------------------------------------------
def run_investigation(
    source: str | Path | bytes | None = None,
    *,
    raw: bytes | str | None = None,
    settings: config.Settings | None = None,
    persist: bool = True,
) -> Case:
    """Investigate a file path, raw bytes, or raw text.

    Examples::

        run_investigation("samples/phish_m365_credential_harvest.eml")
        run_investigation(raw=b"From: a@b.c\\r\\nSubject: hi\\r\\n\\r\\nbody")
    """
    pipeline = InvestigationPipeline(settings=settings, persist=persist)

    if raw is not None:
        return pipeline.investigate_bytes(raw)
    if source is None:
        raise ValueError("provide a file path via 'source' or raw message bytes via 'raw'")
    if isinstance(source, (bytes, bytearray)):
        return pipeline.investigate_bytes(bytes(source))
    return pipeline.investigate_file(Path(source))


def new_case_id() -> str:
    """Random case ID for callers that need one before parsing (e.g. the API)."""
    return f"PHI-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
