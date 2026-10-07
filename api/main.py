"""FastAPI application - HTTP surface for the phishing investigation pipeline.

Run it::

    uvicorn api.main:app --reload
    # then open http://127.0.0.1:8000

The API is a thin shell: all investigation logic lives in
:mod:`phishpipe.pipeline`, so the same code path serves the web UI, the CLI and
the tests.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure repo root is always in sys.path regardless of launch directory
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from phishpipe import __version__, config
from phishpipe.casestore import CaseStore
from phishpipe.detections import load_detections
from phishpipe.narrative import llm_status
from phishpipe.pipeline import InvestigationPipeline
from phishpipe.report import build_report

app = FastAPI(
    title="PhishPipe",
    description="Automated phishing investigation pipeline: ingest, extract, enrich, score, case, report, notify.",
    version=__version__,
)

settings = config.load_settings()
store = CaseStore(settings=settings)
detections = load_detections(settings.detections_file)


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["meta"])
@app.get("/health", include_in_schema=False)
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/status", tags=["meta"])
def status() -> dict:
    """Everything the UI needs to explain how the pipeline is currently configured."""
    from phishpipe.enrich import build_providers

    providers, skipped = build_providers(settings)
    return {
        "version": __version__,
        "offline_mode": config.is_offline_mode(),
        "providers": [
            {"name": p.name, "kind": p.kind, "available": p.is_available()[0]} for p in providers
        ],
        "providers_skipped": skipped,
        "llm": llm_status(),
        "detections": {
            "version": detections.version,
            "updated": detections.updated,
            "description": detections.description,
            "signal_count": len(detections.signals),
            "thresholds": {
                "true_positive": detections.thresholds.true_positive,
                "suspicious": detections.thresholds.suspicious,
            },
        },
        "limits": {
            "max_email_bytes": config.MAX_EMAIL_BYTES,
            "max_attachments": config.MAX_ATTACHMENTS,
        },
        "cases": store.count(),
    }


@app.get("/api/detections", tags=["meta"])
def get_detections() -> dict:
    """The active detection logic, so the UI can explain every signal."""
    return {
        "version": detections.version,
        "updated": detections.updated,
        "description": detections.description,
        "thresholds": detections.thresholds.__dict__,
        "signals": [
            {
                "id": s.id,
                "title": s.title,
                "description": s.description,
                "weight": s.weight,
                "severity": s.severity,
                "category": s.category,
                "techniques": list(s.techniques),
            }
            for s in detections.ordered_signals
        ],
        "mitre": detections.mitre,
    }


# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------
@app.post("/api/investigate/upload", tags=["investigate"])
async def investigate_upload(file: UploadFile = File(...)) -> dict:
    """Ingest an uploaded ``.eml`` / ``.msg`` / ``.txt`` file and investigate it."""
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="empty file")
    if len(content) > config.MAX_EMAIL_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file exceeds {config.MAX_EMAIL_BYTES} bytes",
        )
    try:
        case = InvestigationPipeline(settings=settings, store=store).investigate_upload(
            file.filename or "", content
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - surface parse failures cleanly
        raise HTTPException(status_code=422, detail=f"could not parse message: {exc}") from exc
    return case.to_public_dict()


@app.post("/api/investigate/raw", tags=["investigate"])
def investigate_raw(body: dict) -> dict:
    """Investigate raw RFC 5322 text pasted into the UI."""
    raw = (body or {}).get("raw_email", "")
    if not isinstance(raw, str) or not raw.strip():
        raise HTTPException(status_code=400, detail="raw_email is required")
    if len(raw.encode("utf-8", errors="replace")) > config.MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="message too large")
    case = InvestigationPipeline(settings=settings, store=store).investigate_bytes(
        raw, source="paste", name="pasted-message"
    )
    return case.to_public_dict()


@app.get("/api/samples", tags=["investigate"])
def list_samples() -> list[dict]:
    """Bundled sample messages for demos and regression tests."""
    if not config.SAMPLES_DIR.exists():
        return []
    return [
        {
            "name": p.name,
            "size": p.stat().st_size,
            "path": str(p.relative_to(config.ROOT_DIR)),
        }
        for p in sorted(config.SAMPLES_DIR.iterdir())
        if p.suffix.lower() in {".eml", ".txt", ".msg"}
    ]


@app.post("/api/investigate/sample/{name}", tags=["investigate"])
def investigate_sample(name: str) -> dict:
    path = (config.SAMPLES_DIR / name).resolve()
    if not str(path).startswith(str(config.SAMPLES_DIR.resolve())) or not path.exists():
        raise HTTPException(status_code=404, detail="sample not found")
    case = InvestigationPipeline(settings=settings, store=store).investigate_file(path)
    return case.to_public_dict()


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------
@app.get("/api/cases", tags=["cases"])
def list_cases(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    classification: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    search: str | None = None,
) -> dict:
    items = store.list(
        limit=limit,
        offset=offset,
        classification=classification,
        severity=severity,
        status=status,
        search=search,
    )
    # `total` must honour the active filters or paging counts become misleading.
    total = store.count(
        classification=classification, severity=severity, status=status, search=search
    )
    return {"total": total, "items": items}


@app.get("/api/cases/{case_id}", tags=["cases"])
def get_case(case_id: str) -> dict:
    case = store.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    return case.to_public_dict()


@app.get("/api/cases/{case_id}/report", tags=["cases"])
def get_report(case_id: str, format: str = Query("markdown", pattern="^(markdown|json)$")):
    case = store.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    if format == "json":
        return JSONResponse(
            {
                "id": case.id,
                "title": case.title,
                "report_markdown": case.report_markdown,
                "notification": case.notification.model_dump(),
            }
        )
    return PlainTextResponse(
        case.report_markdown or build_report(case, detections.version),
        media_type="text/markdown",
    )


@app.patch("/api/cases/{case_id}/status", tags=["cases"])
def update_case_status(case_id: str, body: dict) -> dict:
    status_value = (body or {}).get("status", "")
    if status_value not in {"new", "triaged", "escalated", "closed"}:
        raise HTTPException(status_code=400, detail="invalid status")
    if not store.update_status(case_id, status_value):
        raise HTTPException(status_code=404, detail="case not found")
    return {"id": case_id, "status": status_value}


@app.delete("/api/cases/{case_id}", tags=["cases"])
def delete_case(case_id: str) -> dict:
    if not store.delete(case_id):
        raise HTTPException(status_code=404, detail="case not found")
    return {"deleted": case_id}


@app.get("/api/metrics", tags=["cases"])
def metrics() -> dict:
    return store.stats()


@app.post("/api/reset", tags=["cases"])
def reset() -> dict:
    """Clear all stored cases (demo reset)."""
    deleted = store.clear()
    return {"deleted": deleted}


# ---------------------------------------------------------------------------
# Threat Intel & Detection Rule Export (STIX 2.1 & Sigma)
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/stix", tags=["export"])
def get_case_stix(case_id: str) -> dict:
    case = store.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    from phishpipe.stix import export_stix_bundle
    return export_stix_bundle(case)


@app.get("/api/cases/{case_id}/sigma", tags=["export"])
def get_case_sigma(case_id: str):
    case = store.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    from phishpipe.sigma import generate_sigma_rule
    yaml_text = generate_sigma_rule(case)
    return PlainTextResponse(yaml_text, media_type="application/x-yaml")


# ---------------------------------------------------------------------------
# SOC Workflow: Notes & Tagging & Remediation Playbooks
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/notes", tags=["workflow"])
def list_case_notes(case_id: str) -> list[dict]:
    if store.get(case_id) is None:
        raise HTTPException(status_code=404, detail="case not found")
    return store.list_notes(case_id)


@app.post("/api/cases/{case_id}/notes", tags=["workflow"])
def add_case_note(case_id: str, body: dict) -> dict:
    if store.get(case_id) is None:
        raise HTTPException(status_code=404, detail="case not found")
    text = (body or {}).get("text", "").strip()
    author = (body or {}).get("author", "analyst").strip() or "analyst"
    if not text:
        raise HTTPException(status_code=400, detail="note text is required")
    return store.add_note(case_id=case_id, text=text, author=author)


@app.delete("/api/cases/{case_id}/notes/{note_id}", tags=["workflow"])
def delete_case_note(case_id: str, note_id: str) -> dict:
    if store.get(case_id) is None:
        raise HTTPException(status_code=404, detail="case not found")
    if not store.delete_note(case_id, note_id):
        raise HTTPException(status_code=404, detail="note not found")
    return {"deleted": note_id}


@app.get("/api/cases/{case_id}/tags", tags=["workflow"])
def get_case_tags(case_id: str) -> list[str]:
    if store.get(case_id) is None:
        raise HTTPException(status_code=404, detail="case not found")
    return store.get_tags(case_id)


@app.post("/api/cases/{case_id}/tags", tags=["workflow"])
def add_case_tag(case_id: str, body: dict) -> list[str]:
    if store.get(case_id) is None:
        raise HTTPException(status_code=404, detail="case not found")
    tag = (body or {}).get("tag", "").strip()
    if not tag:
        raise HTTPException(status_code=400, detail="tag cannot be empty")
    return store.add_tag(case_id, tag)


@app.delete("/api/cases/{case_id}/tags/{tag}", tags=["workflow"])
def remove_case_tag(case_id: str, tag: str) -> list[str]:
    if store.get(case_id) is None:
        raise HTTPException(status_code=404, detail="case not found")
    return store.remove_tag(case_id, tag)


@app.patch("/api/cases/{case_id}/tags", tags=["workflow"])
def set_case_tags(case_id: str, body: dict) -> list[str]:
    if store.get(case_id) is None:
        raise HTTPException(status_code=404, detail="case not found")
    tags = (body or {}).get("tags", [])
    return store.set_tags(case_id, tags)


@app.post("/api/cases/{case_id}/actions/{action_name}", tags=["workflow"])
def execute_playbook_action(case_id: str, action_name: str, body: dict | None = None) -> dict:
    case = store.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")

    body = body or {}
    action_clean = action_name.lower().strip()
    detail = body.get("detail", "")

    if action_clean == "quarantine":
        detail = detail or "Message moved to secure quarantine mailbox; user access revoked."
        res = store.record_action(case_id, "quarantined", detail=detail)
        store.update_status(case_id, "triaged")
        return {"action": "quarantine", "status": "executed", "result": res}

    elif action_clean == "block_domain":
        domain = case.email.from_address.split("@")[-1] if "@" in case.email.from_address else "sender-domain"
        detail = detail or f"Domain '{domain}' added to edge firewall & DNS sinkhole policy."
        res = store.record_action(case_id, f"blocked_domain:{domain}", detail=detail)
        return {"action": "block_domain", "target": domain, "status": "executed", "result": res}

    elif action_clean == "reset_credentials":
        recip = case.email.to[0] if case.email.to else "recipient"
        detail = detail or f"Active SSO session terminated and force-reset flagged for '{recip}'."
        res = store.record_action(case_id, f"reset_credentials:{recip}", detail=detail)
        return {"action": "reset_credentials", "target": recip, "status": "executed", "result": res}

    elif action_clean in {"webhook_alert", "notify_webhook"}:
        from phishpipe.webhook import dispatch_webhook
        webhook_url = body.get("webhook_url")
        webhook_result = dispatch_webhook(case, webhook_url=webhook_url)
        detail = detail or f"Webhook notification dispatched ({webhook_result.get('status')})"
        res = store.record_action(case_id, "webhook_dispatched", detail=f"{detail} - {webhook_result.get('response', '')}")
        return {"action": "notify_webhook", "status": "executed", "webhook_result": webhook_result, "result": res}

    else:
        raise HTTPException(status_code=400, detail=f"unknown action: {action_name}")


@app.get("/api/cases/{case_id}/actions", tags=["workflow"])
def list_case_actions(case_id: str) -> list[dict]:
    if store.get(case_id) is None:
        raise HTTPException(status_code=404, detail="case not found")
    return store.list_actions(case_id)


# ---------------------------------------------------------------------------
# Positive Click Confirmation Telemetry
# ---------------------------------------------------------------------------
@app.post("/api/cases/{case_id}/click-event", tags=["telemetry"])
def record_case_click_event(case_id: str, body: dict | None = None) -> dict:
    """Register or simulate a verified positive user click from proxy, EDR, or gateway telemetry.

    This immediately escalates the incident to Critical compromise, injects
    the explainable SIGNAL_CONFIRMED_USER_CLICK detection rule, and updates
    containment playbooks.
    """
    case = store.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")

    body = body or {}
    url = body.get("url") or (case.email.urls[0] if case.email.urls else "https://unknown-lure.xyz")
    user_email = body.get("user_email") or (case.email.to[0] if case.email.to else "recipient@company.com")
    client_ip = body.get("client_ip") or "10.0.1.45"
    user_agent = body.get("user_agent") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0"
    source = body.get("source", "web_proxy")
    outcome = body.get("outcome", "allowed")
    credentials_submitted = bool(body.get("credentials_submitted", False))
    details = body.get("details") or f"Gateway telemetry confirms {user_email} navigated to {url}"

    from phishpipe.models import ClickEvent

    evt = ClickEvent(
        url=url,
        user_email=user_email,
        client_ip=client_ip,
        user_agent=user_agent,
        source=source,
        outcome=outcome,
        credentials_submitted=credentials_submitted,
        details=details,
    )
    updated_case = store.record_click(case_id, evt)
    if updated_case is None:
        raise HTTPException(status_code=500, detail="failed to update case click telemetry")

    return {
        "status": "click_recorded",
        "case_id": case_id,
        "escalated_severity": updated_case.verdict.severity,
        "click_count": updated_case.click_telemetry.click_count,
        "credentials_compromised": updated_case.click_telemetry.credentials_compromised,
        "event": evt.model_dump(mode="json"),
    }


@app.get("/api/cases/{case_id}/click-events", tags=["telemetry"])
def get_case_click_events(case_id: str) -> list[dict]:
    case = store.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    events = store.list_clicks(case_id)
    return [e.model_dump(mode="json") if hasattr(e, "model_dump") else e for e in events]


# ---------------------------------------------------------------------------
# Threat Campaigns Clustering
# ---------------------------------------------------------------------------
@app.get("/api/campaigns", tags=["campaigns"])
def list_campaigns() -> dict:
    """Cluster all stored cases into active threat campaigns."""
    campaigns = store.get_campaigns()
    return {"total": len(campaigns), "campaigns": campaigns}


# ---------------------------------------------------------------------------
# Ingestion & Watcher
# ---------------------------------------------------------------------------
@app.post("/api/watch/scan", tags=["ingestion"])
def trigger_inbox_scan(body: dict | None = None) -> dict:
    """Trigger on-demand directory watcher scan of the inbox folder."""
    from phishpipe.watcher import scan_inbox
    inbox_path = (body or {}).get("inbox_path")
    results = scan_inbox(inbox_path=inbox_path, settings=settings, store=store)
    return {"processed": len(results), "results": results}


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    index_file = config.WEB_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="web UI not built")
    response = FileResponse(index_file)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


if config.WEB_DIR.exists():
    class VersionedStaticFiles(StaticFiles):
        """Serve the frontend without letting a browser pin stale assets.

        Static assets are revalidated on every load (`no-cache`), which is what
        you want while tuning the UI: an edit is visible on the next refresh
        instead of surviving in the HTTP cache.
        """

        def file_response(self, full_path, stat_result, scope, status_code=200):
            response = super().file_response(full_path, stat_result, scope, status_code)
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            return response

    app.mount("/static", VersionedStaticFiles(directory=str(config.WEB_DIR)), name="static")


@app.get("/api/openapi.json", include_in_schema=False)
def openapi_json() -> JSONResponse:
    return JSONResponse(json.loads(app.openapi_json()))

if __name__ == "__main__":
    import uvicorn
    print("Launching PhishPipe SOC Console on http://127.0.0.1:8000 ...")
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)
