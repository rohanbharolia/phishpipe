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
from pathlib import Path

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
# Static frontend
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    index_file = config.WEB_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="web UI not built")
    return FileResponse(index_file)


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
