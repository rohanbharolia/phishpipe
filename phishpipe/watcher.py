"""Automated Intake Folder and Mailbox Watcher.

Continuously or on-demand polls an inbox directory for new email files (.eml, .msg, .txt),
automatically running the investigation pipeline and persisting cases.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from phishpipe import config
from phishpipe.casestore import CaseStore
from phishpipe.pipeline import InvestigationPipeline

DEFAULT_INBOX_DIR = config.ROOT_DIR / "data" / "inbox"


def ensure_inbox_structure(inbox_path: Path | None = None) -> tuple[Path, Path]:
    base = Path(inbox_path or DEFAULT_INBOX_DIR)
    archive = base / "archive"
    base.mkdir(parents=True, exist_ok=True)
    archive.mkdir(parents=True, exist_ok=True)
    return base, archive


def scan_inbox(
    inbox_path: Path | None = None,
    settings: config.Settings | None = None,
    store: CaseStore | None = None,
) -> list[dict[str, Any]]:
    """Scan inbox directory for pending email files and autonomously investigate them."""
    base, archive = ensure_inbox_structure(inbox_path)
    settings = settings or config.load_settings()
    store = store or CaseStore(settings=settings)
    pipeline = InvestigationPipeline(settings=settings, store=store, persist=True)

    results: list[dict[str, Any]] = []
    candidates = [
        p for p in base.iterdir()
        if p.is_file() and p.suffix.lower() in {".eml", ".msg", ".txt"}
    ]

    for p in sorted(candidates):
        try:
            case = pipeline.investigate_file(p)
            dest = archive / f"{case.id}_{p.name}"
            shutil.move(str(p), str(dest))
            results.append({
                "filename": p.name,
                "case_id": case.id,
                "status": "success",
                "classification": case.verdict.classification,
                "confidence": case.verdict.confidence,
                "archived_to": str(dest.name),
            })
        except Exception as exc:
            results.append({
                "filename": p.name,
                "status": "error",
                "error": str(exc),
            })

    return results
