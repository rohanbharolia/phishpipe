"""Tests for advanced forensics, STIX, Sigma, and webhook integrations."""

from __future__ import annotations

import pytest
from phishpipe.homoglyph import normalize_domain_homoglyphs, check_domain_typosquatting, detect_quishing
from phishpipe.stix import export_stix_bundle
from phishpipe.sigma import generate_sigma_rule
from phishpipe.webhook import dispatch_webhook, _build_slack_payload, _build_generic_payload
from phishpipe.watcher import scan_inbox, ensure_inbox_structure
from phishpipe.pipeline import InvestigationPipeline
from phishpipe.casestore import CaseStore
from phishpipe.config import load_settings
from tests.conftest import M365_PHISH


def test_homoglyph_and_typosquatting():
    # Leet normalization
    norm = normalize_domain_homoglyphs("micr0s0ft")
    assert norm == "microsoft"

    # Typosquatting detection on homoglyph
    res = check_domain_typosquatting("micros0ft.com")
    assert res is not None
    assert res["brand"] == "microsoft"
    assert res["type"] == "homoglyph_substitution"

    # Typosquatting distance 1
    res_typo = check_domain_typosquatting("paypa1.com")
    assert res_typo is not None
    assert res_typo["brand"] == "paypal"

    # Clean domain
    clean_res = check_domain_typosquatting("microsoft.com")
    assert clean_res is None


def test_quishing_detection():
    # Quishing lure prompt
    q_res = detect_quishing(
        subject="Important MFA Update",
        body_text="Please scan the QR code below on your mobile device to complete authentication.",
        html="",
        attachments=[],
    )
    assert q_res is not None
    assert q_res["quishing_detected"] is True
    assert "scan the qr code" in q_res["evidence"]

    # Clean message
    clean_q = detect_quishing(
        subject="Weekly status",
        body_text="Here is the quarterly meeting agenda.",
        html="",
        attachments=[],
    )
    assert clean_q is None


def test_stix_and_sigma_generation(tmp_path):
    settings = load_settings()
    store = CaseStore(settings=settings)
    pipeline = InvestigationPipeline(settings=settings, store=store, persist=False)
    case = pipeline.investigate_file(M365_PHISH)

    # STIX
    bundle = export_stix_bundle(case)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    objs = bundle["objects"]
    assert any(o["type"] == "identity" for o in objs)
    assert any(o["type"] == "indicator" for o in objs)
    assert any(o["type"] == "report" for o in objs)

    # Sigma
    sigma_yaml = generate_sigma_rule(case)
    assert "title:" in sigma_yaml
    assert "logsource:" in sigma_yaml
    assert "detection:" in sigma_yaml
    assert "level:" in sigma_yaml


def test_webhook_payload_builders(tmp_path):
    settings = load_settings()
    store = CaseStore(settings=settings)
    pipeline = InvestigationPipeline(settings=settings, store=store, persist=False)
    case = pipeline.investigate_file(M365_PHISH)

    # Slack payload
    slack = _build_slack_payload(case)
    assert "attachments" in slack
    assert len(slack["attachments"]) > 0

    # Generic payload
    generic = _build_generic_payload(case)
    assert generic["event"] == "phishing_investigation_completed"
    assert generic["case_id"] == case.id
    assert generic["classification"] == case.verdict.classification

    # Dispatch with no URL configured -> skipped
    res = dispatch_webhook(case, webhook_url=None)
    assert res["status"] == "skipped"


def test_watcher_directory(tmp_path):
    inbox, archive = ensure_inbox_structure(tmp_path / "inbox")
    assert inbox.exists()
    assert archive.exists()

    # Drop a sample email
    sample_file = inbox / "phish.eml"
    sample_file.write_bytes(M365_PHISH.read_bytes())

    settings = load_settings()
    settings.cases_db_file = tmp_path / "cases.db"
    store = CaseStore(settings=settings)

    results = scan_inbox(inbox_path=inbox, settings=settings, store=store)
    assert len(results) == 1
    assert results[0]["status"] == "success"
    # Ensure moved to archive
    assert not sample_file.exists()
    archived_files = list(archive.iterdir())
    assert len(archived_files) == 1


def test_pipeline_typosquatting_and_quishing_integration(tmp_path):
    raw_email = (
        b"From: IT Admin <support@micros0ft.com>\r\n"
        b"To: target@company.com\r\n"
        b"Subject: Emergency: Scan the QR code for MFA authentication\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please scan the QR code to verify your account or proceed to https://paypa1.com/login\r\n"
    )
    settings = load_settings()
    settings.cases_db_file = tmp_path / "cases.db"
    store = CaseStore(settings=settings)
    pipeline = InvestigationPipeline(settings=settings, store=store, persist=True)
    case = pipeline.investigate_bytes(raw_email)

    # 1. Typosquatting
    assert len(case.typosquatting) >= 1
    brands = {t["brand"] for t in case.typosquatting}
    assert "microsoft" in brands or "paypal" in brands

    # 2. Quishing
    assert case.quishing is not None
    assert case.quishing["quishing_detected"] is True

    # 3. LinkDetail
    assert len(case.links) >= 1
    assert any(l.typosquatting is not None for l in case.links)

    # 4. Report verification
    assert "QUISHING" in case.report_markdown
    assert "Brand Lookalike & Typosquatting Analysis" in case.report_markdown
