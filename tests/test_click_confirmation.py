"""Tests for Positive Click Confirmation Telemetry and Action Safeguards."""
from __future__ import annotations

import uuid
import pytest
from fastapi.testclient import TestClient

from api.main import app
from phishpipe.models import Case, ClickEvent, ClickTelemetry, ParsedEmail, Verdict
from phishpipe.report import build_report


@pytest.fixture
def store(tmp_path, monkeypatch):
    from api import main as api_main
    from phishpipe.casestore import CaseStore
    from phishpipe.config import load_settings

    settings = load_settings()
    settings.cases_db_file = tmp_path / "cases.db"
    isolated_store = CaseStore(settings=settings)
    monkeypatch.setattr(api_main, "settings", settings)
    monkeypatch.setattr(api_main, "store", isolated_store)
    return isolated_store


@pytest.fixture
def client(store):
    return TestClient(app)


@pytest.fixture
def sample_case(store):
    cid = f"PHI-CLK-{uuid.uuid4().hex[:6].upper()}"
    case = Case(
        id=cid,
        email=ParsedEmail(
            message_id="<testclk@attacker.xyz>",
            from_address="security@paypal-verify.com",
            to=["target.employee@acme-corp.com"],
            subject="Urgent Security Alert: Verify Your Account Immediately",
            body_plain="Please click here to verify: https://evil-login-portal.com/auth?token=123",
            urls=["https://evil-login-portal.com/auth?token=123"],
        ),
        verdict=Verdict(
            classification="suspicious",
            severity="medium",
            confidence=65,
            explanation="Initial heuristic detection flagged suspicious domain and urgency lure.",
            reasoning=["Sender domain does not match claimed brand."],
            recommended_actions=["Quarantine email across all tenant mailboxes."],
        ),
    )
    store.save(case)
    return case


def test_click_event_model():
    evt = ClickEvent(
        url="https://evil-phish.net/login",
        user_email="victim@company.com",
        client_ip="192.168.1.50",
        outcome="allowed",
        credentials_submitted=True,
    )
    assert evt.url == "https://evil-phish.net/login"
    assert evt.user_email == "victim@company.com"
    assert evt.client_ip == "192.168.1.50"
    assert evt.credentials_submitted is True
    assert evt.outcome == "allowed"
    assert evt.timestamp is not None

    telemetry = ClickTelemetry(
        has_positive_click=True,
        click_count=1,
        credentials_compromised=True,
        events=[evt],
    )
    assert telemetry.has_positive_click is True
    assert telemetry.click_count == 1
    assert telemetry.credentials_compromised is True


def test_casestore_record_click(store, sample_case):
    cid = sample_case.id

    # Verify initial state
    initial = store.get(cid)
    assert initial is not None
    assert initial.verdict.severity == "medium"
    assert initial.click_telemetry.has_positive_click is False
    assert initial.click_telemetry.click_count == 0

    # Record first click (link traversed, no credentials)
    evt1 = ClickEvent(
        url="https://evil-login-portal.com/auth?token=123",
        user_email="target.employee@acme-corp.com",
        client_ip="10.0.1.55",
        outcome="allowed",
        credentials_submitted=False,
    )
    updated = store.record_click(cid, evt1)
    assert updated is not None
    assert updated.click_telemetry.has_positive_click is True
    assert updated.click_telemetry.click_count == 1
    assert updated.verdict.severity == "critical"
    assert "positive-click" in updated.tags
    assert any(s.id == "SIGNAL_CONFIRMED_USER_CLICK" for s in updated.signals)
    assert any("Force immediate" in a for a in updated.verdict.recommended_actions)
    assert any(m.id == "T1204.001" for m in updated.verdict.mitre)

    # Verify list_clicks
    clicks = store.list_clicks(cid)
    assert len(clicks) == 1
    assert clicks[0].url == "https://evil-login-portal.com/auth?token=123"
    assert clicks[0].client_ip == "10.0.1.55"

    # Record second click with credentials submitted
    evt2 = ClickEvent(
        url="https://evil-login-portal.com/submit",
        user_email="target.employee@acme-corp.com",
        client_ip="10.0.1.55",
        outcome="allowed",
        credentials_submitted=True,
    )
    updated2 = store.record_click(cid, evt2)
    assert updated2 is not None
    assert updated2.click_telemetry.click_count == 2
    assert updated2.click_telemetry.credentials_compromised is True
    assert "credentials-compromised" in updated2.tags
    assert any("EDR CONTAINMENT" in a for a in updated2.verdict.recommended_actions)

    clicks2 = store.list_clicks(cid)
    assert len(clicks2) == 2


def test_api_click_endpoints(client, sample_case):
    cid = sample_case.id

    # 1. Post click event
    payload = {
        "url": "https://evil-login-portal.com/auth?token=123",
        "user_email": "target.employee@acme-corp.com",
        "client_ip": "172.16.0.4",
        "outcome": "warned",
        "credentials_submitted": True,
        "details": "User acknowledged gateway warning and proceeded to enter credentials",
    }
    resp = client.post(f"/api/cases/{cid}/click-event", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "click_recorded"
    assert data["case_id"] == cid
    assert data["escalated_severity"] == "critical"
    assert data["credentials_compromised"] is True
    assert data["click_count"] >= 1

    # 2. Get click events
    resp_list = client.get(f"/api/cases/{cid}/click-events")
    assert resp_list.status_code == 200
    events = resp_list.json()
    assert len(events) >= 1
    last_evt = events[-1]
    assert last_evt["url"] == "https://evil-login-portal.com/auth?token=123"
    assert last_evt["credentials_submitted"] is True
    assert last_evt["outcome"] == "warned"

    # 3. 404 for non-existent case
    resp_404 = client.post("/api/cases/NON-EXISTENT/click-event", json=payload)
    assert resp_404.status_code == 404


def test_report_click_telemetry_audit(store, sample_case):
    cid = sample_case.id
    evt = ClickEvent(
        url="https://evil-login-portal.com/auth?token=123",
        user_email="target.employee@acme-corp.com",
        client_ip="10.0.1.55",
        outcome="allowed",
        credentials_submitted=True,
    )
    store.record_click(cid, evt)
    updated = store.get(cid)
    assert updated is not None

    md = build_report(updated)
    assert "> [!CAUTION]" in md
    assert "POSITIVE USER CLICK CONFIRMED" in md
    assert "ACTIVE CREDENTIAL COMPROMISE CONFIRMED" in md
    assert "### Positive Click Telemetry Audit" in md
    assert "target.employee@acme-corp.com" in md
    assert "10.0.1.55" in md


def test_click_telemetry_captures_iocs(store, sample_case):
    cid = sample_case.id
    # sample_case should have auto-extracted indicators from its email
    assert len(sample_case.indicators) > 0
    types = {i.type for i in sample_case.indicators}
    assert "url" in types
    assert "domain" in types
    assert "email" in types

    # Record a click event with a client IP
    evt = ClickEvent(
        url="https://evil-phish-click.org/login",
        user_email="victim@corp.com",
        client_ip="192.168.1.105",
        outcome="allowed",
    )
    updated = store.record_click(cid, evt)
    assert updated is not None
    updated_vals = {i.value for i in updated.indicators}
    assert "https://evil-phish-click.org/login" in updated_vals
    assert "192.168.1.105" in updated_vals
    assert "evil-phish-click.org" in updated_vals
