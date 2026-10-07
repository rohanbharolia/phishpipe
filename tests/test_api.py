"""HTTP surface: endpoints, error handling, and static frontend."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api import main as api_main
from tests.conftest import LEGIT_MAIL, M365_PHISH


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """API client backed by an isolated SQLite DB, never the real one."""
    from phishpipe.casestore import CaseStore
    from phishpipe.config import load_settings

    settings = load_settings()
    settings.cases_db_file = tmp_path / "cases.db"
    monkeypatch.setattr(api_main, "settings", settings)
    monkeypatch.setattr(api_main, "store", CaseStore(settings=settings))
    # Providers must not change mid-suite even if the host has API keys set.
    monkeypatch.setenv("PHISHPIPE_OFFLINE", "1")
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    return TestClient(api_main.app)


# --- meta ------------------------------------------------------------------
def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok", "version": "1.0.0"}
    assert client.get("/health").status_code == 200


def test_status_exposes_pipeline_configuration(client):
    data = client.get("/api/status").json()
    assert data["offline_mode"] is True
    assert data["detections"]["version"] == "1.0.0"
    assert data["detections"]["signal_count"] > 30
    assert data["llm"]["enabled"] is False
    assert "virustotal" in data["providers_skipped"]


def test_detections_endpoint(client):
    data = client.get("/api/detections").json()
    assert data["thresholds"]["true_positive"] == 70
    ids = [s["id"] for s in data["signals"]]
    assert "auth.spf_fail" in ids
    assert len(ids) == len(set(ids))
    assert "T1566" in data["mitre"]


def test_samples_endpoint(client):
    samples = client.get("/api/samples").json()
    names = {s["name"] for s in samples}
    assert "phish_m365_credential_harvest.eml" in names
    assert "legit_it_maintenance_notice.eml" in names


# --- investigation ---------------------------------------------------------
def test_investigate_sample(client):
    resp = client.post("/api/investigate/sample/phish_m365_credential_harvest.eml")
    assert resp.status_code == 200
    case = resp.json()
    assert case["verdict"]["classification"] == "true_positive"
    assert case["verdict"]["confidence"] >= 70
    assert case["indicators"]
    assert case["report_markdown"].startswith("# Incident Report")
    assert case["detected_brands"] == ["microsoft"]


def test_investigate_unknown_sample_404(client):
    assert client.post("/api/investigate/sample/does-not-exist.eml").status_code == 404


def test_investigate_sample_path_traversal_is_blocked(client):
    resp = client.post("/api/investigate/sample/..%2F..%2Fsecrets.txt")
    assert resp.status_code in {404, 422}


def test_investigate_upload_eml(client):
    content = M365_PHISH.read_bytes()
    resp = client.post(
        "/api/investigate/upload",
        files={"file": ("phish.eml", content, "message/rfc822")},
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"]["classification"] == "true_positive"


def test_investigate_upload_legit(client):
    resp = client.post(
        "/api/investigate/upload",
        files={"file": ("legit.eml", LEGIT_MAIL.read_bytes(), "message/rfc822")},
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"]["classification"] == "false_positive"


def test_investigate_upload_empty_file(client):
    resp = client.post("/api/investigate/upload", files={"file": ("x.eml", b"", "text/plain")})
    assert resp.status_code == 400


def test_investigate_upload_too_large(client, monkeypatch):
    from phishpipe.config import MAX_EMAIL_BYTES

    monkeypatch.setattr(api_main.config, "MAX_EMAIL_BYTES", 16)
    resp = client.post(
        "/api/investigate/upload",
        files={"file": ("big.eml", b"x" * 64, "text/plain")},
    )
    assert resp.status_code == 413


def test_investigate_raw(client):
    resp = client.post("/api/investigate/raw", json={"raw_email": LEGIT_MAIL.read_text(encoding="utf-8")})
    assert resp.status_code == 200
    assert resp.json()["verdict"]["classification"] == "false_positive"


def test_investigate_raw_requires_body(client):
    assert client.post("/api/investigate/raw", json={}).status_code == 400
    assert client.post("/api/investigate/raw", json={"raw_email": "   "}).status_code == 400


# --- cases -----------------------------------------------------------------
def _create(client, name="phish_m365_credential_harvest.eml") -> dict:
    resp = client.post(f"/api/investigate/sample/{name}")
    assert resp.status_code == 200
    return resp.json()


def test_case_lifecycle(client):
    case = _create(client)
    cid = case["id"]

    listing = client.get("/api/cases").json()
    assert listing["total"] == 1
    assert listing["items"][0]["id"] == cid
    assert "payload" not in listing["items"][0]

    fetched = client.get(f"/api/cases/{cid}").json()
    assert fetched["id"] == cid

    report = client.get(f"/api/cases/{cid}/report")
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("text/markdown")
    assert "# Incident Report" in report.text

    as_json = client.get(f"/api/cases/{cid}/report?format=json").json()
    assert as_json["id"] == cid
    assert as_json["notification"]["subject"]

    patched = client.patch(f"/api/cases/{cid}/status", json={"status": "closed"})
    assert patched.json()["status"] == "closed"
    assert client.get(f"/api/cases/{cid}").json()["status"] == "closed"

    assert client.delete(f"/api/cases/{cid}").status_code == 200
    assert client.get(f"/api/cases/{cid}").status_code == 404


def test_invalid_status_rejected(client):
    case = _create(client)
    resp = client.patch(f"/api/cases/{case['id']}/status", json={"status": "banana"})
    assert resp.status_code == 400


def test_missing_case_404(client):
    assert client.get("/api/cases/PHI-00000000-deadbeef").status_code == 404
    assert client.delete("/api/cases/PHI-00000000-deadbeef").status_code == 404
    assert client.get("/api/cases/x/report").status_code == 404


def test_metrics_and_reset(client):
    assert client.get("/api/metrics").json()["total_cases"] == 0
    _create(client)
    _create(client, "legit_it_maintenance_notice.eml")
    stats = client.get("/api/metrics").json()
    assert stats["total_cases"] == 2
    assert stats["by_classification"]["true_positive"] == 1
    assert stats["minutes_saved"] > 0

    assert client.post("/api/reset").json()["deleted"] == 2
    assert client.get("/api/metrics").json()["total_cases"] == 0


def test_case_search(client):
    _create(client, "legit_it_maintenance_notice.eml")
    found = client.get("/api/cases", params={"search": "maintenance"}).json()
    assert found["total"] == 1
    assert client.get("/api/cases", params={"search": "zzz"}).json()["total"] == 0


# --- frontend --------------------------------------------------------------
def test_index_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "PhishPipe" in resp.text


def test_static_assets_served(client):
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200


def test_openapi_document(client):
    doc = client.get("/openapi.json").json()
    assert "/api/investigate/upload" in doc["paths"]
    assert "/api/cases/{case_id}" in doc["paths"]


# --- advanced SOC extensions -----------------------------------------------
def test_stix_and_sigma_export(client):
    case = _create(client)
    cid = case["id"]

    # STIX 2.1
    stix_resp = client.get(f"/api/cases/{cid}/stix")
    assert stix_resp.status_code == 200
    stix = stix_resp.json()
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) > 0
    types = {obj["type"] for obj in stix["objects"]}
    assert "identity" in types
    assert "report" in types

    # Sigma Rule
    sigma_resp = client.get(f"/api/cases/{cid}/sigma")
    assert sigma_resp.status_code == 200
    assert "Phishing Threat Activity" in sigma_resp.text and "logsource:" in sigma_resp.text
    assert "logsource:" in sigma_resp.text


def test_case_notes_and_tags(client):
    case = _create(client)
    cid = case["id"]

    # Notes
    add_resp = client.post(f"/api/cases/{cid}/notes", json={"text": "Reviewing payload URL", "author": "senior_analyst"})
    assert add_resp.status_code == 200
    note_id = add_resp.json()["id"]

    notes = client.get(f"/api/cases/{cid}/notes").json()
    assert len(notes) == 1
    assert notes[0]["text"] == "Reviewing payload URL"

    del_resp = client.delete(f"/api/cases/{cid}/notes/{note_id}")
    assert del_resp.status_code == 200
    assert len(client.get(f"/api/cases/{cid}/notes").json()) == 0

    # Tags
    client.post(f"/api/cases/{cid}/tags", json={"tag": "FIN7"})
    client.post(f"/api/cases/{cid}/tags", json={"tag": "CredentialHarvest"})
    tags = client.get(f"/api/cases/{cid}/tags").json()
    assert "fin7" in tags
    assert "credentialharvest" in tags

    client.delete(f"/api/cases/{cid}/tags/fin7")
    assert "fin7" not in client.get(f"/api/cases/{cid}/tags").json()


def test_playbook_actions(client):
    case = _create(client)
    cid = case["id"]

    # Quarantine
    q_resp = client.post(f"/api/cases/{cid}/actions/quarantine", json={})
    assert q_resp.status_code == 200
    assert q_resp.json()["action"] == "quarantine"

    # Block Domain
    b_resp = client.post(f"/api/cases/{cid}/actions/block_domain", json={})
    assert b_resp.status_code == 200
    assert b_resp.json()["action"] == "block_domain"

    # Reset Credentials
    r_resp = client.post(f"/api/cases/{cid}/actions/reset_credentials", json={})
    assert r_resp.status_code == 200

    # List Actions
    actions = client.get(f"/api/cases/{cid}/actions").json()
    assert len(actions) >= 3


def test_campaigns_and_watcher(client, tmp_path):
    _create(client)
    camp_resp = client.get("/api/campaigns")
    assert camp_resp.status_code == 200
    assert "campaigns" in camp_resp.json()

    # Watcher scan
    inbox = tmp_path / "test_inbox"
    inbox.mkdir()
    scan_resp = client.post("/api/watch/scan", json={"inbox_path": str(inbox)})
    assert scan_resp.status_code == 200
    assert scan_resp.json()["processed"] == 0
