"""Stages 5-6 and the orchestrator: case assembly, reporting, notification, store."""

from __future__ import annotations

import pytest

from phishpipe.casestore import CaseStore
from phishpipe.models import Case
from phishpipe.narrative import generate_narrative, llm_status
from phishpipe.pipeline import run_investigation
from tests.conftest import DHL_PHISH, LEGIT_MAIL, M365_PHISH, PLAIN_LEGIT


# --- orchestration ---------------------------------------------------------
def test_pipeline_produces_every_stage_artifact(pipeline, detections):
    case = pipeline.investigate_file(M365_PHISH)
    assert case.id.startswith("PHI-")
    assert case.indicators
    assert case.signals
    assert case.enrichment.results
    assert case.verdict.classification
    assert case.timeline
    assert case.narrative
    assert case.report_markdown
    assert case.notification.subject
    assert case.notification.body


def test_all_six_stages_are_timed(m365_case):
    stages = [t.stage for t in m365_case.timeline]
    assert stages == ["ingest", "extract", "enrich", "analyze", "reason", "report"]
    assert all(t.duration_ms >= 0 for t in m365_case.timeline)


def test_metrics_show_time_saved(m365_case):
    m = m365_case.metrics
    assert m.total_ms > 0
    assert m.estimated_minutes >= 0
    assert m.minutes_saved > 40  # automation is milliseconds, baseline is 45 min
    assert m.offline is True


def test_case_id_is_stable_for_identical_message(pipeline):
    a = pipeline.investigate_file(M365_PHISH)
    b = pipeline.investigate_file(M365_PHISH)
    assert a.id == b.id


def test_run_investigation_convenience(pipeline):
    case = run_investigation(M365_PHISH, settings=pipeline.settings, persist=False)
    assert isinstance(case, Case)
    assert case.verdict.classification == "true_positive"


def test_run_investigation_requires_input():
    with pytest.raises(ValueError):
        run_investigation()


def test_paste_and_file_agree(pipeline):
    pasted = pipeline.investigate_bytes(M365_PHISH.read_text(encoding="utf-8"))
    uploaded = pipeline.investigate_file(M365_PHISH)
    assert pasted.verdict.classification == uploaded.verdict.classification
    assert pasted.verdict.confidence == uploaded.verdict.confidence


# --- report ----------------------------------------------------------------
def test_report_contains_all_sections(m365_case):
    md = m365_case.report_markdown
    for heading in (
        "# Incident Report",
        "## 1. Verdict",
        "## 2. Investigation summary",
        "## 3. Message details",
        "## 4. Investigation timeline",
        "## 5. Indicators of Compromise",
        "## 6. Enrichment",
        "## 7. Analysis findings",
        "## 8. MITRE ATT&CK mapping",
        "## 10. Recommended actions",
        "## 11. User notification (ready to send)",
    ):
        assert heading in md, heading


def test_report_defangs_indicators(m365_case):
    md = m365_case.report_markdown
    # Live URLs must never appear in the IOC section.
    ioc_section = md.split("## 5. Indicators of Compromise")[1].split("## 6.")[0]
    assert "http://" not in ioc_section
    assert "https://" not in ioc_section
    assert "[.]" in ioc_section or "[@]" in ioc_section


def test_report_includes_signal_table(m365_case):
    md = m365_case.report_markdown
    findings = md.split("## 7. Analysis findings")[1].split("## 8.")[0]
    assert "| Signal | Matched | Weight | Severity | Evidence |" in findings
    assert "auth.spf_fail" in findings


def test_report_includes_detection_version(m365_case, detections):
    assert f"`{detections.version}`" in m365_case.report_markdown


def test_report_shows_provider_skip_reasons(m365_case):
    md = m365_case.report_markdown
    section = md.split("## 6. Enrichment")[1].split("## 7.")[0]
    assert "Providers skipped" in section
    assert "VT_API_KEY" in section


# --- narrative -------------------------------------------------------------
def test_narrative_is_deterministic_without_keys(m365_case):
    summary, _ = generate_narrative(m365_case)
    assert "true positive" in summary.lower()
    assert "SPF" in summary or "spf" in summary


def test_llm_disabled_by_default():
    status = llm_status()
    assert status["enabled"] is False
    assert status["mode"] == "deterministic-template"


def test_notification_is_plain_language(pipeline):
    case = pipeline.investigate_file(M365_PHISH)
    body = case.notification.body
    # The recipient-facing message must avoid raw IOCs and internal jargon.
    assert "hxxp" not in body
    assert "T1566" not in body
    assert "confidence" not in body.lower()
    assert "Do not click" in body or "do not click" in body
    assert case.notification.to == "jane.doe@yourcompany.com"


def test_legit_case_gets_a_no_action_notification(pipeline):
    case = pipeline.investigate_file(LEGIT_MAIL)
    body = case.notification.body
    assert "no action is needed" in body.lower()


def test_narrative_runs_for_every_sample(pipeline, samples_dir):
    for path in sorted(samples_dir.glob("*.eml")):
        case = pipeline.investigate_file(path)
        assert case.narrative.strip(), path.name
        assert case.notification.body.strip(), path.name
        assert case.report_markdown.strip(), path.name


def test_plain_legit_message_is_false_positive(pipeline):
    case = pipeline.investigate_bytes(PLAIN_LEGIT)
    assert case.verdict.classification == "false_positive"
    assert case.verdict.needs_human_review is False


# --- case store ------------------------------------------------------------
@pytest.fixture()
def store(tmp_path):
    return CaseStore(db_path=tmp_path / "cases.db")


def test_store_round_trip(store, pipeline):
    case = pipeline.investigate_file(M365_PHISH)
    store.save(case)
    loaded = store.get(case.id)
    assert loaded is not None
    assert loaded.id == case.id
    assert loaded.verdict.confidence == case.verdict.confidence
    assert len(loaded.indicators) == len(case.indicators)
    assert loaded.report_markdown == case.report_markdown


def test_store_list_and_count(store, pipeline):
    for path in (M365_PHISH, DHL_PHISH, LEGIT_MAIL):
        store.save(pipeline.investigate_file(path))
    assert store.count() == 3
    items = store.list()
    assert len(items) == 3
    # Newest first.
    assert items[0]["created_at"] >= items[-1]["created_at"]
    # Payload column is excluded from list results.
    assert "payload" not in items[0]


def test_store_filters(store, pipeline):
    store.save(pipeline.investigate_file(M365_PHISH))
    store.save(pipeline.investigate_file(LEGIT_MAIL))
    assert len(store.list(classification="true_positive")) == 1
    assert len(store.list(classification="false_positive")) == 1
    assert len(store.list(search="maintenance")) == 1
    assert len(store.list(severity="critical")) == 1


def test_store_update_status_and_delete(store, pipeline):
    case = pipeline.investigate_file(M365_PHISH)
    store.save(case)
    assert store.update_status(case.id, "triaged") is True
    assert store.get(case.id).status == "triaged"
    assert store.update_status("missing", "triaged") is False
    assert store.delete(case.id) is True
    assert store.get(case.id) is None
    assert store.delete(case.id) is False


def test_store_stats(store, pipeline):
    store.save(pipeline.investigate_file(M365_PHISH))
    store.save(pipeline.investigate_file(LEGIT_MAIL))
    stats = store.stats()
    assert stats["total_cases"] == 2
    assert stats["by_classification"]["true_positive"] == 1
    assert stats["avg_confidence"] > 0
    assert stats["minutes_saved"] > 0


def test_store_missing_case_returns_none(store):
    assert store.get("PHI-00000000-00000000") is None
