"""Stage 4 - analysis: signal evaluation, scoring, severity, ATT&CK mapping."""

from __future__ import annotations

from phishpipe.analyze import classify, map_mitre, score_signals, severity_for
from phishpipe.detections import load_detections


# --- detection file integrity ---------------------------------------------
def test_detection_file_loads(detections):
    assert detections.version == "1.0.0"
    assert len(detections.signals) >= 30


def test_every_signal_has_a_category_and_severity(detections):
    for sig in detections.ordered_signals:
        assert sig.category, sig.id
        assert sig.severity in {"info", "low", "medium", "high", "critical"}, sig.id
        assert sig.title and sig.description, sig.id


def test_every_signal_technique_exists_in_catalogue(detections):
    for sig in detections.ordered_signals:
        for tid in sig.techniques:
            assert tid in detections.mitre, f"{sig.id} references unknown technique {tid}"


def test_thresholds_are_ordered(detections):
    th = detections.thresholds
    assert 0 <= th.suspicious < th.true_positive <= 100
    assert th.low <= th.medium <= th.high <= th.critical


def test_signal_ids_are_unique(detections):
    ids = [s.id for s in detections.ordered_signals]
    assert len(ids) == len(set(ids))


# --- scoring ---------------------------------------------------------------
def test_empty_signals_score_zero(detections):
    assert score_signals([], detections) == 0


def test_negative_only_signals_clamp_to_zero(detections):
    from phishpipe.models import Signal

    signals = [
        Signal(id="a", title="a", weight=-30, matched=True),
        Signal(id="b", title="b", weight=-20, matched=True),
    ]
    assert score_signals(signals, detections) == 0


def test_score_is_clamped_at_100(detections):
    from phishpipe.models import Signal

    signals = [Signal(id=f"s{i}", title=f"s{i}", weight=40, matched=True) for i in range(6)]
    assert score_signals(signals, detections) == 100


def test_unmatched_signals_contribute_nothing(detections):
    from phishpipe.models import Signal

    signals = [Signal(id="s", title="s", weight=40, matched=False)]
    assert score_signals(signals, detections) == 0


def test_classification_thresholds(detections):
    assert classify(0, detections) == "false_positive"
    assert classify(29, detections) == "false_positive"
    assert classify(30, detections) == "suspicious"
    assert classify(69, detections) == "suspicious"
    assert classify(70, detections) == "true_positive"
    assert classify(100, detections) == "true_positive"


def test_severity_bands(detections):
    assert severity_for(0, [], detections) == "info"
    assert severity_for(20, [], detections) == "low"
    assert severity_for(45, [], detections) == "medium"
    assert severity_for(75, [], detections) == "high"
    assert severity_for(95, [], detections) == "critical"


def test_structural_critical_signal_forces_critical_severity(detections):
    from phishpipe.models import Signal

    signals = [
        Signal(id="attach.suspicious_extension", title="x", weight=20, matched=True,
               severity="critical", category="attachment")
    ]
    # Confidence is only medium, but a dangerous attachment escalates severity.
    assert severity_for(50, signals, detections) == "critical"


def test_enrichment_critical_signal_does_not_override_confidence(detections):
    from phishpipe.models import Signal

    signals = [
        Signal(id="enrich.malicious", title="x", weight=25, matched=True,
               severity="critical", category="enrichment")
    ]
    assert severity_for(50, signals, detections) == "medium"


# --- MITRE -----------------------------------------------------------------
def test_unmatched_signals_map_no_techniques(detections):
    from phishpipe.models import Signal

    signals = [Signal(id="s", title="s", weight=10, matched=False, mitre=["T1566"])]
    assert map_mitre(signals, detections) == []


def test_matched_signals_union_techniques(detections):
    from phishpipe.models import Signal

    signals = [
        Signal(id="a", title="a", weight=10, matched=True, mitre=["T1566.002", "T1204.001"]),
        Signal(id="b", title="b", weight=10, matched=True, mitre=["T1566.002"]),
        Signal(id="c", title="c", weight=10, matched=False, mitre=["T1078"]),
    ]
    techniques = map_mitre(signals, detections)
    ids = [t.id for t in techniques]
    assert ids == ["T1566.002", "T1204.001"]  # de-duplicated, catalogue order
    assert all(t.name and t.tactic and t.url for t in techniques)


def test_attack_urls_are_well_formed(detections):
    from phishpipe.analyze import format_attack_url

    assert format_attack_url("T1566") == "https://attack.mitre.org/techniques/T1566/"
    assert format_attack_url("T1566.002") == "https://attack.mitre.org/techniques/T1566/002/"


# --- end-to-end expectations ----------------------------------------------
def test_phish_case_is_true_positive(m365_case):
    v = m365_case.verdict
    assert v.classification == "true_positive"
    assert v.confidence >= 70
    assert v.severity in {"high", "critical"}
    assert v.explanation
    assert v.reasoning
    assert v.recommended_actions


def test_legit_case_is_false_positive(legit_case):
    v = legit_case.verdict
    assert v.classification == "false_positive"
    assert v.confidence < 30
    assert v.needs_human_review is False
    assert v.recommended_actions


def test_suspicious_case_needs_human_review(pipeline):
    from tests.conftest import DHL_PHISH

    case = pipeline.investigate_file(DHL_PHISH)
    assert case.verdict.classification == "suspicious"
    assert case.verdict.needs_human_review is True
    assert 30 <= case.verdict.confidence < 70


def test_phish_case_maps_phishing_techniques(m365_case):
    ids = {t.id for t in m365_case.verdict.mitre}
    assert "T1566" in ids
    assert ids & {"T1566.001", "T1566.002"}
    assert "T1204" in ids or "T1204.001" in ids


def test_attachment_case_maps_spearphishing_attachment(pipeline):
    from tests.conftest import INVOICE_PHISH

    case = pipeline.investigate_file(INVOICE_PHISH)
    ids = {t.id for t in case.verdict.mitre}
    assert "T1566.001" in ids
    assert "T1204.002" in ids


def test_every_signal_is_present_in_case(m365_case, detections):
    assert len(m365_case.signals) == len(detections.signals)
    assert m365_case.verdict.signals_total == len(detections.signals)


def test_confidence_matches_signal_sum(m365_case, detections):
    from phishpipe.analyze import score_signals

    expected = score_signals(m365_case.signals, detections)
    assert m365_case.verdict.confidence == expected


def test_critical_signal_is_always_reviewed(pipeline, detections):
    """A message carrying a dangerous attachment must never auto-close."""
    from tests.conftest import INVOICE_PHISH

    case = pipeline.investigate_file(INVOICE_PHISH)
    critical = [s for s in case.signals if s.matched and s.severity == "critical"]
    assert critical
    assert case.verdict.needs_human_review is True
