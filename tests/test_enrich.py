"""Stage 3 - enrichment: offline provider, provider registry, bundle assembly."""

from __future__ import annotations

import json

from phishpipe.enrich import (
    OfflineProvider,
    build_providers,
    run_enrichment,
)
from phishpipe.models import Indicator


def _ind(kind: str, value: str) -> Indicator:
    return Indicator(type=kind, value=value, source="test")


# --- offline provider ------------------------------------------------------
def test_offline_dataset_loads():
    provider = OfflineProvider()
    assert provider.is_available()[0] is True
    assert provider.dataset_size > 0


def test_known_malicious_domain_is_matched():
    result = OfflineProvider().lookup(_ind("domain", "secure-login-microsoft365.xyz"))
    assert result.verdict == "malicious"
    assert result.offline is True
    assert result.score and result.score > 90


def test_url_resolves_to_host_entry():
    result = OfflineProvider().lookup(_ind("url", "http://parcel-redelivery-dhl.click/reschedule"))
    assert result.verdict == "malicious"


def test_known_clean_domain():
    result = OfflineProvider().lookup(_ind("domain", "microsoft.com"))
    assert result.verdict == "clean"


def test_unknown_domain_returns_unknown_not_clean():
    result = OfflineProvider().lookup(_ind("domain", "totally-new-domain-12345.example"))
    assert result.verdict == "unknown"


def test_heuristic_raw_ip_url():
    result = OfflineProvider().lookup(_ind("url", "http://192.0.2.55/x"))
    # 192.0.2.0/24 is documentation space and is in the clean dataset.
    assert result.verdict in {"suspicious", "clean", "unknown"}
    assert result.offline is True


def test_heuristic_punycode_domain():
    result = OfflineProvider().lookup(_ind("domain", "xn--pypal-4ve.com"))
    assert result.verdict == "suspicious"


def test_private_ip_is_clean():
    result = OfflineProvider().lookup(_ind("ip", "10.0.0.5"))
    assert result.verdict == "clean"


def test_provider_never_raises_on_garbage():
    provider = OfflineProvider()
    for kind, value in [("ip", "not-an-ip"), ("url", "///"), ("hash", ""), ("email", "x@y.z")]:
        assert provider.lookup(_ind(kind, value)).verdict in {"malicious", "suspicious", "clean", "unknown"}


def test_missing_dataset_is_tolerated(tmp_path):
    provider = OfflineProvider(tmp_path / "does-not-exist.json")
    assert provider.is_available()[0] is True
    assert provider.dataset_size == 0
    assert provider.lookup(_ind("domain", "example.com")).verdict == "unknown"


def test_corrupt_dataset_is_tolerated(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    provider = OfflineProvider(bad)
    assert provider.dataset_size == 0


# --- provider registry -----------------------------------------------------
def test_no_keys_means_only_offline_provider(monkeypatch):
    for var in ("VT_API_KEY", "URLSCAN_API_KEY", "ABUSEIPDB_API_KEY", "PHISHPIPE_OFFLINE"):
        monkeypatch.delenv(var, raising=False)
    providers, skipped = build_providers()
    assert [p.name for p in providers] == ["offline"]
    assert set(skipped) == {"virustotal", "urlscan", "abuseipdb"}
    assert "VT_API_KEY" in skipped["virustotal"]


def test_key_activates_provider(monkeypatch):
    for var in ("URLSCAN_API_KEY", "ABUSEIPDB_API_KEY", "PHISHPIPE_OFFLINE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VT_API_KEY", "test-key-123")
    providers, skipped = build_providers()
    names = [p.name for p in providers]
    assert "virustotal" in names
    assert "virustotal" not in skipped


def test_offline_env_var_forces_offline(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key-123")
    monkeypatch.setenv("PHISHPIPE_OFFLINE", "1")
    providers, skipped = build_providers()
    assert [p.name for p in providers] == ["offline"]
    assert "PHISHPIPE_OFFLINE" in skipped["virustotal"]


# --- bundle ----------------------------------------------------------------
def test_run_enrichment_builds_bundle(pipeline, settings):
    from phishpipe.extract import build_content_profile, extract_indicators
    from phishpipe.ingest import parse_email_file
    from tests.conftest import M365_PHISH

    email = parse_email_file(M365_PHISH)
    profile = build_content_profile(email)
    inds = extract_indicators(email, profile)
    bundle = run_enrichment(inds, settings)

    assert bundle.indicators_checked > 0
    assert bundle.providers_used == ["offline"]
    assert bundle.worst_verdict == "malicious"
    assert bundle.results
    assert all(r.provider == "offline" for r in bundle.results)


def test_unenrichable_types_are_skipped(settings):
    bundle = run_enrichment([_ind("attachment", "invoice.pdf")], settings)
    assert bundle.indicators_checked == 0
    assert bundle.results == []


def test_offline_dataset_is_valid_json():
    from phishpipe.config import OFFLINE_VERDICTS_FILE

    data = json.loads(OFFLINE_VERDICTS_FILE.read_text(encoding="utf-8"))
    assert "entries" in data
    for key, entry in data["entries"].items():
        assert entry["verdict"] in {"malicious", "suspicious", "clean", "unknown"}, key
