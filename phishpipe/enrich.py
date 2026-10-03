"""Stage 3 - Enrichment: reputation lookups for extracted indicators.

Providers are opt-in. The :class:`OfflineProvider` always runs and answers from
a curated local dataset plus deterministic network-independent heuristics, so
the pipeline produces a complete package with no API keys and no outbound
traffic. Real providers activate only when their key is present in the
environment (see :mod:`phishpipe.config`).

Every provider is defensive: short timeouts, no retries, and any failure is
recorded on the result rather than raised, so a flaky reputation service can
never stall an investigation.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import urlparse

from phishpipe.config import (
    OFFLINE_VERDICTS_FILE,
    Settings,
    active_providers,
    load_settings,
    skipped_providers,
)
from phishpipe.models import EnrichmentBundle, EnrichmentResult, Indicator, VerdictLabel

REQUEST_TIMEOUT_SECONDS = 6


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _host_of(value: str, kind: str) -> str:
    if kind == "url":
        candidate = value if "://" in value else "http://" + value
        try:
            return (urlparse(candidate).hostname or "").lower()
        except ValueError:
            return ""
    if kind in {"domain", "ip"}:
        return value.lower().strip(".[]")
    return ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------
class EnrichmentProvider(ABC):
    """A single reputation source."""

    name: str = "base"
    kind: str = "reputation"

    @abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """Return ``(available, reason_when_not)``."""

    @abstractmethod
    def lookup(self, indicator: Indicator) -> EnrichmentResult:
        """Return a verdict for one indicator. Must never raise."""

    def _result(
        self,
        indicator: Indicator,
        verdict: VerdictLabel,
        summary: str,
        score: float | None = None,
        reference: str | None = None,
        offline: bool = False,
        error: str | None = None,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            provider=self.name,
            indicator=indicator.value,
            indicator_type=indicator.type,
            verdict=verdict,
            score=score,
            summary=summary,
            reference=reference,
            offline=offline,
            error=error,
        )


# ---------------------------------------------------------------------------
# Offline provider - always available
# ---------------------------------------------------------------------------
class OfflineProvider(EnrichmentProvider):
    """Local verdict cache + deterministic heuristics.

    Answers from ``data/offline_verdicts.json``. When an indicator is not in the
    cache it falls back to structural heuristics that require no network access
    (raw-IP hosts, punycode, disposable TLDs, and so on).
    """

    name = "offline"
    kind = "local"

    def __init__(self, dataset_path: Path | None = None) -> None:
        self.dataset_path = Path(dataset_path or OFFLINE_VERDICTS_FILE)
        self._dataset: dict[str, dict] = {}
        self._loaded = False

    def is_available(self) -> tuple[bool, str]:
        return True, ""

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.dataset_path.exists():
            return
        try:
            raw = json.loads(self.dataset_path.read_text(encoding="utf-8"))
            entries = raw.get("entries", raw) if isinstance(raw, dict) else {}
            self._dataset = {str(k).lower(): v for k, v in entries.items()}
        except (json.JSONDecodeError, OSError):
            self._dataset = {}

    @property
    def dataset_size(self) -> int:
        self._load()
        return len(self._dataset)

    def _match(self, indicator: Indicator) -> tuple[str, dict] | None:
        self._load()
        value = indicator.value.lower().strip(".[]")
        if value in self._dataset:
            return value, self._dataset[value]

        if indicator.type == "url":
            host = _host_of(value, "url")
            if host and host in self._dataset:
                return host, self._dataset[host]
            domain = _registrable(host)
            if domain and domain in self._dataset:
                return domain, self._dataset[domain]
        elif indicator.type == "domain":
            domain = _registrable(value)
            if domain in self._dataset:
                return domain, self._dataset[domain]
        elif indicator.type == "email":
            domain = _registrable(value.split("@")[-1])
            if domain in self._dataset:
                return domain, self._dataset[domain]
        return None

    def lookup(self, indicator: Indicator) -> EnrichmentResult:
        if indicator.type not in {"url", "domain", "ip", "email", "hash"}:
            return self._result(indicator, "unknown", "indicator type not enriched", offline=True)

        match = self._match(indicator)
        if match:
            key, entry = match
            verdict = str(entry.get("verdict", "unknown")).lower()
            if verdict not in {"malicious", "suspicious", "clean", "unknown"}:
                verdict = "unknown"
            parts = [entry.get("category", ""), entry.get("campaign", ""), entry.get("note", "")]
            summary = " - ".join(str(p) for p in parts if p) or "listed in local verdict cache"
            reference = entry.get("reference")
            if not reference:
                reference = f"offline dataset entry: {key}"
            return self._result(
                indicator,
                verdict,  # type: ignore[arg-type]
                summary,
                score=float(entry["score"]) if entry.get("score") is not None else None,
                reference=str(reference),
                offline=True,
            )

        # No cached verdict: apply deterministic structural heuristics.
        return self._heuristic(indicator)

    def _heuristic(self, indicator: Indicator) -> EnrichmentResult:
        value = indicator.value.lower()
        if indicator.type == "url":
            host = _host_of(value, "url")
            if _is_ip(host):
                return self._result(indicator, "suspicious", "URL host is a raw IP address", 60, offline=True)
            if "xn--" in host:
                return self._result(indicator, "suspicious", "punycode / homoglyph domain", 55, offline=True)
            if re.search(r"-\d{4,}\.|[a-z]{15,}\.", host):
                return self._result(
                    indicator, "suspicious", "high-entropy generated-looking domain", 45, offline=True
                )
            return self._result(indicator, "unknown", "no local verdict; structural checks passed", offline=True)

        if indicator.type == "domain":
            if "xn--" in value:
                return self._result(indicator, "suspicious", "punycode / homoglyph domain", 55, offline=True)
            return self._result(indicator, "unknown", "no local verdict for domain", offline=True)

        if indicator.type == "ip":
            try:
                addr = ipaddress.ip_address(indicator.value.strip("[]"))
            except ValueError:
                return self._result(indicator, "unknown", "unparseable IP", offline=True)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return self._result(indicator, "clean", "non-routable address", 0, offline=True)
            return self._result(indicator, "unknown", "no local verdict for public IP", offline=True)

        if indicator.type == "hash":
            return self._result(
                indicator, "unknown", "no local verdict; submit to a sandbox for detonation", offline=True
            )

        return self._result(indicator, "unknown", "not enriched", offline=True)


def _registrable(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in {"co.uk", "com.au", "co.nz", "co.za", "com.br", "co.in", "co.jp"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# Optional cloud providers (activated by API key)
# ---------------------------------------------------------------------------
class HttpProvider(EnrichmentProvider):
    """Shared plumbing for providers that call a REST API."""

    env_var: str = ""
    api_key: str = ""

    def is_available(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, f"missing {self.env_var} environment variable"
        return True, ""

    def _get(self, url: str, headers: dict[str, str] | None = None, params: dict | None = None):
        import requests  # imported lazily so offline runs need no HTTP library

        return requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT_SECONDS)


class VirusTotalProvider(HttpProvider):
    """VirusTotal v3 file/URL/domain lookup. 4 req/min on the free tier."""

    name = "virustotal"
    env_var = "VT_API_KEY"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key or ""

    def lookup(self, indicator: Indicator) -> EnrichmentResult:
        available, reason = self.is_available()
        if not available:
            return self._result(indicator, "unknown", reason, error=reason)
        try:
            if indicator.type == "hash":
                resp = self._get(f"{self.BASE}/files/{indicator.value}", headers={"x-apikey": self.api_key})
            elif indicator.type == "domain":
                resp = self._get(f"{self.BASE}/domains/{indicator.value}", headers={"x-apikey": self.api_key})
            elif indicator.type == "url":
                import base64

                id_ = base64.urlsafe_b64encode(indicator.value.encode()).decode().strip("=")
                resp = self._get(f"{self.BASE}/urls/{id_}", headers={"x-apikey": self.api_key})
            else:
                return self._result(indicator, "unknown", f"VirusTotal does not support {indicator.type} lookup")

            if resp.status_code == 404:
                return self._result(indicator, "unknown", "not yet analysed by VirusTotal", offline=False)
            if resp.status_code == 429:
                return self._result(
                    indicator, "unknown", "VirusTotal rate limit reached", offline=False, error="rate limited"
                )
            if resp.status_code != 200:
                return self._result(
                    indicator, "unknown", f"VirusTotal HTTP {resp.status_code}", offline=False,
                    error=f"HTTP {resp.status_code}",
                )

            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            total = sum(int(v or 0) for v in stats.values()) or 1
            ratio = (malicious + 0.5 * suspicious) / total

            verdict: VerdictLabel = "clean"
            if ratio >= 0.30:
                verdict = "malicious"
            elif ratio > 0:
                verdict = "suspicious"
            return self._result(
                indicator,
                verdict,
                f"{malicious}/{total} engines flagged malicious, {suspicious} suspicious",
                score=round(ratio * 100, 1),
                reference=f"https://www.virustotal.com/gui/search/{indicator.value}",
                offline=False,
            )
        except Exception as exc:  # noqa: BLE001 - provider must never break the pipeline
            return self._result(indicator, "unknown", "VirusTotal lookup failed", offline=False, error=str(exc))


class UrlscanProvider(HttpProvider):
    """urlscan.io search (read-only). Submitting pages is opt-in and disabled."""

    name = "urlscan"
    env_var = "URLSCAN_API_KEY"
    BASE = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key or ""

    def lookup(self, indicator: Indicator) -> EnrichmentResult:
        available, reason = self.is_available()
        if not available:
            return self._result(indicator, "unknown", reason, error=reason)
        if indicator.type not in {"url", "domain"}:
            return self._result(indicator, "unknown", f"urlscan does not support {indicator.type} lookup")
        try:
            query = indicator.value if indicator.type == "url" else f"domain:{indicator.value}"
            resp = self._get(
                f"{self.BASE}/search/",
                headers={"API-Key": self.api_key},
                params={"q": query, "size": 5},
            )
            if resp.status_code == 429:
                return self._result(indicator, "unknown", "urlscan rate limit reached", offline=False, error="rate limited")
            if resp.status_code != 200:
                return self._result(
                    indicator, "unknown", f"urlscan HTTP {resp.status_code}", offline=False, error=f"HTTP {resp.status_code}"
                )

            results = resp.json().get("results", [])
            if not results:
                return self._result(indicator, "unknown", "no prior urlscan observations", offline=False)

            verdicts = []
            for r in results:
                page = r.get("page", {})
                verdicts.append(
                    {
                        "score": page.get("score"),
                        "malicious": page.get("malicious"),
                        "url": page.get("url"),
                    }
                )
            flagged = [v for v in verdicts if v.get("malicious")]
            verdict: VerdictLabel = "malicious" if flagged else ("suspicious" if any(
                (v.get("score") or 0) >= 25 for v in verdicts
            ) else "clean")
            top = verdicts[0]
            return self._result(
                indicator,
                verdict,
                f"{len(results)} scan(s); community score {top.get('score')}",
                score=float(top["score"]) if top.get("score") is not None else None,
                reference=f"https://urlscan.io/search/#{query}",
                offline=False,
            )
        except Exception as exc:  # noqa: BLE001
            return self._result(indicator, "unknown", "urlscan lookup failed", offline=False, error=str(exc))


class AbuseIPDBProvider(HttpProvider):
    """AbuseIPDB blocklist check for source IPs."""

    name = "abuseipdb"
    env_var = "ABUSEIPDB_API_KEY"
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key or ""

    def lookup(self, indicator: Indicator) -> EnrichmentResult:
        available, reason = self.is_available()
        if not available:
            return self._result(indicator, "unknown", reason, error=reason)
        if indicator.type != "ip":
            return self._result(indicator, "unknown", f"AbuseIPDB does not support {indicator.type} lookup")
        try:
            resp = self._get(
                f"{self.BASE}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": indicator.value, "maxAgeInDays": 90},
            )
            if resp.status_code != 200:
                return self._result(
                    indicator, "unknown", f"AbuseIPDB HTTP {resp.status_code}", offline=False, error=f"HTTP {resp.status_code}"
                )
            data = resp.json().get("data", {})
            confidence = float(data.get("abuseConfidenceScore") or 0)
            verdict: VerdictLabel = (
                "malicious" if confidence >= 75 else "suspicious" if confidence >= 25 else "clean"
            )
            return self._result(
                indicator,
                verdict,
                f"abuse confidence {confidence:.0f}%, {data.get('totalReports', 0)} report(s)",
                score=confidence,
                reference=f"https://www.abuseipdb.com/check/{indicator.value}",
                offline=False,
            )
        except Exception as exc:  # noqa: BLE001
            return self._result(indicator, "unknown", "AbuseIPDB lookup failed", offline=False, error=str(exc))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def build_providers(settings: Settings | None = None) -> tuple[list[EnrichmentProvider], dict[str, str]]:
    """Return ``(enabled_providers, skipped_providers_with_reason)``."""
    settings = settings or load_settings()
    providers: list[EnrichmentProvider] = [OfflineProvider(settings.offline_verdicts_file)]

    # Read the environment live (rather than using the cached Settings snapshot)
    # so tests and operators can toggle a key without rebuilding Settings.
    keys = active_providers()
    skipped = skipped_providers()

    if "virustotal" in keys:
        providers.append(VirusTotalProvider(keys["virustotal"]))
        skipped.pop("virustotal", None)
    if "urlscan" in keys:
        providers.append(UrlscanProvider(keys["urlscan"]))
        skipped.pop("urlscan", None)
    if "abuseipdb" in keys:
        providers.append(AbuseIPDBProvider(keys["abuseipdb"]))
        skipped.pop("abuseipdb", None)

    return providers, skipped


# Indicator types worth spending an API call on.
ENRICHABLE_TYPES = {"url", "domain", "ip", "hash", "email"}


def run_enrichment(
    indicators: list[Indicator],
    settings: Settings | None = None,
    max_cloud_lookups: int = 25,
) -> EnrichmentBundle:
    """Enrich indicators across every enabled provider.

    The offline provider always runs on everything; cloud providers are capped
    at ``max_cloud_lookups`` so a message stuffed with links cannot burn a free
    API quota.
    """
    settings = settings or load_settings()
    started = time.perf_counter()
    providers, skipped = build_providers(settings)

    cloud = [p for p in providers if p.name != "offline"]
    offline_provider = next((p for p in providers if p.name == "offline"), None)

    results: list[EnrichmentResult] = []
    used: set[str] = set()
    cloud_budget = max_cloud_lookups
    checked = 0

    for indicator in indicators:
        if indicator.type not in ENRICHABLE_TYPES:
            continue
        checked += 1

        if offline_provider is not None:
            results.append(offline_provider.lookup(indicator))
            used.add(offline_provider.name)

        for provider in cloud:
            if cloud_budget <= 0:
                skipped.setdefault(provider.name, f"cloud lookup budget of {max_cloud_lookups} exhausted")
                break
            cloud_budget -= 1
            results.append(provider.lookup(indicator))
            used.add(provider.name)

    duration_ms = int((time.perf_counter() - started) * 1000)
    return EnrichmentBundle(
        results=results,
        providers_used=sorted(used),
        providers_skipped=skipped,
        indicators_checked=checked,
        duration_ms=duration_ms,
    )
