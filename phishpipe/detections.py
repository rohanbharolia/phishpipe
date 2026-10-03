"""Loader for the versioned detection logic in ``detections/signals.yaml``.

Keeping the rules as data means tuning a weight or adding a phrase is a
reviewable one-line diff, and ``version`` can be stamped onto every case so
historical verdicts remain reproducible after a rule change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from phishpipe.config import DETECTIONS_FILE, Settings, load_settings


@dataclass(frozen=True)
class SignalDefinition:
    id: str
    title: str
    description: str
    weight: int
    severity: str
    category: str
    techniques: tuple[str, ...] = ()


@dataclass
class ScoringThresholds:
    true_positive: int = 70
    suspicious: int = 30
    critical: int = 90
    high: int = 70
    medium: int = 40
    low: int = 15
    critical_signal_auto_escalate: bool = True


@dataclass
class Detections:
    version: str = "0.0.0"
    updated: str = ""
    description: str = ""
    thresholds: ScoringThresholds = field(default_factory=ScoringThresholds)
    signals: dict[str, SignalDefinition] = field(default_factory=dict)
    wordlists: dict[str, list[str]] = field(default_factory=dict)
    brand_domains: dict[str, list[str]] = field(default_factory=dict)
    mitre: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def ordered_signals(self) -> list[SignalDefinition]:
        """Signals in catalogue order so reports are deterministic."""
        return list(self.signals.values())

    def wordlist(self, name: str) -> list[str]:
        return [w.lower() for w in self.wordlists.get(name, [])]

    def official_domains_for(self, brand: str) -> list[str]:
        """Domains a brand legitimately sends from (empty when unmapped)."""
        return [d.lower() for d in self.brand_domains.get(brand.lower(), [])]

    def technique(self, technique_id: str) -> dict[str, str]:
        return self.mitre.get(technique_id, {"name": technique_id, "tactic": "Unknown"})


def _parse(raw: dict[str, Any]) -> Detections:
    scoring = raw.get("scoring", {}) or {}
    thresholds = ScoringThresholds(
        true_positive=int(scoring.get("true_positive_threshold", 70)),
        suspicious=int(scoring.get("suspicious_threshold", 30)),
        critical=int(scoring.get("critical_severity_threshold", 90)),
        high=int(scoring.get("high_severity_threshold", 70)),
        medium=int(scoring.get("medium_severity_threshold", 40)),
        low=int(scoring.get("low_severity_threshold", 15)),
        critical_signal_auto_escalate=bool(scoring.get("critical_signal_auto_escalate", True)),
    )

    signals: dict[str, SignalDefinition] = {}
    for entry in raw.get("signals", []) or []:
        sig = SignalDefinition(
            id=str(entry["id"]),
            title=str(entry.get("title", entry["id"])),
            description=str(entry.get("description", "")),
            weight=int(entry.get("weight", 0)),
            severity=str(entry.get("severity", "info")),
            category=str(entry.get("category", "general")),
            techniques=tuple(str(t) for t in entry.get("techniques", []) or []),
        )
        signals[sig.id] = sig

    raw_wordlists = raw.get("wordlists", {}) or {}
    # ``brand_domains`` is a mapping rather than a plain list, so it is parsed
    # separately instead of being flattened with the other word lists.
    brand_domains_raw = raw_wordlists.get("brand_domains", {}) or {}
    brand_domains = {
        str(brand): [str(d).lower() for d in (domains or [])]
        for brand, domains in brand_domains_raw.items()
    }
    wordlists = {
        str(k): [str(x) for x in (v or [])]
        for k, v in raw_wordlists.items()
        if k != "brand_domains"
    }

    mitre_raw = ((raw.get("mitre", {}) or {}).get("techniques", {})) or {}
    mitre = {
        str(tid): {
            "name": str(info.get("name", tid)),
            "tactic": str(info.get("tactic", "Unknown")),
        }
        for tid, info in mitre_raw.items()
    }

    return Detections(
        version=str(raw.get("version", "0.0.0")),
        updated=str(raw.get("updated", "")),
        description=str(raw.get("description", "")),
        thresholds=thresholds,
        signals=signals,
        wordlists=wordlists,
        brand_domains=brand_domains,
        mitre=mitre,
    )


@lru_cache(maxsize=4)
def _load_cached(path_str: str, mtime: float) -> Detections:
    path = Path(path_str)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return _parse(raw)


def load_detections(path: Path | None = None) -> Detections:
    """Load detections, caching on (path, mtime) so edits are picked up on reload."""
    target = Path(path) if path else DETECTIONS_FILE
    if not target.exists():
        raise FileNotFoundError(f"detection file not found: {target}")
    mtime = target.stat().st_mtime
    return _load_cached(str(target.resolve()), mtime)


def load_detections_from_settings(settings: Settings | None = None) -> Detections:
    settings = settings or load_settings()
    return load_detections(settings.detections_file)


def clear_cache() -> None:
    _load_cached.cache_clear()
