"""Runtime configuration for PhishPipe.

Design rules that keep the project demo-able with zero setup:

* No API key is ever required. Providers are *opt-in*: a reputation provider is
  only activated when its environment variable is present.
* All paths resolve relative to the repository so the pipeline runs the same way
  from a venv, a test runner, or ``uvicorn api.main:app``.
* Secrets are read from the environment only, never from a committed file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PACKAGE_DIR = Path(__file__).resolve().parent
ROOT_DIR = PACKAGE_DIR.parent

DETECTIONS_FILE = ROOT_DIR / "detections" / "signals.yaml"
DATA_DIR = ROOT_DIR / "data"
OFFLINE_VERDICTS_FILE = DATA_DIR / "offline_verdicts.json"
CASES_DB_FILE = DATA_DIR / "cases.db"

SAMPLES_DIR = ROOT_DIR / "samples"
REPORTS_DIR = ROOT_DIR / "reports"
WEB_DIR = ROOT_DIR / "web"

# ---------------------------------------------------------------------------
# Optional enrichment providers
#
# Add a key to your shell profile to activate the matching provider:
#   setx VT_API_KEY "..."        VirusTotal
#   setx URLSCAN_API_KEY "..."   urlscan.io
#   setx ABUSEIPDB_API_KEY "..." AbuseIPDB
# ---------------------------------------------------------------------------
PROVIDER_ENV_VARS: dict[str, str] = {
    "virustotal": "VT_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
}

# Environment variable that forces offline mode even when keys are present.
# Useful for deterministic demos and unit tests.
OFFLINE_ENV_VAR = "PHISHPIPE_OFFLINE"


def active_providers() -> dict[str, str]:
    """Return ``{provider_name: api_key}`` for providers with a configured key.

    Returns an empty mapping when :data:`OFFLINE_ENV_VAR` is truthy, which lets
    a demo or CI run stay fully deterministic regardless of the host environment.
    """
    if is_offline_mode():
        return {}
    found: dict[str, str] = {}
    for provider, env_var in PROVIDER_ENV_VARS.items():
        value = os.getenv(env_var, "").strip()
        if value:
            found[provider] = value
    return found


def skipped_providers() -> dict[str, str]:
    """Return ``{provider_name: reason}`` for providers that will not run."""
    reasons: dict[str, str] = {}
    offline = is_offline_mode()
    for provider, env_var in PROVIDER_ENV_VARS.items():
        if offline:
            reasons[provider] = f"offline mode enabled via {OFFLINE_ENV_VAR}"
        elif not os.getenv(env_var, "").strip():
            reasons[provider] = f"missing {env_var} environment variable"
    return reasons


def is_offline_mode() -> bool:
    return os.getenv(OFFLINE_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Optional LLM narrative layer (OpenAI-compatible endpoints)
#
# When absent the pipeline falls back to a deterministic template writer, so
# reports and notifications are always produced.
# ---------------------------------------------------------------------------
LLM_ENV_VARS: tuple[str, ...] = ("OPENAI_API_KEY", "LLM_API_KEY")
LLM_BASE_URL_ENV_VAR = "LLM_BASE_URL"
LLM_MODEL_ENV_VAR = "LLM_MODEL"
DEFAULT_LLM_BASE_URL = "https://api.openai.com/v1"
DEFAULT_LLM_MODEL = "gpt-4o-mini"


def llm_config() -> dict[str, str | None]:
    """Return LLM settings, or ``{"api_key": None}`` when unconfigured."""
    key = next((os.getenv(v, "").strip() for v in LLM_ENV_VARS if os.getenv(v, "").strip()), None)
    return {
        "api_key": key,
        "base_url": (os.getenv(LLM_BASE_URL_ENV_VAR, "").strip() or DEFAULT_LLM_BASE_URL)
        if key
        else None,
        "model": (os.getenv(LLM_MODEL_ENV_VAR, "").strip() or DEFAULT_LLM_MODEL) if key else None,
    }


# ---------------------------------------------------------------------------
# Ingestion limits
# ---------------------------------------------------------------------------
MAX_EMAIL_BYTES = 25 * 1024 * 1024  # 25 MiB, mirrors most mail gateway caps
MAX_ATTACHMENTS = 25
MAX_BODY_CHARS = 500_000


# ---------------------------------------------------------------------------
# Timing baselines used for the "time saved" metric in the report
# ---------------------------------------------------------------------------
MANUAL_INVESTIGATION_MINUTES = int(os.getenv("PHISHPIPE_BASELINE_MINUTES", "45"))


@dataclass
class Settings:
    """Immutable-ish snapshot of effective runtime settings."""

    detections_file: Path = DETECTIONS_FILE
    offline_verdicts_file: Path = OFFLINE_VERDICTS_FILE
    cases_db_file: Path = CASES_DB_FILE
    reports_dir: Path = REPORTS_DIR
    offline_mode: bool = field(default_factory=is_offline_mode)
    providers: dict[str, str] = field(default_factory=active_providers)
    skipped: dict[str, str] = field(default_factory=skipped_providers)
    llm: dict[str, str | None] = field(default_factory=llm_config)

    def ensure_dirs(self) -> None:
        self.cases_db_file.parent.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    return settings
