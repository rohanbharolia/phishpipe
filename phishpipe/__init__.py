"""PhishPipe - automated phishing investigation pipeline.

Stages:
    ingest -> extract -> enrich -> analyze -> case -> notify
"""

__version__ = "1.0.0"

from phishpipe.pipeline import InvestigationPipeline, run_investigation  # noqa: F401

__all__ = ["InvestigationPipeline", "run_investigation", "__version__"]
