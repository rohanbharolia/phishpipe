"""Development helper: run the pipeline over every bundled sample and report verdicts."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishpipe.config import load_settings  # noqa: E402
from phishpipe.pipeline import InvestigationPipeline  # noqa: E402


def main() -> int:
    settings = load_settings()
    pipeline = InvestigationPipeline(settings=settings, persist=False)
    samples = sorted((ROOT / "samples").glob("*.eml"))
    if not samples:
        print("no samples found")
        return 1

    print(f"{'sample':42} {'class':16} {'sev':9} {'conf':>5} {'sig':>7} {'ms':>6}")
    print("-" * 92)
    for path in samples:
        try:
            case = pipeline.investigate_file(path)
        except Exception as exc:  # noqa: BLE001
            print(f"{path.name:42} ERROR: {exc}")
            return 1
        v = case.verdict
        print(
            f"{path.name:42} {v.classification:16} {v.severity:9} "
            f"{v.confidence:>4} {v.signals_matched:>3}/{v.signals_total:<3} {case.metrics.total_ms:>5}"
        )

    print()
    for path in samples:
        case = pipeline.investigate_file(path)
        v = case.verdict
        matched = [s for s in case.signals if s.matched]
        print(f"=== {path.name} -> {v.classification} @ {v.confidence} ({v.severity})")
        for s in matched:
            print(f"    {s.weight:+4d}  {s.id}")
        print(f"    indicators: {len(case.indicators)} | report: {len(case.report_markdown)} chars")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
