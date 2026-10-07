"""Main entry point for running PhishPipe directly from the phishpipe folder."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 65)
    print("  [*] Starting PhishPipe SOC Investigation Console")
    print("  [>] Web Dashboard: http://127.0.0.1:8000")
    print("  [>] API Docs:      http://127.0.0.1:8000/docs")
    print("=" * 65 + "\n")
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)
