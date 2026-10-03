"""Development helper: syntax-check every Python file in the project."""

import ast
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
files = sorted(p for p in root.rglob("*.py") if ".venv" not in p.parts)
failures = 0

for path in files:
    try:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        failures += 1
        print(f"FAIL {path.relative_to(root)}:{exc.lineno} -> {exc.msg}")
    else:
        print(f"OK   {path.relative_to(root)}")

print(f"\n{len(files) - failures}/{len(files)} files parsed cleanly")
sys.exit(1 if failures else 0)
