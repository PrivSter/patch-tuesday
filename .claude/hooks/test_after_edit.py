#!/usr/bin/env python3
"""PostToolUse hook: run the tests after Claude edits Python code.

When a .py file under pt/, report/ or tests/ is edited, runs
`python -m pytest -q` from the repo root. Silent when the tests pass; when they
fail, the end of pytest's output goes back to Claude as the reason to fix it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WATCHED = ("pt", "report", "tests")


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    ti = event.get("tool_input") or {}
    path = ti.get("file_path") or ti.get("notebook_path")
    if not path or not path.endswith(".py"):
        return 0
    p = Path(path)
    if not p.is_absolute():
        p = Path(event.get("cwd") or ".") / p
    try:
        rel = p.resolve().relative_to(ROOT)
    except ValueError:
        return 0
    if rel.parts[0] not in WATCHED:
        return 0
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                       cwd=ROOT, capture_output=True, text=True, timeout=110)
    if r.returncode == 0:
        return 0
    tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-40:])
    json.dump({"decision": "block",
               "reason": f"Tests failed after editing {rel.as_posix()} (python -m pytest -q, exit {r.returncode}):\n{tail}"},
              sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
