#!/usr/bin/env python3
"""PreToolUse hook: block file-editing tools from touching the audit trail.

Blocks Edit / Write / MultiEdit / NotebookEdit on:
  - anything under data/ (written only by the collection bot; its commit
    history is the audit trail) or tests/fixtures/ (frozen test data);
  - any file named report.json or page.html (built by report/gate.py and
    report/render.py; the playbook says never hand-edit them).

This hook only sees Claude's file-editing tools. It does NOT cover writes made
through Bash, which is how gate.py, render.py and pt.cli write their outputs,
so those keep working (and so would a shell redirect: this is a guard rail,
not a sandbox).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROTECTED_DIRS = ("data", "tests/fixtures")
PROTECTED_NAMES = ("report.json", "page.html")


def reason_for(path_str: str, cwd: str) -> str | None:
    p = Path(path_str)
    if not p.is_absolute():
        p = Path(cwd or ".") / p
    p = p.resolve()
    if p.name.endswith(PROTECTED_NAMES):
        return (f"{p.name} is built by report/gate.py and report/render.py and is never "
                "hand-edited (report/playbook.md step 4). Fix the draft or the renderer instead.")
    try:
        rel = p.relative_to(ROOT).as_posix()
    except ValueError:
        return None
    for d in PROTECTED_DIRS:
        if rel == d or rel.startswith(d + "/"):
            what = ("written only by the collection bot; its commit history is the audit trail"
                    if d == "data" else "frozen test data the known-answer tests were written against")
            return f"{rel} is under {d}/, which is {what}. Don't edit it by hand."
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    ti = event.get("tool_input") or {}
    path = ti.get("file_path") or ti.get("notebook_path")
    if not path:
        return 0
    why = reason_for(path, event.get("cwd", ""))
    if why:
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "deny",
                                          "permissionDecisionReason": "Blocked by .claude/hooks/protect_paths.py: " + why}},
                  sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
