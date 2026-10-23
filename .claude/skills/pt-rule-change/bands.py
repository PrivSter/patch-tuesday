#!/usr/bin/env python3
"""Band of every October 2026 fixture CVE under the current pt/triage.py.

  python3 .claude/skills/pt-rule-change/bands.py > before.json   # before the edit
  python3 .claude/skills/pt-rule-change/bands.py --diff before.json   # after it

--diff prints how many CVEs moved band, and each move (CVE: old -> new).
CVEs not in P1-P3 count as "P4/other".
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from pt import triage as T  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def bands() -> dict[str, str]:
    records = json.load(gzip.open(FIX / "2026-Oct" / "records.json.gz", "rt"))
    kev = json.load(gzip.open(FIX / "kev-2026.10.13-microsoft.json.gz", "rt"))
    s = T.triage(records, kev)
    out = {r["cveNumber"]: "P4/other" for r in records}
    for b in ("P1", "P2", "P3"):
        for r in s[b]:
            out[r["cve"]] = b
    return out


def main() -> int:
    now = bands()
    if len(sys.argv) == 3 and sys.argv[1] == "--diff":
        before = json.loads(Path(sys.argv[2]).read_text())
        moved = sorted(c for c in now if before.get(c) != now[c])
        print(f"{len(moved)} CVE(s) moved band on the October 2026 fixture")
        for c in moved:
            print(f"  {c}: {before.get(c)} -> {now[c]}")
    else:
        json.dump(now, sys.stdout, indent=0, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
