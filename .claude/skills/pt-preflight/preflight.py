#!/usr/bin/env python3
"""Offline pre-flight for the coming Patch Tuesday (used by the /pt-preflight skill).

  python3 .claude/skills/pt-preflight/preflight.py [--today YYYY-MM-DD]

1. Checks the cron lines in .github/workflows/patch-tuesday.yml cover days 8-21.
2. Works out the date of the coming Patch Tuesday (second Tuesday).
3. Dry-runs the report pipeline against the frozen October fixture in a temp
   directory: facts.py --offline -> gate.py prepare 1 -> canned checker
   verdicts -> gate.py status -> gate.py final -> render.py.

No network, publishes nothing, writes nothing outside the temp directory.
Prints one "PASS"/"FAIL" line per check; exit 0 only if every check passed.
GitHub workflow status and the test suite are checked by the skill itself.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from pt.cli import second_tuesday  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
URL = "https://example.org/preflight"
results: list[tuple[bool, str]] = []


def check(ok: bool, msg: str) -> bool:
    results.append((ok, msg))
    print(("PASS  " if ok else "FAIL  ") + msg)
    return ok


def cron_days(field: str) -> set[int]:
    if field == "*":
        return set(range(1, 32))
    days: set[int] = set()
    for part in field.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/")
            step = int(s)
        lo, _, hi = part.partition("-")
        lo_i = 1 if lo == "*" else int(lo)
        hi_i = 31 if lo == "*" else int(hi or lo)
        days |= set(range(lo_i, hi_i + 1, step))
    return days


def check_cron() -> None:
    wf = (ROOT / ".github" / "workflows" / "patch-tuesday.yml").read_text()
    crons = re.findall(r'cron:\s*["\']([^"\']+)["\']', wf)
    if not check(bool(crons), f"patch-tuesday.yml has cron lines: {crons}"):
        return
    for c in crons:
        f = c.split()
        need = set(range(8, 22))
        ok = len(f) == 5 and f[3] == "*" and need <= cron_days(f[2])
        check(ok, f'cron "{c}" runs every day 8-21 of every month')


def coming_patch_tuesday(today: date) -> date:
    pt = second_tuesday(today.year, today.month)
    if pt < today:
        y, m = (today.year + 1, 1) if today.month == 12 else (today.year, today.month + 1)
        pt = second_tuesday(y, m)
    return pt


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable] + args, cwd=cwd, capture_output=True, text=True, timeout=120)


def draft() -> dict:
    # Same shape as the report-loop tests: one item of each main type.
    return {"month": "2026-Oct", "compiled_at": "2026-10-14T20:00:00Z", "tooling_sha": "preflight",
            "sources": [{"title": "Pre-flight placeholder", "url": URL}],
            "items": [
                {"id": "bl", "type": "bottom_line", "text": "Patch CVE-2026-96951 first; it is due Thu 15 Oct 2026, 15:00 BST.",
                 "claims": [{"id": "c1", "kind": "data", "text": "P1 due", "ref": "deadlines.P1.uk", "value": "Thu 15 Oct 2026, 15:00 BST"}]},
                {"id": "t1", "type": "source_total", "source": "BleepingComputer", "url": URL, "total": "1,411", "critical": "70",
                 "note": "", "claims": [{"id": "c2", "kind": "reported", "text": "placeholder total", "source_url": URL}]},
                {"id": "z1", "type": "zero_day", "cve": "CVE-2026-96951", "source": "BleepingComputer", "status": "exploited",
                 "text": "Actively exploited zero-day",
                 "claims": [{"id": "c3", "kind": "reported", "text": "placeholder zero-day", "source_url": URL}]},
                {"id": "f1", "type": "finding", "text": "Our read: pre-flight placeholder.",
                 "claims": [{"id": "c4", "kind": "inference", "text": "Our read", "ref": "counts.P2"}]}]}


def dry_run() -> None:
    with tempfile.TemporaryDirectory(prefix="pt-preflight-") as tmp:
        w = Path(tmp)
        r = run([str(ROOT / "report" / "facts.py"), "--data", str(FIX / "2026-Oct"),
                 "--kev", str(FIX / "kev-2026.10.13-microsoft.json.gz"), "--out", str(w / "facts.json"),
                 "--month", "2026-Oct", "--offline"], ROOT)
        if not check(r.returncode == 0, f"facts.py --offline on the October fixture (exit {r.returncode})"):
            print(r.stdout + r.stderr)
            return
        head = json.loads(r.stdout.splitlines()[0])
        check(head["headline"] == 1409 and head["ok"], f"facts headline {head['headline']} (expect 1409), ok={head['ok']}")

        (w / "draft.json").write_text(json.dumps(draft()))
        r = run([str(ROOT / "report" / "gate.py"), "prepare", str(w), "1"], ROOT)
        rd = w / "check" / "round-1"
        if not check(r.returncode == 0 and (rd / "claims.json").exists(), f"gate.py prepare (exit {r.returncode})"):
            print(r.stdout + r.stderr)
            return
        claims = json.loads((rd / "claims.json").read_text())["claims"]
        items = json.loads((rd / "items.json").read_text())["items"]
        (rd / "source_verdicts.json").write_text(json.dumps(
            [{"hash": c["hash"], "claim_id": c["claim_id"],
              "verdict": "INFERENCE_OK" if c["kind"] == "inference" else "SUPPORTED", "note": ""} for c in claims]))
        (rd / "coverage_verdicts.json").write_text(json.dumps(
            [{"hash": i["hash"], "item_id": i["item_id"], "pass": True, "issues": []} for i in items]))

        r = run([str(ROOT / "report" / "gate.py"), "status", str(w)], ROOT)
        check(r.returncode == 0, f"gate.py status after canned verdicts (exit {r.returncode}, expect 0)")
        r = run([str(ROOT / "report" / "gate.py"), "final", str(w)], ROOT)
        if not check(r.returncode == 0 and (w / "report.json").exists(), f"gate.py final (exit {r.returncode})"):
            print(r.stdout + r.stderr)
            return
        r = run([str(ROOT / "report" / "render.py"), str(w / "report.json"), str(w / "page.html")], ROOT)
        html = (w / "page.html").read_text() if (w / "page.html").exists() else ""
        check(r.returncode == 0 and all(s in html for s in ("CVE-2026-96951", 'id="pt-snapshot"', "Verification notes")),
              f"render.py builds the page (exit {r.returncode}, {len(html):,} chars)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--today", type=date.fromisoformat, default=date.today())
    a = ap.parse_args()
    check_cron()
    pt = coming_patch_tuesday(a.today)
    print(f"INFO  coming Patch Tuesday: {pt:%a %d %b %Y} ({(pt - a.today).days} days away); "
          f"collection runs that evening at 19:15 and 21:15 UTC, and again on {pt + timedelta(days=7):%a %d %b}")
    dry_run()
    bad = [m for ok, m in results if not ok]
    print(f"preflight.py: {len(results) - len(bad)} passed, {len(bad)} failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
