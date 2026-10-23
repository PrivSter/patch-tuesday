---
name: pt-preflight
description: Pre-flight check a few days before Patch Tuesday - tests, last GitHub workflow runs, collection schedule, the coming date, and an offline dry run of the report pipeline. Ends with "ready" or "not ready".
disable-model-invocation: true
---

# Patch Tuesday pre-flight

Run from the repo root. Don't fetch anything from the network except GitHub (via `gh`), don't publish anything, and don't change any files. Dave doesn't use GitHub: do every check yourself.

1. **Tests:** `python -m pytest -q`. All must pass.
2. **Last GitHub runs:**
   - `gh run list --workflow tests --limit 1`
   - `gh run list --workflow patch-tuesday-data --limit 1`
   Both latest runs must have succeeded. A failed `patch-tuesday-data` run matters most if it happened on a Tuesday (that is when it actually collects). If it failed, look at why: `gh run view <id> --log-failed`. If `gh` can't reach GitHub, mark this check as "not checked", not as passed.
3. **Schedule, date and dry run:** `python3 .claude/skills/pt-preflight/preflight.py`. This:
   - confirms the cron lines in `.github/workflows/patch-tuesday.yml` still run every day from the 8th to the 21st;
   - works out the coming Patch Tuesday (the second Tuesday) and the follow-up run a week later;
   - dry-runs `report/facts.py --offline`, `report/gate.py prepare`/`status`/`final` and `report/render.py` against the frozen October 2026 fixture in a temp directory (canned checker verdicts, deleted afterwards).
   Every line must say PASS.

## Finish with

A short plain-English summary for Dave: the coming Patch Tuesday date, and one line per check above. Then, on its own line, exactly one of:

- `READY for Patch Tuesday <date>.`
- `NOT READY for Patch Tuesday <date>: <each problem, briefly>.`

Anything you couldn't check (e.g. GitHub unreachable) makes it NOT READY, saying what wasn't checked.
