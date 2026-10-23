# patch-tuesday

Collects Microsoft's monthly Patch Tuesday data, triages it into UK patch bands
(P1-P4) and feeds Dave's monthly report. See `README.md` for how it works and
`report/playbook.md` for the report loop.

## Ground rules

- **`data/` is bot-only.** The `patch-tuesday-data` workflow writes it, and its
  commit history is the audit trail. Never edit it. `tests/fixtures/` is frozen
  test data: don't edit that either. A hook in `.claude/settings.json` blocks
  Claude's file tools on both, and on any `report.json` or `page.html`.
- **Never change an expected test value without a reason.** Only a deliberate
  rule change may move one, with the reason in a comment and the commit message.
- **Dave doesn't use GitHub.** Do all git and GitHub work yourself (commit, push
  to `main` once tests pass, check CI with `gh`). Explain things in plain English.
- Code is Python 3, standard library only (plus pytest for tests).

## Tests

    python -m pytest -q

They read only `tests/fixtures/`, never `data/`, so a re-collection can't break
them. They must pass before the bot collects data. A hook re-runs them after
Claude edits a `.py` file under `pt/`, `report/` or `tests/`.

## Skills

- `/pt-rule-change <change in plain English>`: change a banding rule end to end.
- `/pt-preflight`: run a few days before Patch Tuesday; ends READY / NOT READY.

The checker subagents in `.claude/agents/` are for interactive sessions in this
repo; the scheduled report still uses `general-purpose` (see the playbook, step 3).
