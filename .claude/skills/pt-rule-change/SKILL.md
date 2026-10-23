---
name: pt-rule-change
description: Carry out a change to the Patch Tuesday banding rules from Dave's plain-English description - edit pt/triage.py, update the tests' expected values with a reason, test, commit, push and confirm CI is green.
argument-hint: "[the rule change, in plain English]"
disable-model-invocation: true
---

# Change a Patch Tuesday rule

Dave's requested change: $ARGUMENTS

If that is empty or unclear, ask Dave what he wants changed, in plain English, before touching anything.

Dave doesn't use GitHub. Do every git and GitHub step yourself and never ask him to run, review or click anything there.

## Ground rules

- Never change anything under `data/` or `tests/fixtures/` (bot-written audit trail and frozen test data).
- Only change expected test values that this rule change genuinely moves, and give the reason for each one.
- If the change would conflict with the README's bands table, update that table too, in the same commit.

## Steps

1. **Record the bands before the change:**
   `python3 .claude/skills/pt-rule-change/bands.py > "$TMPDIR/pt-bands-before.json"` (use any temp directory).
2. **Edit `pt/triage.py`** to make the change. Read the surrounding code first and match its style.
3. **Run the tests:** `python -m pytest -q`. Any failures in `tests/test_october_2026.py` or `tests/test_report_loop.py` show which expected values the change moves.
4. **Update those expected values only.** Next to each changed value, add a comment such as `# was 20: <rule change>, <date>`. If a test fails for any other reason, the edit is wrong: fix the code, not the test.
5. **Count the moves:** `python3 .claude/skills/pt-rule-change/bands.py --diff "$TMPDIR/pt-bands-before.json"`.
6. **Run `python -m pytest -q` again.** Every test must pass.
7. **Commit and push to `main`.** The commit message says what rule changed and why, lists each expected value that changed (old -> new) and its reason, and gives the band-move count from step 5.
8. **Confirm CI is green:** `gh run list --workflow tests --limit 3`, then `gh run watch <id> --exit-status` for the run on your commit. If it fails, read the log (`gh run view <id> --log-failed`), fix and push again.

## Report back to Dave in plain English

- What the rule now says, in one or two sentences, and how it differs from before.
- How many October 2026 CVEs moved band, and the moves (e.g. "CVE-2026-70229 moved from P2 to P3").
- Which test numbers changed, and why.
- Whether the tests passed on GitHub. Say plainly if anything wasn't checked.
