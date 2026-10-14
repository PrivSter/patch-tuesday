# Patch Tuesday data

Monthly Microsoft security release data, triaged against UK patch deadlines.
Microsoft's Security Update Guide is the master list: every CVE comes from it,
with Microsoft's fields unchanged. CISA KEV only adds labels and carry-overs.

- `pt/triage.py`: bands, deadlines, data-quality flags and self-checks (pure functions)
- `pt/fetch.py`: Microsoft Update Guide feed and CISA KEV (stdlib only, no keys)
- `pt/cli.py`: `python -m pt.cli --month 2026-Nov` writes `data/<month>/`
- `tests/`: October 2026 known-answer test (1,409 headline; P1/P2/P3/P4 1/20/61/1,818) and report-loop tests
- `report/`: the monthly report's closed loop (below)

## Bands (UK first, counted from Microsoft's release time)

| Band | Rule | Deadline | Basis |
|---|---|---|---|
| P1 | Exploited per Microsoft, or in CISA KEV | 48 h (24 h internet-facing) | NCSC, responding to active exploitation (guidance) |
| P2 | Publicly disclosed; or Critical, AV:N/PR:N/UI:N and (AC:L or "Exploitation More Likely") | 7 days (5 internet-facing) | NCSC, update by default (guidance) |
| P3 | Any other Critical needing customer action | 14 days | Cyber Essentials v3.3 A6.4/A6.5 (mandatory) |
| P4 | Every other record needing customer action | 14 days; mandatory if CVSS ≥ 7.0, unrated, or bundled | Cyber Essentials v3.3 |

## Outputs per month

`summary.json` (counts, bands, deadlines, carry-overs, flags, self-checks),
`bands.csv`, `records.json.gz` (every Microsoft record), `products.json` (KBs for P1/P2).

`summary.json` has `"ok": true` only if every self-check passed. The report
must not be published from data with `"ok": false`.

## Automation

- `tests.yml` runs the tests on every push.
- `patch-tuesday-data.yml` collects data at 19:15 and 21:15 UTC on Patch Tuesday and
  the following Tuesday, and commits it. The commit history is the audit trail.
- The Claude scheduled task reads `data/<month>/summary.json`, reconciles the news
  sources, writes the report and PDF, and publishes them.

To change a rule, edit `pt/triage.py`, update the expected values in the test with
a reason, and push. The tests must pass before data is collected.

## The report loop (`report/`)

The monthly report is built as a closed loop, like the InfoSec Daily Brief V2:
one agent writes, two separate checker agents verify, and a script decides what is printed.

| File | Job |
|---|---|
| `facts.py` | Builds `facts.json` from `data/<month>/` plus a fresh KEV: every number, list, table and deadline on the page. Re-checks each P1 against Microsoft's live record. Exit 5 if fresh KEV moves a CVE into P1. |
| `playbook.md` | What the scheduled run follows: the writer's brief, the claims format and the loop. |
| `checker-source.md` | Brief for the agent that checks each news claim against the exact words on its page. |
| `checker-coverage.md` | Brief for the agent that checks the printed wording says no more than the checked claims. |
| `gate.py` | `prepare` / `status` / `final`. Matches every figure the writer cites to `facts.json` by script, tracks verdicts by text hash, caps the loop at three rounds, and applies the split rule. |
| `render.py`, `page.css` | Build the page from the gate's `report.json`; nothing on the page is typed by hand. |
| `topdf.js` | A4 landscape PDF of the page. |

**Split rule:** CVEs, bands, scores and deadlines come from Microsoft's data and are never
dropped. Narrative that still fails after three rounds is replaced (mechanical bottom line,
"not verified" cells, "no verified credit") or dropped (notes, findings), and listed in the
report's Verification notes.
