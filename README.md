# Patch Tuesday data

Monthly Microsoft security release data, triaged against UK patch deadlines.
Microsoft's Security Update Guide is the master list: every CVE comes from it,
with Microsoft's fields unchanged. CISA KEV only adds labels and carry-overs.

- `pt/triage.py`: bands, deadlines, data-quality flags and self-checks (pure functions)
- `pt/fetch.py`: Microsoft Update Guide feed and CISA KEV (stdlib only, no keys)
- `pt/cli.py`: `python -m pt.cli --month 2026-Nov` writes `data/<month>/`
- `tests/`: October 2026 known-answer test (1,409 headline; P1/P2/P3/P4 1/20/61/1,818)

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
