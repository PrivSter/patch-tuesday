"""Collect a month's Patch Tuesday data and write it under data/<MONTH>/.

    python -m pt.cli --month 2026-Nov            # live: Microsoft + KEV
    python -m pt.cli --month 2026-Oct --offline tests/fixtures/2026-Oct.records.json.gz

Writes:
    records.json.gz   every Microsoft record for the month (the master list)
    summary.json      counts, bands, deadlines, carry-overs, flags, self-checks
    bands.csv         one row per P1-P3 CVE
    products.json     affected products and KBs for P1 and P2 (live runs only)

Exit codes: 0 ok, 3 release not published yet, 4 a self-check failed (don't publish).
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import triage as T

KEEP = ["cveNumber", "cveTitle", "severity", "impact", "baseScore", "temporalScore", "vectorString",
        "exploited", "publiclyDisclosed", "tag", "latestSoftwareRelease", "releaseDate",
        "latestRevisionDate", "customerActionRequired", "issuingCna", "cweList", "releaseNumber"]
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def second_tuesday(y: int, m: int) -> date:
    f = date(y, m, 1)
    return f + timedelta(days=(1 - f.weekday()) % 7 + 7)


def previous_release(month: str) -> datetime:
    y, m = int(month[:4]), MON.index(month[5:]) + 1
    y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    d = second_tuesday(y, m)
    return datetime.combine(d, time(10, 0), ZoneInfo("America/Los_Angeles")).astimezone(timezone.utc)


def slim(r: dict) -> dict:
    return {k: r.get(k) for k in KEEP}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--month", required=True, help="YYYY-Mon, e.g. 2026-Nov")
    ap.add_argument("--out", default="data")
    ap.add_argument("--offline", help="records .json.gz instead of fetching")
    ap.add_argument("--kev", help="KEV .json(.gz) instead of fetching")
    a = ap.parse_args(argv)

    if a.offline:
        records = json.load(gzip.open(a.offline, "rt"))
    else:
        from . import fetch
        records = [slim(r) for r in fetch.month_records(a.month)]
    if a.kev:
        op = gzip.open if a.kev.endswith(".gz") else open
        kev = json.load(op(a.kev, "rt"))
    elif a.offline:
        kev = {"vulnerabilities": []}
    else:
        from . import fetch
        kev = fetch.kev()

    try:
        T.release_time(records)
    except ValueError as e:
        print(f"release not out: {e}", file=sys.stderr)
        return 3

    prev = previous_release(a.month)
    month_cves = {r["cveNumber"] for r in records}
    carry_ids = [k["cveID"] for k in kev.get("vulnerabilities", [])
                 if k.get("vendorProject") == "Microsoft" and k["cveID"] not in month_cves
                 and k.get("dateAdded", "") >= prev.date().isoformat()]
    carry = []
    if carry_ids and not a.offline:
        from . import fetch
        for c in carry_ids:
            r = fetch.cve_record(c)
            if r:
                carry.append(slim(r))
            else:
                print(f"warning: KEV lists {c} as Microsoft but it has no Microsoft record", file=sys.stderr)

    s = T.triage(records, kev, carry, prev)
    s["generated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    s["kev_catalog"] = {"version": kev.get("catalogVersion"), "released": kev.get("dateReleased")}
    s["previous_release"] = prev.isoformat()

    out = Path(a.out) / a.month
    out.mkdir(parents=True, exist_ok=True)
    with gzip.open(out / "records.json.gz", "wt") as f:
        json.dump(sorted(records, key=lambda r: r["cveNumber"]), f, indent=0)
    if not a.offline:
        from . import fetch
        prods = {r["cve"]: fetch.affected_products(r["cve"]) for r in s["P1"] + s["P2"]}
        keep = ("productName", "kbArticles", "fixedBuildNumber", "severity", "releaseNumber")
        (out / "products.json").write_text(json.dumps(
            {c: [{k: p.get(k) for k in keep} for p in v] for c, v in prods.items()}, indent=1))
    (out / "summary.json").write_text(json.dumps(s, indent=1))
    with open(out / "bands.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["band", "cve", "component", "severity", "impact", "baseScore", "vector",
                    "exploited", "publiclyDisclosed", "exploitability", "kev_added", "due_uk"])
        for band in ("P1", "P2", "P3"):
            for r in s[band]:
                w.writerow([band, r["cve"], r["component"], r["severity"], r["impact"], r["baseScore"],
                            r["vector"], r["exploited"], r["publiclyDisclosed"], r["exploitability"],
                            (r["kev"] or {}).get("dateAdded"), s["deadlines"][band]["uk"]])

    c = s["counts"]
    print(f"{a.month}: {c['microsoft_install_needed']} headline, {c['zero_days']} zero-day, "
          f"P1/P2/P3/P4 {c['P1']}/{c['P2']}/{c['P3']}/{c['P4']}, CE deadline {s['deadlines']['cyber_essentials']['uk']}")
    if not s["ok"]:
        print("SELF-CHECK FAILED: " + ", ".join(k for k, v in s["checks"].items() if not v), file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
