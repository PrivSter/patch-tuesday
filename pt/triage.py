"""Patch Tuesday triage: Microsoft's records in, bands, deadlines and checks out.

Pure functions, no network. Microsoft's Security Update Guide records are the
master list: every CVE in the output comes from them, with Microsoft's fields
unchanged. CISA KEV only adds a label (and carry-over items from earlier
months, each of which must also be a Microsoft record).

Deadline rules (UK first), counted from Microsoft's release time:
  P1  exploited per Microsoft, or in KEV      48h (24h internet-facing)  NCSC active exploitation
  P2  publicly disclosed; or Critical, AV:N/PR:N/UI:N and (AC:L or
      "Exploitation More Likely")             7d (5d internet-facing)    NCSC update by default
  P3  any other Critical needing action        14d, mandatory            Cyber Essentials v3.3
  P4  every other record needing action        14d (mandatory if CVSS>=7,
                                               unrated, or bundled)      Cyber Essentials v3.3
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

UK = ZoneInfo("Europe/London")
IMPACTS = ("Remote Code Execution", "Elevation of Privilege", "Information Disclosure",
           "Denial of Service", "Spoofing", "Security Feature Bypass", "Tampering")
DEADLINES = {  # hours from release
    "P1": 48, "P1_internet": 24,
    "P2": 7 * 24, "P2_internet": 5 * 24,
    "P3": 14 * 24, "P4": 14 * 24, "cyber_essentials": 14 * 24,
}


def _get(r: dict, k: str):
    return r.get(k)


def vector(v: str | None) -> dict:
    if not v:
        return {}
    try:
        return dict(p.split(":", 1) for p in v.split("/")[1:])
    except ValueError:
        return {}


def parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def release_time(records: list[dict]) -> datetime:
    """Main release time: the most common releaseDate among Microsoft-issued
    records that need customer action (cloud-only fixes earlier in the month
    and third-party records are excluded)."""
    c = Counter(r["releaseDate"] for r in records
                if _get(r, "issuingCna") == "Microsoft" and _get(r, "customerActionRequired"))
    if not c:
        raise ValueError("no Microsoft-issued customer-action records: release not out yet?")
    return parse_time(c.most_common(1)[0][0])


def uk(dt: datetime) -> str:
    return dt.astimezone(UK).strftime("%a %-d %b %Y, %H:%M %Z")


def is_p2_critical(r: dict) -> bool:
    d = vector(_get(r, "vectorString"))
    pre_auth = d.get("AV") == "N" and d.get("PR") == "N" and d.get("UI") == "N"
    return pre_auth and (d.get("AC") == "L" or _get(r, "latestSoftwareRelease") == "Exploitation More Likely")


def triage(records: list[dict], kev: dict | None = None, carryover: list[dict] | None = None,
           previous_release: datetime | None = None) -> dict:
    """records: every SUG record for the month. kev: CISA KEV JSON.
    carryover: Microsoft records (single-CVE lookups) for KEV entries added
    since previous_release that belong to earlier months."""
    by = {r["cveNumber"]: r for r in records}
    if len(by) != len(records):
        raise ValueError("duplicate cveNumber in records")
    kev_by = {k["cveID"]: k for k in (kev or {}).get("vulnerabilities", [])}

    act = [r for r in records if _get(r, "customerActionRequired")]
    exploited = {c for c, r in by.items() if _get(r, "exploited") == "Yes"}
    disclosed = {c for c, r in by.items() if _get(r, "publiclyDisclosed") == "Yes"}
    in_kev = {c for c in by if c in kev_by}
    crit = [r for r in act if _get(r, "severity") == "Critical"]

    p1 = exploited | in_kev
    p2 = ({r["cveNumber"] for r in crit if is_p2_critical(r)} | disclosed) - p1
    p3 = {r["cveNumber"] for r in crit} - p1 - p2
    p4 = {r["cveNumber"] for r in act} - p1 - p2 - p3

    rel = release_time(records)
    due = {k: rel + timedelta(hours=h) for k, h in DEADLINES.items()}

    sev4 = Counter((_get(by[c], "severity") or "unrated") for c in p4)
    ms = [r for r in records if _get(r, "issuingCna") == "Microsoft"]
    chrome = sum(1 for r in records if _get(r, "issuingCna") == "Chrome")
    counts = {
        "all": len(records),
        "microsoft": len(ms),
        "microsoft_install_needed": sum(1 for r in ms if _get(r, "customerActionRequired")),
        "chrome": chrome,
        "other_organisations": len(records) - len(ms) - chrome,
        "customer_action": len(act),
        "critical_customer_action": len(crit),
        "zero_days": len(exploited),
        "publicly_disclosed": len(disclosed),
        "kev_listed": len(in_kev),
        "P1": len(p1), "P2": len(p2), "P3": len(p3), "P4": len(p4),
        "P4_by_severity": dict(sorted(sev4.items())),
        "P3_preauth_high_complexity": sum(1 for c in p3 if "AV:N/AC:H/PR:N/UI:N" in (_get(by[c], "vectorString") or "")),
    }

    flags = []
    for c, r in sorted(by.items()):
        v = _get(r, "vectorString") or ""
        if c in exploited and "E:U" in v:
            flags.append({"cve": c, "flag": "exploited Yes but vector says E:U (exploit unproven)"})
        if c in in_kev and c not in exploited:
            flags.append({"cve": c, "flag": "in CISA KEV but Microsoft exploited flag is No"})
        t, i = _get(r, "cveTitle") or "", _get(r, "impact") or ""
        if i and t and i not in t and any(k in t for k in IMPACTS):
            flags.append({"cve": c, "flag": f"title says '{next(k for k in IMPACTS if k in t)}' but impact is '{i}'"})
    for r in crit:
        if not _get(r, "vectorString"):
            flags.append({"cve": r["cveNumber"], "flag": "Critical with no CVSS vector"})
        if not _get(r, "cweList"):
            flags.append({"cve": r["cveNumber"], "flag": "Critical with no CWE"})
    if chrome == 0:
        flags.append({"cve": None, "flag": "no Chrome-issued (Edge) records in this release"})

    carry = []
    for r in carryover or []:
        c = r["cveNumber"]
        k = kev_by.get(c, {})
        r_rel = parse_time(r["releaseDate"])
        ce_due = r_rel + timedelta(days=14)
        carry.append({
            "cve": c, "title": _get(r, "cveTitle"), "release": _get(r, "releaseNumber"),
            "baseScore": _get(r, "baseScore"), "microsoft_exploited": _get(r, "exploited"),
            "kev_added": k.get("dateAdded"), "kev_due": k.get("dueDate"),
            "ransomware": k.get("knownRansomwareCampaignUse"),
            "cyber_essentials_due": ce_due.isoformat(), "overdue": ce_due < datetime.now(timezone.utc),
        })
        if _get(r, "exploited") != "Yes":
            flags.append({"cve": c, "flag": "in CISA KEV but Microsoft exploited flag is No (earlier release)"})

    # Self-checks: the gate. Any failure means don't publish.
    checks = {
        "bands_disjoint": not (p1 & p2 or p1 & p3 or p2 & p3 or (p1 | p2 | p3) & p4),
        "criticals_accounted": {r["cveNumber"] for r in crit} <= (p1 | p2 | p3),
        "action_accounted": {r["cveNumber"] for r in act} <= (p1 | p2 | p3 | p4),
        "p4_breakdown_sums": sum(sev4.values()) == len(p4),
        "split_sums": counts["all"] == counts["microsoft"] + counts["chrome"] + counts["other_organisations"],
        "every_cve_is_microsoft_record": all(c in by for c in p1 | p2 | p3 | p4),
    }

    def row(c):
        r = by[c]
        k = kev_by.get(c)
        return {
            "cve": c, "title": _get(r, "cveTitle"), "component": _get(r, "tag"),
            "severity": _get(r, "severity"), "impact": _get(r, "impact"),
            "baseScore": _get(r, "baseScore"), "vector": _get(r, "vectorString"),
            "exploited": _get(r, "exploited"), "publiclyDisclosed": _get(r, "publiclyDisclosed"),
            "exploitability": _get(r, "latestSoftwareRelease"), "cwe": _get(r, "cweList"),
            "issuingCna": _get(r, "issuingCna"),
            "kev": {"dateAdded": k["dateAdded"], "dueDate": k["dueDate"],
                    "ransomware": k.get("knownRansomwareCampaignUse")} if k else None,
        }

    order = lambda s: sorted(s, key=lambda c: (-float(_get(by[c], "baseScore") or 0), c))
    return {
        "month": records[0].get("releaseNumber"),
        "release": rel.isoformat(), "release_uk": uk(rel),
        "deadlines": {k: {"utc": v.isoformat(), "uk": uk(v)} for k, v in due.items()},
        "counts": counts,
        "P1": [row(c) for c in order(p1)], "P2": [row(c) for c in order(p2)],
        "P3": [row(c) for c in order(p3)],
        "disclosed": sorted(disclosed), "exploited": sorted(exploited),
        "carryover": carry, "flags": flags, "checks": checks,
        "ok": all(checks.values()),
    }
