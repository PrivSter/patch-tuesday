#!/usr/bin/env python3
"""Patch Tuesday report loop - step 1: the facts.

Builds facts.json: every number, list, table and deadline the report shows,
computed from the repo's data files plus a fresh KEV catalogue. No model types
any of these; the renderer prints them straight from this file, and the writer
may only cite them as `data` claims, which the gate checks against this file.

  python3 report/facts.py --data <dir with summary.json, products.json, records.json.gz>
                          --kev <kev.json> --out <workdir>/facts.json
                          [--sha <commit>] [--offline]

--offline skips the live Microsoft re-check of each P1 (used by the tests).

Exit codes: 0 ok; 4 data not usable (missing file, ok false, wrong month);
5 the fresh KEV catalogue moves a CVE into P1 that the repo data doesn't have
there - re-run the collector (python3 -m pt.cli) and build facts from its output.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MSRC_ONE = "https://api.msrc.microsoft.com/sug/v2.0/en-GB/vulnerability?$filter="
UG = "https://msrc.microsoft.com/update-guide/vulnerability/{}"
MONTHS = {"Jan": "January", "Feb": "February", "Mar": "March", "Apr": "April", "May": "May",
          "Jun": "June", "Jul": "July", "Aug": "August", "Sep": "September", "Oct": "October",
          "Nov": "November", "Dec": "December"}


# ---------------------------------------------------------------- Windows names

def win_label(product: str) -> str | None:
    m = re.match(r"Windows (10|11) [Vv]ersion (\w+)", product)
    if m:
        return f"Windows {m.group(1)} {m.group(2)}"
    m = re.match(r"Windows Server (\d{4}(?: R2)?)", product)
    if m:
        return f"Server {m.group(1)}"
    return None


def win_key(label: str) -> tuple:
    if label.startswith("Server"):
        y = label.split()[1]
        return (1, int(y), 1 if "R2" in label else 0)
    major, ver = label.split()[1], label.split()[2]
    if re.fullmatch(r"\d{4}", ver):
        yy, mm = int(ver[:2]), int(ver[2:])
    else:
        yy, mm = int(ver[:2]), 3 if ver.endswith("H1") else 9
    return (0, int(major), yy, mm)


def runs(full: list[str], have: set[str]) -> list[str]:
    """Contiguous runs of `have` within the ordered `full` list, e.g.
    'Windows 10 1607 to Windows 11 26H2' or 'Server 2012 to 2022'."""
    out, cur = [], []
    for lab in full + [None]:
        if lab is not None and lab in have:
            cur.append(lab)
            continue
        if cur:
            a, b = cur[0], cur[-1]
            if a == b:
                out.append(a)
            elif a.startswith("Server") and b.startswith("Server"):
                out.append(f"{a} to {b.split(' ', 1)[1]}")
            elif a.split()[:2] == b.split()[:2]:
                out.append(f"{a} to {b.split()[2]}")
            else:
                out.append(f"{a} to {b}")
            cur = []
    return out


def clean_product(name: str) -> str:
    return re.sub(r" for (32|64)-bit (Systems|editions)$", "", name)


def kb_text(k: dict) -> str:
    a, b = str(k.get("articleName") or ""), k.get("fixedBuildNumber")
    return f"KB{a}" + (f" ({b})" if b else "")


# ---------------------------------------------------------------- per-CVE products

def products_for(rows: list[dict], cu_kbs: dict[str, set], all_win: list[str]) -> dict:
    """Affects / Fix summary for one CVE from its products.json rows."""
    win = {}
    other: dict[str, list[dict]] = {}
    for r in rows:
        lab = win_label(r["product"])
        if lab:
            win.setdefault(lab, []).append(r)
        else:
            other.setdefault(clean_product(r["product"]), []).append(r)

    affects, fix, flags = [], [], []
    if win:
        have = set(win)
        clients = [l for l in all_win if not l.startswith("Server")]
        servers = [l for l in all_win if l.startswith("Server")]
        if have >= set(all_win):
            affects.append("All supported Windows, client and server")
        else:
            affects.append("; ".join(runs(clients, have) + runs(servers, have)))
        odd = []
        for lab, rs in win.items():
            kbs = {str(k.get("articleName")) for r in rs for k in (r.get("kbArticles") or [])
                   if str(k.get("articleName", "")).isdigit()}
            if cu_kbs and kbs and not kbs <= cu_kbs.get(lab, set()):
                odd.append(f"{lab}: " + ", ".join("KB" + k for k in sorted(kbs)))
        no_fix = sorted(l for l, rs in win.items() if all(r.get("productStatus") == "known_affected" for r in rs))
        fix.append("Windows cumulative update for the month (table below)")
        fix += [f"Different KB from the cumulative-update table: {o}" for o in sorted(odd)]
        if no_fix:
            fix.append("No fix yet for " + ", ".join(no_fix) + ": deadline starts when Microsoft releases a fix")

    if other:
        affects.append(", ".join(other))
        waiting = []
        for prod, rs in other.items():
            st = {r.get("productStatus") for r in rs}
            if st == {"known_affected"}:
                waiting.append(prod)
                continue
            if None in st:
                flags.append(f"{prod} is listed with no productStatus (neither fixed nor known affected)")
            arts = [k for r in rs for k in (r.get("kbArticles") or [])]
            kbs = sorted({kb_text(k) for k in arts if str(k.get("articleName", "")).isdigit()})
            notes = [k for k in arts if not str(k.get("articleName", "")).isdigit()]
            builds = list(dict.fromkeys(str(k.get("fixedBuildNumber")) for k in notes if k.get("fixedBuildNumber")))
            parts = []
            if kbs:
                parts.append(", ".join(kbs))
            if notes:
                if prod.startswith("Microsoft 365 Apps"):
                    parts.append("Click-to-Run security update")
                elif rs[0].get("productFamily") in ("Open Source Software", "Other"):
                    parts.append("upgrade to " + " / ".join(builds) if builds else "see release notes")
                else:
                    parts.append(" / ".join(builds) if builds else "see release notes")
            fix.append(f"{prod}: " + ("; ".join(parts) if parts else "see the Update Guide"))
        if waiting:
            fix.append("No fix yet for " + ", ".join(sorted(waiting)) + ": deadline starts when Microsoft releases a fix")
    return {"affects": "; ".join(a for a in affects if a) or "Not listed in products.json",
            "fix": fix or ["See the Update Guide"], "flags": flags}


# ---------------------------------------------------------------- attack line

def attack_line(row: dict) -> str:
    v = dict(p.split(":", 1) for p in (row.get("vector") or "").split("/")[1:] if ":" in p)
    if not v:
        return "Microsoft publishes no CVSS vector for this CVE, so the attack path can't be described."
    where = {"N": "The attacker works over the network", "A": "The attacker must be on an adjacent network (same segment, VPN or Wi-Fi)",
             "L": "The attacker needs local access to the machine (an existing foothold, or a user running a file)",
             "P": "The attacker needs physical access to the device"}.get(v.get("AV"), "Attack vector not stated")
    who = {"N": "needs no account", "L": "needs a low-privileged account", "H": "needs an admin-level account"}.get(v.get("PR"), "")
    ui = {"N": "no user action is needed", "R": "a user must act, such as opening a crafted file or link"}.get(v.get("UI"), "")
    ac = {"L": "Attack complexity is low, so it is reliable to exploit.",
          "H": "Attack complexity is high: conditions outside the attacker's control must line up."}.get(v.get("AC"), "")
    cia = "/".join(f"{k}:{v[k]}" for k in ("C", "I", "A") if k in v)
    out = f"Outcome: {(row.get('impact') or 'impact not stated').lower()} in {row.get('component') or 'the component'}"
    out += f" ({cia})." if cia else "."
    return f"{where} and {who}; {ui}. {ac} {out}".replace("  ", " ").strip()


# ---------------------------------------------------------------- live re-check

def live_record(cve: str) -> dict | None:
    url = MSRC_ONE + urllib.parse.quote(f"cveNumber eq '{cve}'")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "patch-tuesday-report/1.0"})
    with urllib.request.urlopen(req, timeout=40) as r:
        v = json.load(r).get("value") or []
    return v[0] if v else None


def live_check(row: dict) -> dict:
    try:
        rec = live_record(row["cve"])
    except Exception as e:  # noqa: BLE001
        return {"ok": None, "note": f"Microsoft's live record could not be fetched: {e}"}
    if rec is None:
        return {"ok": False, "note": "Microsoft's live feed returned no record for this CVE"}
    diffs = []
    for mine, theirs in (("exploited", "exploited"), ("publiclyDisclosed", "publiclyDisclosed"),
                         ("baseScore", "baseScore"), ("vector", "vectorString")):
        a, b = row.get(mine), rec.get(theirs)
        if str(a) != str(b):
            diffs.append(f"{mine}: repo data '{a}', live record '{b}'")
    return {"ok": not diffs, "note": "; ".join(diffs) or "matches Microsoft's live record",
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")}


# ---------------------------------------------------------------- main

def build(data: Path, kev: dict, sha: str = "", offline: bool = False) -> tuple[dict, int]:
    s = json.load(open(data / "summary.json", encoding="utf-8"))
    products = json.load(open(data / "products.json", encoding="utf-8"))
    records = json.load(gzip.open(data / "records.json.gz", "rt", encoding="utf-8"))
    by = {r["cveNumber"]: r for r in records}
    kev_by = {k["cveID"]: k for k in kev.get("vulnerabilities", [])}
    month = s["month"]
    flags = [dict(f, origin="repo") for f in s.get("flags", [])]

    # Fresh KEV: does it move anything into P1?
    p1_ids = {r["cve"] for r in s["P1"]}
    month_kev = sorted(c for c in by if c in kev_by)
    band_change = [c for c in month_kev if c not in p1_ids and by[c].get("customerActionRequired")]
    repo_kev_rel = (s.get("kev_catalog") or {}).get("released") or ""
    kev_rel = kev.get("dateReleased", "")
    if kev_rel and repo_kev_rel and kev_rel > repo_kev_rel:
        flags.append({"cve": None, "origin": "facts",
                      "flag": f"The repo's copy of CISA KEV (released {repo_kev_rel[:16].replace('T', ' ')} UTC) is older than "
                              f"the catalogue used for this report (released {kev_rel[:16].replace('T', ' ')} UTC)."})

    # Windows version list and cumulative-update table
    all_win = sorted({l for rows in products.values() for r in rows if (l := win_label(r["product"]))}, key=win_key)
    best_cve, best = None, set()
    for c, rows in products.items():
        labs = {l for r in rows if (l := win_label(r["product"]))}
        if len(labs) > len(best) or (len(labs) == len(best) and best_cve and c < best_cve):
            best_cve, best = c, labs
    cu_rows, cu_kbs = [], {}
    if best_cve:
        per: dict[str, dict] = {}
        for r in products[best_cve]:
            lab = win_label(r["product"])
            if not lab:
                continue
            for k in r.get("kbArticles") or []:
                if str(k.get("articleName", "")).isdigit():
                    d = per.setdefault(lab, {"kbs": [], "builds": []})
                    if k["articleName"] not in d["kbs"]:
                        d["kbs"].append(str(k["articleName"]))
                    if k.get("fixedBuildNumber") and k["fixedBuildNumber"] not in d["builds"]:
                        d["builds"].append(k["fixedBuildNumber"])
        for lab in sorted(per, key=win_key):
            cu_rows.append({"version": lab, "kb": ", ".join("KB" + k for k in per[lab]["kbs"]),
                            "build": ", ".join(per[lab]["builds"])})
            cu_kbs[lab] = set(per[lab]["kbs"])
        missing = [l for l in all_win if l not in per]
        if missing:
            flags.append({"cve": best_cve, "origin": "facts",
                          "flag": "cumulative-update table source lists no KB for " + ", ".join(missing)})

    def enrich(row: dict, band: str) -> dict:
        r = dict(row)
        r["band"] = band
        r["url"] = UG.format(r["cve"])
        k = kev_by.get(r["cve"])
        r["kev"] = ({"dateAdded": k.get("dateAdded"), "dueDate": k.get("dueDate"),
                     "ransomware": k.get("knownRansomwareCampaignUse"),
                     "forensicTriage": k.get("forensicTriage"), "name": k.get("vulnerabilityName")} if k else None)
        if r["cve"] in products:
            p = products_for(products[r["cve"]], cu_kbs, all_win)
            r["affects"], r["fix"] = p["affects"], p["fix"]
            for f in p["flags"]:
                flags.append({"cve": r["cve"], "origin": "facts", "flag": f})
        vec = r.get("vector") or ""
        chips = []
        if r.get("publiclyDisclosed") == "Yes":
            chips.append("Publicly disclosed")
        if band == "P2" and "AC:H" in vec:
            chips.append("AC:H, " + (r.get("exploitability") or "no Microsoft rating"))
        r["chips"] = chips
        r["vector_short"] = re.sub(r"^CVSS:3\.\d/", "", vec).split("/E:")[0] if vec else ""
        return r

    p1 = [enrich(r, "P1") for r in s["P1"]]
    for r in p1:
        r["attack"] = attack_line(r)
        r["kbs"] = sorted({kb_text(k).split(" ")[0] for x in products.get(r["cve"], [])
                           for k in (x.get("kbArticles") or []) if str(k.get("articleName", "")).isdigit()})
        r["live"] = {"ok": None, "note": "live re-check skipped (offline)"} if offline else live_check(r)
        if r["live"]["ok"] is False:
            flags.append({"cve": r["cve"], "origin": "facts", "flag": "Live Microsoft re-check differs from the repo data: " + r["live"]["note"]})
    p2 = [enrich(r, "P2") for r in s["P2"]]
    p3 = [enrich(r, "P3") for r in s["P3"]]

    # Microsoft-issued, install-needed CVEs by band (must sum to the headline)
    bands = {**{r["cve"]: "P1" for r in p1}, **{r["cve"]: "P2" for r in p2}, **{r["cve"]: "P3" for r in p3}}
    split = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for r in records:
        if r.get("issuingCna") == "Microsoft" and r.get("customerActionRequired"):
            split[bands.get(r["cveNumber"], "P4")] += 1
    c = dict(s["counts"])
    c["kev_listed"] = len(month_kev)
    c["zero_days_total"] = len(set(s["exploited"]) | set(s["disclosed"]))
    c["critical_all_records"] = sum(1 for r in records if r.get("severity") == "Critical")
    c["critical_microsoft_issued"] = sum(1 for r in records if r.get("severity") == "Critical" and r.get("issuingCna") == "Microsoft")
    c["microsoft_by_band"] = split

    zero = []
    for cve in sorted(set(s["exploited"]) | set(s["disclosed"]) | set(month_kev)):
        r = by.get(cve, {})
        zero.append({"cve": cve, "title": r.get("cveTitle"), "url": UG.format(cve),
                     "exploited": r.get("exploited"), "publiclyDisclosed": r.get("publiclyDisclosed"),
                     "kev": (kev_by[cve].get("dateAdded") if cve in kev_by else None)})

    prev = (s.get("previous_release") or "")[:10]
    carry = []
    for x in s.get("carryover", []):
        x = dict(x, url=UG.format(x["cve"]))
        x["note"] = ("Added to KEV on the previous Patch Tuesday, so it was P1 in last month's report."
                     if prev and x.get("kev_added") == prev else "")
        carry.append(x)

    checks = dict(s.get("checks", {}))
    checks["microsoft_split_sums_to_headline"] = sum(split.values()) == c["microsoft_install_needed"]
    checks["band_counts_match_lists"] = (c["P1"], c["P2"], c["P3"]) == (len(p1), len(p2), len(p3))
    checks["p4_breakdown_sums"] = sum(c["P4_by_severity"].values()) == c["P4"]

    y, mon = month.split("-")
    facts = {
        "month": month, "month_name": f"{MONTHS[mon]} {y}", "month_word": MONTHS[mon],
        "release": s["release"], "release_uk": s["release_uk"], "generated": s["generated"],
        "sha": sha, "sha7": sha[:7],
        "data_url": f"https://github.com/PrivSter/patch-tuesday/tree/{sha}/data/{month}" if sha else "",
        "kev_catalog": {"version": kev.get("catalogVersion"), "released": kev_rel},
        "repo_kev_catalog": s.get("kev_catalog"),
        "deadlines": s["deadlines"], "counts": c,
        "P1": p1, "P2": p2, "P3": p3,
        "zero_days": zero, "carryover": carry, "windows_cu": cu_rows, "windows_cu_source": best_cve,
        "flags": flags, "checks": checks, "ok": bool(s.get("ok")) and all(checks.values()),
        "kev_band_change": band_change,
    }
    if not facts["ok"]:
        return facts, 4
    if band_change:
        return facts, 5
    return facts, 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, type=Path)
    ap.add_argument("--kev", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--sha", default="")
    ap.add_argument("--month", help="expected month, e.g. 2026-Nov")
    ap.add_argument("--offline", action="store_true")
    a = ap.parse_args(argv)
    for f in ("summary.json", "products.json", "records.json.gz"):
        if not (a.data / f).exists():
            print(f"MISSING {f} in {a.data}")
            return 4
    opener = gzip.open if str(a.kev).endswith(".gz") else open
    kev = json.load(opener(a.kev, "rt", encoding="utf-8"))
    facts, rc = build(a.data, kev, a.sha, a.offline)
    if a.month and facts["month"] != a.month:
        print(f"WRONG MONTH: data is {facts['month']}, expected {a.month}")
        return 4
    a.out.parent.mkdir(parents=True, exist_ok=True)
    json.dump(facts, open(a.out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    c = facts["counts"]
    print(json.dumps({"month": facts["month"], "ok": facts["ok"], "headline": c["microsoft_install_needed"],
                      "P1": c["P1"], "P2": c["P2"], "P3": c["P3"], "P4": c["P4"], "kev_listed": c["kev_listed"],
                      "kev_band_change": facts["kev_band_change"],
                      "failed_checks": [k for k, v in facts["checks"].items() if not v],
                      "p1_live": {r["cve"]: r["live"]["note"] for r in facts["P1"]}, "out": str(a.out)}))
    if rc == 5:
        print("KEV MOVES CVEs INTO P1: " + ", ".join(facts["kev_band_change"]) + " - re-run the collector and rebuild facts")
    return rc


if __name__ == "__main__":
    sys.exit(main())
