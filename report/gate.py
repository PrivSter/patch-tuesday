#!/usr/bin/env python3
"""Patch Tuesday report loop - the gate.

The writer never decides the report is finished. This script does, from the
checkers' verdict files, using exact text hashes so anything edited after it
was checked counts as unchecked. Modelled on InfoSec Daily Brief V2's gate.

  gate.py prepare <workdir> <round>   write check/round-N/{claims,items}.json with only
                                      what hasn't been checked in its current wording
  gate.py status  <workdir>           list what is failing or unchecked;
                                      exit 0 if everything passes, 3 otherwise
  gate.py final   <workdir>           write report.json for the renderer

The split rule (Dave, 14 Oct 2026): CVEs, bands, scores and deadlines come from
facts.json, which code built from Microsoft's data. They are never dropped. Only
the writer's narrative is checked by the agents, and when it still fails after
three rounds:
  - bottom line           -> replaced by a mechanical bottom line built from facts
  - credit (P1 cards)     -> "no verified credit or attribution"; the card stays
  - news totals / zero-day cells -> shown as "not verified"; the row stays
  - notes and findings    -> dropped
Every fallback and drop is listed in the report's Verification section.

Workdir layout:
  facts.json                 from facts.py
  draft.json                 the writer's narrative, with claims
  check/round-N/claims.json  input for the source checker
  check/round-N/items.json   input for the coverage checker
  check/round-N/source_verdicts.json    written by the source checker
  check/round-N/coverage_verdicts.json  written by the coverage checker
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import sys

PASS_SOURCE = {"SUPPORTED", "INFERENCE_OK"}
MAX_ROUNDS = 3
TYPES = {"bottom_line", "source_total", "zero_day", "credit", "note", "finding"}
ZD_STATUS = {"exploited", "disclosed", "exploited_and_disclosed", "not_listed"}
STATUS_WORDS = {"exploited": "exploited", "disclosed": "publicly disclosed",
                "exploited_and_disclosed": "exploited and publicly disclosed", "not_listed": "not listed as a zero-day"}


def h(*parts) -> str:
    return hashlib.sha256("␟".join("" if p is None else str(p) for p in parts).encode()).hexdigest()[:16]


def load(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)


# ---------------------------------------------------------------- facts lookups

def resolve(facts: dict, ref: str):
    """'counts.P2', 'deadlines.P1.uk', 'P1[CVE-2026-1].baseScore', 'windows_cu[Server 2019].kb'."""
    cur = facts
    for part in re.findall(r"[^.\[\]]+|\[[^\]]+\]", ref or ""):
        if part.startswith("["):
            key = part[1:-1]
            if not isinstance(cur, list):
                raise KeyError(ref)
            hit = [x for x in cur if isinstance(x, dict) and key in (x.get("cve"), x.get("version"))]
            if not hit:
                raise KeyError(ref)
            cur = hit[0]
        else:
            if not isinstance(cur, dict) or part not in cur:
                raise KeyError(ref)
            cur = cur[part]
    return cur


def norm(v) -> str:
    if isinstance(v, (list, dict)):
        return json.dumps(v, sort_keys=True)
    return re.sub(r"[,\s]", "", str(v)).lower()


# ---------------------------------------------------------------- items

def display(it: dict) -> str:
    """Exactly what the page will show for this item - the coverage checker judges this."""
    t = it.get("type")
    if t == "bottom_line":
        return it.get("text", "")
    if t == "source_total":
        return (f"{it.get('source')} gives a total of {it.get('total')} CVEs and {it.get('critical')} Critical. "
                f"What it says it counts or excludes: {it.get('note') or 'nothing stated'}")
    if t == "zero_day":
        return (f"{it.get('source')} on {it.get('cve')}: {it.get('text')} "
                f"(the reconciliation table records this source as saying the CVE is {STATUS_WORDS.get(it.get('status'), it.get('status'))})")
    if t == "credit":
        return f"Credit or attribution for {it.get('cve')}: {it.get('text')}"
    if t == "note":
        return f"{it.get('heading')}: {it.get('text')}"
    return it.get("text", "")


def label(it: dict) -> str:
    t = it.get("type")
    return {"bottom_line": "Bottom line",
            "source_total": f"{it.get('source')} totals",
            "zero_day": f"{it.get('source')} on {it.get('cve')}",
            "credit": f"Credit / attribution for {it.get('cve')}",
            "note": f"Note: {it.get('heading')}",
            "finding": "Finding" + (f" on {it.get('cve')}" if it.get("cve") else "")}.get(t, t or "item")


def claim_hash(c: dict) -> str:
    return h(c.get("text"), c.get("kind"), c.get("source_url"), c.get("ref"))


def item_hash(it: dict) -> str:
    claims = "|".join(f"{c.get('id')}={c.get('kind')}:{c.get('text')}" for c in it.get("claims", []))
    return h(it.get("type"), display(it), claims)


def all_verdicts(workdir: str):
    src, cov = {}, {}
    rounds = sorted(glob.glob(os.path.join(workdir, "check", "round-*")), key=lambda p: int(p.rsplit("-", 1)[1]))
    for r in rounds:
        for v in load(os.path.join(r, "source_verdicts.json"), []) or []:
            src[v.get("hash")] = v
        for v in load(os.path.join(r, "coverage_verdicts.json"), []) or []:
            cov[v.get("hash")] = v
    return src, cov, len(rounds)


def structural(draft: dict, facts: dict) -> dict[str, list[str]]:
    """Mechanical rules, no model involved. Returns {item_id: [problems]}."""
    out: dict[str, list[str]] = {}
    src_urls = [s.get("url") for s in draft.get("sources", [])]
    claimed_urls = set()
    seen_claims, seen_items = set(), set()
    p1 = {r["cve"] for r in facts.get("P1", [])}
    known = p1 | {r["cve"] for b in ("P2", "P3") for r in facts.get(b, [])} | \
        {z["cve"] for z in facts.get("zero_days", [])} | {c["cve"] for c in facts.get("carryover", [])}
    bottoms = 0
    for it in draft.get("items", []):
        iid = it.get("id") or "?"
        probs = out.setdefault(iid, [])
        if iid in seen_items:
            probs.append(f"duplicate item id {iid}")
        seen_items.add(iid)
        t = it.get("type")
        if t not in TYPES:
            probs.append(f"type must be one of {sorted(TYPES)}")
        if t == "bottom_line":
            bottoms += 1
            for cve in set(re.findall(r"CVE-\d{4}-\d+", it.get("text", ""))):
                if cve not in known:
                    probs.append(f"bottom line names {cve}, which is not a P1, P2, P3, zero-day or carry-over CVE in facts.json")
        if t == "source_total":
            for k in ("source", "url", "total", "critical"):
                if not it.get(k):
                    probs.append(f"source_total needs '{k}'")
            if it.get("url") and it["url"] not in src_urls:
                probs.append("source_total url is not listed in draft sources")
        if t == "zero_day":
            if it.get("status") not in ZD_STATUS:
                probs.append(f"zero_day status must be one of {sorted(ZD_STATUS)}")
            if not re.fullmatch(r"CVE-\d{4}-\d+", it.get("cve") or ""):
                probs.append("zero_day needs a cve")
            if not it.get("source"):
                probs.append("zero_day needs a source name")
        if t == "credit" and it.get("cve") not in p1:
            probs.append("credit items are only for P1 CVEs")
        if t in ("credit", "note", "finding", "bottom_line") and not (it.get("text") or "").strip():
            probs.append("text is empty")
        if t == "note" and not it.get("heading"):
            probs.append("note needs a heading")
        claims = it.get("claims") or []
        if not claims:
            probs.append("item has no claims")
        for c in claims:
            cid = c.get("id")
            if cid in seen_claims:
                probs.append(f"duplicate claim id {cid}")
            seen_claims.add(cid)
            k = c.get("kind")
            if k not in ("reported", "inference", "data"):
                probs.append(f"claim {cid}: kind must be reported, inference or data")
                continue
            if k == "data":
                try:
                    actual = resolve(facts, c.get("ref", ""))
                except KeyError:
                    probs.append(f"claim {cid}: ref '{c.get('ref')}' does not exist in facts.json")
                    continue
                if norm(actual) != norm(c.get("value")):
                    probs.append(f"claim {cid}: value '{c.get('value')}' does not match facts.json {c.get('ref')} = '{actual}'")
                continue
            u = c.get("source_url") or ""
            if k == "inference" and not u and c.get("ref"):
                try:
                    resolve(facts, c["ref"])
                except KeyError:
                    probs.append(f"claim {cid}: ref '{c.get('ref')}' does not exist in facts.json")
                continue
            if not u.startswith(("https://", "http://")):
                probs.append(f"claim {cid}: missing or invalid source_url")
            elif u not in src_urls:
                probs.append(f"claim {cid}: source_url not listed in draft sources")
            claimed_urls.add(u)
        if t == "source_total" and it.get("url") and it["url"] not in {c.get("source_url") for c in claims}:
            probs.append("no claim cites the source_total's own url")
    glob_probs = out.setdefault("_draft", [])
    if bottoms != 1:
        glob_probs.append(f"draft must have exactly one bottom_line item (has {bottoms})")
    for u in src_urls:
        if u not in claimed_urls:
            glob_probs.append(f"source {u} backs no claim (unchecked link)")
    return out


def assess(workdir: str):
    draft = load(os.path.join(workdir, "draft.json"))
    facts = load(os.path.join(workdir, "facts.json"))
    if draft is None or facts is None:
        sys.exit("need draft.json and facts.json in " + workdir)
    src, cov, nrounds = all_verdicts(workdir)
    probs = structural(draft, facts)
    report = []
    for it in draft.get("items", []):
        failing, unchecked = [], []
        for c in it.get("claims", []):
            if c.get("kind") == "data":
                continue  # checked mechanically in structural()
            v = src.get(claim_hash(c))
            if v is None:
                unchecked.append(c.get("id"))
            elif v.get("verdict") not in PASS_SOURCE:
                failing.append({"id": c.get("id"), "verdict": v.get("verdict"), "note": v.get("note", "")})
        cv = cov.get(item_hash(it))
        coverage = "unchecked" if cv is None else ("pass" if cv.get("pass") else "fail")
        p = probs.get(it.get("id") or "?", [])
        report.append({"item_id": it.get("id"), "type": it.get("type"), "label": label(it),
                       "ok": not p and not failing and not unchecked and coverage == "pass",
                       "structural": p, "failing_claims": failing, "unchecked_claims": unchecked,
                       "coverage": coverage, "coverage_issues": (cv or {}).get("issues", [])})
    return draft, facts, report, probs.get("_draft", []), nrounds


# ---------------------------------------------------------------- commands

def cmd_prepare(workdir: str, rnd: int):
    draft, facts = load(os.path.join(workdir, "draft.json")), load(os.path.join(workdir, "facts.json"))
    src, cov, _ = all_verdicts(workdir)
    out = os.path.join(workdir, "check", f"round-{rnd}")
    claims, items = [], []
    for it in draft.get("items", []):
        for c in it.get("claims", []):
            if c.get("kind") == "data":
                continue
            ch = claim_hash(c)
            if ch in src:
                continue
            entry = {"hash": ch, "claim_id": c.get("id"), "text": c.get("text"), "kind": c.get("kind")}
            if c.get("source_url"):
                entry["source_url"] = c["source_url"]
            elif c.get("ref"):
                try:
                    entry["basis"] = json.dumps(resolve(facts, c["ref"]), ensure_ascii=False)[:1500]
                except KeyError:
                    entry["basis"] = "(ref not found)"
            claims.append(entry)
        ih = item_hash(it)
        if ih not in cov:
            items.append({"hash": ih, "item_id": it.get("id"), "type": it.get("type"), "shown": display(it),
                          "claims": [{"id": c.get("id"), "kind": c.get("kind"), "text": c.get("text")}
                                     for c in it.get("claims", [])]})
    dump(os.path.join(out, "claims.json"), {"month": draft.get("month"), "release": facts.get("release"),
                                            "claims": claims})
    dump(os.path.join(out, "items.json"), {"items": items})
    print(json.dumps({"round": rnd, "claims_to_check": len(claims), "items_to_check": len(items), "dir": out}))


def cmd_status(workdir: str):
    draft, facts, report, draft_probs, nrounds = assess(workdir)
    bad = [r for r in report if not r["ok"]]
    print(json.dumps({"rounds_run": nrounds, "max_rounds": MAX_ROUNDS, "items_total": len(report),
                      "items_passing": len(report) - len(bad), "draft_problems": draft_probs,
                      "needs_work": bad}, indent=1, ensure_ascii=False))
    sys.exit(0 if not bad and not draft_probs else 3)


def reason(r: dict) -> str:
    bits = []
    bits += r["structural"]
    bits += [f"{f['verdict'].lower()}: {f['note']}".strip(": ") for f in r["failing_claims"]]
    if r["unchecked_claims"]:
        bits.append("not checked by the source checker")
    if r["coverage"] == "fail":
        bits += r["coverage_issues"] or ["wording says more than its checked claims"]
    elif r["coverage"] == "unchecked":
        bits.append("wording not checked")
    return "; ".join(b for b in bits if b) or "did not pass"


def mechanical_bottom_line(f: dict) -> str:
    d, c = f["deadlines"], f["counts"]
    if f["P1"]:
        names = ", ".join(f"{r['cve']} ({r.get('component') or r.get('title')})" for r in f["P1"])
        why = "exploited in the wild per Microsoft or listed in CISA KEV"
        s = (f"Patch {names} first: {why}, so due by {d['P1']['uk']} ({d['P1_internet']['uk']} where internet-facing "
             f"and automatable). ")
    else:
        s = "Nothing in this release is marked exploited by Microsoft or listed in CISA KEV. "
    s += f"Then deploy the {c['P2']} P2 items by {d['P2']['uk']}. "
    s += f"Everything else that needs installing is due by the Cyber Essentials deadline, {d['cyber_essentials']['uk']}."
    return s


def cmd_final(workdir: str):
    draft, f, report, draft_probs, nrounds = assess(workdir)
    src, _, _ = all_verdicts(workdir)
    status = {r["item_id"]: r for r in report}
    items = draft.get("items", [])
    ok = lambda it: status.get(it.get("id"), {}).get("ok", False)  # noqa: E731
    notes, fallbacks, dropped = [], [], []

    # Bottom line
    bl = next((it for it in items if it.get("type") == "bottom_line"), None)
    if bl and ok(bl):
        bottom = {"text": bl["text"], "verified": True}
    else:
        bottom = {"text": mechanical_bottom_line(f), "verified": False}
        r = status.get((bl or {}).get("id"), {})
        notes.append(f"Bottom line: the written version did not pass ({reason(r) if r else 'missing'}); "
                     "this one is built mechanically from the data.")
        fallbacks.append("bottom line")

    # News totals
    totals = []
    for it in (x for x in items if x.get("type") == "source_total"):
        if ok(it):
            totals.append({"source": it["source"], "url": it["url"], "total": it["total"], "critical": it["critical"],
                           "note": it.get("note") or "Does not state what the figure includes or excludes.", "verified": True})
        else:
            totals.append({"source": it.get("source"), "url": it.get("url"), "total": "not verified",
                           "critical": "not verified", "note": "", "verified": False})
            notes.append(f"{label(it)}: not verified ({reason(status[it['id']])}).")
            fallbacks.append(label(it))

    # Zero-day reconciliation rows: every Microsoft zero-day / KEV entry, plus any CVE a source names
    sources_named = list(dict.fromkeys(it.get("source") for it in items if it.get("type") == "zero_day"))
    zd_cves = [z["cve"] for z in f["zero_days"]]
    zd_cves += [it["cve"] for it in items if it.get("type") == "zero_day" and it.get("cve") not in zd_cves]
    zd_by = {z["cve"]: z for z in f["zero_days"]}
    rows = []
    for cve in dict.fromkeys(zd_cves):
        z = zd_by.get(cve)
        if z:
            ms = ("exploited_and_disclosed" if z["exploited"] == "Yes" and z["publiclyDisclosed"] == "Yes" else
                  "exploited" if z["exploited"] == "Yes" else "disclosed" if z["publiclyDisclosed"] == "Yes" else "not_listed")
        else:
            ms = "not_listed"
        cells, verdicts = {}, []
        for sname in sources_named:
            it = next((x for x in items if x.get("type") == "zero_day" and x.get("cve") == cve and x.get("source") == sname), None)
            if it is None:
                cells[sname] = {"text": "Not mentioned", "verified": True, "status": None}
                verdicts.append(f"{sname} does not mention it")
            elif ok(it):
                cells[sname] = {"text": it["text"], "verified": True, "status": it["status"]}
                if it["status"] != ms:
                    verdicts.append(f"{sname} says {STATUS_WORDS[it['status']]}")
            else:
                cells[sname] = {"text": "Not verified", "verified": False, "status": None}
                verdicts.append(f"{sname} not verified")
                notes.append(f"{label(it)}: not verified ({reason(status[it['id']])}).")
                fallbacks.append(label(it))
        agree = "Yes" if not verdicts else ("No: " if any(" says " in v for v in verdicts) else "Partly: ") + "; ".join(verdicts)
        rows.append({"cve": cve, "title": (z or {}).get("title") or "", "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
                     "microsoft": ("Exploited: {} · Disclosed: {}".format(z["exploited"], z["publiclyDisclosed"]) if z
                                   else "Not marked exploited or disclosed by Microsoft"),
                     "kev": (f"Listed {z['kev']}" if z and z.get("kev") else "Not listed"),
                     "cells": cells, "agree": agree})

    # Credits on P1 cards
    credits = {}
    for r1 in f["P1"]:
        its = [x for x in items if x.get("type") == "credit" and x.get("cve") == r1["cve"]]
        good = [x["text"] for x in its if ok(x)]
        for x in its:
            if not ok(x):
                notes.append(f"{label(x)}: removed ({reason(status[x['id']])}).")
                fallbacks.append(label(x))
        credits[r1["cve"]] = {"text": " ".join(good) if good else "No verified credit or attribution this run.",
                              "verified": bool(good)}

    # Notes and findings: kept only if they pass
    kept_notes, kept_findings = [], []
    for it in items:
        if it.get("type") not in ("note", "finding"):
            continue
        if ok(it):
            (kept_notes if it["type"] == "note" else kept_findings).append(
                {"heading": it.get("heading"), "text": it["text"], "cve": it.get("cve")})
        else:
            dropped.append(label(it))
            notes.append(f"{label(it)}: dropped ({reason(status[it['id']])}).")

    # Loop metrics (agent-checked claims in what was kept)
    # A kept claim counts as "corrected" if any earlier verdict on the same claim id failed;
    # otherwise it passed first time (including reuse of text that was already verified).
    failed_ids = set()
    verdict_counts: dict[str, int] = {}
    for r in sorted(glob.glob(os.path.join(workdir, "check", "round-*")), key=lambda p: int(p.rsplit("-", 1)[1])):
        for v in load(os.path.join(r, "source_verdicts.json"), []) or []:
            verdict_counts[v.get("verdict")] = verdict_counts.get(v.get("verdict"), 0) + 1
            if v.get("verdict") not in PASS_SOURCE:
                failed_ids.add(v.get("claim_id"))
    kept_items = [it for it in items if ok(it)]
    agent_claims = [c for it in kept_items for c in it.get("claims", []) if c.get("kind") != "data"]
    data_claims = [c for it in kept_items for c in it.get("claims", []) if c.get("kind") == "data"]
    first_pass = sum(1 for c in agent_claims if c.get("id") not in failed_ids)
    wording_fixes = sum(1 for r in glob.glob(os.path.join(workdir, "check", "round-*"))
                        for v in load(os.path.join(r, "coverage_verdicts.json"), []) or [] if not v.get("pass"))
    verification = {
        "rounds": nrounds, "max_rounds": MAX_ROUNDS,
        "claims_checked": len(agent_claims), "first_pass": first_pass, "corrected": len(agent_claims) - first_pass,
        "data_claims_matched": len(data_claims),
        "items_total": len(items), "items_passed": len(kept_items),
        "fallbacks": fallbacks, "dropped": dropped, "notes": notes, "verdict_counts": verdict_counts,
        "draft_problems": draft_probs,
        "wording_fixes": wording_fixes,
        "line": (f"{len(agent_claims)} news and judgement claims checked against their sources by a separate agent: "
                 f"{first_pass} passed first time, {len(agent_claims) - first_pass} corrected; "
                 f"a second agent checked the wording and asked for {wording_fixes} rewrites; "
                 f"{len(data_claims)} figures matched to the data by script; "
                 f"{len(fallbacks)} shown as not verified, {len(dropped)} dropped. "
                 "CVEs, bands and deadlines come from Microsoft's data and are never dropped."),
    }

    used = {c.get("source_url") for it in kept_items for c in it.get("claims", [])} | {t["url"] for t in totals if t["verified"]}
    sources = [s for s in draft.get("sources", []) if s.get("url") in used]
    out = {"facts": f, "bottom_line": bottom, "totals": totals, "zero_day_rows": rows, "zero_day_sources": sources_named,
           "credits": credits, "notes": kept_notes, "findings": kept_findings, "sources": sources,
           "verification": verification, "compiled_at": draft.get("compiled_at"),
           "tooling_sha": draft.get("tooling_sha", "")}
    dump(os.path.join(workdir, "report.json"), out)
    dump(os.path.join(workdir, "loop_run.json"), {"report": [dict(r) for r in report], "verification": verification})
    print(json.dumps({k: verification[k] for k in ("rounds", "claims_checked", "first_pass", "corrected",
                                                   "data_claims_matched", "fallbacks", "dropped")}, ensure_ascii=False))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd, wd = sys.argv[1], sys.argv[2]
    if cmd == "prepare":
        cmd_prepare(wd, int(sys.argv[3]))
    elif cmd == "status":
        cmd_status(wd)
    elif cmd == "final":
        cmd_final(wd)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
