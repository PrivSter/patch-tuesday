#!/usr/bin/env python3
"""Patch Tuesday report loop - the email to Dave's work inbox.

  python3 report/mailout.py <workdir>/report.json <report.pdf> <artifact_url> > <workdir>/email.json

Writes the email as JSON: to, subject, body (plain text) and the PDF attachment
as a Gmail file reference ("sha256:<hex>:<absolute path>"), plus the minimum
size the sent message must reach for the attachment to be whole. Every figure
comes from report.json (the gate's output), so nothing is typed by hand.

The PDF, not the HTML page, is attached: the CAA's mail filter blocks HTML files.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

TO = "david.privett@caa.co.uk"


def build(rep: dict, pdf: Path, url: str) -> dict:
    f, v = rep["facts"], rep["verification"]
    c, d = f["counts"], f["deadlines"]
    zx = sum(1 for z in f["zero_days"] if z.get("exploited") == "Yes")
    zero = c["zero_days_total"]
    subject = (f"Patch Tuesday {f['month_name']}: {zero} zero-day{'s' if zero != 1 else ''}"
               + (f" ({zx} exploited)" if zero and zx != zero else "")
               + f", {c['P1']} P1 / {c['P2']} P2")
    lines = [f"Patch Tuesday {f['month_name']} (Microsoft release {f['release_uk']})", ""]
    lines += ["BOTTOM LINE", rep["bottom_line"]["text"]]
    if not rep["bottom_line"]["verified"]:
        lines.append("(Built from the data: the written bottom line did not pass its checks.)")
    lines += ["", "DEADLINES",
              f"P1 ({c['P1']}): {d['P1']['uk']}; internet-facing and automatable {d['P1_internet']['uk']}",
              f"P2 ({c['P2']}): {d['P2']['uk']}; internet-facing {d['P2_internet']['uk']}",
              f"P3 ({c['P3']}) and P4 ({c['P4']:,}): {d['P3']['uk']} (Cyber Essentials, mandatory)",
              "", f"Headline figure: {c['microsoft_install_needed']:,} Microsoft CVEs need an update installed.", ""]
    if f["P1"]:
        lines.append("P1")
        for r in f["P1"]:
            name = r.get("title") or ""
            if len(name) > 110:
                name = f"{r.get('component') or 'third-party'} record ({r.get('issuingCna') or 'other organisation'})"
            why = "exploited per Microsoft" if r.get("exploited") == "Yes" else ""
            if r.get("kev"):
                why = (why + ", " if why else "") + f"in CISA KEV since {r['kev']['dateAdded']}"
            lines.append(f"- {r['cve']}: {name} ({why})")
        lines.append("")
    if f["carryover"]:
        lines.append("EXPLOITED SINCE EARLIER RELEASES")
        for x in f["carryover"]:
            lines.append(f"- {x['cve']}: {x.get('title')} (Cyber Essentials due {(x.get('cyber_essentials_due') or '')[:10]}"
                         + (", OVERDUE" if x.get("overdue") else "") + ")")
        lines.append("")
    lines += ["HOW IT WAS CHECKED", v["line"]]
    if v["notes"]:
        lines.append("Not verified or dropped: " + "; ".join(v["fallbacks"] + v["dropped"]) + " (see Verification notes in the PDF).")
    src = (f"Data: patch-tuesday repo commit {f['sha7']}" if f.get("sha7")
           else "Data: collected by this run with the repo's collector (the repo's copy was missing or pre-release)")
    lines += ["", src, f"Full report (Claude, opens outside the CAA network): {url}",
              "The A4 PDF of the full report is attached."]
    data = pdf.read_bytes()
    b64_len = (len(data) + 2) // 3 * 4
    return {"to": [TO], "subject": subject, "body": "\n".join(lines),
            "attachment": {"filename": pdf.name, "mimeType": "application/pdf",
                           "content": f"sha256:{hashlib.sha256(data).hexdigest()}:{pdf.resolve()}"},
            "pdf_bytes": len(data), "min_message_size": b64_len + len("\n".join(lines))}


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    rep = json.load(open(sys.argv[1], encoding="utf-8"))
    print(json.dumps(build(rep, Path(sys.argv[2]), sys.argv[3]), indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
