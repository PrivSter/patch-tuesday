#!/usr/bin/env python3
"""Patch Tuesday report loop - the renderer.

  python3 report/render.py <workdir>/report.json <out.html>

Builds the report page from report.json alone. Every number, table and deadline
comes from facts (code-built); every sentence of narrative comes from an item the
gate passed, or from the gate's mechanical fallback. Nothing is typed by hand, so
the page can't drift from what was checked. The design and print CSS are in
page.css (the layout of the October 2026 report).
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

E = lambda s: html.escape("" if s is None else str(s))  # noqa: E731
HERE = Path(__file__).parent


def a(url, text, cls=""):
    c = f' class="{cls}"' if cls else ""
    return f'<a{c} href="{E(url)}" target="_blank" rel="noopener">{E(text)}</a>'


def cve_link(cve):
    return a(f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}", cve, "mono")


def n(x):
    return f"{x:,}" if isinstance(x, int) else E(x)


def table(cls, heads, rows):
    th = "".join(f"<th>{E(h)}</th>" for h in heads)
    body = "".join("<tr>" + "".join(f"<td{c}>{v}</td>" for c, v in r) + "</tr>" for r in rows)
    return f'<div class="tbl {cls}"><table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'


def render(rep: dict) -> str:
    f, v = rep["facts"], rep["verification"]
    c, d = f["counts"], f["deadlines"]
    month_name, word = f["month_name"], f["month_word"]
    year = f["month_name"].split()[-1]
    pdf = f"Patch_Tuesday_{word}_{year}.pdf"
    kev = f.get("kev_catalog") or {}
    kev_txt = f"{kev.get('version')}, released {(kev.get('released') or '')[:16].replace('T', ' ')} UTC"
    news = ", ".join(t["source"] for t in rep["totals"] if t.get("source")) or "no news source"
    o = []
    w = o.append

    # Header
    w('<main class="wrap"><header class="top">')
    w(f'<span class="eyebrow">Microsoft security release · {E(f["release_uk"])}</span>')
    w(f"<h1>Patch Tuesday {E(month_name)}</h1>")
    data_link = a(f["data_url"], f"commit {f['sha7']}, collected {f['generated'][:19].replace('T', ' ')} UTC") if f.get("data_url") else E(f"collected {f['generated']}")
    tool = f" (tooling {E(rep['tooling_sha'][:7])})" if rep.get("tooling_sha") else ""
    w(f'<p class="meta"><a class="pdf" href="{E(pdf)}" target="_blank" rel="noopener">PDF version (A4) · </a>'
      f"Built from the patch-tuesday repo data ({data_link}) · KEV catalogue {E(kev_txt)} · "
      f"news checked against {E(news)} · checked by the writer/checker loop{tool}</p></header>")

    # Verification box
    w('<section class="vbox"><b class="t">How this report was checked</b>')
    w(f"<span>{E(v['line'])}</span>")
    if v["notes"]:
        w("<span>See Verification notes at the end for what was not verified.</span>")
    w("</section>")

    # Bottom line
    bl = rep["bottom_line"]
    w('<section class="bottom"><h2>Bottom line</h2>')
    w(f"<p>{E(bl['text'])}</p>")
    if not bl["verified"]:
        w('<p class="note unv">Built mechanically from the data: the written bottom line did not pass its checks.</p>')
    w("</section>")

    # Numbers
    split = c["microsoft_by_band"]
    w("<section><h2>Numbers</h2>")
    w(f'<p class="headline">Headline figure: {n(c["microsoft_install_needed"])} CVEs</p>')
    w("<p>Microsoft's own CVEs this month that need an update installed. This is the number to quote.</p>")
    w(f'<p class="note">Microsoft CVEs by band: P1 {n(split["P1"])} + P2 {n(split["P2"])} + P3 {n(split["P3"])} + '
      f'P4 {n(split["P4"])} = {n(sum(split.values()))}. The band tiles count every record that needs action, so P4 also '
      f'includes {n(c["P4_by_severity"].get("unrated", 0))} unrated records, most of them issued by other organisations '
      f'({n(c["other_organisations"])} records this month) for components Microsoft ships.</p>')
    w(f'<div class="ce"><b>Cyber Essentials deadline: {E(d["cyber_essentials"]["uk"])}</b><span>All Critical and High fixes, '
      "and every bundled update (each Windows cumulative update and Office update), must be installed by then to keep certification.</span></div>")
    zx = sum(1 for z in f["zero_days"] if z["exploited"] == "Yes")
    zd = sum(1 for z in f["zero_days"] if z["publiclyDisclosed"] == "Yes" and z["exploited"] != "Yes")
    tiles = [("", "Headline", c["microsoft_install_needed"], "CVEs to install"),
             ("s1", "Zero-days", c["zero_days_total"], f"{zx} exploited, {zd} publicly disclosed"),
             ("", "KEV", c["kev_listed"], "this month's CVEs in KEV"),
             ("", "Critical", c["critical_customer_action"], "need customer action"),
             ("s1", "P1", c["P1"], d["P1"]["uk"]), ("s2", "P2", c["P2"], d["P2"]["uk"]),
             ("s3", "P3", c["P3"], d["P3"]["uk"]), ("s4", "P4", c["P4"], d["P4"]["uk"])]
    w('<div class="stats">' + "".join(f'<div class="stat {k}"><span class="lab">{E(l)}</span><b>{n(x)}</b><span class="sub">{E(s)}</span></div>'
                                      for k, l, x, s in tiles) + "</div>")
    p1sev = sorted({r.get("severity") or "unrated" for r in f["P1"]})
    w('<p class="legend"><b>Zero-days</b> count exploited plus publicly disclosed CVEs, as Microsoft and the news sites do. '
      "Only exploited ones (or KEV-listed ones) are P1; publicly disclosed ones are P2.</p>")
    w('<p class="legend"><b>P1</b> patch now · <b>P2</b> patch this week · <b>P3</b> patch within 14 days · <b>P4</b> patch in the '
      "monthly cycle, still within 14 days. Bands set how fast to patch, not how severe a flaw is"
      + (f": this month's P1 is rated {E(' / '.join(p1sev))}." if f["P1"] else ".") + "</p>")
    w("<h3>Deadlines by band</h3><div class=\"due\">")
    for k, band, extra in (("d1", "P1", f"internet-facing: {d['P1_internet']['uk']}"), ("d2", "P2", f"internet-facing: {d['P2_internet']['uk']}"),
                           ("d3", "P3", "mandatory, Cyber Essentials"), ("d4", "P4", "mandatory where CVSS ≥ 7.0, unrated or bundled")):
        w(f'<div class="{k}"><span class="lab">{band} · {n(c[band])}</span><b>{E(d[band]["uk"])}</b><span>{E(extra)}</span></div>')
    w("</div>")
    sev = c["P4_by_severity"]
    w(f'<p class="note">P4 is counted, not listed: ' + ", ".join(f"{n(x)} {E(k)}" for k, x in sev.items())
      + f' ({n(c["P4"])} in all). {n(c["P3_preauth_high_complexity"])} of the {n(c["P3"])} P3 items are pre-authentication '
      'network flaws with high attack complexity that Microsoft does not rate "Exploitation More Likely".</p>')
    w("<h3>Why the totals differ</h3>")
    rows = [[("", "Microsoft Update Guide (repo data)"),
             ("", f"All records {n(c['all'])} · Microsoft-issued {n(c['microsoft'])} · <b>install needed {n(c['microsoft_install_needed'])}</b> · "
                  f"Chrome {n(c['chrome'])} · other organisations {n(c['other_organisations'])}"),
             ("", f"{n(c['critical_all_records'])} Critical in all records ({n(c['critical_microsoft_issued'])} Microsoft-issued); "
                  f"{n(c['critical_customer_action'])} need customer action"),
             (' class="small"', "Every record in the release, including those published earlier in the month and those issued by other organisations.")]]
    for t in rep["totals"]:
        cls = ' class="num"' if t["verified"] else ' class="unv"'
        rows.append([("", a(t["url"], t["source"]) if t.get("url") else E(t["source"])), (cls, E(t["total"])),
                     (cls, E(t["critical"])), (' class="small"', E(t["note"]) if t["verified"] else '<span class="unv">Not verified</span>')])
    w(table("tot", ["Source", "Total", "Critical", "What it says it counts or excludes"], rows))
    w('<p class="note">Each source counts different things. Reasons are given only where a source states them.</p>')
    for nt in rep["notes"]:
        w(f'<p class="note"><b>{E(nt["heading"])}</b>: {E(nt["text"])}</p>')
    w("</section>")

    # P1
    w('<section><span class="eyebrow">Band P1 · NCSC active-exploitation timeline</span><h2>P1: exploited</h2>')
    if not f["P1"]:
        w("<p>None this month: no CVE in this release is marked exploited by Microsoft or listed in CISA KEV.</p>")
    else:
        w('<p class="note">The NCSC table formally applies to KEV-listed flaws exploited in business-critical systems. '
          "This report applies it to Microsoft-exploited CVEs too.</p>")
    for r in f["P1"]:
        k = r.get("kev")
        kev_s = (f"Added {k['dateAdded']}, CISA due {k['dueDate']}, known ransomware use: {k.get('ransomware')}"
                 + (f", forensic triage: {k['forensicTriage']}" if k.get("forensicTriage") else "")
                 + (f". CISA name: {k['name']}" if k.get("name") else "")) if k else "Not listed in the KEV catalogue used for this report"
        live = r.get("live") or {}
        live_s = {True: '<span class="okc">Matches</span> Microsoft\'s live record', False: '<span class="unv">Differs</span> from Microsoft\'s live record: '}.get(live.get("ok"), '<span class="unv">Not re-checked</span>: ')
        live_s += "" if live.get("ok") else E(live.get("note"))
        cr = rep["credits"].get(r["cve"], {"text": "No verified credit or attribution this run.", "verified": False})
        fields = [("Component", E(r.get("component"))), ("Severity / impact", f"{E(r.get('severity'))} · {E(r.get('impact'))}"),
                  ("CVSS", f"<b>{E(r.get('baseScore'))}</b> <span class=\"mono small\">{E(r.get('vector'))}</span>"),
                  ("Microsoft", f"Exploited: {E(r.get('exploited'))} · Publicly disclosed: {E(r.get('publiclyDisclosed'))} · {E(r.get('exploitability'))}"),
                  ("Live re-check", live_s),
                  ("Deadline", f"<span class=\"req\">{E(d['P1']['uk'])}</span> (48 h) · internet-facing and automatable: "
                               f"<span class=\"req\">{E(d['P1_internet']['uk'])}</span> (24 h). Investigate for compromise as well as patching."),
                  ("How it's attacked", E(r.get("attack")) + ' <span class="small note">(read from the CVSS vector)</span>'),
                  ("Root cause", E("; ".join(r.get("cwe") or []) or "No CWE given")),
                  ("Affects", E(r.get("affects"))), ("Fix", "<br>".join(E(x) for x in r.get("fix") or [])),
                  ("KBs", E(", ".join(r.get("kbs") or []) or "none listed")), ("KEV", E(kev_s)),
                  ("Credit / attribution", ("" if cr["verified"] else '<span class="unv">') + E(cr["text"]) + ("" if cr["verified"] else "</span>")
                   + (' <span class="small note">(secondary reporting)</span>' if cr["verified"] else ""))]
        dl = "".join(f"<dt>{E(k_)}</dt><dd>{v_}</dd>" for k_, v_ in fields)
        w(f'<article class="card"><header><span class="band b1">P1</span><h3>{cve_link(r["cve"])} {E(r.get("title"))}</h3></header><dl>{dl}</dl></article>')
    w("</section>")

    # P2
    w(f'<section><span class="eyebrow">Band P2 · NCSC update by default</span><h2>P2: due {E(d["P2"]["uk"])} · internet-facing {E(d["P2_internet"]["uk"])}</h2>')
    ach = [r for r in f["P2"] if any(x.startswith("AC:H") for x in r.get("chips", []))]
    exc = (" The AC:H exceptions are " + ", ".join(f"{cve_link(r['cve'])} ({E(r.get('component'))})" for r in ach)
           + ', rated "Exploitation More Likely".') if ach else ""
    w('<p class="note">P2 is publicly disclosed CVEs, plus Critical flaws reachable over the network with no login and no user action '
      f'(AV:N/PR:N/UI:N) that are either low complexity (AC:L) or rated "Exploitation More Likely".{exc}</p>')
    rows = []
    for r in f["P2"]:
        chips = "".join(f'<br><span class="chip">{E(x)}</span>' for x in r.get("chips", []))
        rows.append([("", cve_link(r["cve"]) + chips), ("", E(r.get("component"))), (' class="num"', E(r.get("baseScore"))),
                     ("", E(r.get("severity"))), (' class="small"', E(r.get("affects", ""))),
                     (' class="small"', "<br>".join(E(x) for x in r.get("fix") or []))])
    w(table("p2", ["CVE", "Component", "CVSS", "Microsoft rating", "Affects", "Fix"], rows) if rows else "<p>None this month.</p>")
    if f["windows_cu"]:
        w(f"<h3>Windows cumulative updates, {E(month_name)}</h3>")
        w(f'<p class="note">Taken from {cve_link(f["windows_cu_source"])}, which covers every listed Windows version.</p>')
        w(table("cu", ["Windows version", "Cumulative update", "Fixed build"],
                [[("", E(x["version"])), (' class="mono"', E(x["kb"])), (' class="mono"', E(x["build"]))] for x in f["windows_cu"]]))
    w("</section>")

    # Carry-overs, reconciliation, flags
    w("<section><h2>Exploited since earlier releases</h2>")
    if f["carryover"]:
        w('<p class="note">Microsoft CVEs added to KEV since the previous Patch Tuesday that belong to earlier releases. '
          "The 14-day Cyber Essentials deadline runs from each CVE's own release.</p>")
        w(table("", ["CVE", "Title", "Release", "CVSS", "MS exploited", "KEV added / CISA due", "Ransomware", "Cyber Essentials due", "Note"],
                [[("", cve_link(x["cve"])), ("", E(x.get("title"))), ("", E(x.get("release"))), (' class="num"', E(x.get("baseScore"))),
                  ("", E(x.get("microsoft_exploited"))), (' class="mono small"', f"{E(x.get('kev_added'))} / due {E(x.get('kev_due'))}"),
                  ("", E(x.get("ransomware"))),
                  ("", E((x.get("cyber_essentials_due") or "")[:10]) + (' <b class="over">OVERDUE</b>' if x.get("overdue") else "")),
                  (' class="small"', E(x.get("note")))] for x in f["carryover"]]))
    else:
        w("<p>None.</p>")
    w("<h3>Zero-day reconciliation</h3>")
    w('<p class="note">Microsoft\'s record wins for CVE facts. News attribution is secondary reporting.</p>')
    srcs = rep["zero_day_sources"]
    rows = []
    for z in rep["zero_day_rows"]:
        cells = []
        for s in srcs:
            cell = z["cells"].get(s, {"text": "Not mentioned", "verified": True})
            cells.append((' class="small"', E(cell["text"]) if cell["verified"] else '<span class="unv">Not verified</span>'))
        rows.append([("", cve_link(z["cve"]) + (f'<br><span class="small">{E(z["title"])}</span>' if z["title"] else "")),
                     (' class="small"', E(z["microsoft"])), (' class="small"', E(z["kev"]))] + cells + [(' class="small"', E(z["agree"]))])
    w(table("", ["CVE", "Microsoft", f"KEV ({kev.get('version')})"] + srcs + ["Agree?"], rows) if rows else "<p>No zero-days this month.</p>")
    w("<h3>Data-quality flags</h3><ul class=\"flags\">")
    items = []
    for fl in f["flags"]:
        who = "Repo flag" if fl.get("origin") == "repo" else "Script flag"
        items.append(f"<li><b>{who}</b>: " + (cve_link(fl["cve"]) + ": " if fl.get("cve") else "") + E(fl["flag"]) + "</li>")
    for fd in rep["findings"]:
        items.append("<li><b>Our finding</b>: " + (cve_link(fd["cve"]) + ": " if fd.get("cve") else "") + E(fd["text"]) + "</li>")
    w("".join(items) or "<li>None found.</li>")
    w("</ul></section>")

    # P3 and P4
    w(f'<section><span class="eyebrow">Band P3 · Cyber Essentials v3.3</span><h2>P3: {n(c["P3"])} Critical, due {E(d["P3"]["uk"])} (mandatory)</h2>')
    w(table("p3", ["CVE", "Component", "Impact", "CVSS", "Vector", "Microsoft exploitability"],
            [[("", cve_link(r["cve"])), ("", E(r.get("component"))), ("", E(r.get("impact"))), (' class="num"', E(r.get("baseScore"))),
              (' class="mono small"', E(r.get("vector_short"))), (' class="small"', E(r.get("exploitability")))] for r in f["P3"]])
      if f["P3"] else "<p>None this month.</p>")
    w(f'<div class="p4"><b>P4: {n(c["P4"])}</b>, counted not listed: ' + ", ".join(f"{n(x)} {E(k)}" for k, x in sev.items())
      + f". Due {E(d['P4']['uk'])}: mandatory where CVSS is 7.0 or above, no severity is given, or the fix ships in a bundled update.</div>")
    w("</section>")

    # Deadline basis
    w("<section><h2>Deadline basis</h2>")
    w(f'<p class="note">All deadlines count from Microsoft\'s release, {E(f["release_uk"])}. The 14-day clock is defined from vendor release; '
      "the NCSC does not define a start, so using release for every band is an assumption.</p>")
    basis = [("Cyber Essentials v3.3 (A6.4, A6.5)", "must", "Mandatory", "P3, P4 and the 14-day floor for every band",
              "https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf", "NCSC: Cyber Essentials requirements for IT infrastructure v3.3"),
             ("NCSC, responding to active exploitation", "guide", "Guidance", "P1: 48 h, 24 h if internet-facing and automatable",
              "https://www.ncsc.gov.uk/collection/vulnerability-management", "NCSC vulnerability management guidance"),
             ("NCSC update by default", "guide", "Guidance", "P2: 7 days, 5 days if internet-facing",
              "https://www.ncsc.gov.uk/collection/vulnerability-management/guidance/policy-update-by-default", "NCSC: policy, update by default"),
             ("MOD Defence Cyber Certification Level 0", "must", "Mandatory for MOD suppliers", "Requires Cyber Essentials, so the 14-day rule binds defence suppliers",
              "https://iasme.co.uk/defence-cyber-certification", "IASME: Defence Cyber Certification")]
    w(table("", ["Source", "Status", "Bands", "Link"],
            [[("", E(s)), ("", f'<span class="pill {k}">{E(st)}</span>'), ("", E(b)), (' class="small"', a(u, t))] for s, k, st, b, u, t in basis]))
    w("</section>")

    # Verification notes
    w("<section><h2>Verification notes</h2>")
    w(f"<p>{E(v['line'])}</p>")
    w(f'<p class="note">Check rounds run: {v["rounds"]} of {v["max_rounds"]}. Source checks compare each claim with the exact words on its '
      "linked page; wording checks compare what the page shows with the checked claims. Figures cited in the narrative are matched to the data by script.</p>")
    if v["notes"]:
        w('<ul class="vnotes">' + "".join(f"<li>{E(x)}</li>" for x in v["notes"]) + "</ul>")
    else:
        w("<p>Every narrative item passed its checks.</p>")
    w("</section>")

    # Sources
    w('<section><h2>Sources</h2><ul class="src">')
    if f.get("data_url"):
        w(f"<li>Repo data: {a(f['data_url'], 'PrivSter/patch-tuesday @ ' + f['sha7'])}, data/{E(f['month'])}, collected {E(f['generated'][:19].replace('T', ' '))} UTC</li>")
    w(f"<li>Microsoft Security Update Guide: {a('https://msrc.microsoft.com/update-guide', 'msrc.microsoft.com/update-guide')}; "
      "P1 re-checked live against the MSRC API at this run</li>")
    w(f"<li>CISA Known Exploited Vulnerabilities catalogue, version {E(kev_txt)}: {a('https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'cisa.gov KEV')}</li>")
    for s in rep["sources"]:
        w(f"<li>{a(s['url'], s.get('title') or s['url'])}</li>")
    w("</ul></section></main>")

    snap = {"month": f["month"], "source": f"github.com/PrivSter/patch-tuesday@{f['sha7']}",
            "p1": [r["cve"] for r in f["P1"]], "p2": [r["cve"] for r in f["P2"]], "p3": [r["cve"] for r in f["P3"]],
            "disclosed": [z["cve"] for z in f["zero_days"] if z["publiclyDisclosed"] == "Yes"],
            "kev": [z["cve"] for z in f["zero_days"] if z.get("kev")], "p4_counts": c["P4_by_severity"],
            "scores": {r["cve"]: r.get("baseScore") for b in ("P1", "P2", "P3") for r in f[b]},
            "verification": {k: v[k] for k in ("claims_checked", "first_pass", "corrected", "fallbacks", "dropped")}}
    snap_json = json.dumps(snap, ensure_ascii=False).replace("</", "<\\/")

    css = (HERE / "page.css").read_text(encoding="utf-8")
    # A fragment: the Artifact publisher wraps it in the document skeleton (topdf.js does the same for the PDF).
    head = (f"<title>Patch Tuesday {E(month_name)}</title>"
            '<meta name="claude:viewport-fit-sides" content="cover">'
            '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
            '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;700;800&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">'
            f"<style>{css}</style>\n")
    return head + "\n".join(o) + f'\n<script type="application/json" id="pt-snapshot">{snap_json}</script>\n'


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    rep = json.load(open(sys.argv[1], encoding="utf-8"))
    Path(sys.argv[2]).write_text(render(rep), encoding="utf-8")
    print(f"wrote {sys.argv[2]}")


if __name__ == "__main__":
    main()
