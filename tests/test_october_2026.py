"""Known-answer test: October 2026, verified by hand against Microsoft on 13 Oct 2026.

If a change to the rules moves any of these numbers, the test fails and the
change has to be deliberate (update the expected values with a reason).
"""
import gzip
import json
from pathlib import Path

from pt import triage as T

FIX = Path(__file__).parent / "fixtures"
RECORDS = json.load(gzip.open(FIX / "2026-Oct" / "records.json.gz", "rt"))
KEV = json.load(gzip.open(FIX / "kev-2026.10.13-microsoft.json.gz", "rt"))
S = T.triage(RECORDS, KEV)


def test_self_checks_pass():
    assert S["ok"], S["checks"]


def test_headline_split():
    c = S["counts"]
    assert (c["all"], c["microsoft"], c["microsoft_install_needed"], c["chrome"], c["other_organisations"]) == \
        (1907, 1416, 1409, 0, 491)


def test_bands():
    c = S["counts"]
    assert (c["P1"], c["P2"], c["P3"]) == (1, 20, 61)
    assert c["critical_customer_action"] == 79
    assert c["P3_preauth_high_complexity"] == 13
    assert c["P4_by_severity"] == {"Important": 1328, "Moderate": 1, "unrated": 489}  # excludes the 3 in P1/P2


def test_p1_is_the_shell_zero_day():
    assert [r["cve"] for r in S["P1"]] == ["CVE-2026-96951"]
    assert S["P1"][0]["kev"] is None  # KEV snapshot predates the release


def test_disclosed_are_p2():
    p2 = {r["cve"] for r in S["P2"]}
    assert {"CVE-2026-92707", "CVE-2026-108398"} <= p2
    assert {"CVE-2026-70571", "CVE-2026-70229"} <= p2  # AC:H but "More Likely"


def test_deadlines_uk():
    d = S["deadlines"]
    assert S["release_uk"] == "Tue 13 Oct 2026, 15:00 BST"
    assert d["P1"]["uk"] == "Thu 15 Oct 2026, 15:00 BST"
    assert d["P1_internet"]["uk"] == "Wed 14 Oct 2026, 15:00 BST"
    assert d["P2"]["uk"] == "Tue 20 Oct 2026, 15:00 BST"
    assert d["P2_internet"]["uk"] == "Sun 18 Oct 2026, 15:00 BST"
    assert d["cyber_essentials"]["uk"] == "Tue 27 Oct 2026, 14:00 GMT"  # clocks go back 25 Oct


def test_flags():
    f = {(x["cve"], x["flag"]) for x in S["flags"]}
    assert ("CVE-2026-108131", "Critical with no CWE") in f
    assert any(c == "CVE-2026-87713" and "Remote Code Execution" in m for c, m in f)
    assert (None, "no Chrome-issued (Edge) records in this release") in f


def test_carryover_overdue_and_flagged():
    sp = {"cveNumber": "CVE-2026-65660", "cveTitle": "Microsoft SharePoint Server Remote Code Execution Vulnerability",
          "releaseNumber": "2026-Aug", "releaseDate": "2026-08-11T07:00:00-07:00", "baseScore": "8.8", "exploited": "No"}
    s = T.triage(RECORDS, KEV, [sp])
    (c,) = s["carryover"]
    assert c["overdue"] and c["cyber_essentials_due"].startswith("2026-08-25") and c["kev_added"] == "2026-09-25"
    assert any(x["cve"] == "CVE-2026-65660" and "KEV" in x["flag"] for x in s["flags"])


def test_master_list_only_microsoft_cves():
    every = {r["cve"] for b in ("P1", "P2", "P3") for r in S[b]}
    assert every <= {r["cveNumber"] for r in RECORDS}
