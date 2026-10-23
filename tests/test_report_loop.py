"""Offline tests for the report loop: facts, gate (including the split rule) and renderer.

Uses the frozen October 2026 fixture (tests/fixtures/2026-Oct/, copied byte for byte
from data/2026-Oct/ at commit e0e2266) and the KEV fixture; no network. The tests
never read data/, so a re-collection by the bot can't change what they see.
"""
import gzip
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "report"))

import facts as F  # noqa: E402
import gate as G  # noqa: E402
import render as RN  # noqa: E402

KEV = json.load(gzip.open(ROOT / "tests" / "fixtures" / "kev-2026.10.13-microsoft.json.gz", "rt"))
OCT = ROOT / "tests" / "fixtures" / "2026-Oct"
FACTS, RC = F.build(OCT, KEV, sha="e0e22664a6d0b2792f91a54b6eead40a19d5c1b8", offline=True)
URL = "https://example.org/bc"


def test_facts_known_answers():
    c = FACTS["counts"]
    assert RC == 0 and FACTS["ok"], FACTS["checks"]
    assert c["microsoft_install_needed"] == 1409
    assert c["microsoft_by_band"] == {"P1": 1, "P2": 18, "P3": 61, "P4": 1329}
    assert (c["critical_all_records"], c["critical_microsoft_issued"], c["zero_days_total"]) == (86, 85, 3)
    assert [r["cve"] for r in FACTS["P1"]] == ["CVE-2026-96951"]
    assert len(FACTS["windows_cu"]) == 15 and FACTS["windows_cu_source"] == "CVE-2026-100202"


def test_facts_affects_and_attack_line():
    p2 = {r["cve"]: r for r in FACTS["P2"]}
    assert p2["CVE-2026-100202"]["affects"] == "All supported Windows, client and server"
    assert p2["CVE-2026-100219"]["affects"] == "Windows 11 23H2 to 26H2; Server 2022 to 2025"
    assert any("No fix yet" in x for x in p2["CVE-2026-70291"]["fix"])
    assert p2["CVE-2026-70229"]["chips"] == ["AC:H, Exploitation More Likely"]
    a = FACTS["P1"][0]["attack"]
    assert "over the network" in a and "needs no account" in a and "user must act" in a


def test_facts_kev_band_change_exit_5():
    kev = json.loads(json.dumps(KEV))
    kev["vulnerabilities"].append({"cveID": "CVE-2026-100202", "dateAdded": "2026-10-14", "dueDate": "2026-10-17"})
    _, rc = F.build(OCT, kev, offline=True)
    assert rc == 5


def draft(bottom_value="Thu 15 Oct 2026, 15:00 BST"):
    return {"month": "2026-Oct", "compiled_at": "2026-10-14T20:00:00Z",
            "sources": [{"title": "BC", "url": URL}],
            "items": [
                {"id": "bl", "type": "bottom_line", "text": "Patch CVE-2026-96951 first; it is due Thu 15 Oct 2026, 15:00 BST.",
                 "claims": [{"id": "c1", "kind": "data", "text": "P1 due", "ref": "deadlines.P1.uk", "value": bottom_value}]},
                {"id": "t1", "type": "source_total", "source": "BleepingComputer", "url": URL, "total": "1,411", "critical": "70",
                 "note": "", "claims": [{"id": "c2", "kind": "reported", "text": "BC counts 1,411 and 70 Critical", "source_url": URL}]},
                {"id": "z1", "type": "zero_day", "cve": "CVE-2026-96951", "source": "BleepingComputer", "status": "exploited",
                 "text": "Actively exploited zero-day",
                 "claims": [{"id": "c3", "kind": "reported", "text": "BC calls it actively exploited", "source_url": URL}]},
                {"id": "k1", "type": "credit", "cve": "CVE-2026-96951", "text": "BleepingComputer reports a named group exploited it.",
                 "claims": [{"id": "c4", "kind": "reported", "text": "BC names a group", "source_url": URL}]},
                {"id": "f1", "type": "finding", "text": "Our read: something.",
                 "claims": [{"id": "c5", "kind": "inference", "text": "Our read", "ref": "counts.P2"}]}]}


def run_round(wd, verdict_for):
    """Simulate a checker round: verdict_for(claim_id) -> verdict string; coverage always passes."""
    G.cmd_prepare(str(wd), 1)
    rd = wd / "check" / "round-1"
    claims = json.loads((rd / "claims.json").read_text())["claims"]
    items = json.loads((rd / "items.json").read_text())["items"]
    (rd / "source_verdicts.json").write_text(json.dumps(
        [{"hash": c["hash"], "claim_id": c["claim_id"], "verdict": verdict_for(c["claim_id"]), "note": "page says otherwise"} for c in claims]))
    (rd / "coverage_verdicts.json").write_text(json.dumps([{"hash": i["hash"], "item_id": i["item_id"], "pass": True, "issues": []} for i in items]))


def setup(tmp_path, d):
    (tmp_path / "facts.json").write_text(json.dumps(FACTS))
    (tmp_path / "draft.json").write_text(json.dumps(d))
    return tmp_path


def test_data_claim_mismatch_is_structural(tmp_path):
    wd = setup(tmp_path, draft(bottom_value="Fri 16 Oct 2026"))
    _, _, report, _, _ = G.assess(str(wd))
    bl = next(r for r in report if r["item_id"] == "bl")
    assert any("does not match facts.json" in p for p in bl["structural"])


def test_prepare_never_sends_data_claims(tmp_path):
    wd = setup(tmp_path, draft())
    G.cmd_prepare(str(wd), 1)
    claims = json.loads((wd / "check" / "round-1" / "claims.json").read_text())["claims"]
    ids = {c["claim_id"] for c in claims}
    assert "c1" not in ids and {"c2", "c3", "c4", "c5"} <= ids
    assert next(c for c in claims if c["claim_id"] == "c5")["basis"] == "20"


def test_all_pass(tmp_path):
    wd = setup(tmp_path, draft())
    run_round(wd, lambda cid: "SUPPORTED" if cid != "c5" else "INFERENCE_OK")
    G.cmd_final(str(wd))
    rep = json.loads((wd / "report.json").read_text())
    assert rep["bottom_line"]["verified"] and rep["credits"]["CVE-2026-96951"]["verified"]
    assert rep["verification"]["claims_checked"] == 4 and rep["verification"]["first_pass"] == 4
    rows = {z["cve"]: z for z in rep["zero_day_rows"]}
    assert rows["CVE-2026-96951"]["agree"] == "Yes"
    assert rows["CVE-2026-108398"]["agree"] == "Partly: BleepingComputer does not mention it"
    html = RN.render(rep)
    assert "CVE-2026-96951" in html and 'id="pt-snapshot"' in html and "Verification notes" in html


def test_split_rule_keeps_cves_when_narrative_fails(tmp_path):
    wd = setup(tmp_path, draft())
    run_round(wd, lambda cid: "UNSUPPORTED")
    G.cmd_final(str(wd))
    rep = json.loads((wd / "report.json").read_text())
    # P1 card stays, credit is replaced, news cells say not verified, finding is dropped
    assert [r["cve"] for r in rep["facts"]["P1"]] == ["CVE-2026-96951"]
    assert rep["credits"]["CVE-2026-96951"] == {"text": "No verified credit or attribution this run.", "verified": False}
    assert rep["totals"][0]["total"] == "not verified"
    rows = {z["cve"]: z for z in rep["zero_day_rows"]}
    assert rows["CVE-2026-96951"]["cells"]["BleepingComputer"]["verified"] is False
    assert rep["findings"] == [] and rep["verification"]["dropped"] == ["Finding"]
    # bottom line rests only on a data claim, so it passes
    assert rep["bottom_line"]["verified"]
    html = RN.render(rep)
    assert "Not verified" in html and "CVE-2026-96951" in html


def test_bottom_line_fallback(tmp_path):
    d = draft()
    d["items"][0]["claims"].append({"id": "c9", "kind": "reported", "text": "BC says urgent", "source_url": URL})
    wd = setup(tmp_path, d)
    run_round(wd, lambda cid: "SUPPORTED" if cid != "c9" else "OVERSTATED")
    G.cmd_final(str(wd))
    rep = json.loads((wd / "report.json").read_text())
    assert rep["bottom_line"]["verified"] is False
    assert rep["bottom_line"]["text"].startswith("Patch CVE-2026-96951 (Windows Shell) first")
    assert rep["verification"]["fallbacks"] == ["bottom line"]


def test_status_exit_codes(tmp_path):
    wd = setup(tmp_path, draft())
    r = subprocess.run([sys.executable, str(ROOT / "report" / "gate.py"), "status", str(wd)], capture_output=True)
    assert r.returncode == 3
    run_round(wd, lambda cid: "SUPPORTED" if cid != "c5" else "INFERENCE_OK")
    r = subprocess.run([sys.executable, str(ROOT / "report" / "gate.py"), "status", str(wd)], capture_output=True)
    assert r.returncode == 0, r.stdout.decode()
