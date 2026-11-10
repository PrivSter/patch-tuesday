"""The collector and the report must not treat early-month records as the release.

On 10 Nov 2026 a delayed Monday-evening scheduled run collected at 02:08 UTC on
Patch Tuesday, before Microsoft's 16:00 UTC release. The feed then held only 134
early-month records (Chrome, third-party, one Microsoft fix from 4 Nov), and the
collector took 4 Nov as the release date. The fixture is that run's output.
"""
import sys
from pathlib import Path

from pt import cli

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "report"))
import facts as F  # noqa: E402


def test_collector_says_not_out_on_pre_release_records(tmp_path):
    rc = cli.main(["--month", "2026-Nov", "--offline", str(FIX / "2026-Nov-prerelease" / "records.json.gz"),
                   "--out", str(tmp_path)])
    assert rc == 3
    assert not (tmp_path / "2026-Nov").exists()


def test_collector_override_for_off_cycle_release(tmp_path):
    rc = cli.main(["--month", "2026-Nov", "--offline", str(FIX / "2026-Nov-prerelease" / "records.json.gz"),
                   "--out", str(tmp_path), "--allow-off-cycle"])
    assert rc == 0


def test_collector_accepts_real_release(tmp_path):
    rc = cli.main(["--month", "2026-Oct", "--offline", str(FIX / "2026-Oct" / "records.json.gz"), "--out", str(tmp_path)])
    assert rc == 0


def test_facts_refuses_pre_release_summary():
    assert F._is_patch_tuesday("2026-Nov", "2026-11-04T16:00:00+00:00") is False
    assert F._is_patch_tuesday("2026-Nov", "2026-11-10T16:00:00+00:00") is True
    assert F._is_patch_tuesday("2026-Oct", "2026-10-13T14:00:00+00:00") is True
