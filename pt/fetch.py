"""Network side: Microsoft Security Update Guide feed and CISA KEV. Stdlib only."""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

SUG = "https://api.msrc.microsoft.com/sug/v2.0/en-GB"
KEV = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
UA = {"User-Agent": "patch-tuesday-report/1.0", "Accept": "application/json"}


def _get(url: str, tries: int = 3) -> dict:
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=90) as r:
                return json.load(r)
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(5 * (i + 1))


def _odata(entity: str, flt: str, page: int = 500) -> list[dict]:
    """All records for an OData filter. Use 'eq' only: Microsoft's feed ignores
    ne/ge/gt and returns the whole database instead."""
    out, skip, count = [], 0, None
    while True:
        q = urllib.parse.urlencode({"$filter": flt, "$count": "true", "$top": page, "$skip": skip})
        d = _get(f"{SUG}/{entity}?{q}")
        count = d.get("@odata.count", count)
        if count is not None and count > 20000:
            raise RuntimeError(f"filter returned {count} records; the feed ignored it: {flt}")
        out += d["value"]
        skip += len(d["value"])
        if not d["value"] or (count is not None and skip >= count):
            break
    if count is not None and len(out) != count:
        raise RuntimeError(f"got {len(out)} records, feed said {count}")
    return out


def month_records(month: str) -> list[dict]:
    return _odata("vulnerability", f"releaseNumber eq '{month}'")


def cve_record(cve: str) -> dict | None:
    v = _odata("vulnerability", f"cveNumber eq '{cve}'")
    return v[0] if v else None


def affected_products(cve: str) -> list[dict]:
    return _odata("affectedProduct", f"cveNumber eq '{cve}'", page=200)


def kev() -> dict:
    return _get(KEV)
