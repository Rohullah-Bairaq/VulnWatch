"""Small client for the official NVD CVE API 2.0."""

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class NvdError(Exception):
    """A safe, user-displayable NVD lookup problem."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def _severity(score: float | None, api_severity: str | None) -> str:
    if score is not None:
        if score >= 9:
            return "Critical"
        if score >= 7:
            return "High"
        if score >= 4:
            return "Medium"
        return "Low"
    normalized = (api_severity or "").title()
    return normalized if normalized in {"Critical", "High", "Medium", "Low"} else "Unknown"


def normalize_cve(record: dict) -> dict:
    """Map NVD's response into fields used by VulnWatch."""
    descriptions = record.get("descriptions", [])
    description = next((item["value"] for item in descriptions if item.get("lang") == "en"), "")
    metrics = record.get("metrics", {})
    score = None
    api_severity = None
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_name, [])
        if entries:
            cvss = entries[0].get("cvssData", {})
            score = cvss.get("baseScore")
            api_severity = entries[0].get("baseSeverity") or cvss.get("baseSeverity")
            if score is not None:
                break
    cve_id = record.get("id", "")
    return {
        "cve_id": cve_id,
        "title": f"{cve_id}: {description[:180]}" if description else cve_id,
        "description": description,
        "cvss_score": score,
        "severity": _severity(score, api_severity),
        "published_at": record.get("published"),
        "modified_at": record.get("lastModified"),
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def fetch_cve(cve_id: str) -> dict:
    """Fetch one CVE with a finite timeout; optional key stays server-side."""
    normalized_id = cve_id.strip().upper()
    if not CVE_PATTERN.fullmatch(normalized_id):
        raise NvdError("Enter a valid CVE ID, such as CVE-2021-44228.", 422)
    headers = {"User-Agent": "VulnWatch/0.1 (local portfolio application)"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    request = Request(f"{NVD_ENDPOINT}?cveId={normalized_id}", headers=headers)
    try:
        with urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        if error.code == 429:
            raise NvdError("NVD rate limit reached. Wait briefly and try again.", 429) from error
        if error.code in (401, 403):
            raise NvdError("NVD rejected the request. Check API access and try again later.", 502) from error
        raise NvdError(f"NVD returned HTTP {error.code}.", 502) from error
    except (TimeoutError, URLError, OSError) as error:
        raise NvdError("Could not reach NVD. Check the network connection and try again.", 502) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NvdError("NVD returned an unreadable response.", 502) from error

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        raise NvdError(f"NVD has no record for {normalized_id}.", 404)
    return normalize_cve(vulnerabilities[0].get("cve", {}))
