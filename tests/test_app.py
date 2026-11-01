"""Tests for VulnWatch route logic using isolated temporary SQLite databases."""

import asyncio
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from fastapi import HTTPException
from fastapi.routing import APIRoute
from pydantic import ValidationError

from vulnwatch.database import connect, initialize_database
from vulnwatch.integrations.nmap import NmapImportError, parse_nmap_xml
from vulnwatch.integrations.nvd import NvdError, fetch_cve, normalize_cve
from vulnwatch.main import create_app
from vulnwatch.routes import assets, findings, intelligence, scans
from vulnwatch.schemas import AssetCreate, AssetUpdate, FindingCreate, FindingUpdate

NMAP_XML = (Path(__file__).parent / "fixtures" / "sample_nmap.xml").read_bytes()

MOCK_CVE = {
    "cve_id": "CVE-2024-12345", "title": "CVE-2024-12345: Example issue",
    "description": "Example vulnerability description.", "cvss_score": 8.1,
    "severity": "High", "published_at": "2024-01-01T00:00:00.000",
    "modified_at": "2024-01-02T00:00:00.000",
    "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
}


class FakeUpload:
    """Minimal request object for the Nmap upload route's streaming body."""
    headers = {"content-length": "1"}

    def __init__(self, content: bytes):
        self.content = content

    async def stream(self):
        yield self.content


class VulnWatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_patch = patch.dict(os.environ, {"VULNWATCH_DB_PATH": os.path.join(self.temp_directory.name, "test.db")})
        self.database_patch.start()
        initialize_database()
        self.application = create_app()

    def tearDown(self) -> None:
        self.database_patch.stop()
        self.temp_directory.cleanup()

    def test_app_health_and_dashboard_routes(self) -> None:
        health = next(route.endpoint for route in self.application.routes if isinstance(route, APIRoute) and route.path == "/api/health")
        self.assertEqual(health(), {"status": "ok", "application": "VulnWatch"})
        dashboard = next(route.endpoint for route in self.application.routes if isinstance(route, APIRoute) and route.path == "/")
        self.assertTrue(str(dashboard().path).endswith("templates/index.html"))
        self.assertEqual(findings.dashboard_summary()["finding_count"], 0)

    def test_asset_finding_lifecycle_and_validation(self) -> None:
        asset = assets.create_asset(AssetCreate(name="Lab web", ip_address="192.0.2.10"))
        self.assertEqual(asset["ip_address"], "192.0.2.10")
        asset = assets.update_asset(asset["id"], AssetUpdate(name="Updated web", ip_address="192.0.2.11", hostname="web-test"))
        self.assertEqual((asset["name"], asset["ip_address"]), ("Updated web", "192.0.2.11"))
        with self.assertRaises(ValidationError):
            AssetCreate(name="Bad IP", ip_address="not-an-ip")

        finding = findings.create_finding(FindingCreate(
            cve_id="CVE-2024-12345", title="Example issue", severity="High",
            cvss_score=8.1, asset_id=asset["id"], discovered_date="2024-01-04",
        ))
        self.assertFalse(finding["verified"])
        updated = findings.update_finding(finding["id"], FindingUpdate(status="In Progress", remediation_notes="Patch scheduled", verified=True))
        self.assertEqual(updated["status"], "In Progress")
        self.assertTrue(updated["verified"])
        self.assertEqual(findings.list_findings(search="", severity="High", status=None)[0]["cve_id"], "CVE-2024-12345")
        self.assertEqual(findings.get_finding(finding["id"])["remediation_notes"], "Patch scheduled")
        findings.delete_finding(finding["id"])
        with self.assertRaises(HTTPException) as missing:
            findings.get_finding(finding["id"])
        self.assertEqual(missing.exception.status_code, 404)

        # Each operation opens a fresh connection; the row remains in SQLite afterwards.
        with connect() as connection:
            saved_asset = connection.execute("SELECT name FROM assets WHERE id = ?", (asset["id"],)).fetchone()
        self.assertEqual(saved_asset["name"], "Updated web")

    def test_nmap_import_only_adds_asset_inventory(self) -> None:
        parsed = parse_nmap_xml(NMAP_XML)
        self.assertEqual(len(parsed), 1)
        imported = asyncio.run(scans.import_nmap_xml(FakeUpload(NMAP_XML), filename="lab.xml"))
        self.assertEqual((imported["assets_imported"], imported["services_imported"]), (1, 3))
        imported_asset = assets.list_assets()[0]
        self.assertEqual(imported_asset["source"], "nmap")
        self.assertEqual(len(assets.get_asset(imported_asset["id"])["services"]), 3)
        self.assertEqual(findings.list_findings(search="", severity=None, status=None), [])
        with self.assertRaises(NmapImportError):
            parse_nmap_xml(b"<not-nmap/>")

    def test_nvd_import_stays_separate_from_findings(self) -> None:
        with patch.object(intelligence, "fetch_cve", return_value=MOCK_CVE):
            imported = intelligence.import_cve(intelligence.ImportRequest(cve_id="CVE-2024-12345"))
        self.assertEqual(imported["cve_id"], "CVE-2024-12345")
        self.assertEqual(intelligence.list_imported_cves()[0]["cve_id"], "CVE-2024-12345")
        self.assertEqual(findings.list_findings(search="", severity=None, status=None), [])

        with patch.object(intelligence, "fetch_cve", side_effect=NvdError("Rate limited", 429)):
            with self.assertRaises(HTTPException) as limited:
                intelligence.lookup_cve("CVE-2024-12345")
        self.assertEqual(limited.exception.status_code, 429)

    def test_nvd_normalization(self) -> None:
        record = {"id": "CVE-2024-1000", "descriptions": [{"lang": "en", "value": "Example."}],
                  "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}
        normalized = normalize_cve(record)
        self.assertEqual((normalized["severity"], normalized["cvss_score"]), ("Critical", 9.8))
        self.assertEqual(normalize_cve({"id": "CVE-2024-1001"})["severity"], "Unknown")

    def test_nvd_client_parses_api_response_and_rate_limit(self) -> None:
        api_response = {"vulnerabilities": [{"cve": {
            "id": "CVE-2024-12345", "descriptions": [{"lang": "en", "value": "Example issue."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]},
        }}]}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(api_response).encode()

        with patch("vulnwatch.integrations.nvd.urlopen", return_value=FakeResponse()) as open_url:
            result = fetch_cve("CVE-2024-12345")
        self.assertEqual(result["severity"], "High")
        self.assertIn("services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-12345", open_url.call_args.args[0].full_url)

        rate_error = HTTPError("https://nvd.nist.gov", 429, "limited", {}, io.BytesIO(b""))
        with patch("vulnwatch.integrations.nvd.urlopen", side_effect=rate_error):
            with self.assertRaises(NvdError) as limited:
                fetch_cve("CVE-2024-12345")
        self.assertEqual(limited.exception.status_code, 429)


if __name__ == "__main__":
    unittest.main()
