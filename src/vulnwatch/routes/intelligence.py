"""NVD lookup and local intelligence import endpoints."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from vulnwatch.database import connect, row_dict
from vulnwatch.integrations.nvd import NvdError, fetch_cve

router = APIRouter(prefix="/api/nvd", tags=["NVD intelligence"])


class ImportRequest(BaseModel):
    cve_id: str = Field(min_length=1, max_length=32)


@router.get("/{cve_id}")
def lookup_cve(cve_id: str) -> dict:
    try:
        return fetch_cve(cve_id)
    except NvdError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error)) from error


@router.post("/import", status_code=201)
def import_cve(request: ImportRequest) -> dict:
    try:
        cve = fetch_cve(request.cve_id)
    except NvdError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error)) from error
    return save_intelligence(cve)


def save_intelligence(cve: dict) -> dict:
    """Store an already fetched NVD record without creating an asset finding."""
    with connect() as connection:
        connection.execute(
            """INSERT INTO cve_intelligence
               (cve_id, title, description, cvss_score, severity, published_at, modified_at, nvd_url)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET title=excluded.title, description=excluded.description,
                   cvss_score=excluded.cvss_score, severity=excluded.severity,
                   published_at=excluded.published_at, modified_at=excluded.modified_at,
                   nvd_url=excluded.nvd_url, imported_at=CURRENT_TIMESTAMP""",
            (cve["cve_id"], cve["title"], cve["description"], cve["cvss_score"], cve["severity"],
             cve["published_at"], cve["modified_at"], cve["nvd_url"]),
        )
        row = connection.execute("SELECT * FROM cve_intelligence WHERE cve_id = ?", (cve["cve_id"],)).fetchone()
    return row_dict(row)


@router.get("")
def list_imported_cves() -> list[dict]:
    with connect() as connection:
        rows = connection.execute("SELECT * FROM cve_intelligence ORDER BY imported_at DESC LIMIT 100").fetchall()
    return [dict(row) for row in rows]
