"""Vulnerability finding and dashboard summary endpoints."""

import sqlite3

from fastapi import APIRouter, HTTPException, Query

from vulnwatch.database import connect, row_dict
from vulnwatch.schemas import FindingCreate, FindingUpdate

router = APIRouter(prefix="/api", tags=["findings"])


@router.get("/summary")
def dashboard_summary() -> dict:
    with connect() as connection:
        totals = connection.execute(
            """SELECT COUNT(*) AS finding_count,
                      SUM(CASE WHEN status != 'Resolved' THEN 1 ELSE 0 END) AS open_count,
                      SUM(CASE WHEN severity = 'Critical' AND status != 'Resolved' THEN 1 ELSE 0 END) AS critical_count,
                      SUM(CASE WHEN verified = 0 AND status != 'Resolved' THEN 1 ELSE 0 END) AS unverified_count
               FROM findings"""
        ).fetchone()
        asset_count = connection.execute("SELECT COUNT(*) AS count FROM assets").fetchone()["count"]
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM findings WHERE status != 'Resolved' GROUP BY severity"
        ).fetchall()
    severity_counts = {name: 0 for name in ("Critical", "High", "Medium", "Low", "Unknown")}
    severity_counts.update({row["severity"]: row["count"] for row in severity_rows})
    return {**dict(totals), "finding_count": totals["finding_count"] or 0,
            "open_count": totals["open_count"] or 0, "critical_count": totals["critical_count"] or 0,
            "unverified_count": totals["unverified_count"] or 0, "asset_count": asset_count,
            "severity_counts": severity_counts}


@router.get("/findings")
def list_findings(
    search: str = Query(default="", max_length=200),
    severity: str | None = Query(default=None, pattern="^(Critical|High|Medium|Low|Unknown)$"),
    status: str | None = Query(default=None, pattern="^(Open|In Progress|Resolved)$"),
) -> list[dict]:
    conditions: list[str] = []
    values: list[object] = []
    if search.strip():
        term = f"%{search.strip()}%"
        conditions.append("(f.cve_id LIKE ? OR f.title LIKE ? OR a.name LIKE ? OR a.ip_address LIKE ?)")
        values.extend((term, term, term, term))
    if severity:
        conditions.append("f.severity = ?")
        values.append(severity)
    if status:
        conditions.append("f.status = ?")
        values.append(status)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with connect() as connection:
        rows = connection.execute(
            f"""SELECT f.*, a.name AS asset_name, a.ip_address AS asset_ip
                FROM findings f JOIN assets a ON a.id = f.asset_id
                {where} ORDER BY CASE f.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                    WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, f.discovered_date DESC""",
            values,
        ).fetchall()
    return [dict(row) for row in rows]


@router.post("/findings", status_code=201)
def create_finding(finding: FindingCreate) -> dict:
    with connect() as connection:
        if connection.execute("SELECT id FROM assets WHERE id = ?", (finding.asset_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Selected asset was not found.")
        try:
            cursor = connection.execute(
                """INSERT INTO findings
                   (cve_id, title, description, cvss_score, severity, asset_id, status,
                    discovered_date, remediation_notes, verified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding.cve_id.upper(), finding.title.strip(), finding.description,
                 finding.cvss_score, finding.severity, finding.asset_id, finding.status,
                 finding.discovered_date.isoformat(), finding.remediation_notes,
                 int(finding.verified)),
            )
            row = connection.execute(
                """SELECT f.*, a.name AS asset_name, a.ip_address AS asset_ip
                   FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.id = ?""",
                (cursor.lastrowid,),
            ).fetchone()
        except sqlite3.IntegrityError as error:
            raise HTTPException(status_code=400, detail="Finding data could not be saved.") from error
    return row_dict(row)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int) -> dict:
    with connect() as connection:
        row = connection.execute(
            """SELECT f.*, a.name AS asset_name, a.ip_address AS asset_ip
               FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.id = ?""",
            (finding_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return row_dict(row)


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: int, updates: FindingUpdate) -> dict:
    changes = updates.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Provide a status or remediation note to update.")
    with connect() as connection:
        if connection.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Finding not found.")
        assignments = ", ".join(f"{key} = ?" for key in changes)
        connection.execute(f"UPDATE findings SET {assignments} WHERE id = ?", (*changes.values(), finding_id))
    return get_finding(finding_id)


@router.delete("/findings/{finding_id}", status_code=204)
def delete_finding(finding_id: int) -> None:
    with connect() as connection:
        result = connection.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Finding not found.")
