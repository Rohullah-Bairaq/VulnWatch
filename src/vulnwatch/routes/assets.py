"""Asset inventory endpoints."""

import sqlite3

from fastapi import APIRouter, HTTPException

from vulnwatch.database import connect, row_dict
from vulnwatch.schemas import AssetCreate, AssetUpdate

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("")
def list_assets() -> list[dict]:
    with connect() as connection:
        rows = connection.execute(
            """SELECT a.*, COUNT(f.id) AS finding_count
               FROM assets a LEFT JOIN findings f ON f.asset_id = a.id
               GROUP BY a.id ORDER BY a.name COLLATE NOCASE"""
        ).fetchall()
    return [dict(row) for row in rows]


@router.post("", status_code=201)
def create_asset(asset: AssetCreate) -> dict:
    try:
        with connect() as connection:
            cursor = connection.execute(
                "INSERT INTO assets (name, ip_address, hostname, operating_system) VALUES (?, ?, ?, ?)",
                (asset.name.strip(), asset.ip_address.strip(), asset.hostname, asset.operating_system),
            )
            row = connection.execute("SELECT * FROM assets WHERE id = ?", (cursor.lastrowid,)).fetchone()
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="An asset with that IP address already exists.") from error
    return row_dict(row)


@router.get("/{asset_id}")
def get_asset(asset_id: int) -> dict:
    with connect() as connection:
        row = connection.execute(
            """SELECT a.*, COUNT(f.id) AS finding_count
               FROM assets a LEFT JOIN findings f ON f.asset_id = a.id
               WHERE a.id = ? GROUP BY a.id""",
            (asset_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Asset not found.")
        services = connection.execute(
            """SELECT protocol, port, service_name, product, version
               FROM asset_services WHERE asset_id = ? ORDER BY port""",
            (asset_id,),
        ).fetchall()
    result = dict(row)
    result["services"] = [dict(service) for service in services]
    return result


@router.put("/{asset_id}")
def update_asset(asset_id: int, asset: AssetUpdate) -> dict:
    try:
        with connect() as connection:
            existing = connection.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone()
            if existing is None:
                raise HTTPException(status_code=404, detail="Asset not found.")
            connection.execute(
                """UPDATE assets SET name = ?, ip_address = ?, hostname = ?, operating_system = ?
                   WHERE id = ?""",
                (asset.name.strip(), asset.ip_address.strip(), asset.hostname, asset.operating_system, asset_id),
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="Another asset already uses that IP address.") from error
    return get_asset(asset_id)
