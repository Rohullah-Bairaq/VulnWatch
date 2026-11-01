"""Import existing Nmap XML as asset and service inventory."""

import sqlite3

from fastapi import APIRouter, HTTPException, Query, Request

from vulnwatch.integrations.nmap import NmapImportError, parse_nmap_xml, store_nmap_inventory

router = APIRouter(prefix="/api/scans", tags=["Nmap imports"])


@router.post("/nmap")
async def import_nmap_xml(
    request: Request,
    filename: str = Query(default="nmap.xml", max_length=200),
) -> dict:
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > 5_000_000:
        raise HTTPException(status_code=413, detail="Nmap XML files must be smaller than 5 MB.")
    chunks = []
    byte_count = 0
    async for chunk in request.stream():
        byte_count += len(chunk)
        if byte_count > 5_000_000:
            raise HTTPException(status_code=413, detail="Nmap XML files must be smaller than 5 MB.")
        chunks.append(chunk)
    content = b"".join(chunks)
    try:
        hosts = parse_nmap_xml(content)
    except NmapImportError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    try:
        asset_count, service_count = store_nmap_inventory(hosts)
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=400, detail="Could not import the Nmap inventory.") from error
    return {
        "filename": filename,
        "assets_imported": asset_count,
        "services_imported": service_count,
        "message": "Inventory imported. Nmap service matches do not automatically create vulnerability findings.",
    }
