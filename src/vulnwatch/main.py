"""FastAPI application entry point for the VulnWatch MVP."""

from pathlib import Path
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from vulnwatch.database import initialize_database
from vulnwatch.routes import assets, findings, intelligence, scans

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = PROJECT_ROOT / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
    """Create the API app and its local dashboard routes."""
    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        initialize_database()
        yield

    application = FastAPI(
        title="VulnWatch",
        description="A vulnerability management dashboard for assets and findings.",
        version="0.2.0",
        lifespan=lifespan,
    )
    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    application.include_router(assets.router)
    application.include_router(findings.router)
    application.include_router(intelligence.router)
    application.include_router(scans.router)

    @application.get("/api/health")
    def get_health() -> dict[str, str]:
        """Report that the VulnWatch API is responding."""
        return {"status": "ok", "application": "VulnWatch"}

    @application.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(TEMPLATE_DIR / "index.html")

    return application


app = create_app()
