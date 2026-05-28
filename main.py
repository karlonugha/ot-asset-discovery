"""FastAPI application entry point for OT Asset Discovery & Inventory Scanner.

Creates the FastAPI app, registers all routers, configures CORS,
and sets up database lifecycle events.
"""

import os
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router_auth import auth_router
from app.api.devices_router import devices_router
from app.api.router_alerts import alerts_router
from app.api.router_topology import topology_router, ws_topology_router
from app.api.router_scans import scans_router
from app.api.router_export import export_router
from app.api.ws_alerts import ws_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Allowed CORS origins (frontend URL)
CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:3000"
).split(",")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="OT Asset Discovery & Inventory Scanner",
        description="Protocol-aware network scanner for industrial OT environments",
        version="0.1.0",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(auth_router)
    app.include_router(devices_router)
    app.include_router(alerts_router)
    app.include_router(topology_router)
    app.include_router(ws_topology_router)
    app.include_router(scans_router)
    app.include_router(export_router)
    app.include_router(ws_router)

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": "ot-asset-discovery"}

    @app.on_event("startup")
    async def startup():
        logger.info("OT Asset Discovery API starting up...")

    @app.on_event("shutdown")
    async def shutdown():
        logger.info("OT Asset Discovery API shutting down...")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port, reload=False)
