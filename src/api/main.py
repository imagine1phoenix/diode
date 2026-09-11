"""
FastAPI Application — Alert API + WebSocket live feed.

PRD §4: FastAPI backend with polling or WebSocket for live updates.
rules.md R3: FastAPI only — no Django, no Flask.
rules.md R6.5: Dashboard reads from Alert Store via this API.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import config
from src.alert.schema import Alert
from src.alert.store import AlertStore
from src.pipeline.runner import Pipeline

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
_store: AlertStore | None = None
_pipeline: Pipeline | None = None
_ws_clients: set[WebSocket] = set()


async def _broadcast_alert(alert: Alert) -> None:
    """Broadcast a new alert to all connected WebSocket clients."""
    if not _ws_clients:
        return
    data = alert.model_dump_json()
    disconnected: set[WebSocket] = set()
    for ws in _ws_clients:
        try:
            await ws.send_text(data)
        except Exception:
            disconnected.add(ws)
    _ws_clients.difference_update(disconnected)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle — initialize store and pipeline on startup."""
    global _store, _pipeline
    _store = AlertStore(config.DB_PATH)
    _pipeline = Pipeline(store=_store, alert_callback=_broadcast_alert)
    logger.info("API started — store at %s", config.DB_PATH)
    yield
    logger.info("API shutting down")


# ---------------------------------------------------------------------------
# App definition
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SIH Cyber Threat Detection",
    description="AI-Based Detection of Cyber Threats in Unidirectional IP Traffic",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve dashboard static files
dist_path = config.PROJECT_ROOT / "dashboard" / "dist"
dashboard_path = config.PROJECT_ROOT / "dashboard"

if dist_path.exists() and (dist_path / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(dist_path / "assets")), name="assets")
if dashboard_path.exists():
    app.mount("/static", StaticFiles(directory=str(dashboard_path)), name="static")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
async def root():
    """Serve the dashboard (React built app if available, else static HTML)."""
    if dist_path.exists() and (dist_path / "index.html").exists():
        return FileResponse(str(dist_path / "index.html"))
    index_path = dashboard_path / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "SIH Cyber Threat Detection API", "docs": "/docs"}


@app.get("/api/alerts")
async def get_alerts(
    threat_class: str | None = Query(None, description="Filter by threat class"),
    severity: str | None = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> list[dict[str, Any]]:
    """
    Get recent alerts with optional filtering.

    Supports filtering by:
    - threat_class: ddos, c2_beaconing, dga_dns, encrypted_malware, recon_scan, exfiltration
    - severity: low, medium, high, critical
    """
    assert _store is not None
    if threat_class:
        return _store.get_by_threat_class(threat_class, limit)
    if severity:
        return _store.get_by_severity(severity, limit)
    return _store.get_recent(limit)


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str) -> dict[str, Any]:
    """Get a single alert by ID with full evidence."""
    assert _store is not None
    alert = _store.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    """Get aggregated alert statistics for dashboard charts."""
    assert _pipeline is not None
    return _pipeline.get_stats()


@app.get("/api/timeline")
async def get_timeline(
    minutes: int = Query(30, ge=1, le=1440),
    bucket_seconds: int = Query(60, ge=10, le=3600),
) -> list[dict[str, Any]]:
    """Get alert counts bucketed by time for timeline chart."""
    assert _store is not None
    return _store.get_timeline(minutes, bucket_seconds)


@app.get("/api/health")
async def health_check() -> dict[str, Any]:
    """Pipeline health check with throughput info."""
    assert _pipeline is not None
    return {
        "status": "healthy",
        "throughput": _pipeline.throughput.report(),
    }


@app.post("/api/analyze")
async def analyze_pcap(pcap_filename: str = Query(..., description="Filename in traffic/samples/")) -> dict[str, Any]:
    """
    Trigger analysis of a PCAP file from the traffic/samples directory.

    This endpoint is for demo purposes — it kicks off pipeline processing
    on a pre-loaded PCAP file.
    """
    assert _pipeline is not None
    pcap_path = config.DATA_DIR / pcap_filename
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail=f"PCAP file not found: {pcap_filename}")

    alerts = await _pipeline.process_pcap_async(pcap_path)
    return {
        "pcap_file": pcap_filename,
        "alerts_generated": len(alerts),
        "throughput": _pipeline.throughput.report(),
    }


@app.post("/api/simulate")
async def simulate_traffic(
    threat_class: str = Query("all", description="Threat category to simulate (all, ddos, recon_scan, c2_beaconing, dga_dns, exfiltration)")
) -> dict[str, Any]:
    """
    Simulate cyber attack traffic on demand and ingest via pipeline.
    Targeted attacks generate scenario-specific PCAPs, streaming alerts live
    to connected WebSocket clients and updating radar charts dynamically.
    """
    assert _pipeline is not None
    from traffic.generators.generate_traffic import generate_demo_pcap

    logger.info("Triggering on-demand traffic simulation (threat_class=%s)", threat_class)
    pcap_path = generate_demo_pcap(scenario=threat_class)
    alerts = await _pipeline.process_pcap_async(pcap_path)

    return {
        "status": "success",
        "threat_class": threat_class,
        "pcap_file": str(pcap_path),
        "alerts_generated": len(alerts),
        "throughput": _pipeline.throughput.report(),
    }


# ---------------------------------------------------------------------------
# WebSocket — Live alert feed
# ---------------------------------------------------------------------------


@app.websocket("/ws")
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for live alert streaming.

    Clients connect here to receive real-time alert notifications
    as JSON messages. Used by the dashboard for live updates.
    """
    await websocket.accept()
    _ws_clients.add(websocket)
    logger.info("WebSocket client connected (%d total)", len(_ws_clients))
    try:
        while True:
            # Keep connection alive — wait for client messages (e.g., pings)
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(_ws_clients))
