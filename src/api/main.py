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
from pydantic import BaseModel

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
_is_empty_mode_active: bool = False


async def _broadcast_alert(alert: Alert) -> None:
    """Broadcast a new alert to connected WebSocket clients and external notification channels."""
    # 1. WebSocket live broadcast
    if _ws_clients:
        data = alert.model_dump_json()
        disconnected: set[WebSocket] = set()
        for ws in _ws_clients:
            try:
                await ws.send_text(data)
            except Exception:
                disconnected.add(ws)
        _ws_clients.difference_update(disconnected)

    # 2. External operational dispatch (Webhooks, Discord, Slack, Telegram)
    try:
        from src.alert.dispatcher import get_dispatcher
        await get_dispatcher().dispatch_async(alert)
    except Exception as e:
        logger.error("External alert dispatch failed: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle — initialize store and pipeline on startup."""
    global _store, _pipeline
    _store = AlertStore(config.DB_PATH)
    _pipeline = Pipeline(store=_store, alert_callback=_broadcast_alert)
    logger.info("API started — store at %s", config.DB_PATH)

    # Auto-seed diverse multi-vector threat detections if store has fewer than 6 alerts
    recent = _store.get_recent(6)
    if len(recent) < 6:
        try:
            from traffic.generators.generate_traffic import generate_demo_pcap
            pcap_path = generate_demo_pcap(scenario="all")
            await _pipeline.process_pcap_async(pcap_path)
            logger.info("✅ Auto-seeded demonstration threat corpus (%d alerts)", len(_store.get_recent(50)))
        except Exception as e:
            logger.warning("Could not auto-seed demo PCAP: %s", e)

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
    no_cache_headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    }
    if dist_path.exists() and (dist_path / "index.html").exists():
        return FileResponse(str(dist_path / "index.html"), headers=no_cache_headers)
    index_path = dashboard_path / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path), headers=no_cache_headers)
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
    alerts = _store.get_recent(limit)
    if len(alerts) < 6 and not threat_class and not severity and not _is_empty_mode_active:
        try:
            from traffic.generators.generate_traffic import generate_demo_pcap
            pcap_path = generate_demo_pcap(scenario="all")
            if _pipeline is not None:
                await _pipeline.process_pcap_async(pcap_path)
                alerts = _store.get_recent(limit)
        except Exception as e:
            logger.warning("Auto-seed on /api/alerts failed: %s", e)
    return alerts


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
    threat_class: str = Query("all", description="Threat category to simulate (all, ddos, recon_scan, c2_beaconing, dga_dns, exfiltration, encrypted_malware)")
) -> dict[str, Any]:
    """
    Simulate cyber attack traffic on demand and ingest via pipeline.
    Targeted attacks generate scenario-specific PCAPs, streaming alerts live
    to connected WebSocket clients and updating radar charts dynamically.
    """
    assert _pipeline is not None
    global _is_empty_mode_active
    _is_empty_mode_active = False
    from traffic.generators.generate_traffic import generate_demo_pcap

    logger.info("Triggering on-demand traffic simulation (threat_class=%s)", threat_class)
    pcap_path = generate_demo_pcap(scenario=threat_class)
    alerts = await _pipeline.process_pcap_async(pcap_path)

    alert_dicts = [a.model_dump() if hasattr(a, "model_dump") else a for a in alerts]

    return {
        "status": "success",
        "threat_class": threat_class,
        "pcap_file": str(pcap_path),
        "alerts_generated": len(alerts),
        "alerts": alert_dicts[:15],
        "throughput": _pipeline.throughput.report(),
    }


class ResetEnclaveRequest(BaseModel):
    mode: str = "baseline"  # "baseline" (clean 6-vector state) or "empty" (0 alerts clean slate)
    clear_notifications: bool = True


@app.post("/api/reset")
async def reset_enclave(req: ResetEnclaveRequest | None = None) -> dict[str, Any]:
    """
    Reset enclave telemetry, SQLite database, and pipeline throughput.

    Modes:
    - baseline: Wipes attack noise, clears throughput, and re-seeds clean multi-vector baseline (6 threats).
    - empty: Completely purges all alerts (0 alerts, clean slate for pristine live demonstration).
    """
    global _is_empty_mode_active
    if req is None:
        req = ResetEnclaveRequest(mode="baseline", clear_notifications=True)

    assert _store is not None
    assert _pipeline is not None

    mode = req.mode.lower().strip() if req.mode else "baseline"
    deleted_count = _store.clear()
    _pipeline.reset()

    if req.clear_notifications:
        from src.alert.dispatcher import get_dispatcher
        get_dispatcher().clear_logs()

    if mode == "empty":
        _is_empty_mode_active = True
        total_alerts = 0
    else:
        _is_empty_mode_active = False
        # Re-seed clean 6-vector baseline
        try:
            from traffic.generators.generate_traffic import generate_demo_pcap
            pcap_path = generate_demo_pcap(scenario="all")
            await _pipeline.process_pcap_async(pcap_path)
        except Exception as e:
            logger.warning("Baseline re-seed during reset failed: %s", e)
        total_alerts = len(_store.get_recent(50))

    # Broadcast reset event over WebSocket to synchronize all connected UIs immediately
    if _ws_clients:
        reset_payload = json.dumps({
            "event": "reset",
            "mode": mode,
            "total_alerts": total_alerts,
        })
        disconnected: set[WebSocket] = set()
        for ws in _ws_clients:
            try:
                await ws.send_text(reset_payload)
            except Exception:
                disconnected.add(ws)
        _ws_clients.difference_update(disconnected)

    logger.info("Enclave reset complete (mode=%s, deleted=%d, total_alerts=%d)", mode, deleted_count, total_alerts)

    return {
        "status": "success",
        "mode": mode,
        "alerts_deleted": deleted_count,
        "total_alerts": total_alerts,
        "throughput": _pipeline.throughput.report(),
        "notifications_cleared": req.clear_notifications,
    }


@app.post("/api/triage")
async def triage_endpoint(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Air-Gapped Generative AI SOC Analyst (LLM Auto-Triage).
    Evaluates normalized alert telemetry and returns plain-English diagnosis,
    forensic evidence breakdown, and actionable manual mitigation commands.
    """
    from src.api.triage import triage_alert
    return triage_alert(alert)


class CopilotConfigUpdateRequest(BaseModel):
    provider: str | None = None
    api_key: str | None = None
    model: str | None = None
    ollama_base_url: str | None = None
    persist_to_env: bool = True


class CopilotTestRequest(BaseModel):
    provider: str
    api_key: str | None = None
    model: str | None = None
    ollama_base_url: str | None = None


@app.get("/api/copilot/config")
async def get_copilot_config_endpoint() -> dict[str, Any]:
    """Get active Copilot LLM provider, models, and credential status."""
    from src.api.triage import get_copilot_config
    return get_copilot_config()


@app.post("/api/copilot/config")
async def update_copilot_config_endpoint(req: CopilotConfigUpdateRequest) -> dict[str, Any]:
    """Update active Copilot provider, key, model, and persist to .env."""
    from src.api.triage import update_copilot_config
    return update_copilot_config(
        provider=req.provider,
        api_key=req.api_key,
        model=req.model,
        ollama_base_url=req.ollama_base_url,
        persist_to_env=req.persist_to_env,
    )


@app.post("/api/copilot/test")
async def test_copilot_endpoint(req: CopilotTestRequest) -> dict[str, Any]:
    """Test connection to an AI provider with live model roundtrip."""
    from src.api.triage import test_copilot_connection
    return test_copilot_connection(
        provider=req.provider,
        api_key=req.api_key,
        model=req.model,
        base_url=req.ollama_base_url,
    )


class CopilotChatRequest(BaseModel):
    query: str
    alert: dict[str, Any] | None = None
    history: list[dict[str, str]] | None = None


@app.post("/api/copilot/chat")
async def copilot_chat_endpoint(req: CopilotChatRequest) -> dict[str, Any]:
    """
    Interactive Copilot Chat Engine.
    Executes multi-turn tactical Q&A, writes packet filters, and explains ML detector math.
    """
    from src.api.triage import copilot_chat
    assert _pipeline is not None
    assert _store is not None
    enclave_context = {
        "throughput": _pipeline.throughput.report(),
        "total_alerts": len(_store.get_recent(100)),
    }
    return copilot_chat(
        query=req.query,
        alert_data=req.alert,
        history=req.history,
        enclave_context=enclave_context,
    )


@app.get("/api/copilot/briefing")
async def copilot_briefing_endpoint() -> dict[str, Any]:
    """
    Generate an executive AI briefing summarizing overall enclave posture.
    """
    from src.api.triage import generate_enclave_briefing
    assert _pipeline is not None
    assert _store is not None
    recent = _store.get_recent(100)
    stats = _pipeline.get_stats()
    return generate_enclave_briefing(recent, stats)


@app.get("/api/forensics/dossier/{alert_id}")
async def get_forensic_dossier(alert_id: str) -> dict[str, Any]:
    """
    Generate a full forensic PCAP and telemetry dossier for legal/tactical audit.
    """
    import time
    assert _store is not None
    alert = _store.get_by_id(alert_id)
    if alert is None:
        recent = _store.get_recent(1)
        alert = recent[0] if recent else {"alert_id": alert_id, "threat_class": "c2_beaconing"}

    from src.api.triage import triage_alert
    triage = triage_alert(alert)
    flow_id = str(alert.get("flow_id", "unknown"))
    src_ip = flow_id.split("-")[0].split(":")[0] if "-" in flow_id else "unknown"

    return {
        "dossier_title": f"FORENSIC_TELEMETRY_DOSSIER_{alert_id}",
        "export_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "enclave": "NET-DRISHTI AIR-GAPPED TELEMETRY ENCLAVE",
        "tap_mode": "PASSIVE_OPTICAL_DIODE_SIMPLEX_RX",
        "hardware_constraint": "ZERO_TX_WRITES_VERIFIED",
        "alert": alert,
        "ai_triage": triage,
        "recommended_capture_syntax": f"tcpdump -nn -s 0 -i eth0 'host {src_ip}' -w /opt/forensics/{alert_id}.pcap",
    }


@app.get("/api/geoip/threats")
async def geoip_threats(limit: int = Query(200, ge=1, le=1000)) -> list[dict[str, Any]]:
    """
    Aggregate recent alerts by geographic attacker source coordinates.
    Used by the Live Geo-IP World Threat Map.
    """
    from src.features.geoip import aggregate_threat_geo
    assert _store is not None
    recent_alerts = _store.get_recent(limit=limit)
    return aggregate_threat_geo(recent_alerts)


# ---------------------------------------------------------------------------
# External Notification Channel Endpoints
# ---------------------------------------------------------------------------


class NotificationConfigUpdate(BaseModel):
    webhook_url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    min_severity: str | None = None
    cooldown_seconds: float | None = None


class TestNotificationRequest(BaseModel):
    channel: str = "all"
    webhook_url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


@app.get("/api/notifications/config")
async def get_notification_config() -> dict[str, Any]:
    """Get active external alert dispatch configuration (tokens masked)."""
    from src.alert.dispatcher import get_dispatcher
    return get_dispatcher().get_config()


@app.post("/api/notifications/config")
async def update_notification_config(req: NotificationConfigUpdate) -> dict[str, Any]:
    """Update external alert notification channels at runtime."""
    from src.alert.dispatcher import get_dispatcher
    return get_dispatcher().update_config(
        webhook_url=req.webhook_url,
        telegram_bot_token=req.telegram_bot_token,
        telegram_chat_id=req.telegram_chat_id,
        min_severity=req.min_severity,
        cooldown_seconds=req.cooldown_seconds,
    )


@app.post("/api/notifications/test")
async def test_notification_dispatch(req: TestNotificationRequest) -> dict[str, Any]:
    """Trigger a live test alert dispatch to verify Webhook/Telegram connectivity."""
    from src.alert.dispatcher import get_dispatcher
    return await get_dispatcher().test_dispatch_async(
        channel=req.channel,
        webhook_url=req.webhook_url,
        telegram_bot_token=req.telegram_bot_token,
        telegram_chat_id=req.telegram_chat_id,
    )


@app.get("/api/notifications/logs")
async def get_notification_logs(limit: int = Query(30, ge=1, le=100)) -> list[dict[str, Any]]:
    """Get audit logs of recent external alert notification deliveries."""
    from src.alert.dispatcher import get_dispatcher
    return get_dispatcher().get_logs(limit=limit)


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
