from __future__ import annotations

import csv
import json
from io import StringIO

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from app.services.capture import CaptureManager
from app.services.interfaces import list_network_interfaces
from app.services.parser import analyze_packet

app = FastAPI(title="Basic Network Sniffer", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

capture_manager = CaptureManager()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "app": "Basic Network Sniffer"}


@app.get("/api/interfaces")
def get_interfaces() -> list[dict[str, str | bool | list[str]]]:
    return list_network_interfaces()


@app.get("/api/status")
def get_status() -> dict[str, object]:
    return capture_manager.status()


@app.get("/api/packets")
def get_packets() -> list[dict[str, object]]:
    return [
        {key: value for key, value in packet.items() if key != "raw_bytes"}
        for packet in capture_manager.snapshot()
    ]


@app.get("/api/packets/export")
def export_packets(format: str = "json") -> Response:
    if format not in {"json", "csv"}:
        return Response(
            content=json.dumps({"message": "Format must be json or csv."}),
            status_code=400,
            media_type="application/json",
        )

    records = [
        {key: value for key, value in packet.items() if key != "raw_bytes"}
        for packet in capture_manager.snapshot()
    ]

    if format == "json":
        return Response(
            content=json.dumps(records, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="packets.json"'},
        )

    output = StringIO()
    if records:
        fieldnames = list(dict.fromkeys(key for record in records for key in record))
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="packets.csv"'},
    )


@app.post("/api/capture/start")
def start_capture(payload: dict[str, object]) -> dict[str, object]:
    interface = str(payload.get("interface", ""))
    packet_limit = int(payload.get("packet_limit", 100))
    duration = float(payload.get("duration", 10.0))
    bpf_filter = payload.get("bpf_filter")

    if not 1 <= packet_limit <= 100000:
        return {"status": "error", "message": "Packet limit must be between 1 and 100000."}
    if not 1 <= duration <= 3600:
        return {"status": "error", "message": "Duration must be between 1 and 3600 seconds."}

    try:
        capture_manager.start(interface=interface, packet_limit=packet_limit, duration=duration, bpf_filter=str(bpf_filter) if bpf_filter else None)
    except PermissionError as exc:
        return {"status": "permission_error", "message": str(exc)}
    except Exception as exc:  # pragma: no cover - defensive API layer
        return {"status": "error", "message": str(exc)}

    return {"status": "started", "interface": interface, "packet_limit": packet_limit, "duration": duration}


@app.post("/api/capture/stop")
def stop_capture() -> dict[str, object]:
    capture_manager.stop()
    return {"status": "stopped"}


@app.post("/api/packets/clear")
def clear_packets() -> dict[str, object]:
    if capture_manager.status()["running"]:
        return {"status": "error", "message": "Stop capture before clearing packet history."}
    capture_manager.clear()
    return {"status": "cleared", "packet_count": 0}


@app.post("/api/packets/analyze")
def analyze_live_packet(payload: dict[str, object]) -> dict[str, object]:
    raw = payload.get("packet")
    if not isinstance(raw, dict):
        return {"status": "error", "message": "Packet payload must be a dictionary"}

    # This is a simple compatibility endpoint for external packet objects.
    return {"status": "ok", "analysis": analyze_packet({})}
