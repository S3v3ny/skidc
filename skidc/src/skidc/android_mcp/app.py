from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from skidc.android_mcp.adb import AdbController, AndroidCommandError
from skidc.android_mcp.mobile_analysis import (
    analyze_apk,
    frida_script_templates,
    lab_profiles,
    parse_network_import,
    tool_status,
    utc_now,
)


class AndroidMcpState:
    def __init__(self) -> None:
        self.controller = AdbController()
        self.network_events: list[dict[str, Any]] = []
        self.reverse_reports: list[dict[str, Any]] = []
        self.frida_observations: list[dict[str, Any]] = []


state = AndroidMcpState()

app = FastAPI(
    title="Skidc Android MCP Bridge",
    description="Minimal Android emulator/app control bridge for authorized mobile testing",
    version="0.1.0",
)


def configure(*, adb_path: str = "adb", device_id: str | None = None, timeout: int = 20) -> None:
    state.controller = AdbController(adb_path=adb_path, device_id=device_id, timeout=timeout)


class PackageRequest(BaseModel):
    package: str = Field(min_length=1)

    @field_validator("package")
    @classmethod
    def validate_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class InstallRequest(BaseModel):
    apk_path: str = Field(min_length=1)
    reinstall: bool = True


class StartAppRequest(PackageRequest):
    activity: str | None = None


class TapRequest(BaseModel):
    x: int = Field(ge=0)
    y: int = Field(ge=0)


class SwipeRequest(BaseModel):
    x1: int = Field(ge=0)
    y1: int = Field(ge=0)
    x2: int = Field(ge=0)
    y2: int = Field(ge=0)
    duration_ms: int = Field(default=300, ge=0, le=10000)


class TextRequest(BaseModel):
    text: str


class KeyRequest(BaseModel):
    key: str = Field(min_length=1)


class LogcatRequest(BaseModel):
    lines: int = Field(default=200, ge=1, le=2000)


class NetworkEvent(BaseModel):
    method: str | None = None
    url: str
    status_code: int | None = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    request_body_preview: str | None = None
    response_body_preview: str | None = None
    note: str | None = None


class NetworkImportRequest(BaseModel):
    content: str = Field(min_length=1)
    source: str = "manual"


class ProxyRequest(BaseModel):
    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(ge=1, le=65535)


class ApkAnalyzeRequest(BaseModel):
    apk_path: str = Field(min_length=1)


class FridaObservation(BaseModel):
    package: str = Field(min_length=1)
    script_id: str | None = None
    event_type: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)


@app.exception_handler(AndroidCommandError)
def adb_error_handler(_request, exc: AndroidCommandError):
    return JSONResponse(
        status_code=502,
        content={
            "message": str(exc),
            "returncode": exc.returncode,
            "stdout": exc.stdout[-2000:],
            "stderr": exc.stderr[-2000:],
        },
    )


@app.get("/health")
def health():
    payload = state.controller.health()
    payload["mobile_tools"] = tool_status()
    return payload


@app.get("/devices")
def devices():
    return {"devices": state.controller.devices()}


@app.post("/app/install")
def install_app(body: InstallRequest):
    try:
        return state.controller.install_apk(Path(body.apk_path), reinstall=body.reinstall)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/app/start")
def start_app(body: StartAppRequest):
    return state.controller.start_app(body.package, body.activity)


@app.post("/app/stop")
def stop_app(body: PackageRequest):
    return state.controller.stop_app(body.package)


@app.post("/app/clear")
def clear_app_data(body: PackageRequest):
    return state.controller.clear_app_data(body.package)


@app.post("/input/tap")
def tap(body: TapRequest):
    return state.controller.tap(body.x, body.y)


@app.post("/input/swipe")
def swipe(body: SwipeRequest):
    return state.controller.swipe(body.x1, body.y1, body.x2, body.y2, body.duration_ms)


@app.post("/input/text")
def type_text(body: TextRequest):
    return state.controller.type_text(body.text)


@app.post("/input/key")
def press_key(body: KeyRequest):
    return state.controller.press_key(body.key)


@app.post("/input/back")
def press_back():
    return state.controller.press_key("BACK")


@app.post("/input/home")
def press_home():
    return state.controller.press_key("HOME")


@app.get("/observe/screenshot")
def screenshot():
    return state.controller.screenshot_base64()


@app.get("/observe/ui")
def dump_ui():
    return state.controller.dump_ui()


@app.get("/observe/activity")
def current_activity():
    return state.controller.current_activity()


@app.post("/observe/logcat")
def logcat_tail(body: LogcatRequest):
    return state.controller.logcat_tail(body.lines)


@app.get("/network/history")
def network_history(limit: int = 100):
    bounded = max(1, min(limit, 1000))
    return {"events": state.network_events[-bounded:]}


@app.post("/network/events")
def add_network_event(event: NetworkEvent):
    payload = event.model_dump()
    payload["recorded_at"] = utc_now()
    state.network_events.append(payload)
    return {"stored": True, "index": len(state.network_events) - 1}


@app.post("/network/import")
def import_network_events(body: NetworkImportRequest):
    try:
        events = parse_network_import(body.content)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    for event in events:
        event["source"] = body.source
    state.network_events.extend(events)
    return {"stored": len(events), "total": len(state.network_events), "source": body.source}


@app.post("/network/proxy/set")
def set_network_proxy(body: ProxyRequest):
    return state.controller.set_http_proxy(body.host, body.port)


@app.post("/network/proxy/clear")
def clear_network_proxy():
    return state.controller.clear_http_proxy()


@app.delete("/network/history")
def clear_network_history():
    state.network_events.clear()
    return {"cleared": True}


@app.post("/reverse/analyze")
def reverse_analyze(body: ApkAnalyzeRequest):
    try:
        report = analyze_apk(Path(body.apk_path))
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    state.reverse_reports.append(report)
    return report


@app.get("/reverse/reports")
def reverse_reports(limit: int = 20):
    bounded = max(1, min(limit, 100))
    return {"reports": state.reverse_reports[-bounded:]}


@app.delete("/reverse/reports")
def clear_reverse_reports():
    state.reverse_reports.clear()
    return {"cleared": True}


@app.get("/frida/scripts")
def frida_scripts():
    return {"templates": frida_script_templates(), "tools": tool_status()}


@app.post("/frida/observations")
def add_frida_observation(body: FridaObservation):
    payload = body.model_dump()
    payload["recorded_at"] = utc_now()
    state.frida_observations.append(payload)
    return {"stored": True, "index": len(state.frida_observations) - 1}


@app.get("/frida/observations")
def frida_observations(limit: int = 100):
    bounded = max(1, min(limit, 1000))
    return {"observations": state.frida_observations[-bounded:]}


@app.delete("/frida/observations")
def clear_frida_observations():
    state.frida_observations.clear()
    return {"cleared": True}


@app.get("/lab/profiles")
def labs():
    return {"profiles": lab_profiles()}
