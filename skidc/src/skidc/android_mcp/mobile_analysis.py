from __future__ import annotations

import json
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
PATH_RE = re.compile(rb"/(?:api|v[0-9]|auth|user|users|account|balance|transfer|transaction|login|signup)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*")
SECRET_RE = re.compile(rb"(?i)(api[_-]?key|secret|token|jwt|password|passwd|bearer)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{0,80}")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def tool_status() -> dict[str, str | None]:
    return {
        "adb": shutil.which("adb"),
        "aapt": shutil.which("aapt"),
        "apktool": shutil.which("apktool"),
        "jadx": shutil.which("jadx"),
        "frida": shutil.which("frida"),
        "frida-ps": shutil.which("frida-ps"),
        "mitmproxy": shutil.which("mitmproxy"),
    }


def analyze_apk(apk_path: Path, *, max_files: int = 400, max_bytes_per_file: int = 750_000) -> dict[str, Any]:
    if not apk_path.exists() or not apk_path.is_file():
        raise ValueError(f"apk not found: {apk_path}")
    if apk_path.suffix.lower() != ".apk":
        raise ValueError(f"expected an .apk file: {apk_path}")

    urls: set[str] = set()
    paths: set[str] = set()
    secrets: set[str] = set()
    interesting_files: list[str] = []
    permissions: set[str] = set()
    manifest_text: str | None = None

    with zipfile.ZipFile(apk_path) as archive:
        names = archive.namelist()
        for name in names:
            lower = name.lower()
            if lower == "androidmanifest.xml" or lower.endswith((".dex", ".so", ".xml", ".json", ".properties")):
                interesting_files.append(name)

        for name in names[:max_files]:
            info = archive.getinfo(name)
            if info.file_size > max_bytes_per_file:
                continue
            try:
                data = archive.read(name)
            except (KeyError, RuntimeError, zipfile.BadZipFile):
                continue

            if name.lower() == "androidmanifest.xml":
                decoded = _decode_text(data)
                if decoded and "<manifest" in decoded:
                    manifest_text = decoded
                    permissions.update(re.findall(r"android\.permission\.[A-Z0-9_]+", decoded))

            urls.update(_decode_match(match) for match in URL_RE.findall(data))
            paths.update(_decode_match(match) for match in PATH_RE.findall(data))
            secrets.update(_decode_match(match) for match in SECRET_RE.findall(data))

    endpoints = sorted(urls)[:200]
    endpoint_paths = sorted(paths)[:200]
    secret_hits = sorted(secrets)[:100]
    return {
        "apk_path": str(apk_path),
        "size_bytes": apk_path.stat().st_size,
        "analyzed_at": utc_now(),
        "tools": tool_status(),
        "manifest_decoded": manifest_text is not None,
        "permissions": sorted(permissions),
        "interesting_files": interesting_files[:200],
        "endpoints": endpoints,
        "endpoint_paths": endpoint_paths,
        "secret_indicators": secret_hits,
        "notes": [
            "Pure ZIP/string analysis is always available.",
            "Install jadx/apktool/aapt to enrich this report with decompiled sources and decoded manifest details.",
        ],
    }


def parse_network_import(content: str) -> list[dict[str, Any]]:
    text = content.strip()
    if not text:
        return []

    parsed: Any
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            events.append(_normalise_network_event(json.loads(line)))
        return events

    if isinstance(parsed, list):
        return [_normalise_network_event(item) for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        if isinstance(parsed.get("events"), list):
            return [_normalise_network_event(item) for item in parsed["events"] if isinstance(item, dict)]
        if isinstance(parsed.get("flows"), list):
            return [_normalise_network_event(item) for item in parsed["flows"] if isinstance(item, dict)]
        return [_normalise_network_event(parsed)]
    raise ValueError("network import must be a JSON object, JSON array, or JSONL content")


def lab_profiles() -> list[dict[str, Any]]:
    return [
        {
            "id": "dvba",
            "name": "Damn Vulnerable Bank",
            "source": "https://github.com/rewanthtammana/Damn-Vulnerable-Bank",
            "target_type": "android_app_plus_backend",
            "recommended_for": ["API inventory", "auth/session testing", "IDOR", "storage/logcat leakage"],
            "expected_output": [
                "Install and operate the vulnerable banking APK",
                "Capture login, profile, balance, transfer, beneficiary, and transaction traffic",
                "Correlate two-account actions with API requests",
                "Produce evidence-backed mobile API findings",
            ],
        },
        {
            "id": "bugbazaar",
            "name": "BugBazaar",
            "source": "https://github.com/payatu/BugBazaar",
            "target_type": "android_native_vulnerability_lab",
            "recommended_for": ["WebView", "deep link", "IPC", "storage", "runtime instrumentation"],
            "expected_output": [
                "Navigate native Android vulnerability modules",
                "Collect UI, logcat, static reverse, and Frida observations",
                "Produce Android-native vulnerability evidence",
            ],
        },
    ]


def frida_script_templates() -> list[dict[str, str]]:
    return [
        {
            "id": "okhttp_request_observer",
            "name": "OkHttp request observer",
            "purpose": "Record URLs, headers, and request metadata observed inside the app runtime.",
        },
        {
            "id": "retrofit_endpoint_observer",
            "name": "Retrofit endpoint observer",
            "purpose": "Record Retrofit interface methods and generated endpoint paths.",
        },
        {
            "id": "ssl_pinning_observer",
            "name": "SSL pinning observer",
            "purpose": "Identify certificate pinning checks during authorized lab testing.",
        },
        {
            "id": "token_source_observer",
            "name": "Token source observer",
            "purpose": "Trace where authorization tokens are read or written at runtime.",
        },
    ]


def _normalise_network_event(item: dict[str, Any]) -> dict[str, Any]:
    request = item.get("request") if isinstance(item.get("request"), dict) else {}
    response = item.get("response") if isinstance(item.get("response"), dict) else {}
    url = item.get("url") or request.get("url") or item.get("pretty_url")
    if not url:
        raise ValueError("network event is missing url")
    return {
        "method": item.get("method") or request.get("method"),
        "url": str(url),
        "status_code": item.get("status_code") or response.get("status_code") or response.get("status"),
        "request_headers": _string_map(item.get("request_headers") or request.get("headers") or {}),
        "response_headers": _string_map(item.get("response_headers") or response.get("headers") or {}),
        "request_body_preview": item.get("request_body_preview") or request.get("body") or request.get("content"),
        "response_body_preview": item.get("response_body_preview") or response.get("body") or response.get("content"),
        "note": item.get("note") or item.get("source"),
        "imported_at": utc_now(),
    }


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _decode_match(value: bytes) -> str:
    return value.decode("utf-8", errors="ignore").strip("\x00\r\n\t ")


def _decode_text(value: bytes) -> str | None:
    for encoding in ("utf-8", "utf-16", "latin1"):
        try:
            return value.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None
