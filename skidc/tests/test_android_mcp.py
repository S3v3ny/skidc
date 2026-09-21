from __future__ import annotations

import zipfile

from fastapi.testclient import TestClient

from skidc.android_mcp.app import app, state
from skidc.android_mcp.adb import parse_uiautomator_xml
from skidc.android_mcp.mobile_analysis import analyze_apk, parse_network_import


def test_parse_uiautomator_xml_extracts_useful_nodes() -> None:
    xml = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
    <hierarchy rotation="0">
      <node text="" resource-id="" class="android.widget.FrameLayout" package="p" clickable="false" enabled="true" bounds="[0,0][100,100]">
        <node text="登录" resource-id="com.demo:id/login" class="android.widget.Button" package="p" clickable="true" enabled="true" bounds="[10,20][80,60]" />
        <node text="" content-desc="更多" resource-id="" class="android.widget.ImageButton" package="p" clickable="true" enabled="true" bounds="[80,20][100,60]" />
      </node>
    </hierarchy>
    """

    nodes = parse_uiautomator_xml(xml)

    assert nodes == [
        {
            "text": "登录",
            "resource_id": "com.demo:id/login",
            "content_desc": "",
            "class": "android.widget.Button",
            "package": "p",
            "clickable": True,
            "enabled": True,
            "bounds": "[10,20][80,60]",
        },
        {
            "text": "",
            "resource_id": "",
            "content_desc": "更多",
            "class": "android.widget.ImageButton",
            "package": "p",
            "clickable": True,
            "enabled": True,
            "bounds": "[80,20][100,60]",
        },
    ]


def test_parse_uiautomator_xml_returns_empty_on_invalid_xml() -> None:
    assert parse_uiautomator_xml("<bad") == []


def test_network_import_accepts_jsonl_mitm_style_events() -> None:
    content = """
{"request":{"method":"POST","url":"https://bank.test/api/login","headers":{"Authorization":"Bearer redacted"}},"response":{"status_code":200}}
{"method":"GET","url":"https://bank.test/api/balance","status_code":200}
"""

    events = parse_network_import(content)

    assert [event["url"] for event in events] == [
        "https://bank.test/api/login",
        "https://bank.test/api/balance",
    ]
    assert events[0]["method"] == "POST"
    assert events[0]["response_headers"] == {}


def test_analyze_apk_extracts_strings_from_zip(tmp_path) -> None:
    apk = tmp_path / "demo.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"https://bank.test/api/login\x00/api/transfer\x00jwt_token")

    report = analyze_apk(apk)

    assert "https://bank.test/api/login" in report["endpoints"]
    assert "/api/transfer" in report["endpoint_paths"]
    assert any("jwt" in item.lower() for item in report["secret_indicators"])


def test_android_mcp_records_import_reverse_and_frida(tmp_path) -> None:
    client = TestClient(app)
    state.network_events.clear()
    state.reverse_reports.clear()
    state.frida_observations.clear()

    network = client.post(
        "/network/import",
        json={"source": "mitmproxy", "content": '{"events":[{"method":"GET","url":"https://bank.test/api/profile","status_code":200}]}'},
    )
    assert network.status_code == 200
    assert network.json()["stored"] == 1
    assert client.get("/network/history").json()["events"][0]["source"] == "mitmproxy"

    apk = tmp_path / "lab.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"https://bank.test/api/transactions")

    reverse = client.post("/reverse/analyze", json={"apk_path": str(apk)})
    assert reverse.status_code == 200
    assert "https://bank.test/api/transactions" in reverse.json()["endpoints"]
    assert client.get("/reverse/reports").json()["reports"]

    frida = client.post(
        "/frida/observations",
        json={
            "package": "com.demo.bank",
            "script_id": "okhttp_request_observer",
            "event_type": "http_request",
            "summary": "Observed OkHttp request to profile endpoint",
            "details": {"url": "https://bank.test/api/profile"},
        },
    )
    assert frida.status_code == 200
    assert client.get("/frida/observations").json()["observations"][0]["script_id"] == "okhttp_request_observer"
