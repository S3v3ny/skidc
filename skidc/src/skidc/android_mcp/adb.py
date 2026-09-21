from __future__ import annotations

import base64
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


class AndroidCommandError(RuntimeError):
    def __init__(self, message: str, *, returncode: int, stdout: str, stderr: str):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


class AdbController:
    """Small, deliberately narrow wrapper around adb.

    The bridge exposes high-level device/app actions instead of a raw unrestricted
    shell. That keeps the Android target controllable by agents without turning the
    service into an arbitrary command runner.
    """

    def __init__(self, adb_path: str = "adb", device_id: str | None = None, timeout: int = 20):
        self.adb_path = adb_path
        self.device_id = device_id
        self.timeout = timeout

    def devices(self) -> list[dict[str, str]]:
        result = self._adb("devices", "-l")
        devices: list[dict[str, str]] = []
        for line in result.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            entry = {"id": parts[0], "state": parts[1]}
            for item in parts[2:]:
                if ":" in item:
                    key, value = item.split(":", 1)
                    entry[key] = value
            devices.append(entry)
        return devices

    def health(self) -> dict[str, Any]:
        result = self._adb("version")
        return {
            "ok": True,
            "adb": result.stdout.strip(),
            "device_id": self.device_id,
            "devices": self.devices(),
        }

    def install_apk(self, apk_path: Path, reinstall: bool = True) -> dict[str, str]:
        if not apk_path.exists() or not apk_path.is_file():
            raise ValueError(f"apk not found: {apk_path}")
        args = ["install"]
        if reinstall:
            args.append("-r")
        args.append(str(apk_path))
        result = self._adb(*args, timeout=max(self.timeout, 120))
        return {"status": "installed", "stdout": result.stdout.strip()}

    def start_app(self, package: str, activity: str | None = None) -> dict[str, str]:
        if activity:
            component = f"{package}/{activity}"
            result = self._adb_shell("am", "start", "-n", component)
        else:
            result = self._adb_shell(
                "monkey",
                "-p",
                package,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            )
        return {"status": "started", "stdout": result.stdout.strip()}

    def stop_app(self, package: str) -> dict[str, str]:
        result = self._adb_shell("am", "force-stop", package)
        return {"status": "stopped", "stdout": result.stdout.strip()}

    def clear_app_data(self, package: str) -> dict[str, str]:
        result = self._adb_shell("pm", "clear", package)
        return {"status": "cleared", "stdout": result.stdout.strip()}

    def tap(self, x: int, y: int) -> dict[str, int]:
        self._adb_shell("input", "tap", str(x), str(y))
        return {"x": x, "y": y}

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300) -> dict[str, int]:
        self._adb_shell("input", "swipe", str(x1), str(y1), str(x2), str(y2), str(duration_ms))
        return {"x1": x1, "y1": y1, "x2": x2, "y2": y2, "duration_ms": duration_ms}

    def type_text(self, text: str) -> dict[str, str]:
        # Android's input command uses %s for spaces. Complex IME text entry can
        # be added later; this MVP covers common account/password/test strings.
        encoded = text.replace(" ", "%s")
        self._adb_shell("input", "text", encoded)
        return {"text": text}

    def press_key(self, key: str) -> dict[str, str]:
        self._adb_shell("input", "keyevent", key)
        return {"key": key}

    def screenshot_base64(self) -> dict[str, str]:
        argv = self._base_argv() + ["exec-out", "screencap", "-p"]
        result = self._run(argv, timeout=self.timeout, binary=True)
        png = result.stdout.encode("latin1")
        return {"mime_type": "image/png", "png_base64": base64.b64encode(png).decode("ascii")}

    def dump_ui(self) -> dict[str, Any]:
        remote = "/sdcard/skidc-window.xml"
        self._adb_shell("uiautomator", "dump", remote)
        result = self._adb("exec-out", "cat", remote)
        xml = result.stdout
        return {"xml": xml, "nodes": parse_uiautomator_xml(xml)}

    def current_activity(self) -> dict[str, str | None]:
        result = self._adb_shell("dumpsys", "window")
        text = result.stdout
        patterns = (
            r"mCurrentFocus=Window\{[^ ]+ [^ ]+ ([^}]+)\}",
            r"mFocusedApp=.* ActivityRecord\{[^ ]+ [^ ]+ ([^ ]+) ",
            r"topResumedActivity=ActivityRecord\{[^ ]+ [^ ]+ ([^ ]+) ",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return {"activity": match.group(1)}
        return {"activity": None}

    def logcat_tail(self, lines: int = 200) -> dict[str, str]:
        bounded = max(1, min(lines, 2000))
        result = self._adb("logcat", "-d", "-t", str(bounded))
        return {"lines": result.stdout}

    def set_http_proxy(self, host: str, port: int) -> dict[str, str | int]:
        proxy = f"{host}:{port}"
        self._adb_shell("settings", "put", "global", "http_proxy", proxy)
        return {"status": "proxy_set", "host": host, "port": port}

    def clear_http_proxy(self) -> dict[str, str]:
        self._adb_shell("settings", "put", "global", "http_proxy", ":0")
        self._adb_shell("settings", "delete", "global", "http_proxy")
        return {"status": "proxy_cleared"}

    def _adb_shell(self, *args: str, timeout: int | None = None) -> CommandResult:
        return self._adb("shell", *args, timeout=timeout)

    def _adb(self, *args: str, timeout: int | None = None) -> CommandResult:
        return self._run(self._base_argv() + list(args), timeout=timeout or self.timeout)

    def _base_argv(self) -> list[str]:
        argv = [self.adb_path]
        if self.device_id:
            argv.extend(["-s", self.device_id])
        return argv

    @staticmethod
    def _run(argv: list[str], *, timeout: int, binary: bool = False) -> CommandResult:
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("adb executable not found; install Android Platform Tools or set --adb-path") from exc
        except subprocess.TimeoutExpired as exc:
            stdout = _decode_output(exc.stdout, binary=binary)
            stderr = _decode_output(exc.stderr, binary=binary)
            raise AndroidCommandError(
                f"adb command timed out after {timeout}s",
                returncode=124,
                stdout=stdout,
                stderr=stderr,
            ) from exc

        stdout = _decode_output(completed.stdout, binary=binary)
        stderr = _decode_output(completed.stderr, binary=binary)
        result = CommandResult(argv=argv, returncode=completed.returncode, stdout=stdout, stderr=stderr)
        if completed.returncode != 0:
            raise AndroidCommandError(
                f"adb command failed: {' '.join(argv)}",
                returncode=completed.returncode,
                stdout=stdout,
                stderr=stderr,
            )
        return result


def parse_uiautomator_xml(xml: str) -> list[dict[str, Any]]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return []

    nodes: list[dict[str, Any]] = []
    for node in root.iter("node"):
        attrs = node.attrib
        text = attrs.get("text") or ""
        resource_id = attrs.get("resource-id") or ""
        content_desc = attrs.get("content-desc") or ""
        if not any((text, resource_id, content_desc, attrs.get("clickable") == "true")):
            continue
        nodes.append(
            {
                "text": text,
                "resource_id": resource_id,
                "content_desc": content_desc,
                "class": attrs.get("class") or "",
                "package": attrs.get("package") or "",
                "clickable": attrs.get("clickable") == "true",
                "enabled": attrs.get("enabled") == "true",
                "bounds": attrs.get("bounds") or "",
            }
        )
    return nodes


def _decode_output(value: bytes | str | None, *, binary: bool = False) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if binary:
        return value.decode("latin1")
    return value.decode("utf-8", errors="replace")
