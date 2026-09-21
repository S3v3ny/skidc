"""Minimal Skidc API client for the benchmark runner — stdlib urllib only.

The runner only needs three things from the server: create a project, read a project's
state (facts + status), and (optionally) list/stop. It never writes facts/intents —
that's the dispatcher's job. Workers reach the *target*, the runner reaches the *server*.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class SkidcError(RuntimeError):
    pass


class SkidcClient:
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, body: dict | None = None) -> dict | list:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "ignore")
            raise SkidcError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise SkidcError(f"{method} {path} -> {exc.reason}") from exc

    def health(self) -> bool:
        try:
            self._request("GET", "/projects")
            return True
        except SkidcError:
            return False

    def create_project(self, title: str, origin: str, goal: str,
                       hints: list[dict] | None = None,
                       bootstrap_enabled: bool = True) -> dict:
        body = {
            "title": title,
            "origin": origin,
            "goal": goal,
            "bootstrap_enabled": bootstrap_enabled,
        }
        if hints:
            body["hints"] = hints
        result = self._request("POST", "/projects", body)
        assert isinstance(result, dict)
        return result

    def get_project(self, project_id: str) -> dict:
        result = self._request("GET", f"/projects/{project_id}")
        assert isinstance(result, dict)
        return result

    def stop_project(self, project_id: str) -> None:
        try:
            self._request("PUT", f"/projects/{project_id}/status", {"status": "stopped"})
        except SkidcError:
            pass  # best-effort

    def delete_project(self, project_id: str) -> None:
        try:
            self._request("DELETE", f"/projects/{project_id}")
        except SkidcError:
            pass  # best-effort
