from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlparse


TEST_FAMILY_REFS = {
    "surface_config": ["WSTG-v4.2-INFO", "WSTG-v4.2-CONF", "WSTG-v4.2-ERRH", "ASVS-v5.0.0-Chapter-13"],
    "identity_auth": ["WSTG-v4.2-IDNT", "WSTG-v4.2-ATHN", "ASVS-v5.0.0-Chapter-06"],
    "authorization": ["WSTG-v4.2-ATHZ", "ASVS-v5.0.0-Chapter-08", "OWASP-API1:2023"],
    "session_csrf": ["WSTG-v4.2-SESS", "ASVS-v5.0.0-Chapter-07"],
    "injection": ["WSTG-v4.2-INPV", "ASVS-v5.0.0-Chapter-01"],
    "file_path": ["WSTG-v4.2-ATHZ", "WSTG-v4.2-INPV", "ASVS-v5.0.0-Chapter-05"],
    "server_side_processing": ["WSTG-v4.2-INPV", "ASVS-v5.0.0-Chapter-01", "ASVS-v5.0.0-Chapter-04"],
    "client_side": ["WSTG-v4.2-CLNT", "ASVS-v5.0.0-Chapter-03"],
    "business_logic": ["WSTG-v4.2-BUSL", "ASVS-v5.0.0-Chapter-02"],
    "crypto_transport": ["WSTG-v4.2-CRYP", "ASVS-v5.0.0-Chapter-11", "ASVS-v5.0.0-Chapter-12"],
    "api_behavior": ["WSTG-v4.2-API", "ASVS-v5.0.0-Chapter-04", "OWASP-API-Security-2023"],
    "support_service": ["WSTG-v4.2-CONF", "ASVS-v5.0.0-Chapter-13", "Scope-Policy-Support-Service"],
}

_INTENT_FAMILY_TERMS = {
    "surface_config": ("recon", "discover", "enumerate", "fingerprint", "route", "directory", "exposure", "config"),
    "identity_auth": ("login", "signin", "authentication", "auth bypass", "credential", "password", "account enumeration"),
    "authorization": ("authorization", "authz", "idor", "privilege", "access control", "horizontal", "vertical"),
    "session_csrf": ("session", "cookie", "csrf", "logout", "jwt"),
    "injection": ("injection", "sql", "sqli", "sqlmap", "command injection", "ssti"),
    "file_path": ("upload", "download", "file inclusion", "path traversal", "lfi", "rfi"),
    "server_side_processing": ("ssrf", "xxe", "xml", "webhook", "callback", "template injection", "deserialization"),
    "client_side": ("xss", "cors", "clickjacking", "dom", "client-side", "client side"),
    "business_logic": ("business logic", "workflow", "replay", "race condition", "sequence", "invariant"),
    "crypto_transport": ("tls", "ssl", "https", "transport security", "cryptographic"),
    "api_behavior": ("api", "graphql", "rest", "bola", "bfla", "mass assignment"),
    "support_service": ("mysql", "redis", "database", "middleware", "support service"),
}

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_STATE_CHANGE_TERMS = ("delete", "remove", "logout", "install", "update", "edit", "submit", "save", "add", "reply")
_STATIC_SUFFIXES = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2"}
_OBJECT_PARAMS = {"id", "uid", "user_id", "userid", "cid", "pid", "order_id", "account_id", "file_id"}


def normalize_surface_map(surface_map: dict, *, support_ports: Iterable[int] = ()) -> list[dict]:
    entries: list[tuple[object, str | None]] = []
    for key, surface_type in (
        ("surfaces", None),
        ("routes", "route"),
        ("endpoints", "route"),
        ("pages", "route"),
        ("admin_routes", "admin_route"),
        ("forms", "form"),
        ("upload_points", "upload_point"),
        ("params", "param"),
        ("services", "service"),
    ):
        for entry in _as_list(surface_map.get(key)):
            entries.append((entry, surface_type))

    merged: dict[str, dict] = {}
    for entry, type_hint in entries:
        normalized = normalize_surface_entry(entry, type_hint=type_hint, support_ports=support_ports)
        if normalized is None:
            continue
        fingerprint = normalized["fingerprint"]
        previous = merged.get(fingerprint)
        if previous is None:
            merged[fingerprint] = normalized
            continue
        previous["params"] = sorted(set(previous["params"]) | set(normalized["params"]))
        previous["roles"] = sorted(set(previous["roles"]) | set(normalized["roles"]))
        previous["traits"].update({key: value for key, value in normalized["traits"].items() if value})
    return list(merged.values())


def normalize_surface_entry(
    entry: object,
    *,
    type_hint: str | None = None,
    support_ports: Iterable[int] = (),
) -> dict | None:
    raw = {"url": entry} if isinstance(entry, str) else dict(entry) if isinstance(entry, dict) else None
    if raw is None:
        return None
    endpoint = _first_text(raw, "endpoint")
    url = _first_text(raw, "url") or (endpoint if endpoint and "://" in endpoint else None)
    parsed = urlparse(url) if url else None
    target = _first_text(raw, "host", "target")
    if parsed and parsed.hostname:
        target = parsed.hostname
    port = _first_int(raw, "port") or (parsed.port if parsed else None)
    if port is None and parsed and parsed.scheme:
        port = 443 if parsed.scheme == "https" else 80
    path = _first_text(raw, "path", "route") or (endpoint if endpoint and "://" not in endpoint else None)
    if (not path or not path.startswith("/")) and parsed and parsed.path:
        path = parsed.path
    path_template = _path_template(path)
    method = (_first_text(raw, "method") or "GET").upper()
    path_query = urlparse(path).query if path else ""
    params = _surface_params(raw, (parsed.query if parsed else "") or path_query)
    surface_type = (_first_text(raw, "surface_type", "type") or type_hint or "route").lower()
    text = " ".join(
        str(value)
        for value in (
            surface_type, target, path_template, params, raw.get("name"), raw.get("risk"), raw.get("summary"), raw.get("description")
        ) if value
    ).lower()
    service_like = surface_type in {"database", "middleware", "support_service"}
    support = port in set(support_ports)
    auth = any(token in text for token in ("login", "signin", "auth", "password", "register", "recover"))
    admin = "admin" in text or "manage" in text
    upload = "upload" in text or surface_type == "upload_point"
    download = any(token in text for token in ("download", "export", "attachment", "file"))
    api = any(token in text for token in ("/api/", "graphql", "application/json", "rest"))
    writes = (
        method in _WRITE_METHODS
        or surface_type in {"form", "upload_point"}
        or any(token in text for token in _STATE_CHANGE_TERMS)
    )
    has_input = bool(params) or surface_type in {"form", "param", "upload_point"}
    object_reference = bool(set(params) & _OBJECT_PARAMS) or any(token in text for token in ("object", "record", "profile"))
    url_input = any(token in text for token in ("url", "uri", "webhook", "callback", "remote", "fetch"))
    xml_input = "xml" in text or "soap" in text
    template_input = any(token in text for token in ("template", "render", "view"))
    reflects_input = has_input and any(token in text for token in ("search", "contact", "comment", "message", "name", "query", "keyword"))
    roles = _string_list(raw.get("roles"))
    auth_context = _first_text(raw, "auth_context") or (
        "anonymous" if auth else "admin" if admin else "authenticated" if raw.get("authenticated") else "anonymous"
    )
    traits = {
        "support_service": support,
        "out_of_scope_support": service_like and not support,
        "static": _is_static(path_template),
        "auth": auth,
        "admin": admin,
        "has_input": has_input,
        "writes": writes,
        "upload": upload,
        "download": download,
        "api": api,
        "object_reference": object_reference,
        "url_input": url_input,
        "xml_input": xml_input,
        "template_input": template_input,
        "reflects_input": reflects_input,
    }
    surface_group = _first_text(raw, "surface_group") or _surface_group(
        target, port, path_template, surface_type, traits
    )
    identity = {
        "target": (target or "").lower(),
        "port": port,
        "method": method,
        "path": path_template,
        "params": params,
        "auth": auth_context.lower(),
    }
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
    return {
        "fingerprint": fingerprint,
        "surface_group": surface_group,
        "target": target,
        "port": port,
        "method": method,
        "path_template": path_template,
        "params": params,
        "surface_type": surface_type,
        "auth_context": auth_context,
        "roles": roles,
        "traits": traits,
    }


def build_web_coverage_profile(surface: dict, *, source_fact_id: str | None = None, intent_id: str | None = None) -> list[dict]:
    traits = surface.get("traits") or {}
    if traits.get("out_of_scope_support"):
        return []
    if traits.get("support_service"):
        return [_coverage_item(surface, "support_service", "Allowed support service is in scope for configuration review.", source_fact_id, intent_id)]
    families: list[tuple[str, str]] = [("surface_config", "Discovered Web surface requires configuration and exposure review.")]
    if traits.get("auth"):
        families.append(("identity_auth", "Surface implements identity or authentication behavior."))
    if _authorization_applicable(surface):
        families.append(("authorization", "Surface crosses an object, role, or administrative authorization boundary."))
    if traits.get("auth") or traits.get("writes"):
        families.append(("session_csrf", "Surface creates session state or performs a state-changing request."))
    if traits.get("has_input"):
        families.append(("injection", "Surface accepts user-controlled input processed by the server."))
    if traits.get("upload") or traits.get("download") or _has_file_param(surface):
        families.append(("file_path", "Surface uploads, downloads, or resolves file/path input."))
    if traits.get("url_input") or traits.get("xml_input") or traits.get("template_input"):
        families.append(("server_side_processing", "Surface accepts URL, XML, template, or parser-controlled input."))
    if traits.get("reflects_input") or surface.get("surface_type") == "form":
        families.append(("client_side", "Input-bearing browser surface may reach an HTML or script output context."))
    if traits.get("writes"):
        families.append(("business_logic", "State-changing workflow requires replay, sequencing, and invariant checks."))
    if traits.get("api"):
        families.append(("api_behavior", "Surface exposes API semantics and object/function authorization boundaries."))
    if surface.get("port") == 443 and surface.get("path_template") in {None, "", "/"}:
        families.append(("crypto_transport", "Origin transport and externally observable cryptographic controls require review."))
    return [_coverage_item(surface, family, reason, source_fact_id, intent_id) for family, reason in families]


def build_profile_for_surfaces(surfaces: list[dict], *, source_fact_id: str | None = None) -> list[dict]:
    items: dict[tuple[str, str, str], dict] = {}
    for surface in surfaces:
        for item in build_web_coverage_profile(surface, source_fact_id=source_fact_id):
            auth_key = "any" if item["test_family"] == "surface_config" else item.get("auth_context") or "anonymous"
            key = (
                item.get("surface_fingerprint") or "",
                item["test_family"],
                auth_key,
            )
            previous = items.get(key)
            if previous is None:
                items[key] = item
                continue
            previous["test_variants"] = sorted(set(previous["test_variants"]) | set(item["test_variants"]))
            previous["roles"] = sorted(set(previous["roles"]) | set(item["roles"]))
            previous["priority"] = max(previous["priority"], item["priority"])
    return list(items.values())


def bind_profile_to_intent(items: list[dict], seed: dict, intent_id: str, *, limit: int = 1) -> list[dict]:
    """Bind one named test family to an intent; keep the rest as independent pending work."""
    available = {str(item.get("test_family")) for item in items if item.get("test_family")}
    text_parts = [
        seed.get("description"),
        seed.get("action_kind"),
        seed.get("test_variant"),
        seed.get("surface_type"),
        seed.get("path"),
        seed.get("param"),
        *(seed.get("suggested_tools") or []),
    ]
    text = " ".join(str(part) for part in text_parts if part).lower()
    selected = [
        family
        for family, terms in _INTENT_FAMILY_TERMS.items()
        if family in available and any(term in text for term in terms)
    ][:limit]
    if not selected:
        selected = [
            item["test_family"]
            for item in sorted(items, key=lambda item: (-(item.get("priority") or 0), item.get("test_family") or ""))
            if item.get("test_family")
        ][:1]
    selected_set = set(selected)
    return [
        {**item, **({"intent_id": intent_id} if item.get("test_family") in selected_set else {})}
        for item in items
    ]


def _authorization_applicable(surface: dict) -> bool:
    traits = surface.get("traits") or {}
    if traits.get("static"):
        return False
    if traits.get("object_reference") or surface.get("roles"):
        return True
    auth_context = str(surface.get("auth_context") or "anonymous").casefold()
    return bool(
        traits.get("admin")
        and (traits.get("writes") or auth_context in {"authenticated", "admin"})
    )


def _coverage_item(surface: dict, family: str, reason: str, source_fact_id: str | None, intent_id: str | None) -> dict:
    variants = _variants(family, surface)
    required = family not in {"surface_config", "support_service"}
    surface_group = surface["surface_group"]
    if family == "surface_config":
        surface_group = f"config:{surface.get('target') or 'origin'}:{surface.get('port') or 'default'}"
    if family == "crypto_transport":
        surface_group = f"transport:{surface.get('target') or 'origin'}:{surface.get('port') or 'default'}"
    return {
        "item_type": "service" if family == "support_service" else "vuln_class",
        "target": surface.get("target"),
        "port": surface.get("port"),
        "method": surface.get("method"),
        "path": surface.get("path_template"),
        "param": ",".join(surface.get("params") or []) or None,
        "description": f"{surface_group} x {family} ({surface.get('auth_context') or 'anonymous'})",
        "priority": _priority(family, surface),
        "source_fact_id": source_fact_id,
        "intent_id": intent_id,
        "surface_group": surface_group,
        "surface_fingerprint": surface.get("fingerprint"),
        "test_family": family,
        "test_variants": variants,
        "auth_context": surface.get("auth_context") or "anonymous",
        "roles": surface.get("roles") or [],
        "applicability_reason": reason,
        "required": required,
        "disposition": "required" if required else "excluded",
        "disposition_reason": None if required else reason,
        "standard_refs": TEST_FAMILY_REFS[family],
        "execution_status": "untested",
    }


def _variants(family: str, surface: dict) -> list[str]:
    traits = surface.get("traits") or {}
    params = set(surface.get("params") or [])
    if family == "identity_auth":
        return ["default_credentials", "auth_bypass", "account_enumeration"]
    if family == "authorization":
        return ["idor", "vertical_access", "horizontal_access"]
    if family == "session_csrf":
        return ["cookie_session", "csrf"]
    if family == "injection":
        variants = ["sql"]
        if {"cmd", "command", "exec"} & params:
            variants.append("command")
        if traits.get("template_input"):
            variants.append("ssti")
        return variants
    if family == "file_path":
        return [name for name, enabled in (("upload", traits.get("upload")), ("path_traversal", True), ("file_inclusion", True)) if enabled]
    if family == "server_side_processing":
        return [name for name, enabled in (("ssrf", traits.get("url_input")), ("xxe", traits.get("xml_input")), ("unsafe_template", traits.get("template_input"))) if enabled]
    if family == "client_side":
        return ["xss", "cors", "clickjacking"]
    if family == "business_logic":
        return ["workflow_integrity"]
    if family == "crypto_transport":
        return ["tls_transport"]
    if family == "api_behavior":
        return ["bola", "bfla", "mass_assignment", "resource_consumption"]
    return []


def _priority(family: str, surface: dict) -> int:
    base = {
        "surface_config": 5,
        "identity_auth": 8,
        "authorization": 8,
        "session_csrf": 7,
        "injection": 7,
        "file_path": 8,
        "server_side_processing": 7,
        "client_side": 6,
        "business_logic": 6,
        "crypto_transport": 5,
        "api_behavior": 8,
        "support_service": 4,
    }[family]
    if family == "file_path" and (surface.get("traits") or {}).get("upload"):
        return 10
    return base


def _surface_group(target: str | None, port: int | None, path: str | None, surface_type: str, traits: dict) -> str:
    if traits.get("support_service"):
        return f"support:{target or 'host'}:{port or 'unknown'}"
    if traits.get("static"):
        parent = "/".join((path or "/static").split("/")[:-1]) or "/"
        return f"static:{parent}"
    if traits.get("auth"):
        return f"auth:{path or '/'}"
    if traits.get("upload"):
        return f"upload:{path or '/'}"
    segments = [segment for segment in (path or "/").split("/") if segment]
    if traits.get("api"):
        meaningful = [segment for segment in segments if segment.lower() not in {"api", "v1", "v2", "v3"}]
        return "api:" + (meaningful[0] if meaningful else "root")
    if not segments:
        return f"web:{target or 'origin'}:{port or 'default'}"
    leaf = re.sub(r"\.[a-z0-9]+$", "", segments[-1], flags=re.IGNORECASE)
    prefix = "/".join(segments[:-1][-1:] + [leaf])
    return f"web:/{prefix}"


def _path_template(path: str | None) -> str | None:
    if not path:
        return None
    clean = path.split("?", 1)[0] or "/"
    clean = re.sub(r"/(?:(?:\d+)|(?:[0-9a-f]{16,})|(?:[0-9a-f-]{32,}))(?=/|$)", "/{id}", clean, flags=re.IGNORECASE)
    return clean if clean.startswith("/") else f"/{clean}"


def _surface_params(raw: dict, query: str) -> list[str]:
    values: list[str] = [key for key, _ in parse_qsl(query, keep_blank_values=True)]
    for key in ("param", "parameter", "name"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    for key in ("params", "parameters", "fields"):
        value = raw.get(key)
        if isinstance(value, dict):
            values.extend(str(item) for item in value)
        else:
            values.extend(_string_list(value))
    return sorted(set(values))


def _has_file_param(surface: dict) -> bool:
    return any(token in param.lower() for param in surface.get("params") or [] for token in ("file", "path", "dir", "template"))


def _is_static(path: str | None) -> bool:
    lowered = (path or "").lower()
    return any(lowered.endswith(suffix) for suffix in _STATIC_SUFFIXES)


def _first_text(raw: dict, *keys: str) -> str | None:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_int(raw: dict, *keys: str) -> int | None:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def _string_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


def _as_list(value: object) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []
