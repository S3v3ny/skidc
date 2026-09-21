from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit


@dataclass(frozen=True, slots=True)
class HypothesisCandidate:
    behavior_key: str
    test_family: str
    test_variant: str
    rationale: str
    trigger_fact_ids: tuple[str, ...]
    confidence: float
    impact: float
    goal_value: float
    novelty: float
    estimated_cost: float
    score: float
    required: bool
    basis_fingerprint: str


_OBJECT_PARAM = re.compile(r"(?:^|_)(?:id|uid|user|account|order|article|file|record)(?:_id)?$", re.I)
_URL_PARAM = re.compile(r"(?:url|uri|link|callback|webhook|redirect|target|dest)", re.I)
_FILE_PARAM = re.compile(r"(?:file|path|dir|folder|template|page|include|download)", re.I)
_TEXT_PARAM = re.compile(r"(?:q|query|search|keyword|name|title|content|comment|message|body|text)", re.I)
_AUTH_PATH = re.compile(r"/(?:login|signin|auth|session|token)(?:/|$)", re.I)
_ADMIN_PATH = re.compile(r"/(?:admin|manage|backend|console)(?:/|$)", re.I)
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_ROUTE_SELECTOR_KEYS = ("r", "type", "action", "module", "controller", "do", "op")
_STABLE_ROUTE_VALUE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$", re.I)


def _route_discriminators(raw_path: str, params: list[str], traits: dict[str, Any]) -> tuple[str, ...]:
    pairs: list[tuple[str, str]] = list(parse_qsl(urlsplit(raw_path).query, keep_blank_values=False))
    for param in params:
        text = str(param).strip().lstrip("?")
        if "=" in text:
            pairs.extend(parse_qsl(text, keep_blank_values=False))
    route_params = traits.get("route_params")
    if isinstance(route_params, dict):
        pairs.extend((str(key), str(value)) for key, value in route_params.items())

    selected: dict[str, str] = {}
    allowed = set(_ROUTE_SELECTOR_KEYS)
    for key, value in pairs:
        normalized_key = key.strip().casefold()
        normalized_value = value.strip()
        if (
            normalized_key in allowed
            and normalized_key not in selected
            and _STABLE_ROUTE_VALUE.fullmatch(normalized_value)
        ):
            selected[normalized_key] = normalized_value.casefold()
    return tuple(
        f"{key}={selected[key]}" for key in _ROUTE_SELECTOR_KEYS if key in selected
    )[:3]




def behavior_identity(surface: Any) -> tuple[str, str, list[str]]:
    """Return stable behavior identity independent of discovered parameter count."""
    raw_path = str(_value(surface, "path_template") or "/")
    path = urlsplit(raw_path).path or "/"
    method = str(_value(surface, "method") or "GET").upper()
    target = str(_value(surface, "target") or "origin").casefold()
    traits = _dict(_value(surface, "traits"))
    params = [str(item) for item in (_value(surface, "params") or [])]
    port = _value(surface, "port") or "default"
    auth = str(_value(surface, "auth_context") or "anonymous").casefold()

    normalized_path = re.sub(r"\{[^/{}]+\}", "{}", path)
    normalized_path = re.sub(r"/(?:(?:\d{2,})|(?:[0-9a-f]{8,}))(?=/|$)", "/{}", normalized_path, flags=re.I)
    operation = _operation_type(method, normalized_path, traits)
    route_discriminators = _route_discriminators(raw_path, params, traits)
    route_suffix = f"?{'&'.join(route_discriminators)}" if route_discriminators else ""
    capabilities = _capabilities(method, normalized_path, params, traits, surface)
    explicit = str(_value(surface, "behavior_key") or "").strip()
    behavior_key = explicit or f"{target}:{port}:{method}:{normalized_path}{route_suffix}:{auth}:{operation}"
    return behavior_key, operation, capabilities


def cluster_behaviors(surfaces: Iterable[Any]) -> list[dict[str, Any]]:
    """Merge observations of one handler without merging auth or sink boundaries."""
    grouped: dict[str, dict[str, Any]] = {}
    for surface in surfaces:
        behavior_key, operation, capabilities = behavior_identity(surface)
        current = grouped.get(behavior_key)
        if current is None:
            current = {
                name: _value(surface, name)
                for name in (
                    "fingerprint", "surface_group", "target", "port", "method",
                    "path_template", "surface_type", "auth_context", "source_fact_id",
                )
            }
            current.update(
                behavior_key=behavior_key,
                operation_type=operation,
                params=[],
                roles=[],
                traits={},
                capabilities=[],
                evidence_fact_ids=[],
            )
            grouped[behavior_key] = current

        current["params"] = sorted(
            set(current["params"]) | {str(value) for value in (_value(surface, "params") or [])}
        )
        current["roles"] = sorted(
            set(current["roles"]) | {str(value) for value in (_value(surface, "roles") or [])}
        )
        current["capabilities"] = sorted(
            set(current["capabilities"])
            | set(capabilities)
            | {str(value) for value in (_value(surface, "capabilities") or [])}
        )
        current["evidence_fact_ids"] = sorted(
            set(current["evidence_fact_ids"]) | set(_evidence_ids(surface))
        )
        current["traits"].update(_dict(_value(surface, "traits")))
        source = _value(surface, "source_fact_id")
        if source and not current.get("source_fact_id"):
            current["source_fact_id"] = source
    return sorted(grouped.values(), key=lambda item: item["behavior_key"])


def derive_candidates(
    surfaces: Iterable[Any],
    *,
    goal_text: str = "",
    terminal_keys: set[tuple[str, str, str]] | None = None,
    required_score: float = 1.0,
) -> list[HypothesisCandidate]:
    """Generate only evidence-supported candidates and rank them by expected value."""
    terminal_keys = terminal_keys or set()
    by_key: dict[tuple[str, str, str, str], HypothesisCandidate] = {}
    for surface in cluster_behaviors(surfaces):
        behavior_key, operation, capabilities = behavior_identity(surface)
        evidence = _evidence_ids(surface)
        params = [str(item) for item in (_value(surface, "params") or [])]
        path = str(_value(surface, "path_template") or "/")
        auth = str(_value(surface, "auth_context") or "anonymous").casefold()
        traits = _dict(_value(surface, "traits"))
        rules: list[tuple[str, str, str, float, float, float]] = []

        if "authentication" in capabilities:
            rules.append((
                "identity_auth", "authentication_flow",
                "Authentication behavior was observed; test the concrete login/session boundary.",
                0.82, 4.0, 1.5,
            ))
        if "object_reference" in capabilities and auth != "anonymous":
            rules.append((
                "authorization", "object_boundary",
                "An authenticated object reference was observed; compare access across concrete identities.",
                0.78, 5.0, 2.0,
            ))
        if "privileged_operation" in capabilities:
            rules.append((
                "authorization", "privilege_boundary",
                "A privileged operation was observed; verify that lower privilege contexts cannot invoke it.",
                0.84, 5.0, 2.0,
            ))
        if "state_change" in capabilities and auth not in {"anonymous", "token", "bearer"}:
            rules.append((
                "session_csrf", "csrf_state_change",
                "A cookie/session-backed state change was observed; verify origin and anti-CSRF enforcement.",
                0.72, 4.0, 2.0,
            ))
        if "query_input" in capabilities:
            rules.append((
                "injection", "sql_injection",
                "User-controlled query-like input reaches a data-oriented behavior.",
                0.64, 5.0, 2.5,
            ))
        if "file_input" in capabilities:
            variant = "file_upload" if operation == "upload" else "path_traversal"
            rules.append((
                "file_path", variant,
                "A concrete file/path behavior was observed; test the matching file boundary.",
                0.78, 5.0, 2.0,
            ))
        if "url_input" in capabilities:
            rules.append((
                "server_side_processing", "ssrf",
                "A URL-like input was observed in a server-side operation.",
                0.76, 5.0, 2.5,
            ))
        if "rendered_text" in capabilities:
            rules.append((
                "client_side", "xss",
                "Text-like input is rendered or searched by this behavior.",
                0.62, 4.0, 2.0,
            ))
        if "state_change" in capabilities and operation not in {"login", "upload"}:
            rules.append((
                "business_logic", "workflow_invariant",
                "A state-changing workflow was observed; verify its concrete state and replay invariants.",
                0.60, 4.0, 3.0,
            ))
        if traits.get("graphql") or "graphql" in path.casefold():
            rules.append((
                "api_behavior", "graphql_boundary",
                "A GraphQL behavior was observed; test schema and resolver authorization boundaries.",
                0.78, 4.0, 2.5,
            ))

        for family, variant, rationale, confidence, impact, cost in rules:
            if (behavior_key, family, variant) in terminal_keys:
                continue
            goal_value = _goal_value(goal_text, family, variant)
            novelty = 1.0
            score = round((impact * confidence * goal_value * novelty) / max(cost, 0.5), 4)
            basis = _basis_fingerprint(
                behavior_key, family, variant, evidence, params, capabilities, traits
            )
            key = (behavior_key, family, variant, basis)
            candidate = HypothesisCandidate(
                behavior_key=behavior_key,
                test_family=family,
                test_variant=variant,
                rationale=rationale,
                trigger_fact_ids=tuple(evidence),
                confidence=confidence,
                impact=impact,
                goal_value=goal_value,
                novelty=novelty,
                estimated_cost=cost,
                score=score,
                required=score >= required_score,
                basis_fingerprint=basis,
            )
            previous = by_key.get(key)
            if previous is None or candidate.score > previous.score:
                by_key[key] = candidate
    return sorted(
        by_key.values(),
        key=lambda item: (-item.score, item.estimated_cost, item.behavior_key, item.test_variant),
    )


def select_round(
    candidates: Iterable[HypothesisCandidate],
    *,
    max_items: int = 3,
    min_score: float = 1.0,
) -> list[HypothesisCandidate]:
    """Select a small diverse batch instead of materializing a Cartesian matrix."""
    selected: list[HypothesisCandidate] = []
    used_behaviors: set[str] = set()
    used_families: set[str] = set()
    eligible = [item for item in candidates if item.score >= min_score]
    for candidate in eligible:
        if len(selected) >= max_items:
            break
        if candidate.behavior_key in used_behaviors and candidate.test_family in used_families:
            continue
        selected.append(candidate)
        used_behaviors.add(candidate.behavior_key)
        used_families.add(candidate.test_family)
    return selected


def _operation_type(method: str, path: str, traits: dict[str, Any]) -> str:
    if traits.get("upload") or any(token in path.casefold() for token in ("upload", "import")):
        return "upload"
    if _AUTH_PATH.search(path):
        return "login"
    if method == "DELETE" or any(token in path.casefold() for token in ("delete", "remove")):
        return "delete"
    if method in _STATE_METHODS:
        return "state_change"
    if any(token in path.casefold() for token in ("download", "export", "file")):
        return "file_read"
    if any(token in path.casefold() for token in ("search", "query", "list")):
        return "query"
    return "read"


def _capabilities(
    method: str,
    path: str,
    params: list[str],
    traits: dict[str, Any],
    surface: Any,
) -> list[str]:
    caps = set(str(item) for item in (_value(surface, "capabilities") or []))
    operation = _operation_type(method, path, traits)
    if operation == "login" or traits.get("auth"):
        caps.add("authentication")
    if operation in {"state_change", "delete", "upload"}:
        caps.add("state_change")
    if _ADMIN_PATH.search(path) or traits.get("admin"):
        caps.add("privileged_operation")
    if any(_OBJECT_PARAM.search(param) for param in params) or "{}" in path:
        caps.add("object_reference")
    if any(_URL_PARAM.search(param) for param in params):
        caps.add("url_input")
    if operation in {"upload", "file_read"} or any(_FILE_PARAM.search(param) for param in params):
        caps.add("file_input")
    if operation == "query" or any(_TEXT_PARAM.search(param) for param in params):
        caps.add("query_input")
    if any(_TEXT_PARAM.search(param) for param in params) and operation in {"read", "query", "state_change"}:
        caps.add("rendered_text")
    return sorted(caps)


def _evidence_ids(surface: Any) -> list[str]:
    values = [str(item) for item in (_value(surface, "evidence_fact_ids") or []) if str(item)]
    source = _value(surface, "source_fact_id")
    if source and str(source) not in values:
        values.append(str(source))
    return sorted(values)


def _basis_fingerprint(*parts: Any) -> str:
    payload = json.dumps(parts, ensure_ascii=True, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def _goal_value(goal: str, family: str, variant: str) -> float:
    text = goal.casefold()
    if family.casefold() in text or variant.replace("_", " ").casefold() in text:
        return 1.35
    return 1.0


def _value(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
