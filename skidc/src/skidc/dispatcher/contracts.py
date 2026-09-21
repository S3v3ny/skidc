from __future__ import annotations

from typing import Any

from skidc.dispatcher.output_parser import extract_json_object


def parse_json_output(stdout: str) -> dict[str, Any]:
    return extract_json_object(stdout)


def _unwrap_wrapped_payload(payload: dict[str, Any]) -> tuple[bool | None, dict[str, Any] | None]:
    accepted = payload.get("accepted")
    if accepted is False:
        return False, None
    if accepted is True:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("data must be an object")
        return True, data
    return None, None


def _is_dict(value: Any) -> bool:
    return isinstance(value, dict)


def _looks_like_reason_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    metadata_keys = {"attack_paths", "attack_surface_map", "explore_seed_deck", "recon_complete"}
    if "complete" in keys and keys <= {"complete", *metadata_keys}:
        complete = payload["complete"]
        return isinstance(complete, dict) and "from" in complete and "description" in complete
    if "intents" in keys and keys <= {"intents", *metadata_keys}:
        return isinstance(payload["intents"], list)
    if "intent" in keys and keys <= {"intent", *metadata_keys}:
        intent = payload["intent"]
        return isinstance(intent, dict) and "from" in intent and "description" in intent
    if keys and keys <= metadata_keys:
        return "attack_surface_map" in keys or "explore_seed_deck" in keys
    return False


def _looks_like_bootstrap_execute_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict) or set(payload) != {"fact", "complete"}:
        return False
    return _is_dict(payload.get("fact")) and _is_dict(payload.get("complete"))


def _looks_like_bootstrap_conclude_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys not in ({"fact"}, {"fact", "complete"}):
        return False
    return _is_dict(payload.get("fact"))


def _looks_like_explore_data(payload: dict[str, Any]) -> bool:
    # description is required; the rest are optional fact metadata fields.
    return isinstance(payload, dict) and "description" in payload


_EXPLORE_STRING_FIELDS = (
    "scope",
    "vuln_type",
    "severity",
    "parent_fact",
    "verification_of",
    "goal_type",
    "status",
    "recon_category",
    "recon_tool",
    "recon_target",
    "recon_evidence_ref",
    "kind",
    "summary",
    "created_by",
)
_EXPLORE_BOOL_FIELDS = ("recon_executed", "recon_found_results")


def validate_reason_payload(
    payload: dict[str, Any], open_intents_empty: bool, max_intents: int,
) -> tuple[str, dict[str, Any] | list[dict[str, Any]] | None, bool]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None, False
    if accepted is None:
        if not _looks_like_reason_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    recon_complete = bool(data.pop("recon_complete", False))
    complete = data.get("complete")
    intents = data.get("intents")
    # backward compat: accept singular "intent" key from models
    if intents is None:
        singular = data.get("intent")
        if isinstance(singular, dict):
            intents = [singular]
    if complete is not None:
        if intents is not None:
            raise ValueError("complete and intents cannot coexist")
        if not isinstance(complete, dict) or "from" not in complete or "description" not in complete:
            raise ValueError("invalid complete payload")
        return "complete", complete, recon_complete
    if intents is not None:
        if not isinstance(intents, list):
            raise ValueError("intents must be an array")
        for i, intent in enumerate(intents):
            if not isinstance(intent, dict) or "from" not in intent or "description" not in intent:
                raise ValueError(f"invalid intent at index {i}")
        intents = intents[:max_intents]
        if not intents:
            return "noop", None, recon_complete
        return "intents", intents, recon_complete
    if any(key in data for key in ("attack_surface_map", "explore_seed_deck", "attack_paths")):
        return "noop", None, recon_complete
    return "noop", None, recon_complete


def _normalize_explore_seed_deck(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("seeds")
    if not isinstance(value, list):
        return []
    seeds: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        fact_ids = entry.get("from")
        description = entry.get("description")
        if not isinstance(fact_ids, list) or not fact_ids:
            continue
        if not all(isinstance(fact_id, str) and fact_id.strip() for fact_id in fact_ids):
            continue
        if not isinstance(description, str) or not description.strip():
            continue
        seed = dict(entry)
        seed["from"] = [fact_id.strip() for fact_id in fact_ids]
        seed["description"] = description.strip()
        seeds.append(seed)
    return seeds


def extract_reason_handoff(payload: dict[str, Any]) -> dict[str, Any]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return {"attack_surface_map": None, "explore_seed_deck": []}
    if data is None:
        data = payload if isinstance(payload, dict) else {}
    attack_surface_map = data.get("attack_surface_map")
    if not isinstance(attack_surface_map, dict):
        attack_surface_map = None
    return {
        "attack_surface_map": attack_surface_map,
        "explore_seed_deck": _normalize_explore_seed_deck(data.get("explore_seed_deck")),
    }


def extract_reason_attack_paths(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull optional attack_paths out of a reason payload (wrapped or bare).
    Returns only well-formed entries (name + non-empty fact_chain); skips the rest.
    Kept separate from validate_reason_payload so its return contract is unchanged."""
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return []
    if data is None:
        data = payload if isinstance(payload, dict) else {}
    raw = data.get("attack_paths")
    if not isinstance(raw, list):
        return []
    paths: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        chain = entry.get("fact_chain")
        description = entry.get("description")
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(chain, list) or not chain or not all(isinstance(c, str) and c.strip() for c in chain):
            continue
        if not isinstance(description, str) or not description.strip():
            continue
        severity = entry.get("severity")
        status = entry.get("status")
        normalized_status = status.strip() if isinstance(status, str) and status.strip() else "hypothesis"
        if normalized_status not in ("hypothesis", "confirmed", "inconclusive", "refuted"):
            normalized_status = "hypothesis"
        paths.append({
            "name": name.strip(),
            "fact_chain": [c.strip() for c in chain],
            "description": description.strip(),
            "severity": severity.strip() if isinstance(severity, str) and severity.strip() else "medium",
            "status": normalized_status,
        })
    return paths


def validate_bootstrap_execute_payload(payload: dict[str, Any]) -> tuple[str, dict[str, str] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_execute_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")

    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")

    result = {"fact_description": fact_description.strip()}
    complete = data.get("complete")
    if complete is None:
        raise ValueError("complete is required")
    if not isinstance(complete, dict):
        raise ValueError("complete must be an object")
    complete_description = complete.get("description")
    if not isinstance(complete_description, str) or not complete_description.strip():
        raise ValueError("complete.description is required")
    result["complete_description"] = complete_description.strip()
    return "complete", result


def validate_bootstrap_conclude_payload(payload: dict[str, Any]) -> tuple[str, str | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_conclude_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    extra_keys = set(data) - {"fact", "complete"}
    if extra_keys:
        raise ValueError("unexpected keys in conclude payload")
    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")
    return "fact", fact_description.strip()


def validate_explore_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_explore_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("description is required")
    result: dict[str, Any] = {"description": description.strip()}
    for field in _EXPLORE_STRING_FIELDS:
        value = data.get(field)
        if isinstance(value, str) and value.strip():
            result[field] = value.strip()
    for field in _EXPLORE_BOOL_FIELDS:
        value = data.get(field)
        if isinstance(value, bool):
            result[field] = value
    for field in ("subject", "data"):
        value = data.get(field)
        if isinstance(value, dict):
            result[field] = dict(value)
    for field in ("parent_fact_ids", "evidence_refs"):
        value = data.get(field)
        if isinstance(value, list):
            result[field] = [item.strip() for item in value if isinstance(item, str) and item.strip()]
    confidence = data.get("confidence")
    if isinstance(confidence, (int, float)) and 0 <= float(confidence) <= 1:
        result["confidence"] = float(confidence)
    schema_version = data.get("schema_version")
    if isinstance(schema_version, int) and schema_version >= 1:
        result["schema_version"] = schema_version
    observed_surfaces = data.get("observed_surfaces")
    if isinstance(observed_surfaces, list):
        result["observed_surfaces"] = [
            dict(surface) for surface in observed_surfaces[:100] if isinstance(surface, dict)
        ]
    return "fact", result
