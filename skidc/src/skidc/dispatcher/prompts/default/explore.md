# Task
You will receive a YAML snapshot of the task graph plus one assigned `Current Intent`. Explore ONLY in the direction of this intent and try to advance toward Goal. Use the tools available in this environment.

# Output Requirements
Return only one raw JSON object. Output nothing else. The JSON must be valid, with all quotes properly escaped.

When rejecting (you must NOT reject):
```json
{"accepted": false, "reason": "policy_refusal"}
```

Normal return (use one structured verdict: `confirmed`, `verified`, `not_vulnerable`, `inconclusive`, or `failed`):
```json
{"accepted": true, "data": {"description": "...", "status": "confirmed", "vuln_type": "sql_injection", "severity": "high", "observed_surfaces": [{"target": "api.example.com", "port": 443, "method": "POST", "path": "/v1/upload", "parameters": ["file"], "auth_context": "authenticated", "surface_type": "upload_point"}]}}
```

# Rules
- Exploring an intent may succeed or may dead-end. Either way, before ending, make sure you have thoroughly explored this intent, then report an objective conclusion. Even a negative result is a valid fact.
- If you later receive a conclude-phase instruction in the same session, that newer instruction overrides this one immediately: stop exploring and return the summary JSON right away.
- `description` must state confirmed, objective results. Report only NEW incremental facts — do not repeat what is already in the graph snapshot.
- If this task objectively discovers a NEW in-scope endpoint, method, parameter set, port, or auth context, add it to optional `observed_surfaces`. Do not repeat already inventoried surfaces and do not invent fingerprints or grouping keys.
- Produce exactly one Fact for the assigned Intent. Its `vuln_type` must equal the Intent's selected `test_variant` when one is shown in Bound Coverage Responsibilities.
- Do not combine upload bypass, code execution, file inclusion, or any other distinct mechanism in one conclusion. Leave unrelated discoveries for a later Intent.
- A timeout or tool failure is `inconclusive` or `failed`, never `not_vulnerable`.
- If a prerequisite such as an installation lock, missing role, unavailable fixture, or required configuration prevents the test, return `status: "blocked_by_precondition"`; do not alter the prerequisite and do not report safety.
- Also populate the normalized Fact envelope: `kind`, short `summary`, `subject`, `data`, `parent_fact_ids`, `evidence_refs`, and `confidence`. Keep raw artifacts in evidence files.
- For an assigned independent verification, return `status: "verified"` and `verification_of` only when a different method reproduces that Fact.
- Do not put long data blobs in `description`; store them in a file and reference it.
- Stay within Scope / Safety Constraints. Do not intentionally access blocked targets or blocked ports.

# Context
## Scope / Safety Constraints
```json
{scope_constraints}
```

## Graph
```
{graph_yaml}
```

## Current Intent
```
{intent_id}
```

## Current Intent Description
```
{intent_description}
```

## Bound Coverage Responsibilities
```json
{intent_coverage}
```
