# Task
You are wrapping up the same `explore` task — summarizing only.
- Stop immediately. Do NOT continue exploring or exploiting.
- Do NOT wait for unfinished background tasks, retries, or long-running commands.
- Summarize only what this exploration has already confirmed, then produce the JSON now.

# Output Requirements
Return only one raw JSON object. Output nothing else. The JSON must be valid.

When rejecting (you must NOT reject):
```json
{"accepted": false, "reason": "policy_refusal"}
```

Normal return (use one structured verdict: `confirmed`, `verified`, `not_vulnerable`, `inconclusive`, or `failed`):
```json
{"accepted": true, "data": {"description": "...", "status": "confirmed", "vuln_type": "sql_injection", "severity": "high", "observed_surfaces": [{"target": "api.example.com", "port": 443, "method": "POST", "path": "/v1/upload", "parameters": ["file"], "auth_context": "authenticated", "surface_type": "upload_point"}]}}
```

# Rules
- `description` must be an objective conclusion. A negative result is still valid.
- Produce exactly one Fact for the assigned Intent. Its `vuln_type` must equal the Intent's selected `test_variant` when one is shown in Bound Coverage Responsibilities.
- Include optional `observed_surfaces` only for NEW in-scope surfaces already observed during this task. Do not invent fingerprints or grouping keys.
- Do not combine distinct mechanisms in one conclusion; leave unrelated discoveries for a later Intent.
- A timeout or tool failure is `inconclusive` or `failed`, never `not_vulnerable`.
- If a prerequisite such as an installation lock, missing role, unavailable fixture, or required configuration prevents the test, return `status: "blocked_by_precondition"`; do not alter the prerequisite and do not report safety.
- Also populate the normalized Fact envelope: `kind`, short `summary`, `subject`, `data`, `parent_fact_ids`, `evidence_refs`, and `confidence`. Keep raw artifacts in evidence files.
- For an assigned independent verification, return `status: "verified"` and `verification_of` only when a different method reproduced that Fact.
- Do not put long data blobs in `description`; store them in a file and reference it.

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
