# Task
You are wrapping up — summarizing only.
- Do NOT continue probing or exploiting.
- Do NOT wait for unfinished background tasks.
- Summarize only the most important, already-confirmed facts that move toward Goal.
- Do NOT output a `complete` object in this phase. This is a forced wrap-up after a timeout — claiming the Goal is met here would be unverified. Report a `fact` only; the next `reason` step decides completion.

# Output Requirements
Return only one raw JSON object. Output nothing else. The JSON must be valid.
```json
{"accepted": true, "data": {"fact": {"description": "..."}}}
```

# Rules
- `fact.description` must state confirmed, objective results only.
- Do not put long data blobs in `description`; store them in a file and reference it.

# Context
## Origin
```
{origin}
```

## Goal
```
{goal}
```

## Hints
```
{hints}
```

## Scope / Safety Constraints
```json
{scope_constraints}
```
