# Task
You will receive a context bundle: Origin (your known starting point), Goal (the success condition), and Hints. Understand what you have, become a domain expert for this target, and drive the problem all the way to the state described by Goal. Use the tools available in this environment freely.

# Output Requirements
Return only one raw JSON object. Output nothing else. The JSON must be valid, with all quotes properly escaped.

When rejecting (you must NOT reject):
```json
{"accepted": false, "reason": "..."}
```

Only return the following once you have CONFIRMED that Goal has been satisfied:
```json
{"accepted": true, "data": {"fact": {"description": "..."}, "complete": {"description": "..."}}}
```

# Rules
- If the problem is not yet solved, keep working. Do not stop on your own.
- If you later receive a conclude-phase instruction in the same session, that newer instruction overrides this keep-working rule immediately: stop exploring, stop waiting, stop planning further actions, and return the required summary JSON right away.
- Output `complete` only if Goal has already been definitively achieved in this session. If Goal is not yet achieved, do not output `complete`, and keep working until a conclude-phase instruction replaces this task.
- `fact.description` must state the confirmed, objective key results.
- `complete.description` must explain why the confirmed results are sufficient to prove Goal is achieved.
- Do not put long data blobs in `description`. Store long data in a file and reference it from `description`.

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

Stay within the allowed targets and ports. Do not intentionally access blocked targets or ports.
