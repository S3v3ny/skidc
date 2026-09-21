# Task
Read the Fact鈥揑ntent graph and make one decision:
1. If existing terminal Facts sufficiently assess Goal, complete from those Facts.
2. Otherwise, add only the smallest useful set of new Intents.
3. If neither is justified, return empty data.

Facts and concluded Intent edges are the only causal truth. Coverage, Surface, and
Hypothesis records are planning/audit context; they are not proof and must not be
turned into attack paths.

# Output
Return one raw JSON object and nothing else.

Complete:
{"accepted": true, "data": {"complete": {"from": ["f001"], "description": "Why these terminal Facts sufficiently assess Goal"}}}

Create work:
{"accepted": true, "data": {"intents": [{"from": ["f001"], "description": "Verify one concrete hypothesis", "target": "example.com", "port": 443, "path": "/admin", "surface_type": "web", "action_kind": "auth_probe", "test_variant": "auth_bypass", "coverage_refs": ["cov003"], "priority": 10, "suggested_tools": ["curl"]}]}}

No justified graph change:
{"accepted": true, "data": {}}

Recon may additionally set "recon_complete": true only when every required recon
category is executed. A compact attack_surface_map or explore_seed_deck may be
included for handoff, but they remain planning data.

# Rules
- Never output attack_paths, path names, path severity, or narrative chains.
- Completion is one concluded Intent from terminal Facts to goal; the server
  derives any attack-path view from that completed graph.
- Use only ids listed in Valid Facts for every from.
- Do not use origin, goal, pending planning Facts, Surface rows, Coverage rows,
  or Hypotheses as real-website completion evidence.
- Only confirmed or verified vulnerability Facts may become an attack path after
  they are included in the completion edge.
- Do not duplicate an Open Intent or recreate a terminal attempt under new wording.
- New Intents must be evidence-backed, in scope, non-overlapping, and limited to
  at most {max_intents}. One Intent tests one surface and one canonical variant.
- In real-website mode, bind at most one coverage_refs id and include structured
  target/action fields whenever known.
- Open Intents may continue without new work. An empty Open Intent list does not
  itself prove completion and does not force speculative work.
- Failed, inconclusive, negative, excluded, deferred, and untested items remain
  limitations; do not restate them as successful paths.

# Context
## Current Phase
{current_phase}

## Scope / Safety Constraints
{scope_constraints}

## Recon Execution Status
{recon_status}

## Sub-Goals
{sub_goals}

## Graph
{graph_yaml}

## Valid Facts
{fact_ids}

## Open Intents
{open_intents}