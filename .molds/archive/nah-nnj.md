# ask-llm policy — explicit LLM-gated action type policy

## Problem

The `context` policy is overloaded. It means "run the deterministic context resolver" which checks paths, hosts, scripts, and may return `allow`, `ask`, or `block`. The LLM only enters when the resolver returns `ask`. There's no way to say "skip the resolver, go straight to the LLM."

Users who want LLM-gated control over specific action types (e.g. `git_remote_write`) must set the type to `context`, which also runs path/host resolution logic that's irrelevant for git operations. The result is confusing and indirect.

Current policies: `allow`, `context`, `ask`, `block`. The gap is between `context` (deterministic + maybe LLM) and `ask` (always prompt, no LLM).

## Solution

Add `ask-llm` as a new policy value. Semantics:

- Skip the deterministic context resolver entirely
- Send the command directly to the unified LLM (Path 1)
- LLM says allow → auto-approve silently
- LLM says uncertain → prompt the user (same as `ask`)
- LLM unavailable/off → fall back to `ask` (fail-closed)

Config usage:
```yaml
actions:
  git_remote_write: ask-llm
```

CLI usage:
```bash
nah allow git_remote_write ask-llm   # or a new verb?
```

%% Decide: extend `nah allow` to accept `ask-llm` as a value, or add a new CLI verb?

### Eligibility bypass

`ask-llm` types bypass the normal eligibility check (`_is_llm_eligible_stages`). The user explicitly opted in — no need to check if the type is in the eligible list or if it's a sensitive path.

### Integration point

In `main()` after handlers return, before the existing unified LLM block:
- If any stage has `policy: ask-llm`, send to LLM regardless of eligibility
- The handler would return `ask` (since `ask-llm` isn't `allow` or `block`)
- The unified block checks for `ask-llm` policy in stages and skips eligibility

%% Decide: should `ask-llm` be handled in the context resolver (returns ask, then main() LLM block picks it up) or as a distinct path?

### Backward compat

- New policy value — no existing config uses it
- `context` behavior unchanged
- `ask` behavior unchanged

## Files to Modify

| File | Action | Purpose |
|------|--------|---------|
| `src/nah/taxonomy.py` | modify | Add `ASK_LLM = "ask-llm"` constant, add to `POLICIES`, `STRICTNESS` |
| `src/nah/hook.py` | modify | In `main()` unified block: detect `ask-llm` policy in stages, bypass eligibility check |
| `src/nah/context.py` | modify | `resolve_context`: if policy is `ask-llm`, return `(ASK, "ask-llm: LLM will decide")` — pass through to main() |
| `src/nah/config.py` | modify | Accept `ask-llm` as valid policy in merge/validation |
| `src/nah/cli.py` | modify | `nah types` shows ask-llm, `nah allow` accepts ask-llm value |
| `tests/test_ask_llm.py` | create | Tests for the new policy |

## Verification

- `nah test "git push"` with `actions: {git_remote_write: ask-llm}` + LLM on → shows LLM decision
- `nah test "git push"` with `actions: {git_remote_write: ask-llm}` + LLM off → falls back to ask
- `nah test "git push"` without config change → unchanged behavior (ask, no LLM)
- `nah types` shows `ask-llm` as a valid policy
- Eligibility bypass: `ask-llm` type goes to LLM even if not in `eligible` list

## Implementation Notes

- Depends on: nah-5no (unified LLM mode) — merged
- Priority: P2
- Scope: small — one new constant, a few conditionals
