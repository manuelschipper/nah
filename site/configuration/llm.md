# LLM Layer

nah can optionally consult an LLM for decisions that need judgment after deterministic classification.

```
Tool call → nah (deterministic) → LLM (optional) → Claude Code permissions → execute
```

The deterministic layer always runs first. Unified ask-refinement only sees eligible `ask` decisions. Script inspection can call the LLM as a veto path, and write-like tools can call the LLM for safety + intent review. The LLM cannot relax deterministic blocks. If no LLM is configured or available, the deterministic decision stands.

## Providers

nah supports 5 LLM providers. Configure one or more in cascade order -- first success wins.

| Provider | API | Default model | Auth env var |
|----------|-----|---------------|-------------|
| `ollama` | Chat API (`/api/chat`) | `qwen3.5:9b` | *(none -- local)* |
| `openrouter` | OpenAI-compatible | `google/gemini-3.1-flash-lite-preview` | `OPENROUTER_API_KEY` |
| `openai` | Responses API (`/v1/responses`) | `gpt-5.3-codex` | `OPENAI_API_KEY` |
| `anthropic` | Messages API (`/v1/messages`) | `claude-haiku-4-5` | `ANTHROPIC_API_KEY` |
| `cortex` | Snowflake Cortex REST | `claude-haiku-4-5` | `SNOWFLAKE_PAT` |

All providers use `urllib.request` (stdlib) -- no external HTTP dependencies.

## Configuration

```yaml
# ~/.config/nah/config.yaml
llm:
  mode: on
  providers: [ollama, openrouter]   # cascade order
  ollama:
    url: http://localhost:11434/api/chat
    model: qwen3.5:9b
    timeout: 10
  openrouter:
    url: https://openrouter.ai/api/v1/chat/completions
    key_env: OPENROUTER_API_KEY
    model: google/gemini-3.1-flash-lite-preview
    timeout: 10
```

`llm.enabled: true` is still accepted for backward compatibility, but `llm.mode: on` is the current form.

### Provider examples

=== "Ollama (local)"

    ```yaml
    llm:
      mode: on
      providers: [ollama]
      ollama:
        url: http://localhost:11434/api/chat
        model: qwen3.5:9b
        timeout: 10
    ```

=== "OpenRouter"

    ```yaml
    llm:
      mode: on
      providers: [openrouter]
      openrouter:
        url: https://openrouter.ai/api/v1/chat/completions
        key_env: OPENROUTER_API_KEY
        model: google/gemini-3.1-flash-lite-preview
    ```

=== "OpenAI"

    ```yaml
    llm:
      mode: on
      providers: [openai]
      openai:
        url: https://api.openai.com/v1/responses
        key_env: OPENAI_API_KEY
        model: gpt-5.3-codex
    ```

=== "Anthropic"

    ```yaml
    llm:
      mode: on
      providers: [anthropic]
      anthropic:
        url: https://api.anthropic.com/v1/messages
        key_env: ANTHROPIC_API_KEY
        model: claude-haiku-4-5
    ```

=== "Snowflake Cortex"

    ```yaml
    llm:
      mode: on
      providers: [cortex]
      cortex:
        account: myorg-myaccount   # or set SNOWFLAKE_ACCOUNT env var
        key_env: SNOWFLAKE_PAT
        model: claude-haiku-4-5
    ```

## LLM options

### eligible

Control which `ask` categories route to the LLM:

```yaml
llm:
  eligible: default    # strict | default | all
```

Or use an explicit list:

```yaml
llm:
  eligible:
    - strict
    - git_discard
    - composition      # opt in to composition asks
    - sensitive        # opt in to sensitive context asks
```

`strict` routes `unknown`, `lang_exec`, and non-sensitive `context` asks to the LLM.

`default` adds `package_uninstall`, `container_exec`, `browser_exec`, and `agent_exec_read`. It keeps `process_signal`, service writes, destructive container/service actions, git discard/history/remote writes, agent write/remote/server/bypass actions, `composition`, and `sensitive` prompts human-gated by default.

Explicit lists can combine presets and action types. `composition` and `sensitive` are gates: add them explicitly, or use top-level `eligible: all`, if you want those asks routed to the LLM.

Provider responses of `block` are treated as `uncertain`, so the LLM can allow an eligible ask or leave it as an ask; it cannot block through ask-refinement.

LLM responses include a short prompt-safe `reasoning` summary and a longer `reasoning_long` explanation for observability. Claude-visible prompts use the short summary; structured logs and `nah test` can show the longer explanation for debugging.

## Write/Edit review

When LLM mode is enabled, Write/Edit/MultiEdit/NotebookEdit operations are reviewed after deterministic checks. Deterministic `block` results skip the LLM and stay blocked.

For deterministic `allow` results, the LLM can still escalate to `ask` when the content looks risky. This catches suspicious write content that deterministic patterns miss. Provider `block` responses are treated as non-allow, so write review never produces a final block.

For deterministic `ask` results, the only relaxable class is a project-boundary ask:

- `<Tool> outside project: ...`
- `<Tool> outside project (no git root): ...`

If the LLM returns `allow` for one of those asks, nah records an `allow` decision. Whether nah emits an automatic allow to Claude Code is still controlled by `active_allow`; if Write/Edit is not active-allowed, Claude Code's normal permission prompt handles the tool.

These ask classes stay human-gated even if the LLM returns `allow`:

- hook self-protection
- nah config self-protection
- sensitive paths
- deterministic content-pattern asks
- malformed or unparseable write-like payloads

The write-review prompt includes the tool, target path, working directory, inside-project status, deterministic decision and reason, the write/edit content with secret redaction, and recent transcript context. The LLM is instructed to allow only narrow edits that match recent user intent and do not add or expose literal credentials, exfiltrate data, weaken auth, add persistence, alter hooks, or bypass safety controls.

### context_chars

How much conversation transcript context to include in the LLM prompt:

```yaml
llm:
  context_chars: 12000  # default: 12000 characters of recent transcript
```

Set to `0` to disable transcript context entirely.

The transcript is read from Claude Code's JSONL conversation file. It includes user/assistant messages and tool use summaries, wrapped with anti-injection framing.

## How the cascade works

1. nah tries each provider in the order listed in `providers:`
2. If a provider returns `allow`, that decision is used
3. If a provider returns `uncertain`, the cascade **stops** (doesn't try the next provider)
4. If a provider errors (timeout, auth failure), nah tries the next provider
5. If all providers fail, the deterministic decision stands; for ask-refinement, that means the decision stays `ask`

Provider `uncertain` responses stop the cascade. In ask-refinement they leave the decision as `ask`; in write-like review they are treated as non-allow, so risky content stays human-gated.

## Testing

```bash
nah test "python3 -c 'import os; os.system(\"rm -rf /\")'"
# Shows: LLM eligible: yes/no, LLM decision (if configured)
```

The `nah test` command shows LLM eligibility and, if enabled, makes a live LLM call so you can verify the full pipeline.
