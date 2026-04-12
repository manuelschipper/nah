# LLM Layer

nah can optionally consult an LLM for decisions that need judgment after deterministic classification.

```
Tool call → nah (deterministic) → LLM (optional) → Claude Code permissions → execute
```

The deterministic layer always runs first. Unified ask-refinement only sees eligible `ask` decisions; write/script inspection can also call the LLM as a veto path. The LLM cannot relax deterministic blocks. If no LLM is configured or available, the deterministic decision stands.

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
  enabled: true
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

### Provider examples

=== "Ollama (local)"

    ```yaml
    llm:
      enabled: true
      providers: [ollama]
      ollama:
        url: http://localhost:11434/api/chat
        model: qwen3.5:9b
        timeout: 10
    ```

=== "OpenRouter"

    ```yaml
    llm:
      enabled: true
      providers: [openrouter]
      openrouter:
        url: https://openrouter.ai/api/v1/chat/completions
        key_env: OPENROUTER_API_KEY
        model: google/gemini-3.1-flash-lite-preview
    ```

=== "OpenAI"

    ```yaml
    llm:
      enabled: true
      providers: [openai]
      openai:
        url: https://api.openai.com/v1/responses
        key_env: OPENAI_API_KEY
        model: gpt-5.3-codex
    ```

=== "Anthropic"

    ```yaml
    llm:
      enabled: true
      providers: [anthropic]
      anthropic:
        url: https://api.anthropic.com/v1/messages
        key_env: ANTHROPIC_API_KEY
        model: claude-haiku-4-5
    ```

=== "Snowflake Cortex"

    ```yaml
    llm:
      enabled: true
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

`default` adds `package_uninstall`, `container_exec`, and `browser_exec`. It keeps `process_signal`, service writes, destructive container/service actions, git discard/history/remote writes, `composition`, and `sensitive` prompts human-gated by default.

Explicit lists can combine presets and action types. `composition` and `sensitive` are gates: add them explicitly, or use top-level `eligible: all`, if you want those asks routed to the LLM.

Provider responses of `block` are treated as `uncertain`, so the LLM can allow an eligible ask or leave it as an ask; it cannot block through ask-refinement.

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
5. If all providers fail or return uncertain, the decision stays `ask`

## Testing

```bash
nah test "python3 -c 'import os; os.system(\"rm -rf /\")'"
# Shows: LLM eligible: yes/no, LLM decision (if configured)
```

The `nah test` command shows LLM eligibility and, if enabled, makes a live LLM call so you can verify the full pipeline.
