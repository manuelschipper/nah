# LLM Layer

nah can optionally consult an LLM to resolve ambiguous `ask` decisions that the deterministic classifier can't handle.

```
Tool call → nah (deterministic) → LLM (optional) → Claude Code permissions → execute
```

The deterministic layer always runs first. The LLM only sees leftover `ask` decisions. If no LLM is configured or available, the decision stays `ask` and the user is prompted.

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
  eligible: default    # default: unknown, lang_exec, context (excludes composition and sensitive)
  eligible: all        # route all ask decisions to LLM
  eligible:            # explicit list
    - unknown
    - lang_exec
    - context
    - composition      # must be explicitly added
    - sensitive        # must be explicitly added
```

The `default` set routes `unknown`, `lang_exec`, and `context` to the LLM. Categories like `composition` and `sensitive` are excluded by default (they involve pipe safety or sensitive paths and should generally prompt the user). Add them explicitly if you want LLM resolution for those too.

### max_decision

Cap the LLM's escalation power:

```yaml
llm:
  max_decision: ask    # default: LLM can allow or ask, never block
  max_decision: block  # LLM can block (full trust)
```

When the LLM suggests `block` but `max_decision` is `ask`, the decision is downgraded to `ask` with the LLM's reasoning preserved in the prompt.

### context_chars

How much conversation transcript context to include in the LLM prompt:

```yaml
llm:
  context_chars: 4000   # default: 4000 characters of recent transcript
  context_chars: 0       # disable transcript context
```

The transcript is read from Claude Code's JSONL conversation file. It includes user/assistant messages and tool use summaries, wrapped with anti-injection framing.

## How the cascade works

1. nah tries each provider in the order listed in `providers:`
2. If a provider returns `allow` or `block`, that decision is used
3. If a provider returns `uncertain`, the cascade **stops** (doesn't try the next provider)
4. If a provider errors (timeout, auth failure), nah tries the next provider
5. If all providers fail or return uncertain, the decision stays `ask`

## Testing

```bash
nah test "python3 -c 'import os; os.system(\"rm -rf /\")'"
# Shows: LLM eligible: yes/no, LLM decision (if configured)
```

The `nah test` command shows LLM eligibility and, if enabled, makes a live LLM call so you can verify the full pipeline.
