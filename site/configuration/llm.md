# Optional LLM Classification

nah can optionally use an LLM for one narrow job: map a deterministically
`unknown` Bash command to one built-in action type and identify the targets it
touches.

```text
unknown Bash command -> LLM classification -> deterministic target and policy checks
```

The model receives the command and the closed set of built-in action types. It
returns an action type (or `unknown`), touched paths/hosts/containers/databases,
and short evidence from the command tokens. nah then applies its normal local
checks to the result.

The LLM does not receive conversation context, file contents, scripts, or write
payloads. It cannot clear a known `ask`, approve inline code or writes, or weaken
a deterministic block.

| Decision path | LLM behavior |
| --- | --- |
| Unknown Bash command | May classify the command; deterministic checks make the final decision |
| Known Bash `ask` | No LLM call; normal runtime/fallback handling applies |
| Inline `lang_exec`, write-like tool, deterministic block | No LLM call |
| Claude Code or interactive Codex | Uses classification when enabled |
| `codex exec` or Terminal Guard | Deterministic-only; no LLM call |

## Configure

LLM configuration and provider credentials are global-only:

```yaml
# ~/.config/nah/config.yaml
llm:
  mode: on
  providers: [openrouter]
  openrouter:
    key_env: OPENROUTER_API_KEY
```

Install nah with YAML and optional keyring support when needed:

```bash
pip install "nah[config,keys]"
nah key set openrouter
nah key status
```

Environment variables also work. `key_env` names the environment/keyring slot;
do not put the secret value in YAML. See [`nah key`](../cli.md#nah-key) for key
management commands.

## Providers

Providers run in the order listed under `providers`.

| Provider | Default API/model | Default credential slot |
| --- | --- | --- |
| `ollama` | `http://localhost:11434/api/chat` / `qwen3.5:9b` | none |
| `openrouter` | OpenAI-compatible / `google/gemini-3.1-flash-lite-preview` | `OPENROUTER_API_KEY` |
| `openai` | Responses API / `gpt-5.3-codex` | `OPENAI_API_KEY` |
| `azure` | Azure Responses or chat completions / deployment-dependent | `AZURE_OPENAI_API_KEY` |
| `anthropic` | Messages API / `claude-haiku-4-5` | `ANTHROPIC_API_KEY` |
| `cortex` | Snowflake Cortex / `claude-haiku-4-5` | `SNOWFLAKE_PAT` |

Each selected provider needs a non-empty config block. Common overrides are
`url`, `model`, `timeout`, and `key_env`.

Ollama needs no credential:

```yaml
llm:
  mode: on
  providers: [ollama]
  ollama:
    url: http://localhost:11434/api/chat
```

Azure requires the resource endpoint. Use a `/chat/completions` URL for a chat
deployment; other URLs use the Responses payload shape.

```yaml
llm:
  mode: on
  providers: [azure]
  azure:
    url: https://YOUR-RESOURCE-NAME.openai.azure.com/openai/v1/responses
    key_env: AZURE_OPENAI_API_KEY
    model: your-deployment-name
```

Snowflake Cortex requires the account identifier:

```yaml
llm:
  mode: on
  providers: [cortex]
  cortex:
    account: myorg-myaccount
    key_env: SNOWFLAKE_PAT
```

All providers use `urllib.request` from the Python standard library.

## Runtime Overrides

Provider selection and credentials stay global. A trusted target override can
turn classification on or off for an interactive runtime:

```yaml
targets:
  claude:
    llm:
      mode: off
  codex:
    llm:
      mode: on
```

Target LLM settings from project config require `nah trust-project`. Bash and
zsh target settings are accepted for compatibility but Terminal Guard remains
deterministic-only.

## Cascade and Failure Behavior

1. nah tries providers in configured order.
2. A valid classification, including explicit `unknown`, ends the cascade.
3. A provider error or malformed response advances to the next provider.
4. If every provider fails, the original `unknown -> ask` decision stands.

Successful classifications are cached in-process by command string.

## Verify

```bash
nah config show
nah test "some-unknown-wrapper github.com"
nah log --llm
```

`nah test --json` includes a `classify_llm` object when the model maps an
unknown command. Known asks and inline code remain outside the LLM path.
