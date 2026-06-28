# LLM Layer

nah can optionally consult an LLM after deterministic classification, but the
LLM now has exactly one job: classify a deterministically `unknown` Bash command
into one built-in action type and list the targets it touches.

```
Guarded Bash command -> nah deterministic floor -> optional classify-unknown -> deterministic target re-check
```

The deterministic layer always runs first. The LLM does not see recent
conversation context, file contents, scripts, write payloads, or a general
review prompt. It receives the command and the closed set of built-in action
types, then returns:

- one action type, or `unknown`
- touched targets such as paths, hosts, containers, or databases
- short evidence from the command tokens

The surfaced type and targets re-enter deterministic policy. Sensitive paths,
project boundaries, known hosts, trusted containers, database targets, and action
policies are still checked by local code. The LLM can reduce friction only when
it names the command accurately and every surfaced target passes the floor. It
cannot clear a known `ask`, cannot inspect inline code, cannot approve writes,
and cannot weaken a deterministic block.

| Path | LLM behavior |
|------|--------------|
| Unknown Bash command | Optionally maps to a built-in action type plus targets; floor re-check decides allow / ask / block |
| Known Bash `ask` | No LLM call; human prompt stays |
| Inline `lang_exec` payload | No LLM call; deterministic ask stays |
| Write-like tools | No LLM call; path, boundary, and patch checks decide |
| Deterministic block | No LLM call; block stays blocked |
| Terminal Guard | No LLM call; direct shell commands are deterministic-only |

Claude Code and Codex use the same classify-unknown path. For Codex,
interactive `PermissionRequest` uses it when LLM mode is on; headless
`PreToolUse` remains deterministic-only.

## Providers

nah supports 6 LLM providers. Configure one or more in cascade order -- first
usable classification wins.

| Provider | API | Default model | Key slot / env var |
|----------|-----|---------------|--------------------|
| `ollama` | Chat API (`/api/chat`) | `qwen3.5:9b` | *(none -- local)* |
| `openrouter` | OpenAI-compatible | `google/gemini-3.1-flash-lite-preview` | `OPENROUTER_API_KEY` |
| `openai` | Responses API (`/v1/responses`) | `gpt-5.3-codex` | `OPENAI_API_KEY` |
| `azure` | Azure OpenAI Responses/chat completions | *(deployment-dependent)* | `AZURE_OPENAI_API_KEY` |
| `anthropic` | Messages API (`/v1/messages`) | `claude-haiku-4-5` | `ANTHROPIC_API_KEY` |
| `cortex` | Snowflake Cortex REST | `claude-haiku-4-5` | `SNOWFLAKE_PAT` |

All providers use `urllib.request` from the Python standard library.

## Configuration

```yaml
# ~/.config/nah/config.yaml
llm:
  mode: on
  providers: [ollama, openrouter]
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

`llm.enabled: true` is still accepted for backward compatibility, but
`llm.mode: on` is the current form. Old `llm.eligible` and `llm.deny_limit`
settings are ignored.

LLM provider setup lives in global config. Store environment-variable names such
as `key_env: OPENROUTER_API_KEY`, not raw API keys. Runtime setup lives in the
guides for [Claude Code](../runtimes/claude-code.md),
[Codex](../runtimes/codex.md), and
[Terminal Guard](../runtimes/terminal-guard.md).

Install `nah[config]` or inject PyYAML into pipx when you want nah to read YAML
config files.

For remote providers, the secret value can live either in the process
environment or in an OS keychain/keyring when your CLI install includes
keyring support, such as `pip install "nah[keys]"`, `pipx inject nah keyring`,
or the default Nix package on systems with a usable keyring backend:

```bash
pip install "nah[config,keys]"
nah key set openrouter
nah key status
```

If you already exported a provider key, `nah key import-env openrouter` copies
that value into the configured keyring slot for `OPENROUTER_API_KEY`. It does
not remove the existing env var from your current shell or shell startup files.

The Claude Code plugin does not install the `nah` CLI, so `nah key ...`
requires a CLI install. For custom `key_env` values, you can manually store a
matching slot in your keyring under the service name `nah.llm`.

## Provider examples

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

=== "Azure OpenAI"

    ```yaml
    llm:
      mode: on
      providers: [azure]
      azure:
        url: https://YOUR-RESOURCE-NAME.openai.azure.com/openai/v1/responses
        key_env: AZURE_OPENAI_API_KEY
        model: your-deployment-name
    ```

    Azure uses `api-key` header auth, not bearer auth. The `url` is required
    because it depends on your Azure resource and deployment. For
    chat-completions deployments, set `url` to the deployment's
    `/chat/completions` endpoint; nah selects the payload shape from the URL.

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
        account: myorg-myaccount
        key_env: SNOWFLAKE_PAT
        model: claude-haiku-4-5
    ```

## Target-Specific Policy

The global provider cascade and credentials are shared across targets.
Per-target overrides can change whether a runtime uses the classify-unknown
LLM path:

```yaml
llm:
  mode: on
  providers: [openrouter]
  openrouter:
    key_env: OPENROUTER_API_KEY
    model: google/gemini-3.1-flash-lite-preview

targets:
  claude:
    llm:
      mode: on
  codex:
    llm:
      mode: on
```

The terminal-guard targets (`bash`, `zsh`) are deterministic-only and do not use
the LLM. Their `llm.mode` knob is still accepted for backward compatibility but
has no effect on terminal decisions.

Project `.nah.yaml` files can tighten target policy by default, but target LLM
settings and provider credentials are trusted/global config only. Use
`nah trust-project` when you want that exact project root to control non-policy
target settings.

## How the Cascade Works

1. nah tries each provider in the order listed in `providers:`
2. A valid classification is terminal, including an explicit `unknown`
3. If a provider response cannot be parsed or the provider errors, nah tries the next provider
4. If all providers fail, the deterministic `unknown -> ask` decision stands

Provider results are cached in-process by command string after a classification
is produced. All-provider-error results are not cached.

## Testing

```bash
nah config show
nah test "some-unknown-wrapper github.com"
nah test "curl -I https://example.com"
nah test "python3 -c 'print(1)'"
nah log --llm
```

`nah test` shows the classify pass in JSON output as `classify_llm` when an
unknown command is mapped by the LLM. Known asks and inline code remain asks.
