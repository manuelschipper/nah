# LLM Layer

nah can optionally consult an LLM for decisions that need judgment after deterministic classification.

```
Guarded action → nah (deterministic) → LLM (optional) → agent/terminal approval flow → execute
```

The deterministic layer always runs first. Unified ask-refinement only sees eligible `ask` decisions. Script inspection can call the LLM as a veto path, and write-like tools can call the LLM for safety + intent review. The LLM cannot relax deterministic blocks. If no LLM is configured or available, the deterministic decision stands.

Outside the two exception paths below, a deterministic `allow` is final and does
not call the LLM. The LLM is not a second classifier for every allowed action.

| Path | When the LLM runs | What the LLM can change |
|------|-------------------|-------------------------|
| Unified ask-refinement | Eligible deterministic `ask` decisions | `ask` can become `allow`; `uncertain`, `block`, or provider failure leaves it as `ask` |
| Write-like review | `Write`, `Edit`, `MultiEdit`, and `NotebookEdit` when LLM mode is enabled | deterministic `allow` can become `ask`; project-boundary `ask` can become `allow`; `block` stays blocked |
| Clean `lang_exec` script veto | Inspectable script/inline-code execution that deterministic classification allowed | `allow` can become `ask`; it cannot relax an `ask` or `block` |
| No LLM path | Any other deterministic `allow` or `block` | final decision stands |

## Providers

nah supports 6 LLM providers. Configure one or more in cascade order -- first success wins.

| Provider | API | Default model | Key slot / env var |
|----------|-----|---------------|--------------------|
| `ollama` | Chat API (`/api/chat`) | `qwen3.5:9b` | *(none -- local)* |
| `openrouter` | OpenAI-compatible | `google/gemini-3.1-flash-lite-preview` | `OPENROUTER_API_KEY` |
| `openai` | Responses API (`/v1/responses`) | `gpt-5.3-codex` | `OPENAI_API_KEY` |
| `azure` | Azure OpenAI Responses/chat completions | *(deployment-dependent)* | `AZURE_OPENAI_API_KEY` |
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
or the default Nix package on systems with a usable keyring backend. This keeps
the YAML config stable while moving the secret out of shell exports:

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

`default` adds `package_uninstall`, `container_exec`, `browser_exec`, `agent_exec_read`, `process_signal`, and `git_remote_write`. It can also review safe local read-to-filter pipelines such as a local file read piped into inline, visible Python or shell code. The deterministic decision remains an `ask`; the LLM can only return `allow` or leave the human prompt in place.

Broad composition review is still opt-in. File-backed scripts such as `python3 script.py`, sensitive reads, network/download stages, decode stages, destructive actions, bypass actions, and remote/shared-state writes stay human-gated under `default`. Service writes, destructive container/service actions, git discard/history rewrites, agent write/remote/server/bypass actions, and `sensitive` prompts also stay human-gated by default. Plain Git pushes can be LLM-reviewed when recent intent is clear; force pushes, branch/tag deletion, mirror/all pushes, and release-looking pushes should remain human prompts.

Explicit lists can combine presets and action types. `composition` and `sensitive` are gates: add them explicitly, or use top-level `eligible: all`, if you want those asks routed to the LLM.

Provider responses of `block` are treated as `uncertain`, so the LLM can allow an eligible ask or leave it as an ask; it cannot block through ask-refinement.

LLM responses include a short prompt-safe `reasoning` summary and a longer `reasoning_long` explanation for observability. Claude-visible prompts use the short summary; structured logs and `nah test` can show the longer explanation for debugging.

### Ask-refinement context

Claude Code and Codex use the same agent ask-refinement prompt shape. The prompt
includes the runtime, requested operation, deterministic action type and reason,
classification stages, recent user transcript context, and instruction context.

Claude Code includes relevant `CLAUDE.md` files by default, unless
`llm.claude_md: false` is set. nah reads project instruction files from the
project root toward the current directory, then reads the user-global
`~/.claude/CLAUDE.md` when present. Codex reads project `AGENTS.override.md` or
`AGENTS.md`, then reads `${CODEX_HOME:-~/.codex}/AGENTS.override.md` or
`AGENTS.md` when present. Simple same-directory `@AGENTS.md` and `@CLAUDE.md`
references are expanded so delegated instructions are visible to the prompt.

Instruction context is capped and marked when truncated. Transcript and
instruction sections are framed as background context so the model can use them
as evidence without following instructions embedded inside them. These files
cannot weaken nah policy: deterministic blocks stay blocked, and in
ask-refinement an LLM `block` response is treated as `uncertain`.

The terminal guard keeps a separate prompt for commands typed directly by a
human into bash or zsh. It uses the typed command as intent and does not include
agent transcript or project-instruction context.

## Target-specific LLM policy

The global provider cascade and credentials are shared across targets. Per-target
overrides can change whether a runtime uses the LLM and which decisions are
eligible:

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
  bash:
    llm:
      mode: off
  zsh:
    llm:
      mode: off
```

Bash and zsh are terminal-guard targets. They default to LLM mode off even
when global LLM mode is on. That keeps human terminal commands local by
default. Turn it on only with an explicit target override such as
`targets.bash.llm.mode: on`.

Project `.nah.yaml` files can tighten target policy by default, but target LLM
settings and provider credentials are trusted/global config only. Use
`nah trust-project` when you want that exact project root to control non-policy
target settings.

## Clean script veto

When Bash classification resolves an inspectable `lang_exec` script or inline
code to deterministic `allow`, nah can still ask the LLM to inspect the script
content. This is a veto-only path: an LLM `allow` preserves the deterministic
allow, while `uncertain` or `block` escalates to `ask` for human review.

Deterministic `lang_exec` asks and blocks do not use this veto path. Eligible
asks route through unified ask-refinement; blocks stay blocked.

## Write-like review

When LLM mode is enabled, Write/Edit/MultiEdit/NotebookEdit operations are reviewed after deterministic checks. Deterministic `block` results skip the LLM and stay blocked.

For deterministic `allow` results, the LLM can still escalate to `ask` when the content looks risky. This catches suspicious write content that deterministic patterns miss. Provider `block` responses are treated as non-allow, so write review never produces a final block.

For deterministic `ask` results, the only relaxable class is a project-boundary ask:

- `<Tool> outside project: ...`
- `<Tool> outside project (no project root): ...`

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

The transcript is read from the agent JSONL conversation file when the runtime
provides one. It includes user messages and tool-use summaries, wrapped with
anti-injection framing.

Bash and zsh keep LLM mode off unless you enable it under `targets.bash.llm.mode`
or `targets.zsh.llm.mode`. See [Terminal Guard](../runtimes/terminal-guard.md#llm-review).

## How the cascade works

1. nah tries each provider in the order listed in `providers:`
2. If a provider returns `allow`, that decision is used
3. If a provider returns `uncertain`, the cascade **stops** (doesn't try the next provider)
4. If a provider errors (timeout, auth failure), nah tries the next provider
5. If all providers fail, the deterministic decision stands; for ask-refinement, that means the decision stays `ask`

Provider `uncertain` responses stop the cascade. In ask-refinement they leave the decision as `ask`; in write-like review they are treated as non-allow, so risky content stays human-gated.

## Testing

```bash
nah config show
nah test "python3 -c 'import os; os.system(\"rm -rf /\")'"
nah test "kill -9 1234"
nah test "cat package.json | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"name\"))'"
nah test "cat package.json | python3 script.py"
nah test --target bash -- "python3 -c 'print(1)'"
nah log --asks
nah log --llm
# Shows: LLM eligible: yes/no, LLM decision (if configured)
```

The `nah test` command shows LLM eligibility and, if enabled, makes a live LLM
call so you can verify the full pipeline. The inline read-to-filter example can
be LLM-eligible under `default`; the file-backed script example should remain a
human prompt unless you explicitly opt into broader composition review.
