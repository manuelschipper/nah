# LLM Layer

nah can optionally consult an LLM for decisions that need judgment after deterministic classification.

```
Guarded action → nah (deterministic) → LLM (optional) → agent/terminal approval flow → execute
```

The deterministic layer always runs first. The LLM layer is split into two
single-purpose roles: **Layer 1** classifies a deterministically-`unknown`
command into an action type plus the targets it touches, and **Layer 2** (the
intent relaxer) refines eligible `ask` decisions. Script inspection can call the
LLM as a veto path, and an optional session-provenance review can weigh the
later effects of same-session writes. Write-like tool calls
(Write/Edit/MultiEdit/NotebookEdit and Codex `apply_patch`) are never sent to the
LLM — they are guarded by a deterministic path/boundary floor only. The LLM
cannot relax deterministic blocks. If no LLM is configured or available, the
deterministic decision stands.

Outside the paths below, a deterministic `allow` is final and does not call the
LLM. The LLM is not a second classifier for every allowed action.

| Path | When the LLM runs | What the LLM can change |
|------|-------------------|-------------------------|
| Layer 1 — classify-unknown | A deterministic `unknown` Bash command | maps the unknown to an action type **+ the targets it touches**; the type re-enters the policy machinery and each surfaced target is re-checked against the same deterministic floor. Can tighten to `ask`/`block`, or allow only when every surfaced target passes the floor; cannot bypass a sensitive-path/host/boundary veto |
| Layer 2 — intent relaxer | Eligible deterministic `ask` decisions | `ask` can become `allow` **only with a cited user message** (cite-or-ask); a successful relax is surfaced as a distinct `relaxed` outcome. `uncertain`, an uncited allow, `block`, or provider failure leaves it as `ask` |
| Write-like tools | Never — not an LLM path | `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, and Codex `apply_patch` are guarded by a deterministic path/boundary floor only and are never sent to the LLM |
| Clean `lang_exec` script veto | Inspectable script/inline-code execution that deterministic classification allowed | `allow` can become `ask`; it cannot relax an `ask` or `block` |
| No LLM path | Any other deterministic `allow` or `block` | final decision stands |

Layer 1 **extracts**; the deterministic floor **matches**. The model proposes a
type and the resources the command touches, but the sensitive-path,
project-boundary, and trusted-host checks stay in deterministic code — the model
is never the thing that clears a dangerous target. The risk taxonomy below
applies to Layer 2, the clean-script veto, and the session-provenance review, not
to Layer 1 (which emits action types, not risk categories).

## What LLM review looks for

All LLM review paths use the same security scope, adapted to the surface being
reviewed. nah asks the model to stay uncertain when the reviewed operation
visibly includes one of these risks:

- Credentials and sensitive paths: credentials, tokens, private keys,
  passwords, sensitive paths, or broader secret access.
- Exfiltration or unauthorized access: local data, environment values,
  repository content, credentials, or user data sent to unauthorized remote
  destinations.
- Untrusted or obfuscated execution: downloaded, generated, obfuscated, hidden,
  or injection-prone execution.
- Persistence and trust-boundary changes: startup files, hooks, package
  lifecycle scripts, CI/deploy/release automation, auth/session config, or
  other trust-boundary changes.
- Privileged runtime or system state: process, service, container, database,
  system, or privileged runtime state changes.
- Destructive or hard-to-reverse state changes: broad deletion, overwrite,
  migration, reset, purge, force/history rewrite, or hard-to-reverse state
  mutation.
- Production, shared, remote, or external mutations: production, shared,
  remote, or externally visible mutation.
- Safety, sandbox, approval, or audit bypass: sandbox, approval, audit, policy,
  hook, or guard bypass.
- Explicit user safety-scope conflict: recent user instructions constrain
  credentials, production, deploys, auth, persistence, external writes, safety
  controls, or similar boundaries, and the operation visibly crosses that
  constraint.

The code owns this taxonomy. The docs describe it in human-readable terms; the
internal category IDs are implementation details for tests and maintenance.

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

LLM responses include a prompt-safe `reasoning` summary of at most 10 words and
a longer `reasoning_long` explanation for observability. Prompt-safe means the
summary must not include secrets, sensitive values, or hidden reasoning.
Claude-visible prompts use the short summary; structured logs and `nah test`
can show the longer explanation for debugging.

### Ask-refinement context

Claude Code and Codex use the same agent ask-refinement (Layer 2) prompt **and
the same enforcement** — both paths route the model's reply through one shared
interpreter, so the cite-or-ask rule below applies identically whether the guard
is fronting Claude Code or a Codex permission request. The static rules live in
the system message (so a caching provider reuses them across asks); the per-ask
user message is intentionally minimal — the command, the cwd and whether it is
inside the project, and the recent user messages from the transcript. Nah-internal signals (the deterministic action type, reason, and
stage breakdown) are not placed in the prompt: the deterministic floor already
used them to decide this is an ask, and the model judges relaxation from the
command, scope, and the user's own words.

The relaxer is strictly **cite-or-ask**: it may choose `allow` only when it can
quote the recent user message that authorizes the action's target and effect
(returned in a `citation` field) — there is no "routine low-risk" auto-allow. It
must cite **only** from the recent user messages; nothing else in the prompt,
including the command being judged, counts as user intent. The cwd / `inside
project` flag is a blast-radius weight: an action reaching outside the project
(home, other repos, system files, external hosts) is higher risk and is relaxed
only when the citation clearly authorizes that wider reach.

The agent ask-refinement path does not read `CLAUDE.md`, `AGENTS.md`, global
instruction files, or instruction includes. Those files can guide the agent
itself, but nah treats recent transcript context as the evidence of user intent.
The transcript is framed as data, so the model can use it as evidence without
following instructions embedded inside it.

The shared risk categories appear as a compact one-line checklist drawn from the
same canonical list the verbose review prompts use, so the two can never drift.
Each category carries a **veto tier**: a **hard** category (credentials,
exfiltration, untrusted/obfuscated execution, safety/sandbox bypass, explicit
user-scope conflict) is never relaxable — a citation can never override it. A
**soft** category (external/remote mutation, destructive state, privileged state,
persistence/trust-boundary changes) is consequential but routinely authorized, so
a citation **may** relax it — but only for the specific action types that opt in.
The opt-in is per action: a soft category's veto is lifted from the checklist only
when judging an action allowed to relax it, so the same category still vetoes
every other action.

Today these soft relaxations are enabled (all routine, low-stakes, reversible
ops the user authorizes constantly — each lifts only the soft category that
otherwise over-vetoes its everyday case):

| Action | Lifted soft category | Example |
| --- | --- | --- |
| `git push` (`git_remote_write`) | external/remote mutation | "push please" |
| restart/kill a process (`process_signal`) | privileged runtime state | "restart the dev server" |
| run a command in a container (`container_exec`) | privileged runtime state | "run the tests in the container" |
| uninstall a dependency (`package_uninstall`) | persistence + destructive state | "uninstall that package" |

A relax only applies to an action that is also in `llm.eligible` (the breadth
gate); the lift here is the code-owned permissiveness gate that bounds how far
broad eligibility can go (it keeps `eligible: all` from auto-relaxing a cited
`rm -rf` or a prod deploy). Hard categories are never lifted for any action.

`git push` carries one accepted, documented security-debt tradeoff: it relaxes
with **no destination check**, so a misaligned agent that repoints the repo's
remote could have a cited push relaxed to an attacker destination. The exposure
is narrow — it needs both a repoint and a real cited push intent, and the
deterministic floor still makes every push an `ask` by default. The durable fix
(snapshot the trusted destination at session start and relax only if it has not
moved at push time) is tracked separately.

The relaxer can only allow an eligible ask or leave it in place; provider `block`
responses are treated as `uncertain`, and deterministic blocks do not route
through ask-refinement.

The terminal guard is deterministic-only and does not use the LLM: a command
typed directly into bash or zsh is already the human's own intent, so it is
classified to allow / ask / block with no provider call, and an `ask` is
confirmed inline at the prompt. The review scope above applies to the agent
runtimes only.

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
```

The terminal-guard targets (`bash`, `zsh`) are deterministic-only and do not use
the LLM. Their `llm.mode` knob is still accepted for backward compatibility but
has no effect on terminal decisions; see
[Terminal Guard](../runtimes/terminal-guard.md#deterministic-by-design).

Project `.nah.yaml` files can tighten target policy by default, but target LLM
settings and provider credentials are trusted/global config only. Use
`nah trust-project` when you want that exact project root to control non-policy
target settings.

## Clean script veto

When Bash classification resolves an inspectable `lang_exec` script or inline
code to deterministic `allow`, nah can still ask the LLM to inspect the script
content. This is a veto-only path: an LLM `allow` preserves the deterministic
allow, while `uncertain` or `block` escalates to `ask` for human review.

The clean script veto uses the shared review scope above. It is meant to catch
visible security or safety risk in otherwise clean script execution, not to
review code style or general implementation quality.

Deterministic `lang_exec` asks and blocks do not use this veto path. Eligible
asks route through Layer 2 ask-refinement; blocks stay blocked.

## Write-like tools are not LLM-reviewed

Write, Edit, MultiEdit, NotebookEdit, and Codex `apply_patch` are guarded by a
deterministic floor only: sensitive paths block or ask, `~/.claude/hooks/`
blocks, `~/.config/nah/` asks, writes outside the project root ask, destructive
`apply_patch` operations (delete/rename) ask, and everything else allows. Their
content is never sent to an LLM and is never scanned for secret-shaped text. Use
[sensitive paths](sensitive-paths.md), [taint tracking](taint-tracking.md), and
[provenance](provenance.md) for write-side protection.

## context_chars

How much conversation transcript context to include in the LLM prompt:

```yaml
llm:
  context_chars: 12000  # default: 12000 characters of recent transcript
```

Set to `0` to disable transcript context entirely.

The transcript is read from the agent JSONL conversation file when the runtime
provides one. It includes user messages and tool-use summaries, wrapped with
anti-injection framing.

Bash and zsh are deterministic-only and do not use the LLM; their `llm.mode`
setting is accepted for backward compatibility but has no effect. See
[Terminal Guard](../runtimes/terminal-guard.md#deterministic-by-design).

## How the cascade works

1. nah tries each provider in the order listed in `providers:`
2. If a provider returns `allow`, that decision is used
3. If a provider returns `uncertain`, the cascade **stops** (doesn't try the next provider)
4. If a provider errors (timeout, auth failure), nah tries the next provider
5. If all providers fail, the deterministic decision stands; for ask-refinement, that means the decision stays `ask`

Provider `uncertain` responses stop the cascade. In ask-refinement they leave the decision as `ask`; in the clean-script veto they leave the script as an `ask`.

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
