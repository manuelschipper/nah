# Running unsupervised agents

Use this setup when a coding agent should keep working without waiting for
permission prompts.

The model is simple:

- The sandbox or disposable workspace is the blast-radius boundary.
- nah is the side-effect policy layer inside that boundary.
- Clear safe work continues.
- Clear dangerous work blocks.
- Anything nah would normally ask about fails closed with `ask_fallback: block`.

## Codex: choose the boundary

`nah run codex` uses Codex `danger-full-access` by default. That means Codex is
not adding its own filesystem sandbox, but the run is still guarded by nah's
Codex hooks.

This default is often the right fit when the agent already runs inside your
intended boundary, such as a devcontainer, VM, CI worker, throwaway checkout, or
locked-down build host. It also avoids breaking host-integrated workflows that
need Docker, local services, extra bind mounts, or non-project tool state.

Use the default host-integrated mode like this:

```bash
nah codex setup
nah run codex --preset sandboxed-build-agent exec "run tests and fix failures"
```

`nah run codex exec` is the guarded headless path. In headless mode, Codex has
no useful approval prompt, so nah enforces decisions in `PreToolUse`.

If you prefer, you can use Codex workspace sandboxing:

```bash
nah run codex --sandbox workspace-write --network --preset sandboxed-build-agent exec "run tests and fix failures"
```

Codex `workspace-write` is OS-level containment. Codex can write in the current
workspace plus configured writable roots, `/tmp`, `$TMPDIR`, and its memories
root; network is off unless you pass `--network`; project metadata such as
`.git`, `.agents`, and `.codex` stays read-only. This is useful defense in
depth, but it can be overkill for workflows that intentionally need host-level
resources.

## What nah guards

nah is the side-effect policy layer. It classifies Codex Bash, MCP, and
`apply_patch` hook payloads, then allows, asks, or blocks before execution.

With this preset, unresolved asks become blocks. That covers review-only cases
such as filesystem changes outside the project, destructive container cleanup,
unknown network hosts, database writes, and unknown commands. Remote
download-to-shell compositions are blocked directly as remote code execution.

nah is not a full OS sandbox. An allowed command can still do what its process,
credentials, and host environment permit. Use Codex `workspace-write` or an
outer container/VM when you need filesystem containment beyond nah policy.

## Claude Code: use print mode

For unattended Claude Code, use Claude's non-interactive print mode through nah:

```bash
nah run claude --preset sandboxed-build-agent -p "run tests and fix failures"
```

`claude -p` runs one prompt, prints the result, and exits. `nah run claude`
passes `-p` through to Claude, injects nah hooks when direct hooks or the plugin
are not already installed, and exports `NAH_PRESET` for the hook process.
Claude skips the workspace trust dialog in print mode, so run it only from a
trusted checkout or inside an outer sandbox.

Claude Code does not have a `nah run claude --sandbox workspace-write`
equivalent. Claude has an optional sandboxed Bash tool, but that contains Bash
commands and their child processes. Claude's file tools, MCP servers, plugins,
and hooks still run in the host process unless you put the whole Claude process
inside a container, VM, devcontainer, or another sandbox runtime.

For `claude -p`, keep nah's active allow behavior on. Safe calls need a hook
`allow` decision because there is no interactive prompt to answer. The
`ask_fallback: block` preset setting turns unresolved reviews into denials
instead of stalled permission prompts.

`nah run claude` rejects bypass modes for guarded Claude runs:

```bash
# Do not use these with nah-run unattended work
nah run claude --allow-dangerously-skip-permissions
nah run claude --dangerously-skip-permissions
nah run claude --permission-mode auto
nah run claude --permission-mode bypassPermissions
nah run claude --bare
```

`--dangerously-skip-permissions` and `bypassPermissions` skip Claude's
permission layer, and auto mode makes Claude's own classifier the approval
authority. `--bare` skips hooks, which means nah does not see the tool calls. If
you intentionally want those modes, run Claude inside an outer sandbox and treat
it as outside nah's protection.

You can make Claude's own permission layer deny anything nah does not actively
allow:

```bash
nah run claude --preset sandboxed-build-agent -p --permission-mode dontAsk "run tests and fix failures"
```

This is useful for CI-style jobs. It is not a replacement for nah's preset: nah
still supplies the detailed path, content, command, MCP, taint, and provenance
decisions.

Avoid broad `--allowedTools` lists for unattended Claude runs unless you have a
separate reason to use Claude's native permission rules. The nah preset is the
policy bundle; Claude flags should stay minimal.

## Add an unsupervised preset

Put the preset in `~/.config/nah/config.yaml`.

```yaml
# ~/.config/nah/config.yaml
presets:
  sandboxed-build-agent:
    sensitive_paths:
      ~/.ssh: block
      ~/.aws: block
      ~/.config/gh/hosts.yml: block
      .env: block
      .env.production: block

    actions:
      filesystem_read: allow
      filesystem_write: context
      filesystem_delete: context

      git_safe: allow
      git_write: allow
      git_remote_write: block
      git_discard: block
      git_history_rewrite: block

      package_install: allow
      package_run: allow
      package_uninstall: block
      lang_exec: context

      network_outbound: context
      network_write: block
      network_diagnostic: allow

      db_read: allow
      db_write: context

      service_read: context
      service_write: block
      service_destructive: block

      container_read: allow
      container_write: context
      container_exec: block
      container_destructive: block

      browser_read: allow
      browser_interact: allow
      browser_state: allow
      browser_navigate: context
      browser_exec: block
      browser_file: context

      agent_read: allow
      agent_write: block
      agent_exec_read: block
      agent_exec_write: block
      agent_exec_remote: block
      agent_server: block
      agent_exec_bypass: block

      process_signal: block
      obfuscated: block
      unknown: block

    targets:
      codex:
        ask_fallback: block
      claude:
        ask_fallback: block

    taint:
      mode: enforce
      inherit_sensitive_paths: true
      policies:
        default:
          activation: block
          boundary: block
          unknown: block
        secret:
          activation: block
          boundary: block
          unknown: block

    provenance:
      mode: enforce
      policies:
        activation: context
        boundary: block
        git_remote_write: block
```

This preset avoids explicit `ask` policies. `context` can still produce an
internal ask when nah cannot prove the operation is safe. The target fallback
then converts that unresolved ask into a final block.

## What `context` does

`context` keeps the agent productive without turning unknowns into allows.

- `filesystem_write: context` allows project-local writes and asks on unresolved
  outside-project writes. With `ask_fallback: block`, that ask becomes a block.
- `lang_exec: context` allows clean project scripts or clean inline code, and
  blocks missing, outside-project, sensitive, or suspicious execution.
- `network_outbound: context` allows localhost and known read-like hosts, and
  blocks unknown hosts.
- `db_write: context` can allow configured local/test database targets and
  blocks unresolved writes.

In an interactive session, unresolved context would ask. In this preset, it
blocks.

## Run it

Inspect the effective config first:

```bash
nah config show --preset sandboxed-build-agent
```

Dry-run the policy:

```bash
nah test --target codex --preset sandboxed-build-agent "python3 -c 'print(1)'"
nah test --target codex --preset sandboxed-build-agent "python3 missing.py"
nah test --target codex --preset sandboxed-build-agent "curl https://example.com"
nah test --target codex --preset sandboxed-build-agent "git push"
```

Then run the agent:

```bash
nah run codex --preset sandboxed-build-agent exec "run tests and fix failures"
```

If you prefer Codex workspace sandboxing, run:

```bash
nah run codex --sandbox workspace-write --network --preset sandboxed-build-agent exec "run tests and fix failures"
```

For interactive Claude Code sessions:

```bash
nah run claude --preset sandboxed-build-agent
```

For unattended Claude Code:

```bash
nah run claude --preset sandboxed-build-agent -p "run tests and fix failures"
```

If Claude hooks are already installed or provided by the plugin, you can also
select the preset through the environment:

```bash
NAH_PRESET=sandboxed-build-agent claude
```

## PR agent variant

For an agent that is allowed to push branches, create a second preset by
copying `sandboxed-build-agent` and changing only the remote Git policy:

```yaml
# In the copied sandboxed-pr-agent preset:
actions:
  git_remote_write: allow

provenance:
  policies:
    git_remote_write: context
```

Use narrowly scoped Git credentials for this preset. Branch protection and repo
permissions are the publishing boundary. Do not pair it with broad
`network_write: allow`.

Run it with:

```bash
nah run codex --preset sandboxed-pr-agent exec "open a PR for the failing tests"
```

## Check the run

Inspect decisions after the run:

```bash
nah log
nah log --blocks
nah log --asks
```

For headless Codex, log entries include headless runtime metadata, the selected
preset, sandbox mode, and fallback metadata when an ask became a block.
