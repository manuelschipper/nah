# Running unsupervised agents

Use a global preset when Codex or Claude Code should keep working without
waiting for permission prompts.

nah is a policy layer for agent tool calls and shell commands. It is not a
substitute for a sandbox: an allowed operation still runs with the process's
real filesystem, network, credentials, and host access. Use a devcontainer, VM,
CI worker, throwaway checkout, Codex workspace sandboxing, or another outer
boundary when you need containment.

## Add the preset

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
      git_remote_write: block
      git_discard: block
      git_history_rewrite: block

      package_uninstall: block

      network_write: block

      service_read: context
      service_write: block
      service_destructive: block

      env_read: block

      container_build: block
      container_exec: block
      container_destructive: block

      process_signal: block
      unknown: block

    targets:
      codex:
        ask_fallback: block
      claude:
        ask_fallback: block
```

This preset lets routine project work continue while making unattended runs fail
closed.

High-risk actions are blocked directly where they should never happen in this
mode. This includes `container_build`, because Docker builds can execute
Dockerfile `RUN` steps and mutate image or container infrastructure even though
the default policy is `allow`. `env_read: block` stops commands whose purpose is
exposing environment or secret values (`printenv`, `vault kv get`,
`kubectl get secret`, …) so credentials are never dumped during an unattended
run. `ask_fallback: block` catches remaining default-`ask` and unresolved review
cases that would otherwise need a human.

The service taxonomy is split: `service_inspect` (local daemon inspection such as
`systemctl status` or `journalctl`) is read-only and stays at its `allow` default,
while `service_read` now covers only *remote* API reads (`curl` GET, gRPC, GraphQL)
and is host-checked via `context`. Tighten either explicitly if even read-only
service inspection should pause in your environment.

`context` is used where the answer depends on what nah can inspect, such as the
path, command, content, or tool target.

The result is intentionally conservative: safe build/test/edit work can proceed,
while secrets, remote writes, destructive operations, bypasses, and unresolved
cases stop the run.

Check the merged config:

```bash
nah config show --preset sandboxed-build-agent
```

## Run Codex headless

```bash
nah setup codex
nah run codex --preset sandboxed-build-agent exec "run tests and fix failures"
```

`nah run codex exec` is the guarded headless path. By default, `nah run codex`
uses Codex `danger-full-access`, so Codex does not add filesystem sandboxing.
This is often right inside an existing devcontainer, VM, CI worker, or
throwaway checkout.

If you prefer, use Codex workspace sandboxing:

```bash
nah run codex --sandbox workspace-write --network --preset sandboxed-build-agent exec "run tests and fix failures"
```

`workspace-write` allows writes in the workspace and temporary roots, keeps
`.git`, `.agents`, and `.codex` read-only, and disables network unless
`--network` is set.

## Run Claude Code headless

```bash
nah run claude --preset sandboxed-build-agent -p "run tests and fix failures"
```

`claude -p` runs one prompt, prints the result, and exits. Claude Code has no
full filesystem sandbox equivalent to Codex `workspace-write`; its optional
Bash sandbox does not contain file tools, MCP, plugins, or hooks. Use an outer
sandbox when host containment matters.

## Use the preset in the TUI

You can use the same preset in normal interactive sessions:

```bash
nah run codex --preset sandboxed-build-agent
nah run claude --preset sandboxed-build-agent
```

These are not headless runs; the agent opens normally with the preset active.

## Test the preset

```bash
nah test --target codex --preset sandboxed-build-agent "python3 -c 'print(1)'"
nah test --target codex --preset sandboxed-build-agent "python3 missing.py"
nah test --target codex --preset sandboxed-build-agent "curl https://example.com"
nah test --target codex --preset sandboxed-build-agent "git push"
```

Inspect decisions after a run:

```bash
nah log
nah log --blocks
nah log --asks
```

## Customize or make variants

Create a second preset when one job needs a narrower or broader policy. For
example, a branch-pushing agent can allow the remote Git the base preset blocks:

```yaml
# In the copied sandboxed-pr-agent preset:
actions:
  git_remote_write: allow
```

Use narrowly scoped Git credentials for this preset. Do not pair it with broad
`network_write: allow`.

```bash
nah run codex --preset sandboxed-pr-agent exec "open a PR for the failing tests"
```
