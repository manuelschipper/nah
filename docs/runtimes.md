# Agent runtimes

Install, inspect, or remove a supported integration:

```sh
nah hook <runtime> install
nah hook <runtime> status
nah hook <runtime> uninstall
```

nah runs on Windows, macOS, and Linux. Runtime integration support varies by
platform. The official Windows release is x86-64 only and currently unsigned;
ARM64 Windows and package-manager distributions are not supported.

Run `nah docs runtime-<name>` for a runtime-specific guide:

- `antigravity` — Google Antigravity
- `claude` — Claude Code
- `codex` — Codex
- `cursor` — Cursor
- `hermes` — Hermes
- `openclaw` — OpenClaw
- `opencode` — OpenCode
- `pi` — Pi

Nah 2.0 no longer supports Amp, Cline, GitHub Copilot, Devin, Factory Droid
or Kiro CLI; Nah 1.x still does. A hook 1.x installed for one checks nothing
after the upgrade and says so once per session; remove it with
`nah hook <runtime> uninstall`. To ask for Nah in another harness, open an
issue at https://github.com/manuelschipper/nah/issues.

## Where it works

Save then run and session memory (`nah docs concepts`) work only where this
table says. Elsewhere nah judges each call alone, and `work` at core blocks
only what 1.x blocked, such as a hard reset or a forced clean.

| Runtime | Save then run | Session memory |
| --- | --- | --- |
| Claude Code | macOS, Linux | macOS, Linux, Windows |
| Google Antigravity | macOS, Linux | macOS, Linux, Windows |
| Codex | macOS, Linux | macOS, Linux, Windows |
| Cursor | macOS, Linux | macOS, Linux, Windows |
| Hermes | no | macOS, Linux |
| OpenClaw | no | macOS, Linux |
| OpenCode | macOS, Linux | macOS, Linux |
| Pi | macOS, Linux | macOS, Linux |

## Analysis on Windows

These integrations have an explicit Windows contract:

| Runtime | Lifecycle | Analysis on Windows |
| --- | --- | --- |
| Claude Code | supported | Bash, PowerShell |
| Codex | supported | partial |
| Cursor | supported | partial |
| Hermes | unsupported | not available |
| OpenCode | unsupported | not available |

Supported lifecycle includes native install, status, reinstall, uninstall,
typed filesystem tools, self-protection, and failure policy. `partial` means a
shell payload delegates without shell effects when the runtime does not identify
its dialect. It does not weaken typed filesystem decisions. Hermes and
OpenCode return `runtime-platform-unsupported` before installation writes, while status reports `not configured`. Other runtime integrations do
not have a Windows support claim in this matrix.

## Shared contract

Runtime hooks are observation points, not sandboxes. nah returns `block` to
tell the runtime to stop the intercepted call, or `delegate` to return it to
the runtime's normal approval, permission, or sandbox flow. nah never approves
a call.

Unknown valid tool semantics delegate absent understood danger. If an adapter
cannot produce a valid nah decision, including from malformed outer input, it
uses its runtime-specific unavailable fallback. Fixed, non-secret feedback is
sent only when the runtime has a non-blocking channel. Built-in evaluation
failures delegate unless the available evidence suggests an enabled guard.
Redacted details are in `nah log` and `nah why`.

Nesting-limit refusals block by default. `--fail-closed` blocks other
explicit failures/refusals; ordinary uncertainty delegates, and adapter
unavailability uses native denial. `--fail-open` restores the default; flagless
reinstall keeps a known mode. This needs nah to respond.

When nah crashes or times out before it answers, a fail-open install lets the
call run, as in 1.x, so a discard may run without a fresh save; fail-closed
blocks it. That holds in Claude Code, Cursor, Hermes, OpenClaw, OpenCode and
Pi. Elsewhere the runtime decides, whatever the policy: in Codex and Google
Antigravity, for OpenClaw's own hook timeout, which blocks, and in Claude
Code's experimental Code Mode, which refuses a call whose hook timed out.

`install` writes nah-owned integration files or configuration. `uninstall`
removes only that wiring. `status` reports `not configured`, `wiring current`,
or `reinstall required` plus the detected failure policy from disk. Status
cannot prove that a running agent loaded the hook, that the runtime permits it,
or that every tool path emits an intercepted event.

Users must configure their runtime so the hook is loaded and stays active. Hook deadlines are runtime-owned and vary by product, surface,
configuration, and version.

Once an adapter is active, nah blocks understood intercepted attempts to alter
its active wiring or launch a child that skips the hook. The response tells the
agent not to retry and to ask the operator for `nah nap`.

Current installations are user-scoped, not same-user tamper-proof. Users still
own filesystem and runtime hardening.

Project shadow settings, UI actions, unrecognized or opaque launch forms,
already-unhooked processes, and direct operator commands outside an
intercepted call remain available. nah does not guarantee that a runtime will
load or invoke its adapter.

Each integration is best effort. Read its `runtime-*` page for known
limitations and verification steps, and double-check the latest upstream
runtime documentation after upgrades.

After installation, restart or reload the runtime, inspect its active hooks,
and test the integration before relying on it.

A runtime may ask you to review or trust hooks after `nah hook <runtime>
install`. Open the runtime once after installing and accept nah's hooks. Until
you do, the runtime does not run them, so save then run and session memory do
not work there. `nah hook <runtime> status` reads only the hook files and
cannot see a runtime's trust decision.
