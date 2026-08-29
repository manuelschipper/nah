# Agent runtimes

Install, inspect, or remove one integration:

```sh
nah hook <runtime> install
nah hook <runtime> status
nah hook <runtime> uninstall
```

nah runs on Windows, macOS, and Linux. Runtime integration support varies by
platform. The official Windows release is x86-64 only and currently unsigned;
ARM64 Windows and package-manager distributions are not supported.

Run `nah docs runtime-<name>` for a runtime-specific guide:

- `amp` — Amp
- `antigravity` — Google Antigravity
- `claude` — Claude Code
- `cline` — Cline
- `codex` — Codex
- `copilot` — GitHub Copilot
- `cursor` — Cursor
- `devin` — Devin
- `droid` — Factory Droid
- `hermes` — Hermes
- `kiro` — Kiro CLI
- `openclaw` — OpenClaw
- `opencode` — OpenCode
- `pi` — Pi
- `prime-agent` — Prime Agent

## Analysis on Windows

These integrations have an explicit Windows contract:

| Runtime | Lifecycle | Analysis on Windows |
| --- | --- | --- |
| Claude Code | supported | Bash |
| Codex | supported | partial |
| Cursor | supported | partial |
| GitHub Copilot | supported | Bash, PowerShell, or partial by payload |
| Cline | supported | partial |
| Kiro CLI | supported | Bash |
| Amp | unsupported | not available |
| Factory Droid | unsupported | not available |
| Hermes | unsupported | not available |
| OpenCode | unsupported | not available |

Supported lifecycle includes native install, status, reinstall, uninstall,
typed filesystem tools, self-protection, and failure policy. `partial` means a
shell payload delegates without shell effects when the runtime does not identify
its dialect. It does not weaken typed filesystem decisions. Amp, Factory Droid,
Hermes, and OpenCode return `runtime-platform-unsupported` before installation
writes, while status reports `not configured`. Other runtime integrations do
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
failures yield `delegate`. A custom-guard failure contributes no finding, so
other guards still decide. Persisted redacted details are available through
`nah log` and `nah why`.

`--fail-closed` blocks explicit failures/refusals; ordinary uncertainty
delegates, and adapter unavailability uses native denial. `--fail-open` restores
the default; flagless reinstall preserves a known mode. This requires nah to
respond.

`install` writes nah-owned integration files or configuration. `uninstall`
removes only that wiring. `status` reports `not configured`, `wiring current`,
or `reinstall required` plus the detected failure policy from disk. It cannot
prove that a running agent loaded the hook, that the runtime permits it, or
that every tool path emits an intercepted event.

Users are responsible for configuring their runtime so the hook is loaded and
remains active. Hook deadlines are runtime-owned and vary by product, surface,
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
