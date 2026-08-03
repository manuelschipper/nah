# Threat model

nah is a guardrail in a coding agent's tool-call path. Its built-in analysis is
deterministic. It blocks positively identified dangerous actions before the
runtime executes them and protects its own authority and active runtime wiring
from understood agent mutation outside maintenance.

nah is not a sandbox, a least-privilege system, or a recovery mechanism. It
does not contain the agent or reduce the authority of the operating-system
account, tools, and credentials given to it.

## Adversary

The primary adversary is a prompt-injected, confused, or stuck agent in an
already-hooked session. It runs with the developer's ordinary privileges and
may retry a blocked goal through another tool, shell wrapper, or statically
visible interpreter form.

The adversary is not a malicious operator or administrator. An operator who
works outside the intercepted session, starts an unhooked runtime, or grants
the agent stronger access is exercising authority that nah does not control.
An agent running as root or administrator is outside nah's local protection
boundary.

## Security properties

- A completed decision is only `block` or `delegate`; nah never approves a call.
- Any active guard may block. Otherwise the call returns to the runtime's normal
  sandbox, permission, and approval flow.
- Structural self-protection is not a configurable guard. Outside an active
  maintenance nap, it protects nah's authority state, installed executable,
  authority-changing commands, and the active runtime's standard hook and
  enablement files.
- Recognized in-session attempts to remove the active hook or launch a child
  runtime without it block outside maintenance and direct the agent to the
  operator.
- Valid unknown, opaque, or bounded semantics delegate unless understood
  evidence positively identifies danger. Uncertainty alone is not a block.
- Analyzer or custom-guard failure adds no finding by default. A loaded
  `--fail-closed` hook blocks explicit failures/refusals and uses native denial
  for malformed/no-decision input; ordinary uncertainty still delegates.

These properties apply only to tool calls that reach a loaded nah adapter and
to evidence nah can observe and model. Inline child effects require exact
source and arguments; unproven child cwd, environment, or output capture is not
assumed and supplies no derived fact or flow.

## Trust assumptions and limits

nah relies on the runtime to load the installed adapter, send relevant tool
calls, honor its blocking response, and meet its hook deadline. Runtime bugs,
UI actions, remote tools, already-unhooked processes, trusted plugins, opaque
programs, unobservable filesystems, and configuration changed outside an
intercepted call remain outside the guarantee.

User-level hook installation is a prompt-injection guardrail, not a
same-user tamper-proof boundary. Stronger installation integrity requires a
runtime-managed or administrator-controlled configuration, and still depends
on the runtime offering a mandatory hook contract.

Activated custom guards are trusted, unsandboxed programs. They run with the
user's permissions, inherit nah's environment, and receive the unredacted
modeled request. A malicious custom guard is outside this threat model.

Read `nah docs security` for concrete enforced and unenforced behavior, and
`nah docs runtimes` plus the selected `runtime-*` topic for integration-specific
coverage and bypasses.

## Defense in depth

For a sensitive, valuable, or difficult-to-recover environment, do not rely on
nah or any single policy hook as the sole boundary:

- Sandbox the agent with the runtime's sandbox, a container, a disposable
  virtual machine, or an isolated development host. Restrict filesystem mounts
  and network access.
- Give the agent only the tools, directories, services, and environments
  required for the task. Avoid root or administrator access.
- Use short-lived, narrowly scoped credentials. Prefer read-only access,
  separate development from production, and withhold deployment, billing, or
  organization-administration tokens unless the task requires them.
- Keep runtime permissions and approval prompts enabled. `delegate` means the
  runtime still decides; it is not an approval from nah.
- Maintain version control, backups, snapshots, or disposable environments so
  prevention failure is recoverable.
- Protect required hooks with runtime-managed settings or administrator-owned
  configuration when same-user mutation must be resisted.

## Operator control

Direct operator work outside an intercepted call remains available. When an
intercepted tool must intentionally change protected nah state or active
runtime wiring, the operator can run `nah nap` in a separate interactive
terminal, let the tool make the change during the fixed maintenance window,
and run `nah wake` to resume sooner. `nah nap --all` pauses all non-permanent
enforcement; authenticated nap state remains protected. See `nah docs
configuration`.
