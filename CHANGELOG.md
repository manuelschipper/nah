# Changelog

## Unreleased

- **Guard names match their scope** — `fs-system-tree` replaces `fs-root`,
  and `secrets-exfil` replaces `exfil-pipe`, so configuration and block
  attribution name the protected system trees and sensitive network flow.
- **Network-shell documentation** — `exec-network-shell` now documents shell
  redirection alongside netcat and socat attachments.
- **Mobile theme toggle alignment** — the homepage theme control now shares
  the navigation links' text baseline on small screens.

## nah 1.2.0 — Aug 4, 2026

- **Generated web guard reference** — the homepage build now renders
  `/docs/guards/` directly from the compiled CLI catalog under shipped-default
  state, preventing a second hand-maintained guard list from drifting.
- **Destructive Git worktree guards** — two new default-on guards block forced
  project-root cleans, project-wide checkout/restore, and statically proven
  forced branch changes while named targets and ambiguous checkout forms still
  delegate.

## nah 1.1.0 — Aug 3, 2026

- **Opt-in fail-closed runtime hooks** — `nah hook <runtime> install
  --fail-closed` now blocks otherwise-delegated explicit evaluation failures
  and bounded analysis refusals, with fixed recovery guidance and native denial
  when no valid decision exists. Default installs remain delegate-on-failure;
  `--fail-open` downgrades and flagless reinstall preserves recognized mode.
- **Inline language disaster signatures** — built-in guards now recognize
  selected exact visible Python, JavaScript, Ruby, Perl, PHP, Lua, R, Julia,
  Swift, PowerShell, and cmd forms for supported filesystem and execution
  disasters. Exact child shell and argv calls reuse normal Bash effects and
  proven stdout flows; ambiguous child calls or unsupported code add nothing.
- **Stable inline extension input** — visible interpreter code remains an
  `code-execution` invocation with source `interpreter-inline` for custom
  guards, alongside any proven child effects; private built-in findings do not
  rewrite its source classification.

## nah 1.0.0 — Aug 1, 2026

First release. One static Rust binary that hooks into a coding agent,
blocks catastrophic tool calls before they run, and delegates everything
else to the runtime.

- **17 built-in guards, all on by default** — execution hijacks, secret
  theft, filesystem destruction, and Git disasters, decided
  deterministically in microseconds with no LLM.
- **Block or delegate, never approve** — any guard can block a call;
  nothing can widen the runtime's own permissions. Partial understanding
  can block, never allow.
- **14 runtime adapters** — one install command each for claude code,
  codex, cursor, cline, copilot, antigravity, kiro, amp, devin, droid,
  opencode, openclaw, hermes, and pi. Every adapter hooks the native path.
- **Custom guards in any language** — `nah guard new`, effects on stdin,
  block or abstain on stdout. Extensions can only make nah stricter, and
  project guards stay inert until a human trusts the repository.
- **Structural self-protection** — an agent cannot disable guards, trust
  a project, or unhook the runtime through a tool call. Operators get a
  supervised ten-minute window with `nah nap` / `nah wake`.
- **On the record** — every decision is stored redacted and explained by
  `nah why`; structure only, never command text.
- **Self-teaching CLI** — embedded `nah docs` topics shared verbatim by
  the binary, the repository, and nahguard.ai.
- **Policy version 1** — guards-only decision semantics: every decision
  is `block` or `delegate`; custom guards answer `block` or `abstain`.
