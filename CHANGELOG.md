# Changelog

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
  opencode, openclaw, hermes, and pi. Every adapter hooks the native
  path and fails closed.
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
