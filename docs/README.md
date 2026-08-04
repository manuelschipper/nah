# nah documentation

nah is a deterministic safety guard for coding agents. It blocks visible tool
calls it can prove are disasters — deterministically, without an LLM — and
leaves everything else to the runtime's normal approval flow. Start
narrow and load only the topic needed for the current task.

- [Start](start.md) — install nah and guard one agent.
- [Core concepts](concepts.md) — effects, verdicts, guards, and trust.
- [CLI guide](cli.md) — the complete human and machine command map.
- [Configuration](configuration.md) — shipped policy and trusted projects.
- [Extending](extensions.md) — build one-shot guard programs.
- [Agent runtimes](runtimes.md) — supported integrations and their boundaries.
- [Threat model](threat-model.md) — adversary, assumptions, and defense in depth.
- [Security boundaries](security.md) — what nah does and does not enforce.
- [Architecture](architecture.md) — contributor-oriented code navigation.
- [Changelog](../CHANGELOG.md) — user-visible changes.

The focused pages under `docs/` ship inside the binary; this index and the
changelog remain repository-only:

```sh
nah docs
nah docs start
```

Runtime-specific topics use names such as `runtime-codex` and
`runtime-hermes`. The website publishes a generated
[guard catalog](https://nahguard.ai/docs/guards/) from the compiled binary.
`nah docs guards` renders the same built-in policy catalog and tested examples,
plus local enablement state and custom guard status.
