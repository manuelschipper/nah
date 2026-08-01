# P2 tree-sitter spike

This is a disposable, standalone Cargo workspace. It tests whether
`tree-sitter-bash` exposes enough structure for `nah-actions` to lower Bash
without a fallback shell tokenizer. Whether and how explicit Bash interpreter
payloads are parsed recursively is deferred to P5; this spike claims no
evidence for that behavior. This is not production `nah-parse` code and is
intentionally outside the root Cargo workspace.

This spike selected the production parser. Its syntax and normalization tests
remain useful and self-contained, but the root workspace tests are the current
production verification. Run the standalone harness with:

```sh
cargo test --manifest-path spikes/p2-tree-sitter/Cargo.toml --locked
```

`judgments.json` is a spike-only sidecar. Its legacy `corpus_id` fields retain
unique provenance links to the retired corpus; supplemental adversarial cases
stay here rather than extending the production corpus schema.

The spike passes only when Bash syntax acceptance agrees, every expected
semantic structure matches exactly, and malformed input remains incomplete
even when tree-sitter exposes useful recovered fragments.

This selects the parser, not this normalizer. Production lowering must consume
every execution-relevant node and account for every non-trivia source byte by
attributing it to a lowered construct or an explicitly unsupported construct.
This source-byte coverage guards against omitted-token divergence even when the
tree is clean. Anything unaccounted for or not understood must produce
`Partial`.
