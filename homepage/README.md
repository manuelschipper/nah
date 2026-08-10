# nahguard.ai homepage

A self-contained generated static site. The landing-page fonts, line art,
asciinema player, and TUI recording ship inline; `dist/` also contains the generated
documentation, news, crawler files, install script, og card, and WASM engine.

## Layout

- `fragment.html` — the searchable page source: `<title>`, CSS, markup, and JS.
  Large inline payloads are named markers; `build.py` restores them and wraps
  the fragment in a document head.
- `assets/` — binary-like data URLs and vendored minified JS injected into the
  generated page. These files are excluded from normal repository searches.
- `build.py` — assembles `dist/`: bakes the GitHub issue count using
  `issues.txt` for offline builds, splices
  `nah-tui.cast`, derives the favicons and the og card from the
  hand-lettered word mask embedded in the fragment, renders the compiled
  CLI's built-in guard catalog at `/docs/guards/`, and copies the wasm engine
  when it has been built.
- `record-tui.py` — re-records the TUI demo into `nah-tui.cast` by
  driving `target/release/nah tui` through a PTY with a sandboxed HOME.
- `wasm/` — the "Try it yourself" engine: the real decision pipeline
  (`nah-parse` → `nah-actions` + `nah-inline` → `nah-policy` via `nah-cli`'s
  `decide_with`) compiled to wasm32-wasip1, deciding against a fixed
  synthetic machine with shipped defaults. The page falls back to
  inline regex rules until it loads or where WebAssembly is missing.

## Build & preview

```
cargo build --release --locked -p nah-cli --manifest-path ../Cargo.toml
python3 build.py
cp -r dist/. /home/dev/previews/nah-homepage/   # served on :8090
```

`build.py` intentionally fails if `../target/release/nah` is missing. Set
`NAH_DOCS_BIN` only when testing an explicit alternative compiled binary.

## Rebuilding the wasm engine

Needs a Rust toolchain with the `wasm32-wasip1` std and a wasm-capable
C compiler for tree-sitter. On this machine both live in `~/toolchains`
(isolated rustup at `~/toolchains/rustup`, wasi-sdk 25 at
`~/toolchains/wasi-sdk`), so the workspace's system cargo stays
untouched:

```
cd homepage/wasm
RUSTUP_HOME=$HOME/toolchains/rustup \
PATH=$HOME/toolchains/cargo-wasm/bin:$PATH \
CC_wasm32_wasip1=$HOME/toolchains/wasi-sdk/bin/clang \
AR_wasm32_wasip1=$HOME/toolchains/wasi-sdk/bin/llvm-ar \
cargo build --release --lib --target wasm32-wasip1
```

Then prove it still tells the truth — the native harness runs the same
code and must match `nah test --json` (with built-in defaults) on every
command:

```
cargo build --release --bin harness
./target/release/harness < commands.txt   # one command per line
HOME=$(mktemp -d) nah test --json "<command>"   # compare per command
```

## Editing rules

Copy voice and truthfulness rules live in `.internal/COPY.md`. The short
version: guard names and reason text are never paraphrased — they must
match `nah test --json` output clause-for-clause. Re-diff after any
change to `crates/nah-inline`, `crates/nah-policy`, or the hook messages.
