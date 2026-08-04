# Contributing to nah

Thanks for helping improve nah. Keep changes focused and easy to review.

## Contributor License Agreement

By opening a pull request, you agree to the
[Contributor License Agreement](CLA.md). The CLA confirms that you have the
right to contribute and lets the maintainer keep the project maintainable over
time.

## Development setup

```sh
git clone https://github.com/manuelschipper/nah.git
cd nah
cargo build
cargo install --path crates/nah-cli
```

The toolchain is pinned by `rust-toolchain.toml`.

## Running tests

Run the crate you touched first, then the workspace gates:

```sh
cargo test -p nah-policy   # or whichever crate owns your change
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Use `nah test "..."` when you want to dry-run the decision pipeline on a
command without executing it.

## Pull requests

- Create a branch from `main`.
- Keep changes focused.
- Add or update tests when behavior changes.
- Update docs and `CHANGELOG.md` when user-visible behavior changes.
- Run the relevant tests before submitting.

## Project conventions

- Start from [`docs/architecture.md`](docs/architecture.md); every area has an
  owning module.
- Preserve the dependency direction: ambient I/O stays out of `nah-proto`,
  `nah-parse`, `nah-inline`, `nah-actions`, and `nah-policy`, and the decision
  pipeline is assembled only in `nah-cli`.
- Prefer existing effect and guard patterns over new abstractions.
