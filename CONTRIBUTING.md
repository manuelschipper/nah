# Contributing to nah

Contributions are welcome! Before submitting a pull request, please review the following.

## Contributor License Agreement

All contributors must agree to the [Contributor License Agreement](CLA.md) before their pull request can be merged. This gives the maintainer the right to relicense future versions of nah (e.g., for a commercial offering) while keeping existing releases under MIT.

By opening a pull request, you confirm that you have read and agree to the CLA.

## Development setup

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
pip install -e ".[dev]"
```

## Running tests

```bash
nah test "pytest"    # classify it first if you have nah installed
pytest               # run the test suite
```

## Pull request guidelines

- Create a feature branch from `main`
- Keep changes focused — one feature or fix per PR
- Add tests for new behavior
- Run `pytest` before submitting
- `main` is protected — all changes require a PR

## Code conventions

- Python 3.10+, zero external dependencies for the core hook (stdlib only)
- No silent pass-through — see CLAUDE.md for error handling policy
- Use `nah test "..."` for testing commands, never `python -m nah`
