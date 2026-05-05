# Contributing to nah

Thanks for helping improve nah. Keep changes focused and easy to review.

## Contributor License Agreement

By opening a pull request, you agree to the
[Contributor License Agreement](CLA.md). The CLA confirms that you have the
right to contribute and lets the maintainer keep the project maintainable over
time.

## Development setup

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
pip install -e ".[dev,config,keys]"
```

The core guard should not gain required third-party dependencies. Optional
extras are used for local development, YAML config, and keyring-backed LLM
secrets.

## Running tests

```bash
pytest tests/ --ignore=tests/test_llm_live.py
```

Use `nah test "..."` when you want to dry-run nah's classifier. Do not run nah
itself with `python -m nah`; nah intentionally classifies that pattern as
language execution.

## Pull requests

- Create a branch from `main`.
- Keep changes focused.
- Add or update tests when behavior changes.
- Update docs and the changelog when user-visible behavior changes.
- Run the relevant tests before submitting.

## Project conventions

- Python 3.10+.
- The core hook should stay dependency-light and stdlib-only.
- Avoid silent pass-through. If a fallback is intentional, document why it is
  safe.
- Prefer existing classifier and config patterns over new abstractions.
