# Contributing to GDPRLint

Thanks for your interest in contributing. GDPRLint is a **local-first,
deterministic-by-default** technical guardrail: it must stay free of hard
dependencies on any single coding agent and never send code or findings to
external services.

## Development setup

Requires Python ≥ 3.10 and Git.

```bash
git clone https://github.com/pablorivast/GDPRLint.git
cd GDPRLint
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

Run these before every PR (CI runs the same ones):

```bash
ruff check .        # lint
mypy                # type check (src/)
pytest              # tests + coverage (fails below 78%)
pytest -m "not laya_e2e"   # skip tests that load real model weights
pytest -m laya_e2e          # optional: run against the real Laya checkpoint
```

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new user-facing behaviour
- `fix:` bug fix
- `docs:` documentation only
- `refactor:` code change without behaviour change
- `test:`, `chore:`, `ci:` as appropriate

A `!` after the type (`refactor!:`) marks a breaking change.

## Adding a rule

1. Add the pattern and a stable rule id in `src/gdprlint/scanners/`
   (`secrets.py`, `pii.py` or `security.py`). Id shape: `SECRET.*`,
   `PII.*`, `SECURITY.*`.
2. Attach `related_articles` only as **contextual** tags — never as legal
   claims.
3. Add **positive and false-positive** tests under `tests/`.
4. Keep evidence **redacted** via `gdprlint.redact` — full secrets must never
   reach output, reports or logs.

## Reporting a false positive

Open an issue with:

- The rule id and the (redacted!) line that triggered it
- The file type / context (test fixture, docs, generated file, …)
- Your `.gdprlint.json` overrides, if any

## Pull requests

- Keep the project local-first, deterministic by default and agent-agnostic.
- Tests are required for behaviour changes; bug fixes need a regression test.
- Docs (`README.md`, `CHANGELOG.md`) should be updated in the same PR.
- Expect review focused on false-positive risk and redaction guarantees.

## License

By contributing you agree that your contributions are licensed under
Apache-2.0, the same license as the project.
