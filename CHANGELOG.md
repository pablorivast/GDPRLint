# Changelog

All notable changes to GDPRLint are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: the minor version may contain breaking changes).

## [Unreleased]

### Added

- `gdprlint scan --format text|json|sarif` — machine-readable reports:
  - **json**: stable schema `gdprlint/report/v1` with decision, counts, reasons
    and redacted findings (built on `Finding.to_dict()`).
  - **sarif**: SARIF 2.1.0 output compatible with GitHub code scanning.
- `gdprlint scan --output PATH` — write the report to a file instead of stdout.
- `gdprlint install --force` — replace an outdated managed hook block while
  preserving foreign hook content (previously a no-op).
- `ESCALATE_REVIEW` is now emitted in `decision.reasons` when findings need
  human review (previously a dead branch in the engine).
- Real-weights end-to-end test marked `laya_e2e`
  (`pytest -m laya_e2e` / `pytest -m "not laya_e2e"`).
- `CONTRIBUTING.md` and this changelog.

### Changed

- CI: GitHub Actions workflow (Ruff, mypy, pytest on Python 3.10–3.13 with
  coverage fail-under 78%).
- Tooling: Ruff and mypy configured in `pyproject.toml` and enabled as `dev`
  extras; codebase passes both cleanly.
- Pytest now enforces coverage reporting (`--cov` + `--cov-fail-under=78`).
- The hook e2e test disables the Laya gate via test config, so the suite is
  deterministic and needs no model downloads.

### Fixed

- Dead code removed from the engine (empty `escalate` branch, unused imports).
- Minor linter findings across scanners, config, reporting and tests.

## [0.2.0] - 2026-09-23

### Added

- Blocking credential rules: `SECRET.CREDENTIALS_IN_URL`,
  `SECURITY.LOG_CREDENTIAL`, `SECURITY.LOCALSTORAGE_SECRET`.
- Default lockfile/minified excludes (`exclude_defaults`) and exact rule
  action overrides in config.
- Detection matrix and v0.2 documentation.

### Changed

- PII false positives reduced; privacy/review output tightened.
- Hugging Face progress bars and Laya router warnings muted during scans.

## [0.1.0] - 2026-09-23

### Added

- Initial MVP: staged-diff scanners (secrets, PII, security), Laya gate with
  rules-only fallback, pre-commit hook install/uninstall, `.gdprlint.json`
  configuration, redacted text reports.
