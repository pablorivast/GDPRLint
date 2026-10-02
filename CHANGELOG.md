# Changelog

All notable changes to GDPRLint are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: the minor version may contain breaking changes).

## [Unreleased]

## [0.3.1] - 2026-10-02

### Changed

- `gdprlint scan --all` no longer requires a git repository: it walks the
  worktree directly (new dependency `pathspec` for gitignore semantics),
  starting at the nearest ancestor containing `.git` or, without one, the
  current directory. Root and nested `.gitignore` files are honored with
  git precedence rules (negations and deeper overrides included).
  Behavior changes: `.git/info/exclude` and global excludes are no longer
  consulted, and tracked files that a `.gitignore` matches are now skipped.
  Output order is now deterministically sorted by path.

## [0.3.0] - 2026-10-01

### Added

- pre-commit framework support: `.pre-commit-hooks.yaml` exposing the
  `gdprlint` hook (`repos:` snippet in the README).
- `SECURITY.md` — private vulnerability reporting via GitHub Security Advisories.
- Release automation: `v*` tags build and verify the package, publish to PyPI
  via trusted publishing (OIDC) and create a GitHub release with artifacts;
  Dependabot keeps Actions and pip dependencies fresh.
- Custom rules: `custom_rules` in `.gdprlint.json` defines project-specific
  regex detections (`id`, `pattern`, optional `flags`/`category`/`action`/
  `severity`/`confidence`/`message`/`remediation`/`articles`). Invalid
  patterns fail at load time (exit 2); evidence is redacted like built-ins;
  `gdprlint list-rules` shows them (text and `custom_rules` in JSON).
- Pluggable scanners: packages contribute via the `gdprlint.scanners`
  entry-point group; broken plugins are reported on stderr and skipped;
  `"plugins": false` disables loading.
- `gdprlint scan --all` — scan every tracked and untracked non-ignored file
  (binary and >1 MiB files are skipped).
- `gdprlint scan --history RANGE` — scan lines added across a git revision
  range (e.g. `main~3..main`); option-like ranges are rejected.
- Reports expose the scan input as `mode` (`staged` | `all` | `history`) in
  JSON and SARIF output.
- `gdprlint init` — write a starter `.gdprlint.json` mirroring the built-in
  defaults (`--force` to overwrite).
- `gdprlint list-rules [--format json]` — catalog of all 64 built-in rules
  with their effective action (schema `gdprlint/rules/v1`), backed by a new
  central registry in `gdprlint.rules` with a scanner-sync test.
- `gdprlint scan --config PATH` — explicit config file instead of
  `./.gdprlint.json`.
- `gdprlint scan --no-laya` — force rules-only mode for a single run.
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

- The package version is single-sourced from `gdprlint.__version__`
  (dynamic in `pyproject.toml`) and packaging metadata follows PEP 639
  (SPDX license expression, `project.urls`); `py.typed` (PEP 561) is
  verified to ship with the wheel.
- CI: GitHub Actions workflow (Ruff, mypy, pytest on Python 3.10–3.13 with
  coverage fail-under 78%).
- Tooling: Ruff and mypy configured in `pyproject.toml` and enabled as `dev`
  extras; codebase passes both cleanly.
- Pytest now enforces coverage reporting (`--cov` + `--cov-fail-under=78`).
- The hook e2e test disables the Laya gate via test config, so the suite is
  deterministic and needs no model downloads.
- `config.py` refactored: `load_config_file()` (explicit paths) and
  `write_config()` extracted from `load_config()`.
- README documents previously undocumented options
  (`laya.device`, `laya.preload`, `laya.flag_special_category`,
  `laya.flag_dpia_signal`, `scan --quiet`).

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
