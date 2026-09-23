<p align="center">
  <img src="docs/assets/logo.svg" alt="GDPRLint logo" width="96" height="96"/>
</p>

<h1 align="center">GDPRLint</h1>

<p align="center">
  <strong>Technical privacy and security guardrail for coding agents, enforced at the Git commit boundary.</strong>
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-0.2.0-2563eb"/>
  <img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-green"/>
  <img alt="python" src="https://img.shields.io/badge/python-%E2%89%A53.10-3776ab"/>
  <img alt="tests" src="https://img.shields.io/badge/tests-136%20passing-brightgreen"/>
  <img alt="status" src="https://img.shields.io/badge/status-alpha-orange"/>
  <img alt="local-first" src="https://img.shields.io/badge/local-first-purple"/>
</p>

<p align="center">
  <em>GDPR Lint for the commit boundary — block secrets, PII leaks, and dangerous patterns before they enter history.</em>
</p>

> **GDPRLint is a technical privacy and security guardrail. It does not certify legal or GDPR compliance.**

## Introduction

Coding agents (OpenAI Codex, Claude Code, OpenCode, Cursor, and others) modify repositories at high velocity. GDPRLint inspects **staged Git changes** before they enter history and can **block** commits that introduce secrets, personal data exposures, or basic dangerous code patterns.

```
Coding Agent
    │  modifies files
    ▼
git add .
    │
    ▼
Git staged changes
    │
    ▼
GDPRLint (pre-commit)
    ├── Secrets / credentials
    ├── PII / personal data
    └── Dangerous code patterns
    │  (+ optional Laya local decisor gate)
    ▼
ALLOW / BLOCK
```

## Screenshots

<p align="center">
  <img src="docs/assets/screenshots/scan-output00.png" alt="GDPRLint scan output" width="800"/>
</p>
<p align="center">
  <img src="docs/assets/screenshots/scan-output01.png" alt="GDPRLint blocked commit" width="800"/>
</p>

## Why it exists

- **Agent-agnostic:** the only integration point is **Git**. Any tool that changes a repo can use it.
- **Privacy by design:** analysis runs **locally**. No code, PII, or secrets are sent to external APIs. Reports **redact** sensitive values.
- **Fail safely:** high-confidence secrets block by default; false positives are configurable.
- **Open source:** Apache-2.0, auditable, extensible rules.

## What it detects (v0.2)

| Category | Examples | Default action |
|---|---|---|
| **Secrets** | AWS keys, GitHub/OpenAI/Google/Slack/Stripe tokens, private keys, JWT, connection strings, hardcoded passwords/API keys, **credentials in URL query**, weak compose/env passwords | **block** (high confidence); `SECRET.HARDCODED_WEAK_PW` → **warn** |
| **PII** | email (placeholder domains ignored), phone (context required; lockfiles skipped), IBAN (ES + international), Spanish DNI/NIE, credit cards (Luhn), SSN/NHS/CPF with context, public IPs, MAC, GPS, DOB, license plates, URL/query PII (incl. password/username params), logging PII (real interpolation only), special-category signals | **warn** |
| **Security** | `eval`/`exec`, `os.system`, `shell=True`, `child_process.exec`, `dangerouslySetInnerHTML`, SQL concat, pickle/unsafe YAML, TLS verify off, CORS `*` (`cors()` / `origin: "*"`), weak RNG for secrets, **credential logging**, **password/token in localStorage** | **warn**; `SECURITY.LOG_CREDENTIAL` + `SECURITY.LOCALSTORAGE_SECRET` → **block** |

PII confidence tiers: `possible` · `likely` · `high`. Names are **not** detected (too many false positives).

## Installation

Requires Python ≥ 3.10 and Git.

```bash
git clone <this-repo>
cd gdprlint
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

gdprlint --version
```

> **First Laya load:** the decisor uses local weights from Hugging Face (`pip` dependency `laya`). The first predict may download a checkpoint (~hundreds of MB). If the network or model is unavailable, GDPRLint **falls back to rules-only mode** and still blocks high-confidence secrets.

## Usage

```bash
# In your project repository
gdprlint install    # writes .git/hooks/pre-commit (idempotent)

git add .
git commit -m "my change"
# → GDPRLint runs automatically and may block the commit
```

Manual scan:

```bash
gdprlint scan
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Commit allowed (including warnings-only) |
| `1` | Commit blocked |
| `2` | Usage / config / git error |

`gdprlint uninstall` removes the managed hook block.

## How the Git hook works

`gdprlint install` appends a delimited block to `pre-commit` (creating the file if needed). Existing hooks are preserved. On each commit:

1. `git diff --cached` → only **added lines** staged for commit  
2. Scanners produce **Findings** (evidence already redacted)  
3. Optional **Laya gate** (local System 1 decisor) annotates TP/FP, risk, remediation family  
4. Config resolves `block` / `warn` / `off` → **ALLOW** or **BLOCK**

Directories like `node_modules/` are only touched if you **explicitly staged** files from them.

## Configuration — `.gdprlint.json`

```json
{
  "mode": "block",
  "min_block_confidence": "high",
  "rules": {
    "SECRET.*": "block",
    "SECRET.HARDCODED_WEAK_PW": "warn",
    "PII.*": "warn",
    "PII.SPECIAL_CATEGORY": "block",
    "SECURITY.*": "warn"
  },
  "exclude": ["fixtures/sanitized/**"],
  "exclude_defaults": true,
  "exceptions": [
    { "rule": "PII.EMAIL", "file": "docs/examples.md", "line": 12 }
  ],
  "laya": {
    "enabled": true,
    "min_confidence": 0.7,
    "suppress_fp_below": 0.85,
    "show_gdpr_context": true
  },
  "gdpr_context": "informational"
}
```

- **rules:** glob → `block` | `warn` | `off`  
- **exceptions:** drop a specific finding (`rule` + `file` [+ optional `line`])  
- **exclude:** path globs (added to built-in defaults)  
- **exclude_defaults:** `false` disables built-in lockfile/min.js excludes  
- **laya.enabled:** `false` → rules-only (no model)  
- **gdpr_context:** `off` → hide article references  

Built-in excludes (v0.1.1+): `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `composer.lock`, `*.min.js`, `*.min.css`.

Blocking credential rules (v0.2.0): `SECRET.CREDENTIALS_IN_URL`, `SECURITY.LOG_CREDENTIAL`, `SECURITY.LOCALSTORAGE_SECRET`.

See [`examples/.gdprlint.json`](examples/.gdprlint.json).

## Architecture (prepared for growth)

```
Detector → Finding → LayaAnalyzer (optional gate) → DecisionEngine → ALLOW/BLOCK
                         │
                         └── future: richer risk assessment / explanations
```

- `scanners/` — `SecretScanner`, `PIIScanner`, `SecurityScanner` share one `Finding` schema  
- `analyzer.py` — `LayaAnalyzer` (Router, batched typed questions) or `RulesOnlyAnalyzer`  
- `engine.py` — orchestration + technical decisions (not legal ones)  
- MVP works even if Laya weights cannot load (fail-safe fallback)

## RGPD / GDPR positioning

GDPRLint maps some patterns to **contextual** article tags (e.g. Art. 5(1)(f), 32, 33, 9, 25, 35) as **risk indicators for humans**.

| GDPRLint **does** | GDPRLint **does not** |
|---|---|
| Detect technical exposures in staged code | Certify GDPR/RGPD compliance |
| Recommend remediation | Replace a DPO or legal review |
| Flag “privacy review suggested” signals | Issue DPIAs or notify authorities |
| Redact secrets in output | Send findings to external LLM APIs by default |

**GDPRLint is a technical privacy and security guardrail. It does not certify legal or GDPR compliance.**

## Adding a rule

1. Add a pattern + `rule` id in `src/gdprlint/scanners/*.py`  
2. Attach `related_articles` only as contextual tags  
3. Add positive **and** false-positive tests under `tests/`  
4. Keep evidence **redacted** via `gdprlint.redact`  

Rule ID shape: `SECRET.*` · `PII.*` · `SECURITY.*`.

## Development

```bash
pip install -e ".[dev]"
pytest
pytest -m "not laya_e2e"   # skip tests that load real weights
```

## Limitations

- Pattern-based, line-oriented — **not** a full SAST or data-flow analyzer  
- Special-category and phone/DNI heuristics can false-positive; confidence tiers + exceptions mitigate  
- Laya base checkpoints are not magic: gated by `min_confidence`; uncertain findings become **review flags**, not silent passes  
- Binary staged files are not content-scanned  
- No name detection (deliberate)  
- **Does not** implement multi-jurisdiction privacy law automatically  

## Contributing

Issues and PRs welcome. Keep the project **local-first**, **deterministic by default**, and free of hard dependencies on any single coding agent.

## License

Apache-2.0 — see [LICENSE](LICENSE).
