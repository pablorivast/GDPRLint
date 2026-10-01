# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Use GitHub's private reporting:

**Security tab → Report a vulnerability**:
<https://github.com/pablorivast/GDPRLint/security/advisories/new>

Include the affected version, reproduction steps, impact and (if you have
one) a suggested fix. You should receive an acknowledgement within a few
days; once confirmed we ship a fix and credit reporters who want it.

## Scope

In scope: vulnerabilities in GDPRLint itself — for example code execution
via configuration or the managed Git hook, secret leakage in reports or
logs, or unsafe handling of scanned content.

Out of scope: false positives / false negatives of detection rules (open
a regular issue), and vulnerabilities in dependencies (report upstream;
Dependabot alerts are enabled for this repository).

## Supported versions

Pre-1.0: only the latest release on PyPI and the `main` branch receive
fixes. Older versions are not patched.
