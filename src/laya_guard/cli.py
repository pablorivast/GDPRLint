"""Laya Guard command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence, TextIO

from laya_guard import __version__
from laya_guard.config import ConfigError, load_config
from laya_guard.engine import scan
from laya_guard.git_ops import GitError
from laya_guard.hook import HookError, install_hook, is_installed
from laya_guard.reporting import render

EXIT_OK = 0
EXIT_BLOCK = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="laya-guard",
        description=(
            "Technical privacy and security guardrail for staged Git changes. "
            "Does not certify legal or GDPR compliance."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"laya-guard {__version__}",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser(
        "scan",
        help="scan staged changes (git diff --cached) and block/warn on findings",
    )
    scan_p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress non-essential output",
    )

    install_p = sub.add_parser(
        "install",
        help="install the Git pre-commit hook in the current repository",
    )
    install_p.add_argument(
        "--force",
        action="store_true",
        help="re-append managed block even if markers already exist (no-op if present)",
    )

    sub.add_parser("uninstall", help="remove the managed pre-commit block")

    return parser


def cmd_scan(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    import os
    import warnings

    # Mute model download / progress noise for interactive and hook use
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
    os.environ.setdefault("TQDM_DISABLE", "1")
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

    try:
        cfg = load_config(Path.cwd())
    except ConfigError as exc:
        print(f"laya-guard: config error: {exc}", file=err)
        return EXIT_ERROR

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=r".*invalid temperatures.*")
            decision = scan(Path.cwd(), config=cfg)
    except GitError as exc:
        print(f"laya-guard: git error: {exc}", file=err)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        print(f"laya-guard: unexpected error: {type(exc).__name__}: {exc}", file=err)
        return EXIT_ERROR

    if getattr(args, "quiet", False) and decision.action != "block":
        return decision.exit_code

    render(decision, out)
    return decision.exit_code


def cmd_install(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    already = is_installed(Path.cwd())
    try:
        path = install_hook(Path.cwd())
    except HookError as exc:
        print(f"laya-guard: {exc}", file=err)
        return EXIT_ERROR
    except GitError as exc:
        print(f"laya-guard: {exc}", file=err)
        return EXIT_ERROR

    print("Laya Guard", file=out)
    print("────────────────────────────────────────", file=out)
    print(file=out)
    if already:
        print(f"✓ Hook already installed: {path}", file=out)
    else:
        print(f"✓ Pre-commit hook installed: {path}", file=out)
    print(file=out)
    print("Staged commits will run: laya-guard scan", file=out)
    return EXIT_OK


def cmd_uninstall(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from laya_guard.hook import uninstall_hook

    try:
        removed = uninstall_hook(Path.cwd())
    except HookError as exc:
        print(f"laya-guard: {exc}", file=err)
        return EXIT_ERROR

    if removed:
        print("✓ Laya Guard hook removed.", file=out)
    else:
        print("No managed Laya Guard hook found.", file=out)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command is None:
        parser.print_help(sys.stdout)
        return EXIT_OK

    out = sys.stdout
    err = sys.stderr

    if args.command == "scan":
        return cmd_scan(args, out, err)
    if args.command == "install":
        return cmd_install(args, out, err)
    if args.command == "uninstall":
        return cmd_uninstall(args, out, err)

    parser.print_help(sys.stdout)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
