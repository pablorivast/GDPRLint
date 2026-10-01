"""GDPRLint command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from gdprlint import __version__
from gdprlint.config import (
    CONFIG_FILENAME,
    ConfigError,
    load_config,
    load_config_file,
    write_config,
)
from gdprlint.engine import scan
from gdprlint.git_ops import GitError
from gdprlint.hook import HookError, install_hook, is_installed
from gdprlint.reporting import DIVIDER, render
from gdprlint.rules import CATEGORY_TITLES, RULE_IDS, rules_dict

EXIT_OK = 0
EXIT_BLOCK = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gdprlint",
        description=(
            "Technical privacy and security guardrail for staged Git changes. "
            "Does not certify legal or GDPR compliance."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"gdprlint {__version__}",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser(
        "scan",
        help="scan staged changes (git diff --cached) and block/warn on findings",
    )
    scan_p.add_argument(
        "--format",
        dest="fmt",
        choices=("text", "json", "sarif"),
        default="text",
        help="report format (default: text)",
    )
    scan_p.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="write the report to PATH instead of stdout",
    )
    scan_p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress non-essential text output (ignored for json/sarif)",
    )
    scan_p.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="use an explicit config file instead of ./.gdprlint.json",
    )
    scan_p.add_argument(
        "--no-laya",
        action="store_true",
        help="disable the Laya gate for this run (rules-only mode)",
    )
    mode_group = scan_p.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--all",
        dest="scan_all",
        action="store_true",
        help="scan all non-ignored worktree files (works without git) instead of staged changes",
    )
    mode_group.add_argument(
        "--history",
        metavar="RANGE",
        default=None,
        help="scan lines added across a git revision range (e.g. main~3..main)",
    )

    init_p = sub.add_parser(
        "init",
        help="write a starter .gdprlint.json in the current directory",
    )
    init_p.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing .gdprlint.json",
    )

    rules_p = sub.add_parser(
        "list-rules",
        help="list built-in rules with their effective action",
    )
    rules_p.add_argument(
        "--format",
        dest="fmt",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )

    install_p = sub.add_parser(
        "install",
        help="install the Git pre-commit hook in the current repository",
    )
    install_p.add_argument(
        "--force",
        action="store_true",
        help="replace the managed block even if already installed (keeps foreign hooks)",
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
        if getattr(args, "config", None) is not None:
            cfg = load_config_file(args.config)
        else:
            cfg = load_config(Path.cwd())
    except ConfigError as exc:
        print(f"gdprlint: config error: {exc}", file=err)
        return EXIT_ERROR

    if getattr(args, "no_laya", False):
        cfg.laya.enabled = False

    mode = "staged"
    rev_range = None
    if getattr(args, "scan_all", False):
        mode = "all"
    elif getattr(args, "history", None):
        mode = "history"
        rev_range = args.history

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=r".*invalid temperatures.*")
            decision = scan(Path.cwd(), config=cfg, mode=mode, rev_range=rev_range)
    except GitError as exc:
        print(f"gdprlint: git error: {exc}", file=err)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 — CLI last-resort error handler
        print(f"gdprlint: unexpected error: {type(exc).__name__}: {exc}", file=err)
        return EXIT_ERROR

    fmt = getattr(args, "fmt", "text")
    output: Path | None = getattr(args, "output", None)
    if output is not None:
        try:
            with output.open("w", encoding="utf-8") as fh:
                render(decision, fh, fmt=fmt)
        except OSError as exc:
            print(f"gdprlint: cannot write report to {output}: {exc}", file=err)
            return EXIT_ERROR
        return decision.exit_code

    quiet = getattr(args, "quiet", False) and fmt == "text"
    if quiet and decision.action != "block":
        return decision.exit_code

    render(decision, out, fmt=fmt)
    return decision.exit_code


def cmd_init(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    force = bool(getattr(args, "force", False))
    path = Path.cwd() / CONFIG_FILENAME
    try:
        write_config(path, force=force)
    except ConfigError as exc:
        print(f"gdprlint: {exc}", file=err)
        return EXIT_ERROR

    print("GDPRLint", file=out)
    print(DIVIDER, file=out)
    print(file=out)
    print(f"✓ Wrote {path}", file=out)
    print(file=out)
    print("Next steps:", file=out)
    print("  • edit rules/excludes to fit your project", file=out)
    print("  • gdprlint list-rules   # see all built-in rules", file=out)
    print("  • gdprlint install      # enable the pre-commit hook", file=out)
    return EXIT_OK


def cmd_list_rules(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    try:
        cfg = load_config(Path.cwd())
    except ConfigError as exc:
        print(f"gdprlint: config error: {exc}", file=err)
        return EXIT_ERROR

    fmt = getattr(args, "fmt", "text")
    if fmt == "json":
        json.dump(rules_dict(cfg), out, indent=2, ensure_ascii=False)
        out.write("\n")
        return EXIT_OK

    total = sum(len(ids) for ids in RULE_IDS.values())
    print(f"GDPRLint rules — {total} built-in rules", file=out)
    print(DIVIDER, file=out)
    source = cfg.path if cfg.path else "built-in defaults (no .gdprlint.json found)"
    print(f"Actions as resolved by: {source}", file=out)
    for category in ("secret", "pii", "security"):
        ids = RULE_IDS[category]
        print(file=out)
        print(f"{CATEGORY_TITLES[category]} ({len(ids)})", file=out)
        for rule in ids:
            print(f"  {cfg.action_for_rule(rule):5}  {rule}", file=out)
    if cfg.custom_rules:
        print(file=out)
        print(f"Custom rules ({len(cfg.custom_rules)})", file=out)
        for custom in cfg.custom_rules:
            print(f"  {cfg.action_for_rule(custom.id):5}  {custom.id}", file=out)
    print(file=out)
    print("block = stops the commit · warn = reports only · off = ignored", file=out)
    return EXIT_OK


def cmd_install(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    already = is_installed(Path.cwd())
    force = bool(getattr(args, "force", False))
    try:
        path = install_hook(Path.cwd(), force=force)
    except HookError as exc:
        print(f"gdprlint: {exc}", file=err)
        return EXIT_ERROR
    except GitError as exc:
        print(f"gdprlint: {exc}", file=err)
        return EXIT_ERROR

    print("GDPRLint", file=out)
    print("────────────────────────────────────────", file=out)
    print(file=out)
    if already and not force:
        print(f"✓ Hook already installed: {path}", file=out)
    elif already:
        print(f"✓ Hook refreshed: {path}", file=out)
    else:
        print(f"✓ Pre-commit hook installed: {path}", file=out)
    print(file=out)
    print("Staged commits will run: gdprlint scan", file=out)
    return EXIT_OK


def cmd_uninstall(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from gdprlint.hook import uninstall_hook

    try:
        removed = uninstall_hook(Path.cwd())
    except HookError as exc:
        print(f"gdprlint: {exc}", file=err)
        return EXIT_ERROR

    if removed:
        print("✓ GDPRLint hook removed.", file=out)
    else:
        print("No managed GDPRLint hook found.", file=out)
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
    if args.command == "init":
        return cmd_init(args, out, err)
    if args.command == "list-rules":
        return cmd_list_rules(args, out, err)
    if args.command == "install":
        return cmd_install(args, out, err)
    if args.command == "uninstall":
        return cmd_uninstall(args, out, err)

    parser.print_help(sys.stdout)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
