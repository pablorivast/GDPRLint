"""CLI end-to-end tests (install + scan on a temporary repo)."""

import io
import json
import os
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from gdprlint.cli import main
from tests.conftest import stage_file


def run_cli(args: list[str], cwd: Path) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    old = Path.cwd()
    os.chdir(cwd)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(args)
    finally:
        os.chdir(old)
    return code, out.getvalue(), err.getvalue()


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "gdprlint" in captured.out
    assert "0.2.0" in captured.out


def test_help_when_no_command(capsys):
    code = main([])
    captured = capsys.readouterr()
    assert code == 0
    assert "scan" in captured.out
    assert "install" in captured.out


def test_install_and_scan_clean(git_repo: Path):
    stage_file(git_repo, "app.py", "def hello():\n    return 'world'\n")
    code, out, _err = run_cli(["install"], git_repo)
    assert code == 0
    assert "hook installed" in out.lower() or "already installed" in out.lower()

    code, out, _err = run_cli(["scan"], git_repo)
    assert code == 0
    assert "Commit allowed." in out
    assert "files scanned" in out


def test_scan_blocks_secret(git_repo: Path):
    stage_file(
        git_repo,
        "src/config.js",
        'const key = "sk-proj-abcDEF1234567890xyzXYZ9f2a";\n',
    )
    code, out, _err = run_cli(["scan"], git_repo)
    assert code == 1
    assert "Commit blocked." in out
    # Full secret must never appear
    full = "sk-proj-abcDEF1234567890xyzXYZ9f2a"
    assert full not in out
    assert "GDPRLint" in out
    # Disclaimer present on block path
    assert "does not certify legal or GDPR compliance" in out


def test_scan_outside_git_errors(tmp_path: Path):
    code, _out, err = run_cli(["scan"], tmp_path)
    assert code == 2
    assert "git error" in err.lower() or "not a git" in err.lower()


def test_scan_no_compliant_claim(git_repo: Path):
    stage_file(git_repo, "x.py", "print('ok')\n")
    _code, out, _err = run_cli(["scan"], git_repo)
    lowered = out.lower()
    assert "rgpd compliant" not in lowered
    assert "gdpr compliant" not in lowered
    assert "is compliant" not in lowered


def test_real_git_commit_blocked_by_hook(git_repo: Path):
    """Install hook, stage a secret, ensure git commit fails (rules-only, no model)."""
    # Deterministic e2e: disable the Laya gate so no weights/network are needed
    (git_repo / ".gdprlint.json").write_text('{"laya": {"enabled": false}}', encoding="utf-8")
    code, _out, _err = run_cli(["install"], git_repo)
    assert code == 0

    # 36+ char body after ghp_ → high-confidence SECRET.GITHUB_TOKEN
    stage_file(
        git_repo,
        "leak.js",
        'token = "ghp_1234567890abcdefghij1234567890abcdef";\n',
    )
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    assert hook.is_file()
    env = os.environ.copy()
    # Prefer venv console script so `laya` package imports
    venv_bin = Path(__file__).resolve().parents[1] / ".venv" / "bin"
    env["PATH"] = str(venv_bin) + os.pathsep + env.get("PATH", "")
    src = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        ["sh", str(hook)],
        cwd=str(git_repo),
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=180,
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    combined = proc.stdout + proc.stderr
    full = "ghp_1234567890abcdefghij1234567890abcdef"
    assert full not in combined
    assert "Commit blocked." in combined


def test_scan_format_json(git_repo: Path):
    stage_file(
        git_repo,
        "src/config.js",
        'const key = "sk-proj-abcDEF1234567890xyzXYZ9f2a";\n',
    )
    code, out, _err = run_cli(["scan", "--format", "json"], git_repo)
    assert code == 1
    data = json.loads(out)
    assert data["blocked"] is True
    assert data["exit_code"] == 1
    assert any(f["rule"].startswith("SECRET.") for f in data["findings"])
    full = "sk-proj-abcDEF1234567890xyzXYZ9f2a"
    assert full not in out


def test_scan_format_sarif(git_repo: Path):
    stage_file(git_repo, "app.py", "eval(user_input)\n")
    code, out, _err = run_cli(["scan", "--format", "sarif"], git_repo)
    assert code == 0
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "GDPRLint"


def test_scan_output_writes_file(git_repo: Path, tmp_path: Path):
    stage_file(git_repo, "x.py", "print('ok')\n")
    report = git_repo / "gdprlint-report.json"
    code, out, _err = run_cli(
        ["scan", "--format", "json", "--output", str(report)],
        git_repo,
    )
    assert code == 0
    assert out == ""  # nothing on stdout when writing to a file
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["action"] in {"allow", "allow_warn"}
    assert report.name.startswith("gdprlint-report")


def test_scan_output_unwritable_path_errors(git_repo: Path):
    stage_file(git_repo, "x.py", "print('ok')\n")
    missing_parent = git_repo / "no-such-dir" / "report.json"
    code, _out, err = run_cli(
        ["scan", "--format", "json", "--output", str(missing_parent)],
        git_repo,
    )
    assert code == 2
    assert "cannot write report" in err


def test_install_force_refreshes_managed_block(git_repo: Path):
    code, out, _err = run_cli(["install"], git_repo)
    assert code == 0
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    content = hook.read_text(encoding="utf-8")
    # Simulate a stale managed block from an older version
    stale = content.replace("# GDPRLint pre-commit hook", "# STALE old hook text")
    hook.write_text(stale, encoding="utf-8")

    code, out, _err = run_cli(["install", "--force"], git_repo)
    assert code == 0
    assert "refreshed" in out.lower()
    refreshed = hook.read_text(encoding="utf-8")
    assert "# STALE old hook text" not in refreshed
    assert "# GDPRLint pre-commit hook" in refreshed
    assert refreshed.count("# >>> gdprlint begin (managed) >>>") == 1
