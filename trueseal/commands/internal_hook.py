import os
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path

import click

from ..utils.helpers import auto_discover_key


def _ansi(prefix, color_code):
    if os.environ.get("NO_COLOR"):
        return prefix
    return f"\033[{color_code}m{prefix}\033[0m"


def _log_info(message):
    click.echo(f"{_ansi('[TrueSeal][INFO]', '36')} {message}")


def _log_warn(message):
    click.echo(f"{_ansi('[TrueSeal][WARN]', '33')} {message}")


def _log_error(message):
    click.echo(f"{_ansi('[TrueSeal][ERROR]', '31')} {message}", err=True)


def _run_command(args, cwd):
    return subprocess.run(args, cwd=str(cwd), check=False)


def _resolve_trueseal_runner():
    if shutil.which("trueseal"):
        return ["trueseal"]
    return [sys.executable, "-m", "trueseal"]


def _resolve_key_path(repo_path, allow_missing=False):
    key_from_env = os.environ.get("TRUESEAL_KEY_PATH")
    if key_from_env:
        env_key_path = Path(key_from_env).expanduser()
        if not env_key_path.is_absolute():
            env_key_path = (repo_path / env_key_path).resolve()
        if env_key_path.exists() and env_key_path.is_file():
            return str(env_key_path)
        if allow_missing:
            _log_warn(f"Configured key path does not exist: {env_key_path}")
            return None
        raise click.ClickException(
            f"TRUESEAL_KEY_PATH points to a missing file: {env_key_path}"
        )

    try:
        return auto_discover_key(str(repo_path))
    except (FileNotFoundError, ValueError) as e:
        if allow_missing:
            _log_warn("TRUESEAL_KEY_PATH is not set and no valid .tskey file was auto-discovered.")
            return None
        raise click.ClickException(
            f"Key auto-discovery failed: {e}. Please export TRUESEAL_KEY_PATH before committing."
        )


def _collect_staged_paths(repo_path):
    changed = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        check=False,
    )
    removed = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=D"],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        check=False,
    )

    if changed.returncode != 0 or removed.returncode != 0:
        raise click.ClickException("Failed to collect staged file changes from git index.")

    changed_files = [
        line.strip() for line in changed.stdout.splitlines() if line.strip() and line.strip() != ".trueseal.vault"
    ]
    removed_files = [
        line.strip() for line in removed.stdout.splitlines() if line.strip() and line.strip() != ".trueseal.vault"
    ]
    return changed_files, removed_files


def _write_temp_list(values):
    temp_file = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, newline="\n")
    try:
        if values:
            temp_file.write("\n".join(values))
            temp_file.write("\n")
        temp_file.flush()
    finally:
        temp_file.close()
    return temp_file.name


def _run_pre_commit(repo_path):
    key_path = _resolve_key_path(repo_path)
    changed_files, removed_files = _collect_staged_paths(repo_path)

    if not changed_files and not removed_files:
        _log_info("No staged file changes detected for sealing.")
        return 0

    runner = _resolve_trueseal_runner()
    targets_file = _write_temp_list(changed_files)
    removed_file = _write_temp_list(removed_files)

    try:
        _log_info("Securing staged workspace changes before commit...")
        seal_args = runner + [
            "seal",
            ".",
            "--key",
            key_path,
            "--out",
            ".trueseal.vault",
            "--targets-file",
            targets_file,
            "--remove-targets-file",
            removed_file,
            "--base-vault",
            ".trueseal.vault",
        ]
        seal_result = _run_command(seal_args, repo_path)
        if seal_result.returncode != 0:
            _log_error("Workspace encryption failed. Commit aborted.")
            return 1

        add_result = _run_command(["git", "add", "--force", ".trueseal.vault"], repo_path)
        if add_result.returncode != 0:
            _log_error("Failed to stage .trueseal.vault after sealing.")
            return 1

        if changed_files:
            rm_args = ["git", "rm", "--cached", "-r", "--ignore-unmatch", "--quiet"] + changed_files
            rm_result = _run_command(rm_args, repo_path)
            if rm_result.returncode != 0:
                _log_error("Failed to unstage plaintext files after sealing.")
                return 1

        _log_warn("Ensure your .gitignore blocks plaintext files from being committed.")
        return 0
    finally:
        Path(targets_file).unlink(missing_ok=True)
        Path(removed_file).unlink(missing_ok=True)


def _run_post_checkout(repo_path):
    if not (repo_path / ".trueseal.vault").exists():
        return 0

    key_path = _resolve_key_path(repo_path, allow_missing=True)
    if not key_path:
        _log_warn("Skipping auto-decryption because no valid key is available.")
        return 0

    runner = _resolve_trueseal_runner()
    _log_info("Decrypting vault after branch switch...")
    open_result = _run_command(
        runner + ["open", ".trueseal.vault", "--key", key_path, "--out", "."],
        repo_path,
    )
    if open_result.returncode != 0:
        _log_warn(
            "Vault decryption failed or access policy rejected, or uncommitted changes blocked extraction."
        )
    return 0


@click.command(hidden=True)
@click.argument("stage", type=click.Choice(["pre-commit", "post-checkout"]))
@click.option("--repo", default=".", help="Repository path")
def cmd(stage, repo):
    """Internal hook runtime used by generated git hooks."""
    repo_path = Path(repo).resolve()
    if stage == "pre-commit":
        code = _run_pre_commit(repo_path)
    else:
        code = _run_post_checkout(repo_path)

    if code != 0:
        raise SystemExit(code)

