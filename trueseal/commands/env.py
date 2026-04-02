import os
import platform
import shutil
import subprocess
import shlex
from pathlib import Path

import click

from ..ui.styling import UIStyle

MANAGED_BLOCK_START = "# >>> TrueSeal managed key path >>>"
MANAGED_BLOCK_END = "# <<< TrueSeal managed key path <<<"


def _resolve_key_path(key_value: str | None, repo_path: Path) -> Path:
    if key_value:
        key_path = Path(key_value).expanduser()
        if not key_path.is_absolute():
            key_path = (repo_path / key_path).resolve()
        if not key_path.exists() or not key_path.is_file():
            raise click.ClickException(f"Key file not found: {key_path}")
        return key_path

    discovered = sorted(repo_path.glob("*.tskey"))
    if len(discovered) == 1:
        return discovered[0].resolve()
    if len(discovered) == 0:
        raise click.ClickException(
            "No .tskey file found. Provide one with --key or run `trueseal keygen` first."
        )
    raise click.ClickException(
        "Multiple .tskey files found. Please specify one explicitly with --key."
    )


def _upsert_managed_block(profile_path: Path, key_path: Path, shell_type: str) -> None:
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    existing = profile_path.read_text(encoding="utf-8") if profile_path.exists() else ""

    if shell_type == "powershell":
        safe_key_path = str(key_path).replace('"', '`"')
        managed_body = (
            f"{MANAGED_BLOCK_START}\n"
            f"$env:TRUESEAL_KEY_PATH = \"{safe_key_path}\"\n"
            f"{MANAGED_BLOCK_END}\n"
        )
    else:
        safe_key_path = shlex.quote(str(key_path))
        managed_body = (
            f"{MANAGED_BLOCK_START}\n"
            f"export TRUESEAL_KEY_PATH={safe_key_path}\n"
            f"{MANAGED_BLOCK_END}\n"
        )

    start_idx = existing.find(MANAGED_BLOCK_START)
    end_idx = existing.find(MANAGED_BLOCK_END)

    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        end_idx += len(MANAGED_BLOCK_END)
        new_content = existing[:start_idx].rstrip() + "\n\n" + managed_body + existing[end_idx:].lstrip("\n")
    else:
        base = existing.rstrip()
        if base:
            base += "\n\n"
        new_content = base + managed_body

    profile_path.write_text(new_content, encoding="utf-8", newline="\n")


def _configure_windows_env(key_path: Path) -> list[str]:
    updated_targets: list[str] = []

    if len(str(key_path)) > 1024:
        raise click.ClickException("Path to key is too long for Windows setx (max 1024 chars).")

    setx_result = subprocess.run(
        ["setx", "TRUESEAL_KEY_PATH", str(key_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if setx_result.returncode != 0:
        stderr = (setx_result.stderr or "").strip()
        stdout = (setx_result.stdout or "").strip()
        detail = stderr or stdout or "Unknown setx error"
        raise click.ClickException(f"Failed to persist TRUESEAL_KEY_PATH via setx: {detail}")
    updated_targets.append("Windows user environment (setx)")

    home = Path.home()
    profile_candidates = [
        home / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",
        home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
    ]
    for profile in profile_candidates:
        _upsert_managed_block(profile, key_path, "powershell")
    updated_targets.append("PowerShell profile (WindowsPowerShell + PowerShell)")

    return updated_targets


def _configure_posix_env(key_path: Path) -> list[str]:
    shell = os.environ.get("SHELL", "")
    home = Path.home()

    if shell.endswith("zsh"):
        target = home / ".zshrc"
    elif shell.endswith("bash"):
        target = home / ".bashrc"
    else:
        target = home / ".profile"

    _upsert_managed_block(target, key_path, "posix")
    return [str(target)]


def _hook_status(repo_path: Path) -> dict[str, bool]:
    hooks_dir = repo_path / ".git" / "hooks"
    return {
        "pre-commit": (hooks_dir / "pre-commit").exists(),
        "post-checkout": (hooks_dir / "post-checkout").exists(),
    }


@click.command()
@click.argument("action", type=click.Choice(["init", "status", "doctor", "path-init"]))
@click.option("--repo", default=".", help="Repository root for key discovery and hook checks")
@click.option("--key", help="Key file path (.tskey). If omitted, auto-discover in --repo")
@click.option("--dry-run", is_flag=True, help="Preview environment updates without writing changes")
@click.pass_context
def cmd(ctx, action, repo, key, dry_run):
    """Manage environment setup for TrueSeal Git workflows."""
    quiet = ctx.obj.get("quiet", False)

    repo_path = Path(repo).expanduser().resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise click.ClickException(f"Invalid repository path: {repo_path}")

    normalized_action = "init" if action == "path-init" else action

    if normalized_action == "init":
        key_path = _resolve_key_path(key, repo_path)
        system_name = platform.system().lower()

        if not quiet:
            UIStyle.header("Initializing TrueSeal environment")
            UIStyle.info(f"Detected OS: {platform.system()}")
            UIStyle.info(f"Resolved key path: {key_path}")
            if dry_run:
                UIStyle.warning("Dry-run mode enabled. No files or environment variables will be changed.")

        if dry_run:
            if system_name == "windows":
                UIStyle.info("Would update Windows user environment variable via setx")
                UIStyle.info("Would update PowerShell profiles in Documents/WindowsPowerShell and Documents/PowerShell")
            else:
                UIStyle.info("Would update shell profile export block for TRUESEAL_KEY_PATH")
            return

        if system_name == "windows":
            updated_targets = _configure_windows_env(key_path)
        else:
            updated_targets = _configure_posix_env(key_path)

        if not quiet:
            for target in updated_targets:
                UIStyle.success(f"Updated: {target}")
            UIStyle.panel_info(
                "Next Step",
                "Restart your terminal session, then run `trueseal git init --repo .` inside your repository.",
            )
        return

    env_key = os.environ.get("TRUESEAL_KEY_PATH")

    if normalized_action == "status":
        if not quiet:
            UIStyle.header("TrueSeal environment status")

        if env_key:
            exists = Path(env_key).expanduser().exists()
            if exists:
                UIStyle.success(f"TRUESEAL_KEY_PATH set and reachable: {env_key}")
            else:
                UIStyle.warning(f"TRUESEAL_KEY_PATH is set but file does not exist: {env_key}")
        else:
            UIStyle.warning("TRUESEAL_KEY_PATH is not set in current session")

        hooks = _hook_status(repo_path)
        for hook_name, is_present in hooks.items():
            if is_present:
                UIStyle.success(f"Hook installed: {hook_name}")
            else:
                UIStyle.warning(f"Hook missing: {hook_name}")
        return

    if not quiet:
        UIStyle.header("TrueSeal environment doctor")

    git_available = shutil.which("git") is not None
    trueseal_available = shutil.which("trueseal") is not None

    if git_available:
        UIStyle.success("Git binary found in PATH")
    else:
        UIStyle.error("Git binary not found in PATH")

    if trueseal_available:
        UIStyle.success("trueseal command found in PATH")
    else:
        UIStyle.warning("trueseal command not found in PATH (python -m trueseal is still supported)")

    if env_key:
        if Path(env_key).expanduser().exists():
            UIStyle.success("TRUESEAL_KEY_PATH is configured and valid")
        else:
            UIStyle.error(f"TRUESEAL_KEY_PATH points to a missing file: {env_key}")
    else:
        UIStyle.error("TRUESEAL_KEY_PATH is not configured")

    hooks = _hook_status(repo_path)
    if all(hooks.values()):
        UIStyle.success("Git hooks are installed")
    else:
        missing = ", ".join(name for name, ok in hooks.items() if not ok)
        UIStyle.warning(f"Missing hooks: {missing}")
        UIStyle.info("Run `trueseal git init --repo .` to install hooks")

