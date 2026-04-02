"""
TrueSeal Git Hook Integration Command

Integrates TrueSeal directly into developer Git workflows. Automatically
seals repository content pre-commit to prevent plaintext source code leaks,
and automatically decrypts vaults post-checkout when switching branches.
"""

import click
import subprocess
import shutil
from pathlib import Path
from ..ui.styling import UIStyle, console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn





@click.command(help="""
[EXPERIMENTAL] Git Hooks Integration for TrueSeal

Automatically seal/unseal vaults during Git workflows.
WARNING: This feature is experimental. You must configure .gitignore 
to prevent plaintext source files from being committed alongside the vault.
""")
@click.argument('action', type=click.Choice(['init', 'status', 'remove']))
@click.option('--repo', default='.', help='Git repository path')
@click.pass_context
def cmd(ctx, action, repo):
    """
    Git Hooks Integration for TrueSeal

    Automatically seal/unseal vaults during Git workflows.

    Actions:
      init   - Setup Git pre-commit and post-checkout hooks
      status - Check hook installation status
      remove - Uninstall hooks from repository

    Examples:
      trueseal git init
      trueseal git status
      trueseal git remove
    """
    quiet = ctx.obj.get('quiet', False)

    repo_path = Path(repo)
    git_hooks_dir = repo_path / '.git' / 'hooks'

    if action == 'init':
        if not quiet:
            UIStyle.warning("[EXPERIMENTAL] TrueSeal Git Hooks")
            UIStyle.info("Preparing repository and installing TrueSeal hooks")

        repo_path.mkdir(parents=True, exist_ok=True)

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}[/cyan]"),
            BarColumn(bar_width=24),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
            transient=False,
            disable=quiet,
        ) as progress:
            task = progress.add_task("Checking Git availability", total=3)

            if shutil.which('git') is None:
                raise click.ClickException("Git is not available in PATH. Please install Git first.")
            progress.update(task, advance=1)

            progress.update(task, description="Ensuring Git repository")
            if not (repo_path / '.git').exists():
                init_result = subprocess.run(
                    ['git', 'init', str(repo_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if init_result.returncode != 0:
                    error_message = init_result.stderr.strip() or init_result.stdout.strip() or "Unknown git init error"
                    raise click.ClickException(f"Failed to initialize git repository: {error_message}")
            progress.update(task, advance=1)

            progress.update(task, description="Creating hook files")
            git_hooks_dir.mkdir(parents=True, exist_ok=True)
            progress.update(task, advance=1)

        pre_commit_hook = git_hooks_dir / 'pre-commit'
        post_checkout_hook = git_hooks_dir / 'post-checkout'

        pre_commit_content = """#!/bin/bash
# TrueSeal pre-commit hook bootstrap.

if command -v trueseal >/dev/null 2>&1; then
  trueseal internal-hook pre-commit --repo .
  exit $?
fi

if command -v python >/dev/null 2>&1; then
  python -m trueseal internal-hook pre-commit --repo .
  exit $?
fi

echo "[TrueSeal][ERROR] Neither 'trueseal' nor 'python' is available in PATH."
exit 127
"""

        post_checkout_content = """#!/bin/bash
# TrueSeal post-checkout hook bootstrap.

if command -v trueseal >/dev/null 2>&1; then
  trueseal internal-hook post-checkout --repo .
  exit $?
fi

if command -v python >/dev/null 2>&1; then
  python -m trueseal internal-hook post-checkout --repo .
  exit $?
fi

echo "[TrueSeal][WARN] Neither 'trueseal' nor 'python' is available in PATH."
exit 0
"""

        with open(pre_commit_hook, 'w', encoding='utf-8', newline='\n') as f:
            f.write(pre_commit_content)
        pre_commit_hook.chmod(0o755)

        with open(post_checkout_hook, 'w', encoding='utf-8', newline='\n') as f:
            f.write(post_checkout_content)
        post_checkout_hook.chmod(0o755)

        if not quiet:
            UIStyle.panel_success(
                "Git hooks installed",
                "[bold cyan]pre-commit:[/bold cyan] Encrypts workspace before commit\n"
                "[bold cyan]post-checkout:[/bold cyan] Decrypts vault after branch switch"
            )

    elif action == 'status':
        pre_commit_exists = (git_hooks_dir / 'pre-commit').exists()
        post_checkout_exists = (git_hooks_dir / 'post-checkout').exists()

        if pre_commit_exists:
            UIStyle.success("[ACTIVE] Pre-commit hook")
        else:
            UIStyle.warning("[INACTIVE] Pre-commit hook")

        if post_checkout_exists:
            UIStyle.success("[ACTIVE] Post-checkout hook")
        else:
            UIStyle.warning("[INACTIVE] Post-checkout hook")

    elif action == 'remove':
        (git_hooks_dir / 'pre-commit').unlink(missing_ok=True)
        (git_hooks_dir / 'post-checkout').unlink(missing_ok=True)
        if not quiet:
            UIStyle.success("Git hooks removed")
