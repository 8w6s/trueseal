import time
import click
from ..ui.styling import console, UITheme, TrueSealProgress


@click.command()
@click.option('--prb', is_flag=True, help='Show the progress bar animation demo')
def cmd(prb):
    """Demo aesthetic progress bar and UI elements"""
    if not prb:
        console.print(f"[{UITheme.PRIMARY}]TrueSeal UI Demo mode[/{UITheme.PRIMARY}]")
        console.print("Run `demo --prb` inside REPL to view the progress bar animation.")
        return

    console.print(f"\n[{UITheme.PRIMARY}]Starting TrueSeal Vault Encryption Sequence[/{UITheme.PRIMARY}]\n")

    with TrueSealProgress() as progress:
        task = progress.add_task("Analyzing Source Code", total=100)

        for index in range(30):
            time.sleep(0.03)
            progress.update(task, advance=1, description=f"Analyzing Source Code [dim]({index + 1}/30 files)[/dim]")

        progress.update(task, description="Generating Aegis Cipher Keys")
        for _ in range(20):
            time.sleep(0.04)
            progress.update(task, advance=1)

        progress.update(task, description="Forging Aegis Container")
        for _ in range(40):
            time.sleep(0.05)
            progress.update(task, advance=1)

        progress.update(task, description="Sealing Vault")
        for _ in range(10):
            time.sleep(0.06)
            progress.update(task, advance=1)

    console.print(f"\n[{UITheme.ACCENT}]Vault sealed successfully.[/{UITheme.ACCENT}]\n")
