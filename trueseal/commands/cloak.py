from pathlib import Path

import click
from rich.panel import Panel

from ..ui.styling import InteractivePrompts, console
from ..vault.stego import Steganographer, SteganographyError


def _confirm_stego_key() -> str:
    while True:
        stego_key = InteractivePrompts.ask_text("Enter Stego Key", password=True)
        confirmation = InteractivePrompts.ask_text("Confirm Stego Key", password=True)
        if stego_key == confirmation:
            return stego_key

        console.print("[bold red]Error:[/bold red] Stego keys do not match. Try again.")


@click.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--cover", type=click.Path(exists=True, dir_okay=False), help="Cover image for steganographic hiding")
@click.option("--extract", is_flag=True, help="Extract hidden vault from image")
@click.option("-o", "--out", required=True, help="Output file path")
@click.option("-k", "--stego-key", help="Password to secure hidden data")
@click.pass_context
def cmd(ctx, input_file, cover, extract, out, stego_key):
    """Hide a vault inside an image or extract it back out."""
    quiet = ctx.obj.get("quiet", False)

    try:
        if extract:
            if not quiet:
                console.print(f"[bold cyan]Extracting hidden data from:[/bold cyan] [yellow]{input_file}[/yellow]")

            key = stego_key or click.prompt("Enter Stego Key", hide_input=True)
            secret_data = Steganographer.extract_from_image(input_file, key)

            out_path = Path(out)
            temp_path = out_path.with_suffix(".extract.tmp")
            temp_path.write_bytes(secret_data)
            temp_path.chmod(0o600)
            temp_path.replace(out_path)

            if not quiet:
                console.print(
                    Panel(
                        f"[green]Extracted {len(secret_data):,} bytes[/green]\n"
                        f"[cyan]Output File: [magenta]{out}[/magenta][/cyan]",
                        title="[bold green]Extraction successful[/bold green]",
                        expand=False,
                        border_style="green",
                    )
                )
            return

        if not cover:
            raise click.ClickException("--cover image required for hiding")

        if not quiet:
            console.print(
                Panel(
                    f"[bold cyan]Vault Data:[/bold cyan] [green]{input_file}[/green]\n"
                    f"[bold cyan]Cover Image:[/bold cyan] [yellow]{cover}[/yellow]",
                    title="[bold magenta]Hiding vault in image (steganography)[/bold magenta]",
                    expand=False,
                )
            )

        key = stego_key or _confirm_stego_key()
        secret_bytes = Path(input_file).read_bytes()
        Steganographer.hide_in_image(cover, secret_bytes, out, key)

        if not quiet:
            console.print(
                Panel(
                    f"[green]Hidden Size:[/green] [yellow]{len(secret_bytes):,} bytes[/yellow]\n"
                    f"[cyan]Output Image:[/cyan] [magenta]{out}[/magenta]",
                    title="[bold green]Vault cloaked successfully[/bold green]",
                    expand=False,
                    border_style="green",
                )
            )
    except SteganographyError as exc:
        console.print(f"[bold red]Steganography error:[/bold red] {exc}")
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        console.print(f"[bold red]Cloak operation failed:[/bold red] {exc}")
        raise click.ClickException(f"Cloak failed: {exc}") from exc
