import click
from pathlib import Path
from ..vault.vault import AegisContainer
from ..crypto.keygen import KeyGenerator
from ..crypto.cipher import initialize_authenticated_cipher
from ..vault.duress import DuressManager
from ..ui.styling import UIStyle, console, InteractivePrompts
from rich.table import Table

@click.command()
@click.argument('vault_path', type=click.Path(exists=True))
@click.option('-k', '--key', required=False, type=click.Path(exists=True, dir_okay=False), 
              help='Key file path (auto-discovered if omitted)')
@click.option('--detailed', is_flag=True, help='Show detailed file listing')
@click.pass_context
def cmd(ctx, vault_path, key, detailed):
    """Inspect Vault Metadata

    View vault structure, file list, and integrity without extracting or decrypting files.
    Useful for verifying vault contents before opening.

    Examples:
      trueseal inspect ./project.vault
      trueseal inspect ./project.vault --key app.tskey
    """
    quiet = ctx.obj.get('quiet', False)
    
    try:
        if not quiet:
            UIStyle.header("Inspecting Vault")

        if not key:
            key = InteractivePrompts.auto_discover_key_interactive(quiet)
            if not quiet:
                UIStyle.subheader(f"Using key: {Path(key).name}")
                
        key_obj = KeyGenerator.load_from_file(key)
        KeyGenerator.assert_key_usable(key_obj)
        encrypted_data = DuressManager.extract_vault(vault_path, key_obj)
        
        cipher = initialize_authenticated_cipher(key_obj.algorithm, key_obj.key_material)
        vault_data = cipher.decrypt(encrypted_data)
        
        vault = AegisContainer.deserialize(vault_data)
        
        if not quiet:
            meta_table = Table(title=f"[bold cyan]Vault Information[/bold cyan]", show_header=False)
            meta_table.add_column("Property", style="bold light_green", width=20)
            meta_table.add_column("Value", style="white")

            meta_table.add_row("Vault File:", f"[yellow]{Path(vault_path).name}[/yellow]")
            meta_table.add_row("Format Version:", f"[cyan]v{vault.vsn_major}[/cyan]")
            meta_table.add_row("Algorithm:", f"[light_green]{vault.algorithm}[/light_green]")
            meta_table.add_row("Scope:", f"[magenta]{getattr(vault, 'scope', 'auto')}[/magenta]")

            compression = getattr(vault, 'compression', 'gzip')
            meta_table.add_row("Compression:", f"[cyan]{compression}[/cyan]")

            import hmac
            expected_hmac = vault.sign_aegis_hmac(key_obj.key_material)
            status = "[light_green]VALID[/light_green]" if hmac.compare_digest(expected_hmac, vault.hmac_value) else "[red]TAMPERED[/red]"
            meta_table.add_row("Integrity:", status)

            console.print(meta_table)
            console.print()

            files_table = Table(title="[bold cyan]Encrypted Files[/bold cyan]")
            files_table.add_column("Filename", style="light_green", no_wrap=False)
            files_table.add_column("Stored Size (bytes)", style="yellow", justify="right")
            if detailed:
                files_table.add_column("Permissions", style="magenta", justify="center")
            
            total_size = 0
            file_count = 0
            for seg in vault.segments:
                if detailed:
                    perms = oct(seg.get('permissions', 0o644))[-3:]
                    files_table.add_row(
                        seg['filename'],
                        f"{seg['size']:,}",
                        str(perms)
                    )
                else:
                    files_table.add_row(
                        seg['filename'],
                        f"{seg['size']:,}"
                    )
                total_size += seg['size']
                file_count += 1

            console.print(files_table)

            size_mb = total_size / (1024 * 1024)
            total_size_fmt = f"{total_size:,}"
            size_mb_fmt = f"{size_mb:.2f}"
            summary = (
                f"[light_green]Total Files:[/light_green]  {file_count}\n"
                f"[light_green]Stored Size:[/light_green]  {total_size_fmt} bytes ({size_mb_fmt} MB - Compressed)\n"
                f"[light_green]Status:[/light_green]       Vault is intact"
            )
            UIStyle.panel_info("Summary", summary)

    except click.UsageError as e:
        UIStyle.panel_error("Inspection Failed", str(e))
        raise click.ClickException(str(e))
    except Exception as e:
        UIStyle.panel_error("Inspection Failed", f"Vault verification or decryption error: {e}")
        raise click.ClickException(f"Inspect failed: {e}")
