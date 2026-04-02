import click
from pathlib import Path
from rich.table import Table
from ..vault.vault import AegisContainer
from ..ui.styling import UIStyle, console, InteractivePrompts
from rich.panel import Panel
from ..crypto.keygen import KeyGenerator
from ..crypto.cipher import initialize_authenticated_cipher

@click.command()
@click.argument('vaults', nargs=-1, type=click.Path(exists=True))
@click.option('-k', '--key', required=False, type=click.Path(exists=True, dir_okay=False), 
              help='Project wrapping key (auto-discovered if omitted)')
@click.option('-o', '--out', default='merged_project.vault', help='Output merged vault path')
@click.pass_context
def cmd(ctx, vaults, key, out):
    """Merge multiple vaults into a single project vault.
    
    Combine multiple vaults into a single hierarchical project vault.
    Creates a nested structure with master project key for unified access control.
    
    Note: 'merge' does not decrypt the child vaults. It wraps the raw encrypted 
    bytes of each child vault into a single new master vault file. When you open 
    the resulting merged vault, you will receive the individual embedded .vault 
    files, which must then be opened individually with their respective keys.
    
    Examples:
      trueseal merge app.vault config.vault --key master.tskey --out project.vault
      trueseal merge vault1.vault vault2.vault vault3.vault -o merged.vault
    """
    quiet = ctx.obj.get('quiet', False)
    
    if len(vaults) < 2:
        raise click.ClickException("At least two vaults are required to perform a merge.")
        
    try:
        if not quiet:
            UIStyle.header("Merging Vaults")
            
        if not key:
            key = InteractivePrompts.auto_discover_key_interactive(quiet)
            if not quiet:
                UIStyle.subheader(f"Using key: {Path(key).name}")
                
        master_key = KeyGenerator.load_from_file(key)
        KeyGenerator.assert_key_usable(master_key)
        
        merged_vault = AegisContainer(algorithm=master_key.algorithm, scope='project', compression='none')
        
        table = Table(title="[bold blue]Packaging Child Vaults[/bold blue]", box=None)
        table.add_column("Index", style="dim")
        table.add_column("Vault Path", style="green")
        table.add_column("Size", justify="right", style="yellow")
        
        total_size = 0
        seen_names = set()
        for idx, v_path in enumerate(vaults):
            path = Path(v_path)
            size = path.stat().st_size
            total_size += size
            
            # Obfuscate filename to prevent information disclosure (Metadata Leak)
            base_name = f"vault_segment_{idx+1:03d}.vault"
            
            table.add_row(f"[{idx+1}]", str(path.name), f"{size:,} B")
            
            with open(path, 'rb') as f:
                data = f.read()
                
            merged_vault.forge_payload(base_name, data, path.stat().st_mode)
            
        if not quiet:
            console.print(table)
            
        merged_vault.hmac_value = merged_vault.sign_aegis_hmac(master_key.key_material)
        
        if not quiet:
            console.print("[cyan]Encrypting merged project vault...[/cyan]")
            
        cipher = initialize_authenticated_cipher(master_key.algorithm, master_key.key_material)
        encrypted = cipher.encrypt(merged_vault.serialize())
        
        out_path = Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(encrypted)
            
        out_path.chmod(0o600)
        
        if not quiet:
            result_table = Table(show_header=False, box=None)
            result_table.add_column("Property", style="bold cyan")
            result_table.add_column("Value")
            
            result_table.add_row("Merged Parts:", f"{len(vaults)} Vaults")
            result_table.add_row("Total Size:", f"{len(encrypted):,} bytes")
            result_table.add_row("Output File:", f"[magenta]{out_path}[/magenta]")
            
            console.print(Panel(result_table, title="[bold green]Vaults merged successfully[/bold green]", border_style="green", expand=False))

    except (ValueError, FileNotFoundError, RuntimeError, KeyError) as e:
        console.print(f"[bold red]Merge operation failed:[/bold red] {e}")
        raise click.ClickException(f"Merge failed: {e}") from e
