import click
from pathlib import Path
import json
from ..crypto.keygen import TrueSealKey, KeyGenerator
from ..crypto.shamir import Shamir
from ..ui.styling import UIStyle, console
from rich.panel import Panel
from rich.table import Table

@click.command()
@click.argument('target', type=click.Path(exists=True), required=False)
@click.option('-n', '--parts', type=int, default=5, help='Total number of shares')
@click.option('-t', '--threshold', type=int, default=3, help='Shares needed to restore')
@click.option('-o', '--out', default='./shards/', help='Output directory for shards')
@click.option('--restore', is_flag=True, help='Restore key from shards')
@click.option('--recipients', multiple=True, help='Email recipients for distribution')
@click.option('--distribute', type=click.Choice(['none', 'email', 'aws-ses']), 
              default='none', metavar='[none|email|aws-ses]', help='Auto-distribution method (placeholder)')
@click.pass_context
def cmd(ctx, target, parts, threshold, out, restore, recipients, distribute):
    """Split keys using Shamir's Secret Sharing.
    
    Create M-of-N threshold scheme. Requires minimum threshold shares to restore original key.
    Perfect for distributed key storage and key escrow scenarios.
    
    Examples:
      trueseal shard mykey.tskey --parts 5 --threshold 3 --out ./shards/
      trueseal shard ./shards/ --restore --out recovered.tskey
    """
    quiet = ctx.obj.get('quiet', False)
    
    try:
        if restore:
            _restore_from_shards(ctx, target, quiet)
            return

        if threshold > parts:
            raise click.UsageError("Threshold cannot be greater than the total number of shards!")

        if not quiet:
            panel_content = (f"[bold cyan]Splitting Key:[/bold cyan] [green]{target}[/green]\n"
                             f"[bold cyan]Parts:[/bold cyan] [yellow]{parts}[/yellow]\n"
                             f"[bold cyan]Threshold:[/bold cyan] [magenta]{threshold}[/magenta] (need {threshold}/{parts} to restore)\n"
                             f"[bold cyan]Output:[/bold cyan] [blue]{out}[/blue]")
            console.print(Panel(panel_content, title="[bold cyan]Shamir's Secret Sharing Split[/bold cyan]", expand=False))

        _split_key(target, parts, threshold, out, quiet)

    except (ValueError, FileNotFoundError, PermissionError, click.UsageError) as e:
        console.print(f"[bold red]Shard failed:[/bold red] {e}")
        raise click.ClickException(f"Shard failed: {e}") from e
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        raise click.ClickException(f"System error: {e}") from e

def _split_key(key_path, parts, threshold, output_dir, quiet):
    """Split key into shares"""
    if not key_path:
        raise click.UsageError("Missing target key file to split.")
        
    from ..utils.helpers import SecureKeyContext
    with SecureKeyContext(KeyGenerator.load_from_file(key_path)) as key:
        sss = Shamir(key.key_material, parts=parts, threshold=threshold)
        shares = sss.split()
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        if not quiet:
            shard_table = Table(title="[bold blue]Generated Shards[/bold blue]", box=None)
            shard_table.add_column("Seq", style="dim")
            shard_table.add_column("Filename", style="green")
            
        for share in shares:
            filename = output_path / f"shard-{share['x']:02d}-of-{parts}.tshard"
            
            shard_data = {
                'x': share['x'],
                'y': share['y'],
                'total': share['total'],
                'threshold': share['threshold'],
                'len': share.get('len', 32),
                'key_id': key.key_id,
                'key_algorithm': key.algorithm,
                'created_at': key.created_at.isoformat() if hasattr(key, 'created_at') else None
            }
            
            with open(str(filename), 'w') as f:
                json.dump(shard_data, f, indent=2)
            
            Path(filename).chmod(0o600)
            
            if not quiet:
                shard_table.add_row(f"[{share['x']:02d}]", filename.name)
                
        if not quiet:
            console.print(shard_table)
            res_table = Table(show_header=False, box=None)
            res_table.add_column("Property", style="bold cyan")
            res_table.add_column("Value")
            
            res_table.add_row("Total Shards:", str(parts))
            res_table.add_row("Threshold:", str(threshold))
            res_table.add_row("Location:", str(output_dir))
            
            console.print(Panel(res_table, title="[bold green]Key split successfully[/bold green]", border_style="green", expand=False))

def _restore_from_shards(ctx, shard_dir, quiet):
    """Restore key from shards"""
    import glob
    path = Path(shard_dir) if shard_dir else Path('.')
    
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = list(path.glob('*.tshard'))
    else:
        files = [Path(f) for f in glob.glob(str(shard_dir))]
        
    if not files:
        raise click.ClickException(f"No shard files found at: {shard_dir}")
        
    shares_by_key = {}
    
    for f in files:
        try:
            with open(f, 'r') as fp:
                data = json.load(fp)
                kid = data.get('key_id')
                if kid not in shares_by_key:
                    shares_by_key[kid] = []
                shares_by_key[kid].append(data)
        except (FileNotFoundError, json.JSONDecodeError, IOError) as e:
            if not quiet:
                console.print(f"[yellow]Warning: Could not read {f}: {e}[/yellow]")

    if not shares_by_key:
        raise click.ClickException("Could not load any valid shards.")
        
    # Pick the first key_id that has enough shares
    valid_shares = None
    for kid, shares_list in shares_by_key.items():
        threshold = shares_list[0].get('threshold', len(shares_list))
        if len(shares_list) >= threshold:
            valid_shares = shares_list
            break
            
    if not valid_shares:
        raise click.ClickException("No key has enough shares to meet its threshold for restoration.")
        
    shares = valid_shares
    threshold = shares[0].get('threshold', len(shares))
    metadata = shares[0]
        
    if not quiet:
        console.print(f"[bold cyan]Restoring key from {len(shares)} shards (threshold: {threshold})[/bold cyan]")

    try:
        secret_bytes = Shamir.combine(shares)

        key = TrueSealKey(key_material=secret_bytes, 
                 algorithm=metadata.get('key_algorithm', 'chacha20'))
        
        if 'key_id' in metadata and metadata.get('key_id'):
            key.key_id = metadata['key_id']
        
        if metadata.get('created_at'):
            from datetime import datetime
            key.created_at = datetime.fromisoformat(metadata['created_at'])
                 
        out_path = ctx.params.get('out', 'recovered.tskey')
        if Path(out_path).is_dir() or str(out_path) == './shards/':
            out_path = Path('.') / "recovered.tskey"
            
        KeyGenerator.save_to_file(key, str(out_path))
        
        # Secure memory wipe
        del secret_bytes
        import gc
        gc.collect()
        
        if not quiet:
            console.print(Panel(
                f"[bold green]Key successfully recovered[/bold green]\n"
                f"[bold cyan]Output File:[/bold cyan] [magenta]{out_path}[/magenta]",
                expand=False, border_style="green"
            ))
            
    except (ValueError, KeyError, FileExistsError, IOError) as e:
        console.print(f"[bold red]Restore failed:[/bold red] {e}")
        raise click.ClickException(f"Restore failed: {e}") from e