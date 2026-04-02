import click
from pathlib import Path
from ..vault.duress import DuressManager
from ..crypto.keygen import KeyGenerator
from ..ui.styling import UIStyle, console, TrueSealSpinner

@click.command()
@click.argument('real_vault', type=click.Path(exists=True, dir_okay=False))
@click.argument('duress_vault', type=click.Path(exists=True, dir_okay=False))
@click.option('--duress-key', required=True, type=click.Path(exists=True, dir_okay=False), help='Key for the duress vault')
@click.option('-o', '--out', required=True, type=click.Path(), help='Output combined vault path')
@click.pass_context
def cmd(ctx, real_vault, duress_vault, duress_key, out):
    """Combine two vaults into a duress-protected vault.
    
    Examples:
      trueseal duress real.vault fake.vault --duress-key f.tskey -o safe.vault
    """
    quiet = ctx.obj.get('quiet', False)
    
    try:
        if not quiet:
            UIStyle.info(f"Creating anti-coercion vault...")
            console.print(f"   [{UIStyle.MUTED}]Real vault:[/{UIStyle.MUTED}] {real_vault}")
            console.print(f"   [{UIStyle.MUTED}]Duress vault:[/{UIStyle.MUTED}] {duress_vault}")
            
        duress_k = KeyGenerator.load_from_file(duress_key)
        
        spinner = None
        if not quiet:
            spinner = TrueSealSpinner("Creating duress vault...")
            spinner.__enter__()
        
        try:
            manager = DuressManager(real_vault, duress_vault, duress_k)
            manager.combine_vaults(out)
        finally:
            if spinner:
                spinner.__exit__(None, None, None)
        
        # Set file permissions for the combined vault to prevent unauthorized access
        Path(out).chmod(0o600)
        
        if not quiet:
            UIStyle.success(f"Duress vault created successfully!")
            console.print(f"   [{UIStyle.MUTED}]Open with real key to get real data.[/{UIStyle.MUTED}]")
            console.print(f"   [{UIStyle.MUTED}]Open with duress key to get fake data.[/{UIStyle.MUTED}]")
            console.print(f"   [{UIStyle.MUTED}]Output:[/{UIStyle.MUTED}] {out}")
            
    except Exception as e:
        raise click.ClickException(f"Duress setup failed: {e}")
