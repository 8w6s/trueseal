import click
import json
from pathlib import Path
from ..crypto.keygen import KeyGenerator
from ..ui.styling import console, InteractivePrompts
from rich.panel import Panel
@click.command()
@click.argument('key_input')
@click.pass_context
def cmd(ctx, key_input):
    """Mark a TrueSeal key as locally revoked.
    
    WARNING: This only prevents the key from being used on THIS specific machine.
    If your key file was stolen, the attacker can still use it elsewhere.
    To truly secure your data after a key compromise, you MUST rotate your keys 
    by decrypting and re-encrypting your vault with a new key.
    
    Examples:
      trueseal revoke 5e526375
      trueseal revoke mykey.tskey
    """
    quiet = ctx.obj.get('quiet', False)
    
    try:
        path = Path(key_input)
        key_obj = None
        password = None
        if path.exists() and path.is_file():
            try:
                key_obj = KeyGenerator.load_from_file(path)
            except ValueError as e:
                if "password-protected" in str(e):
                    password = InteractivePrompts.ask_text("Key is password protected. Enter password", password=True)
                    key_obj = KeyGenerator.load_from_file(path, password=password)
                else:
                    raise click.ClickException(f"Failed to read key file: {e}")
            
            key_id = key_obj.key_id
        else:
            key_id = key_input
            
        revocation_dir = Path.home() / '.trueseal'
        revocation_dir.mkdir(parents=True, exist_ok=True)
        
        revocation_list = revocation_dir / 'revoked_keys.json'
        revoked = []
        
        if revocation_list.exists():
            try:
                with open(revocation_list, 'r') as f:
                    revoked = json.load(f)
            except json.JSONDecodeError:
                revoked = []
                
        key_id_str = str(key_id)
        if key_id_str not in revoked:
            revoked.append(key_id_str)
            with open(revocation_list, 'w') as f:
                json.dump(revoked, f, indent=2)
            revocation_list.chmod(0o600)
            
            if key_obj is not None:
                key_obj.revoked = True
                KeyGenerator.save_to_file(key_obj, str(path), password=password)
                
            if not quiet:
                console.print(Panel(
                    f"[bold red]Key marked as LOCALLY revoked[/bold red]\n"
                    f"[bold cyan]Key ID:[/bold cyan] [yellow]{key_id}[/yellow]\n\n"
                    f"[yellow]WARNING: This does NOT protect already stolen vault files.[/yellow]\n"
                    f"[yellow]Please rotate your vault keys immediately if this key was compromised.[/yellow]",
                    title="[bold red]TrueSeal Local Revocation System[/bold red]",
                    expand=False, border_style="red"
                ))
        else:
            if not quiet:
                console.print(f"[bold yellow]Key {key_id} is already in the revocation list.[/bold yellow]")
                
    except click.ClickException:
        raise
    except Exception as e:
        console.print(f"[bold red]Revoke operation failed:[/bold red] {e}")
        raise click.ClickException(f"Revoke failed: {e}") from e
