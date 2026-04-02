import click
from pathlib import Path
from ..vault.seal import SealOperation, MFARequiredError
from ..ui.styling import UIStyle, console, InteractivePrompts, TrueSealSpinner


def _load_target_lines(file_path):
    if not file_path:
        return []
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        raise click.ClickException(f"Targets file not found: {file_path}")
    return [line.strip() for line in path_obj.read_text(encoding='utf-8').splitlines() if line.strip()]

@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('-k', '--key', required=True, help='Key file path (required), use "-" to read from stdin')
@click.option('-o', '--out', help='Output file path (.vault)')
@click.option('--scope', type=click.Choice(['file', 'group', 'project', 'auto']), 
              default='auto', help='Scope mode')
@click.option('-e', '--exclude', multiple=True, help='Exclude patterns')
@click.option('--compression', type=click.Choice(['none', 'gzip', 'brotli']), 
              default='gzip', help='Compression method')
@click.option('--verify', is_flag=True, help='Verify integrity after seal')
@click.option('--dry-run', is_flag=True, help='Simulate without creating files')
@click.option('--wipe', is_flag=True, help='Securely delete source files after sealing')
@click.option('-y', '--yes', is_flag=True, help='Skip confirmation prompt for destructive actions')
@click.option('--targets-file', type=click.Path(exists=True, dir_okay=False), help='Optional file list for incremental sealing')
@click.option('--remove-targets-file', type=click.Path(exists=True, dir_okay=False), help='Optional removed file list for incremental sealing')
@click.option('--base-vault', type=click.Path(exists=True, dir_okay=False), help='Existing vault used as merge base for incremental sealing')
@click.pass_context
def cmd(ctx, path, key, out, scope, exclude, compression, verify, dry_run, wipe, yes, targets_file, remove_targets_file, base_vault):
    """Encrypt files or project into a sealed vault.
    
    Examples:
      trueseal seal ./config.toml --key app.tskey
      trueseal seal ./my-project --key prod.tskey --scope group
      trueseal seal . --key app.tskey --exclude "*.log" --exclude ".git/**"
    """
    quiet = ctx.obj.get('quiet', False)
    
    # 1. Fail-Fast validity checks
    if key != '-':
        key_path = Path(key)
        if not key_path.exists() and not key_path.suffix:
            inferred_key_path = key_path.with_suffix('.tskey')
            if inferred_key_path.exists():
                key = str(inferred_key_path)
                key_path = inferred_key_path
        if not key_path.exists():
            raise click.ClickException(f"Key file not found: {key}")

    # 2. Safety lock for --wipe
    if wipe and not yes:
        if not click.confirm("Are you sure you want to securely wipe the original source files after sealing?", default=False):
            UIStyle.warning("Operation cancelled.")
            return

    try:
        output = out or f"{path}.vault"
        explicit_targets = _load_target_lines(targets_file)
        remove_targets = _load_target_lines(remove_targets_file)

        if (explicit_targets or remove_targets) and not base_vault:
            base_candidate = Path(output)
            if base_candidate.exists() and base_candidate.is_file():
                base_vault = str(base_candidate)

        if not quiet:
            UIStyle.info(f"Sealing: {path}")
            console.print(f"   [{UIStyle.MUTED}]Key:[/{UIStyle.MUTED}] {key}")
            console.print(f"   [{UIStyle.MUTED}]Output:[/{UIStyle.MUTED}] {output}")
            console.print(f"   [{UIStyle.MUTED}]Scope:[/{UIStyle.MUTED}] {scope}")
            if explicit_targets or remove_targets:
                console.print(f"   [{UIStyle.MUTED}]Mode:[/{UIStyle.MUTED}] Incremental")

        # Use elegant spinner
        spinner = None
        if not quiet:
            spinner = TrueSealSpinner(text=f"Sealing {path}...")
            spinner.__enter__()
        
        def progress(msg, pct):
            if spinner and not quiet:
                spinner.update(f"{msg} [{pct*100:.0f}%]")

        sealer = SealOperation(
            key_path=key,
            root_path=path,
            output_path=output,
            scope=scope,
            exclude=list(exclude),
            compression=compression,
            verify=verify,
            scrub=wipe,
            dry_run=dry_run,
            explicit_targets=explicit_targets,
            remove_targets=remove_targets,
            base_vault_path=base_vault,
        )
        
        try:
            result = sealer.execute(progress_callback=progress)
        except MFARequiredError:
            if spinner:
                spinner.__exit__(None, None, None)
                
            UIStyle.warning("MFA Required for this key.")
                
            attempts = 0
            while attempts < 3:
                mfa_password = InteractivePrompts.ask_text("Enter your MFA file password", password=True)
                mfa_code = InteractivePrompts.ask_text("Enter MFA Code or Recovery Code")
                try:
                    if spinner:
                        spinner.__enter__()
                    result = sealer.execute(progress_callback=progress, mfa_password=mfa_password, mfa_code=mfa_code)
                    break
                except Exception as e:
                    if spinner:
                        spinner.__exit__(None, None, None)
                    attempts += 1
                    if attempts >= 3:
                        raise click.ClickException("MFA authentication failed after 3 attempts.")
                    console.print(f"[bold red]MFA Error:[/bold red] {e}. Please try again.")
        
        if spinner:
            spinner.__exit__(None, None, None)
            
        if not quiet:
            UIStyle.success(f"Vault sealed successfully!")
            console.print(f"   [{UIStyle.MUTED}]Files:[/{UIStyle.MUTED}] {result['files']}")
            console.print(f"   [{UIStyle.MUTED}]Size:[/{UIStyle.MUTED}] {result['size']:,} bytes")
            console.print(f"   [{UIStyle.MUTED}]Vault:[/{UIStyle.MUTED}] {result['vault']}")
            if wipe:
                console.print(f"   [{UIStyle.WARNING}]Wiped:[/{UIStyle.WARNING}] Original source files have been securely deleted.")
    
    except (FileNotFoundError, PermissionError, ValueError) as e:
        if 'spinner' in locals() and spinner:
            spinner.__exit__(None, None, None)
        raise click.ClickException(f"Seal failed: {e}")
