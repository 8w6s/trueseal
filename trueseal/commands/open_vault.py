import click
from pathlib import Path
from ..vault.open import OpenOperation, MFARequiredError
from ..ui.styling import UIStyle, console, InteractivePrompts, TrueSealSpinner


@click.command()
@click.argument('vault_path', type=click.Path(exists=True, dir_okay=False))
@click.option('-k', '--key', required=False, type=click.Path(exists=True, dir_okay=False), help='Key file path')
@click.option('-o', '--out', help='Output directory')
@click.option('--verify', is_flag=True, help='Verify vault integrity')
@click.option('--force', is_flag=True, help='Overwrite existing files')
@click.pass_context
def cmd(ctx, vault_path, key, out, verify, force):
    """Decrypt a sealed vault.

    Examples:
      trueseal open ./project.vault --key app.tskey
      trueseal open ./project.vault --key app.tskey --out ./recovered/
      trueseal open ./project.vault --key app.tskey --verify
    """
    quiet = ctx.obj.get('quiet', False)

    try:
        default_output_dir = f"{Path(vault_path).stem}_extracted"
        output_dir = out or default_output_dir

        if not key:
            key = InteractivePrompts.auto_discover_key_interactive(quiet)

        if not quiet:
            UIStyle.info(f"Opening: {vault_path}")
            console.print(f"   [{UIStyle.MUTED}]Key:[/{UIStyle.MUTED}] {key}")
            console.print(f"   [{UIStyle.MUTED}]Output:[/{UIStyle.MUTED}] {output_dir}")

        spinner = None
        if not quiet:
            spinner = TrueSealSpinner(text=f"Opening vault {vault_path}...")
            spinner.__enter__()

        def progress(message, pct):
            if spinner and not quiet:
                spinner.update(f"{message} [{pct*100:.0f}%]")

        opener = OpenOperation(
            vault_path=vault_path,
            key_path=key,
            output_dir=output_dir,
            verify=verify,
            force=force,
        )

        try:
            result = opener.execute(progress_callback=progress)
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
                    result = opener.execute(progress_callback=progress, mfa_password=mfa_password, mfa_code=mfa_code)
                    break
                except Exception as error:
                    if spinner:
                        spinner.__exit__(None, None, None)
                    attempts += 1
                    if attempts >= 3:
                        raise click.ClickException("MFA authentication failed after 3 attempts.")
                    console.print(f"[bold red]MFA Error:[/bold red] {error}. Please try again.")

        if spinner:
            spinner.__exit__(None, None, None)

        if not quiet:
            if verify:
                UIStyle.success("Vault integrity verified successfully!")
            else:
                UIStyle.success("Vault extracted successfully!")
            console.print(f"   [{UIStyle.MUTED}]Files:[/{UIStyle.MUTED}] {result.get('files', 0)}")
            console.print(f"   [{UIStyle.MUTED}]Location:[/{UIStyle.MUTED}] {result.get('out_dir', output_dir)}")

    except (FileNotFoundError, PermissionError, ValueError, click.Abort, click.UsageError) as error:
        if 'spinner' in locals() and spinner:
            spinner.__exit__(None, None, None)
        raise click.ClickException(str(error))
    except Exception as error:
        if 'spinner' in locals() and spinner:
            spinner.__exit__(None, None, None)
        raise click.ClickException(f"Open failed: {error}")
