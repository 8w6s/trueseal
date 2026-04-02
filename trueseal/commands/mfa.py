import click
import json
from pathlib import Path
from ..crypto.keygen import KeyGenerator
from ..crypto.mfa import TOTPManager
from ..ui.styling import UIStyle, InteractivePrompts, console
from rich.panel import Panel

@click.command()
@click.argument('key_file', type=click.Path(exists=True))
@click.option('--setup', is_flag=True, help='Setup MFA for this key')
@click.option('--verify', help='Verify an OTP code')
@click.pass_context
def cmd(ctx, key_file, setup, verify):
    """Manage Multi-Factor Authentication for keys.
    
    Examples:
      trueseal mfa my.tskey --setup
      trueseal mfa my.tskey --verify 123456
    """
    quiet = ctx.obj.get('quiet', False)
    
    key = KeyGenerator.load_from_file(key_file)
    KeyGenerator.assert_key_usable(key)
    mfa_file = Path(key_file).with_suffix('.mfa')

    if setup:
        mfa_password = key.key_material.hex()
        secret = TOTPManager.generate_totp_secret()
        uri = TOTPManager.generate_provisioning_uri_for_authenticator(secret, account_name=f"TrueSeal-{key.key_id}")
        recovery = TOTPManager.generate_backup_recovery_codes()

        mfa_data = {
            'key_id': key.key_id,
            'totp_secret': secret,
            'recovery_codes': recovery
        }

        encrypted_payload = TOTPManager.encrypt_mfa_data(mfa_data, mfa_password)

        with open(mfa_file, 'w') as f:
            json.dump(encrypted_payload, f, indent=2)

        mfa_file.chmod(0o600)

        if not quiet:
            UIStyle.success(f"MFA Setup initialized for key: {key.key_id}")
            UIStyle.info("Add this to your Authenticator app (Authy/Google/Microsoft).")

            try:
                import qrcode
                qr = qrcode.QRCode()
                qr.add_data(uri)
                console.print("\n[bold cyan]Scan this QR code:[/bold cyan]")
                qr.print_ascii()
            except ImportError:
                console.print(f"\n[bold cyan]Provisioning URI:[/bold cyan] {UIStyle.muted(uri)}")

            UIStyle.warning("WARNING: Please keep this QR code/URI safe, it will never be shown again!")

            console.print(Panel(
                f"[bold magenta]Recovery Codes generated and saved.[/bold magenta]\n\n[dim]View them securely inside {mfa_file.name}[/dim]",
                title="[bold green]MFA Setup Complete[/bold green]",
                border_style="green",
                expand=False
            ))

    elif verify:
        if not mfa_file.exists():
            raise click.ClickException("MFA not set up for this key.")

        mfa_password = key.key_material.hex()
        with open(mfa_file, 'r') as f:
            encrypted_payload = json.load(f)

        try:
            mfa_data = TOTPManager.decrypt_mfa_data(encrypted_payload, mfa_password)
        except Exception:
            raise click.ClickException("Incorrect password or corrupted MFA file.")

        is_valid = TOTPManager.verify_totp_code(mfa_data['totp_secret'], verify)

        if is_valid:
            UIStyle.panel_success("MFA Verification", "MFA Verification SUCCESSFUL.")
        else:
            if verify in mfa_data['recovery_codes']:
                UIStyle.panel_info("MFA Recovery", "Valid Recovery Code. Please use 'trueseal open' to apply it.")
            else:
                raise click.ClickException("Invalid MFA code.")
    else:
        UIStyle.info("Use --setup to initialize MFA or --verify <code> to check.")
