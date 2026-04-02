from datetime import datetime, timedelta, timezone
from pathlib import Path

import click

from ..crypto.keygen import KeyGenerator
from ..ui.styling import InteractivePrompts, UIStyle, console, create_key_info_panel


def _parse_expiration(expire: str | None) -> tuple[dict | None, str]:
    if not expire:
        return None, "Never"

    value = expire.strip().lower()
    if value.endswith("d"):
        days = int(value[:-1])
        return {"days": days}, f"{days} days"
    if value.endswith("h"):
        hours = int(value[:-1])
        return {"hours": hours}, f"{hours} hours"

    moment = datetime.fromisoformat(expire)
    delta = moment.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
    if delta.total_seconds() <= 0:
        return {"days": 0}, "Expired"
    return {"hours": max(1, int(delta.total_seconds() // 3600))}, moment.strftime("%Y-%m-%d")


def _prompt_password(quiet: bool) -> str | None:
    if quiet:
        return None

    if not InteractivePrompts.ask_confirm("Protect key with a password?", default=True):
        return None

    while True:
        password = InteractivePrompts.ask_text("Enter password (minimum 8 characters)", password=True)
        if len(password) < 8:
            UIStyle.error("Password too short.")
            continue

        confirm = InteractivePrompts.ask_text("Confirm password", password=True)
        if password != confirm:
            UIStyle.warning("Passwords do not match.")
            continue

        UIStyle.success("Password accepted")
        return password


@click.command()
@click.argument("out_path", required=False)
@click.option("-a", "--algo", default="chacha20", type=click.Choice(["aes256", "chacha20", "hybrid"]), help="Algorithm")
@click.option("-e", "--expire", help="Expiry duration like 30d, 12h, or 2026-12-31")
@click.option("-l", "--label", help="Human-readable label")
@click.option("-o", "--out", help="Output file path")
@click.option("-s", "--strength", type=click.IntRange(128, 256), default=256, help="Key strength in bits")
@click.option("--format", "output_format", type=click.Choice(["yaml", "json"]), default="yaml", help="Output format")
@click.option("--bind-device", is_flag=True, help="Bind the key to this device")
@click.option("--interactive", "-i", is_flag=True, help="Prompt for values interactively")
@click.pass_context
def cmd(ctx, out_path, algo, expire, label, out, strength, output_format, bind_device, interactive):
    """Generate a new TrueSeal key file."""
    quiet = ctx.obj.get("quiet", False)
    verbose = ctx.obj.get("verbose", False)

    try:
        if strength != 256:
            raise click.ClickException("Current build only supports 256-bit keys.")

        if not quiet:
            UIStyle.header("Generating Encryption Key")

        if interactive and not quiet:
            algo = InteractivePrompts.ask_choice(
                "Select encryption algorithm:",
                ["ChaCha20", "AES-256", "Hybrid"],
                default=0,
            ).strip().lower()
            label = InteractivePrompts.ask_text("Key label (optional)", default=label or "TrueSeal Key")
            bind_device = InteractivePrompts.ask_confirm("Bind to this device?", default=bind_device)

        output_path = out_path or out or "generated.tskey"
        if not Path(output_path).suffix:
            output_path = f"{output_path}.tskey"

        key = KeyGenerator.generate_random_key(algorithm=algo, device_binding=bind_device)

        expiration, expiration_label = _parse_expiration(expire)
        if expiration:
            key.set_expiration(**expiration)

        password = _prompt_password(quiet)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        KeyGenerator.save_to_file(key, output_path, password=password, file_format=output_format)

        if quiet:
            return

        key_info = {
            "Key ID": f"[yellow]{key.key_id[:8]}...{key.key_id[-8:]}[/yellow]",
            "Label": label or key.key_id[:16],
            "Algorithm": f"[light_green]{key.algorithm.upper()}[/light_green]",
            "Strength": f"[cyan]{strength}-bit[/cyan]",
            "Created": key.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "Expires": expiration_label,
            "Device Bound": "[light_green]Yes[/light_green]" if bind_device else "[dim]No[/dim]",
            "Protected": "[light_green]Yes[/light_green]" if password else "[dim]No[/dim]",
        }

        console.print(create_key_info_panel(key_info))
        UIStyle.success(f"Key saved to {output_path}")
        if verbose:
            console.print(f"[dim]Full key ID: {key.key_id}[/dim]")

    except Exception as exc:
        UIStyle.panel_error("Key Generation Failed", str(exc))
        raise

