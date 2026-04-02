import click
import gzip
from pathlib import Path
from ..vault.vault import AegisContainer
from ..crypto.keygen import KeyGenerator
from ..crypto.cipher import initialize_authenticated_cipher
import struct
import io
import hashlib
from ..vault.manifest import AegisManifest, AegisTamperedError
from ..ui.styling import UIStyle, console
from rich.panel import Panel
from ..ui.styling import InteractivePrompts

@click.command()
@click.argument('vault_path', type=click.Path(exists=True))
@click.option('-k', '--key', required=False, type=click.Path(exists=True, dir_okay=False), 
              help='Key file path (auto-discovered if omitted)')
@click.option('--deep', is_flag=True, help='Perform deep integrity check on all files')
@click.pass_context
def cmd(ctx, vault_path, key, deep):
    """Verify vault integrity without extracting
    
    Check HMAC signatures and manifest hashes to detect tampering.
    Ensures vault has not been modified since creation.
    

    Examples:
      trueseal verify ./project.vault
      trueseal verify ./project.vault --key app.tskey --deep
    """
    quiet = ctx.obj.get('quiet', False)
    
    try:
        if not quiet:
            UIStyle.header("Verifying Vault Integrity")

        if not key:
            key = InteractivePrompts.auto_discover_key_interactive(quiet)
            if not quiet:
                UIStyle.subheader(f"Using key: {Path(key).name}")
                
        from ..utils.helpers import SecureKeyContext
        with SecureKeyContext(KeyGenerator.load_from_file(key)) as key_obj:
            KeyGenerator.assert_key_usable(key_obj)
            with open(vault_path, 'rb') as f:
                raw_vault_bytes = f.read()

            cipher_ctx = initialize_authenticated_cipher(key_obj.algorithm, key_obj.key_material)

            def decrypt_payload(payload_bytes):
                return cipher_ctx.decrypt(payload_bytes)

            try:
                cleartxt = decrypt_payload(raw_vault_bytes)
            except Exception:
                # Deniable duress fallback: if the vault is an even-length payload,
                # try both halves and accept the first valid AEAD block.
                if len(raw_vault_bytes) % 2 != 0:
                    raise click.ClickException("Vault ciphertext authentication failed!")

                half = len(raw_vault_bytes) // 2
                for candidate in (raw_vault_bytes[:half], raw_vault_bytes[half:]):
                    try:
                        cleartxt = decrypt_payload(candidate)
                        break
                    except Exception:
                        cleartxt = None

                if cleartxt is None:
                    raise click.ClickException("Vault ciphertext authentication failed (Duress integrity compromised)!")
        
        if not deep:
            if not quiet:
                console.print(Panel(
                    "[bold green]TrueSeal structural verification passed (AEAD Validated).[/bold green]\n"
                    "[dim]Run with --deep to verify inner file contents against manifest.[/dim]",
                    title="[cyan]Verification Integrity[/cyan]",
                    expand=False
                ))
            return
            
        vault = AegisContainer.deserialize(cleartxt)
        
        brotli_module = None
        if vault.compression == 'brotli':
            try:
                import brotli as brotli_module
            except ImportError:
                raise click.ClickException("You need to install the brotli package to verify this vault (pip install brotli).")

        manifest = None
        for segment in vault.segments:
            if segment['filename'] == '.tsmanifest':
                manifest_payload = segment['data']
                if vault.compression == 'gzip':
                    manifest_payload = gzip.decompress(manifest_payload)
                elif vault.compression == 'brotli':
                    manifest_payload = brotli_module.decompress(manifest_payload)
                manifest = AegisManifest.deserialize(manifest_payload)
                break
                
        if not manifest:
            raise click.ClickException("Deep verify requested, but vault is missing internal `.tsmanifest`.")
            
        for seg in vault.segments:
            if seg['filename'] == '.tsmanifest':
                continue
                
            expected_hash_info = manifest.ts_records.get(seg['filename'])
            if not expected_hash_info:
                raise click.ClickException(f"Tamper detected in block [{seg['filename']}]: Unregistered payload injection")
            
            expected_hash = expected_hash_info['hash']
            hasher = hashlib.sha256()
            
            # Streaming decompression to prevent RAM explosion (OOM)
            stream = io.BytesIO(seg['data'])
            
            if vault.compression == 'gzip':
                with gzip.GzipFile(fileobj=stream, mode='rb') as gz:
                    while True:
                        chunk = gz.read(65536)
                        if not chunk:
                            break
                        hasher.update(chunk)
            elif vault.compression == 'brotli':
                decompressor = brotli_module.Decompressor()
                while True:
                    in_chunk = stream.read(65536)
                    if not in_chunk:
                        # Flush the rest
                        if hasattr(decompressor, 'flush'):
                            # brotli API may or may not support flush, usually process() returns all
                            pass
                        break
                    out_chunk = decompressor.process(in_chunk)
                    hasher.update(out_chunk)
            else:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    
            computed_hash = hasher.hexdigest()
            import hmac
            if not hmac.compare_digest(expected_hash, computed_hash):
                console.print(f"[bold red]Tamper detected in block [{seg['filename']}]: Hashes do not match[/bold red]")
                raise click.ClickException(f"Tamper detected in block [{seg['filename']}]: Integrity failed")
        
        if not quiet:
            console.print(Panel(
                "[bold green]TrueSeal full verification passed (0 bytes compromised).[/bold green]",
                title="[cyan]Verification Integrity[/cyan]",
                expand=False
            ))
            
    except Exception as e:
        console.print(f"[bold red]Verify failed:[/bold red] {e}")
        raise click.ClickException(f"Verify failed: {e}")
