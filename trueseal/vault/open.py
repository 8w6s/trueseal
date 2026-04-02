import os
import gzip
import hmac
from pathlib import Path
from .vault import AegisContainer
from ..crypto.cipher import initialize_authenticated_cipher
from ..crypto.keygen import KeyGenerator
from ..crypto.mfa import TOTPManager


class MFARequiredError(Exception):
    pass


class AegisShatterOperation:
    def __init__(self, vault_path, key_path, output_dir, verify=False, force=False):
        self.vault_path = vault_path
        self.key_path = key_path
        self.output_dir = Path(output_dir)
        self.verify = verify
        self.force = force

    def _resolve_output_path(self, stored_filename):
        normalized = Path(stored_filename.replace('\\', '/'))
        target_path = (self.output_dir / normalized).resolve()
        output_root = self.output_dir.resolve()
        if target_path != output_root and output_root not in target_path.parents:
            raise ValueError(f"Unsafe path in vault segment: {stored_filename}")
        return target_path

    def _decompress_segment(self, compressed_data, compression):
        if compression == 'none':
            return compressed_data
        if compression == 'gzip':
            return gzip.decompress(compressed_data)
        if compression == 'brotli':
            try:
                import brotli
            except ImportError as exc:
                raise ValueError("Vault uses brotli compression but 'brotli' is not installed.") from exc
            return brotli.decompress(compressed_data)
        raise ValueError(f"Unsupported compression format: {compression}")

    def execute(self, progress_callback=None, mfa_password=None, mfa_code=None):
        if progress_callback:
            progress_callback("Analyzing Aegis cipher", 0.1)

        from ..utils.helpers import SecureKeyContext

        with SecureKeyContext(KeyGenerator.load_from_file(self.key_path, password=mfa_password)) as key:
            KeyGenerator.assert_key_usable(key)
            TOTPManager.verify_key_file_mfa(self.key_path, key.key_material.hex(), mfa_code)

            with open(self.vault_path, 'rb') as vault_file:
                encrypted_data = vault_file.read()

            if progress_callback:
                progress_callback("Shattering encryption shield", 0.3)

            cipher = initialize_authenticated_cipher(key.algorithm, key.key_material)

            from ..crypto.cipher import AuthenticatedCipherError
            try:
                raw_payload = cipher.decrypt(encrypted_data)
            except AuthenticatedCipherError:
                # Deniable Duress extraction: mathematically try the halves if padded
                if len(encrypted_data) % 2 == 0:
                    half = len(encrypted_data) // 2
                    try:
                        raw_payload = cipher.decrypt(encrypted_data[:half])
                    except AuthenticatedCipherError:
                        try:
                            raw_payload = cipher.decrypt(encrypted_data[half:])
                        except AuthenticatedCipherError:
                            raise ValueError("Vault integrity verification failed (HMAC mismatch / invalid key).")
                else:
                    raise ValueError("Vault integrity verification failed (HMAC mismatch / invalid key).")

            aegis = AegisContainer.deserialize(raw_payload)

            if self.verify:
                expected_hmac = aegis.sign_aegis_hmac(key.key_material)
                if not hmac.compare_digest(expected_hmac, aegis.hmac_value):
                    raise ValueError("Vault integrity verification failed (HMAC mismatch).")
                # Integrity is natively verified during cipher.decrypt() via AEAD (GCM/Poly1305).

        self.output_dir.mkdir(parents=True, exist_ok=True)
        total_files = len(aegis.segments)

        for index, segment in enumerate(aegis.segments):
            output_path = self._resolve_output_path(segment['filename'])
            output_path.parent.mkdir(parents=True, exist_ok=True)

            payload = self._decompress_segment(segment['data'], aegis.compression)
            if output_path.exists() and not self.force:
                continue

            with open(output_path, 'wb') as output_file:
                output_file.write(payload)
            os.chmod(output_path, segment['permissions'])

            # Mask dangerous bits (Setuid, Setgid, Sticky) for security
            safe_permissions = segment['permissions'] & 0o777
            os.chmod(output_path, safe_permissions)

            if progress_callback:
                progress_callback(f"Extracting {segment['filename']}", 0.6 + (0.4 * (index / max(1, total_files))))

        if progress_callback:
            progress_callback("Decryption Complete", 1.0)

        return {'status': 'success', 'files': total_files, 'out_dir': str(self.output_dir)}


OpenOperation = AegisShatterOperation
