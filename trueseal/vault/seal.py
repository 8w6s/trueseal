from pathlib import Path
from .builder import AegisForge
from .vault import AegisContainer
from ..crypto.cipher import initialize_authenticated_cipher
from ..crypto.keygen import KeyGenerator
from ..crypto.mfa import TOTPManager
from ..utils.helpers import secure_erase


class MFARequiredError(Exception):
    pass


class AegisForgeOperation:
    def __init__(self, key_path, root_path, output_path, scope='auto', exclude=None, compression='gzip', verify=False, scrub=False, dry_run=False, explicit_targets=None, remove_targets=None, base_vault_path=None):
        self.key_path = key_path
        self.root_path = root_path
        self.output_path = output_path
        self.scope = scope
        self.exclude = exclude or []
        self.compression = compression
        self.verify = verify
        self.scrub = scrub
        self.dry_run = dry_run
        self.explicit_targets = explicit_targets or []
        self.remove_targets = remove_targets or []
        self.base_vault_path = base_vault_path

    @staticmethod
    def _normalize_segment_name(raw_path):
        normalized = str(raw_path).replace('\\', '/')
        while normalized.startswith('./'):
            normalized = normalized[2:]
        normalized = normalized.lstrip('/').rstrip('/')
        if not normalized or normalized == '.':
            raise ValueError(f"Invalid segment name: {raw_path}")
        return normalized

    def _load_base_segments(self, key):
        if not self.base_vault_path:
            return {}
        base_path = Path(self.base_vault_path)
        if not base_path.exists() or not base_path.is_file():
            return {}

        with open(base_path, 'rb') as base_fp:
            encrypted_base = base_fp.read()
        cipher = initialize_authenticated_cipher(key.algorithm, key.key_material)
        raw_base = cipher.decrypt(encrypted_base)
        base_vault = AegisContainer.deserialize(raw_base)

        if getattr(base_vault, 'compression', self.compression) != self.compression:
            raise ValueError(
                f"Incremental seal compression mismatch: base uses '{base_vault.compression}', current run uses '{self.compression}'."
            )

        return {
            self._normalize_segment_name(seg['filename']): {
                'filename': self._normalize_segment_name(seg['filename']),
                'data': seg['data'],
                'size': seg['size'],
                'permissions': seg.get('permissions', 0o644),
            }
            for seg in base_vault.segments
        }

    def execute(self, progress_callback=None, mfa_password=None, mfa_code=None):
        if progress_callback:
            progress_callback("Assessing payload", 0.1)

        from ..utils.helpers import SecureKeyContext
        with SecureKeyContext(KeyGenerator.load_from_file(self.key_path, password=mfa_password)) as key:
            KeyGenerator.assert_key_usable(key)
            TOTPManager.verify_key_file_mfa(self.key_path, key.key_material.hex(), mfa_code)

            forge = AegisForge(self.root_path, self.exclude, self.compression, explicit_targets=self.explicit_targets)
            forge.collect_files()

            aegis = AegisContainer(algorithm=key.algorithm, scope=self.scope, compression=self.compression)
            segments_map = self._load_base_segments(key)

            changed_files = len(forge.files)

            for index, file_meta in enumerate(forge.files):
                with open(file_meta['path'], 'rb') as source_file:
                    compressed_data = forge.compress_file(source_file.read())

                normalized_name = self._normalize_segment_name(file_meta['rel_path'])
                segments_map[normalized_name] = {
                    'filename': normalized_name,
                    'data': compressed_data,
                    'size': len(compressed_data),
                    'permissions': file_meta['permissions'],
                }

                if progress_callback:
                    progress_callback(f"Forging {file_meta['rel_path']}", 0.3 + (0.4 * (index / max(1, changed_files))))

            for remove_entry in self.remove_targets:
                segments_map.pop(self._normalize_segment_name(remove_entry), None)

            aegis.segments = [segments_map[name] for name in sorted(segments_map.keys())]

            total_files = len(aegis.segments)
            total_size = sum(seg['size'] for seg in aegis.segments)

            if not self.dry_run:
                aegis.hmac_value = aegis.sign_aegis_hmac(key.key_material)
                raw_payload = aegis.serialize()
                cipher = initialize_authenticated_cipher(key.algorithm, key.key_material)
                encrypted_content = cipher.encrypt(raw_payload)
                with open(self.output_path, 'wb') as output_file:
                    output_file.write(encrypted_content)
                if self.scrub:
                    for file_meta in forge.files:
                        secure_erase(file_meta['path'])

            if progress_callback:
                progress_callback("Sealing Complete", 1.0)

            return {'status': 'success', 'files': total_files, 'size': total_size, 'vault': self.output_path}


SealOperation = AegisForgeOperation
