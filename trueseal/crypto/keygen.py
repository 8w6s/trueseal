"""
TrueSeal Key Generation Module

Provides cryptographic key generation and management functionality
for TrueSeal encryption operations. Supports password-based key
derivation, device identity binding, and key persistence.
"""

import os
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .cipher import (
    SealAES256GCM,
    SealChaCha20Poly1305,
    AuthenticatedCipherError
)
from .identity import DeviceIdentity
from .zeroize import memzero


class TrueSealKey:
    """
    Represents a TrueSeal encryption key with metadata.

    Attributes:
        key_material (bytes): 32-byte cryptographic key
        key_id (str): Unique identifier for this key
        algorithm (str): Cipher algorithm (aes256, chacha20, hybrid)
        created_at (datetime): Key creation timestamp
        expires_at (datetime): Optional key expiration time
        device_id (str): Hardware device binding identifier
    """

    def __init__(self, key_material, algorithm='chacha20', device_binding=False):
        """
        Initialize a TrueSeal key object.

        Args:
            key_material (bytes): 32-byte cryptographic key material
            algorithm (str): Cipher algorithm name
            device_binding (bool): Whether to bind key to this device
        """
        if len(key_material) != 32:
            raise ValueError("Key material must be exactly 32 bytes")
        
        self.key_material = key_material
        self.key_id = hashlib.sha256(key_material).hexdigest()[:16]
        self.algorithm = algorithm
        self.created_at = datetime.now(timezone.utc)
        self.expires_at = None
        self.device_id = DeviceIdentity.get_hardware_fingerprint().hex() if device_binding else None
        self.revoked = False

    def __del__(self):
        """Securely wipe cryptographic key material from RAM when object is deleted/GC'd."""
        if hasattr(self, 'key_material') and self.key_material:
            memzero(self.key_material)

    def set_expiration(self, days=None, hours=None):
        """
        Set key expiration time.

        Args:
            days (int): Number of days until expiration
            hours (int): Number of hours until expiration
        """
        if days:
            self.expires_at = self.created_at + timedelta(days=days)
        elif hours:
            self.expires_at = self.created_at + timedelta(hours=hours)

    def is_expired(self):
        """Check if key has expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def serialize_to_dict(self):
        """Serialize key to dictionary (NO HMAC)."""
        return {
            'key_id': self.key_id,
            'key_material': self.key_material.hex(),
            'algorithm': self.algorithm,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'device_id': self.device_id,
            'revoked': self.revoked
        }

    def serialize_to_json(self):
        """
        Serialize key to JSON format.

        Returns:
            dict: JSON-serializable key representation
        """
        return self.serialize_to_dict()

    def serialize_to_yaml(self):
        """
        Serialize key to YAML format.

        Returns:
            str: YAML representation of key
        """
        import yaml
        return yaml.dump(self.serialize_to_dict(), default_flow_style=False)


class KeyGenerator:
    """
    Generates and manages TrueSeal encryption keys.

    Supports multiple key derivation methods:
      - Random key generation
      - Password-based key derivation (PBKDF2)
      - Device-bound keys
    """

    @staticmethod
    def generate_random_key(algorithm='chacha20', device_binding=False):
        """
        Generate cryptographically random 256-bit key.

        Args:
            algorithm (str): Cipher algorithm to use with key
            device_binding (bool): Bind key to current device

        Returns:
            TrueSealKey: Generated key object
        """
        key_material = os.urandom(32)
        key = TrueSealKey(key_material, algorithm, device_binding)
        return key

    @staticmethod
    def derive_key_from_password(password, salt=None, iterations=600000,
                                  algorithm='chacha20', device_binding=False):
        """
        Derive 256-bit key from password using Argon2id, with PBKDF2 fallback.

        Args:
            password (str): User-provided password
            salt (bytes): Optional salt
            iterations (int): Ignored for Argon2id
            algorithm (str): Cipher algorithm
            device_binding (bool): Bind to device

        Returns:
            tuple: (TrueSealKey, salt)
        """
        if not password:
            raise ValueError("Password cannot be empty")

        if salt is None:
            salt = os.urandom(16)

        try:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        except Exception:
            Argon2id = None

        if Argon2id is not None:
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=65536,
                ad=None,
                secret=None
            )
            key_material = kdf.derive(password.encode('utf-8'))
        else:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )
            key_material = kdf.derive(password.encode('utf-8'))

        key = TrueSealKey(key_material, algorithm, device_binding)

        return key, salt

    @staticmethod
    def _parse_key_content(content):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            try:
                import yaml
                data = yaml.safe_load(content)
            except Exception as exc:
                raise ValueError("Invalid key file format: expected JSON or YAML") from exc

        if not isinstance(data, dict):
            raise ValueError("Invalid key file format")
        return data

    @staticmethod
    def load_from_file(filepath, password=None):
        """
        Load key from file or stdin. REQUIRED password if protected.

        Args:
            filepath (str|Path): Path to key file, or "-" to read from stdin
            password (str): Password if key is protected

        Returns:
            TrueSealKey: Loaded key object

        Raises:
            ValueError: If key format is invalid, incorrect password, or file not found
        """
        if str(filepath) == '-':
            import sys
            content = sys.stdin.read()
            data = KeyGenerator._parse_key_content(content)
        else:
            filepath = Path(filepath)

            if not filepath.exists():
                raise ValueError(f"Key file not found: {filepath}")

            content = filepath.read_text(encoding='utf-8')
            data = KeyGenerator._parse_key_content(content)

        # 1. Check encryption status
        if data.get('protected') == True:
            if not password:
                raise ValueError("This key file is password-protected. Please provide a password.")
            
            try:
                salt = bytes.fromhex(data['salt'])
                encrypted_data = bytes.fromhex(data['encrypted'])
                
                protection_key, _ = KeyGenerator.derive_key_from_password(password, salt=salt)
                cipher = SealAES256GCM(protection_key.key_material)
                decrypted_content = cipher.decrypt(encrypted_data)
                
                data = json.loads(decrypted_content.decode('utf-8'))
                
                # Secure cleanup
                del encrypted_data
                del decrypted_content
                if hasattr(protection_key, 'key_material'):
                    del protection_key.key_material
            except AuthenticatedCipherError:
                raise ValueError("Incorrect password or corrupted key file.")

        # 2. RECONSTRUCT KEY OBJECT
        key = TrueSealKey(
            bytes.fromhex(data['key_material']),
            algorithm=data.get('algorithm', 'chacha20')
        )
        key.key_id = data['key_id']
        key.created_at = datetime.fromisoformat(data['created_at'])
        if data.get('expires_at'):
            key.expires_at = datetime.fromisoformat(data['expires_at'])
        key.device_id = data.get('device_id')
        key.revoked = data.get('revoked', False)

        return key

    @staticmethod
    def assert_key_usable(key):
        """Raise ValueError when the key exists but must not be used."""
        revocation_file = Path.home() / '.trueseal' / 'revoked_keys.json'
        if revocation_file.exists():
            try:
                revoked_ids = json.loads(revocation_file.read_text(encoding='utf-8'))
            except json.JSONDecodeError as exc:
                raise ValueError("Revocation list is corrupted and cannot be trusted.") from exc

            if key.key_id in set(revoked_ids):
                raise ValueError("This key has been locally revoked and cannot be used.")

        if getattr(key, 'revoked', False):
            raise ValueError("This key has been revoked and cannot be used.")

        if getattr(key, 'expires_at', None) and key.is_expired():
            raise ValueError("This key has expired and cannot be used.")

        if getattr(key, 'device_id', None) and not DeviceIdentity.verify_same_device(key.device_id):
            raise ValueError("This key is bound to a different device.")

    @staticmethod
    def save_to_file(key, filepath, password=None, file_format=None):
        """
        Save the key to disk. Password protection is strongly recommended.

        Args:
            key (TrueSealKey): Key to save
            filepath (str|Path): Output file path
            password (str): Optional password to encrypt key file
            file_format (str): Optional output format override ('json' or 'yaml')

        Raises:
            IOError: If write fails
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        data = key.serialize_to_dict()
        if file_format not in {None, 'json', 'yaml'}:
            raise ValueError(f"Unsupported file format: {file_format}")

        is_yaml = file_format == 'yaml' if file_format else filepath.suffix in ['.yaml', '.yml']

        if password:
            """Encrypt the payload dictionary with the password."""
            inner_json = json.dumps(data, indent=2).encode('utf-8')
            protection_key, salt = KeyGenerator.derive_key_from_password(password)
            cipher = SealAES256GCM(protection_key.key_material)
            encrypted = cipher.encrypt(inner_json)

            wrapped = {
                'encrypted': encrypted.hex(),
                'salt': salt.hex(),
                'protected': True
            }
            if is_yaml:
                import yaml
                content = yaml.dump(wrapped, default_flow_style=False)
            else:
                content = json.dumps(wrapped, indent=2)
        else:
            try:
                from ..ui.styling import console
                console.print("[bold yellow]Warning: Saving key material in plaintext to disk is highly insecure.[/bold yellow]")
            except ImportError:
                import warnings
                warnings.warn("Saving key material in plaintext to disk is highly insecure!", UserWarning)
                
            if is_yaml:
                import yaml
                content = yaml.dump(data, default_flow_style=False)
            else:
                content = json.dumps(data, indent=2)

        import os
        import tempfile
        tmp_output = filepath.with_suffix('.tskey.tmp')
        
        try:
            tmp_output.write_text(content, encoding='utf-8')
            tmp_output.chmod(0o600)  # Read/Write only for owner
            tmp_output.replace(filepath)
        except Exception as e:
            if tmp_output.exists():
                tmp_output.unlink()
            raise IOError(f"Failed to safely save key file: {e}") from e
        finally:
            # Clean up sensitive strings from memory
            del content
            if password:
                del wrapped
                del inner_json
            import gc
            gc.collect()


# Alias for backward compatibility in commands
Key = TrueSealKey
