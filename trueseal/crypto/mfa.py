"""
TrueSeal Multi-Factor Authentication Module

Supports TOTP (Time-based One-Time Password) for MFA with authenticator apps 
(Google Authenticator, Authy, Microsoft Authenticator).
Provides encrypted MFA credential storage using Argon2id KDF + ChaCha20.
"""

import pyotp
import json
import base64
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from .cipher import create_cipher, AuthenticatedCipherError
from .zeroize import memzero


class TimebasedOneTimePasswordManager:
    """
    Manage TOTP-based multi-factor authentication.
    
    Handles TOTP secret generation, code verification, and QR provisioning
    for authenticator apps (Google Authenticator, Microsoft Authenticator, etc).
    """
    
    @staticmethod
    def generate_totp_secret() -> str:
        """
        Generate TOTP secret for authenticator apps.
        
        Returns:
            str: Base32-encoded random secret for TOTP
        """
        return pyotp.random_base32()
    
    @staticmethod
    def retrieve_current_totp_code(secret: str) -> str:
        """
        Retrieve current time-based one-time password.
        
        Args:
            secret (str): Base32-encoded TOTP secret
            
        Returns:
            str: 6-digit TOTP code valid for ~30 seconds
        """
        totp = pyotp.TOTP(secret)
        return totp.now()
    
    @staticmethod
    def verify_totp_code(secret: str, code: str) -> bool:
        """
        Verify TOTP code against secret.
        
        Args:
            secret (str): Base32-encoded TOTP secret
            code (str): User-provided 6-digit code
            
        Returns:
            bool: True if code is valid and current
        """
        if not secret or not code:
            return False
        totp = pyotp.TOTP(secret)
        # Apply valid_window=1 to account for minor time drift (±30 seconds)
        return totp.verify(str(code), valid_window=1)
    
    @staticmethod
    def generate_provisioning_uri_for_authenticator(secret: str, account_name: str = "TrueSeal", issuer_name: str = "TrueSeal") -> str:
        """
        Generate QR code URI for authenticator app provisioning.
        
        Args:
            secret (str): Base32-encoded TOTP secret
            account_name (str): User account identifier
            issuer_name (str): Service/issuer name
            
        Returns:
            str: otpauth:// URI for QR code generation
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=account_name, issuer_name=issuer_name)
    
    @staticmethod
    def generate_backup_recovery_codes(count: int = 10) -> list[str]:
        """
        Generate backup recovery codes for account recovery.
        
        Args:
            count (int): Number of recovery codes to generate
            
        Returns:
            list[str]: List of random alphanumeric recovery codes
        """
        import secrets
        import string
        codes = []
        for _ in range(count):
            parts = [''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(4)) for _ in range(3)]
            codes.append('-'.join(parts))
        return codes

    @staticmethod
    def _derive_key_from_password(password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using Argon2id KDF, with PBKDF2 fallback.
        
        Uses strong parameters: 65536 KB memory, 3 iterations, 4 lanes.
        Resistant to GPU/ASIC attacks and password cracking.
        
        Args:
            password (str): User password
            salt (bytes): Random salt (16 bytes)
            
        Returns:
            bytes: 32-byte derived key
        """
        try:
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=65536,
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600000,
            )
            return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def encrypt_mfa_data(credentials_dict: dict, password: str) -> dict:
        """
        Encrypt MFA credentials (secrets, recovery codes) with password.
        
        Args:
            credentials_dict (dict): MFA data (secrets, codes, etc)
            password (str): User password for key derivation
            
        Returns:
            dict: {'salt': b64_string, 'payload': b64_string}
        """
        salt = secrets.token_bytes(16)
        key = TimebasedOneTimePasswordManager._derive_key_from_password(password, salt)
        cipher = create_cipher('chacha20', key)
        raw_json = json.dumps(credentials_dict).encode('utf-8')
        sealed_payload = cipher.encrypt(raw_json)
        memzero(key)
        return {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'payload': base64.b64encode(sealed_payload).decode('utf-8')
        }

    @staticmethod
    def decrypt_mfa_data(encrypted_dict: dict, password: str) -> dict:
        """
        Decrypt MFA credentials using password.
        
        Args:
            encrypted_dict (dict): Output from encrypt_mfa_data
            password (str): User password for key derivation
            
        Returns:
            dict: Decrypted MFA data
            
        Raises:
            ValueError: If password wrong or credentials corrupted
        """
        salt = base64.b64decode(encrypted_dict['salt'])
        sealed_payload = base64.b64decode(encrypted_dict['payload'])
        key = TimebasedOneTimePasswordManager._derive_key_from_password(password, salt)
        cipher = create_cipher('chacha20', key)
        try:
            clear_json = cipher.decrypt(sealed_payload)
        except AuthenticatedCipherError as e:
            memzero(key)
            raise ValueError("MFA decryption failed: Invalid PIN or corrupted credentials.") from e
        memzero(key)
        return json.loads(clear_json.decode('utf-8'))

    @staticmethod
    def verify_key_file_mfa(key_file_path: str | Path, key_material_hex: str, mfa_code: str | None) -> bool:
        """
        Validate MFA protection for a key file if an adjacent `.mfa` payload exists.

        Returns True when MFA is not configured for the key file.
        Raises ValueError when MFA is configured but missing/invalid.
        """
        mfa_file = Path(key_file_path).with_suffix('.mfa')
        if not mfa_file.exists():
            return True

        if not mfa_code:
            raise ValueError("This key requires MFA confirmation.")

        with mfa_file.open('r', encoding='utf-8') as fp:
            encrypted_payload = json.load(fp)

        mfa_data = TimebasedOneTimePasswordManager.decrypt_mfa_data(encrypted_payload, key_material_hex)
        if TOTPManager.verify_totp_code(mfa_data['totp_secret'], mfa_code):
            return True

        if mfa_code in mfa_data.get('recovery_codes', []):
            return True

        raise ValueError("Invalid MFA code or recovery code.")

TOTPManager = TimebasedOneTimePasswordManager
