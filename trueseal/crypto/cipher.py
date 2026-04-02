"""
TrueSeal Cryptographic Cipher Module

Provides authenticated encryption implementations for vault operations.
All ciphers follow NIST/RFC standards with 96-bit nonces and 128-bit
authentication tags (AEAD pattern).

Available ciphers:
  SealAES256GCM: AES-256 in Galois/Counter Mode (NIST standard)
  SealChaCha20Poly1305: ChaCha20 stream + Poly1305 MAC (RFC 7539/8439)
  SealHybridCipher: Sequential dual-encryption (ChaCha20 -> AES) defense-in-depth
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
import secrets
from abc import ABC, abstractmethod


class AuthenticatedCipherError(Exception):
    """
    Raised when authenticated encryption/decryption fails.
    
    Covers authentication tag verification failures and decryption errors.
    Intentionally vague to prevent information leakage (no padding oracle attacks).
    """
    pass


class SealCipherProtocol(ABC):
    """
    Abstract base for TrueSeal authenticated encryption implementations.
    
    Defines contract for encrypt/decrypt operations with built-in
    authentication tags. All subclasses must handle nonce generation,
    encryption, and decryption with authentication verification.
    """
    
    @abstractmethod
    def encrypt(self, plaintext):
        """
        Encrypt plaintext with authenticated encryption.
        
        Args:
            plaintext (bytes): Data to encrypt
            
        Returns:
            bytes: Nonce (12 bytes) + Ciphertext + Authentication Tag (16 bytes)
                   Format is ready for transmission/storage
        """
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext_with_nonce):
        """
        Decrypt and verify authenticated ciphertext.
        
        Args:
            ciphertext_with_nonce (bytes): Encrypted data with embedded nonce/tag
            
        Returns:
            bytes: Decrypted plaintext on successful verification
            
        Raises:
            AuthenticatedCipherError: If authentication fails or key is invalid
        """
        pass


class SealAES256GCM(SealCipherProtocol):
    """
    AES-256-GCM: Galois/Counter Mode Authenticated Encryption.
    
    Parameters:
      - Key: 256 bits (32 bytes)
      - Nonce: 96 bits (12 bytes, random per encrypt)
      - Auth Tag: 128 bits (16 bytes)
    
    Characteristics:
      - NIST standardized and widely supported
      - Hardware-accelerated on modern CPUs
      - Best choice for general-purpose vault encryption
    """
    
    def __init__(self, key):
        """
        Initialize AES-256-GCM cipher with key validation.
        
        Args:
            key (bytes): Exactly 32 bytes (256 bits)
            
        Raises:
            ValueError: If key length ≠ 32 bytes
        """
        if len(key) != 32:
            raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
        self.key = key
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext with AES-256-GCM.
        
        Generates random 12-byte nonce per encryption, produces
        authenticated ciphertext with 16-byte tag.
        """
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(self.key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt(self, ciphertext_with_nonce):
        """
        Decrypt and authenticate with AES-256-GCM.
        
        Extracts embedded nonce, verifies authentication tag,
        returns plaintext or raises error.
        """
        try:
            nonce = ciphertext_with_nonce[:12]
            ct = ciphertext_with_nonce[12:]
            cipher = AESGCM(self.key)
            return cipher.decrypt(nonce, ct, None)
        except Exception as e:
            raise AuthenticatedCipherError(
                "Decryption failed: invalid key or corrupted data"
            ) from e


class SealChaCha20Poly1305(SealCipherProtocol):
    """
    ChaCha20-Poly1305: Stream Cipher + Poly1305 Authentication.
    
    Parameters:
      - Key: 256 bits (32 bytes)
      - Nonce: 96 bits (12 bytes)
      - Auth Tag: 128 bits (16 bytes)
    
    Characteristics:
      - RFC 7539 and RFC 8439 compliant
      - Faster than AES on machines without AES-NI
      - Preferred for resource-constrained environments
    """
    
    def __init__(self, key):
        """
        Initialize ChaCha20-Poly1305 cipher with key validation.
        
        Args:
            key (bytes): Exactly 32 bytes (256 bits)
            
        Raises:
            ValueError: If key length ≠ 32 bytes
        """
        if len(key) != 32:
            raise ValueError(f"ChaCha20 requires 32-byte key, got {len(key)}")
        self.key = key
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext with ChaCha20-Poly1305.
        
        Generates random 12-byte nonce, produces stream-encrypted
        ciphertext with Poly1305 authentication tag.
        """
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(self.key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt(self, ciphertext_with_nonce):
        """
        Decrypt and authenticate with ChaCha20-Poly1305.
        
        Extracts nonce, verifies Poly1305 tag, returns plaintext.
        """
        try:
            nonce = ciphertext_with_nonce[:12]
            ct = ciphertext_with_nonce[12:]
            cipher = ChaCha20Poly1305(self.key)
            return cipher.decrypt(nonce, ct, None)
        except Exception as e:
            raise AuthenticatedCipherError(
                "Decryption failed: invalid key or corrupted data"
            ) from e


class SealHybridCipher(SealCipherProtocol):
    """
    Defense-in-depth dual encryption: ChaCha20-Poly1305 → AES-256-GCM.
    
    Strategy:
      1. Encrypt plaintext with ChaCha20-Poly1305
      2. Encrypt result with AES-256-GCM
    
    Key Derivation:
      - HKDF-SHA256 expands 32-byte input to 64 bytes
      - First 32 bytes → ChaCha20 key
      - Second 32 bytes → AES-256 key
    
    Benefits:
      - Remains secure if one cipher is theoretically broken
      - Provides cryptographic agility through multiple layers
    
    Trade-off:
      - ~2× slower than single cipher
      - Higher CPU/memory cost justified by security assurance
    """
    
    def __init__(self, key):
        """
        Initialize hybrid cipher with HKDF key derivation.
        
        Derives two independent 32-byte keys from input using HKDF-SHA256.
        Initializes both ChaCha20 and AES-256 instances.
        
        Args:
            key (bytes): Base key (32 bytes)
            
        Raises:
            ValueError: If key length ≠ 32 bytes
        """
        if len(key) != 32:
            raise ValueError(f"HybridCipher requires 32-byte key, got {len(key)}")
        
        """
        HKDF (HMAC-based Key Derivation Function) per RFC 5869.
        Expands base key to 64 bytes for independent cipher keys.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b"trueseal_hybrid",
            info=b"encryption"
        )
        derived = hkdf.derive(key)
        
        """ Split derived key into two independent 32-byte keys """
        self.chacha = SealChaCha20Poly1305(derived[:32])
        self.aes = SealAES256GCM(derived[32:64])
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using both ciphers sequentially.
        
        ChaCha20 → AES-256 to achieve defense-in-depth.
        """
        try:
            encrypted1 = self.chacha.encrypt(plaintext)
            encrypted2 = self.aes.encrypt(encrypted1)
            return encrypted2
        except Exception as e:
            raise RuntimeError("Encryption failed") from e
    
    def decrypt(self, ciphertext_with_nonce):
        """
        Decrypt using both ciphers in reverse order.
        
        AES-256 → ChaCha20 to undo dual encryption.
        """
        try:
            inner_ciphertext = self.aes.decrypt(ciphertext_with_nonce)
            plaintext = self.chacha.decrypt(inner_ciphertext)
            return plaintext
        except AuthenticatedCipherError:
            raise
        except Exception as e:
            raise AuthenticatedCipherError(
                "Decryption failed: invalid key or corrupted data"
            ) from e


def initialize_authenticated_cipher(algorithm, key):
    """
    Factory function to create authenticated cipher instances.
    
    Instantiates appropriate cipher class based on algorithm name.
    Validates key length during initialization.
    
    Args:
        algorithm (str): Cipher type ('aes256', 'chacha20', 'hybrid')
        key (bytes): 32-byte key material
        
    Returns:
        SealCipherProtocol: Initialized cipher instance
        
    Raises:
        ValueError: If algorithm name is unknown or key invalid
    """
    if algorithm == 'aes256':
        return SealAES256GCM(key)
    elif algorithm == 'chacha20':
        return SealChaCha20Poly1305(key)
    elif algorithm == 'hybrid':
        return SealHybridCipher(key)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

create_cipher = initialize_authenticated_cipher
