import os
import pytest
from pathlib import Path
from trueseal.crypto.keygen import TrueSealKey, KeyGenerator
from trueseal.crypto.cipher import initialize_authenticated_cipher, SealAES256GCM, SealChaCha20Poly1305, AuthenticatedCipherError


def test_keygen_random():
    """Test random key generation"""
    k = KeyGenerator.generate_random_key(algorithm='chacha20')
    assert k.key_id is not None
    assert k.algorithm == 'chacha20'
    assert len(k.key_material) == 32
    assert k.created_at is not None


def test_keygen_password_derivation():
    """Test password-based key derivation"""
    k, salt = KeyGenerator.derive_key_from_password(
        "test_password_123",
        algorithm='aes256'
    )
    assert k.key_id is not None
    assert k.algorithm == 'aes256'
    assert len(k.key_material) == 32
    assert len(salt) == 16
    
    # Determinism Check
    k2, salt2 = KeyGenerator.derive_key_from_password(
        "test_password_123",
        salt=salt,
        algorithm='aes256'
    )
    assert k.key_material == k2.key_material


def test_cipher_aes256():
    """Test AES-256-GCM encryption/decryption"""
    plaintext = b"Hello TrueSeal"
    key = os.urandom(32)
    cipher = SealAES256GCM(key)
    
    encrypted = cipher.encrypt(plaintext)
    assert len(encrypted) > len(plaintext)
    assert encrypted[:12] != plaintext[:12]
    
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == plaintext
    
    # Empty payload
    empty_enc = cipher.encrypt(b"")
    assert cipher.decrypt(empty_enc) == b""
    
    # Wrong key
    wrong_cipher = SealAES256GCM(os.urandom(32))
    with pytest.raises(AuthenticatedCipherError):
        wrong_cipher.decrypt(encrypted)
        
    # Tamper checking
    tampered_enc = bytearray(encrypted)
    tampered_enc[15] ^= 1
    with pytest.raises(AuthenticatedCipherError):
        cipher.decrypt(bytes(tampered_enc))


def test_cipher_chacha20():
    """Test ChaCha20-Poly1305 encryption/decryption"""
    plaintext = b"Hello TrueSeal ChaCha20"
    key = os.urandom(32)
    cipher = SealChaCha20Poly1305(key)
    
    encrypted = cipher.encrypt(plaintext)
    assert len(encrypted) > len(plaintext)
    
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == plaintext
    
    # Empty payload
    empty_enc = cipher.encrypt(b"")
    assert cipher.decrypt(empty_enc) == b""
    
    # Wrong key
    wrong_cipher = SealChaCha20Poly1305(os.urandom(32))
    with pytest.raises(AuthenticatedCipherError):
        wrong_cipher.decrypt(encrypted)
        
    # Tamper checking
    tampered_enc = bytearray(encrypted)
    tampered_enc[15] ^= 1
    with pytest.raises(AuthenticatedCipherError):
        cipher.decrypt(bytes(tampered_enc))


def test_key_serialization(tmp_path):
    """Test key save/load with JSON"""
    key = KeyGenerator.generate_random_key()
    key_file = tmp_path / 'test.tskey'
    
    KeyGenerator.save_to_file(key, str(key_file))
    assert key_file.exists()
    
    loaded = KeyGenerator.load_from_file(str(key_file))
    assert loaded.key_id == key.key_id
    assert loaded.algorithm == key.algorithm
    assert loaded.key_material == key.key_material


def test_key_expiration(tmp_path):
    """Test key expiration checking"""
    from datetime import timedelta
    key = KeyGenerator.generate_random_key()
    # Set expiration to past time (so it's already expired)
    key.expires_at = key.created_at - timedelta(hours=1)
    
    key_file = tmp_path / 'expired.tskey'
    KeyGenerator.save_to_file(key, str(key_file))
    
    loaded = KeyGenerator.load_from_file(str(key_file))
    assert loaded.is_expired()


def test_cipher_chacha20_aead_failure():
    """Test ChaCha20-Poly1305 tampering detection"""
    plaintext = b"Secret Data"
    key = os.urandom(32)
    cipher = SealChaCha20Poly1305(key)
    
    encrypted = bytearray(cipher.encrypt(plaintext))
    
    # Tamper with cipher length/tag
    encrypted[-1] ^= 1
    
    with pytest.raises(AuthenticatedCipherError):
         cipher.decrypt(bytes(encrypted))

def test_shamir_leading_zeros():
    """Test Shamir secret sharing with zero byte pad to preserve array length."""
    from trueseal.crypto.shamir import Shamir
    
    # Secret starting with three null bytes (0x00)
    original_secret = b"\x00\x00\x00" + os.urandom(29)
    assert len(original_secret) == 32
    
    # Simulate parts=5, threshold=3
    sss = Shamir(original_secret, parts=5, threshold=3)
    shares = sss.split()
    assert len(shares) == 5
    
    # Pick any 3 shares
    selected_shares = shares[:3]
    
    # Combine (without passing len property to simulate old format, should fallback up to 32)
    for sh in selected_shares:
        sh.pop('len', None)
        
    recovered = Shamir.combine(selected_shares, expected_len=32)
    assert len(recovered) == 32
    assert recovered == original_secret

def test_vault_hmac_uses_constant_time(monkeypatch):
    """Test that hmac.compare_digest is actively used for integrity checks."""
    from trueseal.vault.open import OpenOperation
    import hmac
    
    # Track the call calls
    compare_called = False
    original_compare = hmac.compare_digest
    
    def mock_compare(a, b):
        nonlocal compare_called
        compare_called = True
        return original_compare(a, b)
        
    monkeypatch.setattr('trueseal.vault.open.hmac.compare_digest', mock_compare)

    # Prepare a dummy key and a dummy vault path
    # We just need it to hit the integrity check and fail, or we can use pytest.raises
    # If the file does not exist or format is invalid, it won't reach hmac comparison.
    # We will instead test verify_integrity in Vault if easier, or create a quick fake vault.
    
    from trueseal.vault.seal import SealOperation
    from trueseal.crypto.keygen import KeyGenerator
    import tempfile
    
    # Setup test file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        vault_path = tmp.name
        
    try:
        key = KeyGenerator.generate_random_key()
        
        # Save key temp
        key_path = tmp.name + ".key"
        KeyGenerator.save_to_file(key, key_path)
        
        # Test add file manually to create a vault
        test_dir = tempfile.mkdtemp()
        payload_path = os.path.join(test_dir, "data.txt")
        with open(payload_path, "wb") as payload:
            payload.write(b"data")
            
        try:
            sealer = SealOperation(key_path, test_dir, output_path=vault_path)
            sealer.execute()
            
            extract_dir = tempfile.mkdtemp()
            
            # Now extract to trigger the read and HMAC check with verify enabled
            opener = OpenOperation(vault_path, key_path, extract_dir, verify=True)
            opener.execute()
            assert compare_called, "hmac.compare_digest was not utilized during vault extraction!"
            
        finally:
            import time
            import time
            time.sleep(0.1) # Windows handle closure
            try:
                if os.path.exists(payload_path):
                    os.remove(payload_path)
                if os.path.exists(test_dir):
                    os.rmdir(test_dir)
                import shutil
                if os.path.exists('extract_dir') and 'extract_dir' in locals():
                    shutil.rmtree(extract_dir, ignore_errors=True)
            except Exception:
                pass
            
    finally:
        if os.path.exists(key_path):
            os.remove(key_path)
        if os.path.exists(vault_path):
            os.remove(vault_path)
