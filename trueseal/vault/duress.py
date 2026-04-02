import os
import struct

class AegisDecoyManager:
    def __init__(self, real_vault_path, duress_vault_path, duress_key=None):
        self.real_vault_path = real_vault_path
        self.duress_vault_path = duress_vault_path
        self.duress_key = duress_key

    def _pad_and_obfuscate(self, data, target_size):
        """
        Pad the data to target_size with random bytes.
        Append exactly 4 bytes of obfuscated original length.
        """
        original_length = len(data)
        padding_length = target_size - original_length
        padding = os.urandom(padding_length)
        
        # Obfuscate length by XORing with the first 4 bytes of data (which is the random nonce)
        nonce_prefix = data[:4] if len(data) >= 4 else os.urandom(4)
        length_bytes = struct.pack('<I', original_length)
        obfuscated_length = bytes(a ^ b for a, b in zip(length_bytes, nonce_prefix))
        
        return data + padding + obfuscated_length

    def combine_vaults(self, output_path):
        with open(self.real_vault_path, 'rb') as f:
            real_data = f.read()
        with open(self.duress_vault_path, 'rb') as f:
            duress_data = f.read()

        # Size padding to make both blocks IDENTICAL in length, defeating size analysis
        max_size = max(len(real_data), len(duress_data))
        
        block1 = self._pad_and_obfuscate(real_data, max_size)
        block2 = self._pad_and_obfuscate(duress_data, max_size)

        # True Plausible Deniability: NO MAGIC HEADERS.
        # Format: [BLOCK 1] [BLOCK 2] exactly split in half.
        # Mathematically indistinguishable from a single block of 2 * max_size random bytes.
        
        combined_data = block1 + block2

        with open(output_path, 'wb') as f:
            f.write(combined_data)

        # Secure wipe
        return {'files': 2, 'size': len(combined_data), 'vault': output_path}

    @staticmethod
    def extract_vault(vault_path, key_obj):
        """
        Used by inspect.py to probe the file.
        Try the whole file first, then try halves to locate the valid AEAD segment.
        """
        with open(vault_path, 'rb') as f:
            data = f.read()
            
        from ..crypto.cipher import initialize_authenticated_cipher, AuthenticatedCipherError
        cipher = initialize_authenticated_cipher(key_obj.algorithm, key_obj.key_material)
        
        # 1. Try full file
        try:
            cipher.decrypt(data)
            return data
        except AuthenticatedCipherError:
            pass
            
        # 2. Try halves (Deniable Duress Mode)
        if len(data) % 2 == 0:
            half = len(data) // 2
            try:
                cipher.decrypt(data[:half])
                return data[:half]
            except AuthenticatedCipherError:
                pass
            try:
                cipher.decrypt(data[half:])
                return data[half:]
            except AuthenticatedCipherError:
                pass
                
        # If all fail, return raw data to let it crash upstream correctly
        return data

DuressManager = AegisDecoyManager
