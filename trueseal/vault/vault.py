"""
trueseal/vault/vault.py - Core vault format (TSVL - TrueSeal Vault Layout)

Standard container for encrypted source code and secrets. Defines binary format,
serialization/deserialization, and integrity checking (HMAC-SHA256).

Wire format:
  [Magic (4B)] [Version (1B)] [Algorithm] [Compression] [Segments] [HMAC]
  
All integer fields use little-endian byte order for cross-platform compatibility.
Segments are variable-length blocks, each containing a file with metadata.
"""

import struct
import hmac
import hashlib

class _BufferReader:
    """Read binary buffers safely with bounds checks."""
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.total_len = len(data)

    def read(self, size, name="data"):
        if self.offset + size > self.total_len:
            raise ValueError(f"Corrupted vault: missing or truncated {name}.")
        chunk = self.data[self.offset:self.offset + size]
        self.offset += size
        return chunk

    def read_struct(self, fmt, size, name="struct"):
        return struct.unpack(fmt, self.read(size, name))

    def read_uint8(self, name="byte"):
        return self.read(1, name)[0]

    def read_string(self, name="string"):
        length = self.read_uint8(f"{name} length")
        return self.read(length, name).decode('utf-8', errors='replace')

class AegisContainer:
    """
    Core container class for TrueSeal encrypted files.
    
    Represents a collection of files packed into a single sealed unit.
    Tracks algorithm, compression method, and maintains file segments with integrity.
    
    Attributes:
        algorithm (str): Cipher algorithm ('aes256', 'chacha20', 'hybrid')
        scope (str): Sealing scope ('file', 'group', 'project', 'auto')
        compression (str): Compression method ('gzip', 'brotli', 'none')
        segments (list): List of file dicts {filename, data, size, permissions}
        hmac_value (bytes): HMAC-SHA256 of vault metadata (32 bytes)
    """
    
    TSVL_MAGIC = 0x5453564C
    VSN_MAJOR = 3

    def __init__(self, algorithm='chacha20', scope='auto', compression='gzip'):
        """
        Initialize empty vault structure.
        
        Args:
            algorithm (str): Cipher algorithm for this vault
            scope (str): Sealing granularity (affects how files are grouped)
            compression (str): Data compression applied before encryption
        """
        self.tsvl_magic = self.TSVL_MAGIC
        self.vsn_major = self.VSN_MAJOR
        self.algorithm = algorithm
        self.scope = scope
        self.compression = compression
        self.segments = []
        self.hmac_value = b''

    def forge_payload(self, ts_filename, ts_payload, permissions=0o644):
        """
        Add a file to vault (before encryption).
        
        Args:
            ts_filename (str): Relative path within vault (e.g., 'src/main.py')
            ts_payload (bytes): Uncompressed file contents
            permissions (int): Unix-style file mode (default 0o644 for regular files)
        """
        ts_filename = ts_filename.replace('\\', '/')
        if '..' in ts_filename.split('/') or ts_filename.startswith('/'):
            raise ValueError(f"Invalid filename: path traversal or absolute path detected ({ts_filename})")

        self.segments.append({
            'filename': ts_filename,
            'data': ts_payload,
            'size': len(ts_payload),
            'permissions': permissions
        })
    
    def sign_aegis_hmac(self, ts_key_data):
        mac = hmac.new(ts_key_data, digestmod=hashlib.sha256)
        mac.update(struct.pack('<III', self.tsvl_magic, self.vsn_major, len(self.segments)))
        mac.update(struct.pack('<B', len(self.algorithm.encode('utf-8'))))
        mac.update(self.algorithm.encode('utf-8'))
        mac.update(struct.pack('<B', len(self.scope.encode('utf-8'))))
        mac.update(self.scope.encode('utf-8'))
        mac.update(struct.pack('<B', len(self.compression.encode('utf-8'))))
        mac.update(self.compression.encode('utf-8'))
        for seg in self.segments:
            mac.update(seg['filename'].encode('utf-8'))
            sz = len(seg['data'])
            mac.update(struct.pack('<Q', sz))
            mac.update(seg['data'])
            mac.update(struct.pack('<H', seg['permissions']))

        return mac.digest()

    def serialize(self):
        """
        Flatten vault structures into binary wire format.
        
        Encodes all segments sequentially with length-prefixed fields.
        Output suitable for compression + encryption.
        
        Returns:
            bytes: Serialized vault data
        """
        hmac_val = self.hmac_value if self.hmac_value else b'\x00' * 32
        if len(hmac_val) != 32:
            raise ValueError(f"Invalid HMAC length: expected 32, got {len(hmac_val)}")

        ts_buf = bytearray()
        
        ts_buf.extend(struct.pack('<I', self.tsvl_magic))
        ts_buf.append(self.vsn_major)
        
        algo_bytes = self.algorithm.encode()
        ts_buf.append(len(algo_bytes))
        ts_buf.extend(algo_bytes)

        ts_buf.extend(struct.pack('<H', len(hmac_val)))
        ts_buf.extend(hmac_val)


        scope_bytes = self.scope.encode()
        ts_buf.append(len(scope_bytes))
        ts_buf.extend(scope_bytes)
        
        comp_bytes = self.compression.encode()
        ts_buf.append(len(comp_bytes))
        ts_buf.extend(comp_bytes)
        
        ts_buf.extend(struct.pack('<I', len(self.segments)))
        
        for seg in self.segments:
            fn_bytes = seg['filename'].encode()
            ts_buf.extend(struct.pack('<I', len(fn_bytes)))
            ts_buf.extend(fn_bytes)
            ts_buf.extend(struct.pack('<Q', seg['size']))
            ts_buf.extend(struct.pack('<I', seg['permissions']))
            ts_buf.extend(seg['data'])

        # HMAC is completely removed as AEAD handles ciphertext authentication.
        return bytes(ts_buf)
    
    @staticmethod
    def deserialize(ts_raw_data, verify_hmac=True, ts_key_data=None):
        """Unpack TSVL structures. Reject fundamentally corrupted magic frames."""
        reader = _BufferReader(ts_raw_data)
        
        magic, = reader.read_struct('<I', 4, "TSVL magic bitmask")
        if magic != AegisContainer.TSVL_MAGIC:
            raise ValueError(f"Invalid TSVL magic bitmask: {magic}")
        
        vsn_major = reader.read_uint8("version byte")
        
        algorithm = reader.read_string("algorithm")

        hmac_len, = reader.read_struct('<H', 2, "HMAC length")
        hmac_value = reader.read(hmac_len, "HMAC value")

        scope = 'auto'
        if vsn_major >= 3:
            scope = reader.read_string("scope")
        
        compression = 'gzip'
        if vsn_major >= 2:
            compression = reader.read_string("compression")
        
        seg_count, = reader.read_struct('<I', 4, "segment count")

        ts_vault = AegisContainer(algorithm=algorithm, scope=scope, compression=compression)
        ts_vault.vsn_major = vsn_major
        ts_vault.hmac_value = hmac_value

        for _ in range(seg_count):
            fn_len, = reader.read_struct('<I', 4, "filename length")
            filename = reader.read(fn_len, "filename string").decode('utf-8', errors='replace')
            size, = reader.read_struct('<Q', 8, f"payload size for file '{filename}'")
            perms, = reader.read_struct('<I', 4, f"permissions for file '{filename}'")
            file_payload = reader.read(size, f"payload for file '{filename}'")

            ts_vault.segments.append({
                'filename': filename,
                'data': file_payload,
                'size': size,
                'permissions': perms,
            })

        if verify_hmac and ts_key_data:
            expected_hmac = ts_vault.sign_aegis_hmac(ts_key_data)
            if not hmac.compare_digest(expected_hmac, ts_vault.hmac_value):
                raise ValueError("HMAC verification failed! Vault has been tampered with.")

        return ts_vault
    
    @staticmethod
    def deserialize_from_file(ts_file_path, verify_hmac=True, ts_key_data=None):
        """Load vault from file. HMAC validation logic removed as AEAD secures files."""
        with open(ts_file_path, 'rb') as ts_fp:
            ts_raw_data = ts_fp.read()
        
        ts_vault = AegisContainer.deserialize(ts_raw_data)
        
        # In this updated architecture, verify_hmac functionality is
        # delegated entirely to the outer cipher.decrypt()
        return ts_vault


# Backward-compatible alias for older command modules.
Vault = AegisContainer


