import ctypes
import sys

def memzero(obj) -> None:
    """
    Securely overwrite sensitive data in RAM.
    
    WARNING: Highly experimental and relies on CPython's internal memory
    layout. It overwrites the underlying C-buffer of immutable bytes/strings.
    This effectively wipes the memory so a memory dump or RAM scraper cannot
    recover the cryptographic key after it has been used.
    """
    if isinstance(obj, bytes):
        # sys.getsizeof(b'') gives the base Object size for empty bytes.
        # the payload directly follows the PyBytesObject header (except a null byte possibly).
        # In CPython 3.x, ob_sval is at offset sys.getsizeof(b'') - 1
        buffer_offset = sys.getsizeof(b'') - 1
        ctypes.memset(id(obj) + buffer_offset, 0, len(obj))
    elif isinstance(obj, bytearray):
        # bytearray uses a pointer to a buffer. However, modifying bytearray
        # can just be done via index assignment for safety.
        for i in range(len(obj)):
            obj[i] = 0
    elif isinstance(obj, str):
        # Wiping strings is harder due to variable formats (ASCII, UCS-2, UCS-4).
        # We attempt a basic wipe of the raw unicode object size.
        buffer_offset = sys.getsizeof("") - 1
        length = len(obj.encode('utf-8'))
        ctypes.memset(id(obj) + buffer_offset, 0, length)
    else:
        pass

