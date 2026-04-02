import os
import secrets
from pathlib import Path
from ..crypto.zeroize import memzero


def auto_discover_key(search_dir: str = '.') -> str:
    """
    Automatically search for a single .tskey file in the specified directory.
    Raises FileNotFoundError if zero keys are found.
    Raises ValueError if multiple keys are found.
    """
    search_path = Path(search_dir)
    # Use union to ensure we catch hidden files (starting with .) on Unix-like systems,
    # while using a set avoids duplicates if standard glob also picks them up.
    keys_found = set(search_path.glob('*.tskey')).union(search_path.glob('.*.tskey'))

    # Filter out any matched directories just to be safe
    files_only = [k for k in keys_found if k.is_file()]

    if len(files_only) == 1:
        return str(files_only[0])
    elif len(files_only) == 0:
        raise FileNotFoundError("No key file found in current directory.")
    else:
        raise ValueError("Multiple key files found in current directory.")


class SecureKeyContext:
    """
    Context manager to securely zeroize key material automatically when exiting scope.
    """
    def __init__(self, key_obj):
        self.key_obj = key_obj

    def __enter__(self):
        return self.key_obj

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self.key_obj, 'key_material') and self.key_obj.key_material:
            memzero(self.key_obj.key_material)


def secure_erase(file_path: str, passes: int = 3) -> None:
    """
    Securely wipe a file by overwriting its contents with random bytes,
    flushing to disk via fsync, and then unlinking it.
    This helps mitigate forensic data recovery from magnetic/NAND storage (though OS/SSD TRIM
    wear-leveling may still leave artifacts, this is the best application-level effort).
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return

    try:
        length = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                # First pass zero, second pass random, third pass zero
                if _ % 2 == 0:
                    f.write(b'\x00' * length)
                else:
                    f.write(secrets.token_bytes(length))
                f.flush()
                os.fsync(f.fileno())

        # Finally, remove the file
        path.unlink()
    except Exception:
        # Fallback to standard removal if we lack permission to overwrite
        path.unlink(missing_ok=True)
