from __future__ import annotations

import re
import sys
from pathlib import Path


def _read_version_from_pyproject(pyproject_path: Path) -> str:
    content = pyproject_path.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, flags=re.MULTILINE)
    if not match:
        raise ValueError("Cannot find project version in pyproject.toml")
    return match.group(1)


def _read_version_from_init(init_path: Path) -> str:
    content = init_path.read_text(encoding="utf-8")
    content = content.lstrip("\ufeff")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', content, flags=re.MULTILINE)
    if not match:
        raise ValueError("Cannot find __version__ in trueseal/__init__.py")
    return match.group(1)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyproject_version = _read_version_from_pyproject(root / "pyproject.toml")
    init_version = _read_version_from_init(root / "trueseal" / "__init__.py")

    if pyproject_version != init_version:
        print("[ERROR] Version mismatch detected")
        print(f"  pyproject.toml: {pyproject_version}")
        print(f"  trueseal/__init__.py: {init_version}")
        return 1

    print(f"[OK] Version is consistent: {pyproject_version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

