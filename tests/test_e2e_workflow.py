import os
import hashlib
from pathlib import Path
from trueseal.crypto.keygen import KeyGenerator
from trueseal.vault.seal import SealOperation
from trueseal.vault.open import OpenOperation


def hash_directory(directory_path):
    """Compute SHA256 hashes for all files in a directory."""
    hashes = {}
    for fp in Path(directory_path).rglob('*'):
        if fp.is_file():
            # Get relative path for comparison
            rel_path = str(fp.relative_to(directory_path)).replace("\\", "/")
            with open(fp, 'rb') as f:
                hashes[rel_path] = hashlib.sha256(f.read()).hexdigest()
    return hashes


def test_full_seal_and_open_workflow(tmp_path):
    """E2E workflow test: Generate key, seal a directory, open, and verify contents."""
    
    # 1. Setup paths
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    
    output_vault = tmp_path / "test.vault"
    
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    
    key_file = tmp_path / "test.tskey"
    
    # 2. Create some dummy files in source
    (source_dir / "secret.txt").write_text("This is top secret data.")
    (source_dir / "subfolder").mkdir()
    (source_dir / "subfolder" / "config.json").write_text('{"db": "production", "password": "123"}')
    # Add an empty file
    (source_dir / "empty.log").write_bytes(b"")

    original_hashes = hash_directory(source_dir)
    
    # 3. Generate key and save it
    key = KeyGenerator.generate_random_key(algorithm='chacha20')
    KeyGenerator.save_to_file(key, str(key_file))
    
    # 4. Seal the directory
    sealer = SealOperation(
        key_path=str(key_file),
        root_path=source_dir,
        output_path=output_vault,
        scope='project',
        compression='gzip'
    )
    seal_result = sealer.execute()
    
    assert seal_result['status'] == 'success'
    assert output_vault.exists()
    assert output_vault.stat().st_size > 0
    
    # 5. Open the vault
    opener = OpenOperation(
        key_path=str(key_file),
        vault_path=output_vault,
        output_dir=extract_dir
    )
    open_result = opener.execute()
    
    assert open_result['status'] == 'success'
    assert open_result['files'] == len(original_hashes)
    
    # 6. Verify contents
    extracted_hashes = hash_directory(extract_dir)
    
    assert original_hashes == extracted_hashes


def test_incremental_seal_merges_with_base_vault(tmp_path):
    source_dir = tmp_path / "repo"
    source_dir.mkdir()
    (source_dir / "a.txt").write_text("v1-a")
    (source_dir / "b.txt").write_text("v1-b")

    output_vault = tmp_path / "repo.vault"
    key_file = tmp_path / "key.tskey"
    key = KeyGenerator.generate_random_key(algorithm='chacha20')
    KeyGenerator.save_to_file(key, str(key_file))

    first_seal = SealOperation(
        key_path=str(key_file),
        root_path=source_dir,
        output_path=output_vault,
        scope='project',
        compression='gzip'
    )
    first_result = first_seal.execute()
    assert first_result['status'] == 'success'

    (source_dir / "a.txt").write_text("v2-a")
    (source_dir / "c.txt").write_text("v1-c")
    os.remove(source_dir / "b.txt")

    second_seal = SealOperation(
        key_path=str(key_file),
        root_path=source_dir,
        output_path=output_vault,
        scope='project',
        compression='gzip',
        explicit_targets=[str(source_dir / "a.txt"), str(source_dir / "c.txt")],
        remove_targets=["b.txt"],
        base_vault_path=str(output_vault)
    )
    second_result = second_seal.execute()
    assert second_result['status'] == 'success'

    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir()
    open_result = OpenOperation(
        key_path=str(key_file),
        vault_path=output_vault,
        output_dir=extracted_dir
    ).execute()

    assert open_result['status'] == 'success'
    assert (extracted_dir / "a.txt").read_text() == "v2-a"
    assert (extracted_dir / "c.txt").read_text() == "v1-c"
    assert not (extracted_dir / "b.txt").exists()


def test_incremental_seal_preserves_dotfile_names(tmp_path):
    source_dir = tmp_path / "repo_dot"
    source_dir.mkdir()
    (source_dir / ".env").write_text("TOKEN=v1")

    output_vault = tmp_path / "repo_dot.vault"
    key_file = tmp_path / "key_dot.tskey"
    key = KeyGenerator.generate_random_key(algorithm='chacha20')
    KeyGenerator.save_to_file(key, str(key_file))

    SealOperation(
        key_path=str(key_file),
        root_path=source_dir,
        output_path=output_vault,
        scope='project',
        compression='gzip'
    ).execute()

    (source_dir / ".env").write_text("TOKEN=v2")
    SealOperation(
        key_path=str(key_file),
        root_path=source_dir,
        output_path=output_vault,
        scope='project',
        compression='gzip',
        explicit_targets=[str(source_dir / ".env")],
        base_vault_path=str(output_vault)
    ).execute()

    extracted_dir = tmp_path / "extract_dot"
    extracted_dir.mkdir()
    OpenOperation(
        key_path=str(key_file),
        vault_path=output_vault,
        output_dir=extracted_dir
    ).execute()

    assert (extracted_dir / ".env").exists()
    assert (extracted_dir / ".env").read_text() == "TOKEN=v2"


