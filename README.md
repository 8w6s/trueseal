# TrueSeal

TrueSeal is a Python CLI for sealing source code and sensitive secrets into an authenticated vault, with MFA, device binding, revocation, and Git hook automation.

## Why TrueSeal

TrueSeal is built for teams that want more than file encryption. It gives you a controlled vault workflow for source code, keys, and operational secrets while keeping integrity checks, policy enforcement, and local revocation in the loop.

## Highlights

- Authenticated vault sealing and opening
- AES-256-GCM and ChaCha20-Poly1305 support
- Shamir Secret Sharing for distributed key handling
- MFA-backed key access through `.mfa` files
- Device-bound keys and local revocation checks
- Duress and decoy workflows
- Steganographic hiding with `cloak`
- Git hook automation for protected repositories
- CI/CD-ready package and release workflow

## Installation

### From source

```powershell
git clone https://github.com/8w6s/trueseal.git
cd trueseal
python -m pip install .
```

### From PyPI

```powershell
pip install trueseal
```

## Quick Start

### 1) Generate a key

```powershell
trueseal keygen --out generated.tskey
```

### 2) Seal a project

```powershell
trueseal seal . --key generated.tskey --out project.vault
```

### 3) Open the vault

```powershell
trueseal open project.vault --key generated.tskey --out recovered
```

### 4) Verify integrity

```powershell
trueseal verify project.vault --key generated.tskey
```

> Run `trueseal <command> --help` for the exact flags supported by each command.

## Command Reference

| Command | Purpose |
| --- | --- |
| `keygen` | Generate a new TrueSeal key file |
| `seal` | Seal files or a project into a vault |
| `open` | Open a sealed vault back into files |
| `verify` | Verify vault integrity without extracting |
| `shard` | Split or restore keys with Shamir Secret Sharing |
| `mfa` | Configure or verify MFA for a key |
| `revoke` | Add a key to the local revocation list |
| `cloak` | Hide or extract a vault inside an image |
| `git` | Install or manage Git hook integration |
| `env` | Manage environment setup and path bootstrap |
| `pipeline` | Generate CI/CD pipeline helpers |
| `duress` | Handle decoy or duress workflows |
| `inspect` | Inspect vault or key metadata |
| `merge` | Merge shard or vault artifacts |
| `demo` | Run a demo of the CLI UX |
| `version` | Print the current TrueSeal version |

## CI / CD

TrueSeal includes two core workflows in `.github/workflows/`:

- `ci.yml`
  - Python matrix validation on `3.10` through `3.14`
  - release version consistency check
  - `compileall` pass
  - full test suite
  - Windows CLI smoke test
  - package build and `twine check`

- `Release Validation` (`release.yml`)
  - pre-release validation
  - build `sdist` and `wheel`
  - collect artifacts for review

- `PyPI Publish` (`workflow.yml`)
  - manual publish step
  - target selection for TestPyPI or PyPI
  - trusted publishing via OIDC

## Security Notes

- Keep `.tskey`, `.vault`, `.tshard`, and `.mfa` files out of version control.
- Revocation is enforced at use-time, not just as metadata.
- Expired keys can still be inspected, but they cannot be used.
- Use `verify` before opening untrusted vaults.
- Treat Git hook automation as a protection layer, not a trust boundary.

## Project Structure

```text
trueseal/
├── commands/   # CLI command implementations
├── crypto/     # Key generation, ciphers, MFA, sharing, zeroization
├── ui/         # CLI styling, prompts, REPL helpers
├── utils/      # Logger and helper utilities
└── vault/      # Seal/open, policy, manifest, and steganography logic
```

## Development Workflow

```powershell
python scripts/check_release_state.py
pytest -q tests
python -m compileall trueseal
```

## Contributing

1. Create a virtual environment.
2. Run the full test suite before opening a pull request.
3. Keep changes focused, documented, and aligned with the existing CLI contract.

## Versioning

Keep `pyproject.toml` and `trueseal/__init__.py::__version__` in sync. The release check is enforced by `scripts/check_release_state.py`.
