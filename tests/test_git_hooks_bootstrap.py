import os
import subprocess
from pathlib import Path


def test_git_init_generates_python_bootstrap_hooks(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    git_init = subprocess.run(["git", "init", str(repo)], capture_output=True, text=True, check=False)
    if git_init.returncode != 0:
        import pytest
        pytest.skip("git binary unavailable in test environment")

    cmd = ["python", "-m", "trueseal", "git", "init", "--repo", str(repo)]
    result = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True, check=False)
    assert result.returncode == 0

    pre_hook = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    post_hook = (repo / ".git" / "hooks" / "post-checkout").read_text(encoding="utf-8")

    assert "internal-hook pre-commit" in pre_hook
    assert "internal-hook post-checkout" in post_hook
    assert "run_trueseal" not in pre_hook


def test_internal_hook_pre_commit_no_changes_exits_clean(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    if subprocess.run(["git", "init", str(repo)], capture_output=True, text=True, check=False).returncode != 0:
        import pytest
        pytest.skip("git binary unavailable in test environment")

    key_path = repo / "auto.tskey"
    key_path.write_text("{}", encoding="utf-8")

    env = os.environ.copy()
    env["TRUESEAL_KEY_PATH"] = str(key_path)

    result = subprocess.run(
        ["python", "-m", "trueseal", "internal-hook", "pre-commit", "--repo", str(repo)],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0
    assert "No staged file changes detected for sealing" in result.stdout

