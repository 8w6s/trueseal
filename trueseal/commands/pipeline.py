"""
TrueSeal Command: DevOps Pipeline Integration

Configures TrueSeal for automated CI/CD workflows. Manages key sources
(AWS KMS, HashiCorp Vault) and sets up secure credential injection
for GitHub Actions, GitLab CI, and other CI platforms.

This command bridges TrueSeal with enterprise deployment pipelines,
ensuring keys are never hardcoded in repositories while maintaining
seamless encrypt/decrypt operations during build stages.
"""

import click
from pathlib import Path
from ..ui.styling import UIStyle, console
from rich.panel import Panel
from rich.table import Table

@click.command()
@click.argument('action', type=click.Choice(['init', 'status', 'remove', 'test']))
@click.option('-c', '--ci-provider', 
              type=click.Choice(['github-actions', 'gitlab-ci', 'github', 'gitlab']),
              help='CI platform (github-actions, gitlab-ci, etc.)')
@click.option('-s', '--key-source',
              type=click.Choice(['aws-kms', 'vault', 'local', 'env']),
              default='local',
              help='Where to fetch encryption keys')
@click.option('--key-path', help='Key location path or KMS ARN')
@click.option('--role-arn', help='AWS IAM role for OIDC federation')
@click.option('--vault-addr', help='HashiCorp Vault server address')
@click.option('--vault-path', help='Vault secret path')
@click.option('--output-dir', default='.trueseal/pipeline', help='Pipeline config output')
@click.pass_context
def cmd(ctx, action, ci_provider, key_source, key_path, role_arn, vault_addr, vault_path, output_dir):
    """
    DevOps Pipeline Integration for TrueSeal

    Configure TrueSeal to work with CI/CD platforms. Automates key management
    and secure secret injection for automated builds and deployments.
    
    [WARNING]: Output workflows are experimental. They rely on piping external
    secrets provider outputs to TrueSeal via `trueseal seal . --key -`.

    Examples:
      trueseal pipeline init --ci-provider=github-actions --key-source=aws-kms
      trueseal pipeline status
      trueseal pipeline test
    """
    quiet = ctx.obj.get('quiet', False)
    verbose = ctx.obj.get('verbose', False)
    config_dir = Path(output_dir)

    if action == 'init':
        _initialize_pipeline(
            ci_provider, key_source, key_path, role_arn, vault_addr,
            vault_path, config_dir, quiet, verbose
        )
    elif action == 'status':
        _check_pipeline_status(config_dir, quiet)
    elif action == 'remove':
        _remove_pipeline_config(config_dir, quiet)
    elif action == 'test':
        _test_pipeline_connection(key_source, key_path, role_arn, vault_addr, quiet)


def _initialize_pipeline(ci_provider, key_source, key_path, role_arn, vault_addr,
                        vault_path, config_dir, quiet, verbose):
    """
    Initialize pipeline configuration for selected CI platform and key source.

    Sets up necessary environment files, GitHub Actions workflows, or GitLab
    CI configurations depending on platform choice.
    """
    if not ci_provider:
        raise click.ClickException("--ci-provider is required for pipeline init")

    config_dir.mkdir(parents=True, exist_ok=True)

    if ci_provider in ['github', 'github-actions']:
        _setup_github_actions(key_source, key_path, role_arn, vault_addr,
                             vault_path, config_dir, quiet)
    elif ci_provider in ['gitlab', 'gitlab-ci']:
        _setup_gitlab_ci(key_source, key_path, vault_addr, vault_path,
                        config_dir, quiet)

    if not quiet:
        console.print(Panel(
            f"Pipeline initialized for [bold]{ci_provider}[/bold]\n"
            f"Key source: [bold]{key_source}[/bold]\n"
            f"Config directory: [bold]{config_dir}[/bold]",
            title="[bold green]Pipeline Configuration Complete[/bold green]",
            border_style="green"
        ))


def _setup_github_actions(key_source, key_path, role_arn, vault_addr,
                         vault_path, config_dir, quiet):
    """
    Configure GitHub Actions workflow for TrueSeal integration.

    Supports OIDC federation (keyless auth with AWS) or environment secrets.
    """
    workflow_dir = config_dir.parent / '.github' / 'workflows'
    workflow_dir.mkdir(parents=True, exist_ok=True)

    if key_source == 'aws-kms':
        if not role_arn:
            raise click.ClickException("--role-arn required for AWS KMS integration")
        workflow_content = _generate_github_aws_kms_workflow(role_arn, key_path)
    elif key_source == 'vault':
        if not vault_addr:
            raise click.ClickException("--vault-addr required for Vault integration")
        workflow_content = _generate_github_vault_workflow(vault_addr, vault_path)
    else:
        workflow_content = _generate_github_local_workflow(key_path)

    workflow_file = workflow_dir / 'trueseal-seal.yml'
    workflow_file.write_text(workflow_content, encoding='utf-8')

    if not quiet:
        console.print(f"[cyan]GitHub Actions workflow created: {workflow_file}[/cyan]")


def _setup_gitlab_ci(key_source, key_path, vault_addr, vault_path, config_dir, quiet):
    """
    Configure GitLab CI pipeline for TrueSeal integration.

    Leverages GitLab's protected variables and runner authentication.
    """
    gitlab_ci_content = _generate_gitlab_ci_config(key_source, key_path, vault_addr, vault_path)
    gitlab_ci_file = Path.cwd() / '.gitlab-ci.yml'
    gitlab_ci_file.write_text(gitlab_ci_content, encoding='utf-8')

    if not quiet:
        console.print(f"[cyan]GitLab CI configuration created: {gitlab_ci_file}[/cyan]")


def _generate_github_aws_kms_workflow(role_arn, key_path):
    """
    Generate GitHub Actions workflow with AWS KMS OIDC federation.

    Uses GitHub's OIDC provider for keyless authentication to AWS.
    """
    return f"""name: TrueSeal Seal with AWS KMS

on:
  push:
    branches: [main, develop]

permissions:
  id-token: write
  contents: read

jobs:
  seal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: {role_arn}
          aws-region: us-east-1
      
      - name: Install TrueSeal
        run: pip install -e .
      
      - name: Seal codebase
        run: |
          set +x
          aws kms decrypt --ciphertext-blob fileb://{key_path or 'encrypted_key.bin'} --output text --query Plaintext | base64 --decode | trueseal seal . --key -
          set -x
      
      - name: Commit sealed vault
        run: |
          git config user.name "TrueSeal Bot"
          git config user.email "trueseal@bot.local"
          git add .vault
          git commit -m "Automated seal: ${{{{ github.sha }}}} [skip ci]"
          git push
"""

def _generate_github_vault_workflow(vault_addr, vault_path):
    """
    Generate GitHub Actions workflow with HashiCorp Vault integration.

    Fetches secrets from Vault using JWT authentication.
    """
    return f"""name: TrueSeal Seal with Vault

on:
  push:
    branches: [main, develop]

jobs:
  seal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Fetch secret from Vault
        uses: hashicorp/vault-action@v2
        with:
          url: {vault_addr}
          path: {vault_path or 'secret/data/trueseal'}
          method: jwt
          jwtGithubAudience: '${{ secrets.VAULT_ADDR }}'
          secrets: |
            - path: secret/data/trueseal
              key: encryption-key
      
      - name: Install TrueSeal
        run: pip install -e .
      
      - name: Seal codebase
        env:
          TRUESEAL_KEY: ${{{{ steps.vault.outputs.encryption-key }}}}
        run: |
          set +x
          printenv TRUESEAL_KEY | trueseal seal . --key -
          unset TRUESEAL_KEY
          set -x
"""


def _generate_github_local_workflow(key_path):
    """
    Generate GitHub Actions workflow with local key storage.

    Uses GitHub repository secrets for key storage (less secure, for demo only).
    """
    return """name: TrueSeal Seal (Local Key)

on:
  push:
    branches: [main, develop]

jobs:
  seal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install TrueSeal
        run: pip install -e .
      
      - name: Seal codebase
        env:
          TRUESEAL_KEY_B64: ${{{{ secrets.TRUESEAL_KEY_B64 }}}}
        run: |
          set +x
          printenv TRUESEAL_KEY_B64 | base64 -d | trueseal seal . --key -
          unset TRUESEAL_KEY_B64
          set -x
          git config user.name "TrueSeal Bot"
          git config user.email "trueseal@bot.local"
          git add .vault
          git commit -m "Automated seal: ${{{{ github.sha }}}}"
          git push
"""

def _generate_gitlab_ci_config(key_source, key_path, vault_addr, vault_path):
    """
    Generate GitLab CI configuration.

    Uses GitLab's protected variables and CI tokens for authentication.
    """
    if key_source == 'vault':
        vault_config = f"""
  secrets:
    VAULT_ADDR: {vault_addr}
    VAULT_PATH: {vault_path or 'secret/trueseal'}
"""
    else:
        vault_config = ""

    return f"""stages:
  - seal

seal_vault:
  stage: seal
  image: python:3.11-slim
  {vault_config}
  script:
    - set +x
    - pip install -e .
    - cat $TRUESEAL_KEY_FILE | trueseal seal . --key -
    - shred -u $TRUESEAL_KEY_FILE || rm -f $TRUESEAL_KEY_FILE
    - set -x
    - git config user.name "TrueSeal Bot"
    - git config user.email "trueseal@bot.local"
    - git add .vault
    - git commit -m "Automated seal: $CI_COMMIT_SHA [skip ci]"
    - git push https://oauth2:$CI_JOB_TOKEN@$CI_SERVER_HOST/$CI_PROJECT_PATH.git HEAD:$CI_COMMIT_BRANCH
  only:
    - main
    - develop
"""


def _check_pipeline_status(config_dir, quiet):
    """
    Check if pipeline configuration is properly set up.

    Validates existence of configuration files and required dependencies.
    """
    if not config_dir.exists():
        if not quiet:
            console.print("[yellow]No pipeline configuration found.[/yellow]")
        return

    table = Table(title="Pipeline Configuration Status")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="magenta")

    github_workflow = config_dir.parent / '.github' / 'workflows' / 'trueseal-seal.yml'
    gitlab_ci = config_dir.parent / '.gitlab-ci.yml'

    if github_workflow.exists():
        table.add_row("GitHub Actions", "[green]Installed[/green]")
    else:
        table.add_row("GitHub Actions", "[yellow]Not configured[/yellow]")

    if gitlab_ci.exists():
        table.add_row("GitLab CI", "[green]Installed[/green]")
    else:
        table.add_row("GitLab CI", "[yellow]Not configured[/yellow]")

    if not quiet:
        console.print(table)


def _remove_pipeline_config(config_dir, quiet):
    """
    Remove pipeline configuration from repository.

    Cleans up workflow files and configuration directories.
    """
    import shutil

    if config_dir.exists():
        shutil.rmtree(config_dir)

    github_workflow = Path.cwd() / '.github' / 'workflows' / 'trueseal-seal.yml'
    if github_workflow.exists():
        github_workflow.unlink()

    gitlab_ci = Path.cwd() / '.gitlab-ci.yml'
    if gitlab_ci.exists():
        gitlab_ci.unlink()

    if not quiet:
        console.print("[green]Pipeline configuration removed[/green]")


def _test_pipeline_connection(key_source, key_path, role_arn, vault_addr, quiet):
    """
    Test pipeline connectivity and key source access.

    Validates that configured key sources are reachable and functional.
    """
    if key_source == 'aws-kms':
        if not role_arn:
            raise click.ClickException("--role-arn required for AWS KMS test")
        try:
            import boto3
            client = boto3.client('sts')
            client.assume_role(RoleArn=role_arn, RoleSessionName='TrueSealTest')
            identity = client.get_caller_identity()
            if not quiet:
                console.print("[green]AWS KMS: Connected[/green]")
                console.print(f"Account: {identity['Account']}")
        except ImportError:
            raise click.ClickException("AWS KMS test failed: 'boto3' library not installed. Please run: pip install boto3")
        except Exception as e:
            raise click.ClickException(f"AWS KMS test failed: {e}")

    elif key_source == 'vault':
        if not vault_addr:
            raise click.ClickException("--vault-addr required for Vault test")
        try:
            import hvac
            client = hvac.Client(url=vault_addr)
            client.is_authenticated()
            if not quiet:
                console.print("[green]HashiCorp Vault: Connected[/green]")
        except ImportError:
            raise click.ClickException("Vault test failed: 'hvac' library not installed. Please run: pip install hvac")
        except Exception as e:
            raise click.ClickException(f"Vault test failed: {e}")

    else:
        if not quiet:
            console.print("[green]Local key source: Ready[/green]")
