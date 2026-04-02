import click
import sys
import importlib
from .utils.logger import configure_trueseal_logger
from .ui.styling import UIStyle, console
from .ui.styling import UITheme as _UITheme

UITheme = _UITheme

# Lazy-load command modules so help/version stays fast.
class LazyLoaderGroup(click.Group):
    COMMANDS = {
        'keygen': 'keygen',
        'env': 'env',
        'seal': 'seal',
        'open': 'open_vault',
        'shard': 'shard',
        'cloak': 'cloak',
        'git': 'git',
        'duress': 'duress',
        'mfa': 'mfa',
        'inspect': 'inspect',
        'verify': 'verify',
        'merge': 'merge',
        'pipeline': 'pipeline',
        'revoke': 'revoke',
        'version': 'version',
        'demo': 'demo',
        'internal-hook': 'internal_hook'
    }

    @staticmethod
    def _build_broken_command(cmd_name, error_message):
        @click.command(name=cmd_name, help=f"Command '{cmd_name}' is unavailable due to an internal load error.")
        def _broken_cmd():
            raise click.ClickException(error_message)

        return _broken_cmd

    def get_command(self, ctx, cmd_name):
        if cmd_name not in self.COMMANDS:
            return super().get_command(ctx, cmd_name)
        mod_name = self.COMMANDS[cmd_name]
        qualified_module_name = f'trueseal.commands.{mod_name}'
        try:
            mod = importlib.import_module(f'.commands.{mod_name}', package='trueseal')
            return mod.cmd
        except ModuleNotFoundError as e:
            if e.name == qualified_module_name:
                return self._build_broken_command(
                    cmd_name,
                    f"Command '{cmd_name}' is not available in this build ({qualified_module_name} is missing)."
                )
            return self._build_broken_command(
                cmd_name,
                f"Command '{cmd_name}' failed to load due to a missing dependency: {e}"
            )
        except AttributeError:
            return self._build_broken_command(
                cmd_name,
                f"Command '{cmd_name}' is misconfigured: expected attribute 'cmd' was not found."
            )
        except ImportError as e:
            return self._build_broken_command(
                cmd_name,
                f"Command '{cmd_name}' failed to import: {e}"
            )

    def list_commands(self, ctx):
        base_cmds = super().list_commands(ctx)
        return sorted(set(list(self.COMMANDS.keys()) + base_cmds))

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(cls=LazyLoaderGroup, context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
@click.option('-q', '--quiet', is_flag=True, help='Suppress output')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('-c', '--config', type=click.Path(), help='Config file path')
@click.option('--profile', default='default', help='Profile (dev/prod/custom)')
@click.pass_context
def cli(ctx, verbose, quiet, no_color, config, profile):
    """
    TrueSeal - Enterprise-grade source code protection
    
    Features:
      * AES-256-GCM + ChaCha20-Poly1305 encryption
      * Shamir's Secret Sharing for key distribution
      * Duress mode for anti-coercion protection
      * Steganography (hide vault in images)
      * TOTP/Authenticator App MFA Support
      * Git hooks automation
    
    Examples:
      trueseal keygen                        Generate a new key
      trueseal seal ./my-project --key app.tskey  Encrypt project
      trueseal open ./my-project.vault --key app.tskey  Decrypt
      trueseal cloak vault.sealed --cover img.png  Hide in image
    
    For more info: https://github.com/8w6s/trueseal
    """
    if verbose and quiet:
        raise click.UsageError("Cannot use both --verbose (-v) and --quiet (-q) at the same time.")

    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    ctx.obj['no_color'] = no_color
    ctx.obj['config'] = config
    ctx.obj['profile'] = profile
    configure_trueseal_logger(verbose, quiet)
    
    # Only open REPL for interactive terminals to avoid hanging CI/scripts.
    if ctx.invoked_subcommand is None:
        is_interactive_terminal = sys.stdin.isatty() and sys.stdout.isatty()
        if is_interactive_terminal:
            from .ui.repl import launch_repl
            launch_repl(cli)
        else:
            click.echo(ctx.get_help())


@click.command(hidden=True)
def completion():
    """Generate shell completion script instructions"""
    console.print(
        "To enable autocompletion, run the following command for your shell:\n\n"
        "  Bash: eval \"$(_TRUESEAL_COMPLETE=bash_source trueseal)\"\n"
        "  Zsh:  eval \"$(_TRUESEAL_COMPLETE=zsh_source trueseal)\"\n"
        "  Fish: eval \"$(_TRUESEAL_COMPLETE=fish_source trueseal)\"\n"
    )
cli.add_command(completion, name='completion')


def main():
    try:

        cli(obj={})
    except KeyboardInterrupt:
        UIStyle.error('Interrupted by user')
        sys.exit(130)

if __name__ == '__main__':
    main()
