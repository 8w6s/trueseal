import click
import sys
import platform
from importlib.metadata import PackageNotFoundError, version as pkg_version
from ..ui.styling import console, UITheme


def get_version():
    try:
        return pkg_version("trueseal")
    except PackageNotFoundError:
        from .. import __version__
        return __version__


@click.command()
@click.pass_context
def cmd(ctx):
    """Show TrueSeal version information"""
    quiet = ctx.obj.get('quiet', False)
    
    # Just skip mascot, no flag check needed
    
    if quiet:
        click.echo(get_version())
    else:
        v = get_version()
        py_ver = sys.version.split(' ')[0]
        os_info = platform.system() + " " + platform.release()
        
        console.print(f"[{UITheme.PRIMARY}]TrueSeal[/{UITheme.PRIMARY}] v{v}")
        console.print(f"[{UITheme.MUTED}]Python {py_ver} on {os_info}[/{UITheme.MUTED}]")
