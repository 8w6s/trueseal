"""
TrueSeal Command Decorators

Provides consistent command styling and error handling across all CLI commands.
Ensures uniform UX/UI across the entire TrueSeal system.
"""

from functools import wraps
import click
from .styling import UIStyle, console


def styled_command(style_tag: str = "cmd"):
    """Decorator to add consistent styling to TrueSeal commands
    
    Usage:
        @styled_command("vault")
        @click.command()
        def my_cmd():
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except click.ClickException:
                raise
            except KeyboardInterrupt:
                console.print("\n[bold red]Interrupted by user[/bold red]")
                raise SystemExit(130)
            except Exception as e:
                UIStyle.panel_error("Command Failed", str(e))
                raise SystemExit(1)
        return wrapper
    return decorator


def with_progress(description: str = "Processing"):
    """Wrapper to add progress bar to long-running operations
    
    Usage:
        @with_progress("Encrypting files")
        def encrypt_files(files):
            for f in files:
                yield f  # Progress updates on each yield
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Progress bar handling
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_key(auto_discover=True):
    """Decorator to enforce key file requirement
    
    Auto-discovers .tskey in current directory if enabled.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            from pathlib import Path
            
            key = kwargs.get('key') or args[-1] if args else None
            
            if not key and auto_discover:
                keys = list(Path('.').glob('*.tskey'))
                if len(keys) == 1:
                    kwargs['key'] = str(keys[0])
                    UIStyle.subheader(f"Auto-discovered key: {Path(keys[0]).name}")
                elif len(keys) > 1:
                    raise click.UsageError(f"Found {len(keys)} key files. Please specify one with -k")
                else:
                    raise click.UsageError("No key file found. Use -k to specify")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def interactive_mode_handler(supported: list = None):
    """Decorator to handle interactive mode prompts
    
    Converts command-line options to interactive prompts if -i flag is set.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            interactive = kwargs.get('interactive', False)
            
            if interactive:
                from .styling import InteractivePrompts
                # Placeholder for interactive mode handling
                pass
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

