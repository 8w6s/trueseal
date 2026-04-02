import click
import shlex
import sys
from rich.console import Console
from .styling import UIStyle, UITheme

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter, PathCompleter
from prompt_toolkit.history import DummyHistory
from prompt_toolkit.formatted_text import HTML

console = Console()

class TrueSealREPL:
    """Interactive shell for TrueSeal."""
    
    def __init__(self, cli_group):
        self.cli_group = cli_group
        self.context = {}
        self.is_interactive_terminal = sys.stdin.isatty() and sys.stdout.isatty()
        
        self.commands = list(getattr(self.cli_group, 'COMMANDS', {}).keys())
        if not self.commands:
            self.commands = list(self.cli_group.commands.keys())
            
        comp_dict = {
            'help': None,
            'exit': None,
            'quit': None
        }
        for cmd in self.commands:
            comp_dict[cmd] = PathCompleter(expanduser=True)
            
        self.completer = NestedCompleter.from_nested_dict(comp_dict)
            
        self.session = PromptSession(
            history=DummyHistory(),
            completer=self.completer,
            complete_while_typing=True
        )

    def welcome(self):
        console.print()
        welcome_banner = f"""
[{UITheme.PRIMARY}]TrueSeal Interactive Shell[/{UITheme.PRIMARY}]
[{UITheme.SECONDARY}]Enterprise-grade source code protection[/{UITheme.SECONDARY}]
[{UITheme.MUTED}]Type 'help' for cmds, 'exit', 'quit' or Ctrl+D to leave.[/{UITheme.MUTED}]
"""
        console.print(welcome_banner)

    def run(self):
        if not self.is_interactive_terminal:
            raise click.ClickException("Interactive REPL requires a TTY terminal.")

        click.clear()
        self.welcome()
        
        while True:
            try:
                raw_input = self.session.prompt(HTML("<ansigreen>trueseal:</ansigreen> "))
                cmd_line = raw_input.strip()
                
                if cmd_line == '\x04' or '\x04' in cmd_line or cmd_line.upper() == '^D':
                    break
                
                if not cmd_line:
                    continue
                
                if cmd_line.lower() in ('exit', 'quit'):
                    break
                
                try:
                    args = shlex.split(cmd_line)
                except ValueError as e:
                    UIStyle.error(f"Invalid syntax: {e}")
                    continue
                
                if args and args[0].lower() == 'help':
                    args = ['--help']
                
                try:
                    self.cli_group.main(args=args, prog_name="trueseal", standalone_mode=False)
                except click.UsageError as e:
                    UIStyle.error(f"Usage Error: {e.format_message()}")
                except click.ClickException as e:
                    UIStyle.error(e.format_message())
                except click.Abort:
                    console.print(f"[{UITheme.WARNING}]Aborted[/{UITheme.WARNING}]")
                except SystemExit as e:
                    exit_code = e.code
                    if isinstance(exit_code, int) and exit_code != 0:
                        UIStyle.error(f"Command failed with exit code {exit_code}")
                except Exception as e:
                    console.print_exception(show_locals=False)
                    UIStyle.error(f"Unexpected error: {e}")
                    
            except KeyboardInterrupt:
                console.print(f"\n[{UITheme.WARNING}]KeyboardInterrupt - press Ctrl+D or type 'exit' to quit[/{UITheme.WARNING}]")
                continue
            except EOFError:
                break
                
        console.print(f"\n[{UITheme.PRIMARY}]Goodbye![/{UITheme.PRIMARY}]")

def launch_repl(cli_group):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise click.ClickException("Interactive REPL requires a TTY terminal.")

    repl = TrueSealREPL(cli_group)
    repl.run()