"""
TrueSeal CLI UI Styling Module

Provides consistent, beautiful formatting for all CLI output.
Uses Rich library for colors, tables, panels, and formatting.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.prompt import Prompt, Confirm
import sys

console = Console(force_terminal=sys.stdout.isatty(), color_system="auto")


class UITheme:
    """Global color theme for TrueSeal"""
    PRIMARY = "bold green"           # Primary actions/headers
    ACCENT = "bold light_green"      # Success/completed
    SECONDARY = "cyan"               # Secondary info
    WARNING = "bold yellow"          # Warnings
    DANGER = "bold red"              # Errors/critical
    MUTED = "dim"                    # Less important
    HIGHLIGHT = "bold magenta"       # Key values
    
    BORDER_SUCCESS = "light_green"
    BORDER_ERROR = "red"
    BORDER_INFO = "cyan"
    BORDER_WARNING = "yellow"


class TrueSealSpinner_Old:
    """A sleek, modern spinner mimicking high-end CLI tools."""
    
    def __init__(self, text="Processing..."):
        self.text = text
        self.status = console.status(
            f"[{UITheme.PRIMARY}]{self.text}[/{UITheme.PRIMARY}]",
            spinner="dots",
            spinner_style=UITheme.SECONDARY
        )

    def __enter__(self):
        self.status.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.status.stop()

    def update(self, text):
        """Update the spinner text"""
        self.text = text
        self.status.update(f"[{UITheme.PRIMARY}]{self.text}[/{UITheme.PRIMARY}]")

class UIStyle:
    """Centralized UI styling for TrueSeal CLI"""

    HEADER = UITheme.PRIMARY
    SUCCESS = UITheme.ACCENT
    ERROR = UITheme.DANGER
    WARNING = UITheme.WARNING
    INFO = UITheme.SECONDARY
    MUTED = UITheme.MUTED
    ACCENT = UITheme.HIGHLIGHT

    @staticmethod
    def header(text: str) -> None:
        """Display main header"""
        console.print()
        console.print(f"[{UIStyle.HEADER}]{text}[/{UIStyle.HEADER}]")
        console.print(f"[{UIStyle.MUTED}]{'─' * min(64, len(text) + 6)}[/{UIStyle.MUTED}]")

    @staticmethod
    def subheader(text: str) -> None:
        """Display subheader"""
        console.print(f"[{UITheme.SECONDARY}]{text}[/{UITheme.SECONDARY}]")

    @staticmethod
    def success(text: str) -> None:
        """Display success message"""
        console.print(f"[{UIStyle.SUCCESS}][SUCCESS][/{UIStyle.SUCCESS}] {text}")

    @staticmethod
    def error(text: str) -> None:
        """Display error message"""
        console.print(f"[{UIStyle.ERROR}][ERROR][/{UIStyle.ERROR}] {text}")

    @staticmethod
    def warning(text: str) -> None:
        """Display warning message"""
        console.print(f"[{UIStyle.WARNING}][WARN][/{UIStyle.WARNING}] {text}")

    @staticmethod
    def info(text: str) -> None:
        """Display info message"""
        console.print(f"[{UIStyle.INFO}][INFO][/{UIStyle.INFO}] {text}")

    @staticmethod
    def debug(text: str) -> None:
        """Display debug message"""
        console.print(f"[{UIStyle.MUTED}][DEBUG][/{UIStyle.MUTED}] {text}")

    @staticmethod
    def panel_success(title: str, content: str) -> None:
        """Display success panel"""
        panel = Panel(
            content,
            title=f"[{UIStyle.SUCCESS}]{title}[/{UIStyle.SUCCESS}]",
            border_style=UITheme.BORDER_SUCCESS,
            expand=False,
            padding=(1, 2)
        )
        console.print(panel)

    @staticmethod
    def panel_error(title: str, content: str) -> None:
        """Display error panel"""
        panel = Panel(
            content,
            title=f"[{UIStyle.ERROR}]{title}[/{UIStyle.ERROR}]",
            border_style=UITheme.BORDER_ERROR,
            expand=False,
            padding=(1, 2)
        )
        console.print(panel)

    @staticmethod
    def panel_info(title: str, content: str) -> None:
        """Display info panel"""
        panel = Panel(
            content,
            title=f"[{UIStyle.INFO}]{title}[/{UIStyle.INFO}]",
            border_style=UITheme.BORDER_INFO,
            expand=False,
            padding=(1, 2)
        )
        console.print(panel)

    @staticmethod
    def panel_warning(title: str, content: str) -> None:
        """Display warning panel"""
        panel = Panel(
            content,
            title=f"[{UIStyle.WARNING}]{title}[/{UIStyle.WARNING}]",
            border_style=UITheme.BORDER_WARNING,
            expand=False,
            padding=(1, 2)
        )
        console.print(panel)


    @staticmethod
    def table_properties(title: str = None) -> Table:
        """Create property table with consistent styling"""
        table = Table(
            title=title,
            show_header=True,
            header_style=f"{UIStyle.HEADER}",
            border_style=UITheme.BORDER_SUCCESS,
            box=box.ROUNDED,
            padding=(0, 1),
            expand=False
        )
        table.add_column("Property", style="bold light_green", width=20)
        table.add_column("Value", style="white")
        return table

    @staticmethod
    def table_list(title: str = None) -> Table:
        """Create list table"""
        table = Table(
            title=title,
            show_header=True,
            header_style=f"{UIStyle.HEADER}",
            border_style=UITheme.BORDER_SUCCESS,
            box=box.ROUNDED,
            padding=(0, 1)
        )
        return table

    @staticmethod
    def progress_start(task: str) -> None:
        """Display task start"""
        console.print(f"[{UIStyle.INFO}]{task}...[/{UIStyle.INFO}]")

    @staticmethod
    def progress_complete(task: str) -> None:
        """Display task completion"""
        console.print(f"[{UIStyle.SUCCESS}]{task} complete[/{UIStyle.SUCCESS}]")

    @staticmethod
    def badge(label: str, value: str, style: str = "cyan") -> str:
        """Create inline badge"""
        return f"[bold {style}]{label}[/bold {style}] {value}"

    @staticmethod
    def highlight(text: str, style: str = "yellow") -> str:
        """Highlight text"""
        return f"[{style}]{text}[/{style}]"

    @staticmethod
    def muted(text: str) -> str:
        """Muted text"""
        return f"[dim]{text}[/dim]"

    @staticmethod
    def separator() -> None:
        """Display separator line"""
        console.print("[dim]" + "─" * 60 + "[/dim]")


class InteractivePrompts:
    """Methods that require user interaction"""

    @staticmethod
    def ask_confirm(prompt_text: str, default: bool = False) -> bool:
        """Ask for confirmation with styled prompt"""
        return Confirm.ask(
            f"[{UITheme.PRIMARY}]>[/{UITheme.PRIMARY}] {prompt_text}",
            default=default
        )

    @staticmethod
    def ask_text(prompt_text: str, default: str = "", password: bool = False) -> str:
        """Ask for text input with styled prompt"""
        return Prompt.ask(
            f"[{UITheme.PRIMARY}]>[/{UITheme.PRIMARY}] {prompt_text}",
            default=default,
            password=password
        )

    @staticmethod
    def ask_choice(prompt_text: str, choices: list, default: int = 0) -> str:
        """Ask to choose from a list of options"""
        from rich.prompt import Prompt
        console.print(f"[{UITheme.PRIMARY}]>[/{UITheme.PRIMARY}] {prompt_text}")
        for i, choice in enumerate(choices):
            console.print(f"  [cyan]{i+1}.[/cyan] {choice}")
            
        choice_idx = Prompt.ask(
            "Select option",
            choices=[str(i+1) for i in range(len(choices))],
            default=str(default+1)
        )
        return choices[int(choice_idx)-1]

    @staticmethod
    def show_progress(description: str, total: int = 100):
        """Create styled progress bar"""
        return Progress(
            SpinnerColumn(),
            TextColumn(f"[{UITheme.SECONDARY}]{{task.description}}[/{UITheme.SECONDARY}]"),
            BarColumn(bar_width=30, style=UITheme.BORDER_SUCCESS),
            TextColumn(f"[{UITheme.ACCENT}]{{task.percentage:>3.0f}}%[/{UITheme.ACCENT}]"),
            console=console
        )

    @staticmethod
    def auto_discover_key_interactive(quiet: bool = False) -> str:
        """
        Discover a key automatically using pure helpers, then confirm with the user.
        Raises click.UsageError if no keys, multiple keys, or user aborts.
        """
        import click
        from ..utils.helpers import auto_discover_key
        try:
            key_path = auto_discover_key()
        except Exception as e:
            raise click.UsageError(str(e))
        
        if not quiet:
            from rich.prompt import Confirm
            UIStyle.warning(f"Auto-discovered key '{key_path}' in current directory. Ensure this is the intended key.")
            if not Confirm.ask("Do you want to continue with this key?"):
                raise click.Abort()
        return key_path


def create_key_info_panel(key_data: dict) -> Panel:
    """
    Create formatted key information panel

    Args:
        key_data: Dictionary with key properties

    Returns:
        Panel with formatted key info
    """
    content_lines = []

    for key, value in key_data.items():
        if value is None:
            value = "[dim](None)[/dim]"
        elif isinstance(value, bool):
            value = "[light_green]Yes[/light_green]" if value else "[red]No[/red]"

        content_lines.append(f"{key.replace('_', ' ').title():.<25} {value}")

    content = "\n".join(content_lines)

    return Panel(
        content,
        border_style=UITheme.BORDER_SUCCESS,
        padding=(1, 2),
        expand=False
    )


def create_file_info_panel(filepath: str, size: int = None, hash_val: str = None) -> Panel:
    """
    Create formatted file information panel

    Args:
        filepath: Path to file
        size: File size in bytes
        hash_val: File hash

    Returns:
        Panel with formatted file info
    """
    content = f"[cyan]File:[/cyan] [yellow]{filepath}[/yellow]\n"

    if size:
        size_mb = size / (1024 * 1024)
        content += f"[cyan]Size:[/cyan] [light_green]{size_mb:.2f} MB[/light_green]\n"

    if hash_val:
        content += f"[cyan]SHA256:[/cyan] [magenta]{hash_val}[/magenta]"

    return Panel(
        content.strip(),
        border_style=UITheme.BORDER_SUCCESS,
        padding=(1, 2),
        expand=False
    )

class TrueSealProgress:
    """High-fidelity progress UI tuned for REPL/CLI workloads."""

    def __init__(self):
        self.progress = Progress(
            SpinnerColumn("bouncingBar", style=UITheme.HIGHLIGHT),
            TextColumn(f"[{UITheme.PRIMARY}]{{task.description}}"),
            BarColumn(bar_width=38, complete_style=UITheme.ACCENT, finished_style=UITheme.PRIMARY),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        )

    def __enter__(self):
        self.progress.start()
        return self.progress

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.progress.stop()


class TrueSealSpinner:
    """Compatibility wrapper for existing command flow that expects spinner.update()."""

    def __init__(self, text="Processing..."):
        self._progress_adapter = TrueSealProgress()
        self._task_id = None
        self._text = text
        self._progress = None

    def __enter__(self):
        self._progress = self._progress_adapter.__enter__()
        self._task_id = self._progress.add_task(self._text, total=100)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._progress_adapter.__exit__(exc_type, exc_val, exc_tb)

    def update(self, text):
        if self._task_id is not None:
            self._progress.update(self._task_id, description=text)
