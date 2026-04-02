import logging
from rich.logging import RichHandler
from ..ui.styling import console


def configure_trueseal_logger(verbose=False, quiet=False):
    """
    Configure TrueSeal application logger using RichHandler.
    
    Log levels:
    - quiet=True: CRITICAL only
    - verbose=True: DEBUG (all messages)
    - else: WARNING (errors + important info)
    
    Args:
        verbose: Enable DEBUG level logging
        quiet: Suppress all but critical errors
    """
    level = logging.WARNING
    if quiet:
        level = logging.CRITICAL
    elif verbose:
        level = logging.DEBUG
    
    logger = logging.getLogger('trueseal')
    logger.setLevel(level)
    
    # Remove existing handlers to prevent duplicates
    if logger.hasHandlers():
        logger.handlers.clear()
        
    # Prevent propagation to root logger
    logger.propagate = False
    
    # Add RichHandler
    handler = RichHandler(console=console, rich_tracebacks=True, show_path=False)
    handler.setLevel(level)
    
    # Set formatting (RichHandler handles most formatting, but we can set basic message structure)
    formatter = logging.Formatter("%(message)s", datefmt="[%X]")
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
