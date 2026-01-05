"""
Logging infrastructure for the SOCKS5 proxy scanner.

Provides:
- Structured logging with levels (DEBUG/INFO/WARN/ERROR)
- Console and file handlers
- Colored output for terminals
- JSON logging for machine parsing
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


# =============================================================================
# ANSI Colors
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_CYAN = "\033[96m"

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY or Windows without ANSI support)."""
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper():
                setattr(cls, attr, '')


# =============================================================================
# Custom Formatters
# =============================================================================

class ColoredFormatter(logging.Formatter):
    """Formatter with colored output for terminals."""

    LEVEL_COLORS = {
        logging.DEBUG: Colors.DIM + Colors.CYAN,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.BOLD + Colors.RED,
    }

    def __init__(self, fmt: str = None, datefmt: str = None, use_colors: bool = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            color = self.LEVEL_COLORS.get(record.levelno, Colors.RESET)
            record.levelname = f"{color}{record.levelname:<7}{Colors.RESET}"
            record.name = f"{Colors.DIM}{record.name}{Colors.RESET}"

        return super().format(record)


class JSONFormatter(logging.Formatter):
    """Formatter that outputs JSON for machine parsing."""

    def format(self, record: logging.LogRecord) -> str:
        import json

        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ('name', 'msg', 'args', 'created', 'filename',
                          'funcName', 'levelname', 'levelno', 'lineno',
                          'module', 'msecs', 'pathname', 'process',
                          'processName', 'relativeCreated', 'stack_info',
                          'thread', 'threadName', 'exc_info', 'exc_text',
                          'message'):
                log_data[key] = value

        return json.dumps(log_data)


class CompactFormatter(logging.Formatter):
    """Minimal formatter for clean CLI output."""

    SYMBOLS = {
        logging.DEBUG: '·',
        logging.INFO: '→',
        logging.WARNING: '⚠',
        logging.ERROR: '✗',
        logging.CRITICAL: '‼',
    }

    def format(self, record: logging.LogRecord) -> str:
        symbol = self.SYMBOLS.get(record.levelno, '?')
        return f"{symbol} {record.getMessage()}"


# =============================================================================
# Logger Setup
# =============================================================================

def setup_logger(
    name: str = 'socks5_scanner',
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    json_output: bool = False,
    colored: bool = True,
    compact: bool = False
) -> logging.Logger:
    """
    Set up and configure the scanner logger.

    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for file logging
        json_output: Use JSON format (for pipelines)
        colored: Use colored console output
        compact: Use compact format (minimal symbols)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []  # Clear existing handlers

    # Determine if we should use colors
    use_colors = colored and sys.stdout.isatty()
    if not use_colors:
        Colors.disable()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if json_output:
        console_handler.setFormatter(JSONFormatter())
    elif compact:
        console_handler.setFormatter(CompactFormatter())
    else:
        fmt = "%(asctime)s │ %(levelname)s │ %(name)s │ %(message)s"
        datefmt = "%H:%M:%S"
        console_handler.setFormatter(ColoredFormatter(fmt, datefmt, use_colors))

    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # Always capture everything to file

        if json_output:
            file_handler.setFormatter(JSONFormatter())
        else:
            fmt = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
            file_handler.setFormatter(logging.Formatter(fmt))

        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = 'socks5_scanner') -> logging.Logger:
    """Get or create a logger with the given name."""
    return logging.getLogger(name)


# =============================================================================
# Convenience Functions
# =============================================================================

def set_level(level: str):
    """Set logging level by name (debug/info/warning/error)."""
    level_map = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'warn': logging.WARNING,
        'error': logging.ERROR,
    }
    log_level = level_map.get(level.lower(), logging.INFO)
    logging.getLogger('socks5_scanner').setLevel(log_level)


def enable_debug():
    """Enable debug logging."""
    set_level('debug')


def quiet():
    """Set to warning level only."""
    set_level('warning')


# =============================================================================
# Progress Reporting
# =============================================================================

class ProgressReporter:
    """
    Progress reporter for scan operations.

    Provides both callback-style and context-manager interfaces.
    """

    def __init__(
        self,
        total: int,
        prefix: str = "Scanning",
        bar_width: int = 40,
        show_stats: bool = True
    ):
        self.total = total
        self.prefix = prefix
        self.bar_width = bar_width
        self.show_stats = show_stats
        self.completed = 0
        self.working = 0
        self.failed = 0
        self.start_time = None

    def start(self):
        """Start the progress timer."""
        self.start_time = datetime.now()
        self._print_bar()

    def update(self, result=None):
        """Update progress with optional result."""
        self.completed += 1

        if result:
            if hasattr(result, 'is_working') and result.is_working:
                self.working += 1
            elif hasattr(result, 'error') and result.error:
                self.failed += 1

        self._print_bar()

    def finish(self):
        """Complete the progress bar."""
        print()  # New line after bar
        if self.show_stats and self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            rate = self.completed / elapsed if elapsed > 0 else 0
            print(f"Completed {self.completed} in {elapsed:.1f}s ({rate:.1f}/s)")
            print(f"Working: {self.working} | Failed: {self.failed}")

    def _print_bar(self):
        """Print the progress bar."""
        if self.total == 0:
            percent = 100
            filled = self.bar_width
        else:
            percent = (self.completed / self.total) * 100
            filled = int(self.bar_width * self.completed / self.total)

        bar = '█' * filled + '░' * (self.bar_width - filled)

        stats = ""
        if self.show_stats:
            stats = f" │ ✓{self.working} ✗{self.failed}"

        line = f"\r{self.prefix} │{bar}│ {self.completed}/{self.total} ({percent:.0f}%){stats}"
        print(line, end='', flush=True)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.finish()


# Create default logger on import
_default_logger = setup_logger(compact=True)
