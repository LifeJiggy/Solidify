"""Formatter - Streaming output formatting for Solidify"""

import sys
from typing import Optional, Callable
from enum import Enum


class DisplayMode(Enum):
    PLAIN = "plain"
    COLOR = "color"
    VERBOSE = "verbose"
    MINIMAL = "minimal"


class ColorCode:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"


class StreamFormatter:
    def __init__(self, use_colors: bool = True, mode: DisplayMode = DisplayMode.COLOR):
        self.use_colors = use_colors
        self.mode = mode

    def format_header(self, provider: str, model: str) -> str:
        if self.mode == DisplayMode.PLAIN:
            return f"[{provider}] {model}"
        if self.mode == DisplayMode.MINIMAL:
            return f"[{provider}]"
        return (
            f"\n  ┌─ {self._color(provider.upper(), 'cyan')} - {model} ─"
            + "─" * 30
            + "\n"
        )

    def format_footer(self, total_chars: int = 0, duration: float = 0.0) -> str:
        if self.mode == DisplayMode.PLAIN:
            return ""
        if self.mode == DisplayMode.MINIMAL:
            return f" [{total_chars} chars, {duration:.2f}s]"
        return f"\n  └" + "─" * 50 + "\n"

    def format_chunk(self, chunk: str, chunk_num: int = 0) -> str:
        return f"  │ {chunk}"

    def format_error(self, error: str) -> str:
        return f"  │ {self._color('✗ Error: ' + error, 'red')}"

    def _color(self, text: str, color: str) -> str:
        if not self.use_colors:
            return text
        color_map = {
            "red": ColorCode.RED,
            "green": ColorCode.GREEN,
            "yellow": ColorCode.YELLOW,
            "cyan": ColorCode.CYAN,
            "bold": ColorCode.BOLD,
        }
        return f"{color_map.get(color, '')}{text}{ColorCode.RESET}"


class StreamingDisplay:
    def __init__(
        self,
        formatter: Optional[StreamFormatter] = None,
        output_callback: Optional[Callable[[str], None]] = None,
    ):
        self.formatter = formatter or StreamFormatter()
        self.output_callback = output_callback or self._default_output
        self._buffer = ""
        self._chunk_count = 0

    def _default_output(self, text: str):
        print(text, end="", flush=True)

    def start_stream(self, provider: str, model: str) -> str:
        header = self.formatter.format_header(provider, model)
        self.output_callback(header)
        return header

    def add_chunk(self, chunk: str) -> str:
        self._chunk_count += 1
        self._buffer += chunk
        formatted = self.formatter.format_chunk(chunk, self._chunk_count)
        self.output_callback(formatted)
        return formatted

    def end_stream(self, total_chars: int = 0, duration: float = 0.0) -> str:
        footer = self.formatter.format_footer(total_chars, duration)
        self.output_callback(footer)
        self._buffer = ""
        self._chunk_count = 0
        return footer

    def show_error(self, error: str) -> str:
        formatted = self.formatter.format_error(error)
        self.output_callback(formatted + "\n")
        return formatted


def create_formatter(mode: str = "color", use_colors: bool = True) -> StreamFormatter:
    display_mode = DisplayMode(mode.lower())
    return StreamFormatter(use_colors=use_colors, mode=display_mode)


def create_console_display(
    provider: str = "nvidia", model: str = ""
) -> StreamingDisplay:
    formatter = create_formatter()
    return StreamingDisplay(formatter=formatter)
