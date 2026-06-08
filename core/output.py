#!/usr/bin/env python3
"""Shared colour utilities.

Exports Fore/Style (colorama or dummy) for sqli_detector, and ANSI constants
for qgen/effuzz which don't depend on colorama.
"""
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
except ImportError:
    class _Dummy:
        def __getattr__(self, name):
            return ""
    Fore = Style = _Dummy()

# Plain ANSI constants used by qgen and effuzz
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"
GREY    = "\033[90m"
BOLD    = "\033[1m"
RESET   = "\033[0m"
