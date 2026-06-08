#!/usr/bin/env python3
"""Shared HTTP helpers: header parsing and cookie file loading."""

import json
import os
import re
import sys
from typing import Dict, List, Optional


def parse_header_args(headers_list: List[str]) -> Dict[str, str]:
    """Parse a list of 'Name: Value' strings (from argparse action=append) into a dict.

    Last value wins on duplicates.
    """
    hdrs: Dict[str, str] = {}
    for h in headers_list or []:
        if ":" not in h:
            print(f"[!] Ignoring malformed header (expected 'Name: Value'): {h!r}",
                  file=sys.stderr)
            continue
        name, value = h.split(":", 1)
        hdrs[name.strip()] = value.strip()
    return hdrs


def parse_headers_input(h) -> Dict[str, str]:
    """Parse headers from several formats accepted by sqli_detector.

    Handles:
      - None / empty string → {}
      - JSON object string  → {"Authorization": "Bearer x", ...}
      - JSON array of dicts → [{...}, ...]
      - Semicolon/comma-separated 'Name: Value' pairs
    """
    if not h:
        return {}
    if isinstance(h, list):
        return parse_header_args(h)
    if isinstance(h, str):
        try:
            parsed = json.loads(h)
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, list):
                result: Dict[str, str] = {}
                for item in parsed:
                    if isinstance(item, dict):
                        result.update(item)
                return result
        except (ValueError, TypeError):
            pass
        result = {}
        for part in re.split(r"[;,]", h):
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                k, v = part.split(":", 1)
                result[k.strip()] = v.strip()
        return result
    return {}


def load_cookie_file(path: str) -> Optional[str]:
    """Read a one-line cookie file. Returns the cookie string or None."""
    if not os.path.isfile(path):
        print(f"[!] Cookie file not found: {path}", file=sys.stderr)
        return None
    with open(path, "r", encoding="utf-8") as f:
        value = f.read().strip()
    return value or None


def build_headers(headers_list: Optional[List[str]] = None,
                  cookie_file: Optional[str] = None) -> Dict[str, str]:
    """Build an HTTP headers dict.

    Always includes Content-Type: application/json. Merges -H style args and
    an optional cookie file. An explicit Cookie header via -H takes precedence
    over the cookie file.
    """
    hdrs: Dict[str, str] = {"Content-Type": "application/json"}
    if headers_list:
        hdrs.update(parse_header_args(headers_list))
    if cookie_file and "Cookie" not in hdrs:
        cookie = load_cookie_file(cookie_file)
        if cookie:
            hdrs["Cookie"] = cookie
    return hdrs
