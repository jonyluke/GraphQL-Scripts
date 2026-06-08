#!/usr/bin/env python3
"""Shared introspection helpers: fetch, bypass, load, save, and schema extraction."""

import json
import sys
from typing import Any, Dict, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None  # type: ignore

# Rich introspection query (includes inputFields for input object expansion and enumValues).
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
        type { kind name ofType { kind name } }
      }
      inputFields {
        name
        description
        defaultValue
        type { kind name ofType { kind name ofType { kind name } } }
      }
      enumValues {
        name
      }
    }
  }
}
"""

# Bypass variant: newline between __schema and { evades naive regex filters.
# Most WAFs block the literal string "__schema{" but ignore whitespace between them.
INTROSPECTION_BYPASS_QUERY = INTROSPECTION_QUERY.replace("  __schema {", "  __schema\n{", 1)


def _is_valid_introspection(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("data"), dict) and "__schema" in data["data"]:
        return True
    if "__schema" in data:
        return True
    return False


def fetch_introspection(url: str, headers: Dict[str, str],
                        timeout: int = 15) -> Optional[Dict[str, Any]]:
    """POST the standard introspection query to url.

    Returns the parsed response dict on success, or None on failure.
    """
    if requests is None:
        print("[!] 'requests' library required. Install with: pip install requests",
              file=sys.stderr)
        return None
    try:
        resp = requests.post(url, headers=headers,
                             json={"query": INTROSPECTION_QUERY}, timeout=timeout)
        data = resp.json()
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error during introspection: {e}", file=sys.stderr)
        return None
    except ValueError as e:
        print(f"[!] Response is not valid JSON: {e}", file=sys.stderr)
        return None
    return data if _is_valid_introspection(data) else None


def fetch_with_bypass(url: str, headers: Dict[str, str],
                      timeout: int = 15) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Try normal introspection, then the newline-bypass variant if the first fails.

    Returns (data, strategy) where strategy is 'normal', 'bypass', or None.
    The bypass works because GraphQL ignores whitespace but many regex filters
    match the literal string '__schema{' without accounting for newlines.
    """
    result = fetch_introspection(url, headers, timeout)
    if result is not None:
        return result, "normal"

    if requests is None:
        return None, None

    try:
        resp = requests.post(url, headers=headers,
                             json={"query": INTROSPECTION_BYPASS_QUERY}, timeout=timeout)
        data = resp.json()
        if _is_valid_introspection(data):
            return data, "bypass"
    except Exception:
        pass

    return None, None


def load_from_file(path: str) -> Optional[Dict[str, Any]]:
    """Load introspection JSON from a file. Returns dict or None on error."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] {path!r} is not valid JSON: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"[!] Cannot read {path!r}: {e}", file=sys.stderr)
        return None


def save_to_file(data: Dict[str, Any], path: str = "introspection_schema.json") -> None:
    """Serialize introspection data to a JSON file."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] Introspection saved to: {path}")
    except OSError as e:
        print(f"[!] Failed to save introspection to {path!r}: {e}", file=sys.stderr)


def extract_schema(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract the __schema dict from either response shape.

    Handles both:
      {"data": {"__schema": ...}}  — standard GraphQL introspection response
      {"__schema": ...}            — some servers omit the data wrapper
    """
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("data"), dict):
        return data["data"].get("__schema")
    return data.get("__schema")
