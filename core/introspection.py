#!/usr/bin/env python3
"""Shared introspection helpers: fetch, bypass, and schema extraction."""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

try:
    import requests
except ImportError:
    requests = None  # type: ignore

# ── Query forms ───────────────────────────────────────────────────────────────
#
# INTROSPECTION_QUERY         — no directives; works on most modern servers.
# INTROSPECTION_QUERY_LOCATIONS — adds `directives { locations }` (Burp form).
# INTROSPECTION_QUERY_ON_STAR  — adds `directives { onField onOperation onFragment }`
#                                (older GraphQL spec; some servers require these).

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

INTROSPECTION_QUERY_LOCATIONS = INTROSPECTION_QUERY.replace(
    "    queryType { name }",
    "    queryType { name }\n    directives { name isRepeatable locations }",
    1,
)

INTROSPECTION_QUERY_ON_STAR = INTROSPECTION_QUERY.replace(
    "    queryType { name }",
    "    queryType { name }\n    directives { name isRepeatable onField onOperation onFragment }",
    1,
)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _is_valid_introspection(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("data"), dict) and "__schema" in data["data"]:
        schema = data["data"]["__schema"]
        return bool(schema and schema.get("types"))
    if "__schema" in data:
        return bool(data["__schema"] and data["__schema"].get("types"))
    return False


def _apply_schema_bypass(query: str, variant: str) -> str:
    """Rewrite the `__schema {` token with a whitespace/comment variant."""
    table = {
        "newline":      "  __schema\n{",
        "newline2":     "  __schema\n\n{",
        "double-space": "  __schema  {",
        "tab":          "  __schema\t{",
        "comment":      "  __schema #bypass\n{",
        "compact":      "  __schema{",
    }
    replacement = table.get(variant)
    return query.replace("  __schema {", replacement, 1) if replacement else query


def _post_json(url: str, h: Dict[str, str], query: str, timeout: int) -> Optional[Dict]:
    try:
        resp = requests.post(url, headers=h, json={"query": query}, timeout=timeout)
        return resp.json()
    except Exception:
        return None


def _get_query(url: str, h: Dict[str, str], query: str, timeout: int) -> Optional[Dict]:
    no_ct = {k: v for k, v in h.items() if k.lower() != "content-type"}
    try:
        resp = requests.get(url, headers=no_ct, params={"query": query}, timeout=timeout)
        return resp.json()
    except Exception:
        return None


def _post_form(url: str, h: Dict[str, str], query: str, timeout: int) -> Optional[Dict]:
    form_h = {k: v for k, v in h.items() if k.lower() != "content-type"}
    form_h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        resp = requests.post(url, headers=form_h, data=f"query={quote(query)}", timeout=timeout)
        return resp.json()
    except Exception:
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_with_bypass(url: str, headers: Dict[str, str],
                      timeout: int = 15) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Try every bypass strategy in priority order. Return (data, strategy) or (None, None).

    Returns "normal" when the plain POST succeeds without any bypass.
    Otherwise returns a descriptive tag like "post-json/newline",
    "post-json/locations/comment", "get/newline", "post-form", etc.

    Strategy order: all query forms with each bypass variant before moving to the
    next variant — so a wrong query form is detected after just 3 requests.

    POST JSON variants:
      bypass × {normal, newline, comment, double-space, tab, compact, newline2}
      form   × {plain, locations, on-star}
    GET and POST form-urlencoded:
      plain form × {normal, newline}
    """
    if requests is None:
        return None, None

    h = {"Content-Type": "application/json"}
    h.update(headers or {})

    _forms = [
        ("plain",     INTROSPECTION_QUERY),
        ("locations", INTROSPECTION_QUERY_LOCATIONS),
        ("on-star",   INTROSPECTION_QUERY_ON_STAR),
    ]
    _variants = ["normal", "newline", "comment", "double-space", "tab", "compact", "newline2"]

    # Build strategy list: iterate variant-first so all forms are tried per variant.
    strategies: List[Tuple[str, str, str, str]] = []
    for variant in _variants:
        for form_label, base_query in _forms:
            q = base_query if variant == "normal" else _apply_schema_bypass(base_query, variant)
            strategies.append((form_label, q, variant, "post-json"))

    for variant in ["normal", "newline"]:
        q = INTROSPECTION_QUERY if variant == "normal" else _apply_schema_bypass(INTROSPECTION_QUERY, variant)
        strategies.append(("plain", q, variant, "get"))
        strategies.append(("plain", q, variant, "post-form"))

    for form_label, query_str, variant, method in strategies:
        if method == "post-json":
            data = _post_json(url, h, query_str, timeout)
        elif method == "get":
            data = _get_query(url, h, query_str, timeout)
        else:
            data = _post_form(url, h, query_str, timeout)

        if data and _is_valid_introspection(data):
            if method == "post-json" and form_label == "plain" and variant == "normal":
                return data, "normal"
            tag = method
            if form_label != "plain":
                tag += f"/{form_label}"
            if variant != "normal":
                tag += f"/{variant}"
            return data, tag

    return None, None


# ── Error-based schema reconstruction ────────────────────────────────────────

_DEFAULT_WORDLIST = [
    "id", "user", "users", "me", "profile", "account", "accounts",
    "viewer", "node", "nodes",
    "post", "posts", "article", "articles", "comment", "comments",
    "message", "messages", "chat", "conversation",
    "product", "products", "order", "orders", "item", "items", "cart",
    "search", "query", "find", "list",
    "create", "update", "delete", "add", "remove", "edit",
    "login", "logout", "register", "auth", "token", "session",
    "admin", "settings", "config", "info", "status", "health",
    "file", "files", "upload", "download", "image", "images",
    "paste", "pastes", "audit", "audits",
    "systemHealth", "systemDebug", "systemUpdate",
    "readAndBurn", "deleteAllPastes",
]


def reconstruct_schema_from_errors(
    url: str,
    headers: Dict[str, str],
    timeout: int = 20,
    wordlist: Optional[List[str]] = None,
    verbose: bool = False,
) -> Optional[Dict[str, Any]]:
    """Partially reconstruct the schema when introspection is disabled.

    1. Bogus-field probe  → parse "Did you mean X?" suggestions.
    2. Wordlist batch     → fields that don't get "Cannot query field" exist.
    3. Required-arg probe → per field, extract arg names/types from error messages.

    Returns a minimal introspection-shaped dict or None.
    """
    if requests is None:
        return None
    if wordlist is None:
        wordlist = _DEFAULT_WORDLIST

    h = {"Content-Type": "application/json"}
    h.update(headers or {})

    root_type_name = "Query"
    try:
        resp = requests.post(url, headers=h, json={"query": "{__typename}"}, timeout=timeout)
        typename = (resp.json().get("data") or {}).get("__typename")
        if typename:
            root_type_name = typename
    except Exception:
        pass

    if verbose:
        print(f"[*] Error-based reconstruction — root type: {root_type_name}")

    discovered: set = set()

    # Technique 1 — bogus field → "Did you mean X?"
    try:
        resp = requests.post(url, headers=h,
                             json={"query": "{ _zzz_nonexistent_probe_abc123 }"}, timeout=timeout)
        for error in (resp.json().get("errors") or []):
            for m in re.findall(r'Did you mean (?:\"([^\"]+)\"|\'([^\']+)\')',
                                error.get("message", "")):
                discovered.add(m[0] or m[1])
    except Exception:
        pass

    # Technique 2 — wordlist batches
    for i in range(0, len(wordlist), 15):
        batch = wordlist[i: i + 15]
        try:
            resp = requests.post(url, headers=h,
                                 json={"query": "{ " + " ".join(batch) + " }"}, timeout=timeout)
            rjson = resp.json()
            errored: set = set()
            for e in (rjson.get("errors") or []):
                msg = e.get("message", "")
                for m in re.findall(r'Did you mean (?:\"([^\"]+)\"|\'([^\']+)\')', msg):
                    discovered.add(m[0] or m[1])
                m2 = re.search(r'Cannot query field ["\']([^"\']+)["\']', msg)
                if m2:
                    errored.add(m2.group(1))
            for fname in batch:
                if fname in (rjson.get("data") or {}):
                    discovered.add(fname)
                elif fname not in errored:
                    for e in (rjson.get("errors") or []):
                        if fname in str(e.get("path") or []):
                            discovered.add(fname)
        except Exception:
            continue

    if not discovered:
        if verbose:
            print("[!] No fields discovered via error probing.")
        return None

    if verbose:
        print(f"[+] Discovered {len(discovered)} field(s): {sorted(discovered)}")

    # Technique 3 — probe each field for required args
    field_defs: List[Dict[str, Any]] = []
    for fname in sorted(discovered):
        args: List[Dict[str, Any]] = []
        ret_type: Dict[str, Any] = {"kind": "SCALAR", "name": "String", "ofType": None}
        try:
            resp = requests.post(url, headers=h,
                                 json={"query": f"{{ {fname} }}"}, timeout=timeout)
            for error in (resp.json().get("errors") or []):
                msg = error.get("message", "")
                for m in re.finditer(
                    r"[Aa]rgument\s+[\"']([^\"']+)[\"'][^.]*?type\s+[\"']([^\"']+)[\"']", msg
                ):
                    args.append({
                        "name": m.group(1),
                        "type": {"kind": "SCALAR",
                                 "name": re.sub(r"[!\[\]]", "", m.group(2)),
                                 "ofType": None},
                        "defaultValue": None,
                    })
                if re.search(r"must have a selection", msg, re.I):
                    ret_type = {"kind": "OBJECT", "name": "Unknown", "ofType": None}
        except Exception:
            pass
        field_defs.append({
            "name": fname, "description": None, "args": args,
            "type": ret_type, "isDeprecated": False, "deprecationReason": None,
        })

    return {"data": {"__schema": {
        "queryType": {"name": root_type_name},
        "mutationType": None,
        "subscriptionType": None,
        "types": [{
            "kind": "OBJECT",
            "name": root_type_name,
            "description": "Partially reconstructed via error-based probing",
            "fields": field_defs,
            "inputFields": None,
            "interfaces": [],
            "enumValues": None,
            "possibleTypes": None,
        }],
        "directives": [],
    }}}


# ── Schema extraction ─────────────────────────────────────────────────────────

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
