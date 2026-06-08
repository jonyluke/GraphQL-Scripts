#!/usr/bin/env python3
"""Shared introspection helpers: fetch, bypass, load, save, and schema extraction."""

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
# INTROSPECTION_QUERY  — no directives section; works on most modern servers.
# INTROSPECTION_QUERY_LOCATIONS — adds `directives { ... locations }` (Burp form).
# INTROSPECTION_QUERY_ON_STAR  — adds `directives { ... onField onOperation onFragment }`
#                                (older GraphQL spec / some servers require these).
# INTROSPECTION_BYPASS_QUERY   — newline variant of INTROSPECTION_QUERY (backward compat).

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

# Backward-compat alias used by older call sites.
INTROSPECTION_BYPASS_QUERY = INTROSPECTION_QUERY.replace("  __schema {", "  __schema\n{", 1)


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
    """Rewrite the `__schema {` token using the given whitespace/comment variant."""
    orig = "  __schema {"
    table = {
        "newline":       "  __schema\n{",
        "newline2":      "  __schema\n\n{",
        "double-space":  "  __schema  {",
        "tab":           "  __schema\t{",
        "comment":       "  __schema #bypass\n{",
        "compact":       "  __schema{",
    }
    replacement = table.get(variant)
    if replacement:
        return query.replace(orig, replacement, 1)
    return query


def _post_json(url: str, h: Dict[str, str], query: str, timeout: int) -> Optional[Dict]:
    try:
        resp = requests.post(url, headers=h, json={"query": query}, timeout=timeout)
        return resp.json()
    except Exception:
        return None


def _get_query(url: str, h: Dict[str, str], query: str, timeout: int) -> Optional[Dict]:
    no_ct = {k: v for k, v in h.items() if k.lower() != "content-type"}
    try:
        resp = requests.get(url, headers=no_ct,
                            params={"query": query}, timeout=timeout)
        return resp.json()
    except Exception:
        return None


def _post_form(url: str, h: Dict[str, str], query: str, timeout: int) -> Optional[Dict]:
    form_h = {k: v for k, v in h.items() if k.lower() != "content-type"}
    form_h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        resp = requests.post(url, headers=form_h,
                             data=f"query={quote(query)}", timeout=timeout)
        return resp.json()
    except Exception:
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_introspection(url: str, headers: Dict[str, str],
                        timeout: int = 15) -> Optional[Dict[str, Any]]:
    """POST the standard introspection query. Returns the response dict or None."""
    if requests is None:
        print("[!] 'requests' library required.", file=sys.stderr)
        return None
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    data = _post_json(url, h, INTROSPECTION_QUERY, timeout)
    return data if data and _is_valid_introspection(data) else None


def fetch_with_bypass(url: str, headers: Dict[str, str],
                      timeout: int = 15) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Try every bypass strategy in priority order. Return (data, strategy) or (None, None).

    Strategies tried (in order):
      POST JSON × {no-directives, locations, on*} forms × {normal, newline, comment,
                   double-space, tab, compact, newline2} bypass variants
      GET  × no-directives form × {normal, newline} variants
      POST form-urlencoded × no-directives form × {normal, newline} variants
    """
    if requests is None:
        return None, None

    h = {"Content-Type": "application/json"}
    h.update(headers or {})

    # (query_form_label, query_string, bypass_variant, http_method)
    strategies: List[Tuple[str, str, str, str]] = []

    for form_label, base_query in [
        ("plain", INTROSPECTION_QUERY),
        ("locations", INTROSPECTION_QUERY_LOCATIONS),
        ("on-star", INTROSPECTION_QUERY_ON_STAR),
    ]:
        for variant in ["normal", "newline", "comment", "double-space", "tab", "compact", "newline2"]:
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
            strategy_tag = (
                f"{method}"
                + (f"/{form_label}" if form_label != "plain" else "")
                + (f"/{variant}" if variant != "normal" else "")
            )
            return data, strategy_tag

    return None, None


# ── Error-based schema reconstruction ────────────────────────────────────────

# Common GraphQL field names used as probes when introspection is blocked.
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

    Technique 1 — malformed probe: send a non-existent field and parse
      "Did you mean X?" suggestions from the error message.
    Technique 2 — wordlist probe: send batches of candidate field names;
      those that don't error are real fields.
    Technique 3 — required-arg discovery: for each found field, send it
      without args and parse "Argument X of required type T" errors.

    Returns a minimal introspection-shaped dict or None.
    """
    if requests is None:
        return None
    if wordlist is None:
        wordlist = _DEFAULT_WORDLIST

    h = {"Content-Type": "application/json"}
    h.update(headers or {})

    # Discover root type name via __typename
    root_type_name = "Query"
    try:
        resp = requests.post(url, headers=h,
                             json={"query": "{__typename}"}, timeout=timeout)
        typename = (resp.json().get("data") or {}).get("__typename")
        if typename:
            root_type_name = typename
    except Exception:
        pass

    if verbose:
        print(f"[*] Error-based reconstruction — root type: {root_type_name}")

    discovered: set = set()

    # Technique 1 — bogus field names trigger "Did you mean" for real fields
    probe = "{ _zzz_nonexistent_probe_abc123 }"
    try:
        resp = requests.post(url, headers=h, json={"query": probe}, timeout=timeout)
        for error in (resp.json().get("errors") or []):
            msg = error.get("message", "")
            for m in re.findall(r'Did you mean (?:\"([^\"]+)\"|\'([^\']+)\')', msg):
                discovered.add(m[0] or m[1])
    except Exception:
        pass

    # Technique 2 — send batches of wordlist names; collect those that don't 404
    batch_size = 15
    for i in range(0, len(wordlist), batch_size):
        batch = wordlist[i : i + batch_size]
        query = "{ " + " ".join(batch) + " }"
        try:
            resp = requests.post(url, headers=h, json={"query": query}, timeout=timeout)
            rjson = resp.json()
            errors = rjson.get("errors") or []
            errored_fields = set()
            for e in errors:
                msg = e.get("message", "")
                # Collect suggestions triggered by real-field names used as probes
                for m in re.findall(r'Did you mean (?:\"([^\"]+)\"|\'([^\']+)\')', msg):
                    discovered.add(m[0] or m[1])
                # Track which probe fields errored with "Cannot query field"
                m = re.search(r'Cannot query field ["\']([^"\']+)["\']', msg)
                if m:
                    errored_fields.add(m.group(1))
            # Fields in the batch that did NOT appear in "Cannot query field" errors
            # and whose data key is present may be real
            data_obj = rjson.get("data") or {}
            for fname in batch:
                if fname in data_obj:
                    discovered.add(fname)
                # A field that triggered a type/arg error (not "Cannot query field") exists
                for e in errors:
                    if fname not in errored_fields:
                        locs = e.get("locations") or []
                        path = e.get("path") or []
                        if fname in str(path) or any(fname in str(l) for l in locs):
                            discovered.add(fname)
        except Exception:
            continue

    if not discovered:
        if verbose:
            print("[!] No fields discovered via error probing.")
        return None

    if verbose:
        print(f"[+] Discovered {len(discovered)} field(s): {sorted(discovered)}")

    # Technique 3 — probe each found field for required args
    field_defs: List[Dict[str, Any]] = []
    for fname in sorted(discovered):
        args: List[Dict[str, Any]] = []
        ret_type: Dict[str, Any] = {"kind": "SCALAR", "name": "String", "ofType": None}
        try:
            resp = requests.post(url, headers=h,
                                 json={"query": f"{{ {fname} }}"}, timeout=timeout)
            for error in (resp.json().get("errors") or []):
                msg = error.get("message", "")
                # "Argument 'X' of required type 'T!' was not provided"
                for m in re.finditer(
                    r"[Aa]rgument\s+[\"']([^\"']+)[\"'][^.]*?type\s+[\"']([^\"']+)[\"']",
                    msg
                ):
                    args.append({
                        "name": m.group(1),
                        "type": {
                            "kind": "SCALAR",
                            "name": re.sub(r"[!\[\]]", "", m.group(2)),
                            "ofType": None,
                        },
                        "defaultValue": None,
                    })
                # "Field X must have a selection of subfields" → it's an OBJECT type
                if re.search(r"must have a selection", msg, re.I):
                    ret_type = {"kind": "OBJECT", "name": "Unknown", "ofType": None}
        except Exception:
            pass
        field_defs.append({
            "name": fname,
            "description": None,
            "args": args,
            "type": ret_type,
            "isDeprecated": False,
            "deprecationReason": None,
        })

    schema = {
        "queryType": {"name": root_type_name},
        "mutationType": None,
        "subscriptionType": None,
        "types": [
            {
                "kind": "OBJECT",
                "name": root_type_name,
                "description": "Partially reconstructed via error-based probing (introspection disabled)",
                "fields": field_defs,
                "inputFields": None,
                "interfaces": [],
                "enumValues": None,
                "possibleTypes": None,
            }
        ],
        "directives": [],
    }
    return {"data": {"__schema": schema}}


# ── File I/O ──────────────────────────────────────────────────────────────────

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
