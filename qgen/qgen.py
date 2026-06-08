#!/usr/bin/env python3
import json
import os
import sys
import argparse
from typing import Dict, Any, List, Optional

# Allow running from any working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import requests
except ImportError:
    requests = None  # type: ignore

import core.introspection as core_intro
from core.http import build_headers
from core.output import RED, BLUE, YELLOW, CYAN, RESET


def print_banner():
    print(f"""
{YELLOW}
 ██████╗  ██████╗ ███████╗███╗   ██╗
██╔═══██╗██╔════╝ ██╔════╝████╗  ██║
██║   ██║██║  ███╗█████╗  ██╔██╗ ██║
██║▄▄ ██║██║   ██║██╔══╝  ██║╚██╗██║
╚██████╔╝╚██████╔╝███████╗██║ ╚████║
 ╚══▀▀═╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝ v1.1
{RESET}
{CYAN}made by gitblanc — https://github.com/gitblanc/QGen{RESET}
""")


def _prompt_introspection_file() -> Dict[str, Any]:
    """Interactive fallback: ask the user for a path to an introspection JSON file."""
    while True:
        path = input("Enter introspection JSON file path: ").strip()
        if not os.path.isfile(path):
            print(f"[!] File not found: {path!r}\n")
            continue
        data = core_intro.load_from_file(path)
        if data is not None:
            print("[+] Introspection loaded.\n")
            return data


def extract_graphql_queries(introspection: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract query and mutation fields from an introspection response.

    Normalises both response shapes ({data:{__schema:...}} and {__schema:...}).
    Each returned field dict gains a '_root' key ('query' or 'mutation').
    """
    schema = core_intro.extract_schema(introspection)
    if not schema:
        return []

    types = schema.get("types") or []
    methods: List[Dict[str, Any]] = []

    def _add_fields(type_name_ref, root_label: str):
        if not isinstance(type_name_ref, dict):
            return
        type_name = type_name_ref.get("name")
        if not type_name:
            return
        tdef = next((t for t in types if t.get("name") == type_name), None)
        if tdef:
            for f in (tdef.get("fields") or []):
                methods.append({**f, "_root": root_label})

    _add_fields(schema.get("queryType"), "query")
    _add_fields(schema.get("mutationType"), "mutation")
    return methods


def resolve_type(t: Any) -> Any:
    """Unwrap NON_NULL / LIST wrappers to reach the named type."""
    while isinstance(t, dict) and t.get("ofType") is not None:
        t = t["ofType"]
    return t


def build_field_tree(field_type: Any, types: List[Dict[str, Any]],
                     depth: int = 0, visited: Optional[set] = None) -> str:
    """Recursively build a GraphQL selection set string for an OBJECT type."""
    if visited is None:
        visited = set()

    field_type = resolve_type(field_type)
    name = field_type.get("name") if isinstance(field_type, dict) else None

    if name and name in visited:
        return ""
    if name:
        visited.add(name)
    if not isinstance(field_type, dict) or field_type.get("kind") != "OBJECT":
        return ""

    obj = next((t for t in types if t.get("name") == field_type.get("name")), None)
    if not obj or not obj.get("fields"):
        return ""

    indent = "  " * depth
    result = ""
    for f in obj["fields"]:
        f_type = resolve_type(f["type"])
        f_name = f["name"]
        if f_type.get("kind") == "OBJECT":
            sub = build_field_tree(f["type"], types, depth + 1, visited.copy())
            result += f"{indent}{f_name} {{\n{sub}{indent}}}\n"
        else:
            result += f"{indent}{f_name}\n"
    return result


def stringify_type(t: Any) -> str:
    """Convert a GraphQL type tree dict to a readable type string (e.g. '[String!]')."""
    if not isinstance(t, dict):
        return "Unknown"
    if t.get("kind") == "NON_NULL":
        return f"{stringify_type(t['ofType'])}!"
    if t.get("kind") == "LIST":
        return f"[{stringify_type(t['ofType'])}]"
    return t.get("name", "Unknown")


def build_input_object(type_ref: Any, types: List[Dict[str, Any]],
                       depth: int = 0, visited: Optional[set] = None) -> str:
    """Expand an INPUT_OBJECT type into an inline example literal."""
    if visited is None:
        visited = set()

    resolved = resolve_type(type_ref)
    type_name = resolved.get("name") if isinstance(resolved, dict) else None
    if not type_name or type_name in visited:
        return "{}"
    visited.add(type_name)

    type_obj = next((t for t in types if t.get("name") == type_name), None)
    if not type_obj:
        return "{}"

    input_fields = type_obj.get("inputFields") or []
    indent = "  " * depth
    inner_indent = "  " * (depth + 1)

    parts = []
    for f in input_fields:
        fname = f["name"]
        if f.get("defaultValue") is not None:
            parts.append(f"{inner_indent}{fname}: {f['defaultValue']}")
            continue
        val = format_input_value(f["type"], types, fname, depth + 1, visited.copy())
        parts.append(f"{inner_indent}{fname}: {val}")

    if not parts:
        return "{}"
    if depth == 0:
        inner = ", ".join(p.strip() for p in parts)
        return "{ " + inner + " }"
    body = "\n".join(parts)
    return "{\n" + body + f"\n{indent}}}"


def format_input_value(type_ref: Any, types: List[Dict[str, Any]],
                       field_name: Optional[str] = None,
                       depth: int = 0,
                       visited: Optional[set] = None) -> str:
    """Generate a sensible example value for a given GraphQL type."""
    if not isinstance(type_ref, dict):
        return '"example"'
    if type_ref.get("kind") == "NON_NULL":
        return format_input_value(type_ref["ofType"], types, field_name, depth, visited)
    if type_ref.get("kind") == "LIST":
        inner = format_input_value(type_ref["ofType"], types, field_name, depth + 1, visited)
        return f"[{inner}]"

    kind = type_ref.get("kind")
    name = type_ref.get("name", "")

    if kind == "SCALAR" or name in ("String", "ID", ""):
        if field_name:
            lname = field_name.lower()
            if "pass" in lname:
                return '"password123"'
            if "email" in lname:
                return f'"{field_name}@example.com"'
            if "role" in lname:
                return '"user"'
            if "name" in lname:
                return f'"{field_name}_example"'
            if "msg" in lname or "message" in lname:
                return f'"{field_name}_example"'
        return '"example"'
    if name in ("Int", "Float"):
        return "0"
    if name == "Boolean":
        return "false"

    if kind == "ENUM" or any(t.get("name") == name and t.get("enumValues") for t in types):
        tobj = next((t for t in types if t.get("name") == name), None)
        if tobj:
            vals = tobj.get("enumValues") or []
            if vals:
                first = vals[0].get("name")
                return first if first is not None else '"ENUM_VALUE"'
        return '"ENUM_VALUE"'

    if kind == "INPUT_OBJECT" or any(t.get("name") == name and t.get("inputFields") for t in types):
        return build_input_object(type_ref, types, depth, visited)

    return '"example"'


def generate_full_query(method_field: Dict[str, Any],
                        introspection: Dict[str, Any]) -> str:
    """Build a complete GraphQL query/mutation for a given schema field."""
    schema = core_intro.extract_schema(introspection)
    types = (schema.get("types") or []) if schema else []

    args = method_field.get("args") or []
    variables: List[str] = []
    call_args: List[str] = []

    for a in args:
        var_name = a["name"]
        resolved = resolve_type(a["type"])
        kind = resolved.get("kind")
        type_name = resolved.get("name")

        is_input_obj = (
            kind == "INPUT_OBJECT"
            or any(t.get("name") == type_name and t.get("inputFields") for t in types)
        )
        if is_input_obj:
            call_args.append(f"{var_name}: {build_input_object(a['type'], types)}")
        else:
            var_type = stringify_type(a["type"])
            variables.append(f"${var_name}: {var_type}")
            call_args.append(f"{var_name}: ${var_name}")

    variables_str = f"({', '.join(variables)})" if variables else ""
    call_args_str = f"({', '.join(call_args)})" if call_args else ""

    fields_tree = build_field_tree(method_field["type"], types, depth=2)
    operation = method_field.get("_root", "query")

    return f"""
{operation} {method_field['name']}{variables_str} {{
  {method_field['name']}{call_args_str} {{
{fields_tree}
  }}
}}""".rstrip()


def save_query_to_file(method_name: str, query_text: str) -> None:
    """Write a generated query to queries/<method_name>.txt."""
    os.makedirs("queries", exist_ok=True)
    path = f"queries/{method_name}.txt"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(query_text)
        print(f"[+] Query saved to: {path}\n")
    except OSError as e:
        print(f"[!] Error saving query: {e}")


def interactive_console(methods: List[Dict[str, Any]],
                        introspection: Dict[str, Any]) -> None:
    print("Type 'help' to see available commands.\n")

    while True:
        try:
            raw_cmd = input(f"{RED}qgen ${RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[+] Exiting.")
            break

        # Pipe support: listMethods | grep <text>
        grep_text = None
        if "|" in raw_cmd:
            left, _, right = raw_cmd.partition("|")
            raw_cmd = left.strip()
            pipe_part = right.strip()
            if pipe_part.startswith("grep"):
                grep_text = pipe_part[4:].strip().lower()
            else:
                print("[!] Unsupported pipe command.\n")
                continue

        cmd = raw_cmd

        # Allow bare number or exact method name as shorthand for 'use <n>'
        if not cmd.startswith("use ") and cmd not in ("help", "listMethods", "exit", ""):
            if cmd.isdigit():
                cmd = f"use {cmd}"
            elif any(m["name"] == cmd for m in methods):
                cmd = f"use {cmd}"

        if cmd == "help":
            output = (
                "Available commands:\n"
                "  help               - Show this help\n"
                "  listMethods        - List all available GraphQL methods\n"
                "  use <num|method>   - Generate the full query for a method\n"
                "  exit               - Exit\n"
            )
            if grep_text:
                output = "\n".join(
                    l for l in output.splitlines() if grep_text in l.lower()
                )
            print(output)

        elif cmd == "listMethods":
            lines = []
            for i, m in enumerate(methods, start=1):
                label = "Q" if m.get("_root") == "query" else "M"
                lines.append(f" [{i}] ({label}) {m['name']}")
            if grep_text:
                lines = [l for l in lines if grep_text in l.lower()]
            print("\n[*] Available methods:")
            for line in lines:
                print(line)
            print()

        elif cmd.startswith("use "):
            _, _, value = cmd.partition(" ")
            value = value.strip()

            if value.isdigit():
                idx = int(value) - 1
                if not 0 <= idx < len(methods):
                    print("[!] Invalid method number.\n")
                    continue
                selected = methods[idx]
            else:
                selected = next((m for m in methods if m["name"] == value), None)
                if not selected:
                    print(f"[!] Method {value!r} not found.\n")
                    continue

            print(f"[+] Selected: {selected['name']}\n")
            try:
                query = generate_full_query(selected, introspection)
                print("\n" + "-" * 40)
                print(f"{BLUE}{query}{RESET}")
                print("-" * 40 + "\n")
                save_query_to_file(selected["name"], query)
            except Exception as e:
                print(f"[!] Error generating query: {e}\n")

        elif cmd == "exit":
            print("[+] Exiting.")
            break

        elif cmd == "":
            continue

        else:
            print("[!] Unknown command. Type 'help' for the command list.\n")


def _confirm_endpoint(url: str, headers: Dict[str, str]) -> None:
    """Send {__typename} to confirm the URL is a live GraphQL endpoint before introspection."""
    if requests is None:
        return
    try:
        resp = requests.post(url, headers=headers,
                             json={"query": "query{__typename}"}, timeout=10)
        data = resp.json()
        typename = None
        if isinstance(data, dict):
            d = data.get("data") or data
            if isinstance(d, dict):
                typename = d.get("__typename")
        if typename:
            print(f"[+] Endpoint confirmed — __typename: {typename}")
        else:
            print("[!] Endpoint responded but no __typename found. Proceeding anyway.")
    except Exception as e:
        print(f"[!] Could not confirm endpoint ({e}). Proceeding with introspection.")


def main():
    print_banner()
    print("=== GraphQL Interactive Query Generator ===\n")

    parser = argparse.ArgumentParser(description="GraphQL Introspection CLI — query generator")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--introspection", metavar="FILE",
                     help="Path to introspection JSON file")
    src.add_argument("--url", metavar="URL",
                     help="GraphQL endpoint URL (auto-introspection)")
    parser.add_argument("-H", "--header", action="append", default=[],
                        metavar="Name: Value",
                        help="HTTP header for auto-introspection (repeatable)")
    parser.add_argument("--cookie", metavar="FILE",
                        help="Cookie file (one line) for auto-introspection")
    parser.add_argument("--save-introspection", dest="save_introspection",
                        action="store_true",
                        help="Save fetched introspection to introspection_schema.json (default)")
    parser.add_argument("--no-save-introspection", dest="save_introspection",
                        action="store_false",
                        help="Do not save introspection to disk")
    parser.set_defaults(save_introspection=True)
    args = parser.parse_args()

    introspection = None

    if args.introspection:
        if not os.path.isfile(args.introspection):
            print(f"[!] File not found: {args.introspection!r}")
            sys.exit(1)
        introspection = core_intro.load_from_file(args.introspection)
        if introspection is None:
            sys.exit(1)
        print("[+] Introspection loaded from file.\n")

    elif args.url:
        headers = build_headers(args.header, args.cookie)
        _confirm_endpoint(args.url, headers)
        print(f"[*] Fetching introspection from {args.url} ...")
        introspection, strategy = core_intro.fetch_with_bypass(args.url, headers)
        if introspection is None:
            print("[!] Could not obtain introspection. Falling back to interactive prompt.\n")
            introspection = _prompt_introspection_file()
        else:
            tag = " (via newline bypass)" if strategy == "bypass" else ""
            print(f"[+] Introspection obtained{tag}.\n")
            if args.save_introspection:
                core_intro.save_to_file(introspection)
    else:
        introspection = _prompt_introspection_file()

    methods = extract_graphql_queries(introspection)
    if not methods:
        print("[!] No GraphQL methods found in the introspection.")
        sys.exit(1)

    n_q = sum(1 for m in methods if m.get("_root") == "query")
    n_m = sum(1 for m in methods if m.get("_root") == "mutation")
    print(f"[+] Schema loaded: {n_q} queries, {n_m} mutations\n")

    interactive_console(methods, introspection)


if __name__ == "__main__":
    main()
