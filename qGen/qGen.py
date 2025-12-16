#!/usr/bin/env python3
import json
import os
import sys
import argparse
import textwrap
from typing import Dict, Any, List, Optional

# Try to import requests; if missing, we'll show a helpful message when needed
try:
    import requests
except Exception:
    requests = None

# ANSI COLORS
RED = "\033[31m"
GREY = "\033[90m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

def print_banner():
    print(f"""
{YELLOW}
 ██████╗  ██████╗ ███████╗███╗   ██╗
██╔═══██╗██╔════╝ ██╔════╝████╗  ██║
██║   ██║██║  ███╗█████╗  ██╔██╗ ██║
██║▄▄ ██║██║   ██║██╔══╝  ██║╚██╗██║
╚██████╔╝╚██████╔╝███████╗██║ ╚████║
 ╚══▀▀═╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝ v1.0
{RESET}

{CYAN}made by gitblanc — https://github.com/gitblanc/QGen{RESET}

""")

def load_introspection():
    while True:
        path = input("Enter introspection JSON file path: ").strip()

        if not os.path.exists(path):
            print("❌ File not found. Try again.\n")
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            print("✅ Introspection successfully loaded.\n")
            return data
        except Exception as e:
            print(f"❌ Error reading JSON: {e}\n")

# Introspection query used when obtaining schema from endpoint.
# NOTE: includes inputFields for input objects so we can expand them inline.
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

def parse_header_list(headers_list: List[str]) -> Dict[str, str]:
    """
    Convert list of 'Name: Value' strings to a dict (last wins for duplicates).
    """
    hdrs: Dict[str, str] = {}
    for h in headers_list or []:
        if ":" not in h:
            print(f"⚠️ Ignoring malformed header (expected 'Name: Value'): {h}")
            continue
        name, value = h.split(":", 1)
        hdrs[name.strip()] = value.strip()
    return hdrs

def perform_introspection_request(url: str, headers: Dict[str, str], timeout: int = 15) -> Optional[Dict[str, Any]]:
    """
    Perform a POST request to the GraphQL endpoint with the introspection query.
    Returns parsed JSON on success, or None on failure.
    """
    if requests is None:
        print("❌ The 'requests' library is required for automatic introspection. Install with: pip install requests")
        return None

    try:
        resp = requests.post(url, headers=headers, json={"query": INTROSPECTION_QUERY}, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"❌ HTTP error while requesting introspection: {e}")
        return None

    try:
        data = resp.json()
    except Exception as e:
        print(f"❌ Response is not valid JSON: {e}")
        return None

    if (isinstance(data, dict) and
        ((data.get("data") and isinstance(data["data"], dict) and "__schema" in data["data"]) or ("__schema" in data))):
        return data

    print("❌ Introspection response does not contain '__schema' (not a valid GraphQL introspection).")
    return None

def save_introspection_file(data: Dict[str, Any], path: str = "introspection_schema.json") -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"✅ Introspection saved to: {path}")
    except Exception as e:
        print(f"⚠️ Failed to save introspection to {path}: {e}")

# Extract query and mutation fields
def extract_graphql_queries(introspection):
    try:
        types = introspection["data"]["__schema"]["types"]
    except Exception:
        return []

    methods = []

    # Extract query fields (if present)
    query_type = introspection["data"]["__schema"].get("queryType")
    query_type_name = query_type.get("name") if isinstance(query_type, dict) else query_type
    if query_type_name:
        qtype = next((t for t in types if t.get("name") == query_type_name), None)
        if qtype and "fields" in qtype:
            for f in qtype["fields"]:
                f_copy = f.copy()
                f_copy["_root"] = "query"
                methods.append(f_copy)

    # Extract mutation fields (if present)
    mutation_type = introspection["data"]["__schema"].get("mutationType")
    mutation_type_name = mutation_type.get("name") if isinstance(mutation_type, dict) else mutation_type
    if mutation_type_name:
        mtype = next((t for t in types if t.get("name") == mutation_type_name), None)
        if mtype and "fields" in mtype:
            for f in mtype["fields"]:
                f_copy = f.copy()
                f_copy["_root"] = "mutation"
                methods.append(f_copy)

    return methods


# Follow NON_NULL / LIST / etc.
def resolve_type(t):
    # t is expected to be a dict with possible 'ofType' recursing
    while isinstance(t, dict) and t.get("ofType") is not None:
        t = t["ofType"]
    return t

# Recursively build full field tree for the query (response shape)
def build_field_tree(field_type, types, depth=0, visited=None):
    if visited is None:
        visited = set()

    field_type = resolve_type(field_type)

    # Some types might not have a name (e.g., scalars) - guard
    name = field_type.get("name")
    if name and name in visited:
        return ""

    if name:
        visited.add(name)

    if field_type.get("kind") != "OBJECT":
        return ""

    obj = next((t for t in types if t["name"] == field_type["name"]), None)
    if not obj or "fields" not in obj:
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

def save_query_to_file(method_name, query_text):
    # Ensure directory exists
    os.makedirs("queries", exist_ok=True)

    path = f"queries/{method_name}.txt"

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(query_text)
        print(f"📁 Query saved to: {path}\n")
    except Exception as e:
        print(f"❌ Error saving query: {e}")

def stringify_type(t):
    """Convert GraphQL type tree into a printable type string."""
    if not isinstance(t, dict):
        return "Unknown"
    if t.get("kind") == "NON_NULL":
        return f"{stringify_type(t['ofType'])}!"
    elif t.get("kind") == "LIST":
        return f"[{stringify_type(t['ofType'])}]"
    else:
        return t.get("name", "Unknown")

# Helpers to build inline input objects with example values
def build_input_object(type_ref, types, depth=0, visited=None):
    """
    Given a type reference (dict with kind/name/ofType), find the corresponding INPUT_OBJECT
    type definition in 'types' and return a formatted inline object string like:
      { username: "user", password: "pass" }
    """
    if visited is None:
        visited = set()

    resolved = resolve_type(type_ref)
    type_name = resolved.get("name")
    if not type_name:
        return "{}"

    if type_name in visited:
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
        # If defaultValue is provided in introspection, use it
        if f.get("defaultValue") is not None:
            val = f["defaultValue"]
            # defaultValue in introspection is a string representation; leave as-is
            parts.append(f"{inner_indent}{fname}: {val}")
            continue

        val = format_input_value(f["type"], types, fname, depth + 1, visited.copy())
        parts.append(f"{inner_indent}{fname}: {val}")

    if not parts:
        return "{}"

    if depth == 0:
        # single-line compact for top-level input
        inner = ", ".join(p.strip() for p in parts)
        return "{ " + inner + " }"
    else:
        # multi-line with indentation
        body = "\n".join(parts)
        return "{\n" + body + f"\n{indent}}}"

def format_input_value(type_ref, types, field_name=None, depth=0, visited=None):
    """
    Return a string representing a sample value for the given type reference.
    Strings are quoted, booleans and numbers are unquoted, lists are bracketed, objects expanded.
    """
    t = type_ref
    # Handle NON_NULL / LIST wrappers
    if not isinstance(t, dict):
        return "\"example\""

    if t.get("kind") == "NON_NULL":
        return format_input_value(t["ofType"], types, field_name, depth, visited)
    if t.get("kind") == "LIST":
        # produce a single-element list
        inner = format_input_value(t["ofType"], types, field_name, depth + 1, visited)
        return f"[{inner}]"

    # Now resolved scalar/enum/input object/type
    kind = t.get("kind")
    name = t.get("name", "")

    # Primitive scalars
    if kind == "SCALAR" or name in ("String", "ID", ""):
        # sensible defaults by common field name
        if field_name:
            lname = field_name.lower()
            if "user" in lname and "name" in lname:
                return f"\"{field_name}_example\""
            if "name" == lname:
                return f"\"{field_name}_example\""
            if "pass" in lname:
                return "\"password123\""
            if "email" in lname:
                return f"\"{field_name}@example.com\""
            if "msg" in lname or "message" in lname:
                return f"\"{field_name}_example\""
            if "role" in lname:
                return "\"user\""
        # default string
        return "\"example\""
    if name in ("Int", "Float"):
        return "0"
    if name == "Boolean":
        return "false"

    # Enums: try to pick first enum value if present
    if kind == "ENUM" or (name and any(ti.get("name") == name and ti.get("enumValues") for ti in types)):
        t_obj = next((ti for ti in types if ti.get("name") == name), None)
        if t_obj:
            enum_vals = t_obj.get("enumValues") or []
            if enum_vals:
                first = enum_vals[0].get("name")
                # enums are unquoted or sometimes unquoted values -> return first as bare token
                return first if first is not None else "\"ENUM_VALUE\""
        return "\"ENUM_VALUE\""

    # Input objects -> expand recursively
    if kind == "INPUT_OBJECT" or (name and any(ti.get("name") == name and ti.get("inputFields") for ti in types)):
        return build_input_object(t, types, depth, visited)

    # Fallback to string
    return "\"example\""

def generate_full_query(method_field, introspection):
    types = introspection["data"]["__schema"]["types"]

    # ---- Extract arguments ----
    args = method_field.get("args", []) or []
    variables = []
    call_args = []

    # Decide per-arg whether to inline (INPUT_OBJECT) or use variable
    for a in args:
        var_name = a["name"]
        resolved = resolve_type(a["type"])
        kind = resolved.get("kind")
        name = resolved.get("name")

        if kind == "INPUT_OBJECT" or (name and any(t.get("name") == name and t.get("inputFields") for t in types)):
            # inline expanded object
            inline_obj = build_input_object(a["type"], types)
            call_args.append(f"{var_name}: {inline_obj}")
        else:
            # keep as variable
            var_type = stringify_type(a["type"])
            variables.append(f"${var_name}: {var_type}")
            call_args.append(f"{var_name}: ${var_name}")

    # Build signature
    variables_str = f"({', '.join(variables)})" if variables else ""
    call_args_str = f"({', '.join(call_args)})" if call_args else ""

    # ---- Build field tree ----
    root_type = method_field["type"]
    fields_tree = build_field_tree(root_type, types, depth=2)

    # Determine operation type (query or mutation)
    operation = method_field.get("_root", "query")

    # ---- Build final query ----
    return f"""
{operation} {method_field['name']}{variables_str} {{
  {method_field['name']}{call_args_str} {{
{fields_tree}
  }}
}}
""".rstrip()


def print_help():
    print("""
Available commands:
  help               - Show this help message
  listMethods        - List all available GraphQL methods
  use <num|method>   - Select a method and immediately generate its full query
  exit               - Exit the application
""")


def interactive_console(methods, introspection):
    selected_method = None

    print("Type 'help' to see available commands.\n")

    while True:
        raw_cmd = input(f"{RED}Qgen ${RESET} ").strip()

        # --- PIPE SUPPORT ---
        if "|" in raw_cmd:
            left, _, right = raw_cmd.partition("|")
            cmd = left.strip()
            pipe_cmd = right.strip()

            if pipe_cmd.startswith("grep"):
                _, _, grep_text = pipe_cmd.partition("grep")
                grep_text = grep_text.strip().lower()
            else:
                print("❌ Unsupported pipe command.\n")
                continue
        else:
            cmd = raw_cmd
            pipe_cmd = None
        # ---------------------

        # Allow shorthand: bare number or exact method name selects the method
        # but don't override primary commands
        if not cmd.startswith("use ") and cmd not in ("help", "listMethods", "exit", ""):
            if cmd.isdigit():
                cmd = f"use {cmd}"
            else:
                if any(m["name"] == cmd for m in methods):
                    cmd = f"use {cmd}"

        # MAIN COMMAND HANDLING
        if cmd == "help":
            output = """Available commands:
  help               - Show this help message
  listMethods        - List all available GraphQL methods
  use <num|method>   - Select a method and immediately generate its full query
  exit               - Exit the application
"""
            if pipe_cmd:
                output = "\n".join(
                    line for line in output.splitlines() if grep_text in line.lower()
                )
            print(output)

        elif cmd == "listMethods":
            lines = []
            for i, m in enumerate(methods, start=1):
                root = m.get("_root", "query")
                prefix = "Q" if root == "query" else "M"
                lines.append(f" [{i}] ({prefix}) {m['name']}")

            if pipe_cmd:
                lines = [l for l in lines if grep_text in l.lower()]

            print("\n📌 Available methods:")
            for line in lines:
                print(line)
            print()

        elif cmd.startswith("use "):
            _, _, value = cmd.partition(" ")
            value = value.strip()

            if value.isdigit():
                idx = int(value) - 1
                if 0 <= idx < len(methods):
                    selected_method = methods[idx]
                    print(f"✔ Selected method: {selected_method['name']}\n")
                else:
                    print("❌ Invalid method number.\n")
                    continue
            else:
                match = next((m for m in methods if m["name"] == value), None)
                if match:
                    selected_method = match
                    print(f"✔ Selected method: {value}\n")
                else:
                    print("❌ Method not found.\n")
                    continue

            # Unified behavior: immediately generate the full query for the selected method
            try:
                query = generate_full_query(selected_method, introspection)
                print("\n----------------------------------------")
                print(f"{BLUE}{query}{RESET}")
                print("----------------------------------------\n")

                # Save the query automatically
                save_query_to_file(selected_method["name"], query)
            except Exception as e:
                print(f"❌ Error generating query: {e}\n")

        elif cmd == "exit":
            print("👋 Exiting...")
            break

        else:
            if cmd == "":
                # ignore empty input
                continue
            print("❌ Unknown command. Type 'help' for the command list.\n")


def main():
    print_banner()
    print("=== GraphQL Interactive CLI (extruder) ===\n")

    parser = argparse.ArgumentParser(description="GraphQL Introspection CLI Extruder")
    parser.add_argument(
        "--introspection",
        type=str,
        help="Path to introspection JSON file"
    )
    # New: endpoint URL to query introspection if --introspection is omitted
    parser.add_argument(
        "--url",
        type=str,
        help="GraphQL endpoint URL to perform introspection automatically if --introspection is not provided"
    )
    # Support repeated headers -H "Name: Value"
    parser.add_argument("-H", "--header", action="append", default=[], help="Additional HTTP header to include when performing automatic introspection. Format: 'Name: Value'")
    # Cookie file support (for automatic introspection)
    parser.add_argument("--cookie", help="File containing cookie in plain text (one line) to use when performing automatic introspection")
    # Saving option for automatic introspection
    parser.add_argument("--save-introspection", dest="save_introspection", action="store_true", help="Save automatic introspection to introspection_schema.json")
    parser.add_argument("--no-save-introspection", dest="save_introspection", action="store_false", help="Do not save automatic introspection to disk")
    parser.set_defaults(save_introspection=True)

    args = parser.parse_args()

    introspection = None

    # If provided via CLI file, try to load it directly
    if args.introspection:
        if os.path.exists(args.introspection):
            try:
                with open(args.introspection, "r", encoding="utf-8") as f:
                    introspection = json.load(f)
                print("✅ Introspection successfully loaded from CLI argument.\n")
            except Exception as e:
                print(f"❌ Error reading JSON: {e}\n")
                return
        else:
            print("❌ File path passed to --introspection does not exist.\n")
            return
    else:
        # Attempt to perform automatic introspection if --url provided
        if args.url:
            # Build headers: Content-Type + user provided headers + cookie (if provided)
            headers = {"Content-Type": "application/json"}
            extra_headers = parse_header_list(args.header)
            if args.cookie:
                if not os.path.exists(args.cookie):
                    print(f"❌ Cookie file not found: {args.cookie}\n")
                    return
                with open(args.cookie, "r", encoding="utf-8") as f:
                    cookie_value = f.read().strip()
                # Respect explicit Cookie header if user provided it via -H
                if "Cookie" not in extra_headers:
                    extra_headers["Cookie"] = cookie_value
            headers.update(extra_headers)

            print(f"[*] No --introspection provided; performing introspection query against {args.url} ...")
            result = perform_introspection_request(args.url, headers)
            if result is None:
                print("❌ Could not obtain introspection from endpoint. Falling back to interactive prompt.\n")
                introspection = load_introspection()
            else:
                introspection = result
                print("✅ Introspection obtained from endpoint.\n")
                if args.save_introspection:
                    save_introspection_file(introspection, path="introspection_schema.json")
        else:
            # Fall back to interactive prompt if no --url supplied
            introspection = load_introspection()

    methods = extract_graphql_queries(introspection)

    if not methods:
        print("❌ No GraphQL methods found in the introspection.")
        return

    interactive_console(methods, introspection)


if __name__ == "__main__":
    main()
