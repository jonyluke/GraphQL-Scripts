#!/usr/bin/env python3
import json
import requests
import argparse
import sys
import os
 
# =====================================================
# COLORS
# =====================================================
RED = "\033[91m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"
CYAN = "\033[36m"
RESET = "\033[0m"
 
def print_banner():
    print(f"""
{YELLOW}
███████╗███████╗███████╗██╗   ██╗███████╗███████╗
██╔════╝██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
█████╗  █████╗  █████╗  ██║   ██║  ███╔╝   ███╔╝ 
██╔══╝  ██╔══╝  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
███████╗██║     ██║     ╚██████╔╝███████╗███████╗
╚══════╝╚═╝     ╚═╝      ╚═════╝ ╚══════╝╚══════╝
                                                  v1.0
{RESET}
 
{CYAN}made by gitblanc — https://github.com/gitblanc/GraphQL-Scripts{RESET}
 
""")
 
# =====================================================
# CLI ARGUMENTS
# =====================================================
parser = argparse.ArgumentParser(description="Test GraphQL endpoints using introspection.")
parser.add_argument("--introspection", required=True, help="Path to the introspection JSON file")
parser.add_argument("--url", required=True, help="GraphQL endpoint URL")
 
parser.add_argument("-s", "--silent", action="store_true",
                    help="Only show endpoints that DO NOT return 401")
 
parser.add_argument("--cookie", help="File containing cookie in plain text (one line)")
parser.add_argument("--variables", help="JSON file with variables for the payload")
parser.add_argument("--debug", action="store_true", help="Show full request and response")
parser.add_argument("--match-code", "-mc",
                    help="Show only responses with matching status codes (e.g., 200,403,500)")
parser.add_argument("--filter-code", "-fc",
                    help="Hide responses with matching status codes (e.g., 401,404)")
 
args = parser.parse_args()
 
GRAPHQL_URL = args.url
INTROSPECTION_FILE = args.introspection
 
# Parse match-code
match_codes = None
if args.match_code:
    match_codes = set(int(x.strip()) for x in args.match_code.split(",") if x.strip().isdigit())
 
# Parse filter-code
filter_codes = None
if args.filter_code:
    filter_codes = set(int(x.strip()) for x in args.filter_code.split(",") if x.strip().isdigit())
 
print_banner()
 
# =====================================================
# VALIDATE FILE
# =====================================================
if not os.path.exists(INTROSPECTION_FILE):
    print(f"❌ File not found: {INTROSPECTION_FILE}")
    sys.exit(1)
 
try:
    with open(INTROSPECTION_FILE, "r") as f:
        introspection_data = json.load(f)
except json.JSONDecodeError:
    print("❌ The introspection file is NOT valid JSON.")
    sys.exit(1)
 
# =====================================================
# LOAD COOKIE AND VARIABLES
# =====================================================
cookie_value = None
if args.cookie:
    if not os.path.exists(args.cookie):
        print(f"❌ Cookie file not found: {args.cookie}")
        sys.exit(1)
    with open(args.cookie, "r") as f:
        cookie_value = f.read().strip()
 
variables_value = {}
if args.variables:
    if not os.path.exists(args.variables):
        print(f"❌ Variables file not found: {args.variables}")
        sys.exit(1)
    try:
        with open(args.variables, "r") as f:
            variables_value = json.load(f)
    except:
        print("❌ Variables file is NOT valid JSON.")
        sys.exit(1)
 
# =====================================================
# EXTRACT QUERIES / MUTATIONS FROM THE SCHEMA
# =====================================================
if "data" not in introspection_data:
    print("❌ JSON does not contain 'data' key. Not valid introspection.")
    sys.exit(1)
 
schema = introspection_data["data"].get("__schema", {})
types = schema.get("types", [])
 
def get_fields(type_name):
    for t in types:
        if t.get("name") == type_name:
            return [f["name"] for f in t.get("fields", [])]
    return []
 
query_type_name = schema.get("queryType", {}).get("name")
mutation_type_name = schema.get("mutationType", {}).get("name")
 
queries = get_fields(query_type_name) if query_type_name else []
mutations = get_fields(mutation_type_name) if mutation_type_name else []
 
print(f"[✓] Introspection loaded ({len(queries)} queries, {len(mutations)} mutations)")
print("------------------------------------------------------------")
 
# =====================================================
# HEADERS (With or without authentication)
# =====================================================
HEADERS = {
    "Content-Type": "application/json"
}
 
if cookie_value:
    HEADERS["Cookie"] = cookie_value
 
# =====================================================
# FFUF-LIKE PROCESSING
# =====================================================
def response_stats(resp):
    text = resp.text
    size = len(text)
    words = len(text.split())
    lines = text.count("\n") + 1
    return size, words, lines
 
def color_status(code, resp):
    """Assign a color according to the real response type."""
 
    if code == 200:
        try:
            data = resp.json()
            if "errors" not in data:
                return f"{GREEN}{code}{RESET}"
        except:
            pass
        return f"{YELLOW}{code}{RESET}"
 
    if code in (401, 403) or "Method forbidden" in resp.text:
        return f"{RED}{code}{RESET}"
 
    if code in (400, 500):
        return f"{YELLOW}{code}{RESET}"
 
    return str(code)
 
 
def test_endpoint(name, is_mutation=False):
 
    if is_mutation:
        gql = f"mutation {name} {{ {name} }}"
    else:
        gql = f"query {name} {{ {name} }}"
 
    body = {
        "operationName": name,
        "variables": variables_value,
        "query": gql
    }
 
    try:
        if args.debug:
            print("\n====================== REQUEST ======================")
            print("→ Endpoint:", GRAPHQL_URL)
            print("→ Headers:", json.dumps(HEADERS, indent=2))
            print("→ Sent body:")
            print(json.dumps(body, indent=2))
        resp = requests.post(GRAPHQL_URL, headers=HEADERS, json=body)
        if args.debug:
            print("\n====================== RESPONSE =====================")
            print("← HTTP Status:", resp.status_code)
            try:
                print(json.dumps(resp.json(), indent=2))
            except:
                print(resp.text)
            print("=====================================================\n")
    except Exception:
        return None
 
    size, words, lines = response_stats(resp)
    status_colored = color_status(resp.status_code, resp)
 
    return {
        "status": status_colored,
        "status_raw": resp.status_code,
        "size": size,
        "words": words,
        "lines": lines,
    }
 
# =====================================================
# FFUF-LIKE OUTPUT
# =====================================================
def print_result(name, r):
    if r is None:
        return
 
    status_raw = r["status_raw"]
 
    if args.silent and status_raw == 401:
        return
 
    if match_codes is not None and status_raw not in match_codes:
        return
 
    if filter_codes is not None and status_raw in filter_codes:
        return
 
    print(
        f"{CYAN}{name}{RESET}   "
        f"[Status: {r['status']}] "
        f"[Size: {r['size']}] "
        f"[Words: {r['words']}] "
        f"[Lines: {r['lines']}] "
    )
 
# ========================= QUERIES ==========================
for q in queries:
    res = test_endpoint(q)
    print_result(q, res)
 
# ========================= MUTATIONS ==========================
for m in mutations:
    res = test_endpoint(m, is_mutation=True)
    print_result(m, res)
 
print("\n[✓] Test completed.\n")
