#!/usr/bin/env python3
"""
effuzz.py — GraphQL endpoint fuzzer.

Enumerates every query and mutation from the schema and sends a minimal request
for each, reporting HTTP status/size/words/lines (ffuf-style output).

Extra modes:
  --discover       Probe common GraphQL paths and confirm with {__typename}
  --check-methods  Test GET and form-urlencoded support (CSRF surface assessment)
"""

import json
import os
import sys
import argparse
import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse, urlencode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import requests
except ImportError:
    print("[!] 'requests' library required. Install with: pip install requests",
          file=sys.stderr)
    sys.exit(1)

import core.introspection as core_intro
from core.http import build_headers
from core.output import RED, GREEN, YELLOW, BLUE, RESET

# Ordered by likelihood of being a valid GraphQL endpoint
GRAPHQL_DISCOVERY_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/graphql/console",
    "/api",
    "/graphql/api",
    "/graphql/graphql",
    "/graphql.php",
]


def print_banner():
    print(textwrap.dedent(f"""
    {YELLOW}
    ███████╗███████╗███████╗██╗   ██╗███████╗███████╗
    ██╔════╝██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
    █████╗  █████╗  █████╗  ██║   ██║  ███╔╝   ███╔╝
    ██╔══╝  ██╔══╝  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝
    ███████╗██║     ██║     ╚██████╔╝███████╗███████╗
    ╚══════╝╚═╝     ╚═╝      ╚═════╝╚══════╝╚══════╝ v1.1
    {RESET}"""))


def response_stats(resp: requests.Response) -> Tuple[int, int, int]:
    text = resp.text or ""
    return len(text), len(text.split()), text.count("\n") + 1


def color_status(code: int, resp: requests.Response) -> str:
    if code == 200:
        try:
            if "errors" not in resp.json():
                return f"{GREEN}{code}{RESET}"
        except Exception:
            pass
        return f"{YELLOW}{code}{RESET}"
    if code in (401, 403) or "Method forbidden" in resp.text:
        return f"{RED}{code}{RESET}"
    if code in (400, 500):
        return f"{YELLOW}{code}{RESET}"
    return str(code)


def build_minimal_query(method_name: str, is_mutation: bool = False) -> str:
    """Build the simplest possible query for a field to gauge accessibility."""
    op = "mutation" if is_mutation else "query"
    return f"{op} {{ {method_name} }}"


def perform_request(url: str, headers: Dict[str, str], payload: Dict[str, Any],
                    timeout: int = 15) -> Optional[requests.Response]:
    try:
        return requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error for {url}: {e}", file=sys.stderr)
        return None


def _get_typename(url: str, headers: Dict[str, str], timeout: int = 10) -> Optional[str]:
    """Send {__typename} and return the typename string, or None if not GraphQL."""
    try:
        resp = requests.post(url, headers=headers,
                             json={"query": "query{__typename}"}, timeout=timeout)
        data = resp.json()
        if isinstance(data, dict):
            d = data.get("data") or data
            if isinstance(d, dict):
                return d.get("__typename")
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- #
#  --discover mode                                                             #
# --------------------------------------------------------------------------- #

def discover_endpoint(base_url: str, headers: Dict[str, str],
                      timeout: int = 10) -> Optional[str]:
    """Probe standard GraphQL paths and return the first confirmed endpoint URL."""
    parsed = urlparse(base_url)
    base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    print(f"[*] Discovering GraphQL endpoint under {base}")
    print(f"{'Path':<35} {'Status':<8} {'Confirmed'}")
    print("-" * 65)

    confirmed_url = None
    for path in GRAPHQL_DISCOVERY_PATHS:
        candidate = base + path
        try:
            resp = requests.post(
                candidate, headers=headers,
                json={"query": "query{__typename}"}, timeout=timeout,
            )
            typename = None
            try:
                data = resp.json()
                if isinstance(data, dict):
                    d = data.get("data") or data
                    if isinstance(d, dict):
                        typename = d.get("__typename")
            except Exception:
                pass

            if typename:
                tag = f"{GREEN}YES — __typename: {typename}{RESET}"
                if confirmed_url is None:
                    confirmed_url = candidate
            else:
                tag = "no"
            print(f"{path:<35} {resp.status_code:<8} {tag}")
        except requests.exceptions.ConnectionError:
            print(f"{path:<35} {'—':<8} (connection refused)")
        except requests.exceptions.Timeout:
            print(f"{path:<35} {'timeout':<8}")
        except Exception as e:
            print(f"{path:<35} {'error':<8} {e}")

    print()
    if confirmed_url:
        print(f"[+] Using confirmed endpoint: {confirmed_url}\n")
    else:
        print(f"{RED}[!] No GraphQL endpoint found under {base}{RESET}\n")
    return confirmed_url


# --------------------------------------------------------------------------- #
#  --check-methods mode (CSRF surface)                                        #
# --------------------------------------------------------------------------- #

def check_csrf_surface(url: str, headers: Dict[str, str], timeout: int = 10) -> None:
    """Test whether the endpoint accepts GET queries and form-urlencoded POSTs.

    Both request types bypass CORS preflight and are exploitable for CSRF if the
    endpoint accepts them and relies solely on session cookies for auth.
    """
    print("[*] CSRF surface check:")
    no_ct_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}

    # 1. GET with ?query=...
    try:
        get_url = url + "?" + urlencode({"query": "{__typename}"})
        resp = requests.get(get_url, headers=no_ct_headers, timeout=timeout)
        typename = None
        try:
            data = resp.json()
            if isinstance(data, dict):
                d = data.get("data") or data
                if isinstance(d, dict):
                    typename = d.get("__typename")
        except Exception:
            pass
        if typename:
            status = f"{GREEN}ACCEPTS{RESET}  ← CSRF possible if no token validation"
        elif resp.status_code == 200:
            status = f"{YELLOW}responded{RESET}  (no __typename, may be partial)"
        else:
            status = f"rejected (HTTP {resp.status_code})"
        print(f"  GET  ?query={{...}}          {status}")
    except Exception as e:
        print(f"  GET  ?query={{...}}          error: {e}")

    # 2. POST with application/x-www-form-urlencoded
    try:
        form_headers = dict(no_ct_headers)
        form_headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlencode({"query": "{__typename}"})
        resp = requests.post(url, headers=form_headers, data=body, timeout=timeout)
        typename = None
        try:
            data = resp.json()
            if isinstance(data, dict):
                d = data.get("data") or data
                if isinstance(d, dict):
                    typename = d.get("__typename")
        except Exception:
            pass
        if typename:
            status = f"{GREEN}ACCEPTS{RESET}  ← CSRF possible (no CORS preflight on form POST)"
        elif resp.status_code == 200:
            status = f"{YELLOW}responded{RESET}  (no __typename, may be partial)"
        else:
            status = f"rejected (HTTP {resp.status_code})"
        print(f"  POST form-urlencoded        {status}")
    except Exception as e:
        print(f"  POST form-urlencoded        error: {e}")

    print()


# --------------------------------------------------------------------------- #
#  Core fuzzing loop                                                           #
# --------------------------------------------------------------------------- #

def fuzz_fields(url: str, headers: Dict[str, str],
                fields: List[str], label: str,
                variables_value: Dict[str, Any],
                is_mutation: bool,
                match_codes: Optional[set],
                filter_codes: Optional[set],
                silent: bool,
                debug: bool) -> None:
    if not fields:
        print(f"[*] No {label} found in schema.")
        return

    print(f"\n[*] Fuzzing {label} ({len(fields)}):")
    print(f"{'Method':<35} {'Type':<10} Status     Size    Words   Lines")
    print("-" * 80)

    for name in fields:
        query_str = build_minimal_query(name, is_mutation)
        payload: Dict[str, Any] = {"query": query_str}
        if variables_value:
            payload["variables"] = variables_value

        resp = perform_request(url, headers, payload)
        if resp is None:
            print(f"{name:<35} {'mutation' if is_mutation else 'query':<10} {RED}request failed{RESET}")
            continue

        code = resp.status_code
        size, words, lines = response_stats(resp)
        colored = color_status(code, resp)

        if match_codes and code not in match_codes:
            continue
        if filter_codes and code in filter_codes:
            continue
        if silent and code == 401:
            continue

        op_label = "mutation" if is_mutation else "query"
        print(f"{name:<35} {op_label:<10} [Status: {colored}] "
              f"[Size: {size}] [Words: {words}] [Lines: {lines}]")

        if debug:
            try:
                print(json.dumps(resp.json(), indent=2, ensure_ascii=False))
            except Exception:
                print(resp.text)

    print("-" * 80)


# --------------------------------------------------------------------------- #
#  main                                                                        #
# --------------------------------------------------------------------------- #

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="GraphQL endpoint fuzzer — enumerates operations and checks accessibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", required=True, metavar="URL",
                        help="GraphQL endpoint URL (auto-discovery runs if it doesn't respond as GraphQL)")
    parser.add_argument("--check-methods", action="store_true",
                        help="Test GET and form-urlencoded support (CSRF surface)")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="Hide 401 responses")
    parser.add_argument("--cookie", metavar="FILE",
                        help="Cookie file (one line)")
    parser.add_argument("--variables", metavar="FILE",
                        help="JSON file with variables to include in each request")
    parser.add_argument("--debug", action="store_true",
                        help="Print full response body for each request")
    parser.add_argument("--match-code", "-mc", metavar="CODES",
                        help="Show only these status codes, comma-separated (e.g. 200,400)")
    parser.add_argument("--filter-code", "-fc", metavar="CODES",
                        help="Hide these status codes, comma-separated (e.g. 401,404)")
    parser.add_argument("-H", "--header", action="append", default=[],
                        metavar="Name: Value",
                        help="HTTP header (repeatable)")
    args = parser.parse_args()

    # --- Build headers ---
    if args.cookie and not os.path.isfile(args.cookie):
        print(f"[!] Cookie file not found: {args.cookie!r}", file=sys.stderr)
        sys.exit(1)
    headers = build_headers(args.header, args.cookie)

    # --- Parse code filters ---
    def _parse_codes(raw: Optional[str]) -> Optional[set]:
        if not raw:
            return None
        result = set()
        for tok in raw.split(","):
            tok = tok.strip()
            if not tok.isdigit():
                print(f"[!] Invalid status code in filter: {tok!r}", file=sys.stderr)
                sys.exit(1)
            result.add(int(tok))
        return result

    match_codes = _parse_codes(args.match_code)
    filter_codes = _parse_codes(args.filter_code)

    # --- Load variables ---
    variables_value: Dict[str, Any] = {}
    if args.variables:
        if not os.path.isfile(args.variables):
            print(f"[!] Variables file not found: {args.variables!r}", file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.variables, "r", encoding="utf-8") as f:
                variables_value = json.load(f)
        except (ValueError, OSError) as e:
            print(f"[!] Variables file is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)

    # ------------------------------------------------------------------ #
    #  Resolve GraphQL endpoint (auto-discover if URL isn't GraphQL)      #
    # ------------------------------------------------------------------ #
    graphql_url = args.url
    if _get_typename(graphql_url, headers) is None:
        print(f"[!] {graphql_url} did not respond as a GraphQL endpoint — running auto-discovery...")
        confirmed = discover_endpoint(graphql_url, headers)
        if confirmed is None:
            print(f"{RED}[!] No GraphQL endpoint found. Aborting.{RESET}", file=sys.stderr)
            sys.exit(1)
        graphql_url = confirmed

    # ------------------------------------------------------------------ #
    #  --check-methods: CSRF surface                                      #
    # ------------------------------------------------------------------ #
    if args.check_methods:
        check_csrf_surface(graphql_url, headers)

    # ------------------------------------------------------------------ #
    #  Fetch introspection                                                 #
    # ------------------------------------------------------------------ #
    print(f"[*] Fetching introspection from {graphql_url} ...")
    introspection_data, strategy = core_intro.fetch_with_bypass(graphql_url, headers)
    if introspection_data is None:
        print("[!] All introspection strategies failed — attempting error-based reconstruction...")
        introspection_data = core_intro.reconstruct_schema_from_errors(graphql_url, headers)
        if introspection_data is None:
            print("[!] Could not obtain schema.", file=sys.stderr)
            sys.exit(1)
        strategy = "error-reconstruction"
    tag = f" (strategy: {strategy})" if strategy and strategy != "post-json" else ""
    print(f"[+] Introspection obtained{tag}.")

    schema = core_intro.extract_schema(introspection_data)
    if not schema:
        print("[!] '__schema' not found in introspection.", file=sys.stderr)
        sys.exit(1)

    types = schema.get("types") or []

    def _get_fields(type_name: Optional[str]) -> List[str]:
        if not type_name:
            return []
        for t in types:
            if t.get("name") == type_name:
                return [f["name"] for f in (t.get("fields") or [])]
        return []

    queries = _get_fields((schema.get("queryType") or {}).get("name"))
    mutations = _get_fields((schema.get("mutationType") or {}).get("name"))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"\n[+] Schema: {len(queries)} queries, {len(mutations)} mutations")
    print(f"[*] Target: {graphql_url}  |  {ts}")

    # ------------------------------------------------------------------ #
    #  Fuzz                                                               #
    # ------------------------------------------------------------------ #
    fuzz_fields(graphql_url, headers, queries, "queries",
                variables_value, False,
                match_codes, filter_codes, args.silent, args.debug)

    fuzz_fields(graphql_url, headers, mutations, "mutations",
                variables_value, True,
                match_codes, filter_codes, args.silent, args.debug)

    print("\n[*] effuzz done.")


if __name__ == "__main__":
    main()
