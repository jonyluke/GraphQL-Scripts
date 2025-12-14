```markdown
# Endpoint Fuzzer (effuzz)

This script helps you detect which GraphQL methods you may be able to call (or have permissions for) by enumerating Query/Mutation names from an introspection schema and performing lightweight checks.

```shell
███████╗███████╗███████╗██╗   ██╗███████╗███████╗
██╔════╝██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
█████╗  █████╗  █████╗  ██║   ██║  ███╔╝   ███╔╝ 
██╔══╝  ██╔══╝  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
███████╗██║     ██║     ╚██████╔╝███████╗███████╗
╚══════╝╚═╝     ╚═╝      ╚═════╝╚══════╝╚══════╝
```

## Overview

effuzz enumerates available fields from a GraphQL schema and issues minimal GraphQL requests for each method to learn how the server responds. It is useful to quickly spot methods that accept requests (status 200/400) versus those that deny access (401/403) or cause other errors.

Two modes:
- Explicit introspection: supply a previously saved introspection JSON with `--introspection`.
- Automatic introspection: omit `--introspection` and provide `--url`; effuzz will attempt to fetch the schema from the endpoint (requires the `requests` library). By default the fetched introspection is saved to `introspection_schema.json` (toggle with `--no-save-introspection`).

Note: Use these tools only on targets you are authorized to test.

## Requirements

- Python 3.7+
- requests (only required for automatic introspection / HTTP requests):
  pip install requests

## Usage

Important: either provide a local introspection JSON or let effuzz fetch it automatically from the target with `--url`.

- Using a saved introspection file (explicit mode):

```shell
python3 effuzz/effuzz.py --introspection /path/to/introspection_schema.json --url https://example.com/graphql
```

- Automatic introspection (effuzz fetches the schema from the endpoint):

```shell
python3 effuzz/effuzz.py --url https://example.com/graphql \
  -H "Authorization: Bearer TOKEN" \
  --cookie /path/to/cookie.txt
```

- With variables file and cookie:

```shell
python3 effuzz/effuzz.py --introspection /path/to/introspection_schema.json \
  --url https://example.com/graphql \
  --cookie /path/to/cookie.txt \
  --variables /path/to/variables.json
```

- Enable debug to inspect request and response bodies:

```shell
python3 effuzz/effuzz.py --introspection introspection_schema.json --url https://example.com/graphql --debug
```

- Match specific response status codes (show only these):

```shell
python3 effuzz/effuzz.py --introspection introspection_schema.json --url https://example.com/graphql --match-code 200,403
```

- Filter out specific status codes (hide these):

```shell
python3 effuzz/effuzz.py --introspection introspection_schema.json --url https://example.com/graphql --filter-code 401,404
```

## Important options

```text
--introspection        Path to the introspection JSON file (optional if --url is used)
--url                 GraphQL endpoint URL (required for automatic introspection)
-H, --header          Add HTTP header(s) for requests; repeatable. Format: "Name: Value"
-s, --silent          Hide responses that return 401
--cookie              File containing cookie value (one line); ignored if Cookie provided via -H
--variables           JSON file with variables to include in requests
--debug               Print full request and response bodies (helps troubleshooting)
--match-code, -mc     Show only responses with these status codes (comma separated)
--filter-code, -fc    Hide responses that match these status codes (comma separated)
--save-introspection  Save automatic introspection to introspection_schema.json (default)
--no-save-introspection Do not save automatic introspection to disk
```

## Example output

A short sample run (values and counts are illustrative):

```text
$ python3 effuzz/effuzz.py --introspection introspection_schema.json --url http://94.237.63.174:57732/graphql

[✓] Introspection loaded (120 queries, 8 mutations)
------------------------------------------------------------
getAllTests         [Status: 401] [Size: 32]  [Words: 5]  [Lines: 1]
getAllUsers         [Status: 400] [Size: 261] [Words: 25] [Lines: 1]   # malformed query -> server accepted request
getAllConfigs       [Status: 200] [Size: 48]  [Words: 15] [Lines: 1]   # likely accessible
findUserByEmail     [Status: 200] [Size: 512] [Words: 80] [Lines: 3]   # returns data
------------------------------------------------------------
(Use --debug to dump full responses)
```

Notes on interpreting results:
- 401 / 403: usually indicates authentication/authorization required.
- 400: GraphQL servers commonly return 400 for syntactically invalid or semantically wrong queries – this can still mean the method exists and the server processed the request.
- 200: successful request; check response body for `data` or `errors` to decide further steps.

## Troubleshooting

- Automatic introspection fails:
  - Ensure `--url` points to the GraphQL endpoint.
  - Provide proper auth headers with `-H "Authorization: Bearer ..."` or use `--cookie`.
  - Check that the server accepts the introspection query (some servers disable it).
  - If the endpoint returns non-JSON or a wrapper format, effuzz may not detect `__schema`.

- Requests fail with network errors:
  - Try increasing timeout in the code or check network connectivity/proxy settings.

- Too many fields / huge schema:
  - Consider filtering or generating smaller payloads when using the `--variables` option or modifying the request loop.

## Security & ethics

Only run effuzz on systems you are authorized to test. These tools are intended for legitimate security testing and research.

## Further reading / next steps

- Use qGen to generate full queries for interesting methods discovered by effuzz.
- Use the sqli helper to target string arguments found in introspection for simple SQLi checks.
```
```
