# GraphQL SQLi Detector (sqli_detector.py)

A compact GraphQL SQL injection mini-detector (Python). This script performs GraphQL introspection, attempts a set of SQLi-like payloads against candidate string arguments, and writes reproducible marker `.http` files for use with sqlmap. The detector includes heuristics to reduce false positives and attempts to populate required arguments using values extracted from simple queries or an optional limited crawler. It also prioritizes discovered admin API keys when filling key-like arguments to increase coverage of privileged code paths.

---

## Key capabilities
- Performs GraphQL introspection to discover `Query` fields and their arguments.
- Extracts real values from simple queries (tokens, keys, names) to use as baseline or to fill required arguments.
- Optional, opt-in crawling to follow relationships and collect more candidate inputs (Relay-style pagination attempts included).
- Decodes common GraphQL global IDs encoded as base64 and adds decoded IDs as candidates.
- Tests string-like arguments with a curated set of SQLi payloads.
- Detects SQL error messages included in GraphQL `errors`.
- Detects response differences (baseline vs attack), `NULL`-on-attack, and other signals.
- Writes reproducible `.http` marker files in `repro-payloads/` where the vulnerable value is replaced by `*`.
- Produces a recommended sqlmap command for confirmed findings.
- Prioritizes API keys discovered with role `admin` when filling key-like arguments (e.g. `apiKey`, `key`, `token`), increasing the chance to reach privileged code paths.
- Uses confirmation rules to reduce false positives (reports only when evidence is strong).

---

## What the detector does (high-level)
1. Runs GraphQL introspection to obtain types and `Query` fields.  
2. Extracts values from simple, argument-less queries (seed phase) and, optionally, runs a limited BFS-style crawl:
   - For seed fields it tries several query shapes (simple selection, Relay `first:N` with `edges.node`, and `first:N` without edges) to coax items out of paginated endpoints.
   - Decodes base64/global IDs and adds decoded IDs (and `<Type>Id` keys) to candidate pools.
   - Follows id-like args using extracted IDs to expand discovery.
3. For each field with string-like arguments:
   - Builds a working baseline by trying a few combinations of plausible values for other args.
   - Sends curated SQLi-like payloads in the target argument.
   - Skips GraphQL syntax errors (not SQLi).
   - Detects SQL error messages, response diffs, and null-on-attack.
   - If a required argument is missing, attempts to fill it from extracted values (with a simple name-match fallback).
4. For confirmed signals, writes a `.http` marker file with the attack request (attacked value replaced by `*`) and suggests a sqlmap command.

---

## Usage
Basic usage:
```bash
python sqli_detector.py <endpoint> [headers_json]
```

Examples:
- Quick run without crawling:
  ```bash
  python sqli_detector.py https://example.com/graphql
  ```
- Run with authorization header (no crawl):
  ```bash
  python sqli_detector.py https://example.com/graphql '{"Authorization":"Bearer TOKEN"}'
  ```
- Run with crawling (authorized audits only):
  ```bash
  python sqli_detector.py https://example.com/graphql '{"Authorization":"Bearer TOKEN"}' --crawl --crawl-depth 2 --max-requests 200 --max-items 10 --crawl-delay 0.1 --verbose
  ```

---

## CLI flags (summary)
- `<endpoint>` (positional)  
  GraphQL endpoint URL.

- `[headers_json]` (positional, optional)  
  JSON string or simple "Key: Value" pairs (e.g. `'{"Authorization":"Bearer TOKEN"}'`).

- `--crawl`  
  Enable limited crawling to extract outputs and reuse them as inputs. Opt-in because crawling increases requests.

- `--crawl-depth N` (default: 2)  
  Maximum crawl depth (BFS levels).

- `--max-requests N` (default: 250)  
  Maximum number of requests allowed during crawling.

- `--max-items N` (default: 10)  
  Max items per list to inspect when extracting values.

- `--crawl-delay FLOAT` (default: 0.0)  
  Delay in seconds between requests during crawling.

- `--verbose`  
  Print queries and additional debug information (useful to inspect what the crawler is calling and the responses).
  
---

## Output
- Human-readable findings printed to stdout (colored if colorama is available).
- Repro marker files written to `repro-payloads/` when findings are confirmed. Filenames include a sanitized field/arg name, timestamp, and short hash to avoid collisions.
- Each finding contains:
  - field and argument name
  - arguments used for the attack
  - evidence (error message or description)
  - marker request path
  - recommended sqlmap command:
    ```
    sqlmap --level 5 --risk 3 -r '<marker.http>' -p "JSON[query]" --batch --skip-urlencode --random-agent
    ```

---

## Marker (.http) files
- Marker files are full HTTP POST requests that include headers and a JSON body where the vulnerable value has been replaced by `*`. Example:
  ```
  POST /graphql HTTP/1.1
  Host: example.com
  Content-Type: application/json
  Authorization: Bearer TOKEN

  {"query":"query { user(id: \"123\") { email } }"}
  ```
- The target value in the JSON is substituted with `*` so sqlmap can inject into `JSON[query]` using `-r <marker>` and `-p "JSON[query]"`.

---

## Detection heuristics / confirmation rules
To reduce noisy false positives the detector reports a parameter only when one or more of the following hold:
- A clear SQL error is present in GraphQL `errors` (matches DB error signatures), OR
- Two or more distinct payloads produce evidence, OR
- A combination of strong signals (e.g., RESPONSE_DIFF + NULL_ON_ATTACK), OR
- A `NULL_ON_ATTACK` signal confirmed against a meaningful baseline.

Signals checked:
- SQL error messages in `errors` (MySQL/Postgres/SQLite mentions, syntax errors, etc.)
- Response differences between baseline and attacked request
- `null` appearing in the attack response while baseline returned data
- Differences in a simple `__typename` baseline vs attack (quick sanity check)

---

## Limitations
- Small, curated payload set — not exhaustive. Use sqlmap (the generated markers) for deeper automated testing.
- Tests are sequential; there is no built-in concurrency/worker pool. For large schemas consider extending to multiple workers.
- Crawling can reveal or store sensitive data. Use crawling only on authorized targets and treat `repro-payloads/` as sensitive output.
- Time-based blind SQLi is not tested by default. Add time-based payloads and response timing checks to detect blind techniques.
- If GraphQL introspection is disabled, discovery will fail; provide schema manually or use alternative enumeration techniques.
- Complex input objects, deeply nested relationships, or custom auth flows may need custom logic to populate arguments successfully.

---

## Suggested next improvements
- Add flags for:
  - concurrency / workers
  - custom payload lists and strategies
- Expand payloads to include boolean- and time-based techniques (blind SQLi).
- Add more robust heuristics (email/UUID/hash detection, fuzzy matches).
