```markdown
# Query Generator (qGen)

This script helps you to generate sample queries for enormous GraphQL endpoints.

```shell
 ██████╗  ██████╗ ███████╗███╗   ██╗
██╔═══██╗██╔════╝ ██╔════╝████╗  ██║
██║   ██║██║  ███╗█████╗  ██╔██╗ ██║
██║▄▄ ██║██║   ██║██╔══╝  ██║╚██╗██║
╚██████╔╝╚██████╔╝███████╗██║ ╚████║
 ╚══▀▀═╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝
```

## Usage

>[!Important]
>You must either provide a saved introspection JSON file (e.g. `introspection_schema.json`) or allow qGen to fetch introspection automatically from a GraphQL endpoint by supplying `--url`. Automatic introspection requires the `requests` package.

- To run with a local introspection file:

```shell
python3 qGen.py --introspection /path/to/introspection_schema.json
```

- To run and let qGen obtain the introspection from a live endpoint (automatic mode):

```shell
python3 qGen.py --url https://example.com/graphql \
  -H "Authorization: Bearer TOKEN" \
  --cookie /path/to/cookie.txt
```

Notes:
- Automatic introspection requires the Python package `requests` (install with `pip install requests`).
- When qGen fetches introspection automatically, the result is saved by default to `introspection_schema.json`. Use `--no-save-introspection` to avoid saving the file.

- After starting, you'll be prompted with an interactive terminal:

```shell
qGen $
```

### Option 1 — List and select by index

You can list all methods available in your schema and select the one you want:

```shell
# ------ Listing methods and selecting one ------
qGen $ listMethods

[redacted]
[1] findAllUsers
[2] findAllPasswords
[3] findAllConfigFiles

qGen $ use 1
# Selecting a method with `use` immediately generates and prints the full query,
# and the query is automatically saved to queries/<method>.txt
```

### Option 2 — Select by name

Directly select a method by its name:

```shell
# ------ Directly select one method ------
qGen $ use findAllConfigFiles
# The query is generated and saved automatically
```

### Option 3 — Filtered listing with grep

You can pipe the output of `listMethods` through a simple grep filter:

```shell
# ------ Search for similar methods ------
qGen $ listMethods | grep Id

[redacted]
[11] findAllUsersById
[34] findAllPasswordsByUserId
[89] findAllConfigFilesByContractId

qGen $ use 89
# The full query for method 89 is generated and saved
```

## Available commands

- You can use the following commands:

```shell
  help               - Show the help message
  listMethods        - List all available GraphQL methods
  use <num|method>   - Select a method (by index or name) and immediately generate & save its full query
  exit               - Exit the application
```

Notes about behavior and output
- The `use` command now combines selection and query generation: when you `use` a method, qGen prints the complete GraphQL query (including nested selections) and saves it into `queries/<method>.txt`.
- Saved queries are stored in the `queries/` directory (created automatically if missing).
- A typical generated query will include all scalar fields and descend into nested object fields where possible (respecting cycles by avoiding repeated types).

Example interactive output (sample)
```text
qGen $ use getAllUsers

----------------------------------------
query getAllUsers {
  getAllUsers {
    id
    username
    email
    profile {
      id
      name
    }
  }
}
----------------------------------------

📁 Query saved to: queries/getAllUsers.txt
```

Troubleshooting
- If automatic introspection fails, check:
  - That the `--url` is correct and reachable.
  - Authentication headers or cookie are correct (`-H "Authorization: Bearer ..."` or `--cookie /path/to/cookie.txt`).
  - That the server responds to GraphQL introspection and returns JSON containing `__schema`.
- If you prefer to avoid network fetching, run the introspection query separately (using curl, GraphiQL, or another client), save the JSON, and pass it with `--introspection`.
- If a generated query is too large for your client, consider manually trimming fields or selecting nested fields selectively.
