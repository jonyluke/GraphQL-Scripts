# Query Generator

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
>You must have previously obtained the result of an introspection query and save it to a json file like `introspection_schema.json`.

- You must execute the script like this:

```shell
python3 qGen.py --introspection /path/to/introspection_schema.json
```

- Then you'll be prompted with an interactive terminal:

```shell
qGen $
```

### Option 1

- You can list all methods and mutations available in your schema and select the one you are interested in:

```shell
# ------Listing methods and selecting one------
qGen $ listMethods

[redacted]
[1] findAllUsers
[2] findAllPasswords
[3] findAllConfigFiles

qGen $ use 1
qGen $ genQuery
```

### Option 2

- Directly use one method you know by name:

```shell
# ------Directly select one method------
qGen $ use findAllConfigFiles
qGen $ genQuery
```

### Option 3

- Search for specific methods according to a grep pipe:

```shell
# ------Search for alike methods------
qGen $ listMethods | grep Id

[redacted]
[11] findAllUsersById
[34] findAllPasswordsByUserId
[89] findAllConfigFilesByContractId

qGen $ use 89
qGen $ genQuery
```

## Available commands

- You can use the following commands:

```shell
  help               - Show the help message
  listMethods        - List all available GraphQL methods
  use <num|method>   - Select a method
  genQuery           - Generate a full GraphQL query with all fields
  exit               - Exit the application
```



