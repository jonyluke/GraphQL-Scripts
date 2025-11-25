# GraphQL-Scripts

This repository contains a series of useful scripts for pentesting GraphQL endpoints.

## Basic Information

This repository contains two scripts: [qGen.py]() and [effuzz.py]().
- `qGen.py` allows you to list all the methods available in your GraphQL schema and then generate a query to dump all possible information with a method (like `findAllUsers`).
- `effuzz.py` allows you to check permissions in all the methods of your GraphQL schema (similar output to `ffuf`).

## Methodology to use

>[!Important]
>You must have previously obtained the result of an introspection query and save it to a json file like `introspection_schema.json`

- You can first run `effuzz.py` to check for interesting methods allowed for your session:

```shell
python3 effuzz.py --introspection /path/to/introspection_schema.json --url https://example.com/graphql

[redacted]
getAllTests    [Status: 401] [Size: 32] [Words: 5] [Lines: 1]
getAllUsers    [Status: 400] [Size: 261] [Words: 25] [Lines: 1] #<----- This indicates a malformed query, so you have permissions for this one
getAllConfigs   [Status: 200] [Size: 48] [Words: 15] [Lines: 1] #<----- You also have permissions for this one
```
  
- Once you obtained those methods who might interest you, you can run `qGen.py` and generate a query for that method:

```shell
python3 qGen.py --introspection /path/to/introspection_schema.json

[redacted]
qGen $ use getAllUsers
qGen $ genQuery
```

- Now you can copy the query generated and paste it into BurpSuite, PostMan or GraphiQL.
