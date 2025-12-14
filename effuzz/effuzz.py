#!/usr/bin/env python3
"""
effuzz.py - GraphQL endpoint fuzzer

Comportamiento principal:
- Si se pasa --introspection /ruta/to/file.json, carga ese JSON (valida).
- Si no se pasa --introspection, realiza automáticamente la consulta de introspección
  al endpoint definido por --url usando las cabeceras (-H/--header) y --cookie si se proporcionan.
  Por defecto guarda la introspección en introspection_schema.json (puedes desactivar con --no-save-introspection).
- Extrae queries y mutations del esquema y realiza una comprobación básica tipo ffuf (envía peticiones y muestra status/size/words/lines).
- Mantiene opciones: --variables (JSON), --debug, --match-code, --filter-code, -s/--silent.
"""

import os
import sys
import json
import argparse
import textwrap
from typing import Dict, Any, List, Optional

# Intentar importar requests, indicar al usuario si falta
try:
    import requests
except Exception:
    requests = None

# ANSI colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"

def print_banner():
    print(textwrap.dedent(f"""
    {YELLOW}
    ███████╗███████╗███████╗██╗   ██╗███████╗███████╗
    ██╔════╝██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
    █████╗  █████╗  █████╗  ██║   ██║  ███╔╝   ███╔╝ 
    ██╔══╝  ██╔══╝  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
    ███████╗██║     ██║     ╚██████╔╝███████╗███████╗
    ╚══════╝╚═╝     ╚═╝      ╚═════╝╚══════╝╚══════╝
    {RESET}
    """))

# Introspection query (suficientemente completa)
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
    }
  }
}
"""

def parse_header_list(headers_list: List[str]) -> Dict[str, str]:
    """
    Convierte una lista de 'Name: Value' a dict. Última gana en duplicados.
    """
    hdrs: Dict[str, str] = {}
    for h in headers_list or []:
        if ":" not in h:
            print(f"⚠️ Ignorando cabecera malformada (esperado 'Name: Value'): {h}")
            continue
        name, value = h.split(":", 1)
        hdrs[name.strip()] = value.strip()
    return hdrs

def perform_introspection_request(url: str, headers: Dict[str, str], timeout: int = 15) -> Optional[Dict[str, Any]]:
    """
    Realiza la petición POST con la consulta de introspección.
    Devuelve dict JSON si es válida, o None en fallo.
    """
    if requests is None:
        print("❌ La librería 'requests' es necesaria para obtener introspección automáticamente. Instálala con: pip install requests")
        return None
    try:
        resp = requests.post(url, headers=headers, json={"query": INTROSPECTION_QUERY}, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"❌ Error HTTP al solicitar introspección: {e}")
        return None

    try:
        data = resp.json()
    except Exception as e:
        print(f"❌ La respuesta no es JSON válido: {e}")
        return None

    if (isinstance(data, dict) and
        ((data.get("data") and isinstance(data["data"], dict) and "__schema" in data["data"]) or ("__schema" in data))):
        return data

    print("❌ La respuesta de introspección no contiene '__schema' (no es una introspección GraphQL válida).")
    return None

def save_introspection_file(data: Dict[str, Any], path: str = "introspection_schema.json") -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"✅ Introspection guardada en: {path}")
    except Exception as e:
        print(f"⚠️ Falló al guardar introspección en {path}: {e}")

def load_introspection_from_path(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError:
        print(f"❌ El archivo de introspección no es JSON válido: {path}")
        return None
    except Exception as e:
        print(f"❌ Error leyendo {path}: {e}")
        return None

def response_stats(resp: requests.Response) -> (int, int, int):
    text = resp.text or ""
    size = len(text)
    words = len(text.split())
    lines = text.count("\n") + 1
    return size, words, lines

def color_status(code: int, resp: requests.Response) -> str:
    """
    Devuelve código coloreado acorde al tipo de respuesta.
    Heurística ligera que intenta imitar comportamiento original.
    """
    if code == 200:
        try:
            data = resp.json()
            if "errors" not in data:
                return f"{GREEN}{code}{RESET}"
        except Exception:
            pass
        return f"{YELLOW}{code}{RESET}"

    if code in (401, 403) or "Method forbidden" in resp.text:
        return f"{RED}{code}{RESET}"

    if code in (400, 500):
        return f"{YELLOW}{code}{RESET}"

    return str(code)

def build_minimal_query_for_method(method_name: str) -> str:
    """
    Construye una query simple para testear el método.
    Intentamos la forma: query { methodName }
    Si requiere args o selección, el endpoint responderá con error (400) y eso se reportará.
    """
    return f"query {{ {method_name} }}"

def perform_request(url: str, headers: Dict[str, str], payload: Dict[str, Any], timeout: int = 15) -> Optional[requests.Response]:
    if requests is None:
        print("❌ La librería 'requests' es necesaria para ejecutar effuzz. Instálala con: pip install requests")
        return None
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        return resp
    except requests.exceptions.RequestException as e:
        print(f"❌ Error en petición a {url}: {e}")
        return None

def get_fields_from_schema(schema: Dict[str, Any]) -> (List[str], List[str]):
    types = schema.get("types", []) if isinstance(schema, dict) else []
    def get_fields(type_name: str):
        if not type_name:
            return []
        for t in types:
            if t.get("name") == type_name:
                return [f["name"] for f in t.get("fields", [])] if t.get("fields") else []
        return []
    query_type_name = schema.get("queryType", {}).get("name")
    mutation_type_name = schema.get("mutationType", {}).get("name")
    queries = get_fields(query_type_name)
    mutations = get_fields(mutation_type_name)
    return queries, mutations

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Test GraphQL endpoints using introspection.")
    # Now introspection is optional: if omitted we will query the endpoint automatically
    parser.add_argument("--introspection", required=False, help="Path to the introspection JSON file")
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

    # Support repeated headers -H "Name: Value"
    parser.add_argument("-H", "--header", action="append", default=[], help="Additional HTTP header to include (can be repeated). Format: 'Name: Value'")

    # Control saving of automatic introspection (default: save)
    parser.add_argument("--save-introspection", dest="save_introspection", action="store_true", help="Save automatic introspection to introspection_schema.json")
    parser.add_argument("--no-save-introspection", dest="save_introspection", action="store_false", help="Do not save automatic introspection to disk")
    parser.set_defaults(save_introspection=True)

    args = parser.parse_args()

    GRAPHQL_URL = args.url
    INTROSPECTION_FILE = args.introspection

    match_codes = None
    if args.match_code:
        match_codes = set(int(x.strip()) for x in args.match_code.split(",") if x.strip().isdigit())

    filter_codes = None
    if args.filter_code:
        filter_codes = set(int(x.strip()) for x in args.filter_code.split(",") if x.strip().isdigit())

    # Build headers
    extra_headers = parse_header_list(args.header)
    HEADERS: Dict[str, str] = {
        "Content-Type": "application/json"
    }

    # Cookie file handling: gives precedence to explicit -H Cookie
    if args.cookie:
        if not os.path.exists(args.cookie):
            print(f"❌ Cookie file not found: {args.cookie}")
            sys.exit(1)
        with open(args.cookie, "r", encoding="utf-8") as f:
            cookie_value = f.read().strip()
        if "Cookie" not in extra_headers:
            extra_headers["Cookie"] = cookie_value

    HEADERS.update(extra_headers)

    # Load variables file if provided
    variables_value: Dict[str, Any] = {}
    if args.variables:
        if not os.path.exists(args.variables):
            print(f"❌ Variables file not found: {args.variables}")
            sys.exit(1)
        try:
            with open(args.variables, "r", encoding="utf-8") as f:
                variables_value = json.load(f)
        except Exception:
            print("❌ Variables file is NOT valid JSON.")
            sys.exit(1)

    introspection_data: Optional[Dict[str, Any]] = None

    # If user provided a file, load it
    if INTROSPECTION_FILE:
        if not os.path.exists(INTROSPECTION_FILE):
            print(f"❌ File not found: {INTROSPECTION_FILE}")
            sys.exit(1)
        introspection_data = load_introspection_from_path(INTROSPECTION_FILE)
        if introspection_data is None:
            sys.exit(1)
        print(f"✅ Introspection cargada desde: {INTROSPECTION_FILE}")
    else:
        # No introspection file provided -> perform introspection automatically
        print(f"[*] No se ha pasado --introspection; intentando obtener introspección desde {GRAPHQL_URL} ...")
        result = perform_introspection_request(GRAPHQL_URL, HEADERS)
        if result is None:
            print("❌ No se pudo obtener la introspección del endpoint. Salida.")
            sys.exit(1)
        introspection_data = result
        print("✅ Introspection obtenida del endpoint.")
        if args.save_introspection:
            save_introspection_file(introspection_data, path="introspection_schema.json")

    # Validate introspection structure
    if not isinstance(introspection_data, dict):
        print("❌ La introspección cargada no es un objeto JSON válido.")
        sys.exit(1)

    # Support both shapes: {"data": {"__schema": ...}} or {"__schema": ...}
    schema = None
    if "data" in introspection_data and isinstance(introspection_data["data"], dict):
        schema = introspection_data["data"].get("__schema", {})
    else:
        schema = introspection_data.get("__schema", {})

    if not isinstance(schema, dict) or not schema:
        print("❌ No se encontró '__schema' en la introspección o es inválido.")
        sys.exit(1)

    types = schema.get("types", [])

    # Extract queries and mutations
    def get_fields(type_name: Optional[str]):
        if not type_name:
            return []
        for t in types:
            if t.get("name") == type_name:
                return [f["name"] for f in t.get("fields", [])] if t.get("fields") else []
        return []

    query_type_name = schema.get("queryType", {}).get("name")
    mutation_type_name = schema.get("mutationType", {}).get("name")

    queries = get_fields(query_type_name) if query_type_name else []
    mutations = get_fields(mutation_type_name) if mutation_type_name else []

    print(f"[✓] Introspection cargada ({len(queries)} queries, {len(mutations)} mutations)")
    print("------------------------------------------------------------")

    # ========================================================================
    # Minimal ffuf-like processing: para cada método en queries, enviamos una petición
    # y mostramos status/size/words/lines. Este bloque puede ampliarse con payloads,
    # control de códigos, filtros, etc. (mantiene la funcionalidad básica del original).
    # ========================================================================

    if not queries:
        print("⚠️ No se han encontrado queries para probar.")
    else:
        print("Probando queries (envío minimal):")
        for qname in queries:
            payload_query = build_minimal_query_for_method(qname)
            payload = {"query": payload_query}
            # Si variables globales fueron provistas, intentar incluirlas (aunque la query minimal no las usa)
            if variables_value:
                payload["variables"] = variables_value
            resp = perform_request(GRAPHQL_URL, HEADERS, payload)
            if resp is None:
                print(f"{qname:30} -> {RED}request failed{RESET}")
                continue
            code = resp.status_code
            size, words, lines = response_stats(resp)
            colored = color_status(code, resp)
            # Aplica filtros si están presentes
            if match_codes and code not in match_codes:
                continue
            if filter_codes and code in filter_codes:
                continue
            if args.silent and code == 401:
                continue

            print(f"{qname:30} [Status: {colored}] [Size: {size}] [Words: {words}] [Lines: {lines}]")

            if args.debug:
                try:
                    print("---- RESPONSE JSON ----")
                    print(json.dumps(resp.json(), indent=2, ensure_ascii=False))
                except Exception:
                    print("---- RESPONSE TEXT ----")
                    print(resp.text)

    print("------------------------------------------------------------")
    print("Fin de effuzz. (Este script hace una comprobación básica; modifica el bucle para incluir payloads, concurrencia u otras heurísticas según necesites.)")

if __name__ == "__main__":
    main()
