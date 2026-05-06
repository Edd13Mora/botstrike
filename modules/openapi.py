"""
OpenAPI / Swagger / GraphQL endpoint discovery.

Checks well-known paths for API specifications and introspects GraphQL schemas.
Extracts all endpoints and parameters, expanding the attack surface beyond HTML crawling.
"""

import json
import logging
from typing import Optional
from urllib.parse import urlparse

import requests

from .utils import console, log, phase_banner, stealth_headers, get_proxy_dict

SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api-docs.json", "/api-docs/swagger.json",
    "/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/api/v3/swagger.json", "/openapi.json", "/openapi.yaml",
    "/openapi/v1.json", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/.well-known/openapi.json", "/api/openapi.json", "/api/openapi.yaml",
    "/swagger-ui.html", "/swagger", "/redoc", "/api/redoc", "/docs", "/api/docs",
    "/api/swagger-ui.html", "/api/swagger", "/swagger/index.html",
]

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphiql", "/api/graphiql", "/query", "/api/query",
]

_GRAPHQL_INTROSPECTION = {
    "query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name } } } } }"
}


def _parse_openapi_spec(spec: dict, base: str) -> list[dict]:
    """Extract endpoints from OpenAPI 2.x or 3.x spec."""
    endpoints = []
    if "servers" in spec and spec["servers"]:
        server = spec["servers"][0].get("url", base)
    elif "basePath" in spec:
        p = urlparse(base)
        server = f"{p.scheme}://{p.netloc}{spec.get('basePath', '')}"
    else:
        server = base

    for path, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head"):
                continue
            if not isinstance(op, dict):
                continue
            params = [p.get("name", "") for p in op.get("parameters", []) if isinstance(p, dict)]
            body_params = []
            rb = op.get("requestBody", {})
            for ct, sw in rb.get("content", {}).items():
                body_params.extend(list(sw.get("schema", {}).get("properties", {}).keys()))
            endpoints.append({
                "url": server.rstrip("/") + path,
                "method": method.upper(),
                "path": path,
                "params": params,
                "body_params": body_params,
                "summary": op.get("summary", ""),
                "tags": op.get("tags", []),
            })
    return endpoints


def _parse_graphql_schema(data: dict) -> list[dict]:
    """Extract query/mutation names from GraphQL introspection."""
    ops = []
    try:
        schema = data.get("data", {}).get("__schema", {})
        qt = schema.get("queryType", {}).get("name", "Query")
        mt = (schema.get("mutationType") or {}).get("name", "Mutation")
        for t in schema.get("types", []):
            name = t.get("name", "")
            if name.startswith("__") or name not in (qt, mt):
                continue
            method = "GET" if name == qt else "POST"
            for field in t.get("fields") or []:
                ops.append({
                    "url": None,
                    "method": method,
                    "path": f"/{name.lower()}/{field['name']}",
                    "graphql_operation": field["name"],
                    "params": [a["name"] for a in (field.get("args") or [])],
                    "body_params": [],
                    "summary": f"GraphQL {name}: {field['name']}",
                    "tags": ["graphql"],
                })
    except Exception:
        pass
    return ops


def run(target_url: str, cfg: dict, logger: Optional[logging.Logger] = None) -> dict:
    phase_banner("MODULE 0c: API SPEC & GRAPHQL DISCOVERY")
    timeout = cfg.get("preflight", {}).get("timeout", 10)
    proxies = get_proxy_dict()
    hdrs = stealth_headers()
    p = urlparse(target_url)
    base = f"{p.scheme}://{p.netloc}"

    result = {
        "swagger_found": False, "swagger_url": None, "swagger_endpoints": [],
        "graphql_found": False, "graphql_url": None, "graphql_introspection_open": False,
        "graphql_operations": [], "all_api_endpoints": [],
    }

    # ── Swagger / OpenAPI ──────────────────────────────────────────────────────
    log("[OPENAPI] Scanning for Swagger/OpenAPI spec...", "info", logger)
    for path in SWAGGER_PATHS:
        url = base + path
        try:
            r = requests.get(url, headers=hdrs, timeout=timeout, proxies=proxies,
                             allow_redirects=True, verify=False)
            if r.status_code != 200:
                continue
            try:
                spec = r.json()
            except Exception:
                try:
                    import yaml
                    spec = yaml.safe_load(r.text)
                except Exception:
                    continue
            if not isinstance(spec, dict):
                continue
            if not ("swagger" in spec or "openapi" in spec or ("paths" in spec and "info" in spec)):
                continue
            endpoints = _parse_openapi_spec(spec, base)
            result.update(swagger_found=True, swagger_url=url, swagger_endpoints=endpoints)
            console.print(f"  [bold green][FOUND][/bold green] OpenAPI spec → {url} — {len(endpoints)} endpoints")
            log(f"  OpenAPI at {url} — {len(endpoints)} endpoints", "success", logger)
            break
        except Exception:
            continue

    if not result["swagger_found"]:
        console.print("  [dim]No Swagger/OpenAPI spec found.[/dim]")

    # ── GraphQL introspection ──────────────────────────────────────────────────
    log("[OPENAPI] Testing GraphQL endpoints...", "info", logger)
    for path in GRAPHQL_PATHS:
        url = base + path
        try:
            r = requests.post(url, json=_GRAPHQL_INTROSPECTION,
                              headers={**hdrs, "Content-Type": "application/json"},
                              timeout=timeout, proxies=proxies, verify=False)
            if r.status_code not in (200, 400, 405):
                continue
            try:
                data = r.json()
            except Exception:
                continue
            if r.status_code == 400 and data.get("errors"):
                result.update(graphql_found=True, graphql_url=url)
                console.print(f"  [bold yellow][FOUND][/bold yellow] GraphQL at {url} — introspection disabled (good)")
                log(f"  GraphQL at {url} — introspection disabled", "warning", logger)
                break
            if "data" in data and "__schema" in (data.get("data") or {}):
                ops = _parse_graphql_schema(data)
                result.update(graphql_found=True, graphql_url=url,
                              graphql_introspection_open=True, graphql_operations=ops)
                console.print(f"  [bold red][EXPOSED][/bold red] GraphQL introspection OPEN at {url} — {len(ops)} operations leaked!")
                log(f"  GraphQL introspection open at {url} — {len(ops)} ops", "warning", logger)
                break
        except Exception:
            continue

    if not result["graphql_found"]:
        console.print("  [dim]No GraphQL endpoint found.[/dim]")

    all_eps = result["swagger_endpoints"] + result["graphql_operations"]
    result["all_api_endpoints"] = all_eps
    if all_eps:
        console.print(f"\n  [bold cyan]Total API operations discovered via spec: {len(all_eps)}[/bold cyan]")

    return result
