"""Remote API operation extraction.

This module is intentionally policy-free. It normalizes visible command-line
API calls into a small data shape that later protocol classifiers can consume.
It must not call the network, execute commands, read request body files, or
import the taxonomy/context hot path.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field, replace

MAX_BODY_TEXT_CHARS = 8192

CLIENT_CURL = "curl"
CLIENT_WGET = "wget"
CLIENT_HTTPIE = "httpie"
CLIENT_GH_API = "gh_api"
CLIENT_GLAB_API = "glab_api"
CLIENT_GRPCURL = "grpcurl"
CLIENT_WSCAT = "wscat"
CLIENT_WEBSOCAT = "websocat"
CLIENT_UNKNOWN = "unknown"

PROTOCOL_HTTP = "http"
PROTOCOL_GRAPHQL = "graphql"
PROTOCOL_JSON_RPC = "json_rpc"
PROTOCOL_GRPC = "grpc"
PROTOCOL_WEBSOCKET = "websocket"
PROTOCOL_UNKNOWN = "unknown"

BODY_NONE = "none"
BODY_INLINE = "inline"
BODY_FILE = "file"
BODY_STDIN = "stdin"
BODY_REDIRECT = "redirect"
BODY_DYNAMIC = "dynamic"
BODY_UNKNOWN = "unknown"

FORMAT_UNKNOWN = "unknown"
FORMAT_JSON = "json"
FORMAT_FORM = "form"
FORMAT_RAW = "raw"
FORMAT_GRAPHQL = "graphql"

GRAPHQL_QUERY = "query"
GRAPHQL_MUTATION = "mutation"
GRAPHQL_SUBSCRIPTION = "subscription"

CONFIDENCE_COMPLETE = "complete"
CONFIDENCE_PARTIAL = "partial"
CONFIDENCE_OPAQUE = "opaque"

HOST_EXPLICIT = "explicit"
HOST_IMPLICIT = "implicit_default"
HOST_UNKNOWN = "unknown"

_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
_GRAPHQL_PATH_RE = re.compile(r"(?:^|/)graphql/?(?:[?#].*)?$", re.IGNORECASE)
_GRAPHQL_OP_RE = re.compile(
    r"^\s*(query|mutation|subscription)\b(?:\s+([_A-Za-z][_0-9A-Za-z]*))?",
    re.DOTALL,
)
_GRAPHQL_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_DYNAMIC_MARKERS = ("$(", "${", "`", "__nah_", "<(")


@dataclass(frozen=True)
class BodyItem:
    """A visible request body item such as a form field or typed CLI field."""

    key: str = ""
    value: str = ""
    source: str = BODY_INLINE
    format: str = FORMAT_RAW


@dataclass(frozen=True)
class GraphQLIntent:
    """Policy-free GraphQL document parse result."""

    operation_type: str = ""
    operation_name: str = ""
    root_fields: tuple[str, ...] = ()
    operation_count: int = 0
    ambiguous_reason: str = ""


@dataclass(frozen=True)
class JsonRpcIntent:
    """Policy-free JSON-RPC request parse result."""

    methods: tuple[str, ...] = ()
    method_count: int = 0
    is_batch: bool = False
    tool_name: str = ""
    notification_count: int = 0
    ambiguous_reason: str = ""


@dataclass(frozen=True)
class RemoteOperation:
    """Normalized, policy-free view of a visible remote API operation."""

    client: str = CLIENT_UNKNOWN
    protocol: str = PROTOCOL_UNKNOWN
    host: str = ""
    host_source: str = HOST_UNKNOWN
    scheme: str = ""
    port: str = ""
    path: str = ""
    url: str = ""
    method: str = ""
    operation_name: str = ""
    body_text: str = ""
    body_items: tuple[BodyItem, ...] = ()
    body_source: str = BODY_NONE
    body_format: str = FORMAT_UNKNOWN
    graphql: GraphQLIntent = field(default_factory=GraphQLIntent)
    json_rpc: JsonRpcIntent = field(default_factory=JsonRpcIntent)
    confidence: str = CONFIDENCE_PARTIAL
    reasons: tuple[str, ...] = ()


def extract_remote_operation(tokens: list[str]) -> RemoteOperation | None:
    """Extract a visible remote operation from supported command tokens.

    Unsupported commands return ``None``. Supported commands return a
    ``RemoteOperation`` even when parts of the operation are opaque.
    """
    if not tokens:
        return None

    cmd = _normalize_cmd(tokens[0])
    if cmd == "curl":
        return _extract_curl(tokens)
    if cmd == "wget":
        return _extract_wget(tokens)
    if cmd in {"http", "https", "xh", "xhs"}:
        return _extract_httpie(tokens)
    if cmd == "gh" and len(tokens) >= 2 and tokens[1] == "api":
        return _extract_api_cli(tokens, CLIENT_GH_API)
    if cmd == "glab" and len(tokens) >= 2 and tokens[1] == "api":
        return _extract_api_cli(tokens, CLIENT_GLAB_API)
    if cmd == "grpcurl":
        return _extract_grpcurl(tokens)
    if cmd == "wscat":
        return _extract_wscat(tokens)
    if cmd == "websocat":
        return _extract_websocat(tokens)
    return None


def _normalize_cmd(cmd: str) -> str:
    name = os.path.basename(cmd).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _parse_url(value: str, *, default_scheme: str = "") -> dict[str, str]:
    """Parse a URL or bare host/path without guessing a host from arbitrary text."""
    if not value:
        return {}

    raw = value
    parse_value = value
    if value.startswith("//"):
        parse_value = "http:" + value
    elif "://" not in value:
        parse_value = f"{default_scheme or 'http'}://{value}"

    parsed = urllib.parse.urlparse(parse_value)
    if not parsed.hostname:
        return {}

    path = parsed.path or ""
    if parsed.params:
        path += ";" + parsed.params
    if parsed.query:
        path += "?" + parsed.query
    if parsed.fragment:
        path += "#" + parsed.fragment

    return {
        "url": raw,
        "scheme": parsed.scheme if "://" in raw or raw.startswith("//") or default_scheme else "",
        "host": parsed.hostname or "",
        "port": _safe_port(parsed),
        "path": path,
    }


def _safe_port(parsed: urllib.parse.ParseResult) -> str:
    try:
        return str(parsed.port or "")
    except ValueError:
        # urlparse validates port lazily. Extraction is best-effort and must
        # not crash the hook path; callers still get host/path context.
        return ""


def _looks_urlish(value: str) -> bool:
    if not value or value.startswith("-"):
        return False
    if "://" in value or value.startswith("//"):
        return True
    first = value.split("/", 1)[0]
    return first in {"localhost", "0.0.0.0"} or "." in first or ":" in first


def _looks_dynamic(value: str) -> bool:
    return any(marker in value for marker in _DYNAMIC_MARKERS) or "$" in value


def _body_value_source(value: str | None) -> str:
    if value is None:
        return BODY_UNKNOWN
    if _looks_dynamic(value):
        return BODY_DYNAMIC
    if value == "@-" or value == "-":
        return BODY_STDIN
    if value.startswith("@"):
        return BODY_FILE
    if "=@-" in value or "<@-" in value:
        return BODY_STDIN
    if "=@" in value or "<@" in value:
        return BODY_FILE
    return BODY_INLINE


def _merge_body_source(current: str, new: str) -> str:
    if current in {BODY_DYNAMIC, BODY_FILE, BODY_STDIN, BODY_REDIRECT, BODY_UNKNOWN}:
        return current
    if new == BODY_NONE:
        return current
    if new in {BODY_DYNAMIC, BODY_FILE, BODY_STDIN, BODY_REDIRECT, BODY_UNKNOWN}:
        return new
    if current == BODY_NONE:
        return new
    return current


def _add_reason(reasons: list[str], reason: str) -> None:
    if reason and reason not in reasons:
        reasons.append(reason)


def _bounded_body(value: str) -> tuple[str, list[str]]:
    if len(value) <= MAX_BODY_TEXT_CHARS:
        return value, []
    return value[:MAX_BODY_TEXT_CHARS], ["body truncated"]


def _format_for_body(value: str, preferred: str = FORMAT_RAW) -> str:
    stripped = value.lstrip()
    if preferred == FORMAT_GRAPHQL:
        return FORMAT_GRAPHQL
    if stripped.startswith("{") or stripped.startswith("["):
        return FORMAT_JSON
    return preferred


def _finalize(
    op: RemoteOperation,
    reasons: list[str],
    *,
    body_values: list[str] | None = None,
) -> RemoteOperation:
    body_values = body_values or []
    protocol = op.protocol
    body_format = op.body_format
    operation_name = op.operation_name
    graphql = op.graphql

    if body_values and op.body_source == BODY_INLINE:
        joined = "\n".join(body_values)
        body_text, trunc_reasons = _bounded_body(joined)
        for reason in trunc_reasons:
            _add_reason(reasons, reason)
    else:
        body_text = op.body_text

    graphql_request_operation_name = _extract_graphql_request_operation_name(
        op, body_values,
    )
    graphql_text = _extract_graphql_text(op, body_values)
    if graphql_text:
        protocol = PROTOCOL_GRAPHQL
        body_format = FORMAT_GRAPHQL
        body_text, trunc_reasons = _bounded_body(graphql_text)
        for reason in trunc_reasons:
            _add_reason(reasons, reason)
        graphql = parse_graphql_document(
            graphql_text,
            operation_name=graphql_request_operation_name,
        )
        operation_name = (
            graphql.operation_name
            or graphql_request_operation_name
            or operation_name
            or _graphql_operation_name(graphql_text)
        )

    json_rpc = _parse_json_rpc_intent(body_text or "\n".join(body_values))
    if json_rpc.methods or json_rpc.ambiguous_reason:
        protocol = PROTOCOL_JSON_RPC
        body_format = FORMAT_JSON
        if len(json_rpc.methods) == 1:
            json_rpc_method = json_rpc.methods[0]
            operation_name = operation_name or json_rpc_method
            op = replace(op, method=json_rpc_method)
        if json_rpc.ambiguous_reason:
            _add_reason(reasons, json_rpc.ambiguous_reason)

    malformed_json = _has_malformed_json(op, body_text, body_values)
    if malformed_json:
        body_format = FORMAT_JSON
        _add_reason(reasons, "malformed JSON body")

    if protocol == PROTOCOL_UNKNOWN and (
        op.scheme in {"http", "https"} or op.host or op.path or op.method in _HTTP_METHODS
    ):
        protocol = PROTOCOL_HTTP

    if _GRAPHQL_PATH_RE.search(op.path or ""):
        protocol = PROTOCOL_GRAPHQL
        if body_format == FORMAT_JSON and graphql_text:
            body_format = FORMAT_GRAPHQL

    confidence = CONFIDENCE_COMPLETE
    if op.body_source in {BODY_DYNAMIC, BODY_FILE, BODY_STDIN, BODY_REDIRECT, BODY_UNKNOWN} or malformed_json:
        confidence = CONFIDENCE_OPAQUE
        if op.body_source in {BODY_DYNAMIC, BODY_FILE, BODY_STDIN, BODY_REDIRECT, BODY_UNKNOWN}:
            _add_reason(reasons, f"opaque body source: {op.body_source}")
    elif not op.host and op.client not in {CLIENT_GH_API, CLIENT_GLAB_API}:
        confidence = CONFIDENCE_PARTIAL
        _add_reason(reasons, "host not visible")
    elif op.host_source == HOST_IMPLICIT:
        confidence = CONFIDENCE_PARTIAL
        _add_reason(reasons, "host is implicit CLI default")
    elif reasons:
        confidence = CONFIDENCE_PARTIAL

    return replace(
        op,
        protocol=protocol,
        body_text=body_text,
        body_format=body_format,
        operation_name=operation_name,
        graphql=graphql,
        json_rpc=json_rpc,
        confidence=confidence,
        reasons=tuple(reasons),
    )


def _extract_graphql_text(op: RemoteOperation, body_values: list[str]) -> str:
    for item in op.body_items:
        if item.key == "query" and item.source == BODY_INLINE:
            return item.value

    graphql_endpoint = op.protocol == PROTOCOL_GRAPHQL or bool(_GRAPHQL_PATH_RE.search(op.path or ""))
    json_expected = _body_items_expect_json(op)
    query_from_url = _extract_graphql_url_param(op.path, "query")
    if graphql_endpoint and query_from_url:
        return query_from_url

    values = [op.body_text, *body_values]
    for value in values:
        if not value:
            continue
        stripped = value.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                payload = json.loads(value)
            except json.JSONDecodeError:
                if graphql_endpoint and not json_expected and _looks_graphql_document(value):
                    return value
                continue
            if isinstance(payload, dict) and isinstance(payload.get("query"), str):
                return payload["query"]
            continue
        if graphql_endpoint and _looks_graphql_document(value):
            return value
    return ""


def _body_items_expect_json(op: RemoteOperation) -> bool:
    return any(
        item.source == BODY_INLINE and item.format == FORMAT_JSON
        for item in op.body_items
    )


def _extract_graphql_request_operation_name(
    op: RemoteOperation,
    body_values: list[str],
) -> str:
    for item in op.body_items:
        if item.key == "operationName" and item.source == BODY_INLINE:
            return item.value

    operation_name = _extract_graphql_url_param(op.path, "operationName")
    if operation_name:
        return operation_name

    for value in [op.body_text, *body_values]:
        if not value:
            continue
        stripped = value.lstrip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("operationName"), str):
            return payload["operationName"]
    return ""


def _extract_graphql_url_param(path: str, key: str) -> str:
    if not path or "?" not in path:
        return ""
    query = urllib.parse.urlsplit(path).query
    if not query:
        return ""
    values = urllib.parse.parse_qs(query, keep_blank_values=True).get(key)
    return values[0] if values else ""


def _looks_graphql_document(value: str) -> bool:
    stripped = value.lstrip()
    return (
        stripped.startswith("{")
        or stripped.startswith("query ")
        or stripped.startswith("mutation ")
        or stripped.startswith("subscription ")
    )


def _graphql_operation_name(value: str) -> str:
    match = _GRAPHQL_OP_RE.search(value)
    if match and match.group(2):
        return match.group(2)
    return ""


@dataclass(frozen=True)
class _GraphQLOperation:
    operation_type: str
    name: str
    root_fields: tuple[str, ...]


def parse_graphql_document(value: str, *, operation_name: str = "") -> GraphQLIntent:
    """Parse visible GraphQL intent without assigning policy."""
    tokens = _graphql_tokens(value)
    if not tokens:
        return GraphQLIntent(ambiguous_reason="empty GraphQL document")
    if not _graphql_braces_balanced(tokens):
        return GraphQLIntent(ambiguous_reason="unbalanced GraphQL selection set")

    operations: list[_GraphQLOperation] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "fragment":
            i = _skip_graphql_definition(tokens, i)
            continue
        if tok in {GRAPHQL_QUERY, GRAPHQL_MUTATION, GRAPHQL_SUBSCRIPTION}:
            next_i, operation = _parse_graphql_operation(tokens, i)
            if operation is not None:
                operations.append(operation)
            i = next_i
            continue
        if tok == "{":
            root_fields, next_i = _graphql_root_fields(tokens, i)
            operations.append(_GraphQLOperation(GRAPHQL_QUERY, "", root_fields))
            i = next_i
            continue
        i += 1

    operation_count = len(operations)
    if operation_count == 0:
        return GraphQLIntent(ambiguous_reason="no GraphQL operation")

    selected: _GraphQLOperation | None = None
    if operation_name:
        matches = [op for op in operations if op.name == operation_name]
        if len(matches) != 1:
            return GraphQLIntent(
                operation_count=operation_count,
                ambiguous_reason="operationName did not select one GraphQL operation",
            )
        selected = matches[0]
    elif operation_count == 1:
        selected = operations[0]
    else:
        return GraphQLIntent(
            operation_count=operation_count,
            ambiguous_reason="multiple GraphQL operations without operationName",
        )

    return GraphQLIntent(
        operation_type=selected.operation_type,
        operation_name=selected.name,
        root_fields=selected.root_fields,
        operation_count=operation_count,
    )


def _graphql_tokens(value: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char.isspace() or char == ",":
            i += 1
            continue
        if char == "#":
            newline = value.find("\n", i + 1)
            i = len(value) if newline < 0 else newline + 1
            continue
        if value.startswith('"""', i):
            end = value.find('"""', i + 3)
            i = len(value) if end < 0 else end + 3
            continue
        if char == '"':
            i = _skip_graphql_string(value, i)
            continue
        if value.startswith("...", i):
            tokens.append("...")
            i += 3
            continue
        match = _GRAPHQL_NAME_RE.match(value, i)
        if match:
            tokens.append(match.group(0))
            i = match.end()
            continue
        if char in "{}():@[]!=$|&":
            tokens.append(char)
        i += 1
    return tokens


def _graphql_braces_balanced(tokens: list[str]) -> bool:
    depth = 0
    for tok in tokens:
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _skip_graphql_string(value: str, start: int) -> int:
    i = start + 1
    while i < len(value):
        if value[i] == "\\":
            i += 2
            continue
        if value[i] == '"':
            return i + 1
        i += 1
    return len(value)


def _parse_graphql_operation(
    tokens: list[str],
    start: int,
) -> tuple[int, _GraphQLOperation | None]:
    operation_type = tokens[start]
    i = start + 1
    name = ""
    if i < len(tokens) and _is_graphql_name(tokens[i]):
        name = tokens[i]
        i += 1

    while i < len(tokens):
        tok = tokens[i]
        if tok == "(":
            i = _skip_graphql_wrapped(tokens, i, "(", ")")
            continue
        if tok == "@":
            i = _skip_graphql_directive(tokens, i)
            continue
        if tok == "{":
            root_fields, next_i = _graphql_root_fields(tokens, i)
            return next_i, _GraphQLOperation(operation_type, name, root_fields)
        if tok in {GRAPHQL_QUERY, GRAPHQL_MUTATION, GRAPHQL_SUBSCRIPTION, "fragment"}:
            return i, None
        i += 1
    return len(tokens), None


def _skip_graphql_definition(tokens: list[str], start: int) -> int:
    i = start + 1
    while i < len(tokens):
        if tokens[i] == "{":
            _, next_i = _graphql_root_fields(tokens, i)
            return next_i
        i += 1
    return len(tokens)


def _graphql_root_fields(tokens: list[str], start: int) -> tuple[tuple[str, ...], int]:
    root_fields: list[str] = []
    depth = 1
    i = start + 1
    while i < len(tokens) and depth > 0:
        tok = tokens[i]
        if tok == "{":
            depth += 1
            i += 1
            continue
        if tok == "}":
            depth -= 1
            i += 1
            continue
        if depth != 1:
            i += 1
            continue
        if tok == "...":
            i = _skip_graphql_fragment_spread(tokens, i)
            continue
        if tok == "@":
            i = _skip_graphql_directive(tokens, i)
            continue
        if _is_graphql_name(tok):
            field_name = tok
            if (
                i + 2 < len(tokens)
                and tokens[i + 1] == ":"
                and _is_graphql_name(tokens[i + 2])
            ):
                field_name = tokens[i + 2]
                i += 3
            else:
                i += 1
            root_fields.append(field_name)
            i = _skip_graphql_field_suffix(tokens, i)
            continue
        i += 1
    return tuple(root_fields), i


def _skip_graphql_field_suffix(tokens: list[str], start: int) -> int:
    i = start
    while i < len(tokens):
        tok = tokens[i]
        if tok == "(":
            i = _skip_graphql_wrapped(tokens, i, "(", ")")
            continue
        if tok == "@":
            i = _skip_graphql_directive(tokens, i)
            continue
        if tok in {"{", "}", "..."} or _is_graphql_name(tok):
            break
        i += 1
    return i


def _skip_graphql_fragment_spread(tokens: list[str], start: int) -> int:
    i = start + 1
    if i < len(tokens) and tokens[i] == "on":
        i += 1
        if i < len(tokens) and _is_graphql_name(tokens[i]):
            i += 1
    elif i < len(tokens) and _is_graphql_name(tokens[i]):
        i += 1
    while i < len(tokens) and tokens[i] == "@":
        i = _skip_graphql_directive(tokens, i)
    if i < len(tokens) and tokens[i] == "{":
        return _skip_graphql_wrapped(tokens, i, "{", "}")
    return i


def _skip_graphql_directive(tokens: list[str], start: int) -> int:
    i = start + 1
    if i < len(tokens) and _is_graphql_name(tokens[i]):
        i += 1
    if i < len(tokens) and tokens[i] == "(":
        i = _skip_graphql_wrapped(tokens, i, "(", ")")
    return i


def _skip_graphql_wrapped(
    tokens: list[str],
    start: int,
    open_token: str,
    close_token: str,
) -> int:
    depth = 0
    i = start
    while i < len(tokens):
        if tokens[i] == open_token:
            depth += 1
        elif tokens[i] == close_token:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(tokens)


def _is_graphql_name(token: str) -> bool:
    return _GRAPHQL_NAME_RE.fullmatch(token) is not None


def _parse_json_rpc_intent(value: str) -> JsonRpcIntent:
    if not value:
        return JsonRpcIntent()
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return JsonRpcIntent()
    if isinstance(payload, dict):
        return _parse_json_rpc_object(payload, is_batch=False)
    if isinstance(payload, list):
        return _parse_json_rpc_batch(payload)
    return JsonRpcIntent()


def _parse_json_rpc_batch(payload: list) -> JsonRpcIntent:
    if not payload:
        return JsonRpcIntent(ambiguous_reason="empty JSON-RPC batch")

    methods: list[str] = []
    tool_names: list[str] = []
    notification_count = 0
    ambiguous = ""
    saw_json_rpc_shape = False

    for item in payload:
        if not isinstance(item, dict):
            ambiguous = ambiguous or "invalid JSON-RPC batch entry"
            continue
        item_intent = _parse_json_rpc_object(item, is_batch=True)
        if item_intent.methods or item_intent.ambiguous_reason:
            saw_json_rpc_shape = True
        methods.extend(item_intent.methods)
        if item_intent.tool_name:
            tool_names.append(item_intent.tool_name)
        notification_count += item_intent.notification_count
        if item_intent.ambiguous_reason:
            ambiguous = ambiguous or item_intent.ambiguous_reason

    if not saw_json_rpc_shape and not methods and not ambiguous:
        return JsonRpcIntent()
    return JsonRpcIntent(
        methods=tuple(methods),
        method_count=len(methods),
        is_batch=True,
        tool_name=tool_names[0] if len(tool_names) == 1 else "",
        notification_count=notification_count,
        ambiguous_reason=ambiguous,
    )


def _parse_json_rpc_object(payload: dict, *, is_batch: bool) -> JsonRpcIntent:
    method = payload.get("method")
    if isinstance(method, str):
        return JsonRpcIntent(
            methods=(method,),
            method_count=1,
            is_batch=is_batch,
            tool_name=_json_rpc_tool_name(payload, method),
            notification_count=0 if "id" in payload else 1,
        )
    if "method" in payload or payload.get("jsonrpc") == "2.0":
        return JsonRpcIntent(
            is_batch=is_batch,
            ambiguous_reason="JSON-RPC request without string method",
        )
    return JsonRpcIntent()


def _json_rpc_tool_name(payload: dict, method: str) -> str:
    if method != "tools/call":
        return ""
    params = payload.get("params")
    if not isinstance(params, dict):
        return ""
    name = params.get("name")
    return name if isinstance(name, str) else ""


def _has_malformed_json(op: RemoteOperation, body_text: str, body_values: list[str]) -> bool:
    graphql_endpoint = op.protocol == PROTOCOL_GRAPHQL or bool(_GRAPHQL_PATH_RE.search(op.path or ""))
    json_expected = _body_items_expect_json(op)
    for value in [body_text, *body_values]:
        stripped = value.lstrip()
        if not stripped or not stripped.startswith(("{", "[")):
            continue
        if graphql_endpoint and not json_expected and _looks_graphql_document(value):
            continue
        try:
            json.loads(value)
        except json.JSONDecodeError:
            return True
    return False


def _apply_url(op: RemoteOperation, value: str, *, default_scheme: str = "") -> RemoteOperation:
    parsed = _parse_url(value, default_scheme=default_scheme)
    if not parsed:
        return op
    return replace(
        op,
        url=parsed["url"],
        scheme=parsed["scheme"],
        host=parsed["host"],
        host_source=HOST_EXPLICIT,
        port=parsed["port"],
        path=parsed["path"],
    )


def _extract_curl(tokens: list[str]) -> RemoteOperation:
    op = RemoteOperation(client=CLIENT_CURL, method="GET")
    reasons: list[str] = []
    body_values: list[str] = []
    body_items: list[BodyItem] = []
    explicit_method = False

    i = 1
    while i < len(tokens):
        tok = tokens[i]

        if tok in {"-X", "--request"}:
            if i + 1 < len(tokens):
                op = replace(op, method=tokens[i + 1].upper())
                explicit_method = True
                i += 2
                continue
            _add_reason(reasons, "missing curl request method")
            i += 1
            continue
        if tok.startswith("--request="):
            op = replace(op, method=tok.split("=", 1)[1].upper())
            explicit_method = True
            i += 1
            continue
        if tok.startswith("-") and not tok.startswith("--") and "X" in tok[1:]:
            method = _curl_combined_method(tok, tokens, i)
            if method:
                op = replace(op, method=method)
                explicit_method = True
                if tok.endswith("X") and i + 1 < len(tokens):
                    i += 2
                    continue

        body_parse = _curl_body_arg(tok, tokens, i)
        if body_parse is not None:
            value, fmt, source, consumed, default_method = body_parse
            if default_method and op.method == "GET" and not explicit_method:
                op = replace(op, method=default_method)
            op = replace(op, body_source=_merge_body_source(op.body_source, source))
            if source == BODY_INLINE and value is not None:
                body_values.append(value)
                body_items.append(BodyItem(value=value, source=source, format=fmt))
            else:
                body_items.append(BodyItem(value=value or "", source=source, format=fmt))
            i += consumed
            continue

        if _flag_takes_value(tok, _CURL_SKIP_VALUE_FLAGS):
            i += 2 if "=" not in tok and i + 1 < len(tokens) else 1
            continue

        if _looks_urlish(tok) and not op.host:
            op = _apply_url(op, tok)

        i += 1

    if body_items:
        op = replace(op, body_items=tuple(body_items))
        if op.body_format == FORMAT_UNKNOWN:
            op = replace(op, body_format=_format_for_body(body_values[0]) if body_values else FORMAT_UNKNOWN)
    return _finalize(op, reasons, body_values=body_values)


_CURL_SKIP_VALUE_FLAGS = {
    "-A", "--user-agent", "-b", "--cookie", "-c", "--cookie-jar", "-e", "--referer",
    "-H", "--header", "-o", "--output", "-u", "--user", "-w", "--write-out",
    "--connect-timeout", "--max-time", "--retry", "--retry-delay",
}
_CURL_BODY_FLAGS = {
    "-d": FORMAT_RAW,
    "--data": FORMAT_RAW,
    "--data-raw": FORMAT_RAW,
    "--data-binary": FORMAT_RAW,
    "--data-urlencode": FORMAT_FORM,
    "-F": FORMAT_FORM,
    "--form": FORMAT_FORM,
    "--form-string": FORMAT_FORM,
    "--json": FORMAT_JSON,
    "-T": FORMAT_RAW,
    "--upload-file": FORMAT_RAW,
}
def _curl_combined_method(tok: str, tokens: list[str], idx: int) -> str:
    letters = tok[1:]
    x_idx = letters.find("X")
    if x_idx == -1:
        return ""
    rest = letters[x_idx + 1:]
    method_chars = []
    for char in rest:
        if char.isalpha():
            method_chars.append(char)
        else:
            break
    if method_chars:
        return "".join(method_chars).upper()
    if idx + 1 < len(tokens):
        return tokens[idx + 1].upper()
    return ""


def _curl_body_arg(tok: str, tokens: list[str], idx: int) -> tuple[str | None, str, str, int, str] | None:
    for flag, fmt in _CURL_BODY_FLAGS.items():
        if tok == flag:
            value = tokens[idx + 1] if idx + 1 < len(tokens) else None
            default_method = "PUT" if flag in {"-T", "--upload-file"} else "POST"
            source = _upload_file_source(value) if flag in {"-T", "--upload-file"} else _body_value_source(value)
            return value, fmt, source, 2 if value is not None else 1, default_method
        if flag.startswith("--") and tok.startswith(flag + "="):
            value = tok.split("=", 1)[1]
            default_method = "PUT" if flag == "--upload-file" else "POST"
            source = _upload_file_source(value) if flag == "--upload-file" else _body_value_source(value)
            return value, fmt, source, 1, default_method
    if tok.startswith("-d") and tok != "-d" and not tok.startswith("--"):
        value = tok[2:]
        return value, FORMAT_RAW, _body_value_source(value), 1, "POST"
    return None


def _upload_file_source(value: str | None) -> str:
    if value is None:
        return BODY_UNKNOWN
    if _looks_dynamic(value):
        return BODY_DYNAMIC
    if value == "-":
        return BODY_STDIN
    return BODY_FILE


def _flag_takes_value(tok: str, value_flags: set[str]) -> bool:
    if tok in value_flags:
        return True
    return any(tok.startswith(flag + "=") for flag in value_flags if flag.startswith("--"))


def _extract_wget(tokens: list[str]) -> RemoteOperation:
    op = RemoteOperation(client=CLIENT_WGET, method="GET")
    reasons: list[str] = []
    body_values: list[str] = []
    body_items: list[BodyItem] = []

    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--method":
            if i + 1 < len(tokens):
                op = replace(op, method=tokens[i + 1].upper())
                i += 2
                continue
            _add_reason(reasons, "missing wget method")
            i += 1
            continue
        if tok.startswith("--method="):
            op = replace(op, method=tok.split("=", 1)[1].upper())
            i += 1
            continue

        if tok in {"--post-data", "--post-file"} or tok.startswith("--post-data=") or tok.startswith("--post-file="):
            if "=" in tok:
                flag, value = tok.split("=", 1)
                consumed = 1
            else:
                flag = tok
                value = tokens[i + 1] if i + 1 < len(tokens) else None
                consumed = 2 if value is not None else 1
            source = BODY_FILE if flag == "--post-file" else _body_value_source(value)
            fmt = FORMAT_RAW
            op = replace(op, method="POST" if op.method == "GET" else op.method,
                         body_source=_merge_body_source(op.body_source, source))
            if source == BODY_INLINE and value is not None:
                body_values.append(value)
            body_items.append(BodyItem(value=value or "", source=source, format=fmt))
            i += consumed
            continue

        if _flag_takes_value(tok, _WGET_SKIP_VALUE_FLAGS):
            i += 2 if "=" not in tok and i + 1 < len(tokens) else 1
            continue

        if _looks_urlish(tok) and not op.host:
            op = _apply_url(op, tok)
        i += 1

    if body_items:
        op = replace(op, body_items=tuple(body_items))
        if op.body_format == FORMAT_UNKNOWN:
            op = replace(op, body_format=_format_for_body(body_values[0]) if body_values else FORMAT_UNKNOWN)
    return _finalize(op, reasons, body_values=body_values)


_WGET_SKIP_VALUE_FLAGS = {
    "-O", "--output-document", "--header", "--user", "--password", "--user-agent",
    "--timeout", "--tries", "--wait", "--referer",
}


def _extract_httpie(tokens: list[str]) -> RemoteOperation:
    cmd = _normalize_cmd(tokens[0])
    default_scheme = "https" if cmd in {"https", "xhs"} else "http"
    op = RemoteOperation(client=CLIENT_HTTPIE, method="GET", scheme=default_scheme)
    reasons: list[str] = []
    body_items: list[BodyItem] = []
    body_values: list[str] = []

    args = tokens[1:]
    idx = 0
    found_url = False
    explicit_method = False
    while idx < len(args):
        arg = args[idx]
        if arg in {"--form", "-f"}:
            op = replace(op, body_format=FORMAT_FORM)
            idx += 1
            continue
        if _flag_takes_value(arg, _HTTPIE_SKIP_VALUE_FLAGS):
            idx += 2 if "=" not in arg and idx + 1 < len(args) else 1
            continue
        if arg.startswith("-"):
            idx += 1
            continue

        if not found_url and arg.upper() in _HTTP_METHODS:
            op = replace(op, method=arg.upper())
            explicit_method = True
            idx += 1
            continue

        if not found_url:
            op = _apply_url(op, arg, default_scheme=default_scheme)
            found_url = bool(op.host)
            idx += 1
            continue

        item = _parse_httpie_item(arg)
        if item:
            body_items.append(item)
            op = replace(op, body_source=_merge_body_source(op.body_source, item.source))
            if item.source == BODY_INLINE:
                body_values.append(item.value)
            idx += 1
            continue
        idx += 1

    if body_items:
        method = op.method if explicit_method else "POST"
        op = replace(op, method=method, body_items=tuple(body_items))
        if op.body_format == FORMAT_UNKNOWN:
            op = replace(op, body_format=FORMAT_FORM)
    return _finalize(op, reasons, body_values=body_values)


_HTTPIE_SKIP_VALUE_FLAGS = {
    "--auth", "-a", "--print", "-p", "--output", "-o",
    "--session", "--session-read-only", "--verify",
}


def _parse_httpie_item(arg: str) -> BodyItem | None:
    for sep, fmt in ((":=", FORMAT_JSON), ("==", FORMAT_RAW), ("=", FORMAT_FORM), ("@", FORMAT_RAW)):
        if sep in arg:
            key, value = arg.split(sep, 1)
            if not key:
                return None
            source = _body_value_source(value if sep != "@" else "@" + value)
            return BodyItem(key=key, value=value, source=source, format=fmt)
    return None


def _extract_api_cli(tokens: list[str], client: str) -> RemoteOperation:
    op = RemoteOperation(client=client, method="GET", host_source=HOST_IMPLICIT)
    reasons: list[str] = []
    body_items: list[BodyItem] = []
    body_values: list[str] = []
    endpoint = ""
    explicit_method = False

    i = 2
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            break
        if tok == "--hostname":
            if i + 1 < len(tokens):
                op = replace(op, host=tokens[i + 1], host_source=HOST_EXPLICIT)
                i += 2
                continue
            _add_reason(reasons, "missing API CLI hostname")
            i += 1
            continue
        if tok.startswith("--hostname="):
            op = replace(op, host=tok.split("=", 1)[1], host_source=HOST_EXPLICIT)
            i += 1
            continue
        if tok in {"--method", "-X"}:
            if i + 1 < len(tokens):
                op = replace(op, method=tokens[i + 1].upper())
                explicit_method = True
                i += 2
                continue
            _add_reason(reasons, "missing API CLI method")
            i += 1
            continue
        if tok.startswith("--method="):
            op = replace(op, method=tok.split("=", 1)[1].upper())
            explicit_method = True
            i += 1
            continue
        if tok.startswith("-X") and tok != "-X" and not tok.startswith("--"):
            op = replace(op, method=tok[2:].upper())
            explicit_method = True
            i += 1
            continue
        if tok == "--input" or tok.startswith("--input="):
            value = tok.split("=", 1)[1] if "=" in tok else (tokens[i + 1] if i + 1 < len(tokens) else None)
            source = BODY_STDIN if value == "-" else BODY_FILE if value else BODY_UNKNOWN
            op = replace(op, body_source=_merge_body_source(op.body_source, source))
            body_items.append(BodyItem(value=value or "", source=source, format=FORMAT_JSON))
            i += 1 if "=" in tok or value is None else 2
            continue
        field = _parse_api_field(tok, tokens, i)
        if field is not None:
            item, consumed = field
            body_items.append(item)
            op = replace(op, body_source=_merge_body_source(op.body_source, item.source))
            if item.source == BODY_INLINE:
                body_values.append(item.value)
            i += consumed
            continue
        if _flag_takes_value(tok, _API_SKIP_VALUE_FLAGS):
            i += 2 if "=" not in tok and i + 1 < len(tokens) else 1
            continue
        if tok.startswith("-"):
            i += 1
            continue
        if not endpoint:
            endpoint = tok
            if _looks_urlish(tok):
                op = _apply_url(op, tok)
            else:
                op = replace(op, path=tok)
        i += 1

    if endpoint == "graphql" or _GRAPHQL_PATH_RE.search(op.path or ""):
        op = replace(op, protocol=PROTOCOL_GRAPHQL, path=op.path or "graphql")
    if body_items:
        method = op.method if explicit_method else "POST"
        op = replace(op, method=method, body_items=tuple(body_items))
        if op.body_format == FORMAT_UNKNOWN:
            op = replace(op, body_format=FORMAT_FORM)
    return _finalize(op, reasons, body_values=body_values)


_API_SKIP_VALUE_FLAGS = {
    "--cache", "--header", "-H", "--jq", "-q", "--preview", "-p", "--template", "-t",
}


def _parse_api_field(tok: str, tokens: list[str], idx: int) -> tuple[BodyItem, int] | None:
    flag = ""
    payload: str | None = None
    if tok in {"--raw-field", "-f", "--field", "-F", "--form"}:
        flag = tok
        payload = tokens[idx + 1] if idx + 1 < len(tokens) else None
        consumed = 2 if payload is not None else 1
    elif tok.startswith("--raw-field="):
        flag = "--raw-field"
        payload = tok.split("=", 1)[1]
        consumed = 1
    elif tok.startswith("--field="):
        flag = "--field"
        payload = tok.split("=", 1)[1]
        consumed = 1
    elif tok.startswith("--form="):
        flag = "--form"
        payload = tok.split("=", 1)[1]
        consumed = 1
    elif tok.startswith("-f") and tok != "-f" and not tok.startswith("--"):
        flag = "-f"
        payload = tok[2:]
        consumed = 1
    elif tok.startswith("-F") and tok != "-F" and not tok.startswith("--"):
        flag = "-F"
        payload = tok[2:]
        consumed = 1
    else:
        return None

    key, value = _split_payload(payload)
    source = _body_value_source(value)
    fmt = FORMAT_FORM
    if flag in {"--raw-field", "-f"}:
        source = BODY_INLINE if value is not None and not _looks_dynamic(value) else source
    if key == "query" and value:
        fmt = FORMAT_GRAPHQL
    return BodyItem(key=key, value=value or "", source=source, format=fmt), consumed


def _split_payload(payload: str | None) -> tuple[str, str | None]:
    if payload is None:
        return "", None
    key, sep, value = payload.partition("=")
    if not sep:
        return key, None
    return key, value


def _extract_grpcurl(tokens: list[str]) -> RemoteOperation:
    op = RemoteOperation(client=CLIENT_GRPCURL, protocol=PROTOCOL_GRPC)
    reasons: list[str] = []
    body_values: list[str] = []
    positionals: list[str] = []

    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "-d":
            value = tokens[i + 1] if i + 1 < len(tokens) else None
            source = _body_value_source(value)
            op = replace(op, body_source=_merge_body_source(op.body_source, source),
                         body_format=FORMAT_JSON)
            if source == BODY_INLINE and value is not None:
                body_values.append(value)
            i += 2 if value is not None else 1
            continue
        if tok.startswith("-d") and tok != "-d":
            value = tok[2:]
            source = _body_value_source(value)
            op = replace(op, body_source=_merge_body_source(op.body_source, source),
                         body_format=FORMAT_JSON)
            if source == BODY_INLINE:
                body_values.append(value)
            i += 1
            continue
        if _flag_takes_value(tok, _GRPCURL_SKIP_VALUE_FLAGS):
            i += 2 if "=" not in tok and i + 1 < len(tokens) else 1
            continue
        if tok.startswith("-"):
            i += 1
            continue
        positionals.append(tok)
        i += 1

    for positional in positionals:
        if not op.host and _looks_urlish(positional):
            op = _apply_url(op, positional)
            continue
        if not op.method:
            op = replace(op, method=positional, operation_name=positional)

    return _finalize(op, reasons, body_values=body_values)


_GRPCURL_SKIP_VALUE_FLAGS = {
    "-H", "-authority", "-import-path", "-proto", "-protoset", "-servername",
    "-connect-timeout", "-max-time", "-cacert", "-cert", "-key",
}


def _extract_wscat(tokens: list[str]) -> RemoteOperation:
    op = RemoteOperation(client=CLIENT_WSCAT, protocol=PROTOCOL_WEBSOCKET)
    reasons: list[str] = []
    body_values: list[str] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in {"-c", "--connect"}:
            if i + 1 < len(tokens):
                op = _apply_url(op, tokens[i + 1], default_scheme="ws")
                i += 2
                continue
            _add_reason(reasons, "missing WebSocket URL")
            i += 1
            continue
        if tok in {"-x", "--execute"}:
            value = tokens[i + 1] if i + 1 < len(tokens) else None
            source = _body_value_source(value)
            op = replace(op, body_source=_merge_body_source(op.body_source, source))
            if source == BODY_INLINE and value is not None:
                body_values.append(value)
                event = _extract_event_name(value)
                if event:
                    op = replace(op, method=event, operation_name=event)
            i += 2 if value is not None else 1
            continue
        if _looks_urlish(tok) and not op.host:
            op = _apply_url(op, tok, default_scheme="ws")
        i += 1
    if body_values and op.body_format == FORMAT_UNKNOWN:
        op = replace(op, body_format=_format_for_body(body_values[0]))
    return _finalize(op, reasons, body_values=body_values)


def _extract_websocat(tokens: list[str]) -> RemoteOperation:
    op = RemoteOperation(client=CLIENT_WEBSOCAT, protocol=PROTOCOL_WEBSOCKET)
    reasons: list[str] = []
    body_values: list[str] = []
    positionals: list[str] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if _flag_takes_value(tok, {"-H", "--header", "--protocol", "--origin"}):
            i += 2 if "=" not in tok and i + 1 < len(tokens) else 1
            continue
        if tok.startswith("-") and tok != "-":
            i += 1
            continue
        positionals.append(tok)
        i += 1

    for positional in positionals:
        if not op.host and _looks_urlish(positional):
            op = _apply_url(op, positional, default_scheme="ws")
            continue
        if op.host:
            source = _body_value_source(positional)
            op = replace(op, body_source=_merge_body_source(op.body_source, source))
            if source == BODY_INLINE:
                body_values.append(positional)
                event = _extract_event_name(positional)
                if event:
                    op = replace(op, method=event, operation_name=event)
    if body_values and op.body_format == FORMAT_UNKNOWN:
        op = replace(op, body_format=_format_for_body(body_values[0]))
    return _finalize(op, reasons, body_values=body_values)


def _extract_event_name(value: str) -> str:
    socketio_event = _extract_socketio_event_name(value)
    if socketio_event:
        return socketio_event

    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return ""
    if isinstance(payload, dict):
        for key in ("event", "type", "method", "action"):
            if isinstance(payload.get(key), str):
                return payload[key]
    if isinstance(payload, list) and payload and isinstance(payload[0], str):
        return payload[0]
    return ""


def _extract_socketio_event_name(value: str) -> str:
    """Extract simple visible Socket.IO event packets without session state."""
    rest = value.lstrip()
    if not rest.startswith("42"):
        return ""
    rest = rest[2:]
    if rest.startswith("/"):
        comma = rest.find(",")
        if comma == -1:
            return ""
        rest = rest[comma + 1:]
    if not rest.startswith("["):
        return ""
    try:
        payload = json.loads(rest)
    except json.JSONDecodeError:
        return ""
    if isinstance(payload, list) and payload and isinstance(payload[0], str):
        return payload[0]
    return ""
