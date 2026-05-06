"""Unit tests for nah.api_intent remote operation extraction."""

import shlex

from nah.api_intent import (
    BODY_DYNAMIC,
    BODY_FILE,
    BODY_INLINE,
    BODY_STDIN,
    CLIENT_CURL,
    CLIENT_GH_API,
    CLIENT_GLAB_API,
    CLIENT_GRPCURL,
    CLIENT_HTTPIE,
    CLIENT_WEBSOCAT,
    CLIENT_WGET,
    CLIENT_WSCAT,
    CONFIDENCE_COMPLETE,
    CONFIDENCE_OPAQUE,
    CONFIDENCE_PARTIAL,
    FORMAT_FORM,
    FORMAT_GRAPHQL,
    FORMAT_JSON,
    HOST_EXPLICIT,
    HOST_IMPLICIT,
    PROTOCOL_GRAPHQL,
    PROTOCOL_GRPC,
    PROTOCOL_HTTP,
    PROTOCOL_JSON_RPC,
    PROTOCOL_WEBSOCKET,
    extract_remote_operation,
)


def _op(command: str):
    result = extract_remote_operation(shlex.split(command))
    assert result is not None
    return result


class TestCurlExtraction:
    def test_curl_get_url(self):
        op = _op("curl https://api.example.com/v1/items?limit=10")

        assert op.client == CLIENT_CURL
        assert op.protocol == PROTOCOL_HTTP
        assert op.method == "GET"
        assert op.host == "api.example.com"
        assert op.host_source == HOST_EXPLICIT
        assert op.path == "/v1/items?limit=10"
        assert op.confidence == CONFIDENCE_COMPLETE

    def test_curl_post_json_inline(self):
        op = _op("curl --json '{\"name\":\"demo\"}' https://api.example.com/items")

        assert op.method == "POST"
        assert op.body_source == BODY_INLINE
        assert op.body_format == FORMAT_JSON
        assert op.body_text == '{"name":"demo"}'
        assert op.body_items[0].value == '{"name":"demo"}'

    def test_curl_delete_method(self):
        op = _op("curl -X DELETE https://api.example.com/items/1")

        assert op.method == "DELETE"
        assert op.host == "api.example.com"
        assert op.path == "/items/1"

    def test_curl_malformed_port_does_not_crash(self):
        op = _op("curl https://api.example.com:notaport/items")

        assert op.host == "api.example.com"
        assert op.port == ""
        assert op.path == "/items"

    def test_curl_file_body_is_opaque(self):
        op = _op("curl -d @payload.json https://api.example.com/items")

        assert op.method == "POST"
        assert op.body_source == BODY_FILE
        assert op.confidence == CONFIDENCE_OPAQUE
        assert "opaque body source: file" in op.reasons

    def test_curl_stdin_body_is_opaque(self):
        op = _op("curl -d @- https://api.example.com/items")

        assert op.body_source == BODY_STDIN
        assert op.confidence == CONFIDENCE_OPAQUE

    def test_curl_upload_file_is_opaque(self):
        op = _op("curl --upload-file payload.json https://api.example.com/items/1")

        assert op.method == "PUT"
        assert op.body_source == BODY_FILE
        assert op.confidence == CONFIDENCE_OPAQUE

    def test_curl_dynamic_body_is_opaque(self):
        op = _op("curl -d '$(cat payload.json)' https://api.example.com/items")

        assert op.body_source == BODY_DYNAMIC
        assert op.confidence == CONFIDENCE_OPAQUE

    def test_curl_malformed_json_body_is_opaque(self):
        op = _op("curl --json '{bad' https://api.example.com/items")

        assert op.body_source == BODY_INLINE
        assert op.body_format == FORMAT_JSON
        assert op.confidence == CONFIDENCE_OPAQUE
        assert "malformed JSON body" in op.reasons

    def test_curl_graphql_json_body(self):
        op = _op(
            "curl --json '{\"query\":\"query Viewer { viewer { login } }\"}' "
            "https://api.github.com/graphql"
        )

        assert op.protocol == PROTOCOL_GRAPHQL
        assert op.body_format == FORMAT_GRAPHQL
        assert op.operation_name == "Viewer"
        assert op.body_text == "query Viewer { viewer { login } }"

    def test_curl_json_rpc_body(self):
        op = _op(
            "curl -d '{\"jsonrpc\":\"2.0\",\"method\":\"resources/read\",\"id\":1}' "
            "https://mcp.example.com/rpc"
        )

        assert op.protocol == PROTOCOL_JSON_RPC
        assert op.body_format == FORMAT_JSON
        assert op.method == "resources/read"
        assert op.operation_name == "resources/read"

    def test_curl_explicit_get_with_body_preserves_method(self):
        op = _op("curl -X GET -d data https://api.example.com/items")

        assert op.method == "GET"
        assert op.body_source == BODY_INLINE


class TestWgetExtraction:
    def test_wget_post_data(self):
        op = _op("wget --post-data '{\"x\":1}' https://api.example.com/items")

        assert op.client == CLIENT_WGET
        assert op.method == "POST"
        assert op.body_source == BODY_INLINE
        assert op.body_format == FORMAT_JSON

    def test_wget_post_file_is_opaque(self):
        op = _op("wget --post-file payload.json https://api.example.com/items")

        assert op.body_source == BODY_FILE
        assert op.confidence == CONFIDENCE_OPAQUE


class TestHttpieExtraction:
    def test_httpie_post_data_items(self):
        op = _op("http POST api.example.com/items name=demo count:=1")

        assert op.client == CLIENT_HTTPIE
        assert op.method == "POST"
        assert op.host == "api.example.com"
        assert op.path == "/items"
        assert op.body_source == BODY_INLINE
        assert op.body_format == FORMAT_FORM
        assert [item.key for item in op.body_items] == ["name", "count"]

    def test_httpie_implicit_post_when_body_items_exist(self):
        op = _op("xh https://api.example.com/items name=demo")

        assert op.method == "POST"
        assert op.scheme == "https"
        assert op.body_source == BODY_INLINE


class TestApiCliExtraction:
    def test_gh_api_graphql_query_field(self):
        op = _op("gh api graphql -f 'query=query Viewer { viewer { login } }'")

        assert op.client == CLIENT_GH_API
        assert op.protocol == PROTOCOL_GRAPHQL
        assert op.method == "POST"
        assert op.host == ""
        assert op.host_source == HOST_IMPLICIT
        assert op.confidence == CONFIDENCE_PARTIAL
        assert op.operation_name == "Viewer"
        assert op.body_text == "query Viewer { viewer { login } }"

    def test_gh_api_input_file_is_opaque(self):
        op = _op("gh api repos/owner/repo/issues --input body.json")

        assert op.body_source == BODY_FILE
        assert op.confidence == CONFIDENCE_OPAQUE

    def test_glab_api_hostname_and_endpoint(self):
        op = _op("glab api projects/1 --hostname gitlab.example.com")

        assert op.client == CLIENT_GLAB_API
        assert op.method == "GET"
        assert op.host == "gitlab.example.com"
        assert op.host_source == HOST_EXPLICIT
        assert op.path == "projects/1"
        assert op.confidence == CONFIDENCE_COMPLETE


class TestGrpcExtraction:
    def test_grpcurl_service_method(self):
        op = _op("grpcurl -d '{\"id\":1}' api.example.com:443 pkg.User/GetUser")

        assert op.client == CLIENT_GRPCURL
        assert op.protocol == PROTOCOL_GRPC
        assert op.host == "api.example.com"
        assert op.port == "443"
        assert op.method == "pkg.User/GetUser"
        assert op.operation_name == "pkg.User/GetUser"
        assert op.body_source == BODY_INLINE
        assert op.body_format == FORMAT_JSON


class TestWebSocketExtraction:
    def test_wscat_execute_event(self):
        op = _op("wscat -c ws://api.example.com/socket -x '{\"event\":\"deleteUser\"}'")

        assert op.client == CLIENT_WSCAT
        assert op.protocol == PROTOCOL_WEBSOCKET
        assert op.scheme == "ws"
        assert op.host == "api.example.com"
        assert op.path == "/socket"
        assert op.method == "deleteUser"
        assert op.operation_name == "deleteUser"

    def test_websocat_visible_message_event(self):
        op = _op("websocat ws://api.example.com/socket '{\"type\":\"subscribe\"}'")

        assert op.client == CLIENT_WEBSOCAT
        assert op.protocol == PROTOCOL_WEBSOCKET
        assert op.method == "subscribe"
        assert op.body_source == BODY_INLINE


def test_unsupported_command_returns_none():
    assert extract_remote_operation(["echo", "ok"]) is None
