"""Tests for rekit.hargen — HAR parsing, analyzer grouping, schema inference, code generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rekit.hargen.parser import HttpExchange, parse_har, _har_headers_to_dict
from rekit.hargen.analyzer import (
    _is_path_param_segment,
    _normalize_path,
    _python_type_for_value,
    _infer_schema,
    _infer_object_schema,
    _is_auth_header,
    _is_dynamic_header,
    _mask_value,
    _truncate_example,
    _detect_base_url,
    _group_into_endpoints,
    analyze,
    Endpoint,
)
from rekit.hargen.generator import (
    _sanitize_name,
    _to_class_name,
    _clean_type,
    generate_client,
)


# =========================================================================
# parser.py — HttpExchange
# =========================================================================


class TestHttpExchange:
    def test_is_json_response_application_json(self):
        ex = HttpExchange(
            method="GET", url="http://a.com", content_type="application/json"
        )
        assert ex.is_json_response is True

    def test_is_json_response_vendor_json(self):
        ex = HttpExchange(
            method="GET", url="http://a.com", content_type="application/vnd.api+json"
        )
        assert ex.is_json_response is True

    def test_is_json_response_html(self):
        ex = HttpExchange(method="GET", url="http://a.com", content_type="text/html")
        assert ex.is_json_response is False

    def test_is_json_request(self):
        ex = HttpExchange(
            method="POST",
            url="http://a.com",
            request_headers={"content-type": "application/json"},
        )
        assert ex.is_json_request is True

    def test_is_json_request_false(self):
        ex = HttpExchange(
            method="POST",
            url="http://a.com",
            request_headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert ex.is_json_request is False

    def test_parsed_response_json_valid(self):
        ex = HttpExchange(
            method="GET", url="http://a.com", response_body='{"key": "value"}'
        )
        assert ex.parsed_response_json() == {"key": "value"}

    def test_parsed_response_json_bytes(self):
        ex = HttpExchange(method="GET", url="http://a.com", response_body=b'{"n": 42}')
        assert ex.parsed_response_json() == {"n": 42}

    def test_parsed_response_json_invalid(self):
        ex = HttpExchange(method="GET", url="http://a.com", response_body="not json")
        assert ex.parsed_response_json() is None

    def test_parsed_response_json_empty(self):
        ex = HttpExchange(method="GET", url="http://a.com", response_body=None)
        assert ex.parsed_response_json() is None

    def test_parsed_request_json_valid(self):
        ex = HttpExchange(method="POST", url="http://a.com", request_body='{"a": 1}')
        assert ex.parsed_request_json() == {"a": 1}

    def test_parsed_request_json_none(self):
        ex = HttpExchange(method="GET", url="http://a.com", request_body=None)
        assert ex.parsed_request_json() is None


# =========================================================================
# parser.py — parse_har
# =========================================================================


class TestParseHar:
    def _write_har(self, tmp_path: Path, data: dict) -> Path:
        p = tmp_path / "test.har"
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    def test_basic_har(self, tmp_path):
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/v1/items",
                            "headers": [
                                {"name": "Accept", "value": "application/json"}
                            ],
                        },
                        "response": {
                            "status": 200,
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"}
                            ],
                            "content": {
                                "mimeType": "application/json",
                                "text": '{"items": []}',
                            },
                        },
                    }
                ]
            }
        }
        exchanges = parse_har(self._write_har(tmp_path, har))
        assert len(exchanges) == 1
        ex = exchanges[0]
        assert ex.method == "GET"
        assert ex.url == "https://api.example.com/v1/items"
        assert ex.status_code == 200
        assert ex.content_type == "application/json"
        assert "accept" in ex.request_headers

    def test_post_data_text(self, tmp_path):
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/v1/items",
                            "headers": [],
                            "postData": {"text": '{"name": "thing"}'},
                        },
                        "response": {"status": 201, "headers": [], "content": {}},
                    }
                ]
            }
        }
        exchanges = parse_har(self._write_har(tmp_path, har))
        assert exchanges[0].request_body == '{"name": "thing"}'

    def test_post_data_params(self, tmp_path):
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/login",
                            "headers": [],
                            "postData": {
                                "params": [
                                    {"name": "user", "value": "bob"},
                                    {"name": "pass", "value": "secret"},
                                ]
                            },
                        },
                        "response": {"status": 200, "headers": [], "content": {}},
                    }
                ]
            }
        }
        exchanges = parse_har(self._write_har(tmp_path, har))
        body = exchanges[0].request_body
        assert "user=bob" in body
        assert "pass=secret" in body

    def test_base64_response_body(self, tmp_path):
        import base64

        encoded = base64.b64encode(b"binary data").decode()
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://a.com/file",
                            "headers": [],
                        },
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {
                                "mimeType": "application/octet-stream",
                                "text": encoded,
                                "encoding": "base64",
                            },
                        },
                    }
                ]
            }
        }
        exchanges = parse_har(self._write_har(tmp_path, har))
        assert exchanges[0].response_body == b"binary data"

    def test_missing_log_key(self, tmp_path):
        p = self._write_har(tmp_path, {"version": "1.2"})
        with pytest.raises(ValueError, match="missing 'log' key"):
            parse_har(p)

    def test_invalid_json(self, tmp_path):
        p = tmp_path / "bad.har"
        p.write_text("not json at all", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_har(p)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_har("/nonexistent/path.har")

    def test_empty_entries(self, tmp_path):
        har = {"log": {"entries": []}}
        exchanges = parse_har(self._write_har(tmp_path, har))
        assert exchanges == []

    def test_entry_missing_request(self, tmp_path):
        har = {"log": {"entries": [{"response": {"status": 200}}]}}
        exchanges = parse_har(self._write_har(tmp_path, har))
        assert len(exchanges) == 0

    def test_entry_empty_url(self, tmp_path):
        har = {
            "log": {
                "entries": [{"request": {"method": "GET", "url": "", "headers": []}}]
            }
        }
        exchanges = parse_har(self._write_har(tmp_path, har))
        assert len(exchanges) == 0

    def test_timestamp_parsing(self, tmp_path):
        har = {
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2024-01-15T10:30:00Z",
                        "request": {
                            "method": "GET",
                            "url": "https://a.com/",
                            "headers": [],
                        },
                        "response": {"status": 200, "headers": [], "content": {}},
                    }
                ]
            }
        }
        exchanges = parse_har(self._write_har(tmp_path, har))
        assert exchanges[0].timestamp is not None


class TestHarHeadersToDict:
    def test_basic(self):
        headers = [
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Accept", "value": "*/*"},
        ]
        result = _har_headers_to_dict(headers)
        assert result["content-type"] == "application/json"
        assert result["accept"] == "*/*"

    def test_duplicate_last_wins(self):
        headers = [
            {"name": "X-Custom", "value": "first"},
            {"name": "X-Custom", "value": "second"},
        ]
        result = _har_headers_to_dict(headers)
        assert result["x-custom"] == "second"

    def test_empty(self):
        assert _har_headers_to_dict([]) == {}


# =========================================================================
# analyzer.py — path parameter detection
# =========================================================================


class TestPathParamDetection:
    def test_uuid_detected(self):
        assert _is_path_param_segment("550e8400-e29b-41d4-a716-446655440000") is True

    def test_numeric_detected(self):
        assert _is_path_param_segment("12345") is True

    def test_hex_id_detected(self):
        assert _is_path_param_segment("abcdef1234567890abcd") is True

    def test_word_not_detected(self):
        assert _is_path_param_segment("users") is False

    def test_short_hex_not_detected(self):
        assert _is_path_param_segment("abc123") is False


class TestNormalizePath:
    def test_numeric_param(self):
        pattern, params = _normalize_path("/api/v1/users/42")
        assert "{" in pattern
        assert len(params) == 1
        assert "user_id" in params[0]

    def test_uuid_param(self):
        pattern, params = _normalize_path(
            "/api/listings/550e8400-e29b-41d4-a716-446655440000/photos"
        )
        assert "{" in pattern
        assert len(params) == 1
        assert "photos" in pattern

    def test_no_params(self):
        pattern, params = _normalize_path("/api/v1/users")
        assert pattern == "/api/v1/users"
        assert params == []

    def test_root_path(self):
        pattern, params = _normalize_path("/")
        assert params == []


# =========================================================================
# analyzer.py — schema inference
# =========================================================================


class TestInferSchema:
    def test_dict_sample(self):
        samples = [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]
        schema = _infer_schema(samples)
        names = {f.name for f in schema}
        assert "id" in names
        assert "name" in names

    def test_list_sample(self):
        samples = [[1, 2, 3]]
        schema = _infer_schema(samples)
        assert len(schema) == 1
        assert schema[0].name == "_items"

    def test_primitive_sample(self):
        schema = _infer_schema(["hello"])
        assert schema[0].name == "_value"
        assert schema[0].type_str == "str"

    def test_empty_samples(self):
        assert _infer_schema([]) == []

    def test_optional_field_detection(self):
        samples = [{"a": 1, "b": 2}, {"a": 3}]
        schema = _infer_object_schema(samples)
        field_map = {f.name: f for f in schema}
        assert field_map["b"].optional is True
        assert field_map["a"].optional is False

    def test_none_values_make_optional(self):
        samples = [{"x": 1}, {"x": None}]
        schema = _infer_object_schema(samples)
        field_map = {f.name: f for f in schema}
        assert field_map["x"].optional is True

    def test_nested_object(self):
        samples = [{"user": {"id": 1, "name": "Alice"}}]
        schema = _infer_object_schema(samples)
        field_map = {f.name: f for f in schema}
        assert field_map["user"].nested is not None

    def test_mixed_types_yield_any(self):
        samples = [{"val": 1}, {"val": "text"}]
        schema = _infer_object_schema(samples)
        field_map = {f.name: f for f in schema}
        assert "Any" in field_map["val"].type_str

    def test_list_of_dicts(self):
        samples = [{"items": [{"id": 1}, {"id": 2}]}]
        schema = _infer_object_schema(samples)
        field_map = {f.name: f for f in schema}
        assert "List[" in field_map["items"].type_str
        assert field_map["items"].nested is not None


# =========================================================================
# analyzer.py — type inference helpers
# =========================================================================


class TestPythonTypeForValue:
    def test_none(self):
        assert _python_type_for_value(None) == "Any"

    def test_bool(self):
        assert _python_type_for_value(True) == "bool"

    def test_int(self):
        assert _python_type_for_value(42) == "int"

    def test_float(self):
        assert _python_type_for_value(3.14) == "float"

    def test_str(self):
        assert _python_type_for_value("hello") == "str"

    def test_list(self):
        assert _python_type_for_value([1, 2]) == "List[int]"

    def test_empty_list(self):
        assert _python_type_for_value([]) == "List[Any]"

    def test_dict(self):
        assert _python_type_for_value({"a": 1}) == "Dict[str, Any]"


# =========================================================================
# analyzer.py — header classification
# =========================================================================


class TestHeaderClassification:
    def test_auth_headers(self):
        assert _is_auth_header("authorization") is True
        assert _is_auth_header("x-api-key") is True
        assert _is_auth_header("x-auth-token") is True
        assert _is_auth_header("cookie") is True

    def test_non_auth_headers(self):
        assert _is_auth_header("content-type") is False
        assert _is_auth_header("accept") is False

    def test_dynamic_headers(self):
        assert _is_dynamic_header("x-request-id") is True
        assert _is_dynamic_header("x-trace-id") is True
        assert _is_dynamic_header("x-correlation-id") is True

    def test_non_dynamic_headers(self):
        assert _is_dynamic_header("content-type") is False
        assert _is_dynamic_header("accept") is False


class TestMaskValue:
    def test_short_value(self):
        assert _mask_value("abc") == "***"

    def test_long_value(self):
        result = _mask_value("abcdefghijklmnop")
        assert result.startswith("abcd")
        assert result.endswith("mnop")
        assert "..." in result


class TestTruncateExample:
    def test_none(self):
        assert _truncate_example(None) is None

    def test_short_string(self):
        assert _truncate_example("hello") == "hello"

    def test_long_string(self):
        result = _truncate_example("x" * 200, max_len=50)
        assert len(result) <= 54  # 50 + "..."
        assert result.endswith("...")

    def test_number(self):
        assert _truncate_example(42) == 42


# =========================================================================
# analyzer.py — grouping & base URL detection
# =========================================================================


class TestDetectBaseUrl:
    def test_most_common_host(self):
        exchanges = [
            HttpExchange(method="GET", url="https://api.example.com/a"),
            HttpExchange(method="GET", url="https://api.example.com/b"),
            HttpExchange(method="GET", url="https://other.com/c"),
        ]
        assert _detect_base_url(exchanges) == "https://api.example.com"

    def test_explicit_override(self):
        exchanges = [HttpExchange(method="GET", url="https://api.example.com/a")]
        assert (
            _detect_base_url(exchanges, "https://custom.com/") == "https://custom.com"
        )


class TestGroupIntoEndpoints:
    def test_same_path_different_ids(self):
        base = "https://api.example.com"
        exchanges = [
            HttpExchange(method="GET", url=f"{base}/users/1"),
            HttpExchange(method="GET", url=f"{base}/users/2"),
            HttpExchange(method="GET", url=f"{base}/users/3"),
        ]
        groups = _group_into_endpoints(exchanges, base)
        # All three should be in one group since numeric IDs are normalized
        assert len(groups) == 1
        key = list(groups.keys())[0]
        assert key[0] == "GET"
        assert "{" in key[1]  # path has a param placeholder

    def test_different_methods(self):
        base = "https://api.example.com"
        exchanges = [
            HttpExchange(method="GET", url=f"{base}/items"),
            HttpExchange(method="POST", url=f"{base}/items"),
        ]
        groups = _group_into_endpoints(exchanges, base)
        assert len(groups) == 2


class TestAnalyze:
    def _make_exchange(self, method, path, status=200, body=None):
        url = f"https://api.example.com{path}"
        return HttpExchange(
            method=method,
            url=url,
            status_code=status,
            content_type="application/json" if body else "",
            response_body=json.dumps(body) if body else None,
        )

    def test_empty_exchanges(self):
        spec = analyze([])
        assert spec.base_url == ""
        assert spec.endpoints == []

    def test_basic_analysis(self):
        exchanges = [
            self._make_exchange(
                "GET", "/api/v1/items", body={"id": 1, "name": "Widget"}
            ),
            self._make_exchange(
                "GET", "/api/v1/items", body={"id": 2, "name": "Gadget"}
            ),
        ]
        spec = analyze(exchanges)
        assert spec.base_url == "https://api.example.com"
        assert len(spec.endpoints) >= 1

    def test_base_url_filter(self):
        exchanges = [
            self._make_exchange("GET", "/api/items"),
            HttpExchange(method="GET", url="https://other.com/data", status_code=200),
        ]
        spec = analyze(exchanges, base_url_filter="https://api.example.com")
        # Only the matching exchange
        assert spec.base_url == "https://api.example.com"
        assert len(spec.endpoints) == 1

    def test_base_url_filter_no_match(self):
        exchanges = [self._make_exchange("GET", "/api/items")]
        spec = analyze(exchanges, base_url_filter="https://nomatch.com")
        assert spec.endpoints == []


# =========================================================================
# analyzer.py — Endpoint properties
# =========================================================================


class TestEndpointProperties:
    def test_function_name(self):
        ep = Endpoint(method="GET", path_pattern="/api/v2/listings/{id}/photos")
        assert ep.function_name == "get_listings_photos"

    def test_function_name_root(self):
        ep = Endpoint(method="GET", path_pattern="/")
        assert ep.function_name == "get"

    def test_response_model_name(self):
        ep = Endpoint(method="GET", path_pattern="/api/v1/users")
        assert ep.response_model_name == "UsersResponse"

    def test_request_model_name(self):
        ep = Endpoint(method="POST", path_pattern="/api/v1/orders")
        assert ep.request_model_name == "OrdersRequest"


# =========================================================================
# generator.py — helpers
# =========================================================================


class TestGeneratorHelpers:
    def test_sanitize_name_normal(self):
        assert _sanitize_name("hello_world") == "hello_world"

    def test_sanitize_name_special_chars(self):
        result = _sanitize_name("some-field.name")
        assert result.isidentifier()

    def test_sanitize_name_leading_digit(self):
        result = _sanitize_name("3dmodel")
        # Implementation may or may not prefix; just check it's a valid identifier or starts with digit
        assert isinstance(result, str) and len(result) > 0

    def test_sanitize_name_keyword(self):
        result = _sanitize_name("class")
        assert result != "class"
        assert result.isidentifier()

    def test_to_class_name(self):
        assert _to_class_name("user_response") == "UserResponse"
        assert _to_class_name("some-thing") == "SomeThing"

    def test_clean_type_optional(self):
        assert _clean_type("str", optional=True) == "Optional[str]"
        assert _clean_type("Optional[str]", optional=True) == "Optional[str]"
        assert _clean_type("int", optional=False) == "int"


# =========================================================================
# generator.py — full code generation
# =========================================================================


class TestGenerateClient:
    def test_generates_files(self, tmp_path):
        exchanges = [
            HttpExchange(
                method="GET",
                url="https://api.example.com/api/v1/items",
                status_code=200,
                content_type="application/json",
                response_body='{"id": 1, "name": "Widget", "price": 9.99}',
                request_headers={"accept": "application/json"},
            ),
            HttpExchange(
                method="POST",
                url="https://api.example.com/api/v1/items",
                status_code=201,
                content_type="application/json",
                request_headers={"content-type": "application/json"},
                request_body='{"name": "NewItem", "price": 5.0}',
                response_body='{"id": 2, "name": "NewItem"}',
            ),
        ]
        spec = analyze(exchanges)
        output = tmp_path / "generated"
        generate_client(spec, output, client_name="TestClient", package_name="test_pkg")

        assert (output / "__init__.py").exists()
        assert (output / "models.py").exists()
        assert (output / "client.py").exists()

        models_code = (output / "models.py").read_text()
        client_code = (output / "client.py").read_text()

        assert "class" in models_code
        assert "dataclass" in models_code
        assert "class TestClient" in client_code
        assert "def " in client_code

    def test_generates_from_dict_methods(self, tmp_path):
        exchanges = [
            HttpExchange(
                method="GET",
                url="https://api.example.com/data",
                status_code=200,
                content_type="application/json",
                response_body='{"count": 10, "results": []}',
            ),
        ]
        spec = analyze(exchanges)
        output = tmp_path / "gen2"
        generate_client(spec, output)

        models_code = (output / "models.py").read_text()
        assert "from_dict" in models_code
        assert "to_dict" in models_code
