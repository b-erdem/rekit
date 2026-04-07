"""Comprehensive tests for rekit.protorev — protobuf reverse engineering tools."""

from __future__ import annotations

import struct

import pytest

from rekit.protorev.decoder import (
    ProtoField,
    ProtoMessage,
    WireType,
    decode_protobuf,
    decode_varint,
    decode_zigzag,
    format_decoded,
)
from rekit.protorev.extractor import (
    ProtoExchange,
    extract_proto_exchanges,
)
from rekit.protorev.schema import (
    generate_proto_file,
    generate_python_client,
    infer_schema,
)
from rekit.hargen.parser import HttpExchange


# ---------------------------------------------------------------------------
# Helpers: manual protobuf encoding (no protobuf library needed)
# ---------------------------------------------------------------------------


def encode_varint(value: int) -> bytes:
    """Encode an unsigned integer as a protobuf varint."""
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def encode_field(field_number: int, wire_type: int, data: bytes) -> bytes:
    """Encode a protobuf field tag + data."""
    tag = encode_varint((field_number << 3) | wire_type)
    return tag + data


def encode_string(field_number: int, s: str) -> bytes:
    """Encode a string field."""
    encoded = s.encode("utf-8")
    return encode_field(field_number, 2, encode_varint(len(encoded)) + encoded)


def encode_varint_field(field_number: int, value: int) -> bytes:
    """Encode a varint field."""
    return encode_field(field_number, 0, encode_varint(value))


def encode_bytes_field(field_number: int, data: bytes) -> bytes:
    """Encode a bytes field."""
    return encode_field(field_number, 2, encode_varint(len(data)) + data)


def encode_fixed32_field(field_number: int, value: bytes) -> bytes:
    """Encode a fixed32 field (raw 4 bytes)."""
    return encode_field(field_number, 5, value)


def encode_fixed64_field(field_number: int, value: bytes) -> bytes:
    """Encode a fixed64 field (raw 8 bytes)."""
    return encode_field(field_number, 1, value)


def encode_submessage(field_number: int, inner: bytes) -> bytes:
    """Encode a nested message field."""
    return encode_field(field_number, 2, encode_varint(len(inner)) + inner)


# ---------------------------------------------------------------------------
# Tests: varint decoding
# ---------------------------------------------------------------------------


class TestDecodeVarint:
    def test_small_number(self):
        data = encode_varint(1)
        val, offset = decode_varint(data, 0)
        assert val == 1
        assert offset == 1

    def test_zero(self):
        data = encode_varint(0)
        val, offset = decode_varint(data, 0)
        assert val == 0
        assert offset == 1

    def test_127(self):
        data = encode_varint(127)
        val, offset = decode_varint(data, 0)
        assert val == 127
        assert offset == 1

    def test_128_multi_byte(self):
        data = encode_varint(128)
        val, offset = decode_varint(data, 0)
        assert val == 128
        assert offset == 2

    def test_large_number(self):
        data = encode_varint(300)
        val, offset = decode_varint(data, 0)
        assert val == 300

    def test_very_large_number(self):
        big = 2**50
        data = encode_varint(big)
        val, offset = decode_varint(data, 0)
        assert val == big

    def test_max_uint64(self):
        max_val = (2**64) - 1
        data = encode_varint(max_val)
        val, offset = decode_varint(data, 0)
        assert val == max_val

    def test_truncated_varint_raises(self):
        # A byte with continuation bit set but no following byte
        with pytest.raises(ValueError, match="Truncated"):
            decode_varint(bytes([0x80]), 0)

    def test_offset_in_middle(self):
        data = b"\x00" + encode_varint(42)
        val, offset = decode_varint(data, 1)
        assert val == 42


# ---------------------------------------------------------------------------
# Tests: zigzag decoding
# ---------------------------------------------------------------------------


class TestDecodeZigzag:
    def test_zero(self):
        assert decode_zigzag(0) == 0

    def test_positive(self):
        # zigzag(1) encodes as 2
        assert decode_zigzag(2) == 1
        assert decode_zigzag(4) == 2
        assert decode_zigzag(100) == 50

    def test_negative(self):
        # zigzag(-1) encodes as 1
        assert decode_zigzag(1) == -1
        assert decode_zigzag(3) == -2
        assert decode_zigzag(99) == -50

    def test_large_positive(self):
        assert decode_zigzag(2000) == 1000

    def test_large_negative(self):
        assert decode_zigzag(1999) == -1000


# ---------------------------------------------------------------------------
# Tests: decode simple messages
# ---------------------------------------------------------------------------


class TestDecodeProtobuf:
    def test_simple_varint(self):
        data = encode_varint_field(1, 150)
        msg = decode_protobuf(data)
        assert len(msg.fields) == 1
        assert msg.fields[0].field_number == 1
        assert msg.fields[0].wire_type == WireType.VARINT
        assert msg.fields[0].value == 150

    def test_simple_string(self):
        data = encode_string(2, "hello")
        msg = decode_protobuf(data)
        assert len(msg.fields) == 1
        assert msg.fields[0].field_number == 2
        assert msg.fields[0].wire_type == WireType.LENGTH_DELIMITED
        assert msg.fields[0].value == "hello"
        assert msg.fields[0].interpretation == "string"

    def test_varint_and_string(self):
        data = encode_varint_field(1, 12345) + encode_string(2, "Hello World")
        msg = decode_protobuf(data)
        assert len(msg.fields) == 2
        assert msg.fields[0].value == 12345
        assert msg.fields[1].value == "Hello World"

    def test_multiple_varints(self):
        data = (
            encode_varint_field(1, 1)
            + encode_varint_field(2, 2)
            + encode_varint_field(3, 3)
        )
        msg = decode_protobuf(data)
        assert len(msg.fields) == 3
        for i, f in enumerate(msg.fields):
            assert f.field_number == i + 1
            assert f.value == i + 1


# ---------------------------------------------------------------------------
# Tests: nested messages
# ---------------------------------------------------------------------------


class TestDecodeNestedMessage:
    def test_nested_message(self):
        inner = encode_varint_field(1, 42) + encode_string(2, "nested")
        data = encode_varint_field(1, 100) + encode_submessage(2, inner)
        msg = decode_protobuf(data)
        assert len(msg.fields) == 2
        assert msg.fields[0].value == 100
        nested_field = msg.fields[1]
        assert nested_field.interpretation == "embedded_message"
        assert isinstance(nested_field.value, ProtoMessage)
        assert len(nested_field.value.fields) == 2
        assert nested_field.value.fields[0].value == 42
        assert nested_field.value.fields[1].value == "nested"


# ---------------------------------------------------------------------------
# Tests: fixed32 / fixed64
# ---------------------------------------------------------------------------


class TestDecodeFixed:
    def test_fixed32_uint(self):
        # Encode a uint32 that doesn't look like a plausible float
        val = 0xDEADBEEF
        raw = struct.pack("<I", val)
        data = encode_fixed32_field(1, raw)
        msg = decode_protobuf(data)
        assert len(msg.fields) == 1
        # The value should be the uint32 since the float interpretation
        # would be implausible
        assert msg.fields[0].wire_type == WireType.FIXED32

    def test_fixed32_float(self):
        # Encode a plausible float
        raw = struct.pack("<f", 3.14)
        data = encode_fixed32_field(1, raw)
        msg = decode_protobuf(data)
        assert len(msg.fields) == 1
        f = msg.fields[0]
        assert f.interpretation == "float"
        assert abs(f.value - 3.14) < 0.01

    def test_fixed64_double(self):
        raw = struct.pack("<d", 2.718281828)
        data = encode_fixed64_field(1, raw)
        msg = decode_protobuf(data)
        assert len(msg.fields) == 1
        f = msg.fields[0]
        assert f.interpretation == "double"
        assert abs(f.value - 2.718281828) < 0.0001

    def test_fixed64_uint(self):
        val = 0xDEADBEEFCAFEBABE
        raw = struct.pack("<Q", val)
        data = encode_fixed64_field(1, raw)
        msg = decode_protobuf(data)
        assert len(msg.fields) == 1
        assert msg.fields[0].wire_type == WireType.FIXED64


# ---------------------------------------------------------------------------
# Tests: empty and malformed data
# ---------------------------------------------------------------------------


class TestDecodeEdgeCases:
    def test_empty_message(self):
        msg = decode_protobuf(b"")
        assert len(msg.fields) == 0
        assert msg.raw_bytes == b""

    def test_malformed_data_no_crash(self):
        # Random bytes — should not crash
        data = b"\xff\xff\xff\xff\xff"
        msg = decode_protobuf(data)
        # May decode some fields or none, but should not raise
        assert isinstance(msg, ProtoMessage)

    def test_truncated_field_no_crash(self):
        # Valid tag for field 1, varint, but no value bytes
        data = bytes([0x08])  # field 1, wire type 0
        # This is just a tag with no value — decode_varint will fail
        msg = decode_protobuf(data)
        # Should gracefully stop
        assert isinstance(msg, ProtoMessage)

    def test_string_vs_bytes_disambiguation(self):
        # Binary content that is NOT valid UTF-8
        binary_data = bytes(range(128, 256))
        data = encode_bytes_field(1, binary_data)
        msg = decode_protobuf(data)
        assert len(msg.fields) == 1
        assert msg.fields[0].interpretation == "bytes"
        assert msg.fields[0].value == binary_data


# ---------------------------------------------------------------------------
# Tests: extract_proto_exchanges
# ---------------------------------------------------------------------------


def _make_grpc_frame(proto_data: bytes, compressed: bool = False) -> bytes:
    """Create a gRPC frame with 5-byte prefix."""
    flag = 1 if compressed else 0
    return bytes([flag]) + struct.pack(">I", len(proto_data)) + proto_data


class TestExtractProtoExchanges:
    def test_grpc_content_type(self):
        proto_body = encode_varint_field(1, 42) + encode_string(2, "test")
        framed = _make_grpc_frame(proto_body)

        exchanges = [
            HttpExchange(
                method="POST",
                url="https://api.example.com/my.package.UserService/GetUser",
                request_headers={"content-type": "application/grpc"},
                request_body=framed,
                status_code=200,
                response_headers={},
                response_body=framed,
                content_type="application/grpc",
            )
        ]

        results = extract_proto_exchanges(exchanges)
        assert len(results) == 1
        px = results[0]
        assert px.is_grpc is True
        assert px.grpc_service == "my.package.UserService"
        assert px.grpc_method == "GetUser"
        assert px.request_proto is not None
        assert px.response_proto is not None
        assert len(px.request_proto.fields) == 2

    def test_grpc_frame_stripping(self):
        proto_body = encode_varint_field(1, 99)
        framed = _make_grpc_frame(proto_body)

        # Frame prefix is 5 bytes
        assert len(framed) == 5 + len(proto_body)

        exchanges = [
            HttpExchange(
                method="POST",
                url="https://api.example.com/Service/Method",
                request_headers={"content-type": "application/grpc"},
                request_body=framed,
                status_code=200,
                response_headers={},
                response_body=None,
                content_type="",
            )
        ]

        results = extract_proto_exchanges(exchanges)
        assert len(results) == 1
        assert results[0].request_proto is not None
        assert results[0].request_proto.fields[0].value == 99

    def test_protobuf_content_type(self):
        proto_body = encode_varint_field(1, 7) + encode_string(2, "data")

        exchanges = [
            HttpExchange(
                method="POST",
                url="https://api.example.com/api/data",
                request_headers={"content-type": "application/x-protobuf"},
                request_body=proto_body,
                status_code=200,
                response_headers={},
                response_body=proto_body,
                content_type="application/x-protobuf",
            )
        ]

        results = extract_proto_exchanges(exchanges)
        assert len(results) == 1
        assert results[0].is_grpc is False
        assert results[0].request_proto is not None
        assert results[0].response_proto is not None

    def test_octet_stream_heuristic_positive(self):
        # Valid protobuf with multiple fields — should pass heuristic
        proto_body = encode_varint_field(1, 10) + encode_string(2, "hello")

        exchanges = [
            HttpExchange(
                method="POST",
                url="https://api.example.com/binary",
                request_headers={"content-type": "application/octet-stream"},
                request_body=proto_body,
                status_code=200,
                response_headers={},
                response_body=proto_body,
                content_type="application/octet-stream",
            )
        ]

        results = extract_proto_exchanges(exchanges)
        assert len(results) == 1

    def test_octet_stream_heuristic_negative(self):
        # Random binary — should not match
        exchanges = [
            HttpExchange(
                method="GET",
                url="https://api.example.com/image.png",
                request_headers={},
                request_body=None,
                status_code=200,
                response_headers={},
                response_body=b"\x89PNG\r\n\x1a\n",
                content_type="application/octet-stream",
            )
        ]

        results = extract_proto_exchanges(exchanges)
        assert len(results) == 0

    def test_no_proto_exchanges(self):
        exchanges = [
            HttpExchange(
                method="GET",
                url="https://example.com/api/users",
                request_headers={},
                request_body=None,
                status_code=200,
                response_headers={},
                response_body='{"name": "John"}',
                content_type="application/json",
            )
        ]

        results = extract_proto_exchanges(exchanges)
        assert len(results) == 0

    def test_grpc_service_method_extraction(self):
        proto_body = encode_varint_field(1, 1)
        framed = _make_grpc_frame(proto_body)

        exchanges = [
            HttpExchange(
                method="POST",
                url="https://api.example.com/com.example.GreeterService/SayHello",
                request_headers={"content-type": "application/grpc"},
                request_body=framed,
                status_code=200,
                response_headers={},
                response_body=None,
                content_type="",
            )
        ]

        results = extract_proto_exchanges(exchanges)
        assert len(results) == 1
        assert results[0].grpc_service == "com.example.GreeterService"
        assert results[0].grpc_method == "SayHello"


# ---------------------------------------------------------------------------
# Tests: schema inference
# ---------------------------------------------------------------------------


class TestSchemaInference:
    def _make_proto_exchange(
        self,
        url: str,
        req_fields: list | None = None,
        resp_fields: list | None = None,
        is_grpc: bool = False,
        grpc_service: str | None = None,
        grpc_method: str | None = None,
    ) -> ProtoExchange:
        req_msg = None
        if req_fields:
            req_msg = ProtoMessage(fields=req_fields, raw_bytes=b"")
        resp_msg = None
        if resp_fields:
            resp_msg = ProtoMessage(fields=resp_fields, raw_bytes=b"")
        return ProtoExchange(
            exchange_index=0,
            url=url,
            method="POST",
            content_type="application/grpc",
            request_proto=req_msg,
            response_proto=resp_msg,
            is_grpc=is_grpc,
            grpc_service=grpc_service,
            grpc_method=grpc_method,
        )

    def test_infer_from_single_exchange(self):
        fields = [
            ProtoField(field_number=1, wire_type=WireType.VARINT, value=42),
            ProtoField(
                field_number=2,
                wire_type=WireType.LENGTH_DELIMITED,
                value="hello",
                interpretation="string",
            ),
        ]
        exchanges = [
            self._make_proto_exchange(
                url="https://api.example.com/api/users",
                resp_fields=fields,
            )
        ]

        schema = infer_schema(exchanges)
        assert len(schema.messages) >= 1
        # Should have a response message
        resp_msg = None
        for name, msg in schema.messages.items():
            if "Response" in name:
                resp_msg = msg
                break
        assert resp_msg is not None
        assert 1 in resp_msg.fields
        assert 2 in resp_msg.fields
        assert resp_msg.fields[1].inferred_type == "int32"
        assert resp_msg.fields[2].inferred_type == "string"

    def test_infer_from_multiple_samples(self):
        fields1 = [
            ProtoField(field_number=1, wire_type=WireType.VARINT, value=1),
            ProtoField(
                field_number=2,
                wire_type=WireType.LENGTH_DELIMITED,
                value="Alice",
                interpretation="string",
            ),
        ]
        fields2 = [
            ProtoField(field_number=1, wire_type=WireType.VARINT, value=2),
            ProtoField(
                field_number=2,
                wire_type=WireType.LENGTH_DELIMITED,
                value="Bob",
                interpretation="string",
            ),
            ProtoField(field_number=3, wire_type=WireType.VARINT, value=30),
        ]

        exchanges = [
            self._make_proto_exchange(
                url="https://api.example.com/api/users",
                resp_fields=fields1,
            ),
            self._make_proto_exchange(
                url="https://api.example.com/api/users",
                resp_fields=fields2,
            ),
        ]

        schema = infer_schema(exchanges)
        resp_msg = None
        for name, msg in schema.messages.items():
            if "Response" in name:
                resp_msg = msg
                break
        assert resp_msg is not None
        assert resp_msg.source_count == 2
        # field_3 only appears once — should have lower occurrence_count
        assert resp_msg.fields[3].occurrence_count == 1

    def test_infer_bool_type(self):
        fields = [
            ProtoField(field_number=1, wire_type=WireType.VARINT, value=0),
        ]
        exchanges = [
            self._make_proto_exchange(
                url="https://api.example.com/api/check",
                resp_fields=fields,
            ),
            self._make_proto_exchange(
                url="https://api.example.com/api/check",
                resp_fields=[
                    ProtoField(field_number=1, wire_type=WireType.VARINT, value=1),
                ],
            ),
        ]

        schema = infer_schema(exchanges)
        resp_msg = None
        for name, msg in schema.messages.items():
            if "Response" in name:
                resp_msg = msg
                break
        assert resp_msg is not None
        assert resp_msg.fields[1].inferred_type == "bool"

    def test_infer_grpc_service(self):
        fields = [
            ProtoField(field_number=1, wire_type=WireType.VARINT, value=1),
        ]
        exchanges = [
            self._make_proto_exchange(
                url="https://api.example.com/com.example.Greeter/SayHello",
                resp_fields=fields,
                is_grpc=True,
                grpc_service="com.example.Greeter",
                grpc_method="SayHello",
            )
        ]

        schema = infer_schema(exchanges)
        assert "com.example.Greeter" in schema.services
        assert "SayHello" in schema.services["com.example.Greeter"]


# ---------------------------------------------------------------------------
# Tests: .proto file generation
# ---------------------------------------------------------------------------


class TestGenerateProtoFile:
    def test_basic_proto_generation(self):
        fields = [
            ProtoField(field_number=1, wire_type=WireType.VARINT, value=42),
            ProtoField(
                field_number=2,
                wire_type=WireType.LENGTH_DELIMITED,
                value="hello",
                interpretation="string",
            ),
        ]
        exchanges = [
            ProtoExchange(
                exchange_index=0,
                url="https://api.example.com/api/users",
                method="POST",
                content_type="application/grpc",
                request_proto=None,
                response_proto=ProtoMessage(fields=fields, raw_bytes=b""),
                is_grpc=False,
            )
        ]

        schema = infer_schema(exchanges)
        proto_content = generate_proto_file(schema)

        assert 'syntax = "proto3";' in proto_content
        assert "message" in proto_content
        assert "field_1" in proto_content
        assert "field_2" in proto_content
        assert "int32" in proto_content
        assert "string" in proto_content

    def test_proto_with_service(self):
        fields = [
            ProtoField(field_number=1, wire_type=WireType.VARINT, value=1),
        ]
        exchanges = [
            ProtoExchange(
                exchange_index=0,
                url="https://api.example.com/MyService/GetData",
                method="POST",
                content_type="application/grpc",
                request_proto=ProtoMessage(fields=fields, raw_bytes=b""),
                response_proto=ProtoMessage(fields=fields, raw_bytes=b""),
                is_grpc=True,
                grpc_service="MyService",
                grpc_method="GetData",
            )
        ]

        schema = infer_schema(exchanges)
        proto_content = generate_proto_file(schema)

        assert (
            "service Myservice" in proto_content or "service MyService" in proto_content
        )
        assert "rpc GetData" in proto_content


# ---------------------------------------------------------------------------
# Tests: format_decoded
# ---------------------------------------------------------------------------


class TestFormatDecoded:
    def test_format_varint(self):
        msg = ProtoMessage(
            fields=[
                ProtoField(field_number=1, wire_type=WireType.VARINT, value=42),
            ],
            raw_bytes=b"",
        )
        output = format_decoded(msg)
        assert "1:" in output
        assert "varint" in output
        assert "42" in output

    def test_format_string(self):
        msg = ProtoMessage(
            fields=[
                ProtoField(
                    field_number=2,
                    wire_type=WireType.LENGTH_DELIMITED,
                    value="hello",
                    interpretation="string",
                ),
            ],
            raw_bytes=b"",
        )
        output = format_decoded(msg)
        assert "2:" in output
        assert "string" in output
        assert '"hello"' in output

    def test_format_nested(self):
        inner_msg = ProtoMessage(
            fields=[
                ProtoField(field_number=1, wire_type=WireType.VARINT, value=99),
            ],
            raw_bytes=b"",
        )
        msg = ProtoMessage(
            fields=[
                ProtoField(
                    field_number=3,
                    wire_type=WireType.LENGTH_DELIMITED,
                    value=inner_msg,
                    interpretation="embedded_message",
                ),
            ],
            raw_bytes=b"",
        )
        output = format_decoded(msg)
        assert "3:" in output
        assert "message" in output
        assert "99" in output

    def test_format_bytes(self):
        msg = ProtoMessage(
            fields=[
                ProtoField(
                    field_number=4,
                    wire_type=WireType.LENGTH_DELIMITED,
                    value=b"\x0a\x0b\x0c",
                    interpretation="bytes",
                ),
            ],
            raw_bytes=b"",
        )
        output = format_decoded(msg)
        assert "4:" in output
        assert "bytes" in output
        assert "3 bytes" in output

    def test_format_with_indent(self):
        msg = ProtoMessage(
            fields=[
                ProtoField(field_number=1, wire_type=WireType.VARINT, value=1),
            ],
            raw_bytes=b"",
        )
        output = format_decoded(msg, indent=2)
        assert output.startswith("    ")  # 2 levels of indent (2 spaces each)


# ---------------------------------------------------------------------------
# Tests: Python client generation
# ---------------------------------------------------------------------------


class TestGeneratePythonClient:
    def test_basic_client_generation(self):
        fields = [
            ProtoField(field_number=1, wire_type=WireType.VARINT, value=1),
            ProtoField(
                field_number=2,
                wire_type=WireType.LENGTH_DELIMITED,
                value="test",
                interpretation="string",
            ),
        ]
        exchanges = [
            ProtoExchange(
                exchange_index=0,
                url="https://api.example.com/MyService/DoStuff",
                method="POST",
                content_type="application/grpc",
                request_proto=ProtoMessage(fields=fields, raw_bytes=b""),
                response_proto=ProtoMessage(fields=fields, raw_bytes=b""),
                is_grpc=True,
                grpc_service="MyService",
                grpc_method="DoStuff",
            )
        ]

        schema = infer_schema(exchanges)
        code = generate_python_client(schema)

        assert "@dataclass" in code
        assert "class DoStuffRequest" in code or "class DoStuffResponse" in code
        assert "field_1" in code
        assert "field_2" in code
