"""protorev.extractor — Extract protobuf exchanges from HAR traffic."""

from __future__ import annotations

import base64
import logging
import struct
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

from rekit.hargen.parser import HttpExchange
from rekit.protorev.decoder import ProtoMessage, decode_protobuf

logger = logging.getLogger(__name__)

# Content types that indicate protobuf/gRPC payloads
PROTO_CONTENT_TYPES = {
    "application/grpc",
    "application/grpc-web",
    "application/grpc-web+proto",
    "application/grpc-web-text",
    "application/grpc-web-text+proto",
    "application/x-protobuf",
    "application/protobuf",
    "application/x-google-protobuf",
    "application/vnd.google.protobuf",
}


@dataclass
class ProtoExchange:
    """A protobuf-bearing HTTP exchange extracted from traffic."""

    exchange_index: int
    url: str
    method: str
    content_type: str
    request_proto: Optional[ProtoMessage] = None
    response_proto: Optional[ProtoMessage] = None
    is_grpc: bool = False
    grpc_service: Optional[str] = None
    grpc_method: Optional[str] = None


def extract_proto_exchanges(
    exchanges: List[HttpExchange],
) -> List[ProtoExchange]:
    """Scan HAR exchanges for protobuf content and decode them.

    Identifies exchanges with protobuf/gRPC content types, strips gRPC
    framing when present, and decodes the protobuf payloads.

    For application/octet-stream, uses a heuristic: attempts protobuf
    decoding and accepts if >=2 valid fields are found.

    Args:
        exchanges: List of HttpExchange objects from HAR parsing.

    Returns:
        List of ProtoExchange objects with decoded protobuf messages.
    """
    results: List[ProtoExchange] = []

    for i, ex in enumerate(exchanges):
        req_ct = (
            ex.request_headers.get("content-type", "").lower().split(";")[0].strip()
        )
        resp_ct = (
            ex.content_type.lower().split(";")[0].strip() if ex.content_type else ""
        )

        is_proto_request = _is_proto_content_type(req_ct)
        is_proto_response = _is_proto_content_type(resp_ct)

        # Heuristic for octet-stream
        if not is_proto_request and req_ct == "application/octet-stream":
            is_proto_request = _heuristic_proto_check(_body_to_bytes(ex.request_body))
        if not is_proto_response and resp_ct == "application/octet-stream":
            is_proto_response = _heuristic_proto_check(_body_to_bytes(ex.response_body))

        if not is_proto_request and not is_proto_response:
            continue

        is_grpc = _is_grpc_content_type(req_ct) or _is_grpc_content_type(resp_ct)
        grpc_service, grpc_method = (
            _extract_grpc_info(ex.url) if is_grpc else (None, None)
        )

        request_proto = None
        if is_proto_request and ex.request_body:
            request_proto = _decode_body(ex.request_body, is_grpc, req_ct)

        response_proto = None
        if is_proto_response and ex.response_body:
            response_proto = _decode_body(ex.response_body, is_grpc, resp_ct)

        results.append(
            ProtoExchange(
                exchange_index=i,
                url=ex.url,
                method=ex.method,
                content_type=resp_ct or req_ct,
                request_proto=request_proto,
                response_proto=response_proto,
                is_grpc=is_grpc,
                grpc_service=grpc_service,
                grpc_method=grpc_method,
            )
        )

    return results


def _is_proto_content_type(ct: str) -> bool:
    """Check if a content type indicates protobuf."""
    return ct in PROTO_CONTENT_TYPES


def _is_grpc_content_type(ct: str) -> bool:
    """Check if a content type indicates gRPC."""
    return ct.startswith("application/grpc")


def _extract_grpc_info(url: str) -> tuple:
    """Extract gRPC service and method from URL path.

    gRPC paths follow the pattern: /package.Service/Method
    """
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    parts = path.rsplit("/", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, None


def _body_to_bytes(body) -> bytes:
    """Convert a request/response body to bytes."""
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        # Try base64 first (HAR often base64-encodes binary)
        try:
            decoded = base64.b64decode(body, validate=True)
            # Check if this was actually base64
            if base64.b64encode(decoded).decode("ascii") == body:
                return decoded
        except Exception:
            pass
        return body.encode("utf-8", errors="replace")
    return b""


def _strip_grpc_frame(data: bytes) -> bytes:
    """Strip the 5-byte gRPC frame prefix.

    The frame consists of:
      - 1 byte: compressed flag (0 or 1)
      - 4 bytes: message length (big-endian uint32)
    """
    if len(data) < 5:
        return data
    compressed_flag = data[0]
    if compressed_flag > 1:
        # Not a valid gRPC frame
        return data
    msg_length = struct.unpack(">I", data[1:5])[0]
    if 5 + msg_length <= len(data):
        return data[5 : 5 + msg_length]
    # Length doesn't match — return without stripping
    return data


def _decode_body(body, is_grpc: bool, content_type: str) -> Optional[ProtoMessage]:
    """Decode a request/response body as protobuf."""
    data = _body_to_bytes(body)
    if not data:
        return None

    # Handle grpc-web-text (base64-encoded)
    if "grpc-web-text" in content_type:
        try:
            data = base64.b64decode(data)
        except Exception:
            pass

    if is_grpc:
        data = _strip_grpc_frame(data)

    try:
        msg = decode_protobuf(data)
        if msg.fields:
            return msg
    except Exception as exc:
        logger.warning("Failed to decode protobuf body: %s", exc)

    return None


def _heuristic_proto_check(data: bytes) -> bool:
    """Heuristic check: try to decode as protobuf, accept if >=2 valid fields."""
    if not data or len(data) < 2:
        return False
    try:
        msg = decode_protobuf(data)
        return len(msg.fields) >= 2
    except Exception:
        return False
