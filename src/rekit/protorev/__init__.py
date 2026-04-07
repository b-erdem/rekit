"""
protorev — Reverse engineer Protobuf/gRPC from captured traffic and binaries.

Decodes raw protobuf binary data without schemas, extracts protobuf exchanges
from HAR traffic, and infers .proto schema definitions from observed messages.
"""

from rekit.protorev.decoder import (
    ProtoField,
    ProtoMessage,
    WireType,
    decode_protobuf,
    decode_varint,
    decode_zigzag,
    format_decoded,
)
from rekit.protorev.extractor import ProtoExchange, extract_proto_exchanges
from rekit.protorev.schema import (
    InferredField,
    InferredMessage,
    InferredSchema,
    generate_proto_file,
    generate_python_client,
    infer_schema,
)

__all__ = [
    "WireType",
    "ProtoField",
    "ProtoMessage",
    "decode_protobuf",
    "decode_varint",
    "decode_zigzag",
    "format_decoded",
    "ProtoExchange",
    "extract_proto_exchanges",
    "InferredField",
    "InferredMessage",
    "InferredSchema",
    "infer_schema",
    "generate_proto_file",
    "generate_python_client",
]
