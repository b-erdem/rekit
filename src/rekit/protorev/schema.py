"""protorev.schema — Infer .proto schema from decoded protobuf messages."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from rekit.protorev.decoder import ProtoMessage, WireType
from rekit.protorev.extractor import ProtoExchange


@dataclass
class InferredField:
    """An inferred protobuf field definition."""

    field_number: int
    name: str  # auto-generated like "field_1"
    inferred_type: str  # "int32", "int64", "string", "bytes", etc.
    sub_message: Optional[InferredMessage] = None
    examples: List[Any] = field(default_factory=list)
    occurrence_count: int = 0


@dataclass
class InferredMessage:
    """An inferred protobuf message definition."""

    name: str
    fields: Dict[int, InferredField] = field(default_factory=dict)
    source_count: int = 0


@dataclass
class InferredSchema:
    """An inferred protobuf schema with messages and services."""

    messages: Dict[str, InferredMessage] = field(default_factory=dict)
    services: Dict[str, List[str]] = field(default_factory=dict)


def infer_schema(exchanges: List[ProtoExchange]) -> InferredSchema:
    """Infer a protobuf schema from decoded proto exchanges.

    Groups exchanges by URL path (each unique path is likely a different
    message type), merges field observations, and infers types.

    Args:
        exchanges: Decoded proto exchanges.

    Returns:
        InferredSchema with messages and service definitions.
    """
    schema = InferredSchema()

    # Group exchanges by URL path
    groups: Dict[str, List[ProtoExchange]] = {}
    for ex in exchanges:
        parsed = urlparse(ex.url)
        path = parsed.path.strip("/")
        groups.setdefault(path, []).append(ex)

    for path, group in groups.items():
        # Determine message names
        req_name, resp_name = _message_names_from_path(path, group)

        # Collect request and response messages
        req_messages = [ex.request_proto for ex in group if ex.request_proto]
        resp_messages = [ex.response_proto for ex in group if ex.response_proto]

        if req_messages:
            schema.messages[req_name] = _infer_message(req_name, req_messages)
        if resp_messages:
            schema.messages[resp_name] = _infer_message(resp_name, resp_messages)

        # Track gRPC services
        for ex in group:
            if ex.is_grpc and ex.grpc_service and ex.grpc_method:
                service_methods = schema.services.setdefault(ex.grpc_service, [])
                if ex.grpc_method not in service_methods:
                    service_methods.append(ex.grpc_method)

    return schema


def _message_names_from_path(path: str, group: List[ProtoExchange]) -> tuple:
    """Generate message names from URL path or gRPC method."""
    # Use gRPC method name if available
    sample = group[0]
    if sample.grpc_method:
        method = sample.grpc_method
        return f"{method}Request", f"{method}Response"

    # Fall back to path segments
    segments = [s for s in path.split("/") if s and not s.isdigit()]
    if segments:
        name = _to_pascal_case(segments[-1])
        return f"{name}Request", f"{name}Response"

    return "UnknownRequest", "UnknownResponse"


def _to_pascal_case(s: str) -> str:
    """Convert a string to PascalCase."""
    # Remove non-alphanumeric, split on separators
    parts = re.split(r"[-_./]+", s)
    return "".join(p.capitalize() for p in parts if p)


def _infer_message(name: str, messages: List[ProtoMessage]) -> InferredMessage:
    """Infer a message definition from multiple decoded samples."""
    inferred = InferredMessage(name=name, source_count=len(messages))

    for msg in messages:
        for f in msg.fields:
            if f.field_number not in inferred.fields:
                inferred.fields[f.field_number] = InferredField(
                    field_number=f.field_number,
                    name=f"field_{f.field_number}",
                    inferred_type="unknown",
                )

            inf_field = inferred.fields[f.field_number]
            inf_field.occurrence_count += 1

            # Track examples (keep up to 5)
            example_val = f.value
            if isinstance(example_val, ProtoMessage):
                example_val = "<message>"
            if len(inf_field.examples) < 5 and example_val not in inf_field.examples:
                inf_field.examples.append(example_val)

            # Infer type
            inf_field.inferred_type = _infer_field_type(f, inf_field)

            # Infer nested message
            if f.interpretation == "embedded_message" and isinstance(
                f.value, ProtoMessage
            ):
                sub_name = f"{name}_{f.field_number}"
                inf_field.sub_message = _infer_message(sub_name, [f.value])

    return inferred


def _infer_field_type(f, inf_field: InferredField) -> str:
    """Infer the protobuf type for a field."""
    if f.wire_type == WireType.VARINT:
        # Check if it's a bool
        all_bool = all(ex in (0, 1, True, False) for ex in inf_field.examples)
        if all_bool and inf_field.examples:
            return "bool"
        # Check value range for int32 vs int64
        max_val = max(
            (ex for ex in inf_field.examples if isinstance(ex, int)), default=0
        )
        if max_val > 2**31 - 1:
            return "int64"
        return "int32"

    elif f.wire_type == WireType.FIXED32:
        if f.interpretation == "float":
            return "float"
        return "fixed32"

    elif f.wire_type == WireType.FIXED64:
        if f.interpretation == "double":
            return "double"
        return "fixed64"

    elif f.wire_type == WireType.LENGTH_DELIMITED:
        if f.interpretation == "string":
            return "string"
        if f.interpretation == "utf8_string":
            return "string"
        if f.interpretation == "embedded_message":
            return "message"
        if f.interpretation == "packed_repeated":
            return "repeated int32"
        return "bytes"

    return "unknown"


def generate_proto_file(schema: InferredSchema) -> str:
    """Generate a .proto file from an inferred schema.

    Args:
        schema: The inferred schema.

    Returns:
        A string containing the .proto file content.
    """
    lines = ['syntax = "proto3";', "", "package inferred;", ""]

    # Generate messages
    for msg_name, msg in sorted(schema.messages.items()):
        lines.extend(_generate_message_lines(msg, indent=0))
        lines.append("")

    # Generate services
    for service_name, methods in sorted(schema.services.items()):
        safe_service = _to_pascal_case(service_name)
        lines.append(f"service {safe_service} {{")
        for method in methods:
            req_name = f"{method}Request"
            resp_name = f"{method}Response"
            lines.append(f"  rpc {method}({req_name}) returns ({resp_name});")
        lines.append("}")
        lines.append("")

    return "\n".join(lines)


def _generate_message_lines(msg: InferredMessage, indent: int) -> List[str]:
    """Generate .proto message lines."""
    prefix = "  " * indent
    lines = [f"{prefix}message {msg.name} {{"]

    # Nested messages first
    nested_names: Dict[int, str] = {}
    for fnum, f in sorted(msg.fields.items()):
        if f.sub_message:
            lines.extend(_generate_message_lines(f.sub_message, indent + 1))
            nested_names[fnum] = f.sub_message.name

    # Fields
    for fnum, f in sorted(msg.fields.items()):
        ftype = f.inferred_type
        if ftype == "message" and fnum in nested_names:
            ftype = nested_names[fnum]

        optional = ""
        if f.occurrence_count < msg.source_count:
            optional = "optional "

        # Format examples as comment
        examples_str = ""
        if f.examples:
            example_strs = []
            for ex in f.examples[:3]:
                if isinstance(ex, str):
                    example_strs.append(f'"{ex}"')
                elif isinstance(ex, bytes):
                    example_strs.append(f"<{len(ex)} bytes>")
                else:
                    example_strs.append(str(ex))
            examples_str = f"  // examples: {', '.join(example_strs)}"

        repeated_prefix = ""
        actual_type = ftype
        if ftype.startswith("repeated "):
            repeated_prefix = "repeated "
            actual_type = ftype[len("repeated ") :]
            optional = ""  # repeated fields can't be optional in proto3

        lines.append(
            f"{prefix}  {optional}{repeated_prefix}{actual_type} "
            f"{f.name} = {fnum};{examples_str}"
        )

    lines.append(f"{prefix}}}")
    return lines


def generate_python_client(schema: InferredSchema) -> str:
    """Generate a Python client stub from an inferred schema.

    Uses dataclass-style message definitions and a simple gRPC stub pattern.

    Args:
        schema: The inferred schema.

    Returns:
        A string containing the Python client code.
    """
    lines = [
        '"""Auto-generated protobuf client from inferred schema."""',
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass, field",
        "from typing import List, Optional",
        "",
        "",
    ]

    # Generate dataclasses for messages
    for msg_name, msg in sorted(schema.messages.items()):
        lines.append("@dataclass")
        lines.append(f"class {msg_name}:")
        lines.append(f'    """Inferred from {msg.source_count} sample(s)."""')
        lines.append("")

        if not msg.fields:
            lines.append("    pass")
        else:
            for fnum, f in sorted(msg.fields.items()):
                py_type = _proto_type_to_python(f.inferred_type)
                if f.occurrence_count < msg.source_count:
                    lines.append(f"    {f.name}: Optional[{py_type}] = None")
                elif f.inferred_type.startswith("repeated"):
                    lines.append(
                        f"    {f.name}: List[{py_type}] = field(default_factory=list)"
                    )
                else:
                    default = _python_default(f.inferred_type)
                    lines.append(f"    {f.name}: {py_type} = {default}")

        lines.append("")
        lines.append("")

    # Generate service stubs
    for service_name, methods in sorted(schema.services.items()):
        safe_service = _to_pascal_case(service_name)
        lines.append(f"class {safe_service}Client:")
        lines.append(f'    """gRPC client stub for {service_name}."""')
        lines.append("")
        lines.append("    def __init__(self, channel):")
        lines.append("        self.channel = channel")
        lines.append("")

        for method in methods:
            req_name = f"{method}Request"
            resp_name = f"{method}Response"
            lines.append(
                f"    def {_to_snake_case(method)}("
                f"self, request: {req_name}) -> {resp_name}:"
            )
            lines.append(f'        """Call {service_name}/{method}."""')
            lines.append(
                f'        raise NotImplementedError("Stub: implement {method}")'
            )
            lines.append("")

        lines.append("")

    return "\n".join(lines)


def _proto_type_to_python(proto_type: str) -> str:
    """Map a proto type to a Python type."""
    mapping = {
        "int32": "int",
        "int64": "int",
        "uint32": "int",
        "uint64": "int",
        "sint32": "int",
        "sint64": "int",
        "fixed32": "int",
        "fixed64": "int",
        "sfixed32": "int",
        "sfixed64": "int",
        "float": "float",
        "double": "float",
        "bool": "bool",
        "string": "str",
        "bytes": "bytes",
        "message": "dict",
        "unknown": "object",
    }
    if proto_type.startswith("repeated "):
        inner = proto_type[len("repeated ") :]
        return mapping.get(inner, "object")
    return mapping.get(proto_type, "object")


def _python_default(proto_type: str) -> str:
    """Get a Python default value for a proto type."""
    defaults = {
        "int32": "0",
        "int64": "0",
        "uint32": "0",
        "uint64": "0",
        "float": "0.0",
        "double": "0.0",
        "bool": "False",
        "string": '""',
        "bytes": 'b""',
        "message": "None",
    }
    return defaults.get(proto_type, "None")


def _to_snake_case(s: str) -> str:
    """Convert a string to snake_case."""
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower().replace("-", "_").replace(".", "_")
