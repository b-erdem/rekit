"""protorev.decoder — Decode raw protobuf binary data without a schema."""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


class WireType(IntEnum):
    """Protobuf wire types."""

    VARINT = 0
    FIXED64 = 1
    LENGTH_DELIMITED = 2
    START_GROUP = 3
    END_GROUP = 4
    FIXED32 = 5


@dataclass
class ProtoField:
    """A single decoded protobuf field."""

    field_number: int
    wire_type: WireType
    value: Any  # int for varint, bytes for length-delimited, float for fixed
    interpretation: Optional[str] = None  # "string", "embedded_message", etc.


@dataclass
class ProtoMessage:
    """A decoded protobuf message containing a list of fields."""

    fields: List[ProtoField] = field(default_factory=list)
    raw_bytes: bytes = b""


def decode_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode a varint from data starting at offset.

    Returns:
        Tuple of (decoded value, new offset after varint).

    Raises:
        ValueError: If the varint is malformed or truncated.
    """
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if (byte & 0x80) == 0:
            return result, offset
        shift += 7
        if shift >= 64:
            raise ValueError("Varint too long (>10 bytes)")
    raise ValueError("Truncated varint")


def decode_zigzag(n: int) -> int:
    """Decode a ZigZag-encoded signed integer."""
    return (n >> 1) ^ -(n & 1)


def decode_protobuf(data: bytes) -> ProtoMessage:
    """Decode raw protobuf binary data without a schema.

    Parses varint-encoded field tags and reads values based on wire type.
    For length-delimited fields, attempts interpretation as UTF-8 string,
    nested protobuf message, packed repeated varints, or raw bytes.

    Args:
        data: Raw protobuf bytes.

    Returns:
        ProtoMessage with decoded fields.
    """
    msg = ProtoMessage(fields=[], raw_bytes=data)
    offset = 0

    while offset < len(data):
        try:
            tag, offset = decode_varint(data, offset)
        except ValueError:
            logger.warning("Failed to decode field tag at offset %d, stopping", offset)
            break

        field_number = tag >> 3
        wire_type_val = tag & 0x07

        if field_number == 0:
            logger.warning("Invalid field number 0 at offset %d, stopping", offset)
            break

        try:
            wire_type = WireType(wire_type_val)
        except ValueError:
            logger.warning(
                "Unknown wire type %d for field %d, stopping",
                wire_type_val,
                field_number,
            )
            break

        try:
            proto_field, offset = _decode_field_value(
                data, offset, field_number, wire_type
            )
            msg.fields.append(proto_field)
        except (ValueError, struct.error) as exc:
            logger.warning(
                "Failed to decode field %d (wire type %d) at offset %d: %s",
                field_number,
                wire_type_val,
                offset,
                exc,
            )
            break

    return msg


def _decode_field_value(
    data: bytes, offset: int, field_number: int, wire_type: WireType
) -> Tuple[ProtoField, int]:
    """Decode a single field value based on wire type."""
    if wire_type == WireType.VARINT:
        value, offset = decode_varint(data, offset)
        return ProtoField(
            field_number=field_number, wire_type=wire_type, value=value
        ), offset

    elif wire_type == WireType.FIXED64:
        if offset + 8 > len(data):
            raise ValueError("Truncated fixed64")
        raw = data[offset : offset + 8]
        offset += 8
        uint64_val = struct.unpack("<Q", raw)[0]
        double_val = struct.unpack("<d", raw)[0]
        # Use double if it looks like a reasonable float, otherwise uint64
        if _is_plausible_double(double_val):
            return ProtoField(
                field_number=field_number,
                wire_type=wire_type,
                value=double_val,
                interpretation="double",
            ), offset
        return ProtoField(
            field_number=field_number,
            wire_type=wire_type,
            value=uint64_val,
            interpretation="uint64",
        ), offset

    elif wire_type == WireType.LENGTH_DELIMITED:
        length, offset = decode_varint(data, offset)
        if offset + length > len(data):
            raise ValueError(
                f"Length-delimited field extends past end of data "
                f"(need {length} bytes, have {len(data) - offset})"
            )
        payload = data[offset : offset + length]
        offset += length
        interpretation, value = _interpret_length_delimited(payload)
        return ProtoField(
            field_number=field_number,
            wire_type=wire_type,
            value=value,
            interpretation=interpretation,
        ), offset

    elif wire_type == WireType.FIXED32:
        if offset + 4 > len(data):
            raise ValueError("Truncated fixed32")
        raw = data[offset : offset + 4]
        offset += 4
        uint32_val = struct.unpack("<I", raw)[0]
        float_val = struct.unpack("<f", raw)[0]
        if _is_plausible_float(float_val):
            return ProtoField(
                field_number=field_number,
                wire_type=wire_type,
                value=float_val,
                interpretation="float",
            ), offset
        return ProtoField(
            field_number=field_number,
            wire_type=wire_type,
            value=uint32_val,
            interpretation="uint32",
        ), offset

    elif wire_type in (WireType.START_GROUP, WireType.END_GROUP):
        # Deprecated group wire types — skip
        return ProtoField(
            field_number=field_number, wire_type=wire_type, value=None
        ), offset

    else:
        raise ValueError(f"Unhandled wire type: {wire_type}")


def _interpret_length_delimited(payload: bytes) -> Tuple[str, Any]:
    """Try to interpret a length-delimited payload.

    Tries in order: UTF-8 string, nested protobuf, packed repeated varints,
    raw bytes.
    """
    # Try UTF-8 string
    try:
        text = payload.decode("utf-8")
        if _is_printable_string(text):
            return "string", text
    except UnicodeDecodeError:
        pass

    # Try nested protobuf message
    if len(payload) > 0:
        try:
            nested = decode_protobuf(payload)
            if len(nested.fields) >= 1 and _all_bytes_consumed(payload, nested):
                return "embedded_message", nested
        except Exception:
            pass

    # Try packed repeated varints
    if len(payload) > 0:
        packed = _try_packed_varints(payload)
        if packed is not None:
            return "packed_repeated", packed

    # Try UTF-8 string (lenient — accept even if not all printable)
    try:
        text = payload.decode("utf-8")
        return "utf8_string", text
    except UnicodeDecodeError:
        pass

    return "bytes", payload


def _try_packed_varints(payload: bytes) -> Optional[List[int]]:
    """Try to decode payload as packed repeated varints."""
    values = []
    offset = 0
    while offset < len(payload):
        try:
            val, offset = decode_varint(payload, offset)
            values.append(val)
        except ValueError:
            return None
    if len(values) >= 2:
        return values
    return None


def _all_bytes_consumed(payload: bytes, msg: ProtoMessage) -> bool:
    """Check if the nested decode consumed the payload plausibly."""
    # Re-encode isn't practical, so heuristic: at least one field decoded
    # and no field has a suspicious field number
    for f in msg.fields:
        if f.field_number > 1000:
            return False
    return True


def _is_printable_string(text: str) -> bool:
    """Check if a string looks like human-readable text."""
    if not text:
        return False
    printable_count = sum(1 for c in text if c.isprintable() or c in ("\n", "\r", "\t"))
    return printable_count / len(text) > 0.9


def _is_plausible_float(val: float) -> bool:
    """Check if a float32 value looks like an intentional float."""
    import math

    if math.isnan(val) or math.isinf(val):
        return False
    if val == 0.0:
        return True
    # Very large or very small values are probably not floats
    abs_val = abs(val)
    return 1e-10 < abs_val < 1e10


def _is_plausible_double(val: float) -> bool:
    """Check if a float64 value looks like an intentional double."""
    import math

    if math.isnan(val) or math.isinf(val):
        return False
    if val == 0.0:
        return True
    abs_val = abs(val)
    return 1e-20 < abs_val < 1e20


def format_decoded(msg: ProtoMessage, indent: int = 0) -> str:
    """Pretty-print a decoded protobuf message as a tree structure.

    Example output:
        1: (varint) 12345
        2: (string) "Hello World"
        3: (message)
          1: (varint) 42
          2: (string) "nested"
        4: (bytes) [10 bytes] 0a0b0c...
    """
    lines = []
    prefix = "  " * indent

    for f in msg.fields:
        if f.wire_type == WireType.VARINT:
            zigzag = decode_zigzag(f.value)
            if zigzag != f.value and zigzag < 0:
                lines.append(
                    f"{prefix}{f.field_number}: (varint) {f.value} (zigzag: {zigzag})"
                )
            else:
                lines.append(f"{prefix}{f.field_number}: (varint) {f.value}")

        elif f.interpretation == "string":
            lines.append(f'{prefix}{f.field_number}: (string) "{f.value}"')

        elif f.interpretation == "utf8_string":
            lines.append(f'{prefix}{f.field_number}: (utf8_string) "{f.value}"')

        elif f.interpretation == "embedded_message":
            lines.append(f"{prefix}{f.field_number}: (message)")
            lines.append(format_decoded(f.value, indent + 1))

        elif f.interpretation == "packed_repeated":
            lines.append(
                f"{prefix}{f.field_number}: (packed) [{', '.join(str(v) for v in f.value)}]"
            )

        elif f.interpretation == "bytes":
            data = f.value
            hex_preview = data[:16].hex()
            lines.append(
                f"{prefix}{f.field_number}: (bytes) [{len(data)} bytes] {hex_preview}"
            )

        elif f.interpretation in ("float", "uint32"):
            lines.append(f"{prefix}{f.field_number}: ({f.interpretation}) {f.value}")

        elif f.interpretation in ("double", "uint64"):
            lines.append(f"{prefix}{f.field_number}: ({f.interpretation}) {f.value}")

        elif f.wire_type in (WireType.START_GROUP, WireType.END_GROUP):
            lines.append(f"{prefix}{f.field_number}: (group)")

        else:
            lines.append(f"{prefix}{f.field_number}: (unknown) {f.value!r}")

    return "\n".join(lines)
