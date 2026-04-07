"""
schemadiff.generator — Generate unified Python dataclass code and mapping tables.

Produces production-ready Python source code from a :class:`ComparisonResult`,
including typed dataclass fields, per-source ``from_<source>()`` classmethods,
and human-readable mapping tables.
"""

from __future__ import annotations

import keyword
import re
import textwrap
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from rekit.schemadiff.analyzer import (
    ComparisonResult,
    FieldMapping,
    MergedField,
)


# ---------------------------------------------------------------------------
# Python identifier helpers
# ---------------------------------------------------------------------------

_INVALID_IDENT_RE = re.compile(r"[^a-zA-Z0-9_]")


def _to_python_ident(name: str) -> str:
    """Convert a JSON field name to a valid Python identifier."""
    # camelCase -> snake_case
    ident = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    ident = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", ident)
    ident = ident.lower()
    # Replace invalid chars with underscore
    ident = _INVALID_IDENT_RE.sub("_", ident)
    # Collapse multiple underscores
    ident = re.sub(r"_+", "_", ident).strip("_")
    # Ensure it doesn't start with a digit
    if ident and ident[0].isdigit():
        ident = f"f_{ident}"
    # Avoid Python keywords
    if keyword.iskeyword(ident) or ident in ("type", "id", "list", "dict", "set", "hash"):
        ident = f"{ident}_"
    if not ident:
        ident = "field_"
    return ident


def _to_class_name(name: str) -> str:
    """Convert a string to a PascalCase class name."""
    parts = re.split(r"[^a-zA-Z0-9]+", name)
    return "".join(p.capitalize() for p in parts if p) or "Model"


def _python_type_annotation(suggested: str, has_null: bool) -> str:
    """Return a Python type annotation string, adding Optional if needed."""
    if suggested == "None":
        return "Optional[Any]"
    if has_null:
        return f"Optional[{suggested}]"
    return suggested


# ---------------------------------------------------------------------------
# Python dataclass generation
# ---------------------------------------------------------------------------

def generate_python(
    comparison: ComparisonResult,
    class_name: str = "UnifiedModel",
) -> str:
    """Generate a Python dataclass from a :class:`ComparisonResult`.

    The generated class includes:
      - Universal fields as required (no default value).
      - Common fields as ``Optional`` with ``None`` default.
      - An ``extras: Dict[str, Any]`` field for source-specific data.
      - A ``raw: Dict[str, Any]`` field for the original response.
      - ``from_<source>()`` classmethods for each source.
      - Comments showing which sources provide each field.

    Parameters:
        comparison: The comparison result to generate code from.
        class_name: Name for the generated dataclass.

    Returns:
        A string of valid Python source code.
    """
    lines: List[str] = []

    # Header
    lines.append('"""')
    lines.append(f"Auto-generated unified model from schemadiff.")
    lines.append(f"Sources: {', '.join(comparison.labels)}")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from dataclasses import dataclass, field")
    lines.append("from typing import Any, Dict, List, Optional")
    lines.append("")
    lines.append("")

    # Build field info: (python_name, annotation, default, comment, is_required)
    field_specs: List[_FieldSpec] = []
    used_names: Set[str] = set()

    # Universal fields first (required, no default)
    for name, mf in sorted(comparison.universal_fields.items()):
        py_name = _unique_name(_to_python_ident(name), used_names)
        has_null = "null" in mf.types_seen
        annotation = _python_type_annotation(mf.suggested_type, has_null)
        comment = f"All sources: {', '.join(mf.sources_present)}"
        if mf.types_seen - {"null"}:
            comment += f"  [types: {', '.join(sorted(mf.types_seen - {'null'}))}]"
        field_specs.append(_FieldSpec(
            py_name=py_name,
            json_name=name,
            annotation=annotation,
            default=None,
            comment=comment,
            required=not has_null,
        ))

    # Common fields (optional with None default)
    for name, mf in sorted(comparison.common_fields.items()):
        py_name = _unique_name(_to_python_ident(name), used_names)
        annotation = f"Optional[{mf.suggested_type}]"
        present = ", ".join(mf.sources_present)
        missing = ", ".join(mf.sources_missing)
        comment = f"Present: {present} | Missing: {missing}"
        field_specs.append(_FieldSpec(
            py_name=py_name,
            json_name=name,
            annotation=annotation,
            default="None",
            comment=comment,
            required=False,
        ))

    # Unique fields — still include them as optional
    unique_flat: Dict[str, MergedField] = {}
    for src_fields in comparison.unique_fields.values():
        for name, mf in src_fields.items():
            if name not in unique_flat:
                unique_flat[name] = mf
    for name, mf in sorted(unique_flat.items()):
        py_name = _unique_name(_to_python_ident(name), used_names)
        annotation = f"Optional[{mf.suggested_type}]"
        comment = f"Only: {', '.join(mf.sources_present)}"
        field_specs.append(_FieldSpec(
            py_name=py_name,
            json_name=name,
            annotation=annotation,
            default="None",
            comment=comment,
            required=False,
        ))

    # Write the dataclass
    lines.append("@dataclass")
    lines.append(f"class {class_name}:")
    lines.append(f'    """Unified model merging {len(comparison.labels)} API sources.')
    lines.append("")
    lines.append(f"    Sources: {', '.join(comparison.labels)}")
    lines.append(f"    Total fields: {comparison.stats.get('total_fields', '?')}")
    lines.append(f"    Universal: {comparison.stats.get('universal_count', '?')}")
    lines.append(f"    Type conflicts: {comparison.stats.get('type_conflict_count', '?')}")
    lines.append('    """')
    lines.append("")

    # Required fields first (no default)
    required_specs = [f for f in field_specs if f.required]
    optional_specs = [f for f in field_specs if not f.required]

    for spec in required_specs:
        lines.append(f"    # {spec.comment}")
        lines.append(f"    {spec.py_name}: {spec.annotation}")
        lines.append("")

    for spec in optional_specs:
        lines.append(f"    # {spec.comment}")
        lines.append(f"    {spec.py_name}: {spec.annotation} = {spec.default}")
        lines.append("")

    # extras and raw
    lines.append("    # Source-specific fields not in the unified schema")
    lines.append('    extras: Dict[str, Any] = field(default_factory=dict)')
    lines.append("")
    lines.append("    # Original API response")
    lines.append('    raw: Dict[str, Any] = field(default_factory=dict)')
    lines.append("")

    # Build reverse mapping: source_label -> {source_field: unified_field}
    source_maps: Dict[str, Dict[str, str]] = defaultdict(dict)
    for m in comparison.suggested_mapping:
        source_maps[m.source_label][m.source_field] = m.unified_field

    # Build json_name -> py_name lookup
    json_to_py: Dict[str, str] = {}
    for spec in field_specs:
        json_to_py[spec.json_name] = spec.py_name

    # from_<source> classmethods
    for label in comparison.labels:
        safe_label = _to_python_ident(label)
        src_map = source_maps.get(label, {})

        lines.append("    @classmethod")
        lines.append(f"    def from_{safe_label}(cls, data: Dict[str, Any]) -> \"{class_name}\":")
        lines.append(f'        """Create {class_name} from a {label} API response."""')
        lines.append("        kwargs: Dict[str, Any] = {}")
        lines.append("        extras: Dict[str, Any] = {}")
        lines.append("        known_keys: set = set()")
        lines.append("")

        # Map each source field to the unified field
        mapped_fields: Dict[str, str] = {}  # json source field -> python field name
        for src_field, unified_field in sorted(src_map.items()):
            py_name = json_to_py.get(unified_field, _to_python_ident(unified_field))
            mapped_fields[src_field] = py_name

        for src_field, py_name in sorted(mapped_fields.items()):
            lines.append(f'        if "{src_field}" in data:')
            lines.append(f'            kwargs["{py_name}"] = data["{src_field}"]')
            lines.append(f'            known_keys.add("{src_field}")')
        lines.append("")

        # Collect unmapped keys into extras
        lines.append("        for key, value in data.items():")
        lines.append("            if key not in known_keys:")
        lines.append("                extras[key] = value")
        lines.append("")
        lines.append('        kwargs["extras"] = extras')
        lines.append('        kwargs["raw"] = data')
        lines.append(f"        return cls(**kwargs)")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Mapping table generation
# ---------------------------------------------------------------------------

def generate_mapping_table(comparison: ComparisonResult) -> str:
    """Generate a human-readable text table showing source -> unified field mappings.

    Parameters:
        comparison: The comparison result to generate the table from.

    Returns:
        A formatted string table.
    """
    if not comparison.suggested_mapping:
        return "No field mappings to display."

    # Group by unified field
    groups: Dict[str, List[FieldMapping]] = defaultdict(list)
    for m in comparison.suggested_mapping:
        groups[m.unified_field].append(m)

    lines: List[str] = []
    lines.append("=" * 80)
    lines.append("FIELD MAPPING TABLE")
    lines.append("=" * 80)
    lines.append("")

    # Header
    col_unified = "Unified Field"
    col_widths = {"unified": max(len(col_unified), 20)}
    for label in comparison.labels:
        col_widths[label] = max(len(label), 15)

    header_parts = [col_unified.ljust(col_widths["unified"])]
    for label in comparison.labels:
        header_parts.append(label.ljust(col_widths[label]))
    header_parts.append("Confidence")
    header = " | ".join(header_parts)
    lines.append(header)
    lines.append("-" * len(header))

    # Rows
    for unified_name in sorted(groups.keys()):
        mappings = groups[unified_name]
        src_map = {m.source_label: m for m in mappings}

        row_parts = [unified_name.ljust(col_widths["unified"])]
        confidences: List[float] = []
        for label in comparison.labels:
            m = src_map.get(label)
            if m:
                cell = m.source_field if m.source_field != unified_name else "="
                confidences.append(m.confidence)
            else:
                cell = "-"
            row_parts.append(cell.ljust(col_widths[label]))

        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
        if avg_conf >= 1.0:
            conf_str = "exact"
        else:
            conf_str = f"{avg_conf:.0%}"
        row_parts.append(conf_str)
        lines.append(" | ".join(row_parts))

    lines.append("")
    lines.append(f"Total unified fields: {len(groups)}")
    lines.append(f"Sources: {', '.join(comparison.labels)}")
    lines.append("Legend: '=' = same name as unified, '-' = not present in source")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class _FieldSpec:
    """Internal holder for generated field metadata."""

    __slots__ = ("py_name", "json_name", "annotation", "default", "comment", "required")

    def __init__(
        self,
        py_name: str,
        json_name: str,
        annotation: str,
        default: Optional[str],
        comment: str,
        required: bool,
    ):
        self.py_name = py_name
        self.json_name = json_name
        self.annotation = annotation
        self.default = default
        self.comment = comment
        self.required = required


def _unique_name(name: str, used: Set[str]) -> str:
    """Ensure *name* is unique within *used*, appending a suffix if needed."""
    if name not in used:
        used.add(name)
        return name
    i = 2
    while f"{name}_{i}" in used:
        i += 1
    result = f"{name}_{i}"
    used.add(result)
    return result
