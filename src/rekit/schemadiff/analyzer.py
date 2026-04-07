"""
schemadiff.analyzer — Schema inference, merging, and comparison.

Core analysis engine that infers JSON schemas from sample data, merges
schemas from multiple labeled sources, and produces comparison results
identifying universal, common, and unique fields across sources.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Pattern detection helpers
# ---------------------------------------------------------------------------

_ISO_DATE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"
    r"(T\d{2}:\d{2}(:\d{2})?"
    r"(\.\d+)?"
    r"(Z|[+-]\d{2}:?\d{2})?)?$"
)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _detect_string_subtype(value: str) -> str:
    """Return a more specific type for well-known string patterns."""
    if _ISO_DATE_RE.match(value):
        return "date"
    if _URL_RE.match(value):
        return "url"
    if _EMAIL_RE.match(value):
        return "email"
    if _UUID_RE.match(value):
        return "uuid"
    return "string"


# ---------------------------------------------------------------------------
# SchemaNode — represents inferred schema for a single JSON value
# ---------------------------------------------------------------------------

@dataclass
class SchemaNode:
    """Inferred schema for a single JSON value or subtree.

    Attributes:
        type: Primary type string — one of ``"object"``, ``"array"``,
              ``"string"``, ``"date"``, ``"url"``, ``"email"``, ``"uuid"``,
              ``"integer"``, ``"float"``, ``"boolean"``, ``"null"``,
              ``"mixed"``.
        fields: Mapping of field name to :class:`SchemaNode` when *type*
                is ``"object"``.
        items: Element schema when *type* is ``"array"``.
        optional: ``True`` when the field was absent in at least one
                  observed record.
        example: A representative sample value (kept small).
        count: Number of source records in which this field appeared.
        types_seen: All distinct types observed for this position across
                    records (useful before merging).
    """

    type: str = "null"
    fields: Dict[str, "SchemaNode"] = field(default_factory=dict)
    items: Optional["SchemaNode"] = None
    optional: bool = False
    example: Any = None
    count: int = 1
    types_seen: Set[str] = field(default_factory=set)

    # convenience --------------------------------------------------------

    @property
    def is_object(self) -> bool:
        return self.type == "object"

    @property
    def is_array(self) -> bool:
        return self.type == "array"

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the schema tree to a plain dict (for JSON output)."""
        d: Dict[str, Any] = {"type": self.type}
        if self.optional:
            d["optional"] = True
        if self.example is not None:
            d["example"] = self.example
        if self.types_seen and self.types_seen != {self.type}:
            d["types_seen"] = sorted(self.types_seen)
        if self.fields:
            d["fields"] = {k: v.to_dict() for k, v in self.fields.items()}
        if self.items is not None:
            d["items"] = self.items.to_dict()
        return d


# ---------------------------------------------------------------------------
# Schema inference
# ---------------------------------------------------------------------------

def infer_schema(data: Any, max_depth: int = 3, _depth: int = 0) -> SchemaNode:
    """Infer a :class:`SchemaNode` from an arbitrary JSON value.

    Parameters:
        data: Deserialised JSON value (dict, list, str, int, …).
        max_depth: Maximum object/array nesting depth to recurse into.

    Returns:
        A :class:`SchemaNode` tree describing *data*'s structure.
    """
    if data is None:
        return SchemaNode(type="null", types_seen={"null"})

    if isinstance(data, bool):
        return SchemaNode(type="boolean", example=data, types_seen={"boolean"})

    if isinstance(data, int):
        return SchemaNode(type="integer", example=data, types_seen={"integer"})

    if isinstance(data, float):
        return SchemaNode(type="float", example=data, types_seen={"float"})

    if isinstance(data, str):
        subtype = _detect_string_subtype(data)
        example = data if len(data) <= 120 else data[:117] + "..."
        return SchemaNode(type=subtype, example=example, types_seen={subtype})

    if isinstance(data, list):
        node = SchemaNode(type="array", types_seen={"array"}, example=f"[…{len(data)} items]")
        if data and _depth < max_depth:
            # Merge schemas of all array elements to capture optional keys
            element_schemas = [infer_schema(item, max_depth, _depth + 1) for item in data[:20]]
            node.items = _merge_element_schemas(element_schemas)
        elif data:
            # At depth limit, just record the type of the first element
            node.items = SchemaNode(type=_basic_type(data[0]), types_seen={_basic_type(data[0])})
        return node

    if isinstance(data, dict):
        node = SchemaNode(type="object", types_seen={"object"})
        if _depth < max_depth:
            for key, value in data.items():
                node.fields[key] = infer_schema(value, max_depth, _depth + 1)
        else:
            # At depth limit, record keys but don't recurse
            for key, value in data.items():
                node.fields[key] = SchemaNode(
                    type=_basic_type(value),
                    types_seen={_basic_type(value)},
                    example=_safe_example(value),
                )
        return node

    # Fallback for unexpected types
    return SchemaNode(type="string", example=str(data)[:80], types_seen={"string"})


def _basic_type(value: Any) -> str:
    """Return the basic type string for a value without recursing."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return _detect_string_subtype(value)
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _safe_example(value: Any) -> Any:
    """Return a safe, small example for display."""
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= 80 else value[:77] + "..."
    if isinstance(value, list):
        return f"[…{len(value)} items]"
    if isinstance(value, dict):
        return f"{{…{len(value)} keys}}"
    return str(value)[:80]


def _merge_element_schemas(schemas: List[SchemaNode]) -> SchemaNode:
    """Merge schemas of multiple array elements into a single representative schema.

    For object arrays, this combines all field keys and marks fields not present
    in every element as optional.  For mixed-type arrays, the resulting node
    has type ``"mixed"``.
    """
    if not schemas:
        return SchemaNode(type="null")

    type_counts: Counter = Counter(s.type for s in schemas)
    total = len(schemas)

    # All same type — straightforward merge
    if len(type_counts) == 1:
        representative = schemas[0].type
        if representative == "object":
            return _merge_object_schemas(schemas, total)
        # Non-object homogeneous array: return first element schema
        return schemas[0]

    # Mostly objects with some nulls — still treat as object array
    obj_count = type_counts.get("object", 0)
    null_count = type_counts.get("null", 0)
    if obj_count > 0 and obj_count + null_count == total:
        obj_schemas = [s for s in schemas if s.type == "object"]
        merged = _merge_object_schemas(obj_schemas, total)
        # All fields become optional since some elements are null
        for fnode in merged.fields.values():
            fnode.optional = True
        return merged

    # Numeric coercion: int+float -> float
    if set(type_counts.keys()) <= {"integer", "float"}:
        return SchemaNode(
            type="float",
            example=schemas[0].example,
            types_seen={"integer", "float"},
        )

    # Truly mixed types
    all_types = set()
    for s in schemas:
        all_types.update(s.types_seen or {s.type})
    return SchemaNode(type="mixed", types_seen=all_types, example=schemas[0].example)


def _merge_object_schemas(schemas: List[SchemaNode], total_elements: int) -> SchemaNode:
    """Merge multiple object schemas (from array elements) into one."""
    all_keys: Dict[str, List[SchemaNode]] = defaultdict(list)
    key_counts: Counter = Counter()

    for schema in schemas:
        for key, node in schema.fields.items():
            all_keys[key].append(node)
            key_counts[key] += 1

    merged = SchemaNode(type="object", types_seen={"object"})
    for key, nodes in all_keys.items():
        if len(nodes) == 1:
            child = nodes[0]
        else:
            child = _merge_element_schemas(nodes)
        child.optional = key_counts[key] < total_elements
        child.count = key_counts[key]
        merged.fields[key] = child

    return merged


# ---------------------------------------------------------------------------
# Multi-source merging
# ---------------------------------------------------------------------------

@dataclass
class MergedField:
    """A single field as seen across multiple labeled sources.

    Attributes:
        name: Canonical field name.
        types_seen: All types observed for this field across sources.
        sources_present: Labels of sources that contain this field.
        sources_missing: Labels of sources that lack this field.
        example_values: Mapping of source label to an example value.
        nested: Recursively merged children when the field is an object.
        is_universal: ``True`` when every source has this field.
        suggested_type: Best single Python type to represent the field.
    """

    name: str = ""
    types_seen: Set[str] = field(default_factory=set)
    sources_present: List[str] = field(default_factory=list)
    sources_missing: List[str] = field(default_factory=list)
    example_values: Dict[str, Any] = field(default_factory=dict)
    nested: Optional["MergedSchema"] = None
    is_universal: bool = False
    suggested_type: str = "Any"


@dataclass
class MergedSchema:
    """Result of merging multiple labeled schemas.

    Each entry in *fields* describes one field as observed across all sources.
    """

    fields: Dict[str, MergedField] = field(default_factory=dict)
    labels: List[str] = field(default_factory=list)


def merge_schemas(schemas: List[Tuple[str, SchemaNode]]) -> MergedSchema:
    """Merge multiple labeled root schemas into a :class:`MergedSchema`.

    Parameters:
        schemas: List of ``(label, root_schema_node)`` pairs.  Each root
                 is expected to be an object schema.

    Returns:
        A :class:`MergedSchema` summarising field presence across sources.
    """
    labels = [label for label, _ in schemas]
    merged = MergedSchema(labels=labels)

    all_keys: Dict[str, Dict[str, SchemaNode]] = defaultdict(dict)
    for label, schema in schemas:
        if schema.is_object:
            for key, node in schema.fields.items():
                all_keys[key][label] = node

    for key, source_nodes in all_keys.items():
        mf = MergedField(name=key)
        mf.sources_present = [l for l in labels if l in source_nodes]
        mf.sources_missing = [l for l in labels if l not in source_nodes]
        mf.is_universal = len(mf.sources_missing) == 0

        for label, node in source_nodes.items():
            mf.types_seen.update(node.types_seen or {node.type})
            mf.example_values[label] = node.example

        # Recurse into nested objects
        nested_obj_nodes = [
            (label, node) for label, node in source_nodes.items() if node.is_object
        ]
        if nested_obj_nodes:
            mf.nested = merge_schemas(nested_obj_nodes)

        mf.suggested_type = _suggest_python_type(mf.types_seen)
        merged.fields[key] = mf

    return merged


# ---------------------------------------------------------------------------
# Schema comparison
# ---------------------------------------------------------------------------

@dataclass
class FieldMapping:
    """Maps a source-specific field name to a unified field name."""

    source_label: str
    source_field: str
    unified_field: str
    confidence: float = 1.0


@dataclass
class TypeConflict:
    """Records a field where different sources disagree on type."""

    field_name: str
    types_by_source: Dict[str, str] = field(default_factory=dict)
    suggested_type: str = "Any"


@dataclass
class ComparisonResult:
    """Full comparison result for multiple API schemas.

    Attributes:
        labels: Source labels in order.
        universal_fields: Fields present in ALL sources.
        common_fields: Fields present in the majority (>50%) of sources.
        unique_fields: Per-source dict of fields only that source has.
        type_conflicts: Fields where sources disagree on type.
        suggested_mapping: Source field -> unified field mappings.
        merged: The underlying :class:`MergedSchema`.
        all_fields: Every field with its :class:`MergedField` metadata.
        stats: Summary statistics dict.
    """

    labels: List[str] = field(default_factory=list)
    universal_fields: Dict[str, MergedField] = field(default_factory=dict)
    common_fields: Dict[str, MergedField] = field(default_factory=dict)
    unique_fields: Dict[str, Dict[str, MergedField]] = field(default_factory=dict)
    type_conflicts: List[TypeConflict] = field(default_factory=list)
    suggested_mapping: List[FieldMapping] = field(default_factory=list)
    merged: Optional[MergedSchema] = None
    all_fields: Dict[str, MergedField] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the comparison result to a JSON-friendly dict."""
        return {
            "labels": self.labels,
            "stats": self.stats,
            "universal_fields": {k: _mf_to_dict(v) for k, v in self.universal_fields.items()},
            "common_fields": {k: _mf_to_dict(v) for k, v in self.common_fields.items()},
            "unique_fields": {
                src: {k: _mf_to_dict(v) for k, v in flds.items()}
                for src, flds in self.unique_fields.items()
            },
            "type_conflicts": [
                {
                    "field": tc.field_name,
                    "types_by_source": tc.types_by_source,
                    "suggested_type": tc.suggested_type,
                }
                for tc in self.type_conflicts
            ],
            "suggested_mapping": [
                {
                    "source": m.source_label,
                    "source_field": m.source_field,
                    "unified_field": m.unified_field,
                    "confidence": m.confidence,
                }
                for m in self.suggested_mapping
            ],
        }


def _mf_to_dict(mf: MergedField) -> Dict[str, Any]:
    """Convert a MergedField to a JSON-serialisable dict."""
    d: Dict[str, Any] = {
        "types_seen": sorted(mf.types_seen),
        "sources_present": mf.sources_present,
        "sources_missing": mf.sources_missing,
        "is_universal": mf.is_universal,
        "suggested_type": mf.suggested_type,
    }
    if mf.example_values:
        d["examples"] = mf.example_values
    return d


def compare_schemas(schemas: List[Tuple[str, SchemaNode]]) -> ComparisonResult:
    """Compare multiple labeled schemas and produce a :class:`ComparisonResult`.

    Parameters:
        schemas: List of ``(label, root_schema_node)`` pairs.

    Returns:
        A :class:`ComparisonResult` with universal/common/unique fields,
        type conflicts, and suggested field mappings.
    """
    labels = [label for label, _ in schemas]
    num_sources = len(labels)
    merged = merge_schemas(schemas)

    result = ComparisonResult(labels=labels, merged=merged)
    result.all_fields = dict(merged.fields)

    # Classify fields by presence
    for name, mf in merged.fields.items():
        present_count = len(mf.sources_present)
        if present_count == num_sources:
            result.universal_fields[name] = mf
        elif present_count > num_sources / 2:
            result.common_fields[name] = mf
        else:
            # Unique to specific sources
            for src in mf.sources_present:
                result.unique_fields.setdefault(src, {})[name] = mf

    # Detect type conflicts
    for name, mf in merged.fields.items():
        real_types = mf.types_seen - {"null"}
        if len(real_types) > 1:
            # Build per-source type map
            types_by_source: Dict[str, str] = {}
            for label, schema in schemas:
                if schema.is_object and name in schema.fields:
                    node = schema.fields[name]
                    types_by_source[label] = node.type
            result.type_conflicts.append(TypeConflict(
                field_name=name,
                types_by_source=types_by_source,
                suggested_type=mf.suggested_type,
            ))

    # Build suggested mappings including similarity-based field grouping
    result.suggested_mapping = _build_field_mappings(schemas, merged)

    # Summary stats
    total = len(merged.fields)
    result.stats = {
        "total_fields": total,
        "universal_count": len(result.universal_fields),
        "universal_pct": round(len(result.universal_fields) / max(total, 1) * 100, 1),
        "common_count": len(result.common_fields),
        "unique_count": sum(len(v) for v in result.unique_fields.values()),
        "type_conflict_count": len(result.type_conflicts),
        "sources": num_sources,
    }

    return result


# ---------------------------------------------------------------------------
# Field-name similarity and mapping
# ---------------------------------------------------------------------------

# Common real-estate / API field name fragments that are semantically equivalent
_SYNONYM_GROUPS: List[Set[str]] = [
    {"price", "cost", "amount", "value"},
    {"address", "location", "addr", "loc"},
    {"bedroom", "bed", "room"},
    {"bathroom", "bath"},
    {"area", "size", "sqft", "sqm", "square", "footage", "surface"},
    {"image", "photo", "picture", "img", "pic", "thumbnail", "thumb"},
    {"title", "name", "heading"},
    {"description", "desc", "summary", "detail"},
    {"latitude", "lat"},
    {"longitude", "lng", "lon", "long"},
    {"identifier", "id", "uid", "key"},
    {"created", "create", "creation"},
    {"updated", "update", "modified", "modification"},
    {"url", "link", "href", "uri"},
    {"phone", "tel", "telephone", "mobile"},
    {"email", "mail"},
    {"city", "town", "municipality"},
    {"country", "nation"},
    {"state", "province", "region"},
    {"zip", "postal", "postcode", "zipcode"},
    {"type", "kind", "category", "class"},
    {"status", "state"},
    {"agent", "broker", "realtor", "contact"},
    {"floor", "storey", "story", "level"},
    {"year", "built", "construction"},
    {"garage", "parking"},
    {"garden", "yard", "outdoor"},
    {"rent", "rental"},
    {"sale", "sell", "buy", "purchase"},
]

# Pre-compute a lookup: word -> group index
_WORD_TO_GROUP: Dict[str, int] = {}
for _i, _group in enumerate(_SYNONYM_GROUPS):
    for _word in _group:
        _WORD_TO_GROUP[_word] = _i


def _tokenize_field_name(name: str) -> List[str]:
    """Split a field name into lowercase tokens.

    Handles snake_case, camelCase, and kebab-case.
    """
    # Insert separator before uppercase letters for camelCase
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    # Split on non-alphanumeric
    tokens = re.split(r"[^a-zA-Z0-9]+", spaced.lower())
    return [t for t in tokens if t]


def _field_similarity(name_a: str, name_b: str) -> float:
    """Compute a similarity score (0.0–1.0) between two field names.

    Uses token overlap, synonym groups, and substring matching.
    """
    if name_a == name_b:
        return 1.0

    tokens_a = _tokenize_field_name(name_a)
    tokens_b = _tokenize_field_name(name_b)

    if not tokens_a or not tokens_b:
        return 0.0

    # Exact token overlap
    set_a = set(tokens_a)
    set_b = set(tokens_b)
    overlap = set_a & set_b
    union = set_a | set_b
    jaccard = len(overlap) / len(union) if union else 0.0

    # Synonym group overlap
    groups_a = {_WORD_TO_GROUP[t] for t in tokens_a if t in _WORD_TO_GROUP}
    groups_b = {_WORD_TO_GROUP[t] for t in tokens_b if t in _WORD_TO_GROUP}
    synonym_overlap = len(groups_a & groups_b)
    synonym_total = len(groups_a | groups_b) if (groups_a or groups_b) else 1
    synonym_score = synonym_overlap / synonym_total if synonym_total else 0.0

    # Substring containment bonus
    lower_a = name_a.lower().replace("_", "").replace("-", "")
    lower_b = name_b.lower().replace("_", "").replace("-", "")
    containment = 0.0
    if lower_a in lower_b or lower_b in lower_a:
        containment = 0.3

    # Weighted combination
    score = 0.4 * jaccard + 0.4 * synonym_score + 0.2 * containment
    return min(score, 1.0)


def _build_field_mappings(
    schemas: List[Tuple[str, SchemaNode]],
    merged: MergedSchema,
) -> List[FieldMapping]:
    """Build suggested field mappings from source fields to unified names.

    For fields present in all or most sources under the same name, the mapping
    is trivial (identity).  For source-unique fields, we try to find semantically
    similar fields from other sources and suggest groupings.
    """
    mappings: List[FieldMapping] = []

    # Collect all field names per source
    source_fields: Dict[str, Set[str]] = {}
    for label, schema in schemas:
        if schema.is_object:
            source_fields[label] = set(schema.fields.keys())
        else:
            source_fields[label] = set()

    all_field_names: Set[str] = set()
    for fields in source_fields.values():
        all_field_names.update(fields)

    # Identity mappings for shared fields
    for name, mf in merged.fields.items():
        for src in mf.sources_present:
            mappings.append(FieldMapping(
                source_label=src,
                source_field=name,
                unified_field=name,
                confidence=1.0,
            ))

    # Try to match unique fields across sources via similarity
    # Build per-source unique fields (fields only that source has under that exact name)
    source_only: Dict[str, Set[str]] = {}
    for label in merged.labels:
        own = source_fields.get(label, set())
        others: Set[str] = set()
        for other_label, other_fields in source_fields.items():
            if other_label != label:
                others.update(other_fields)
        source_only[label] = own - others  # fields not in any other source by exact name

    # Cross-source similarity matching for source-unique fields
    matched_pairs: List[Tuple[str, str, str, str, float]] = []  # (src1, f1, src2, f2, score)
    labels = merged.labels
    for i, label_a in enumerate(labels):
        for label_b in labels[i + 1:]:
            for field_a in source_only.get(label_a, set()):
                for field_b in source_only.get(label_b, set()):
                    sim = _field_similarity(field_a, field_b)
                    if sim >= 0.35:
                        matched_pairs.append((label_a, field_a, label_b, field_b, sim))

    # Group matched pairs and assign unified names
    # Use a simple greedy approach: sort by score descending, assign unified names
    matched_pairs.sort(key=lambda x: x[4], reverse=True)
    used_fields: Set[Tuple[str, str]] = set()  # (label, field) pairs already mapped

    for src1, f1, src2, f2, score in matched_pairs:
        if (src1, f1) in used_fields or (src2, f2) in used_fields:
            continue
        used_fields.add((src1, f1))
        used_fields.add((src2, f2))

        # Choose the shorter/simpler name as the unified name
        unified = f1 if len(f1) <= len(f2) else f2
        # Only add if not already an identity mapping
        existing_unified = {m.unified_field for m in mappings
                           if m.source_label == src1 and m.source_field == f1}
        if unified not in existing_unified:
            # Remove old identity mapping if exists, replace with new
            mappings = [
                m for m in mappings
                if not (m.source_label == src1 and m.source_field == f1)
                and not (m.source_label == src2 and m.source_field == f2)
            ]
            mappings.append(FieldMapping(src1, f1, unified, score))
            mappings.append(FieldMapping(src2, f2, unified, score))

    # Sort for stable output
    mappings.sort(key=lambda m: (m.unified_field, m.source_label))
    return mappings


# ---------------------------------------------------------------------------
# Type suggestion
# ---------------------------------------------------------------------------

# Priority order for suggesting a Python type from a set of seen JSON types.
_TYPE_PRIORITY = [
    "object",
    "array",
    "float",
    "integer",
    "date",
    "url",
    "email",
    "uuid",
    "string",
    "boolean",
    "null",
    "mixed",
]

_TYPE_TO_PYTHON = {
    "object": "Dict[str, Any]",
    "array": "List[Any]",
    "float": "float",
    "integer": "int",
    "date": "str",  # ISO date strings stay as str
    "url": "str",
    "email": "str",
    "uuid": "str",
    "string": "str",
    "boolean": "bool",
    "null": "None",
    "mixed": "Any",
}


def _suggest_python_type(types_seen: Set[str]) -> str:
    """Suggest a single Python type annotation from a set of observed types.

    Rules:
      - If only ``null`` is seen, return ``"None"``.
      - Ignore ``null`` otherwise (fields with null become Optional).
      - ``int`` + ``float`` -> ``float``.
      - String subtypes (date, url, email, uuid) collapse to ``str``.
      - Multiple incompatible types -> ``Any``.
    """
    real = types_seen - {"null"}
    if not real:
        return "None"

    # Collapse string subtypes
    string_types = {"string", "date", "url", "email", "uuid"}
    real_collapsed: Set[str] = set()
    has_string = False
    for t in real:
        if t in string_types:
            has_string = True
        else:
            real_collapsed.add(t)
    if has_string:
        real_collapsed.add("string")

    # int + float -> float
    if real_collapsed == {"integer", "float"}:
        return "float"
    if real_collapsed == {"integer"}:
        return "int"
    if real_collapsed == {"float"}:
        return "float"

    if len(real_collapsed) == 1:
        return _TYPE_TO_PYTHON.get(next(iter(real_collapsed)), "Any")

    return "Any"
