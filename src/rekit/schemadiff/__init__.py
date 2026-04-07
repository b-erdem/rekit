"""
schemadiff — Compare API response schemas and suggest unified data models.

Analyzes JSON response structures from multiple API sources, identifies
common and unique fields, detects type conflicts, and generates unified
Python dataclass models with per-source mapping methods.
"""

from rekit.schemadiff.analyzer import (
    SchemaNode,
    MergedField,
    MergedSchema,
    ComparisonResult,
    infer_schema,
    merge_schemas,
    compare_schemas,
)
from rekit.schemadiff.generator import generate_python, generate_mapping_table
from rekit.schemadiff.display import render_comparison, render_field_matrix

__all__ = [
    "SchemaNode",
    "MergedField",
    "MergedSchema",
    "ComparisonResult",
    "infer_schema",
    "merge_schemas",
    "compare_schemas",
    "generate_python",
    "generate_mapping_table",
    "render_comparison",
    "render_field_matrix",
]
