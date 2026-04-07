"""Tests for rekit.schemadiff — schema inference, merging, comparison, field similarity."""

from __future__ import annotations

import pytest

from rekit.schemadiff.analyzer import (
    SchemaNode,
    MergedField,
    MergedSchema,
    ComparisonResult,
    TypeConflict,
    FieldMapping,
    infer_schema,
    merge_schemas,
    compare_schemas,
    _detect_string_subtype,
    _basic_type,
    _safe_example,
    _merge_element_schemas,
    _merge_object_schemas,
    _tokenize_field_name,
    _field_similarity,
    _suggest_python_type,
)
from rekit.schemadiff.generator import (
    _to_python_ident,
    _to_class_name,
    _python_type_annotation,
    _unique_name,
    generate_python,
    generate_mapping_table,
)


# =========================================================================
# String subtype detection
# =========================================================================


class TestDetectStringSubtype:
    def test_iso_date(self):
        assert _detect_string_subtype("2024-01-15") == "date"

    def test_iso_datetime(self):
        assert _detect_string_subtype("2024-01-15T10:30:00Z") == "date"

    def test_iso_datetime_with_offset(self):
        assert _detect_string_subtype("2024-01-15T10:30:00+02:00") == "date"

    def test_iso_datetime_with_millis(self):
        assert _detect_string_subtype("2024-01-15T10:30:00.123Z") == "date"

    def test_url_https(self):
        assert _detect_string_subtype("https://example.com/path") == "url"

    def test_url_http(self):
        assert _detect_string_subtype("http://localhost:8080") == "url"

    def test_email(self):
        assert _detect_string_subtype("user@example.com") == "email"

    def test_uuid(self):
        assert _detect_string_subtype("550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_uuid_uppercase(self):
        assert _detect_string_subtype("550E8400-E29B-41D4-A716-446655440000") == "uuid"

    def test_plain_string(self):
        assert _detect_string_subtype("hello world") == "string"

    def test_numeric_string(self):
        assert _detect_string_subtype("12345") == "string"


# =========================================================================
# Basic type detection
# =========================================================================


class TestBasicType:
    def test_none(self):
        assert _basic_type(None) == "null"

    def test_bool(self):
        assert _basic_type(True) == "boolean"

    def test_int(self):
        assert _basic_type(42) == "integer"

    def test_float(self):
        assert _basic_type(3.14) == "float"

    def test_string(self):
        assert _basic_type("hello") == "string"

    def test_url_string(self):
        assert _basic_type("https://example.com") == "url"

    def test_list(self):
        assert _basic_type([1, 2]) == "array"

    def test_dict(self):
        assert _basic_type({"a": 1}) == "object"


# =========================================================================
# Safe example
# =========================================================================


class TestSafeExample:
    def test_none(self):
        assert _safe_example(None) is None

    def test_int(self):
        assert _safe_example(42) == 42

    def test_short_string(self):
        assert _safe_example("hello") == "hello"

    def test_long_string_truncated(self):
        long_str = "x" * 200
        result = _safe_example(long_str)
        assert len(result) < 200
        assert result.endswith("...")

    def test_list(self):
        result = _safe_example([1, 2, 3])
        assert "3 items" in result

    def test_dict(self):
        result = _safe_example({"a": 1, "b": 2})
        assert "2 keys" in result


# =========================================================================
# Schema inference
# =========================================================================


class TestInferSchema:
    def test_null(self):
        node = infer_schema(None)
        assert node.type == "null"

    def test_boolean(self):
        node = infer_schema(True)
        assert node.type == "boolean"
        assert node.example is True

    def test_integer(self):
        node = infer_schema(42)
        assert node.type == "integer"
        assert node.example == 42

    def test_float(self):
        node = infer_schema(3.14)
        assert node.type == "float"

    def test_string(self):
        node = infer_schema("hello")
        assert node.type == "string"

    def test_date_string(self):
        node = infer_schema("2024-01-15T10:30:00Z")
        assert node.type == "date"

    def test_url_string(self):
        node = infer_schema("https://example.com")
        assert node.type == "url"

    def test_email_string(self):
        node = infer_schema("user@example.com")
        assert node.type == "email"

    def test_uuid_string(self):
        node = infer_schema("550e8400-e29b-41d4-a716-446655440000")
        assert node.type == "uuid"

    def test_long_string_truncated(self):
        node = infer_schema("x" * 200)
        assert len(node.example) <= 120

    def test_object(self):
        node = infer_schema({"name": "Alice", "age": 30})
        assert node.type == "object"
        assert "name" in node.fields
        assert "age" in node.fields
        assert node.fields["name"].type == "string"
        assert node.fields["age"].type == "integer"

    def test_nested_object(self):
        node = infer_schema({"user": {"id": 1}})
        assert node.type == "object"
        assert node.fields["user"].type == "object"
        assert node.fields["user"].fields["id"].type == "integer"

    def test_array(self):
        node = infer_schema([1, 2, 3])
        assert node.type == "array"
        assert node.items is not None
        assert node.items.type == "integer"

    def test_array_of_objects(self):
        node = infer_schema([{"id": 1}, {"id": 2}])
        assert node.type == "array"
        assert node.items is not None
        assert node.items.type == "object"
        assert "id" in node.items.fields

    def test_empty_array(self):
        node = infer_schema([])
        assert node.type == "array"
        assert node.items is None

    def test_max_depth_limits_recursion(self):
        deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        node = infer_schema(deep, max_depth=2)
        assert node.type == "object"
        # At depth 2, should stop recursing
        a_node = node.fields["a"]
        assert a_node.type == "object"

    def test_types_seen(self):
        node = infer_schema(42)
        assert "integer" in node.types_seen


class TestSchemaNodeToDict:
    def test_simple(self):
        node = SchemaNode(type="integer", example=42, types_seen={"integer"})
        d = node.to_dict()
        assert d["type"] == "integer"
        assert d["example"] == 42

    def test_optional(self):
        node = SchemaNode(type="string", optional=True)
        d = node.to_dict()
        assert d["optional"] is True

    def test_object_with_fields(self):
        node = SchemaNode(
            type="object",
            fields={"name": SchemaNode(type="string", types_seen={"string"})},
        )
        d = node.to_dict()
        assert "fields" in d
        assert "name" in d["fields"]

    def test_array_with_items(self):
        node = SchemaNode(
            type="array",
            items=SchemaNode(type="integer", types_seen={"integer"}),
        )
        d = node.to_dict()
        assert "items" in d

    def test_is_object_property(self):
        assert SchemaNode(type="object").is_object is True
        assert SchemaNode(type="string").is_object is False

    def test_is_array_property(self):
        assert SchemaNode(type="array").is_array is True
        assert SchemaNode(type="object").is_array is False


# =========================================================================
# Merge element schemas
# =========================================================================


class TestMergeElementSchemas:
    def test_empty(self):
        result = _merge_element_schemas([])
        assert result.type == "null"

    def test_homogeneous_integers(self):
        schemas = [
            SchemaNode(type="integer", types_seen={"integer"}),
            SchemaNode(type="integer", types_seen={"integer"}),
        ]
        result = _merge_element_schemas(schemas)
        assert result.type == "integer"

    def test_int_float_coercion(self):
        schemas = [
            SchemaNode(type="integer", types_seen={"integer"}),
            SchemaNode(type="float", types_seen={"float"}),
        ]
        result = _merge_element_schemas(schemas)
        assert result.type == "float"

    def test_mixed_types(self):
        schemas = [
            SchemaNode(type="string", types_seen={"string"}),
            SchemaNode(type="integer", types_seen={"integer"}),
        ]
        result = _merge_element_schemas(schemas)
        assert result.type == "mixed"

    def test_objects_merged(self):
        schemas = [
            SchemaNode(
                type="object",
                types_seen={"object"},
                fields={"a": SchemaNode(type="integer", types_seen={"integer"})},
            ),
            SchemaNode(
                type="object",
                types_seen={"object"},
                fields={
                    "a": SchemaNode(type="integer", types_seen={"integer"}),
                    "b": SchemaNode(type="string", types_seen={"string"}),
                },
            ),
        ]
        result = _merge_element_schemas(schemas)
        assert result.type == "object"
        assert "a" in result.fields
        assert "b" in result.fields
        # b is optional since it's only in one of two
        assert result.fields["b"].optional is True

    def test_objects_with_nulls(self):
        schemas = [
            SchemaNode(
                type="object",
                types_seen={"object"},
                fields={"x": SchemaNode(type="string", types_seen={"string"})},
            ),
            SchemaNode(type="null", types_seen={"null"}),
        ]
        result = _merge_element_schemas(schemas)
        assert result.type == "object"
        # All fields become optional due to null elements
        for fnode in result.fields.values():
            assert fnode.optional is True


# =========================================================================
# Schema merging
# =========================================================================


class TestMergeSchemas:
    def test_merge_two_sources(self):
        s1 = SchemaNode(
            type="object",
            fields={
                "id": SchemaNode(type="integer", types_seen={"integer"}),
                "name": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        s2 = SchemaNode(
            type="object",
            fields={
                "id": SchemaNode(type="integer", types_seen={"integer"}),
                "title": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        merged = merge_schemas([("source1", s1), ("source2", s2)])
        assert "id" in merged.fields
        assert "name" in merged.fields
        assert "title" in merged.fields
        assert merged.fields["id"].is_universal is True
        assert merged.fields["name"].is_universal is False
        assert merged.fields["title"].is_universal is False

    def test_merge_preserves_labels(self):
        s1 = SchemaNode(type="object", fields={})
        merged = merge_schemas([("api_a", s1), ("api_b", s1)])
        assert merged.labels == ["api_a", "api_b"]

    def test_merge_nested_objects(self):
        s1 = SchemaNode(
            type="object",
            fields={
                "address": SchemaNode(
                    type="object",
                    types_seen={"object"},
                    fields={"city": SchemaNode(type="string", types_seen={"string"})},
                )
            },
        )
        s2 = SchemaNode(
            type="object",
            fields={
                "address": SchemaNode(
                    type="object",
                    types_seen={"object"},
                    fields={
                        "city": SchemaNode(type="string", types_seen={"string"}),
                        "zip": SchemaNode(type="string", types_seen={"string"}),
                    },
                )
            },
        )
        merged = merge_schemas([("a", s1), ("b", s2)])
        addr = merged.fields["address"]
        assert addr.nested is not None
        assert "city" in addr.nested.fields
        assert "zip" in addr.nested.fields

    def test_merge_type_conflict(self):
        s1 = SchemaNode(
            type="object",
            fields={"price": SchemaNode(type="integer", types_seen={"integer"})},
        )
        s2 = SchemaNode(
            type="object",
            fields={"price": SchemaNode(type="string", types_seen={"string"})},
        )
        merged = merge_schemas([("a", s1), ("b", s2)])
        assert "integer" in merged.fields["price"].types_seen
        assert "string" in merged.fields["price"].types_seen


# =========================================================================
# Schema comparison
# =========================================================================


class TestCompareSchemas:
    def test_basic_comparison(self):
        s1 = SchemaNode(
            type="object",
            fields={
                "id": SchemaNode(type="integer", types_seen={"integer"}),
                "name": SchemaNode(type="string", types_seen={"string"}),
                "only_a": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        s2 = SchemaNode(
            type="object",
            fields={
                "id": SchemaNode(type="integer", types_seen={"integer"}),
                "name": SchemaNode(type="string", types_seen={"string"}),
                "only_b": SchemaNode(type="boolean", types_seen={"boolean"}),
            },
        )
        result = compare_schemas([("api_a", s1), ("api_b", s2)])
        assert "id" in result.universal_fields
        assert "name" in result.universal_fields
        assert result.stats["universal_count"] == 2
        assert result.stats["sources"] == 2

    def test_type_conflicts_detected(self):
        s1 = SchemaNode(
            type="object",
            fields={"amount": SchemaNode(type="integer", types_seen={"integer"})},
        )
        s2 = SchemaNode(
            type="object",
            fields={"amount": SchemaNode(type="string", types_seen={"string"})},
        )
        result = compare_schemas([("a", s1), ("b", s2)])
        assert len(result.type_conflicts) >= 1
        conflict = result.type_conflicts[0]
        assert conflict.field_name == "amount"

    def test_unique_fields(self):
        s1 = SchemaNode(
            type="object",
            fields={"unique_a": SchemaNode(type="string", types_seen={"string"})},
        )
        s2 = SchemaNode(
            type="object",
            fields={"unique_b": SchemaNode(type="string", types_seen={"string"})},
        )
        result = compare_schemas([("a", s1), ("b", s2)])
        # With 2 sources, presence of 1 is not > 50%, so fields go to unique
        assert "a" in result.unique_fields or "b" in result.unique_fields

    def test_three_source_common_fields(self):
        s1 = SchemaNode(
            type="object",
            fields={
                "shared": SchemaNode(type="string", types_seen={"string"}),
                "ab_only": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        s2 = SchemaNode(
            type="object",
            fields={
                "shared": SchemaNode(type="string", types_seen={"string"}),
                "ab_only": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        s3 = SchemaNode(
            type="object",
            fields={
                "shared": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        result = compare_schemas([("a", s1), ("b", s2), ("c", s3)])
        assert "shared" in result.universal_fields
        # ab_only is in 2 of 3 -> common
        assert "ab_only" in result.common_fields

    def test_to_dict(self):
        s1 = SchemaNode(
            type="object",
            fields={"id": SchemaNode(type="integer", types_seen={"integer"})},
        )
        result = compare_schemas([("a", s1), ("b", s1)])
        d = result.to_dict()
        assert "labels" in d
        assert "stats" in d
        assert "universal_fields" in d

    def test_stats(self):
        s1 = SchemaNode(
            type="object",
            fields={
                "a": SchemaNode(type="string", types_seen={"string"}),
                "b": SchemaNode(type="integer", types_seen={"integer"}),
            },
        )
        result = compare_schemas([("src", s1)])
        assert result.stats["total_fields"] == 2
        assert result.stats["sources"] == 1


# =========================================================================
# Field similarity
# =========================================================================


class TestTokenizeFieldName:
    def test_snake_case(self):
        assert _tokenize_field_name("user_name") == ["user", "name"]

    def test_camel_case(self):
        assert _tokenize_field_name("userName") == ["user", "name"]

    def test_kebab_case(self):
        assert _tokenize_field_name("user-name") == ["user", "name"]

    def test_mixed_case(self):
        tokens = _tokenize_field_name("myURLParser")
        assert "my" in tokens
        # The regex splits on lower-to-upper transitions, so "URLParser" stays grouped
        assert any("url" in t for t in tokens)

    def test_single_word(self):
        assert _tokenize_field_name("price") == ["price"]

    def test_empty_string(self):
        assert _tokenize_field_name("") == []


class TestFieldSimilarity:
    def test_identical(self):
        assert _field_similarity("price", "price") == 1.0

    def test_completely_different(self):
        score = _field_similarity("aaaa", "zzzz")
        assert score < 0.3

    def test_synonym_match(self):
        # price and cost are synonyms
        score = _field_similarity("price", "cost")
        assert score > 0.3

    def test_partial_overlap(self):
        score = _field_similarity("user_name", "user_email")
        assert score > 0.0

    def test_containment_bonus(self):
        score = _field_similarity("bed", "bedroom")
        assert score > 0.2

    def test_address_location_synonyms(self):
        score = _field_similarity("address", "location")
        assert score > 0.3

    def test_image_photo_synonyms(self):
        score = _field_similarity("image_url", "photo_url")
        assert score > 0.3

    def test_lat_latitude_synonyms(self):
        score = _field_similarity("lat", "latitude")
        assert score > 0.3


# =========================================================================
# Suggest Python type
# =========================================================================


class TestSuggestPythonType:
    def test_single_integer(self):
        assert _suggest_python_type({"integer"}) == "int"

    def test_single_float(self):
        assert _suggest_python_type({"float"}) == "float"

    def test_int_float(self):
        assert _suggest_python_type({"integer", "float"}) == "float"

    def test_string(self):
        assert _suggest_python_type({"string"}) == "str"

    def test_string_subtypes_collapse(self):
        assert _suggest_python_type({"string", "url", "email"}) == "str"

    def test_date_is_str(self):
        assert _suggest_python_type({"date"}) == "str"

    def test_null_only(self):
        assert _suggest_python_type({"null"}) == "None"

    def test_null_plus_int(self):
        # null is ignored for type, but the field becomes optional
        assert _suggest_python_type({"null", "integer"}) == "int"

    def test_boolean(self):
        assert _suggest_python_type({"boolean"}) == "bool"

    def test_object(self):
        assert _suggest_python_type({"object"}) == "Dict[str, Any]"

    def test_array(self):
        assert _suggest_python_type({"array"}) == "List[Any]"

    def test_mixed_incompatible(self):
        assert _suggest_python_type({"integer", "string"}) == "Any"

    def test_mixed(self):
        assert _suggest_python_type({"mixed"}) == "Any"


# =========================================================================
# generator.py — helpers
# =========================================================================


class TestGeneratorHelpers:
    def test_to_python_ident_snake_case(self):
        assert _to_python_ident("userName") == "user_name"

    def test_to_python_ident_special_chars(self):
        result = _to_python_ident("some-field.name")
        assert result.isidentifier()

    def test_to_python_ident_leading_digit(self):
        result = _to_python_ident("3dModel")
        assert not result[0].isdigit()

    def test_to_python_ident_keyword(self):
        result = _to_python_ident("type")
        assert result != "type"
        assert result.isidentifier()

    def test_to_python_ident_reserved(self):
        result = _to_python_ident("id")
        assert result != "id"

    def test_to_class_name(self):
        assert _to_class_name("user_response") == "UserResponse"
        assert _to_class_name("") == "Model"

    def test_python_type_annotation_with_null(self):
        assert _python_type_annotation("int", True) == "Optional[int]"

    def test_python_type_annotation_without_null(self):
        assert _python_type_annotation("str", False) == "str"

    def test_python_type_annotation_none_type(self):
        assert _python_type_annotation("None", False) == "Optional[Any]"

    def test_unique_name_no_conflict(self):
        used = set()
        assert _unique_name("field", used) == "field"
        assert "field" in used

    def test_unique_name_with_conflict(self):
        used = {"field"}
        result = _unique_name("field", used)
        assert result == "field_2"
        assert "field_2" in used

    def test_unique_name_multiple_conflicts(self):
        used = {"field", "field_2"}
        result = _unique_name("field", used)
        assert result == "field_3"


# =========================================================================
# Code generation
# =========================================================================


class TestGeneratePython:
    def _build_comparison(self):
        s1 = SchemaNode(
            type="object",
            fields={
                "id": SchemaNode(type="integer", types_seen={"integer"}, example=1),
                "name": SchemaNode(type="string", types_seen={"string"}, example="Alice"),
                "only_a": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        s2 = SchemaNode(
            type="object",
            fields={
                "id": SchemaNode(type="integer", types_seen={"integer"}, example=2),
                "name": SchemaNode(type="string", types_seen={"string"}, example="Bob"),
                "only_b": SchemaNode(type="boolean", types_seen={"boolean"}),
            },
        )
        return compare_schemas([("api_a", s1), ("api_b", s2)])

    def test_generates_valid_python(self):
        result = self._build_comparison()
        code = generate_python(result, class_name="Listing")
        assert "@dataclass" in code
        assert "class Listing:" in code
        assert "from __future__" in code

    def test_includes_from_classmethods(self):
        result = self._build_comparison()
        code = generate_python(result)
        assert "from_api_a" in code
        assert "from_api_b" in code

    def test_includes_universal_fields(self):
        result = self._build_comparison()
        code = generate_python(result)
        # id and name are universal
        assert "id_" in code or "id" in code  # may be escaped
        assert "name" in code

    def test_includes_extras_and_raw(self):
        result = self._build_comparison()
        code = generate_python(result)
        assert "extras:" in code
        assert "raw:" in code

    def test_code_compiles(self):
        result = self._build_comparison()
        code = generate_python(result, class_name="TestModel")
        # The generated code should be syntactically valid
        compile(code, "<test>", "exec")


class TestGenerateMappingTable:
    def test_basic_table(self):
        s1 = SchemaNode(
            type="object",
            fields={
                "id": SchemaNode(type="integer", types_seen={"integer"}),
                "name": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        s2 = SchemaNode(
            type="object",
            fields={
                "id": SchemaNode(type="integer", types_seen={"integer"}),
                "title": SchemaNode(type="string", types_seen={"string"}),
            },
        )
        result = compare_schemas([("src_a", s1), ("src_b", s2)])
        table = generate_mapping_table(result)
        assert "FIELD MAPPING TABLE" in table
        assert "id" in table
        assert "src_a" in table
        assert "src_b" in table

    def test_no_mappings(self):
        result = ComparisonResult()
        table = generate_mapping_table(result)
        assert "No field mappings" in table

    def test_table_has_legend(self):
        s1 = SchemaNode(
            type="object",
            fields={"x": SchemaNode(type="string", types_seen={"string"})},
        )
        result = compare_schemas([("a", s1)])
        table = generate_mapping_table(result)
        assert "Legend" in table
