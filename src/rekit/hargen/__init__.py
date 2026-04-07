"""
hargen — Generate typed Python API clients from captured HTTP traffic.

Parses HAR files and mitmproxy flow dumps, analyzes endpoint patterns,
and generates clean Python client code with dataclass models.
"""

from rekit.hargen.parser import HttpExchange, parse_har, parse_mitmproxy, parse_traffic
from rekit.hargen.analyzer import (
    analyze,
    ApiSpec,
    Endpoint,
    FieldSchema,
    HeaderInfo,
    ParamInfo,
)
from rekit.hargen.generator import generate_client

__all__ = [
    "HttpExchange",
    "parse_har",
    "parse_mitmproxy",
    "parse_traffic",
    "analyze",
    "ApiSpec",
    "Endpoint",
    "FieldSchema",
    "HeaderInfo",
    "ParamInfo",
    "generate_client",
]
