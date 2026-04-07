"""
apkmap -- Scan decompiled Android APK source code and map all API endpoints,
request/response models, headers, and authentication mechanisms.

Supports Retrofit, OkHttp, Flutter/Dio, and generic URL/auth pattern discovery.
"""

from rekit.apkmap.scanners.base import (
    AuthPattern,
    EndpointInfo,
    FieldInfo,
    InterceptorInfo,
    ModelInfo,
    ScanResult,
)
from rekit.apkmap.scanners import ALL_SCANNERS
from rekit.apkmap.decompiler import decompile
from rekit.apkmap.report import generate_json, generate_table

__all__ = [
    "AuthPattern",
    "EndpointInfo",
    "FieldInfo",
    "InterceptorInfo",
    "ModelInfo",
    "ScanResult",
    "ALL_SCANNERS",
    "decompile",
    "generate_json",
    "generate_table",
]
