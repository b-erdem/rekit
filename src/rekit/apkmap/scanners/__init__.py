"""
apkmap.scanners — pluggable source-code scanners for Android API discovery.
"""

from rekit.apkmap.scanners.base import (
    AuthPattern,
    EndpointInfo,
    FieldInfo,
    InterceptorInfo,
    ModelInfo,
    Scanner,
    ScanResult,
)
from rekit.apkmap.scanners.retrofit import RetrofitScanner
from rekit.apkmap.scanners.okhttp import OkHttpScanner
from rekit.apkmap.scanners.flutter import FlutterScanner
from rekit.apkmap.scanners.generic import GenericScanner

ALL_SCANNERS: list[type[Scanner]] = [
    RetrofitScanner,
    OkHttpScanner,
    FlutterScanner,
    GenericScanner,
]

__all__ = [
    "AuthPattern",
    "EndpointInfo",
    "FieldInfo",
    "InterceptorInfo",
    "ModelInfo",
    "Scanner",
    "ScanResult",
    "RetrofitScanner",
    "OkHttpScanner",
    "FlutterScanner",
    "GenericScanner",
    "ALL_SCANNERS",
]
