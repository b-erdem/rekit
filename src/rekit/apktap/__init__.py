"""
apktap — Hook into Android app HTTP layer and capture traffic without proxy.

Uses Frida to instrument running Android apps, intercepting HTTP calls
at the library level (OkHttp, HttpURLConnection, WebView, Dio/Flutter).
Captured traffic is saved in HAR 1.2 format for use with hargen or other tools.
"""

__all__ = [
    "CaptureSession",
    "save_har",
]


def __getattr__(name: str):
    if name == "CaptureSession":
        from rekit.apktap.capture import CaptureSession

        return CaptureSession
    if name == "save_har":
        from rekit.apktap.capture import save_har

        return save_har
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
