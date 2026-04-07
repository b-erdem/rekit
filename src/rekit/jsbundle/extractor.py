"""
Extract JS bundles from APK/IPA files or directories.

Identifies React Native, Hermes, Expo, and NativeScript bundles
and extracts them for analysis.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import List

# Hermes bytecode magic: first bytes are 0xc6, 0x1f, 0xbc, 0x03 ("HermesBC")
# or the ASCII prefix "HBC"
_HERMES_MAGIC_BYTES = b"\xc6\x1f\xbc\x03"
_HERMES_ASCII_PREFIX = b"HBC"

# Known bundle file patterns inside APK/IPA
_KNOWN_BUNDLE_PATHS = [
    "assets/index.android.bundle",
    "assets/index.android.bundle.hbc",
    "assets/main.jsbundle",
]

_BUNDLE_EXTENSIONS = {".bundle", ".jsbundle", ".hbc"}


@dataclass
class BundleInfo:
    """Metadata about a discovered JS bundle."""

    path: Path
    size_bytes: int
    bundle_type: str  # "react_native", "hermes", "expo", "nativescript", "unknown"
    is_bytecode: bool


def _detect_bundle_type(
    path: Path, content_bytes: bytes | None = None
) -> tuple[str, bool]:
    """Detect the bundle type and whether it is bytecode."""
    is_bytecode = False
    bundle_type = "unknown"

    # Check for Hermes bytecode
    if content_bytes is not None:
        header = content_bytes[:8]
    else:
        try:
            with open(path, "rb") as f:
                header = f.read(8)
        except OSError:
            return bundle_type, is_bytecode

    if header[:4] == _HERMES_MAGIC_BYTES or header[:3] == _HERMES_ASCII_PREFIX:
        return "hermes", True

    # For text content detection, read more
    if content_bytes is not None:
        sample = content_bytes[:8192]
    else:
        try:
            with open(path, "rb") as f:
                sample = f.read(8192)
        except OSError:
            return bundle_type, is_bytecode

    try:
        text_sample = sample.decode("utf-8", errors="replace")
    except Exception:
        return bundle_type, is_bytecode

    # Expo detection
    if "expo-constants" in text_sample or "expoConfig" in text_sample:
        return "expo", False

    # NativeScript detection
    if "nativescript" in text_sample.lower() or "__nativescript__" in text_sample:
        return "nativescript", False

    # React Native detection
    name = path.name.lower()
    if name in (
        "index.android.bundle",
        "index.android.bundle.hbc",
        "main.jsbundle",
    ):
        return "react_native", False

    if name.endswith((".bundle", ".jsbundle")):
        return "react_native", False

    return bundle_type, is_bytecode


def find_bundles(app_path: Path) -> List[BundleInfo]:
    """Find JS bundles in a directory, APK, or IPA.

    Parameters
    ----------
    app_path:
        Path to an APK file, IPA file, or an extracted directory.

    Returns
    -------
    list of BundleInfo
    """
    results: List[BundleInfo] = []

    if app_path.is_dir():
        results.extend(_find_bundles_in_dir(app_path))
    elif app_path.is_file() and app_path.suffix.lower() in (".apk", ".ipa", ".zip"):
        results.extend(_find_bundles_in_zip(app_path))
    elif app_path.is_file():
        # Treat as a single bundle file
        btype, is_bc = _detect_bundle_type(app_path)
        try:
            size = app_path.stat().st_size
        except OSError:
            size = 0
        results.append(
            BundleInfo(
                path=app_path,
                size_bytes=size,
                bundle_type=btype,
                is_bytecode=is_bc,
            )
        )

    return results


def _find_bundles_in_dir(directory: Path) -> List[BundleInfo]:
    """Scan a directory for known bundle file locations."""
    results: List[BundleInfo] = []

    # Check known paths
    for known in _KNOWN_BUNDLE_PATHS:
        p = directory / known
        if p.is_file():
            btype, is_bc = _detect_bundle_type(p)
            results.append(
                BundleInfo(
                    path=p,
                    size_bytes=p.stat().st_size,
                    bundle_type=btype,
                    is_bytecode=is_bc,
                )
            )

    # Also glob for any other bundle files
    for ext in _BUNDLE_EXTENSIONS:
        for p in directory.rglob(f"*{ext}"):
            if p.is_file() and not any(b.path == p for b in results):
                btype, is_bc = _detect_bundle_type(p)
                results.append(
                    BundleInfo(
                        path=p,
                        size_bytes=p.stat().st_size,
                        bundle_type=btype,
                        is_bytecode=is_bc,
                    )
                )

    return results


def _find_bundles_in_zip(zip_path: Path) -> List[BundleInfo]:
    """Find bundle files inside an APK/IPA zip archive."""
    results: List[BundleInfo] = []

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                name_lower = info.filename.lower()
                is_known = any(
                    info.filename == known or info.filename.endswith("/" + known)
                    for known in _KNOWN_BUNDLE_PATHS
                )
                has_ext = any(name_lower.endswith(ext) for ext in _BUNDLE_EXTENSIONS)

                if is_known or has_ext:
                    # Read first bytes to detect type
                    try:
                        data = zf.read(info.filename)
                        btype, is_bc = _detect_bundle_type(
                            Path(info.filename), content_bytes=data[:8192]
                        )
                    except Exception:
                        btype, is_bc = "unknown", False

                    results.append(
                        BundleInfo(
                            path=Path(info.filename),
                            size_bytes=info.file_size,
                            bundle_type=btype,
                            is_bytecode=is_bc,
                        )
                    )
    except zipfile.BadZipFile:
        pass

    return results


def extract_bundle(app_path: Path, output_dir: Path) -> List[Path]:
    """Extract bundle files from an APK/IPA zip to *output_dir*.

    Returns list of extracted file paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted: List[Path] = []

    if app_path.suffix.lower() not in (".apk", ".ipa", ".zip"):
        # Not a zip; just copy if it's a bundle file
        if app_path.is_file():
            dest = output_dir / app_path.name
            dest.write_bytes(app_path.read_bytes())
            extracted.append(dest)
        return extracted

    bundles = _find_bundles_in_zip(app_path)
    if not bundles:
        return extracted

    try:
        with zipfile.ZipFile(app_path, "r") as zf:
            for bundle in bundles:
                data = zf.read(str(bundle.path))
                dest = output_dir / Path(bundle.path).name
                dest.write_bytes(data)
                extracted.append(dest)
    except zipfile.BadZipFile:
        pass

    return extracted
