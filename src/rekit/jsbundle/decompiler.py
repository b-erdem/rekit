"""
Handle Hermes bytecode decompilation and basic JS beautification.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

# Hermes bytecode magic bytes
_HERMES_MAGIC_BYTES = b"\xc6\x1f\xbc\x03"
_HERMES_ASCII_PREFIX = b"HBC"


def is_hermes_bytecode(data: bytes) -> bool:
    """Check if *data* starts with Hermes bytecode magic bytes."""
    if len(data) < 4:
        return False
    return data[:4] == _HERMES_MAGIC_BYTES or data[:3] == _HERMES_ASCII_PREFIX


def decompile_hermes(path: Path, output_path: Path) -> Optional[Path]:
    """Attempt to decompile Hermes bytecode using available tools.

    Tries ``hbc-decompiler`` and ``hermes-dec`` in order. Returns the
    path to the decompiled output, or *None* if no tool is available.
    """
    # Try hbc-decompiler first
    hbc_decompiler = shutil.which("hbc-decompiler")
    if hbc_decompiler:
        import subprocess

        try:
            subprocess.run(
                [hbc_decompiler, str(path), str(output_path)],
                check=True,
                capture_output=True,
                timeout=120,
            )
            if output_path.exists():
                return output_path
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    # Try hermes-dec
    hermes_dec = shutil.which("hermes-dec")
    if hermes_dec:
        import subprocess

        try:
            subprocess.run(
                [hermes_dec, str(path), "-o", str(output_path)],
                check=True,
                capture_output=True,
                timeout=120,
            )
            if output_path.exists():
                return output_path
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    return None


def try_beautify(content: str) -> str:
    """Basic JS beautification for minified code.

    Not a full beautifier -- just adds newlines and simple indentation
    to make the code grep-friendly.
    """
    result: list[str] = []
    indent = 0
    i = 0
    line_buf: list[str] = []

    while i < len(content):
        ch = content[i]

        # Handle string literals -- don't break inside them
        if ch in ('"', "'", "`"):
            quote = ch
            line_buf.append(ch)
            i += 1
            while i < len(content) and content[i] != quote:
                if content[i] == "\\" and i + 1 < len(content):
                    line_buf.append(content[i])
                    i += 1
                line_buf.append(content[i])
                i += 1
            if i < len(content):
                line_buf.append(content[i])
                i += 1
            continue

        if ch == "{":
            line_buf.append(ch)
            result.append("  " * indent + "".join(line_buf).strip())
            line_buf = []
            indent += 1
            i += 1
            continue

        if ch == "}":
            if line_buf and "".join(line_buf).strip():
                result.append("  " * indent + "".join(line_buf).strip())
                line_buf = []
            indent = max(0, indent - 1)
            result.append("  " * indent + "}")
            i += 1
            continue

        if ch == ";":
            line_buf.append(ch)
            result.append("  " * indent + "".join(line_buf).strip())
            line_buf = []
            i += 1
            continue

        if ch == "\n":
            if line_buf and "".join(line_buf).strip():
                result.append("  " * indent + "".join(line_buf).strip())
                line_buf = []
            i += 1
            continue

        line_buf.append(ch)
        i += 1

    # Flush remaining
    if line_buf and "".join(line_buf).strip():
        result.append("  " * indent + "".join(line_buf).strip())

    return "\n".join(result)
