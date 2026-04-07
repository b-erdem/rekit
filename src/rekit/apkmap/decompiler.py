"""
APK decompilation via jadx.

Provides a thin wrapper around the ``jadx`` command-line tool to decompile
Android APK files into Java source code that the scanners can process.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from rich.console import Console

_console = Console(stderr=True)


class JadxNotFoundError(RuntimeError):
    """Raised when the jadx binary cannot be located."""


class DecompilationError(RuntimeError):
    """Raised when jadx exits with a non-zero status."""


def _find_jadx(jadx_path: str = "jadx") -> str:
    """
    Resolve the jadx binary path.

    Parameters
    ----------
    jadx_path:
        Explicit path or just ``"jadx"`` to search ``$PATH``.

    Returns
    -------
    str
        Absolute path to the jadx binary.

    Raises
    ------
    JadxNotFoundError
        If jadx cannot be found.
    """
    resolved = shutil.which(jadx_path)
    if resolved:
        return resolved

    # Common install locations
    common_paths = [
        Path.home() / "jadx" / "bin" / "jadx",
        Path.home() / ".local" / "bin" / "jadx",
        Path("/usr/local/bin/jadx"),
        Path("/opt/jadx/bin/jadx"),
        Path("/opt/homebrew/bin/jadx"),
    ]
    for p in common_paths:
        if p.is_file():
            return str(p)

    raise JadxNotFoundError(
        f"jadx not found at '{jadx_path}' or in common locations.\n"
        "Install jadx:\n"
        "  - macOS:  brew install jadx\n"
        "  - Linux:  https://github.com/skylot/jadx/releases\n"
        "  - Or specify the path with --jadx-path"
    )


def decompile(
    apk_path: Path,
    output_dir: Optional[Path] = None,
    jadx_path: str = "jadx",
) -> Path:
    """
    Decompile an APK file using jadx.

    Parameters
    ----------
    apk_path:
        Path to the ``.apk`` file.
    output_dir:
        Directory to write decompiled sources into.  If ``None``, a
        temporary directory is created (caller is responsible for cleanup).
    jadx_path:
        Path to the jadx binary (default: search ``$PATH``).

    Returns
    -------
    Path
        The directory containing the decompiled source tree.

    Raises
    ------
    JadxNotFoundError
        If jadx is not installed or cannot be found.
    DecompilationError
        If jadx returns a non-zero exit code.
    FileNotFoundError
        If *apk_path* does not exist.
    """
    apk_path = Path(apk_path).resolve()
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    jadx_bin = _find_jadx(jadx_path)

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="apkmap_"))
    else:
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

    _console.print(f"[bold]Decompiling[/bold] {apk_path.name} with jadx ...")

    cmd = [
        jadx_bin,
        "--no-res",         # skip resources (we only need source)
        "--deobf",          # apply deobfuscation
        "--threads-count", "4",
        "--output-dir", str(output_dir),
        str(apk_path),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout for large APKs
        )
    except subprocess.TimeoutExpired:
        raise DecompilationError(
            f"jadx timed out after 600 seconds while decompiling {apk_path.name}"
        )
    except OSError as exc:
        raise DecompilationError(f"Failed to run jadx: {exc}")

    if proc.returncode != 0:
        # jadx sometimes returns non-zero but still produces partial output
        # Check if source directory exists and has content
        sources_dir = output_dir / "sources"
        if sources_dir.is_dir() and any(sources_dir.iterdir()):
            _console.print(
                "[yellow]Warning:[/yellow] jadx reported errors but produced partial output. "
                "Continuing with available source."
            )
        else:
            stderr_snippet = proc.stderr[:2000] if proc.stderr else "(no stderr)"
            raise DecompilationError(
                f"jadx failed (exit code {proc.returncode}):\n{stderr_snippet}"
            )
    else:
        _console.print("[green]Decompilation complete.[/green]")

    # jadx puts Java source under <output>/sources/
    sources_dir = output_dir / "sources"
    if sources_dir.is_dir():
        return sources_dir

    # Fallback: return the output dir itself
    return output_dir
