"""
apkmap CLI — typer subcommand group.

Usage:
    rekit apkmap scan ./app.apk -o report.json --format json
    rekit apkmap scan ./decompiled_source/ --format table
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from rekit.apkmap.scanners import ALL_SCANNERS, ScanResult
from rekit.apkmap.decompiler import decompile, JadxNotFoundError, DecompilationError
from rekit.apkmap.report import generate_json, generate_table

app = typer.Typer(
    name="apkmap",
    help="Scan decompiled APK source and map API endpoints, models, and auth.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

_console = Console(stderr=True)


@app.command("scan")
def scan(
    path: Path = typer.Argument(..., help="Path to APK file or decompiled source directory"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report to this file"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
    jadx_path: str = typer.Option("jadx", "--jadx-path", help="Path to jadx binary"),
) -> None:
    """Scan an APK or decompiled source directory for API patterns."""
    _run_scan(path, output, fmt, jadx_path)


def _run_scan(
    path: Path,
    output: Optional[Path],
    fmt: str,
    jadx_path: str,
) -> None:
    """Core scan logic shared by the callback and the explicit ``scan`` command."""
    path = path.resolve()

    if not path.exists():
        _console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(code=1)

    # ---- Determine source directory ----
    if path.is_file():
        if path.suffix.lower() not in (".apk",):
            _console.print(f"[red]Error:[/red] expected an .apk file or a directory, got: {path.name}")
            raise typer.Exit(code=1)

        try:
            source_dir = decompile(path, jadx_path=jadx_path)
        except JadxNotFoundError as exc:
            _console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1)
        except DecompilationError as exc:
            _console.print(f"[red]Decompilation failed:[/red] {exc}")
            raise typer.Exit(code=1)
    elif path.is_dir():
        source_dir = path
    else:
        _console.print(f"[red]Error:[/red] path is neither a file nor a directory: {path}")
        raise typer.Exit(code=1)

    # ---- Run scanners ----
    merged = ScanResult()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=_console,
    ) as progress:
        task = progress.add_task("Scanning ...", total=len(ALL_SCANNERS))

        for scanner_cls in ALL_SCANNERS:
            scanner = scanner_cls()
            progress.update(task, description=f"Running {scanner.name} scanner ...")
            result = scanner.scan(source_dir)
            merged.merge(result)
            progress.advance(task)

        progress.update(task, description="Scan complete.")

    # ---- Output ----
    out_console = Console()

    if fmt == "json":
        data = generate_json(merged)
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        if output:
            output.write_text(json_str, encoding="utf-8")
            _console.print(f"[green]Report written to[/green] {output}")
        else:
            out_console.print_json(json_str)
    elif fmt == "table":
        generate_table(merged, console=out_console)
        if output:
            # Also write JSON to the file when --output is given with table format
            data = generate_json(merged)
            output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            _console.print(f"[green]JSON report also written to[/green] {output}")
    else:
        _console.print(f"[red]Unknown format:[/red] {fmt}. Use 'table' or 'json'.")
        raise typer.Exit(code=1)

    # Print summary to stderr
    s = merged.to_dict()["summary"]
    _console.print(
        f"\n[bold]Found:[/bold] "
        f"{s['total_endpoints']} endpoints, "
        f"{s['total_base_urls']} base URLs, "
        f"{s['total_models']} models, "
        f"{s['total_interceptors']} interceptors, "
        f"{s['total_auth_patterns']} auth patterns"
    )
