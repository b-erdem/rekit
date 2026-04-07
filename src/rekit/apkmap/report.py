"""
Report generation for apkmap scan results.

Supports two output formats:
  - **table**: Rich-formatted terminal tables with color-coded sections.
  - **json**: JSON-serializable dictionary.
"""

from __future__ import annotations

from typing import Any, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rekit.apkmap.scanners.base import ScanResult


def generate_json(result: ScanResult) -> Dict[str, Any]:
    """Return a JSON-serializable dictionary from *result*."""
    return result.to_dict()


def generate_table(result: ScanResult, console: Console | None = None) -> None:
    """
    Print a Rich table report to *console* (defaults to stdout).

    Sections:
      - Endpoints (green)
      - Base URLs (cyan)
      - Models (blue)
      - Interceptors (yellow)
      - Auth Patterns (red)
    """
    if console is None:
        console = Console()

    summary = result.to_dict()["summary"]

    # ---- summary panel ----
    summary_text = (
        f"[bold]Endpoints:[/bold] {summary['total_endpoints']}  |  "
        f"[bold]Base URLs:[/bold] {summary['total_base_urls']}  |  "
        f"[bold]Models:[/bold] {summary['total_models']}  |  "
        f"[bold]Interceptors:[/bold] {summary['total_interceptors']}  |  "
        f"[bold]Auth Patterns:[/bold] {summary['total_auth_patterns']}"
    )
    console.print(
        Panel(
            summary_text,
            title="[bold]apkmap scan summary[/bold]",
            border_style="bright_blue",
        )
    )
    console.print()

    # ---- endpoints ----
    if result.endpoints:
        table = Table(
            title="Endpoints",
            title_style="bold green",
            border_style="green",
            show_lines=True,
        )
        table.add_column("Method", style="bold", width=8)
        table.add_column("Path", style="green", min_width=30)
        table.add_column("Params", min_width=15)
        table.add_column("Return Type", min_width=12)
        table.add_column("Source", style="dim", min_width=20)

        for ep in result.endpoints:
            method_style = _method_color(ep.method)
            params_str = (
                ", ".join(
                    f"{p.get('kind', '')}({p.get('name', '')})" for p in ep.params
                )
                if ep.params
                else "-"
            )
            table.add_row(
                Text(ep.method, style=method_style),
                ep.path,
                params_str,
                ep.return_type or "-",
                ep.annotation_source,
            )

        console.print(table)
        console.print()

    # ---- base URLs ----
    if result.base_urls:
        table = Table(title="Base URLs", title_style="bold cyan", border_style="cyan")
        table.add_column("URL", style="cyan", min_width=40)
        table.add_column("Source", style="dim", min_width=20)

        for u in result.base_urls:
            table.add_row(u.get("url", ""), u.get("source", ""))

        console.print(table)
        console.print()

    # ---- models ----
    if result.models:
        table = Table(
            title="Models",
            title_style="bold blue",
            border_style="blue",
            show_lines=True,
        )
        table.add_column("Class", style="bold blue", min_width=20)
        table.add_column("Fields", min_width=40)
        table.add_column("Source", style="dim", min_width=20)

        for model in result.models:
            fields_parts = []
            for f in model.fields:
                label = f.name
                if f.json_name and f.json_name != f.name:
                    label = f"[dim]@{f.json_name}[/dim] {f.name}"
                fields_parts.append(f"{label}: {f.type}")
            fields_str = "\n".join(fields_parts) if fields_parts else "-"
            table.add_row(model.name, fields_str, model.source_file)

        console.print(table)
        console.print()

    # ---- interceptors ----
    if result.interceptors:
        table = Table(
            title="Interceptors",
            title_style="bold yellow",
            border_style="yellow",
            show_lines=True,
        )
        table.add_column("Name", style="bold yellow", min_width=20)
        table.add_column("Type", min_width=10)
        table.add_column("Headers Added", min_width=25)
        table.add_column("Source", style="dim", min_width=20)

        for ic in result.interceptors:
            headers_str = (
                ", ".join(
                    f"{h.get('name', '')}: {h.get('value_expr', h.get('value', ''))}"
                    for h in ic.headers_added
                )
                if ic.headers_added
                else "-"
            )
            type_style = "red" if ic.type == "auth" else "yellow"
            table.add_row(
                ic.name,
                Text(ic.type, style=type_style),
                headers_str,
                ic.source_file,
            )

        console.print(table)
        console.print()

    # ---- auth patterns ----
    if result.auth_patterns:
        table = Table(
            title="Auth Patterns",
            title_style="bold red",
            border_style="red",
            show_lines=True,
        )
        table.add_column("Type", style="bold red", min_width=12)
        table.add_column("Header", min_width=18)
        table.add_column("Description", min_width=30)
        table.add_column("Source", style="dim", min_width=20)

        for ap in result.auth_patterns:
            table.add_row(
                ap.type,
                ap.header_name or "-",
                ap.source_description,
                ap.source_file,
            )

        console.print(table)
        console.print()

    if not any(
        [
            result.endpoints,
            result.base_urls,
            result.models,
            result.interceptors,
            result.auth_patterns,
        ]
    ):
        console.print("[dim]No API patterns found.[/dim]")


def _method_color(method: str) -> str:
    """Return a Rich style for the HTTP method."""
    colors = {
        "GET": "green",
        "POST": "yellow",
        "PUT": "blue",
        "DELETE": "red",
        "PATCH": "magenta",
        "HEAD": "cyan",
        "OPTIONS": "dim",
        "UNKNOWN": "dim italic",
    }
    return colors.get(method.upper(), "white")
