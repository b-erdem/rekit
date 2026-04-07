"""
ratelim CLI -- systematically probe API rate limits.

Usage:
    rekit ratelim probe https://api.example.com/endpoint
    rekit ratelim search https://api.example.com/endpoint --low 1 --high 50
    rekit ratelim headers https://api.example.com/endpoint
"""

from __future__ import annotations

import json
from typing import List, Optional

import typer
from rich.console import Console

app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="[bold]ratelim[/bold] -- Systematically probe API rate limits.",
)

console = Console()


def _parse_header_args(header: Optional[List[str]]) -> dict[str, str]:
    """Turn ``["Key: Value", ...]`` into a dict."""
    out: dict[str, str] = {}
    if not header:
        return out
    for h in header:
        if ":" not in h:
            console.print(
                f"[red]Error:[/red] Invalid header format: {h!r} (expected 'Key: Value')"
            )
            raise typer.Exit(1)
        key, _, value = h.partition(":")
        out[key.strip()] = value.strip()
    return out


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------


@app.command("probe")
def probe(
    url: str = typer.Argument(..., help="Target URL to probe"),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method"),
    max_requests: int = typer.Option(
        50, "--max-requests", "-n", help="Maximum requests to send"
    ),
    rps: float = typer.Option(5.0, "--rps", "-r", help="Requests per second"),
    header: Optional[List[str]] = typer.Option(
        None, "--header", "-H", help="Header in 'Key: Value' format"
    ),
    format: str = typer.Option(
        "panel", "--format", "-f", help="Output format: panel, json"
    ),
) -> None:
    """Probe rate limits by sending controlled request bursts."""
    from rekit.ratelim.prober import probe_rate_limit
    from rekit.ratelim.display import (
        format_probe_result,
        format_rate_limit_headers,
        format_recommendation,
    )

    headers = _parse_header_args(header)

    console.print(f"\n[bold]ratelim[/bold] probing [cyan]{url}[/cyan]")
    console.print(f"Method: {method}  |  Max requests: {max_requests}  |  RPS: {rps}\n")

    result = probe_rate_limit(
        url,
        method=method,
        headers=headers or None,
        max_requests=max_requests,
        rps=rps,
    )

    if format == "json":
        import dataclasses

        data = dataclasses.asdict(result)
        console.print_json(json.dumps(data, default=str))
    else:
        console.print(format_probe_result(result))
        if result.rate_limit_info:
            console.print(format_rate_limit_headers(result.rate_limit_info))
        console.print(format_recommendation(result))


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


@app.command("search")
def search(
    url: str = typer.Argument(..., help="Target URL to probe"),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method"),
    low: float = typer.Option(1.0, "--low", help="Low end of RPS range"),
    high: float = typer.Option(50.0, "--high", help="High end of RPS range"),
    header: Optional[List[str]] = typer.Option(
        None, "--header", "-H", help="Header in 'Key: Value' format"
    ),
) -> None:
    """Binary search for rate limit threshold."""
    from rekit.ratelim.prober import binary_search_limit
    from rekit.ratelim.display import format_probe_result, format_recommendation

    headers = _parse_header_args(header)

    console.print(f"\n[bold]ratelim search[/bold] [cyan]{url}[/cyan]")
    console.print(f"Searching between {low} and {high} RPS ...\n")

    result = binary_search_limit(
        url,
        method=method,
        headers=headers or None,
        low_rps=low,
        high_rps=high,
    )

    console.print(format_probe_result(result))
    console.print(format_recommendation(result))


# ---------------------------------------------------------------------------
# headers
# ---------------------------------------------------------------------------


@app.command("headers")
def headers_cmd(
    url: str = typer.Argument(..., help="Target URL"),
) -> None:
    """Make a single request and show rate limit headers."""
    import requests as req_lib
    from rekit.ratelim.prober import parse_rate_limit_headers
    from rekit.ratelim.display import format_rate_limit_headers

    console.print(f"\n[bold]ratelim headers[/bold] [cyan]{url}[/cyan]\n")

    try:
        resp = req_lib.get(url, timeout=10.0, allow_redirects=False)
    except req_lib.RequestException as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    info = parse_rate_limit_headers(dict(resp.headers))
    if info:
        console.print(format_rate_limit_headers(info))
    else:
        console.print("[yellow]No rate limit headers found in response.[/yellow]")

    # Show all response headers for reference
    from rich.table import Table

    table = Table(title="All Response Headers", show_lines=False)
    table.add_column("Header", style="cyan")
    table.add_column("Value")
    for k, v in resp.headers.items():
        table.add_row(k, v)
    console.print(table)
