"""tokendump CLI — extract and analyze authentication tokens from HAR traffic."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console

from rekit.tokendump.extractor import TokenType

app = typer.Typer(
    name="tokendump",
    help="Extract and analyze authentication tokens from captured HTTP traffic.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _json_serializer(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, TokenType):
        return obj.value
    raise TypeError(f"Cannot serialize {type(obj)}")


@app.command("extract")
def extract(
    har_file: Path = typer.Argument(..., help="Path to HAR file to analyze"),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, detail"
    ),
    show_values: bool = typer.Option(
        False, "--show-values", help="Show full token values (default: masked)"
    ),
    jwt_only: bool = typer.Option(
        False, "--jwt-only", help="Only show JWTs with decoded details"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
) -> None:
    """Extract authentication tokens from a [bold]HAR file[/bold].

    Scans request/response headers and JSON bodies for JWTs, OAuth tokens,
    API keys, session cookies, CSRF tokens, and other credentials.
    """
    from rekit.hargen.parser import parse_har
    from rekit.tokendump.analyzer import (
        analyze_tokens,
        format_chain_diagram,
        format_jwt_details,
        format_token_table,
    )
    from rekit.tokendump.extractor import extract_tokens, mask_token

    if not har_file.exists():
        console.print(f"[red]Error:[/red] HAR file not found: {har_file}")
        raise typer.Exit(code=1)

    with console.status("[bold]Parsing HAR file...[/bold]"):
        exchanges = parse_har(har_file)

    if not exchanges:
        console.print("[yellow]No HTTP exchanges found in HAR file.[/yellow]")
        raise typer.Exit()

    tokens = extract_tokens(exchanges)

    if jwt_only:
        tokens = [t for t in tokens if t.token_type == TokenType.JWT]

    if not tokens:
        console.print("[yellow]No tokens found in captured traffic.[/yellow]")
        raise typer.Exit()

    report = analyze_tokens(tokens)

    if format == "json":
        data = []
        for tok in report.tokens:
            d = asdict(tok)
            d["token_type"] = tok.token_type.value
            if not show_values:
                d["value"] = mask_token(tok.value)
            data.append(d)
        json_output = json.dumps(data, indent=2, default=_json_serializer)
        if output:
            Path(output).write_text(json_output, encoding="utf-8")
            console.print(f"[dim]JSON written to {output}[/dim]")
        else:
            console.print(json_output)

    elif format == "detail":
        # Show table + JWT details + chains
        table = format_token_table(report, show_values=show_values)
        console.print(table)
        console.print()

        # JWT details
        seen_jwts: set[str] = set()
        for tok in report.tokens:
            if tok.token_type == TokenType.JWT and tok.value not in seen_jwts:
                seen_jwts.add(tok.value)
                panel = format_jwt_details(tok)
                console.print(panel)
                console.print()

        # Chains
        if report.chains:
            console.print("[bold]Token Chains:[/bold]")
            for chain in report.chains:
                console.print(format_chain_diagram(chain))
                console.print()

        console.print(f"\n[dim]{report.summary}[/dim]")

    else:
        # Default table format
        table = format_token_table(report, show_values=show_values)
        console.print(table)
        console.print(f"\n[dim]{report.summary}[/dim]")


@app.command("decode")
def decode(
    token: str = typer.Argument(..., help="Raw JWT string to decode"),
) -> None:
    """Decode a raw [bold]JWT[/bold] string and display its contents.

    Parses the header and payload without verifying the signature.
    """
    from rekit.tokendump.extractor import _decode_jwt

    result = _decode_jwt(token)
    if result is None:
        console.print(
            "[red]Error:[/red] Not a valid JWT (expected 3 dot-separated base64url segments)."
        )
        raise typer.Exit(code=1)

    console.print("[bold cyan]Header:[/bold cyan]")
    console.print_json(json.dumps(result["header"], indent=2))
    console.print()
    console.print("[bold cyan]Payload:[/bold cyan]")
    console.print_json(
        json.dumps(result["payload"], indent=2, default=_json_serializer)
    )
