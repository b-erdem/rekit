"""authmap CLI — map authentication flows from captured HAR traffic."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="authmap",
    help="Map authentication flows from captured HTTP traffic.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


@app.command("detect")
def detect(
    har_file: Path = typer.Argument(..., help="Path to HAR file to analyze"),
    format: str = typer.Option(
        "diagram", "--format", "-f", help="Output format: table, json, diagram"
    ),
) -> None:
    """Detect authentication flows in a [bold]HAR file[/bold].

    Analyzes captured HTTP traffic to identify OAuth2, API key,
    session cookie, and other authentication patterns.
    """
    from rekit.authmap.detector import detect_auth_flows
    from rekit.authmap.display import render_flows
    from rekit.hargen.parser import parse_har

    if not har_file.exists():
        console.print(f"[red]Error:[/red] HAR file not found: {har_file}")
        raise typer.Exit(code=1)

    with console.status("[bold]Parsing HAR file...[/bold]"):
        exchanges = parse_har(har_file)

    if not exchanges:
        console.print("[yellow]No HTTP exchanges found in HAR file.[/yellow]")
        raise typer.Exit()

    with console.status("[bold]Detecting authentication flows...[/bold]"):
        flows = detect_auth_flows(exchanges)

    render_flows(flows, format=format)


@app.command("generate")
def generate(
    har_file: Path = typer.Argument(..., help="Path to HAR file to analyze"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path (default: stdout)"
    ),
    class_name: str = typer.Option(
        "ApiAuth", "--class-name", "-c", help="Name for the generated auth class"
    ),
) -> None:
    """Generate a Python auth module from a [bold]HAR file[/bold].

    Produces a reusable Python class that handles authentication based
    on the detected flow patterns in the captured traffic.
    """
    from rekit.authmap.detector import detect_auth_flows
    from rekit.authmap.generator import generate_auth_module
    from rekit.hargen.parser import parse_har

    if not har_file.exists():
        console.print(f"[red]Error:[/red] HAR file not found: {har_file}")
        raise typer.Exit(code=1)

    with console.status("[bold]Parsing HAR file...[/bold]"):
        exchanges = parse_har(har_file)

    if not exchanges:
        console.print("[yellow]No HTTP exchanges found in HAR file.[/yellow]")
        raise typer.Exit()

    with console.status("[bold]Detecting authentication flows...[/bold]"):
        flows = detect_auth_flows(exchanges)

    code = generate_auth_module(flows, class_name=class_name)

    if output:
        output.write_text(code, encoding="utf-8")
        console.print(f"[green]Auth module written to {output}[/green]")
    else:
        console.print(code)
