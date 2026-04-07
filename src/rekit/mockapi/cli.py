"""mockapi.cli — Typer CLI subcommand group for mockapi.

Commands:
  serve    Start a mock HTTP server from captured HAR traffic.
  inspect  Show endpoints that would be served without starting the server.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="mockapi",
    help="Generate and run a mock HTTP server from captured HAR traffic.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


@app.callback(invoke_without_command=True)
def _callback(ctx: typer.Context) -> None:
    """mockapi — generate and run a mock HTTP server from captured HAR traffic."""
    if ctx.invoked_subcommand is None:
        pass


@app.command("serve")
def serve(
    har_file: Path = typer.Argument(
        ...,
        help="Path to HAR file (.har).",
        exists=True,
        readable=True,
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        "-H",
        help="Host to bind the server to.",
    ),
    port: int = typer.Option(
        8080,
        "--port",
        "-p",
        help="Port to bind the server to.",
    ),
    mode: str = typer.Option(
        "sequential",
        "--mode",
        "-m",
        help="Response selection mode: sequential or random.",
    ),
    error_rate: float = typer.Option(
        0.0,
        "--error-rate",
        help="Probability (0.0-1.0) of returning a 500 error.",
    ),
    latency: bool = typer.Option(
        True,
        "--latency/--no-latency",
        help="Simulate original response latency.",
    ),
    stateful: bool = typer.Option(
        False,
        "--stateful",
        help="Enable stateful mode (POST stores, GET retrieves).",
    ),
    cors: bool = typer.Option(
        True,
        "--cors/--no-cors",
        help="Enable CORS headers.",
    ),
    watch: bool = typer.Option(
        False,
        "--watch",
        "-w",
        help="Hot reload when HAR file changes.",
    ),
) -> None:
    """Start a mock HTTP server replaying captured HAR traffic.

    Parses the HAR file, groups exchanges into endpoints, and serves
    recorded responses for matching incoming requests.
    """
    from rekit.mockapi.server import MockServer

    server = MockServer(
        host=host,
        port=port,
        error_rate=error_rate,
    )
    server.mode = mode
    server.simulate_latency = latency
    server.cors = cors
    server.stateful = stateful
    server.watch = watch

    try:
        server.load_har(har_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not server.endpoints:
        console.print("[yellow]No endpoints found in HAR file.[/yellow]")
        raise typer.Exit(code=1)

    # Print endpoint table
    _print_endpoint_table(server)

    console.print(
        f"\n[bold green]Mock server starting on http://{host}:{port}[/bold green]"
    )
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    server.run()


@app.command("inspect")
def inspect(
    har_file: Path = typer.Argument(
        ...,
        help="Path to HAR file (.har).",
        exists=True,
        readable=True,
    ),
) -> None:
    """Inspect endpoints in a HAR file without starting the server.

    Shows a summary table of all endpoints that would be served.
    """
    from rekit.mockapi.server import MockServer

    server = MockServer()

    try:
        server.load_har(har_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not server.endpoints:
        console.print("[yellow]No endpoints found in HAR file.[/yellow]")
        raise typer.Exit(code=1)

    _print_endpoint_table(server)


def _print_endpoint_table(server: object) -> None:
    """Print a Rich table summarising the server's endpoints."""
    table = Table(title="Mock Endpoints", show_lines=True)
    table.add_column("Method", style="bold")
    table.add_column("Path Pattern", style="cyan")
    table.add_column("Responses", justify="right")
    table.add_column("Status Codes")

    for ep in sorted(server.endpoints, key=lambda e: (e.path_pattern, e.method)):
        method_color = {
            "GET": "green",
            "POST": "yellow",
            "PUT": "blue",
            "PATCH": "magenta",
            "DELETE": "red",
        }.get(ep.method, "white")

        status_codes = sorted(set(r.status_code for r in ep.responses))
        status_display = ", ".join(str(s) for s in status_codes)

        table.add_row(
            f"[{method_color}]{ep.method}[/]",
            ep.path_pattern,
            str(len(ep.responses)),
            status_display,
        )

    console.print(table)
