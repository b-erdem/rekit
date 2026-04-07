"""
hargen.cli — Typer CLI subcommand group for hargen.

Commands:
  generate  Generate a typed Python API client from captured HTTP traffic.
  inspect   Show a summary of captured traffic without generating code.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(
    name="hargen",
    help="Generate typed Python API clients from captured HTTP traffic (HAR / mitmproxy).",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


@app.callback(invoke_without_command=True)
def _callback(ctx: typer.Context) -> None:
    """hargen — generate typed Python API clients from captured HTTP traffic."""
    if ctx.invoked_subcommand is None:
        # Default to generate if no subcommand given but we have args
        pass


@app.command()
def generate(
    input_file: Path = typer.Argument(
        ...,
        help="Path to HAR file (.har) or mitmproxy flow file (.flow, .mitm).",
        exists=True,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        "./generated_client",
        "--output", "-o",
        help="Output directory for generated client code.",
    ),
    base_url: Optional[str] = typer.Option(
        None,
        "--base-url", "-b",
        help="Filter traffic to this base URL only (e.g., https://api.example.com).",
    ),
    name: str = typer.Option(
        "ApiClient",
        "--name", "-n",
        help="Name for the generated client class.",
    ),
    package_name: str = typer.Option(
        "api_client",
        "--package", "-p",
        help="Python package name for generated imports.",
    ),
) -> None:
    """
    Generate a typed Python API client from captured HTTP traffic.

    Parses the input file, analyzes endpoint patterns, and generates
    a client package with typed models and methods.
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn

    from rekit.hargen.parser import parse_traffic
    from rekit.hargen.analyzer import analyze
    from rekit.hargen.generator import generate_client

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        # Parse
        task = progress.add_task("Parsing traffic capture...", total=None)
        try:
            exchanges = parse_traffic(input_file)
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from exc

        if not exchanges:
            console.print("[yellow]No HTTP exchanges found in the input file.[/yellow]")
            raise typer.Exit(code=1)

        progress.update(task, description=f"Parsed {len(exchanges)} exchanges")

        # Analyze
        progress.update(task, description="Analyzing endpoint patterns...")
        spec = analyze(exchanges, base_url_filter=base_url)

        if not spec.endpoints:
            console.print(
                "[yellow]No endpoints detected.[/yellow] "
                "Try specifying --base-url to filter traffic."
            )
            raise typer.Exit(code=1)

        progress.update(
            task,
            description=f"Found {len(spec.endpoints)} endpoints at {spec.base_url}",
        )

        # Generate
        progress.update(task, description="Generating client code...")
        result_dir = generate_client(
            spec,
            output_dir=output_dir,
            client_name=name,
            package_name=package_name,
        )

    # Summary
    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Client generated successfully![/bold green]\n\n"
            f"  Base URL:   {spec.base_url}\n"
            f"  Endpoints:  {len(spec.endpoints)}\n"
            f"  Output:     {result_dir}\n\n"
            f"  [dim]from {package_name}.client import {name}[/dim]",
            title="hargen",
            border_style="green",
        )
    )


@app.command()
def inspect(
    input_file: Path = typer.Argument(
        ...,
        help="Path to HAR file (.har) or mitmproxy flow file (.flow, .mitm).",
        exists=True,
        readable=True,
    ),
    base_url: Optional[str] = typer.Option(
        None,
        "--base-url", "-b",
        help="Filter traffic to this base URL only.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Show detailed information including headers and schemas.",
    ),
) -> None:
    """
    Inspect captured traffic and show a summary without generating code.

    Displays endpoints, methods, response codes, and detected patterns.
    """
    from collections import Counter
    from urllib.parse import urlparse

    from rekit.hargen.parser import parse_traffic
    from rekit.hargen.analyzer import analyze

    try:
        exchanges = parse_traffic(input_file)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not exchanges:
        console.print("[yellow]No HTTP exchanges found in the input file.[/yellow]")
        raise typer.Exit(code=1)

    # --- Raw traffic summary ---
    console.print(
        Panel.fit(
            f"[bold]{input_file.name}[/bold] — {len(exchanges)} exchanges",
            title="Traffic Summary",
            border_style="blue",
        )
    )

    # Host breakdown
    host_counts: Counter[str] = Counter()
    method_counts: Counter[str] = Counter()
    status_counts: Counter[int] = Counter()

    for ex in exchanges:
        parsed = urlparse(ex.url)
        host_counts[f"{parsed.scheme}://{parsed.netloc}"] += 1
        method_counts[ex.method] += 1
        if ex.status_code > 0:
            status_counts[ex.status_code] += 1

    # Hosts table
    host_table = Table(title="Hosts", show_lines=False)
    host_table.add_column("Base URL", style="cyan")
    host_table.add_column("Requests", justify="right")
    for host, count in host_counts.most_common(20):
        host_table.add_row(host, str(count))
    console.print(host_table)

    # Methods & status codes
    console.print()
    methods_str = "  ".join(
        f"[bold]{m}[/bold] {c}" for m, c in method_counts.most_common()
    )
    console.print(f"[dim]Methods:[/dim]  {methods_str}")

    status_str = "  ".join(
        f"[{'green' if 200 <= s < 300 else 'yellow' if 300 <= s < 400 else 'red'}]{s}[/] {c}"
        for s, c in sorted(status_counts.items())
    )
    console.print(f"[dim]Status:[/dim]   {status_str}")

    # --- Analyzed endpoints ---
    spec = analyze(exchanges, base_url_filter=base_url)

    if not spec.endpoints:
        console.print(
            "\n[yellow]No endpoint patterns detected.[/yellow] "
            "Try specifying --base-url to focus analysis."
        )
        return

    console.print()
    ep_table = Table(title=f"Endpoints ({spec.base_url})", show_lines=True)
    ep_table.add_column("Method", style="bold")
    ep_table.add_column("Path Pattern", style="cyan")
    ep_table.add_column("Requests", justify="right")
    ep_table.add_column("Status Codes")
    ep_table.add_column("Query Params")
    ep_table.add_column("Response Type")

    for ep in spec.endpoints:
        method_color = {
            "GET": "green",
            "POST": "yellow",
            "PUT": "blue",
            "PATCH": "magenta",
            "DELETE": "red",
        }.get(ep.method, "white")

        status_display = ", ".join(str(s) for s in ep.status_codes)
        qp_display = ", ".join(qp.name for qp in ep.query_params) or "-"
        resp_type = "JSON" if ep.response_schema else "Other"

        ep_table.add_row(
            f"[{method_color}]{ep.method}[/]",
            ep.path_pattern,
            str(ep.request_count),
            status_display,
            qp_display,
            resp_type,
        )

    console.print(ep_table)

    # Verbose: show headers and schemas
    if verbose:
        console.print()
        if spec.auth_headers:
            console.print("[bold]Auth Headers:[/bold]")
            for h in spec.auth_headers:
                console.print(f"  [red]{h.name}[/red]: {h.example_value}")

        if spec.common_headers:
            console.print("[bold]Common Headers:[/bold]")
            for h in spec.common_headers:
                tag = f"[dim]({h.classification})[/dim]"
                console.print(f"  {h.name}: {h.example_value} {tag}")

        console.print()
        for ep in spec.endpoints:
            console.print(
                f"[bold]{ep.method} {ep.path_pattern}[/bold]"
            )
            if ep.path_params:
                console.print(
                    f"  Path params: {', '.join(p.name + ':' + p.type_str for p in ep.path_params)}"
                )
            if ep.query_params:
                for qp in ep.query_params:
                    req = "required" if qp.required else "optional"
                    examples = ", ".join(qp.example_values[:3])
                    console.print(
                        f"  Query: {qp.name} ({qp.type_str}, {req}) e.g. {examples}"
                    )
            if ep.response_schema:
                console.print("  Response fields:")
                for fs in ep.response_schema[:15]:
                    opt = " (optional)" if fs.optional else ""
                    console.print(f"    {fs.name}: {fs.type_str}{opt}")
                if len(ep.response_schema) > 15:
                    console.print(
                        f"    ... and {len(ep.response_schema) - 15} more fields"
                    )
            console.print()
