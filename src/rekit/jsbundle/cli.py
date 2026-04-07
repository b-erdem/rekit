"""
CLI interface for jsbundle -- analyze JS bundles from mobile apps.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from rekit.jsbundle.analyzer import (
    JSAnalysis,
    analyze_bundle,
    analyze_bundle_file,
    mask_secret,
)
from rekit.jsbundle.extractor import extract_bundle, find_bundles

app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


def _read_and_analyze(path: Path) -> JSAnalysis:
    """Read a bundle file (or all bundles from APK/IPA/dir) and analyze."""
    # If it's a single JS/bundle file, analyze directly
    if path.is_file() and path.suffix.lower() not in (".apk", ".ipa", ".zip"):
        return analyze_bundle_file(path)

    # Otherwise find bundles and analyze each
    bundles = find_bundles(path)
    if not bundles:
        console.print("[yellow]No JS bundles found.[/yellow]")
        raise typer.Exit(1)

    combined = JSAnalysis()
    for bundle in bundles:
        if bundle.is_bytecode:
            console.print(
                f"[yellow]Skipping bytecode bundle {bundle.path} "
                f"(decompile first with hermes-dec or hbc-decompiler)[/yellow]"
            )
            continue

        # Read the bundle content
        if path.is_dir() or (
            path.is_file() and path.suffix.lower() not in (".apk", ".ipa", ".zip")
        ):
            content = bundle.path.read_text(errors="replace")
        else:
            # Extract from zip
            import zipfile

            with zipfile.ZipFile(path, "r") as zf:
                content = zf.read(str(bundle.path)).decode("utf-8", errors="replace")

        analysis = analyze_bundle(content)
        _merge_analysis(combined, analysis)

    return combined


def _merge_analysis(target: JSAnalysis, source: JSAnalysis) -> None:
    """Merge source analysis into target."""
    target.endpoints.extend(source.endpoints)
    target.api_base_urls.extend(source.api_base_urls)
    target.auth_patterns.extend(source.auth_patterns)
    target.hardcoded_secrets.extend(source.hardcoded_secrets)
    target.graphql_operations.extend(source.graphql_operations)
    target.env_configs.extend(source.env_configs)
    target.fetch_calls.extend(source.fetch_calls)
    target.navigation_api_map.extend(source.navigation_api_map)


def _render_table(analysis: JSAnalysis, show_secrets: bool) -> None:
    """Render analysis results as rich tables."""
    # API Endpoints
    if analysis.endpoints:
        table = Table(title="API Endpoints", show_lines=True)
        table.add_column("Method", style="cyan", width=8)
        table.add_column("URL / Path", style="green")
        table.add_column("Source", style="dim")
        for ep in analysis.endpoints:
            table.add_row(ep.method, ep.path, ep.annotation_source)
        console.print(table)
        console.print()

    # Base URLs
    if analysis.api_base_urls:
        table = Table(title="API Base URLs", show_lines=True)
        table.add_column("URL", style="green")
        for url in analysis.api_base_urls:
            table.add_row(url)
        console.print(table)
        console.print()

    # Auth Patterns
    if analysis.auth_patterns:
        table = Table(title="Auth Patterns", show_lines=True)
        table.add_column("Type", style="cyan")
        table.add_column("Header", style="yellow")
        table.add_column("Description")
        for ap in analysis.auth_patterns:
            table.add_row(ap.type, ap.header_name or "", ap.source_description)
        console.print(table)
        console.print()

    # Hardcoded Secrets
    if analysis.hardcoded_secrets:
        table = Table(title="Hardcoded Secrets", show_lines=True)
        table.add_column("Key", style="red")
        table.add_column("Value", style="yellow")
        table.add_column("Line", style="dim", width=6)
        for secret in analysis.hardcoded_secrets:
            value = secret["value"] if show_secrets else mask_secret(secret["value"])
            table.add_row(secret["key"], value, str(secret["line_approx"]))
        console.print(table)
        console.print()

    # GraphQL Operations
    if analysis.graphql_operations:
        table = Table(title="GraphQL Operations", show_lines=True)
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="yellow")
        for op in analysis.graphql_operations:
            table.add_row(op["name"], op["type"])
        console.print(table)
        console.print()

    # Environment Config
    if analysis.env_configs:
        table = Table(title="Environment Config", show_lines=True)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")
        for cfg in analysis.env_configs:
            table.add_row(cfg["key"], cfg["value"])
        console.print(table)
        console.print()

    # Summary
    console.print("[bold]Summary:[/bold]")
    console.print(f"  Endpoints: {len(analysis.endpoints)}")
    console.print(f"  Base URLs: {len(analysis.api_base_urls)}")
    console.print(f"  Auth patterns: {len(analysis.auth_patterns)}")
    console.print(f"  Secrets: {len(analysis.hardcoded_secrets)}")
    console.print(f"  GraphQL ops: {len(analysis.graphql_operations)}")
    console.print(f"  Env configs: {len(analysis.env_configs)}")


def _to_json(analysis: JSAnalysis) -> dict:
    """Convert JSAnalysis to a JSON-serializable dict."""
    import dataclasses

    return {
        "endpoints": [dataclasses.asdict(e) for e in analysis.endpoints],
        "api_base_urls": analysis.api_base_urls,
        "auth_patterns": [dataclasses.asdict(a) for a in analysis.auth_patterns],
        "hardcoded_secrets": analysis.hardcoded_secrets,
        "graphql_operations": analysis.graphql_operations,
        "env_configs": analysis.env_configs,
        "fetch_calls": analysis.fetch_calls,
        "navigation_api_map": analysis.navigation_api_map,
    }


@app.command("scan")
def scan(
    path: Path = typer.Argument(..., help="APK, IPA, directory, or .bundle file"),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
    show_secrets: bool = typer.Option(
        False, "--show-secrets", help="Show full secret values (masked by default)"
    ),
) -> None:
    """Scan JS bundles for API endpoints, secrets, and configuration."""
    if not path.exists():
        console.print(f"[red]Path not found: {path}[/red]")
        raise typer.Exit(1)

    analysis = _read_and_analyze(path)

    if format == "json":
        data = _to_json(analysis)
        json_str = json.dumps(data, indent=2)
        if output:
            output.write_text(json_str)
            console.print(f"[green]Output written to {output}[/green]")
        else:
            console.print(json_str)
    else:
        _render_table(analysis, show_secrets)
        if output:
            data = _to_json(analysis)
            output.write_text(json.dumps(data, indent=2))
            console.print(f"[green]JSON output written to {output}[/green]")


@app.command("extract")
def extract(
    app_path: Path = typer.Argument(..., help="APK or IPA file"),
    output_dir: Path = typer.Option(
        Path("./bundle_output"), "--output", "-o", help="Output directory"
    ),
) -> None:
    """Extract JS bundle files from APK/IPA."""
    if not app_path.exists():
        console.print(f"[red]File not found: {app_path}[/red]")
        raise typer.Exit(1)

    extracted = extract_bundle(app_path, output_dir)
    if extracted:
        console.print(f"[green]Extracted {len(extracted)} bundle(s):[/green]")
        for p in extracted:
            console.print(f"  {p}")
    else:
        console.print("[yellow]No bundles found to extract.[/yellow]")


@app.command("list")
def list_bundles(
    app_path: Path = typer.Argument(..., help="APK, IPA, or directory"),
) -> None:
    """List JS bundles found in an APK/IPA/directory."""
    if not app_path.exists():
        console.print(f"[red]Path not found: {app_path}[/red]")
        raise typer.Exit(1)

    bundles = find_bundles(app_path)
    if not bundles:
        console.print("[yellow]No JS bundles found.[/yellow]")
        raise typer.Exit(0)

    table = Table(title="JS Bundles", show_lines=True)
    table.add_column("Path", style="green")
    table.add_column("Size", style="cyan", justify="right")
    table.add_column("Type", style="yellow")
    table.add_column("Bytecode", style="red")

    for b in bundles:
        size_str = _format_size(b.size_bytes)
        table.add_row(
            str(b.path), size_str, b.bundle_type, "Yes" if b.is_bytecode else "No"
        )

    console.print(table)


def _format_size(size_bytes: int) -> str:
    """Format byte size to human readable."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
