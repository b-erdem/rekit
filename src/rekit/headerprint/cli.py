"""
headerprint CLI -- analyse HTTP/2 and header-order fingerprints.

Usage:
    rekit headerprint analyze  capture.har
    rekit headerprint compare  capture.har
    rekit headerprint profiles
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=(
        "[bold]headerprint[/bold] -- Analyse HTTP header order and HTTP/2 fingerprints."
    ),
)

console = Console()


# ---------------------------------------------------------------------------
# profiles command
# ---------------------------------------------------------------------------


@app.command("profiles")
def profiles() -> None:
    """List known browser fingerprint profiles."""
    from rich.table import Table

    from rekit.headerprint.profiles import PROFILES

    table = Table(title="Known Header Fingerprint Profiles", show_lines=False)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Connection", style="magenta")
    table.add_column("Pseudo-Hdr Order")
    table.add_column("H2 Settings Keys", justify="right")
    table.add_column("Headers #", justify="right")

    for name, p in sorted(PROFILES.items()):
        pseudo = ", ".join(p.pseudo_header_order) if p.pseudo_header_order else "-"
        table.add_row(
            p.name,
            p.connection_type,
            pseudo,
            str(len(p.h2_settings)),
            str(len(p.header_order)),
        )

    console.print(table)
    console.print(f"\n[bold]{len(PROFILES)}[/bold] profiles available.")


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------


@app.command("analyze")
def analyze(
    har_file: Path = typer.Argument(..., help="Path to HAR file"),
    format: str = typer.Option(
        "panel", "--format", "-f", help="Output format: panel or json"
    ),
) -> None:
    """Analyze HTTP fingerprint from captured traffic."""
    from rekit.hargen.parser import parse_har
    from rekit.headerprint.analyzer import (
        detect_anomalies,
        extract_fingerprint_from_har,
    )
    from rekit.headerprint.display import format_anomalies, format_fingerprint

    if not har_file.exists():
        console.print(f"[red]Error:[/red] File not found: {har_file}")
        raise typer.Exit(1)

    exchanges = parse_har(har_file)
    if not exchanges:
        console.print("[red]Error:[/red] No HTTP exchanges found in HAR file.")
        raise typer.Exit(1)

    fp = extract_fingerprint_from_har(exchanges)
    anomalies = detect_anomalies(fp)

    if format == "json":
        data = {
            "header_order": fp.header_order,
            "pseudo_header_order": fp.pseudo_header_order,
            "user_agent": fp.user_agent,
            "anomalies": anomalies,
        }
        console.print(json.dumps(data, indent=2))
    else:
        console.print(format_fingerprint(fp))
        console.print(format_anomalies(anomalies))


# ---------------------------------------------------------------------------
# compare command
# ---------------------------------------------------------------------------


@app.command("compare")
def compare(
    har_file: Path = typer.Argument(..., help="Path to HAR file"),
) -> None:
    """Compare captured fingerprint against known browser profiles."""
    from rekit.hargen.parser import parse_har
    from rekit.headerprint.analyzer import (
        compare_to_profiles,
        detect_anomalies,
        extract_fingerprint_from_har,
    )
    from rekit.headerprint.display import (
        format_matches,
        format_recommendations,
    )

    if not har_file.exists():
        console.print(f"[red]Error:[/red] File not found: {har_file}")
        raise typer.Exit(1)

    exchanges = parse_har(har_file)
    if not exchanges:
        console.print("[red]Error:[/red] No HTTP exchanges found in HAR file.")
        raise typer.Exit(1)

    fp = extract_fingerprint_from_har(exchanges)
    matches = compare_to_profiles(fp)
    anomalies = detect_anomalies(fp)

    console.print(format_matches(matches))
    console.print(format_recommendations(matches, anomalies))
