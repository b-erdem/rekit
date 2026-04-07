"""
certpatch CLI — scan for certificate pinning and generate Frida bypasses.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from rekit.certpatch.generator import (
    generate_bypass,
    generate_network_security_config,
)
from rekit.certpatch.scanner import scan_for_pinning

app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@app.command("scan")
def scan(
    source_dir: Path = typer.Argument(..., help="Path to decompiled APK source"),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json"
    ),
) -> None:
    """Scan decompiled APK for certificate pinning."""
    if not source_dir.is_dir():
        console.print(f"[red]Error:[/red] {source_dir} is not a directory")
        raise typer.Exit(1)

    detections = scan_for_pinning(source_dir)

    if not detections:
        console.print("[green]No certificate pinning detected.[/green]")
        return

    if format == "json":
        output = [
            {
                "pinning_type": d.pinning_type.value,
                "file_path": d.file_path,
                "line_number": d.line_number,
                "pinned_domains": d.pinned_domains,
                "pin_hashes": d.pin_hashes,
                "confidence": d.confidence,
                "bypass_difficulty": d.bypass_difficulty,
            }
            for d in detections
        ]
        console.print(json.dumps(output, indent=2))
    else:
        table = Table(title="Certificate Pinning Detections")
        table.add_column("Type", style="cyan")
        table.add_column("File", style="green")
        table.add_column("Line")
        table.add_column("Domains")
        table.add_column("Confidence")
        table.add_column("Difficulty", style="yellow")

        for d in detections:
            difficulty_style = {
                "easy": "[green]easy[/green]",
                "medium": "[yellow]medium[/yellow]",
                "hard": "[red]hard[/red]",
            }.get(d.bypass_difficulty, d.bypass_difficulty)

            table.add_row(
                d.pinning_type.value,
                d.file_path,
                str(d.line_number or "?"),
                ", ".join(d.pinned_domains) or "-",
                f"{d.confidence:.0%}",
                difficulty_style,
            )

        console.print(table)
        console.print(f"\n[bold]{len(detections)}[/bold] pinning detection(s) found.")


@app.command("bypass")
def bypass(
    source_dir: Path = typer.Argument(..., help="Path to decompiled APK source"),
    output: Path = typer.Option(
        Path("bypass.js"), "--output", "-o", help="Output Frida script path"
    ),
) -> None:
    """Generate Frida bypass script for detected pinning."""
    if not source_dir.is_dir():
        console.print(f"[red]Error:[/red] {source_dir} is not a directory")
        raise typer.Exit(1)

    detections = scan_for_pinning(source_dir)

    if not detections:
        console.print("[yellow]No certificate pinning detected.[/yellow]")
        return

    script = generate_bypass(detections)
    output.write_text(script)

    console.print(f"[green]Bypass script written to:[/green] {output}")
    console.print(f"  Bypasses {len(detections)} detection(s)")

    for d in detections:
        console.print(f"  - {d.pinning_type.value} in {d.file_path}")


@app.command("config")
def config(
    output: Path = typer.Option(
        Path("network_security_config.xml"),
        "--output",
        "-o",
        help="Output XML path",
    ),
) -> None:
    """Generate permissive network_security_config.xml."""
    xml_content = generate_network_security_config()
    output.write_text(xml_content)
    console.print(
        f"[green]Permissive network_security_config.xml written to:[/green] {output}"
    )
