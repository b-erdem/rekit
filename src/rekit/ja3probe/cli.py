"""
ja3probe CLI -- test which TLS fingerprints a target URL accepts.

Usage:
    rekit ja3probe probe https://api.example.com
    rekit ja3probe probe https://api.example.com --fingerprints chrome_120,safari_18_0
    rekit ja3probe list
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="[bold]ja3probe[/bold] -- Test which TLS fingerprints a target accepts.",
)

console = Console()


# ---------------------------------------------------------------------------
# list command
# ---------------------------------------------------------------------------

@app.command("list")
def list_profiles() -> None:
    """Show all available TLS fingerprint profiles."""
    from rekit.ja3probe.fingerprints import PROFILES

    table = Table(
        title="Available Fingerprint Profiles",
        show_lines=False,
    )
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Family", style="magenta")
    table.add_column("Version")
    table.add_column("Impersonate", style="green")
    table.add_column("Description")

    for name, p in sorted(PROFILES.items()):
        table.add_row(
            p.name,
            p.browser_family,
            p.version,
            p.impersonate_str or "[dim]none[/dim]",
            p.description,
        )

    console.print(table)
    console.print(f"\n[bold]{len(PROFILES)}[/bold] profiles available.")


# ---------------------------------------------------------------------------
# probe command (default)
# ---------------------------------------------------------------------------

@app.command("probe")
def probe(
    url: str = typer.Argument(..., help="Target URL to probe (HTTPS)"),
    timeout: int = typer.Option(10, "--timeout", "-t", help="Request timeout in seconds"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report to file"),
    fingerprints: Optional[str] = typer.Option(
        None,
        "--fingerprints",
        "-f",
        help="Comma-separated profile names to test (e.g. chrome_120,safari_18_0)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    workers: int = typer.Option(5, "--workers", "-w", help="Number of concurrent probes"),
) -> None:
    """Probe a target URL with multiple TLS fingerprint profiles."""
    _run_probe(url, timeout, output, fingerprints, verbose, workers)


# ---------------------------------------------------------------------------
# Shared implementation
# ---------------------------------------------------------------------------

def _run_probe(
    url: str,
    timeout: int,
    output: Optional[Path],
    fingerprints: Optional[str],
    verbose: bool,
    workers: int,
) -> None:
    """Core probe logic."""

    # Validate HTTPS
    if not url.startswith("https://"):
        if url.startswith("http://"):
            console.print(
                "[yellow]Warning:[/yellow] TLS fingerprinting is meaningless over plain HTTP. "
                "Switching to HTTPS."
            )
            url = "https://" + url[len("http://"):]
        else:
            url = "https://" + url

    # Ensure curl_cffi is available
    try:
        from rekit.ja3probe.prober import probe_all, analyze_results
    except ImportError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    from rekit.ja3probe.fingerprints import PROFILES

    # Select profiles
    profiles_to_test = None
    if fingerprints:
        names = [n.strip() for n in fingerprints.split(",")]
        missing = [n for n in names if n not in PROFILES]
        if missing:
            console.print(
                f"[red]Error:[/red] Unknown profile(s): {', '.join(missing)}\n"
                "Run [bold]rekit ja3probe list[/bold] to see available profiles."
            )
            raise typer.Exit(1)
        profiles_to_test = [PROFILES[n] for n in names]

    console.print(f"\n[bold]ja3probe[/bold] targeting [cyan]{url}[/cyan]")
    n_profiles = len(profiles_to_test) if profiles_to_test else len(PROFILES)
    console.print(f"Testing {n_profiles} fingerprint profiles with {workers} workers ...\n")

    # Run probes
    try:
        results = probe_all(url, profiles=profiles_to_test, timeout=timeout, workers=workers)
    except ImportError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    report = analyze_results(url, results)

    # Display table
    _print_results_table(report, verbose=verbose)

    # JSON output
    if output:
        _write_json_report(report, output)
        console.print(f"\n[dim]Report written to {output}[/dim]")


def _print_results_table(report, *, verbose: bool = False) -> None:
    """Render probe results as a Rich table."""
    from rekit.ja3probe.fingerprints import PROFILES

    table = Table(title=f"TLS Fingerprint Probe: {report.url}", show_lines=False)
    table.add_column("Profile", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("HTTP", justify="center")
    table.add_column("Time (ms)", justify="right")
    table.add_column("Notes")

    for r in report.details:
        # Status cell
        if r.accepted:
            status = "[green]ACCEPTED[/green]"
        elif r.challenge_detected:
            status = "[yellow]CHALLENGE[/yellow]"
        elif r.error:
            status = "[red]ERROR[/red]"
        else:
            status = "[red]REJECTED[/red]"

        # HTTP code
        http_code = str(r.status_code) if r.status_code else "-"

        # Notes
        notes_parts = []
        if r.redirect_url:
            notes_parts.append(f"redirect -> {r.redirect_url[:60]}")
        if r.challenge_detected:
            notes_parts.append("bot challenge detected")
        if r.error:
            notes_parts.append(r.error[:80])
        if verbose:
            profile = PROFILES.get(r.profile_name)
            if profile and profile.impersonate_str:
                notes_parts.append(f"impersonate={profile.impersonate_str}")

        notes = "; ".join(notes_parts) if notes_parts else ""

        table.add_row(
            r.profile_name,
            status,
            http_code,
            f"{r.response_time_ms:.0f}",
            notes,
        )

    console.print(table)

    # Summary
    protection = report.protection_system or "none detected"
    recommended = report.recommended_profile or "N/A"
    console.print(
        f"\n[bold]{report.accepted_count}/{report.total_tested}[/bold] profiles accepted.  "
        f"Protection: [bold]{protection}[/bold].  "
        f"Recommended: [bold green]{recommended}[/bold green]"
    )


def _write_json_report(report, path: Path) -> None:
    """Serialize the analysis report to JSON."""
    data = {
        "url": report.url,
        "total_tested": report.total_tested,
        "accepted_count": report.accepted_count,
        "rejected_count": report.rejected_count,
        "protection_system": report.protection_system,
        "recommended_profile": report.recommended_profile,
        "accepted_profiles": report.accepted_profiles,
        "rejected_profiles": report.rejected_profiles,
        "details": [
            {
                "profile_name": r.profile_name,
                "accepted": r.accepted,
                "status_code": r.status_code,
                "response_time_ms": r.response_time_ms,
                "error": r.error,
                "redirect_url": r.redirect_url,
                "challenge_detected": r.challenge_detected,
                "headers_received": r.headers_received,
            }
            for r in report.details
        ],
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
