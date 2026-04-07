"""botwall CLI — identify bot protection systems on a target URL."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="botwall",
    help="Identify bot protection systems and rate bypass difficulty.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    invoke_without_command=True,
)

console = Console()


def _serialise_report(report) -> dict:
    """Convert a DetectionReport to a JSON-serialisable dict."""
    from rekit.botwall.detectors.base import Difficulty

    def _convert(obj):
        if isinstance(obj, Difficulty):
            return obj.value
        raise TypeError(f"Cannot serialise {type(obj)}")

    raw = asdict(report)
    return json.loads(json.dumps(raw, default=_convert))


@app.command("detect")
def detect(
    url: str = typer.Argument(..., help="Target URL to analyse"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write JSON report to this file path"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show full response headers and cookies"
    ),
    timeout: float = typer.Option(
        15.0, "--timeout", "-t", help="HTTP request timeout in seconds"
    ),
    follow_redirects: bool = typer.Option(
        True,
        "--follow-redirects/--no-follow-redirects",
        help="Whether to follow HTTP redirects",
    ),
) -> None:
    """Detect bot protection systems on [bold]URL[/bold]."""
    from rekit.botwall.reporter import detect_all, render_report

    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    with console.status(f"[bold]Probing {url}...[/bold]"):
        report = detect_all(url, timeout=timeout, follow_redirects=follow_redirects)

    render_report(report, verbose=verbose)

    if output:
        data = _serialise_report(report)
        with open(output, "w") as fh:
            json.dump(data, fh, indent=2)
        console.print(f"\n[dim]JSON report written to {output}[/dim]")
