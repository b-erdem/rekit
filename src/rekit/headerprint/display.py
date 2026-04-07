"""
Rich terminal output for headerprint results.
"""

from __future__ import annotations

from typing import List

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rekit.headerprint.analyzer import FingerprintMatch, HeaderFingerprint


# ---------------------------------------------------------------------------
# Fingerprint display
# ---------------------------------------------------------------------------


def format_fingerprint(fp: HeaderFingerprint) -> Panel:
    """Render the observed fingerprint as a Rich Panel."""
    lines: List[str] = []

    lines.append(f"[bold]User-Agent:[/bold] {fp.user_agent or '(none)'}")
    lines.append("")

    lines.append("[bold]Header order:[/bold]")
    for i, h in enumerate(fp.header_order, 1):
        lines.append(f"  {i:2d}. {h}")

    if fp.pseudo_header_order:
        lines.append("")
        lines.append("[bold]HTTP/2 pseudo-header order:[/bold]")
        for h in fp.pseudo_header_order:
            lines.append(f"  {h}")

    if fp.h2_settings:
        lines.append("")
        lines.append("[bold]HTTP/2 SETTINGS:[/bold]")
        for k, v in fp.h2_settings.items():
            lines.append(f"  {k}: {v}")

    if fp.extra_headers:
        lines.append("")
        lines.append("[bold]Extra headers[/bold] (not in any profile):")
        for h in fp.extra_headers:
            lines.append(f"  {h}")

    if fp.missing_headers:
        lines.append("")
        lines.append("[bold]Missing headers[/bold] (expected by profile):")
        for h in fp.missing_headers:
            lines.append(f"  {h}")

    return Panel("\n".join(lines), title="Observed Fingerprint", border_style="cyan")


# ---------------------------------------------------------------------------
# Match table
# ---------------------------------------------------------------------------


def format_matches(matches: List[FingerprintMatch]) -> Table:
    """Render profile comparison results as a Rich Table."""
    table = Table(title="Profile Comparison", show_lines=False)
    table.add_column("Profile", style="cyan", no_wrap=True)
    table.add_column("Overall", justify="right")
    table.add_column("Header Order", justify="right")
    table.add_column("Pseudo-Hdr", justify="right")
    table.add_column("H2 Settings", justify="right")
    table.add_column("Differences")

    for m in matches:

        def _pct(v: float) -> Text:
            text = f"{v:.0%}"
            if v >= 0.8:
                return Text(text, style="green")
            if v >= 0.5:
                return Text(text, style="yellow")
            return Text(text, style="red")

        diff_summary = "; ".join(m.differences[:2]) if m.differences else "-"

        table.add_row(
            m.profile_name,
            _pct(m.similarity),
            _pct(m.header_order_match),
            _pct(m.pseudo_header_match),
            _pct(m.h2_settings_match),
            diff_summary,
        )

    return table


# ---------------------------------------------------------------------------
# Anomaly panel
# ---------------------------------------------------------------------------


def format_anomalies(anomalies: List[str]) -> Panel:
    """Render anomaly list as a Rich Panel."""
    if not anomalies:
        body = "[green]No anomalies detected. Client looks browser-like.[/green]"
    else:
        items = []
        for i, a in enumerate(anomalies, 1):
            items.append(f"[yellow]{i}.[/yellow] {a}")
        body = "\n".join(items)

    return Panel(body, title="Anomaly Report", border_style="yellow")


# ---------------------------------------------------------------------------
# Recommendations panel
# ---------------------------------------------------------------------------


def format_recommendations(
    matches: List[FingerprintMatch],
    anomalies: List[str],
) -> Panel:
    """Render actionable recommendations as a Rich Panel."""
    lines: List[str] = []

    if not anomalies:
        lines.append(
            "[green]The observed fingerprint looks consistent with a "
            "real browser. No changes recommended.[/green]"
        )
    else:
        lines.append("[bold]To improve browser-likeness, address these issues:[/bold]")
        lines.append("")
        for i, a in enumerate(anomalies, 1):
            lines.append(f"  {i}. {a}")

    if matches:
        best = matches[0]
        lines.append("")
        lines.append(
            f"[bold]Closest profile:[/bold] {best.profile_name} "
            f"({best.similarity:.0%} similarity)"
        )
        if best.differences:
            lines.append("[bold]Key differences from closest profile:[/bold]")
            for d in best.differences:
                lines.append(f"  - {d}")

    return Panel("\n".join(lines), title="Recommendations", border_style="green")
