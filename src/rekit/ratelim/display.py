"""ratelim.display -- Rich output for rate limit probe results."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from rekit.ratelim.prober import ProbeResult, RateLimitInfo


def format_probe_result(result: ProbeResult) -> Panel:
    """Build a Rich panel summarising probe results."""
    lines: list[str] = [
        f"[bold]URL:[/bold] {result.url}",
        f"[bold]Total requests:[/bold] {result.total_requests}",
        f"[bold]Successful (2xx/3xx):[/bold] {result.successful}",
        f"[bold]Rate limited (429):[/bold] {result.rate_limited}",
        f"[bold]Errors (5xx):[/bold] {result.errors}",
    ]

    if result.first_429_at is not None:
        lines.append(f"[bold]First 429 at request:[/bold] #{result.first_429_at}")

    if result.cooldown_seconds is not None:
        lines.append(f"[bold]Cooldown:[/bold] {result.cooldown_seconds:.1f}s")

    if result.safe_rps is not None:
        lines.append(f"[bold]Safe RPS:[/bold] {result.safe_rps}")

    body = "\n".join(lines)
    return Panel(body, title="Rate Limit Probe", border_style="cyan")


def format_rate_limit_headers(info: RateLimitInfo) -> Table:
    """Build a Rich table showing parsed rate limit header values."""
    table = Table(title="Rate Limit Headers", show_lines=False)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    if info.limit is not None:
        table.add_row("Limit", str(info.limit))
    if info.remaining is not None:
        table.add_row("Remaining", str(info.remaining))
    if info.reset_seconds is not None:
        table.add_row("Reset (seconds)", f"{info.reset_seconds:.1f}")
    if info.window_seconds is not None:
        table.add_row("Window (seconds)", f"{info.window_seconds:.1f}")
    table.add_row("Limit type", info.limit_type)
    table.add_row("Source", info.source)

    return table


def format_recommendation(result: ProbeResult) -> Panel:
    """Build a Rich panel with safe-rate recommendations."""
    lines: list[str] = []

    if result.safe_rps is not None:
        lines.append(f"[bold green]Recommended RPS:[/bold green] {result.safe_rps}")
        interval = round(1.0 / result.safe_rps, 3) if result.safe_rps > 0 else None
        if interval is not None:
            lines.append(f"[bold]Sleep between requests:[/bold] {interval}s")
        concurrency = max(1, int(result.safe_rps))
        lines.append(f"[bold]Max concurrency:[/bold] {concurrency}")
    else:
        lines.append("[yellow]Could not determine a safe request rate.[/yellow]")

    if result.cooldown_seconds is not None:
        lines.append(
            f"\n[bold]If rate limited, wait at least:[/bold] {result.cooldown_seconds:.0f}s"
        )

    if result.rate_limit_info and result.rate_limit_info.limit is not None:
        info = result.rate_limit_info
        lines.append(
            f"\n[dim]Server reports limit of {info.limit} requests"
            + (f" per {info.window_seconds:.0f}s window" if info.window_seconds else "")
            + "[/dim]"
        )

    body = "\n".join(lines)
    return Panel(body, title="Recommendation", border_style="green")
