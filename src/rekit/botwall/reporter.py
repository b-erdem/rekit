"""HTTP request execution and detection report generation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rekit.botwall.detectors import ALL_DETECTORS
from rekit.botwall.detectors.base import Detection, Difficulty, ResponseData

console = Console()


@dataclass
class DetectionReport:
    """Full detection report for a URL."""

    url: str
    detections: List[Detection]
    raw_response: ResponseData
    curl_cffi_response: Optional[ResponseData] = None
    summary: str = ""
    error: Optional[str] = None


# ── HTTP fetching ───────────────────────────────────────────────────────


def _fetch_with_requests(
    url: str,
    timeout: float = 15.0,
    follow_redirects: bool = True,
) -> ResponseData:
    """Fetch URL using the ``requests`` library."""
    redirect_chain: list[str] = []

    t0 = time.monotonic()
    resp = requests.get(
        url,
        timeout=timeout,
        allow_redirects=follow_redirects,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
    )
    elapsed_ms = (time.monotonic() - t0) * 1000

    if follow_redirects and resp.history:
        redirect_chain = [r.url for r in resp.history]

    cookies: Dict[str, str] = {k: v for k, v in resp.cookies.items()}
    headers_dict: Dict[str, str] = {k: v for k, v in resp.headers.items()}

    # Truncate very large bodies to avoid memory issues
    body = resp.text[:500_000] if len(resp.text) > 500_000 else resp.text

    return ResponseData(
        url=str(resp.url),
        status_code=resp.status_code,
        headers=headers_dict,
        body=body,
        cookies=cookies,
        redirect_chain=redirect_chain,
        response_time_ms=round(elapsed_ms, 1),
    )


def _fetch_with_curl_cffi(
    url: str,
    timeout: float = 15.0,
    follow_redirects: bool = True,
) -> Optional[ResponseData]:
    """Fetch URL using ``curl_cffi`` with browser TLS impersonation.

    Returns None if curl_cffi is not installed.
    """
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        return None

    redirect_chain: list[str] = []

    t0 = time.monotonic()
    resp = cffi_requests.get(
        url,
        timeout=timeout,
        allow_redirects=follow_redirects,
        impersonate="chrome",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    elapsed_ms = (time.monotonic() - t0) * 1000

    if follow_redirects and hasattr(resp, "history") and resp.history:
        redirect_chain = [str(r.url) for r in resp.history]

    cookies: Dict[str, str] = {k: v for k, v in resp.cookies.items()}
    headers_dict: Dict[str, str] = {k: v for k, v in resp.headers.items()}

    body = resp.text[:500_000] if len(resp.text) > 500_000 else resp.text

    return ResponseData(
        url=str(resp.url),
        status_code=resp.status_code,
        headers=headers_dict,
        body=body,
        cookies=cookies,
        redirect_chain=redirect_chain,
        response_time_ms=round(elapsed_ms, 1),
    )


# ── Detection orchestration ────────────────────────────────────────────


def detect_all(
    url: str,
    timeout: float = 15.0,
    follow_redirects: bool = True,
) -> DetectionReport:
    """Fetch *url* and run every detector. Returns a :class:`DetectionReport`."""

    # 1. Fetch with standard requests
    try:
        response_data = _fetch_with_requests(url, timeout, follow_redirects)
    except requests.exceptions.SSLError as exc:
        return DetectionReport(
            url=url,
            detections=[],
            raw_response=ResponseData(
                url=url, status_code=0, headers={}, body="", cookies={}
            ),
            error=f"SSL error: {exc}",
        )
    except requests.exceptions.ConnectionError as exc:
        return DetectionReport(
            url=url,
            detections=[],
            raw_response=ResponseData(
                url=url, status_code=0, headers={}, body="", cookies={}
            ),
            error=f"Connection error: {exc}",
        )
    except requests.exceptions.Timeout:
        return DetectionReport(
            url=url,
            detections=[],
            raw_response=ResponseData(
                url=url, status_code=0, headers={}, body="", cookies={}
            ),
            error=f"Request timed out after {timeout}s",
        )
    except requests.exceptions.RequestException as exc:
        return DetectionReport(
            url=url,
            detections=[],
            raw_response=ResponseData(
                url=url, status_code=0, headers={}, body="", cookies={}
            ),
            error=f"Request failed: {exc}",
        )

    # 2. Also try curl_cffi for comparison
    curl_response: Optional[ResponseData] = None
    try:
        curl_response = _fetch_with_curl_cffi(url, timeout, follow_redirects)
    except Exception:
        pass  # curl_cffi not available or failed — that's fine

    # 3. Run all detectors against the requests response
    detections: List[Detection] = []
    for detector in ALL_DETECTORS:
        try:
            result = detector.detect(response_data)
            if result is not None:
                detections.append(result)
        except Exception:
            pass  # never let a broken detector crash the whole run

    # 4. If curl_cffi gave a different response, run detectors on that too
    if curl_response is not None:
        for detector in ALL_DETECTORS:
            try:
                result = detector.detect(curl_response)
                if result is not None:
                    # Avoid duplicates: only add if system not already detected
                    existing_names = {d.system_name for d in detections}
                    if result.system_name not in existing_names:
                        result.details["source"] = "curl_cffi"
                        detections.append(result)
                    else:
                        # Merge evidence from curl_cffi into existing detection
                        for d in detections:
                            if d.system_name == result.system_name:
                                new_evidence = [
                                    e for e in result.evidence if e not in d.evidence
                                ]
                                if new_evidence:
                                    d.evidence.extend(
                                        f"[curl_cffi] {e}" for e in new_evidence
                                    )
                                    d.confidence = min(1.0, d.confidence + 0.1)
                                break
            except Exception:
                pass

    # 5. Sort by confidence descending
    detections.sort(key=lambda d: d.confidence, reverse=True)

    # 6. Build summary
    if not detections:
        summary = "No bot protection systems detected."
    elif len(detections) == 1:
        d = detections[0]
        summary = f"{d.system_name} detected (confidence {d.confidence:.0%}, difficulty: {d.difficulty.value})"
    else:
        parts = [f"{d.system_name} ({d.confidence:.0%})" for d in detections]
        summary = f"Multiple systems detected: {', '.join(parts)}"

    return DetectionReport(
        url=url,
        detections=detections,
        raw_response=response_data,
        curl_cffi_response=curl_response,
        summary=summary,
    )


# ── Rich rendering ──────────────────────────────────────────────────────

_DIFFICULTY_EMOJI = {
    Difficulty.TRIVIAL: "[green]TRIVIAL[/green]",
    Difficulty.EASY: "[yellow]EASY[/yellow]",
    Difficulty.MEDIUM: "[dark_orange]MEDIUM[/dark_orange]",
    Difficulty.HARD: "[red]HARD[/red]",
    Difficulty.IMPRACTICAL: "[bold red]IMPRACTICAL[/bold red]",
}


def render_report(report: DetectionReport, verbose: bool = False) -> None:
    """Print the detection report as a Rich panel to the terminal."""
    c = console

    if report.error:
        c.print(
            Panel(
                f"[red bold]Error:[/red bold] {report.error}",
                title=f"[bold]botwall[/bold]  {report.url}",
                border_style="red",
            )
        )
        return

    # ── per-detection panels ────────────────────────────────────────────
    if not report.detections:
        c.print(
            Panel(
                "[green]No bot protection systems detected.[/green]\n"
                "The target appears to serve responses without active bot mitigation.",
                title=f"[bold]botwall[/bold]  {report.url}",
                border_style="green",
            )
        )
    else:
        for det in report.detections:
            _render_detection(det)

    # ── raw response summary ────────────────────────────────────────────
    rd = report.raw_response
    resp_table = Table(show_header=False, box=None, padding=(0, 2))
    resp_table.add_column(style="bold")
    resp_table.add_column()
    resp_table.add_row("URL", rd.url)
    resp_table.add_row("Status", str(rd.status_code))
    resp_table.add_row("Headers", str(len(rd.headers)))
    resp_table.add_row("Body size", f"{len(rd.body):,} chars")
    resp_table.add_row("Response time", f"{rd.response_time_ms:.0f} ms")
    if rd.redirect_chain:
        resp_table.add_row("Redirects", " -> ".join(rd.redirect_chain))

    if report.curl_cffi_response:
        cr = report.curl_cffi_response
        resp_table.add_row("", "")
        resp_table.add_row("[dim]curl_cffi status[/dim]", str(cr.status_code))
        resp_table.add_row("[dim]curl_cffi time[/dim]", f"{cr.response_time_ms:.0f} ms")
        if cr.status_code != rd.status_code:
            resp_table.add_row(
                "[yellow]Note[/yellow]",
                f"Status differs: requests={rd.status_code}, curl_cffi={cr.status_code}",
            )

    c.print(
        Panel(resp_table, title="[bold]Response Summary[/bold]", border_style="dim")
    )

    if verbose:
        _render_verbose(report)


def _render_detection(det: Detection) -> None:
    """Render a single Detection as a Rich panel."""
    lines: list[str] = []

    # System name + version
    title_parts = [f"[bold]{det.system_name}[/bold]"]
    if det.system_version:
        title_parts.append(f"[dim]({det.system_version})[/dim]")

    # Confidence + difficulty
    diff_label = _DIFFICULTY_EMOJI.get(det.difficulty, det.difficulty.value)
    lines.append(
        f"Confidence: [bold]{det.confidence:.0%}[/bold]    Difficulty: {diff_label}"
    )
    lines.append(f"[dim]{det.difficulty.description}[/dim]")
    lines.append("")

    # Evidence
    if det.evidence:
        lines.append("[bold]Evidence:[/bold]")
        for ev in det.evidence:
            lines.append(f"  - {ev}")
        lines.append("")

    # Bypass hints
    if det.bypass_hints:
        lines.append("[bold]Bypass hints:[/bold]")
        for hint in det.bypass_hints:
            lines.append(f"  - {hint}")

    border = det.difficulty.color
    console.print(
        Panel(
            "\n".join(lines),
            title=" ".join(title_parts),
            border_style=border,
        )
    )


def _render_verbose(report: DetectionReport) -> None:
    """Print verbose details: all response headers and cookies."""
    c = console
    rd = report.raw_response

    # Headers table
    if rd.headers:
        ht = Table(title="Response Headers", show_lines=True)
        ht.add_column("Header", style="bold cyan")
        ht.add_column("Value")
        for k, v in sorted(rd.headers.items()):
            ht.add_row(k, v)
        c.print(ht)

    # Cookies table
    if rd.cookies:
        ct = Table(title="Cookies", show_lines=True)
        ct.add_column("Name", style="bold cyan")
        ct.add_column("Value")
        for k, v in sorted(rd.cookies.items()):
            # Truncate long cookie values
            display_val = v if len(v) <= 80 else v[:77] + "..."
            ct.add_row(k, display_val)
        c.print(ct)
