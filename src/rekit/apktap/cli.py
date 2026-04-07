"""
apktap CLI — Typer subcommand group for HTTP traffic capture via Frida.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

console = Console(stderr=True)

app = typer.Typer(
    name="apktap",
    help="Hook into Android app HTTP layer, capture traffic without proxy.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _require_frida():
    """Check that frida is importable; give a helpful error if not."""
    try:
        import frida  # noqa: F401
    except ImportError:
        console.print(
            "[bold red]Error:[/] Frida is not installed.\n"
            "Install it with:  [bold]pip install rekit\\[frida][/]  "
            "or  [bold]pip install frida-tools[/]"
        )
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def _default(
    ctx: typer.Context,
    package: Optional[str] = typer.Argument(None, help="Android package name (e.g. com.example.app)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output HAR file path"),
    device: Optional[str] = typer.Option(None, "--device", "-d", help="Device ID (for multiple devices)"),
    spawn: bool = typer.Option(True, "--spawn/--no-spawn", help="Spawn app vs. attach to running process"),
    timeout: int = typer.Option(0, "--timeout", "-t", help="Seconds to capture (0 = until Ctrl+C)"),
    filter_host: Optional[str] = typer.Option(None, "--filter-host", help="Only capture requests to this host"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show each request in real-time"),
):
    """Capture HTTP traffic from an Android app using Frida hooks.

    If no subcommand is given and a PACKAGE is provided, runs capture mode.
    """
    if ctx.invoked_subcommand is not None:
        return

    if package is None:
        console.print(
            "[bold]apktap[/] — capture HTTP traffic from Android apps.\n\n"
            "Usage:  rekit apktap [bold]<package>[/]  [OPTIONS]\n"
            "        rekit apktap [bold]list-apps[/]\n"
            "        rekit apktap [bold]hooks[/]\n\n"
            "Run [bold]rekit apktap --help[/] for full options."
        )
        raise typer.Exit()

    # Delegate to capture logic
    _require_frida()

    output_path = output or Path(f"{package}_traffic.har")

    from rekit.apktap.capture import CaptureSession

    session = CaptureSession(
        package_name=package,
        device_id=device,
        spawn=spawn,
        filter_host=filter_host,
        verbose=verbose,
    )

    try:
        session.start(timeout=timeout, output_path=output_path)
    except KeyboardInterrupt:
        pass
    finally:
        session.stop(output_path=output_path)


@app.command()
def list_apps(
    device: Optional[str] = typer.Option(None, "--device", "-d", help="Device ID"),
):
    """List installed applications on the connected Android device."""
    _require_frida()
    import frida

    from rekit.apktap.utils import check_frida_server

    try:
        if device:
            dev = frida.get_device(device)
        else:
            dev = frida.get_usb_device(timeout=5)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] Could not connect to device: {exc}")
        console.print(
            "\n[dim]Make sure:\n"
            "  1. USB debugging is enabled\n"
            "  2. Device is connected via USB or ADB\n"
            "  3. `adb devices` shows your device[/]"
        )
        raise typer.Exit(1)

    if not check_frida_server(dev):
        raise typer.Exit(1)

    apps = dev.enumerate_applications()
    apps.sort(key=lambda a: a.identifier)

    from rich.table import Table

    table = Table(title=f"Installed apps on {dev.name}", show_lines=False)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("PID", style="yellow", justify="right")

    for a in apps:
        pid_str = str(a.pid) if a.pid else "[dim]-[/]"
        table.add_row(a.identifier, a.name, pid_str)

    console.print(table)
    console.print(f"\n[dim]{len(apps)} applications found[/]")


@app.command()
def hooks():
    """List available Frida hook scripts and their targets."""
    from rich.table import Table

    hook_info = [
        ("okhttp.js", "OkHttp3", "Most Android apps using Retrofit / OkHttp"),
        ("urlconnection.js", "java.net.HttpURLConnection", "Legacy Java HTTP connections"),
        ("webview.js", "Android WebView", "HTTP traffic from WebView components"),
        ("dio.js", "Dart Dio (Flutter)", "Flutter apps — experimental, see docs"),
    ]

    table = Table(title="Available Hook Scripts", show_lines=False)
    table.add_column("Script", style="cyan")
    table.add_column("Target Library", style="green")
    table.add_column("Description", style="white")

    for script, target, desc in hook_info:
        table.add_row(script, target, desc)

    console.print(table)
    console.print(
        "\n[dim]Hooks are auto-selected based on libraries detected in the target app.\n"
        "OkHttp is injected by default as it covers the vast majority of apps.[/]"
    )
