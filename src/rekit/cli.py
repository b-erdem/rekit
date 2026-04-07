"""
rekit CLI — main entry point.

Usage:
    rekit hargen  capture.har -o ./client/
    rekit apktap  com.example.app -o traffic.har
    rekit apkmap  app.apk -o report.json
    rekit ja3probe https://api.example.com
    rekit botwall  https://www.example.com
    rekit schemadiff response1.json response2.json response3.json
    rekit tokendump extract capture.har
"""

import typer

app = typer.Typer(
    name="rekit",
    help="Reverse Engineering Toolkit for Mobile APIs",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _register_subcommands():
    """Lazily import and register subcommand groups."""
    from rekit.hargen.cli import app as hargen_app
    from rekit.apktap.cli import app as apktap_app
    from rekit.apkmap.cli import app as apkmap_app
    from rekit.ja3probe.cli import app as ja3probe_app
    from rekit.botwall.cli import app as botwall_app
    from rekit.schemadiff.cli import app as schemadiff_app
    from rekit.mockapi.cli import app as mockapi_app
    from rekit.tokendump.cli import app as tokendump_app
    from rekit.authmap.cli import app as authmap_app
    from rekit.protorev.cli import app as protorev_app
    from rekit.jsbundle.cli import app as jsbundle_app
    from rekit.ratelim.cli import app as ratelim_app
    from rekit.certpatch.cli import app as certpatch_app
    from rekit.headerprint.cli import app as headerprint_app

    app.add_typer(
        hargen_app,
        name="hargen",
        help="Generate Python API client from captured HTTP traffic",
    )
    app.add_typer(
        apktap_app,
        name="apktap",
        help="Hook into Android app HTTP layer, capture traffic",
    )
    app.add_typer(
        apkmap_app,
        name="apkmap",
        help="Scan decompiled APK, map API endpoints and models",
    )
    app.add_typer(
        ja3probe_app,
        name="ja3probe",
        help="Test which TLS fingerprints a target accepts",
    )
    app.add_typer(botwall_app, name="botwall", help="Identify bot protection systems")
    app.add_typer(
        schemadiff_app, name="schemadiff", help="Compare API response schemas"
    )
    app.add_typer(
        mockapi_app,
        name="mockapi",
        help="Generate and run a mock HTTP server from captured traffic",
    )
    app.add_typer(
        tokendump_app,
        name="tokendump",
        help="Extract and analyze authentication tokens from HAR traffic",
    )
    app.add_typer(
        authmap_app,
        name="authmap",
        help="Map authentication flows from captured HAR traffic",
    )
    app.add_typer(
        protorev_app,
        name="protorev",
        help="Reverse engineer Protobuf/gRPC from captured traffic",
    )
    app.add_typer(
        jsbundle_app,
        name="jsbundle",
        help="Analyze JS bundles from mobile apps for API endpoints and secrets",
    )
    app.add_typer(
        ratelim_app,
        name="ratelim",
        help="Systematically probe API rate limits",
    )
    app.add_typer(
        certpatch_app,
        name="certpatch",
        help="Scan for certificate pinning and generate Frida bypass scripts",
    )
    app.add_typer(
        headerprint_app,
        name="headerprint",
        help="Analyse HTTP/2 and header-order fingerprints",
    )


_register_subcommands()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
):
    """[bold]rekit[/bold] — Reverse Engineering Toolkit for Mobile APIs"""
    if version:
        from rekit import __version__

        typer.echo(f"rekit {__version__}")
        raise typer.Exit()


if __name__ == "__main__":
    app()
