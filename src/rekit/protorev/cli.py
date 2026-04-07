"""protorev CLI — Decode protobuf, extract from HAR, and infer schemas."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console(stderr=True)
out = Console()


@app.command("decode")
def decode(
    input: str = typer.Argument(help="Hex string, base64 string, or file path"),
    format: str = typer.Option(
        "tree", "--format", "-f", help="Output format: tree, json"
    ),
):
    """Decode raw protobuf. Input can be a hex string, base64 string, or file path."""
    from rekit.protorev.decoder import decode_protobuf, format_decoded

    data = _resolve_input(input)
    if not data:
        console.print("[red]Error:[/red] No data to decode")
        raise typer.Exit(1)

    msg = decode_protobuf(data)

    if not msg.fields:
        console.print("[yellow]Warning:[/yellow] No protobuf fields found in input")
        raise typer.Exit(1)

    if format == "tree":
        out.print(format_decoded(msg))
    elif format == "json":
        import json

        out.print(json.dumps(_msg_to_dict(msg), indent=2))
    else:
        console.print(f"[red]Error:[/red] Unknown format: {format}")
        raise typer.Exit(1)


@app.command("extract")
def extract(
    har_file: Path = typer.Argument(help="Path to HAR file"),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, tree"
    ),
):
    """Extract and decode protobuf exchanges from HAR file."""
    from rekit.hargen.parser import parse_har
    from rekit.protorev.decoder import format_decoded
    from rekit.protorev.extractor import extract_proto_exchanges

    if not har_file.exists():
        console.print(f"[red]Error:[/red] File not found: {har_file}")
        raise typer.Exit(1)

    exchanges = parse_har(har_file)
    proto_exchanges = extract_proto_exchanges(exchanges)

    if not proto_exchanges:
        console.print("[yellow]No protobuf exchanges found in HAR file[/yellow]")
        raise typer.Exit(0)

    if format == "table":
        table = Table(title=f"Protobuf Exchanges ({len(proto_exchanges)} found)")
        table.add_column("#", style="dim")
        table.add_column("Method")
        table.add_column("URL")
        table.add_column("gRPC")
        table.add_column("Req Fields")
        table.add_column("Resp Fields")

        for px in proto_exchanges:
            req_fields = str(len(px.request_proto.fields)) if px.request_proto else "-"
            resp_fields = (
                str(len(px.response_proto.fields)) if px.response_proto else "-"
            )
            grpc_info = ""
            if px.is_grpc:
                grpc_info = (
                    f"{px.grpc_service}/{px.grpc_method}" if px.grpc_service else "yes"
                )
            table.add_row(
                str(px.exchange_index),
                px.method,
                px.url,
                grpc_info,
                req_fields,
                resp_fields,
            )

        out.print(table)

    elif format == "tree":
        for px in proto_exchanges:
            out.print(
                f"\n[bold]Exchange #{px.exchange_index}[/bold]: {px.method} {px.url}"
            )
            if px.is_grpc:
                out.print(f"  gRPC: {px.grpc_service}/{px.grpc_method}")
            if px.request_proto:
                out.print("  [cyan]Request:[/cyan]")
                out.print(format_decoded(px.request_proto, indent=2))
            if px.response_proto:
                out.print("  [cyan]Response:[/cyan]")
                out.print(format_decoded(px.response_proto, indent=2))


@app.command("infer")
def infer(
    har_file: Path = typer.Argument(help="Path to HAR file"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    format: str = typer.Option(
        "proto", "--format", "-f", help="Output format: proto, python"
    ),
):
    """Infer .proto schema from captured traffic."""
    from rekit.hargen.parser import parse_har
    from rekit.protorev.extractor import extract_proto_exchanges
    from rekit.protorev.schema import (
        generate_proto_file,
        generate_python_client,
        infer_schema,
    )

    if not har_file.exists():
        console.print(f"[red]Error:[/red] File not found: {har_file}")
        raise typer.Exit(1)

    exchanges = parse_har(har_file)
    proto_exchanges = extract_proto_exchanges(exchanges)

    if not proto_exchanges:
        console.print("[yellow]No protobuf exchanges found in HAR file[/yellow]")
        raise typer.Exit(0)

    schema = infer_schema(proto_exchanges)

    if format == "proto":
        content = generate_proto_file(schema)
    elif format == "python":
        content = generate_python_client(schema)
    else:
        console.print(f"[red]Error:[/red] Unknown format: {format}")
        raise typer.Exit(1)

    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Schema written to {output}[/green]")
    else:
        out.print(content)


def _resolve_input(input_str: str) -> bytes:
    """Resolve input as hex string, base64 string, or file path."""
    # Try as file path first
    path = Path(input_str)
    if path.exists() and path.is_file():
        return path.read_bytes()

    # Try as hex string
    cleaned = input_str.replace(" ", "").replace("\n", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        pass

    # Try as base64
    try:
        return base64.b64decode(cleaned, validate=True)
    except Exception:
        pass

    # Last resort: treat as raw bytes
    return input_str.encode("utf-8")


def _msg_to_dict(msg) -> dict:
    """Convert ProtoMessage to a JSON-serializable dict."""
    from rekit.protorev.decoder import ProtoMessage

    result = {}
    for f in msg.fields:
        key = str(f.field_number)
        if f.interpretation == "embedded_message" and isinstance(f.value, ProtoMessage):
            result[key] = _msg_to_dict(f.value)
        elif f.interpretation == "bytes" and isinstance(f.value, bytes):
            result[key] = f.value.hex()
        elif f.interpretation == "packed_repeated":
            result[key] = f.value
        else:
            result[key] = f.value
    return result
