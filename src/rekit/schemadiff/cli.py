"""
schemadiff.cli — Typer CLI subcommand group for schema comparison.

Commands:
    compare   Compare multiple JSON response schemas (default).
    from-har  Extract and compare response schemas from a HAR file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import typer
from rich.console import Console

from rekit.schemadiff.analyzer import (
    ComparisonResult,
    SchemaNode,
    compare_schemas,
    infer_schema,
)
from rekit.schemadiff.display import render_comparison, render_field_matrix
from rekit.schemadiff.generator import generate_mapping_table, generate_python

app = typer.Typer(
    name="schemadiff",
    help="Compare API response schemas and generate unified models.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    """Load and parse a JSON file with clear error messages."""
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {path}")
        raise typer.Exit(1)
    if not path.is_file():
        console.print(f"[red]Error:[/red] Not a file: {path}")
        raise typer.Exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/red] Invalid JSON in {path.name}: {exc.msg} "
                       f"(line {exc.lineno}, col {exc.colno})")
        raise typer.Exit(1)
    except UnicodeDecodeError:
        console.print(f"[red]Error:[/red] Cannot read {path.name} — not valid UTF-8 text.")
        raise typer.Exit(1)

    return data


def _resolve_files(paths: List[Path]) -> List[Path]:
    """Expand directories into their contained JSON files."""
    resolved: List[Path] = []
    for p in paths:
        if p.is_dir():
            json_files = sorted(p.glob("*.json"))
            if not json_files:
                console.print(f"[yellow]Warning:[/yellow] No .json files in directory: {p}")
            resolved.extend(json_files)
        elif p.is_file():
            resolved.append(p)
        else:
            console.print(f"[red]Error:[/red] Path does not exist: {p}")
            raise typer.Exit(1)
    return resolved


def _derive_labels(files: List[Path], user_labels: Optional[str]) -> List[str]:
    """Derive labels from user input or file stems."""
    if user_labels:
        labels = [l.strip() for l in user_labels.split(",")]
        if len(labels) != len(files):
            console.print(
                f"[red]Error:[/red] Got {len(labels)} labels but {len(files)} files. "
                f"Labels must match the number of input files."
            )
            raise typer.Exit(1)
        return labels
    return [f.stem for f in files]


def _filter_keys(data: dict, ignore_keys: Optional[str]) -> dict:
    """Remove ignored keys from a top-level dict."""
    if not ignore_keys or not isinstance(data, dict):
        return data
    keys_to_drop = {k.strip() for k in ignore_keys.split(",")}
    return {k: v for k, v in data.items() if k not in keys_to_drop}


def _output_result(
    result: ComparisonResult,
    fmt: str,
    output: Optional[Path],
    class_name: str,
    labels: List[str],
) -> None:
    """Render or write the comparison result in the requested format."""
    if fmt == "table":
        render_comparison(result, labels)
    elif fmt == "matrix":
        render_field_matrix(result)
    elif fmt == "json":
        payload = json.dumps(result.to_dict(), indent=2, default=str)
        if output:
            output.write_text(payload, encoding="utf-8")
            console.print(f"[green]Written:[/green] {output}")
        else:
            sys.stdout.write(payload + "\n")
    elif fmt == "python":
        code = generate_python(result, class_name=class_name)
        if output:
            output.write_text(code, encoding="utf-8")
            console.print(f"[green]Written:[/green] {output}")
        else:
            sys.stdout.write(code)
    elif fmt == "mapping":
        table_text = generate_mapping_table(result)
        if output:
            output.write_text(table_text, encoding="utf-8")
            console.print(f"[green]Written:[/green] {output}")
        else:
            sys.stdout.write(table_text + "\n")
    else:
        console.print(f"[red]Error:[/red] Unknown format: {fmt}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# compare command (default)
# ---------------------------------------------------------------------------

@app.command()
def compare(
    files: List[Path] = typer.Argument(
        ...,
        help="JSON files or directories to compare.",
        exists=False,  # we validate ourselves for better error messages
    ),
    labels: Optional[str] = typer.Option(
        None,
        "--labels",
        "-l",
        help='Comma-separated labels for each file (e.g., "api1,api2,api3").',
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path. Prints to stdout if omitted.",
    ),
    fmt: str = typer.Option(
        "table",
        "--format",
        "-f",
        help='Output format: "table", "matrix", "json", "python", "mapping".',
    ),
    depth: int = typer.Option(
        3,
        "--depth",
        "-d",
        help="Maximum nesting depth to analyse.",
        min=1,
        max=20,
    ),
    ignore_keys: Optional[str] = typer.Option(
        None,
        "--ignore-keys",
        help='Comma-separated top-level keys to ignore (e.g., "raw,_internal").',
    ),
    class_name: str = typer.Option(
        "UnifiedModel",
        "--class-name",
        help="Class name for generated Python dataclass.",
    ),
) -> None:
    """Compare multiple JSON response schemas.

    Accepts JSON file paths and/or directories (which are expanded to their
    *.json contents).  Infers a schema from each file, then compares field
    presence, types, and naming across all sources.

    Examples:

        rekit schemadiff compare api1.json api2.json api3.json

        rekit schemadiff compare ./responses/ --format python -o model.py

        rekit schemadiff compare a.json b.json --labels "source1,source2" -f json
    """
    resolved = _resolve_files(files)
    if len(resolved) < 2:
        console.print("[red]Error:[/red] Need at least 2 JSON files to compare.")
        raise typer.Exit(1)

    source_labels = _derive_labels(resolved, labels)

    # Load, filter, and infer schemas
    schemas: List[Tuple[str, SchemaNode]] = []
    for path, label in zip(resolved, source_labels):
        console.print(f"  Loading [cyan]{path.name}[/cyan] as [bold]{label}[/bold]...")
        data = _load_json(path)
        data = _filter_keys(data, ignore_keys)

        # Handle top-level arrays: infer schema of first element
        if isinstance(data, list):
            if not data:
                console.print(f"[yellow]Warning:[/yellow] {path.name} is an empty array, skipping.")
                continue
            console.print(f"  [dim]{path.name} is an array ({len(data)} items), using merged element schema.[/dim]")
            data = data[0] if len(data) == 1 else data[0]  # TODO: merge multiple elements
            if not isinstance(data, dict):
                console.print(f"[yellow]Warning:[/yellow] {path.name} array elements are not objects, skipping.")
                continue

        if not isinstance(data, dict):
            console.print(f"[yellow]Warning:[/yellow] {path.name} is not a JSON object, skipping.")
            continue

        schema = infer_schema(data, max_depth=depth)
        schemas.append((label, schema))

    if len(schemas) < 2:
        console.print("[red]Error:[/red] Need at least 2 valid object schemas to compare.")
        raise typer.Exit(1)

    result = compare_schemas(schemas)
    _output_result(result, fmt, output, class_name, source_labels)


# ---------------------------------------------------------------------------
# from-har command
# ---------------------------------------------------------------------------

@app.command("from-har")
def from_har(
    har_file: Path = typer.Argument(
        ...,
        help="Path to the HAR file.",
        exists=True,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path.",
    ),
    fmt: str = typer.Option(
        "table",
        "--format",
        "-f",
        help='Output format: "table", "matrix", "json", "python", "mapping".',
    ),
    depth: int = typer.Option(
        3,
        "--depth",
        "-d",
        help="Maximum nesting depth to analyse.",
        min=1,
        max=20,
    ),
    endpoint: Optional[str] = typer.Option(
        None,
        "--endpoint",
        "-e",
        help="Filter to a specific endpoint path (substring match).",
    ),
    class_name: str = typer.Option(
        "UnifiedModel",
        "--class-name",
        help="Class name for generated Python dataclass.",
    ),
) -> None:
    """Extract response schemas from a HAR file and compare them.

    Parses all JSON responses from the HAR, groups them by endpoint path,
    and compares schemas within each group.  Use ``--endpoint`` to focus on
    a specific endpoint.

    Examples:

        rekit schemadiff from-har traffic.har

        rekit schemadiff from-har traffic.har --endpoint "/api/listings" -f python
    """
    console.print(f"  Loading HAR file [cyan]{har_file.name}[/cyan]...")
    har_data = _load_json(har_file)

    if "log" not in har_data or "entries" not in har_data.get("log", {}):
        console.print("[red]Error:[/red] Invalid HAR file — missing log.entries.")
        raise typer.Exit(1)

    entries = har_data["log"]["entries"]
    console.print(f"  Found [bold]{len(entries)}[/bold] entries in HAR file.")

    # Group responses by endpoint path
    endpoint_responses: Dict[str, List[Tuple[str, dict]]] = {}
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        status = response.get("status", 0)
        content = response.get("content", {})
        mime = content.get("mimeType", "")

        # Only process JSON responses with success status
        if "json" not in mime.lower():
            continue
        if status < 200 or status >= 400:
            continue

        text = content.get("text", "")
        if not text:
            continue

        try:
            body = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            continue

        # Normalise the endpoint path
        parsed = urlparse(url)
        path = parsed.path or "/"
        # Strip numeric IDs from path for grouping
        import re
        normalised = re.sub(r"/\d+(?=/|$)", "/{id}", path)

        if endpoint and endpoint not in normalised:
            continue

        method = request.get("method", "GET").upper()
        label = f"{method} {normalised}"

        if isinstance(body, list) and body and isinstance(body[0], dict):
            body = body[0]
        if not isinstance(body, dict):
            continue

        # Use a unique label per response (method + path + index)
        idx = len(endpoint_responses.get(label, []))
        resp_label = f"resp_{idx}"
        endpoint_responses.setdefault(label, []).append((resp_label, body))

    if not endpoint_responses:
        console.print("[yellow]No JSON responses found in HAR file.[/yellow]")
        raise typer.Exit(0)

    # Process each endpoint group
    for ep_label, responses in sorted(endpoint_responses.items()):
        console.print(f"\n[bold cyan]{ep_label}[/bold cyan] — {len(responses)} response(s)")

        if len(responses) < 2:
            console.print("  [dim]Only one response, showing inferred schema.[/dim]")
            label, body = responses[0]
            schema = infer_schema(body, max_depth=depth)
            # Display single schema as a comparison against itself for consistent output
            result = compare_schemas([(label, schema)])
            if fmt == "table":
                render_comparison(result, [label])
            continue

        schemas: List[Tuple[str, SchemaNode]] = []
        for label, body in responses:
            schema = infer_schema(body, max_depth=depth)
            schemas.append((label, schema))

        result = compare_schemas(schemas)
        resp_labels = [label for label, _ in responses]
        _output_result(result, fmt, output, class_name, resp_labels)
