"""
schemadiff.display — Rich terminal display for schema comparison results.

Renders colourful tables, field matrices, and summary statistics using the
Rich library for clear, at-a-glance understanding of how multiple API
schemas overlap.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rekit.schemadiff.analyzer import ComparisonResult, MergedField

console = Console()

# Symbols
_CHECK = Text("\u2713", style="bold green")
_DASH = Text("\u2014", style="dim")
_CONFLICT = Text("\u26a0", style="bold red")


# ---------------------------------------------------------------------------
# Main comparison table
# ---------------------------------------------------------------------------

def render_comparison(
    result: ComparisonResult,
    labels: Optional[List[str]] = None,
) -> None:
    """Render a Rich table comparing fields across sources.

    Columns: Field Name | Type | source1 | source2 | ...

    Colour coding:
      - Green rows for universal fields (present in all sources).
      - Yellow rows for common fields (present in majority).
      - Dim rows for unique fields (present in one or few sources).
      - Red type annotation for type conflicts.

    Parameters:
        result: The :class:`ComparisonResult` to render.
        labels: Override source labels (defaults to ``result.labels``).
    """
    labels = labels or result.labels

    table = Table(
        title="Schema Comparison",
        title_style="bold cyan",
        show_lines=True,
        expand=True,
        padding=(0, 1),
    )

    table.add_column("Field", style="bold", no_wrap=True, min_width=20)
    table.add_column("Type", min_width=10)
    for label in labels:
        table.add_column(label, justify="center", min_width=6)

    # Collect conflict field names for quick lookup
    conflict_names = {tc.field_name for tc in result.type_conflicts}

    # Render rows grouped: universal -> common -> unique
    _add_field_rows(table, result.universal_fields, labels, "green", conflict_names, "universal")
    _add_field_rows(table, result.common_fields, labels, "yellow", conflict_names, "common")

    # Unique fields — flatten from per-source dict
    unique_flat: Dict[str, MergedField] = {}
    for src_fields in result.unique_fields.values():
        for name, mf in src_fields.items():
            if name not in unique_flat:
                unique_flat[name] = mf
    _add_field_rows(table, unique_flat, labels, "dim", conflict_names, "unique")

    console.print()
    console.print(table)

    # Summary
    _render_summary(result)


def _add_field_rows(
    table: Table,
    fields: Dict[str, MergedField],
    labels: List[str],
    row_style: str,
    conflict_names: set,
    category: str,
) -> None:
    """Add rows for a category of fields to the table."""
    if not fields:
        return

    # Section separator
    num_cols = 2 + len(labels)
    section_label = Text(f"  {category.upper()} FIELDS ({len(fields)})", style=f"bold {row_style}")
    table.add_row(section_label, *[""] * (num_cols - 1), style="dim")

    for name in sorted(fields.keys()):
        mf = fields[name]

        # Field name
        field_text = Text(name, style=row_style)

        # Type column
        if name in conflict_names:
            type_text = Text(mf.suggested_type, style="bold red")
            types_detail = ", ".join(sorted(mf.types_seen - {"null"}))
            type_text.append(f" ({types_detail})", style="red")
        else:
            type_text = Text(mf.suggested_type, style=row_style)

        # Source presence columns
        source_cells = []
        for label in labels:
            if label in mf.sources_present:
                source_cells.append(_CHECK)
            else:
                source_cells.append(_DASH)

        table.add_row(field_text, type_text, *source_cells)


def _render_summary(result: ComparisonResult) -> None:
    """Render summary statistics panel."""
    stats = result.stats
    total = stats.get("total_fields", 0)
    universal = stats.get("universal_count", 0)
    universal_pct = stats.get("universal_pct", 0)
    common = stats.get("common_count", 0)
    unique = stats.get("unique_count", 0)
    conflicts = stats.get("type_conflict_count", 0)
    sources = stats.get("sources", 0)

    summary_lines = [
        f"[bold]Sources:[/bold] {sources} ({', '.join(result.labels)})",
        f"[bold]Total fields:[/bold] {total}",
        f"[bold green]Universal:[/bold green] {universal} ({universal_pct}%)",
        f"[bold yellow]Common:[/bold yellow] {common}",
        f"[dim]Unique:[/dim] {unique}",
    ]
    if conflicts > 0:
        summary_lines.append(f"[bold red]Type conflicts:[/bold red] {conflicts}")

    console.print()
    console.print(Panel(
        "\n".join(summary_lines),
        title="Summary",
        border_style="cyan",
        expand=False,
    ))


# ---------------------------------------------------------------------------
# Compact field matrix
# ---------------------------------------------------------------------------

def render_field_matrix(result: ComparisonResult) -> None:
    """Render a compact matrix view of all fields across all sources.

    This is a denser view than :func:`render_comparison`, showing just
    field presence as a grid of checkmarks without type information.

    Parameters:
        result: The :class:`ComparisonResult` to render.
    """
    labels = result.labels
    all_fields = result.all_fields

    if not all_fields:
        console.print("[yellow]No fields to display.[/yellow]")
        return

    table = Table(
        title="Field Presence Matrix",
        title_style="bold cyan",
        show_lines=False,
        padding=(0, 1),
        expand=False,
    )

    table.add_column("Field", style="bold", no_wrap=True, min_width=25)
    for label in labels:
        table.add_column(label, justify="center", min_width=4)
    table.add_column("#", justify="right", min_width=3)

    for name in sorted(all_fields.keys()):
        mf = all_fields[name]
        count = len(mf.sources_present)

        # Determine row style based on coverage
        if mf.is_universal:
            name_style = "green"
        elif count > len(labels) / 2:
            name_style = "yellow"
        else:
            name_style = "dim"

        field_text = Text(name, style=name_style)

        cells = []
        for label in labels:
            if label in mf.sources_present:
                cells.append(Text("\u2713", style="green"))
            else:
                cells.append(Text("\u00b7", style="dim"))

        count_text = Text(str(count), style=name_style)
        table.add_row(field_text, *cells, count_text)

    console.print()
    console.print(table)

    # Type conflicts detail
    if result.type_conflicts:
        _render_type_conflicts(result)

    _render_summary(result)


def _render_type_conflicts(result: ComparisonResult) -> None:
    """Render detailed type conflict information."""
    table = Table(
        title="Type Conflicts",
        title_style="bold red",
        show_lines=True,
        expand=False,
    )

    table.add_column("Field", style="bold", no_wrap=True)
    for label in result.labels:
        table.add_column(label, justify="center")
    table.add_column("Suggested", style="bold cyan")

    for tc in result.type_conflicts:
        cells = []
        for label in result.labels:
            t = tc.types_by_source.get(label, "-")
            style = "red" if t != tc.suggested_type and t != "-" else ""
            cells.append(Text(t, style=style))

        table.add_row(
            Text(tc.field_name, style="bold red"),
            *cells,
            Text(tc.suggested_type, style="bold cyan"),
        )

    console.print()
    console.print(table)
