"""tokendump.analyzer — Analyze token lifecycle and authentication flows."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rekit.tokendump.extractor import Token, TokenType, mask_token


@dataclass
class TokenChain:
    """A chain of related token usages across HTTP exchanges.

    Tracks where a token first appears and how it is subsequently used,
    representing the lifecycle of a single authentication credential.
    """

    tokens: List[Token] = field(default_factory=list)
    chain_type: str = ""
    description: str = ""
    first_seen: int = 0
    last_seen: int = 0
    refreshed: bool = False
    usage_count: int = 0


@dataclass
class TokenReport:
    """Aggregated analysis of all tokens found in captured traffic.

    Contains the raw token list, derived chains, and summary statistics.
    """

    tokens: List[Token] = field(default_factory=list)
    chains: List[TokenChain] = field(default_factory=list)
    unique_tokens: int = 0
    jwt_count: int = 0
    summary: str = ""


def analyze_tokens(tokens: List[Token]) -> TokenReport:
    """Analyze extracted tokens and build a comprehensive report.

    Groups tokens by value, builds usage chains, detects refresh patterns
    and OAuth flows, and generates summary statistics.

    Args:
        tokens: List of Token objects from extract_tokens().

    Returns:
        A TokenReport with chains, counts, and a human-readable summary.
    """
    if not tokens:
        return TokenReport(summary="No tokens found in captured traffic.")

    # Group tokens by value
    by_value: Dict[str, List[Token]] = defaultdict(list)
    for tok in tokens:
        by_value[tok.value].append(tok)

    # Build chains
    chains: List[TokenChain] = []
    for value, group in by_value.items():
        group_sorted = sorted(group, key=lambda t: t.exchange_index)
        first = group_sorted[0]
        last = group_sorted[-1]

        chain_type = _infer_chain_type(first)
        has_response_origin = any(
            t.source.startswith("response:") for t in group_sorted
        )
        has_request_usage = any(t.source.startswith("request:") for t in group_sorted)

        if has_response_origin and has_request_usage:
            desc = (
                f"{chain_type} token issued in exchange {first.exchange_index}, "
                f"used in {sum(1 for t in group_sorted if t.source.startswith('request:'))} request(s)"
            )
        elif has_response_origin:
            desc = f"{chain_type} token issued in exchange {first.exchange_index} (not reused in captured traffic)"
        else:
            desc = f"{chain_type} token sent in {len(group_sorted)} request(s)"

        chains.append(
            TokenChain(
                tokens=group_sorted,
                chain_type=chain_type,
                description=desc,
                first_seen=first.exchange_index,
                last_seen=last.exchange_index,
                refreshed=False,
                usage_count=len(group_sorted),
            )
        )

    # Detect refresh patterns: look for OAuth access + refresh token pairs
    _detect_refresh_patterns(chains)

    # Count unique tokens and JWTs
    unique_tokens = len(by_value)
    jwt_count = sum(1 for v, g in by_value.items() if g[0].token_type == TokenType.JWT)

    # Detect OAuth flows
    has_access = any(t.token_type == TokenType.OAUTH_ACCESS for t in tokens)
    has_refresh = any(t.token_type == TokenType.OAUTH_REFRESH for t in tokens)

    # Build summary
    parts = [
        f"Found {unique_tokens} unique token(s) across {len(tokens)} occurrence(s)."
    ]
    if jwt_count:
        parts.append(f"{jwt_count} JWT(s) detected.")
    if has_access and has_refresh:
        parts.append("OAuth2 flow detected (access + refresh tokens).")
    elif has_access:
        parts.append("OAuth2 access token detected.")

    type_counts: Dict[str, int] = defaultdict(int)
    for tok in tokens:
        type_counts[tok.token_type.value] += 1
    type_summary = ", ".join(f"{v} {k}" for k, v in sorted(type_counts.items()))
    parts.append(f"Token types: {type_summary}.")

    summary = " ".join(parts)

    return TokenReport(
        tokens=tokens,
        chains=chains,
        unique_tokens=unique_tokens,
        jwt_count=jwt_count,
        summary=summary,
    )


def _infer_chain_type(token: Token) -> str:
    """Infer a human-readable chain type from a token."""
    return {
        TokenType.JWT: "jwt",
        TokenType.OAUTH_ACCESS: "oauth2_access",
        TokenType.OAUTH_REFRESH: "oauth2_refresh",
        TokenType.SESSION_COOKIE: "session_cookie",
        TokenType.API_KEY: "api_key",
        TokenType.CSRF: "csrf",
        TokenType.BEARER: "bearer",
        TokenType.OPAQUE: "opaque",
        TokenType.UNKNOWN: "unknown",
    }.get(token.token_type, "unknown")


def _detect_refresh_patterns(chains: List[TokenChain]) -> None:
    """Mark chains as refreshed if a new token of same type replaces an old one."""
    by_type: Dict[str, List[TokenChain]] = defaultdict(list)
    for chain in chains:
        by_type[chain.chain_type].append(chain)

    for chain_type, typed_chains in by_type.items():
        if len(typed_chains) > 1 and chain_type in (
            "oauth2_access",
            "jwt",
            "bearer",
            "session_cookie",
        ):
            sorted_chains = sorted(typed_chains, key=lambda c: c.first_seen)
            for i in range(1, len(sorted_chains)):
                sorted_chains[i].refreshed = True
                sorted_chains[i].description += " (refreshed)"


def format_token_table(report: TokenReport, show_values: bool = False) -> Table:
    """Format the token report as a Rich table.

    Args:
        report: The TokenReport to display.
        show_values: If True, show full token values; otherwise mask them.

    Returns:
        A Rich Table object ready for console printing.
    """
    table = Table(title="Extracted Tokens", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Type", style="cyan")
    table.add_column("Source", style="green")
    table.add_column("Exchange", style="yellow", justify="right")
    table.add_column("URL", style="blue", max_width=50)
    table.add_column("Value", style="white", max_width=40)
    table.add_column("Expires", style="red")
    table.add_column("Uses", justify="right")

    # Deduplicate: show each unique token once with usage count
    seen: Dict[str, int] = {}
    rows: List[tuple[Token, int]] = []
    for tok in report.tokens:
        if tok.value not in seen:
            seen[tok.value] = 0
        seen[tok.value] += 1

    displayed: set[str] = set()
    for i, tok in enumerate(report.tokens):
        if tok.value in displayed:
            continue
        displayed.add(tok.value)
        rows.append((tok, seen[tok.value]))

    for idx, (tok, count) in enumerate(rows):
        value_display = tok.value if show_values else mask_token(tok.value)
        expires = str(tok.expires_at.isoformat()) if tok.expires_at else "-"
        table.add_row(
            str(idx + 1),
            tok.token_type.value,
            tok.source,
            str(tok.exchange_index),
            _truncate(tok.url, 50),
            value_display,
            expires,
            str(count),
        )

    return table


def format_jwt_details(token: Token) -> Panel:
    """Format decoded JWT details as a Rich panel.

    Args:
        token: A Token with token_type JWT and decoded data.

    Returns:
        A Rich Panel showing the JWT header and payload.
    """
    if not token.decoded:
        return Panel("No decoded data available", title="JWT Details")

    lines: List[str] = []
    header = token.decoded.get("header", {})
    payload = token.decoded.get("payload", {})

    lines.append("[bold]Header:[/bold]")
    for k, v in header.items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("[bold]Payload:[/bold]")
    for k, v in payload.items():
        lines.append(f"  {k}: {v}")

    if token.expires_at:
        lines.append("")
        lines.append(f"[bold]Expires:[/bold] {token.expires_at.isoformat()}")
    if token.issued_at:
        lines.append(f"[bold]Issued:[/bold] {token.issued_at.isoformat()}")
    if token.scopes:
        lines.append(f"[bold]Scopes:[/bold] {', '.join(token.scopes)}")
    if token.issuer:
        lines.append(f"[bold]Issuer:[/bold] {token.issuer}")
    if token.subject:
        lines.append(f"[bold]Subject:[/bold] {token.subject}")

    content = Text.from_markup("\n".join(lines))
    return Panel(content, title=f"JWT from {token.source}", border_style="cyan")


def format_chain_diagram(chain: TokenChain) -> str:
    """Format a token chain as a text-based flow diagram.

    Args:
        chain: The TokenChain to visualize.

    Returns:
        A string with ASCII art showing token flow.
    """
    lines: List[str] = []
    lines.append(f"Chain: {chain.chain_type} (uses: {chain.usage_count})")
    lines.append(f"  {chain.description}")
    lines.append("")

    for i, tok in enumerate(chain.tokens):
        prefix = "  [origin]" if tok.source.startswith("response:") else "  [use]   "
        arrow = " -->" if i < len(chain.tokens) - 1 else ""
        lines.append(f"{prefix} exchange#{tok.exchange_index} {tok.source}{arrow}")

    return "\n".join(lines)


def _truncate(s: str, max_len: int) -> str:
    """Truncate a string with ellipsis if too long."""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."
