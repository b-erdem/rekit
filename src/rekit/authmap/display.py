"""authmap.display — Rich output formatting for auth flow analysis."""

from __future__ import annotations

import json
from typing import Any, List

from rich.console import Console
from rich.table import Table

from rekit.authmap.detector import AuthFlow, AuthFlowType

console = Console()

# Display names for flow types
_FLOW_TYPE_LABELS = {
    AuthFlowType.OAUTH2_AUTH_CODE: "OAuth2 Auth Code",
    AuthFlowType.OAUTH2_PKCE: "OAuth2 PKCE",
    AuthFlowType.OAUTH2_CLIENT_CREDENTIALS: "OAuth2 Client Credentials",
    AuthFlowType.OAUTH2_DEVICE_CODE: "OAuth2 Device Code",
    AuthFlowType.CUSTOM_LOGIN: "Custom Login",
    AuthFlowType.API_KEY_STATIC: "Static API Key",
    AuthFlowType.SESSION_COOKIE: "Session Cookie",
    AuthFlowType.BEARER_TOKEN: "Bearer Token",
    AuthFlowType.BASIC_AUTH: "Basic Auth",
    AuthFlowType.HMAC_SIGNATURE: "HMAC Signature",
    AuthFlowType.UNKNOWN: "Unknown",
}

# Step type icons for diagram
_STEP_ICONS = {
    "login_request": "[bold yellow]>>>[/bold yellow]",
    "token_request": "[bold green]>>>[/bold green]",
    "token_response": "[bold green]<<<[/bold green]",
    "api_call_with_token": "[bold blue]-->[/bold blue]",
    "redirect": "[bold cyan]~~~[/bold cyan]",
    "token_refresh": "[bold magenta]>>>[/bold magenta]",
    "token_expired": "[bold red]!!![/bold red]",
    "authorize_request": "[bold cyan]>>>[/bold cyan]",
    "device_code_request": "[bold yellow]>>>[/bold yellow]",
}


def format_flow_diagram(flow: AuthFlow) -> str:
    """Generate a text flow diagram showing authentication steps.

    Args:
        flow: An AuthFlow object with steps to visualize.

    Returns:
        Multi-line string with a text-based flow diagram.
    """
    label = _FLOW_TYPE_LABELS.get(flow.flow_type, flow.flow_type.value)
    lines: List[str] = []
    lines.append(f"[bold]{label}[/bold]")
    lines.append(f"  {flow.description}")
    if flow.token_endpoint:
        lines.append(f"  Token endpoint: {flow.token_endpoint}")
    if flow.login_endpoint:
        lines.append(f"  Login endpoint: {flow.login_endpoint}")
    if flow.redirect_uri:
        lines.append(f"  Redirect URI: {flow.redirect_uri}")
    if flow.refresh_detected:
        lines.append("  [magenta]Token refresh detected[/magenta]")
    lines.append("")

    for i, step in enumerate(flow.steps):
        icon = _STEP_ICONS.get(step.step_type, "[dim]---[/dim]")
        connector = "|" if i < len(flow.steps) - 1 else " "

        lines.append(f"  {icon} [{step.exchange_index}] {step.method} {step.url}")
        lines.append(f"  {connector}   Type: {step.step_type}")
        if step.tokens_sent:
            lines.append(f"  {connector}   Sends: {', '.join(step.tokens_sent)}")
        if step.tokens_received:
            lines.append(f"  {connector}   Receives: {', '.join(step.tokens_received)}")
        if step.description:
            lines.append(f"  {connector}   {step.description}")
        lines.append(f"  {connector}")

    return "\n".join(lines)


def format_flows_table(flows: List[AuthFlow]) -> Table:
    """Generate a Rich table summarizing all detected flows.

    Args:
        flows: List of AuthFlow objects to display.

    Returns:
        Rich Table object.
    """
    table = Table(
        title="Detected Authentication Flows",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Flow Type", style="bold")
    table.add_column("Steps", justify="right")
    table.add_column("Tokens", style="green")
    table.add_column("Refresh", justify="center")
    table.add_column("Endpoints")

    for i, flow in enumerate(flows, 1):
        label = _FLOW_TYPE_LABELS.get(flow.flow_type, flow.flow_type.value)
        tokens = (
            ", ".join(sorted(flow.tokens_involved)) if flow.tokens_involved else "-"
        )
        refresh = "[green]Yes[/green]" if flow.refresh_detected else "[dim]No[/dim]"
        endpoints = []
        if flow.token_endpoint:
            endpoints.append(f"token: {flow.token_endpoint}")
        if flow.login_endpoint:
            endpoints.append(f"login: {flow.login_endpoint}")
        endpoint_str = "\n".join(endpoints) if endpoints else "-"

        table.add_row(
            str(i),
            label,
            str(len(flow.steps)),
            tokens,
            refresh,
            endpoint_str,
        )

    return table


def _flows_to_json(flows: List[AuthFlow]) -> str:
    """Serialize flows to JSON string."""
    data: List[dict] = []
    for flow in flows:
        flow_dict: dict[str, Any] = {
            "flow_type": flow.flow_type.value,
            "description": flow.description,
            "tokens_involved": sorted(flow.tokens_involved),
            "refresh_detected": flow.refresh_detected,
            "token_endpoint": flow.token_endpoint,
            "login_endpoint": flow.login_endpoint,
            "redirect_uri": flow.redirect_uri,
            "steps": [],
        }
        for step in flow.steps:
            flow_dict["steps"].append(
                {
                    "exchange_index": step.exchange_index,
                    "url": step.url,
                    "method": step.method,
                    "step_type": step.step_type,
                    "tokens_sent": step.tokens_sent,
                    "tokens_received": step.tokens_received,
                    "description": step.description,
                }
            )
        data.append(flow_dict)
    return json.dumps(data, indent=2)


def render_flows(flows: List[AuthFlow], format: str = "table") -> None:
    """Render detected auth flows to the console.

    Args:
        flows: List of detected AuthFlow objects.
        format: Output format - "table", "json", or "diagram".
    """
    if format == "json":
        console.print(_flows_to_json(flows))
    elif format == "diagram":
        for flow in flows:
            console.print(format_flow_diagram(flow))
            console.print()
    else:
        table = format_flows_table(flows)
        console.print(table)
