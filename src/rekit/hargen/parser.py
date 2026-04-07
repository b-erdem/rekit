"""
hargen.parser — Parse HAR files and mitmproxy flow dumps into HttpExchange objects.

Supports:
  - HAR 1.2 JSON format (.har)
  - mitmproxy flow files (.flow, .mitm) via mitmproxy's io module
  - Auto-detection based on file extension
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode

from rich.console import Console

logger = logging.getLogger(__name__)
console = Console(stderr=True)


@dataclass
class HttpExchange:
    """A single HTTP request/response pair captured from traffic."""

    method: str
    url: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[Union[str, bytes]] = None
    status_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[Union[str, bytes]] = None
    content_type: str = ""
    timestamp: Optional[datetime] = None

    @property
    def is_json_response(self) -> bool:
        """Check if the response content type is JSON."""
        ct = self.content_type.lower()
        return "application/json" in ct or "+json" in ct

    @property
    def is_json_request(self) -> bool:
        """Check if the request content type is JSON."""
        req_ct = self.request_headers.get("content-type", "").lower()
        return "application/json" in req_ct or "+json" in req_ct

    def parsed_response_json(self) -> Optional[Any]:
        """Attempt to parse response body as JSON, returning None on failure."""
        if not self.response_body:
            return None
        try:
            body = self.response_body
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None

    def parsed_request_json(self) -> Optional[Any]:
        """Attempt to parse request body as JSON, returning None on failure."""
        if not self.request_body:
            return None
        try:
            body = self.request_body
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None


def parse_har(path: Union[str, Path]) -> List[HttpExchange]:
    """
    Parse a HAR 1.2 JSON file into a list of HttpExchange objects.

    Args:
        path: Path to the .har file.

    Returns:
        List of HttpExchange objects extracted from the HAR log entries.

    Raises:
        FileNotFoundError: If the path does not exist.
        ValueError: If the file is not valid HAR JSON.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"HAR file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in HAR file {path}: {exc}") from exc

    if "log" not in data:
        raise ValueError(
            f"Invalid HAR format in {path}: missing 'log' key. Expected HAR 1.2 format."
        )

    log = data["log"]
    entries = log.get("entries", [])

    if not entries:
        console.print(f"[yellow]Warning:[/yellow] HAR file has no entries: {path}")
        return []

    exchanges: List[HttpExchange] = []

    for i, entry in enumerate(entries):
        try:
            exchange = _parse_har_entry(entry, index=i)
            if exchange is not None:
                exchanges.append(exchange)
        except Exception as exc:
            logger.warning("Skipping malformed HAR entry %d: %s", i, exc)
            continue

    return exchanges


def _parse_har_entry(entry: Dict[str, Any], index: int) -> Optional[HttpExchange]:
    """Parse a single HAR entry into an HttpExchange."""
    request = entry.get("request")
    response = entry.get("response")

    if not request:
        logger.warning("HAR entry %d missing 'request' field", index)
        return None

    # --- Request ---
    method = request.get("method", "GET").upper()
    url = request.get("url", "")

    if not url:
        logger.warning("HAR entry %d has empty URL", index)
        return None

    # Parse headers into a flat dict (last value wins for duplicates)
    request_headers = _har_headers_to_dict(request.get("headers", []))

    # Request body from postData
    request_body: Optional[Union[str, bytes]] = None
    post_data = request.get("postData")
    if post_data:
        if "text" in post_data:
            request_body = post_data["text"]
        elif "params" in post_data:
            # Form-encoded params
            params = {p["name"]: p.get("value", "") for p in post_data["params"]}
            request_body = urlencode(params)

    # --- Response ---
    status_code = 0
    response_headers: Dict[str, str] = {}
    response_body: Optional[Union[str, bytes]] = None
    content_type = ""

    if response:
        status_code = response.get("status", 0)
        response_headers = _har_headers_to_dict(response.get("headers", []))

        content = response.get("content", {})
        content_type = content.get("mimeType", "")
        response_text = content.get("text")

        if response_text is not None:
            encoding = content.get("encoding", "")
            if encoding == "base64":
                import base64

                try:
                    response_body = base64.b64decode(response_text)
                except Exception:
                    response_body = response_text
            else:
                response_body = response_text

    # --- Timestamp ---
    timestamp = None
    started = entry.get("startedDateTime")
    if started:
        try:
            # HAR timestamps are ISO 8601
            timestamp = datetime.fromisoformat(started.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass

    return HttpExchange(
        method=method,
        url=url,
        request_headers=request_headers,
        request_body=request_body,
        status_code=status_code,
        response_headers=response_headers,
        response_body=response_body,
        content_type=content_type,
        timestamp=timestamp,
    )


def _har_headers_to_dict(headers: List[Dict[str, str]]) -> Dict[str, str]:
    """Convert HAR-style header list [{"name": ..., "value": ...}] to a dict."""
    result: Dict[str, str] = {}
    for h in headers:
        name = h.get("name", "")
        value = h.get("value", "")
        if name:
            # Normalize header names to lowercase for consistent matching
            result[name.lower()] = value
    return result


def parse_mitmproxy(path: Union[str, Path]) -> List[HttpExchange]:
    """
    Parse a mitmproxy flow file into a list of HttpExchange objects.

    Tries to use mitmproxy's io module for native .flow/.mitm files.
    Falls back to treating the file as HAR if mitmproxy is not installed
    or the file appears to be HAR-exported.

    Args:
        path: Path to the mitmproxy flow file (.flow, .mitm) or exported HAR.

    Returns:
        List of HttpExchange objects.

    Raises:
        FileNotFoundError: If the path does not exist.
        RuntimeError: If parsing fails and mitmproxy is not available.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Mitmproxy flow file not found: {path}")

    # First, try native mitmproxy parsing
    try:
        return _parse_mitmproxy_native(path)
    except ImportError:
        logger.info(
            "mitmproxy not installed; attempting to parse %s as HAR fallback", path
        )
    except Exception as exc:
        logger.warning(
            "Native mitmproxy parsing failed for %s: %s. Trying HAR fallback.",
            path,
            exc,
        )

    # Fallback: try to parse as HAR (mitmproxy can export to HAR)
    try:
        return parse_har(path)
    except (ValueError, json.JSONDecodeError):
        raise RuntimeError(
            f"Could not parse {path} as a mitmproxy flow file. "
            "Install mitmproxy (`pip install mitmproxy`) for native flow support, "
            "or export your capture as HAR format."
        )


def _parse_mitmproxy_native(path: Path) -> List[HttpExchange]:
    """Parse a mitmproxy flow file using the mitmproxy io module."""
    from mitmproxy import io as mitmio  # type: ignore[import-untyped]
    from mitmproxy.http import HTTPFlow  # type: ignore[import-untyped]

    exchanges: List[HttpExchange] = []

    with open(path, "rb") as f:
        reader = mitmio.FlowReader(f)
        for flow in reader.stream():
            if not isinstance(flow, HTTPFlow):
                continue
            if not flow.response:
                continue

            req = flow.request
            resp = flow.response

            # Build URL
            url = req.pretty_url

            # Request headers
            request_headers = {k.lower(): v for k, v in req.headers.items()}

            # Request body
            request_body: Optional[Union[str, bytes]] = None
            if req.content:
                try:
                    request_body = req.content.decode("utf-8", errors="replace")
                except Exception:
                    request_body = req.content

            # Response headers
            response_headers = {k.lower(): v for k, v in resp.headers.items()}

            # Response body
            response_body: Optional[Union[str, bytes]] = None
            if resp.content:
                try:
                    response_body = resp.content.decode("utf-8", errors="replace")
                except Exception:
                    response_body = resp.content

            content_type = resp.headers.get("content-type", "")

            # Timestamp
            timestamp = None
            if hasattr(flow, "timestamp_start") and flow.timestamp_start:
                try:
                    timestamp = datetime.fromtimestamp(flow.timestamp_start)
                except (ValueError, OSError):
                    pass

            exchanges.append(
                HttpExchange(
                    method=req.method.upper(),
                    url=url,
                    request_headers=request_headers,
                    request_body=request_body,
                    status_code=resp.status_code,
                    response_headers=response_headers,
                    response_body=response_body,
                    content_type=content_type,
                    timestamp=timestamp,
                )
            )

    return exchanges


def parse_traffic(path: Union[str, Path]) -> List[HttpExchange]:
    """
    Auto-detect file format and parse HTTP traffic.

    Detection is based on file extension:
      - .har  -> HAR 1.2 JSON
      - .flow, .mitm -> mitmproxy flow format
      - Other -> attempt HAR first, then mitmproxy

    Args:
        path: Path to the traffic capture file.

    Returns:
        List of HttpExchange objects.

    Raises:
        FileNotFoundError: If the path does not exist.
        ValueError: If the format cannot be determined or parsed.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Traffic file not found: {path}")

    suffix = path.suffix.lower()

    if suffix == ".har":
        return parse_har(path)
    elif suffix in (".flow", ".mitm"):
        return parse_mitmproxy(path)
    else:
        # Try HAR first (more common), then mitmproxy
        try:
            return parse_har(path)
        except (ValueError, json.JSONDecodeError):
            pass

        try:
            return parse_mitmproxy(path)
        except Exception:
            pass

        raise ValueError(
            f"Could not determine format of {path}. "
            "Supported formats: .har (HAR 1.2), .flow/.mitm (mitmproxy). "
            "Rename the file with the appropriate extension or ensure it is valid."
        )
