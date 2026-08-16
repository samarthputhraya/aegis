"""Aegis MCP server — verification actions over the Model Context Protocol."""
from __future__ import annotations
import os
from mcp.server.fastmcp import FastMCP
from mcp_server import tools

mcp = FastMCP("aegis-verify")


@mcp.tool()
def get_vendor(key: str) -> dict:
    """Fetch vendor record incl. bank details on file and known contacts."""
    return tools.get_vendor(key)


@mcp.tool()
def verify_vendor_bank(vendor_key: str, requested_iban: str) -> dict:
    """Compare a requested IBAN against the IBAN on file (BEC check)."""
    return tools.verify_vendor_bank(vendor_key, requested_iban)


@mcp.tool()
def open_verification_task(title: str, body: str = "") -> dict:
    """Open an out-of-band verification/escalation task."""
    return tools.open_verification_task(title, body)


if __name__ == "__main__":
    mcp.run(transport="streamable-http" if os.getenv("MCP_HTTP") else "stdio")
