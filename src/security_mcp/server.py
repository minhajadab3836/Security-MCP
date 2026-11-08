import logging
import os
import signal
import sys
from pathlib import Path
from pydantic import Field

# Ensure package root is in sys.path when executed directly as a script
_pkg_root = Path(__file__).resolve().parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

# Import FastMCP / MCPServer (MCP 2.x renamed FastMCP to MCPServer)
try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    from mcp.server.mcpserver import MCPServer as FastMCP

# Tool implementations
try:
    from security_mcp.tools import (
        lookup_dns,
        inspect_http_headers,
        inspect_ssl_cert,
        lookup_whois,
    )
except ImportError:
    from src.security_mcp.tools import (
        lookup_dns,
        inspect_http_headers,
        inspect_ssl_cert,
        lookup_whois,
    )

# CRITICAL FOR STDIO TRANSPORT:
# Force re-route all logging to stderr so stdout is exclusively reserved for MCP JSON-RPC messages.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
    force=True,
)
logger = logging.getLogger("security_mcp")

# Initialize FastMCP Server instance
mcp = FastMCP("Security OSINT & Network Inspector")


@mcp.tool()
def dns_lookup(
    domain: str = Field(..., description="Target domain name (e.g. 'example.com')")
) -> str:
    """Performs DNS resolution for A, AAAA, MX, and TXT records on a target domain name.

    Args:
        domain: Target domain name (e.g. 'example.com')

    Returns:
        Structured Markdown table containing DNS record types, TTLs, and values.
    """
    logger.info(f"MCP Tool Invocation: dns_lookup for domain={domain}")
    try:
        return lookup_dns(domain)
    except ValueError as err:
        return f"**Input Validation Error:** {err}"
    except Exception as err:
        logger.error(f"Unexpected error in dns_lookup: {err}")
        return f"**Internal Error:** {err}"


@mcp.tool()
def http_header_inspector(
    url: str = Field(..., description="Full target URL (e.g. 'https://example.com')")
) -> str:
    """Fetches HTTP response headers and conducts a security header compliance audit.

    Args:
        url: Full target URL (e.g. 'https://example.com')

    Returns:
        Structured Markdown audit of security headers (HSTS, CSP, CORS, etc.).
    """
    logger.info(f"MCP Tool Invocation: http_header_inspector for url={url}")
    try:
        return inspect_http_headers(url)
    except ValueError as err:
        return f"**Input Validation Error:** {err}"
    except Exception as err:
        logger.error(f"Unexpected error in http_header_inspector: {err}")
        return f"**Internal Error:** {err}"


@mcp.tool()
def ssl_cert_inspector(
    target: str = Field(..., description="Target domain or IP address (e.g. 'example.com')")
) -> str:
    """Inspects TLS/SSL certificate details including Subject, Issuer, SANs, and handshake status.

    Args:
        target: Target domain or IP address (e.g. 'example.com')

    Returns:
        Structured Markdown breakdown of TLS certificate properties.
    """
    logger.info(f"MCP Tool Invocation: ssl_cert_inspector for target={target}")
    try:
        return inspect_ssl_cert(target)
    except ValueError as err:
        return f"**Input Validation Error:** {err}"
    except Exception as err:
        logger.error(f"Unexpected error in ssl_cert_inspector: {err}")
        return f"**Internal Error:** {err}"


@mcp.tool()
def whois_lookup(
    domain: str = Field(..., description="Target domain name (e.g. 'example.com')")
) -> str:
    """Executes WHOIS query to retrieve domain registration, registrar, creation, and expiry data.

    Args:
        domain: Target domain name (e.g. 'example.com')

    Returns:
        Structured Markdown table with domain lifecycle and registrar details.
    """
    logger.info(f"MCP Tool Invocation: whois_lookup for domain={domain}")
    try:
        return lookup_whois(domain)
    except ValueError as err:
        return f"**Input Validation Error:** {err}"
    except Exception as err:
        logger.error(f"Unexpected error in whois_lookup: {err}")
        return f"**Internal Error:** {err}"


def _handle_exit(sig, frame):
    logger.info("Security MCP Server stopped.")
    os._exit(0)


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(
            "Security OSINT & Network Inspector MCP Server\n\n"
            "Usage:\n"
            "  python -m security_mcp.server          Start MCP server on stdio transport (for MCP clients)\n"
            "  python -m security_mcp.server --test   Run tool self-tests\n"
            "  python -m security_mcp.server --help   Show this help message\n\n"
            "MCP Client Configuration Example (Claude Desktop / Cursor):\n"
            "  {\n"
            '    "mcpServers": {\n'
            '      "security-mcp": {\n'
            '        "command": "uv",\n'
            f'        "args": ["--directory", "{Path(__file__).resolve().parent.parent.parent}", "run", "security-mcp"]\n'
            "      }\n"
            "    }\n"
            "  }",
            file=sys.stderr,
        )
        sys.exit(0)

    if "--test" in sys.argv:
        try:
            from security_mcp.test_tools import test_all_tools
        except ImportError:
            from src.security_mcp.test_tools import test_all_tools
        test_all_tools()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)

    if sys.stdin.isatty():
        logger.info(
            "Interactive terminal detected. MCP servers wait on stdin for JSON-RPC messages from an MCP client.\n"
            "  - To test tools directly: python -m security_mcp.server --test\n"
            "  - To inspect interactively: npx @modelcontextprotocol/inspector uv run security-mcp\n"
            "  - Press Ctrl+C to stop."
        )

    logger.info("Starting Security OSINT MCP Server on stdio transport...")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
