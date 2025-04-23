# mcp-server.py
from mcp.server.fastmcp import FastMCP
from custom_fastmcp import CustomFastMCP
import random
import anyio

# Flag to use CustomFastMCP or standard FastMCP
USE_CUSTOM_FASTMCP = True

# Initialize the MCP server with a friendly name
if USE_CUSTOM_FASTMCP:
    mcp = CustomFastMCP("Demo MCP SSE")
else:
    mcp = FastMCP("Demo MCP SSE")

# Define a tool to get a random number remotely
@mcp.tool()
async def get_remote_random_number() -> int:
    """Returns a random number between 1 and 100.
    Args:
        None
    Returns:
        A random number between 1 and 100.
    """
    return random.randint(1, 100)

# Add a tool to access request headers (only works with CustomFastMCP)
@mcp.tool()
async def get_request_headers() -> dict:
    """Returns the HTTP headers from the client request.
    Args:
        None
    Returns:
        A dictionary of HTTP headers.
    """
    if isinstance(mcp, CustomFastMCP):
        return mcp.get_headers()
    else:
        return {"error": "This tool only works with CustomFastMCP"}

# Add a tool to get a specific header
@mcp.tool()
async def get_header(header_name: str) -> str:
    """Returns a specific HTTP header value.
    Args:
        header_name: The name of the header to retrieve (case-insensitive)
    Returns:
        The header value or "Not found" if the header doesn't exist.
    """
    if isinstance(mcp, CustomFastMCP):
        headers = mcp.get_headers()
        # Headers are case-insensitive
        header_name = header_name.lower()
        for key, value in headers.items():
            if key.lower() == header_name:
                return value
        return "Not found"
    else:
        return "This tool only works with CustomFastMCP"

async def start_server():
    """Start the server."""
    try:
        # Run the MCP server directly without asyncio.run
        await mcp.run_sse_async()
    finally:
        pass

# Run the MCP server with SSE
if __name__ == "__main__":
    # Use anyio.run instead of asyncio.run
    anyio.run(start_server)
