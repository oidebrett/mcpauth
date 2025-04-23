# mcp-sse
Basic Implementation of an SSE based MCP using only mcp libraries

## Installation

Tested with python version: 3.12.3

### Create virtual environment
```bash
python3 -m venv .venv
```

### Activate virtual environment
```bash
source .venv/bin/activate
```

### Install requirements
```bash
pip install mcp
```

## Using CustomFastMCP to Access HTTP Headers

The project includes a `CustomFastMCP` class that extends the standard `FastMCP` class to capture and expose HTTP headers from client requests. This is particularly useful for:

- Implementing authentication via Authorization headers
- Accessing custom headers like X-Forwarded-User
- Integrating with authentication systems like [MCPAuth](https://github.com/oidebrett/mcpauth)

** DO NOT USE THIS IN PRODUCTION as this will expose confidential data to AI Agents**

### Enabling CustomFastMCP

To use the `CustomFastMCP` class, simply set the `USE_CUSTOM_FASTMCP` flag to `True` in the `mcp-server-sse.py` file:

```python
# Flag to use CustomFastMCP or standard FastMCP
USE_CUSTOM_FASTMCP = True
```

When enabled, the server will capture all HTTP headers from incoming requests and make them available through two additional tools:

1. `get_request_headers()` - Returns all headers as a dictionary
2. `get_header(header_name)` - Returns a specific header value by name (case-insensitive)

### Example Usage

Once enabled, you can access headers in your MCP client:

```
# Get all headers
headers = await mcp.call_tool("get_request_headers")
print(headers)

# Get a specific header
auth_header = await mcp.call_tool("get_header", {"header_name": "Authorization"})
print(auth_header)
```

### Notes

- Using `CustomFastMCP` is optional - the standard `FastMCP` works fine for basic MCP functionality
- Header access is particularly useful when implementing authentication or authorization systems
- This feature can be integrated with external auth systems like MCPAuth

## Use local (Stdio) MCP

Update claude_desktop_config.json with your mcp server config

```bash
{
    "mcpServers": {
         "test-mcp-server": {
            "name": "Test MCP Server",
            "command": "[YOUR_GUTHUB_REPO]/.venv/bin/python",
            "args": ["[YOUR_GUTHUB_REPO]/mcp-server-sse.py"],
            "description": "A simple MCP server to test"
          }
    }
}
```

### Use SSE (requires mcp proxy)

Install mcp-proxy (https://github.com/sparfenyuk/mcp-proxy)

```bash
pip install mcp-proxy
```

Update claude_desktop_config.json with your mcp proxy config

```bash
{
    "mcpServers": {
        "matter-mcp-server-sse-proxied": {
            "command": "[YOUR_GUTHUB_REPO]/.venv/bin/mcp-proxy",
            "env": {
              "SSE_URL": "http://127.0.0.1:8000/sse"
            }
          },   
          "test-mcp-server": {
            "name": "Test MCP Server",
            "command": "[YOUR_GUTHUB_REPO]/.venv/bin/python",
            "args": ["[YOUR_GUTHUB_REPO]/mcp-server-sse.py"],
            "description": "A simple MCP server to test"
          }
    }
}
```

