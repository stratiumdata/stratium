"""An MCP server for the litellm-guarded service, with one tool the
integration suite grants and one it does not. Each says so when it runs, so a
reply that carries neither sentence came from a call that did not run."""
from mcp.server.mcpserver import MCPServer

server = MCPServer("guarded")


@server.tool()
def read_file(path: str) -> str:
    """Read a file."""
    return f"read_file ran on {path}"


@server.tool()
def write_file(path: str, content: str) -> str:
    """Write a file."""
    return f"write_file ran on {path}"


server.run(transport="streamable-http", host="0.0.0.0", port=9002)
