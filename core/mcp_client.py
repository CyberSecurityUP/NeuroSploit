#!/usr/bin/env python3
"""
MCP Client - Model Context Protocol tool connectivity.

Provides a standard interface for connecting to MCP servers and
executing tools. Supports both stdio and SSE transports.

Coexists with existing subprocess-based tool execution:
- MCP is tried first when enabled
- Falls back silently to subprocess if MCP unavailable
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    logger.debug("MCP package not installed. MCP tool connectivity disabled.")

try:
    from mcp.client.sse import sse_client
    HAS_MCP_SSE = True
except ImportError:
    HAS_MCP_SSE = False


class MCPToolClient:
    """Client for connecting to MCP servers and executing tools."""

    def __init__(self, config: Dict):
        mcp_config = config.get('mcp_servers', {})
        self.enabled = mcp_config.get('enabled', False) and HAS_MCP
        self.servers_config = mcp_config.get('servers', {})
        self._sessions: Dict[str, Any] = {}  # server_name -> (session, cleanup)
        self._available_tools: Dict[str, List[Dict]] = {}  # server_name -> tools list

        if self.enabled:
            logger.info(f"MCP client initialized with {len(self.servers_config)} server(s)")
        else:
            if not HAS_MCP and mcp_config.get('enabled', False):
                logger.warning("MCP enabled in config but mcp package not installed. "
                              "Install with: pip install mcp>=1.0.0")

    async def connect(self, server_name: str) -> bool:
        """Establish connection to an MCP server.

        Returns True if connection successful, False otherwise.
        """
        if not self.enabled:
            return False

        if server_name in self._sessions:
            return True  # Already connected

        server_config = self.servers_config.get(server_name)
        if not server_config:
            logger.error(f"MCP server '{server_name}' not found in config")
            return False

        transport = server_config.get('transport', 'stdio')

        try:
            if transport == 'stdio':
                return await self._connect_stdio(server_name, server_config)
            elif transport == 'sse':
                return await self._connect_sse(server_name, server_config)
            else:
                logger.error(f"Unsupported MCP transport: {transport}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to MCP server '{server_name}': {e}")
            return False

    async def _connect_stdio(self, server_name: str, config: Dict) -> bool:
        """Connect to a stdio-based MCP server."""
        if not HAS_MCP:
            return False

        command = config.get('command', '')
        args = config.get('args', [])

        if not command:
            logger.error(f"MCP server '{server_name}' has no command specified")
            return False

        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=config.get('env')
        )

        try:
            # Create the stdio client connection
            read_stream, write_stream = await asyncio.wait_for(
                self._start_stdio_process(server_params),
                timeout=30
            )

            session = ClientSession(read_stream, write_stream)
            await session.initialize()

            # Cache available tools
            tools_result = await session.list_tools()
            self._available_tools[server_name] = [
                {"name": t.name, "description": t.description}
                for t in tools_result.tools
            ]

            self._sessions[server_name] = session
            logger.info(f"Connected to MCP server '{server_name}' via stdio "
                       f"({len(self._available_tools[server_name])} tools available)")
            return True

        except Exception as e:
            logger.error(f"Stdio connection to '{server_name}' failed: {e}")
            return False

    async def _start_stdio_process(self, params: 'StdioServerParameters'):
        """Start a stdio MCP server process."""
        async with stdio_client(params) as (read, write):
            return read, write

    async def _connect_sse(self, server_name: str, config: Dict) -> bool:
        """Connect to an SSE-based MCP server."""
        if not HAS_MCP_SSE:
            logger.error("MCP SSE transport not available")
            return False

        url = config.get('url', '')
        if not url:
            logger.error(f"MCP server '{server_name}' has no URL specified")
            return False

        try:
            async with sse_client(url) as (read, write):
                session = ClientSession(read, write)
                await session.initialize()

                tools_result = await session.list_tools()
                self._available_tools[server_name] = [
                    {"name": t.name, "description": t.description}
                    for t in tools_result.tools
                ]

                self._sessions[server_name] = session
                logger.info(f"Connected to MCP server '{server_name}' via SSE "
                           f"({len(self._available_tools[server_name])} tools available)")
                return True

        except Exception as e:
            logger.error(f"SSE connection to '{server_name}' failed: {e}")
            return False

    async def call_tool(self, server_name: str, tool_name: str,
                         arguments: Optional[Dict] = None) -> Optional[str]:
        """Call a tool on an MCP server.

        Returns the tool result as a string, or None if the call fails.
        """
        if not self.enabled:
            return None

        session = self._sessions.get(server_name)
        if not session:
            connected = await self.connect(server_name)
            if not connected:
                return None
            session = self._sessions.get(server_name)

        try:
            result = await session.call_tool(tool_name, arguments or {})
            # Extract text content from result
            if result.content:
                texts = [c.text for c in result.content if hasattr(c, 'text')]
                return '\n'.join(texts) if texts else str(result.content)
            return ""

        except Exception as e:
            logger.error(f"MCP tool call failed ({server_name}/{tool_name}): {e}")
            return None

    async def list_tools(self, server_name: str = None) -> Dict[str, List[Dict]]:
        """List available tools from MCP servers.

        If server_name is specified, lists tools for that server only.
        Otherwise lists tools from all connected servers.
        """
        if server_name:
            tools = self._available_tools.get(server_name, [])
            return {server_name: tools}

        return dict(self._available_tools)

    def find_tool_server(self, tool_name: str) -> Optional[str]:
        """Find which MCP server provides a given tool.

        Returns the server name, or None if no server has the tool.
        """
        for server_name, tools in self._available_tools.items():
            for tool in tools:
                if tool["name"] == tool_name:
                    return server_name
        return None

    async def try_tool(self, tool_name: str, arguments: Optional[Dict] = None) -> Optional[str]:
        """Try to execute a tool via any available MCP server.

        Searches all configured servers for the tool and executes it.
        Returns None silently if no server has the tool (for fallback pattern).
        """
        if not self.enabled:
            return None

        # Connect to any servers not yet connected
        for server_name in self.servers_config:
            if server_name not in self._sessions:
                await self.connect(server_name)

        server = self.find_tool_server(tool_name)
        if server:
            return await self.call_tool(server, tool_name, arguments)

        return None  # Silent fallback

    async def disconnect_all(self):
        """Disconnect from all MCP servers."""
        for server_name, session in self._sessions.items():
            try:
                if hasattr(session, 'close'):
                    await session.close()
            except Exception as e:
                logger.debug(f"Error closing MCP session '{server_name}': {e}")
        self._sessions.clear()
        self._available_tools.clear()
        logger.info("Disconnected from all MCP servers")
