"""Tests for MCP server."""

import pytest
from mcp_bitcoin_cli.server import create_server


class TestServerCreation:
    """Test server initialization."""

    def test_create_server_returns_server(self):
        """create_server returns configured server."""
        server = create_server()
        assert server is not None

    def test_server_registers_tools(self):
        """Server registers expected tools."""
        server = create_server()

        # Check that tools are registered by checking the server has a tool manager
        assert hasattr(server, '_tool_manager')

    @pytest.mark.asyncio
    async def test_server_has_expected_tools(self):
        """Server registers all expected tools."""
        server = create_server()

        # Get list of registered tools
        tools = await server.list_tools()
        tool_names = {tool.name for tool in tools}

        # Low-level primitives
        assert "encode_op_return" in tool_names
        assert "decode_op_return" in tool_names
        assert "build_op_return_transaction" in tool_names
        assert "parse_envelope" in tool_names

        # Bitcoin Core interface
        assert "get_node_info" in tool_names
        assert "list_utxos" in tool_names
        assert "broadcast_transaction" in tool_names
        assert "get_transaction" in tool_names
        assert "search_op_returns" in tool_names

        # Token operations
        assert "create_token_deploy" in tool_names
        assert "create_token_mint" in tool_names
        assert "create_token_transfer" in tool_names

        # Document storage
        assert "embed_document" in tool_names
        assert "read_document" in tool_names

        # Timestamping
        assert "create_timestamp" in tool_names
        assert "verify_timestamp" in tool_names

    @pytest.mark.asyncio
    async def test_server_tool_count(self):
        """Server has expected number of tools."""
        server = create_server()

        tools = await server.list_tools()
        # 16 tools total:
        # 4 low-level primitives + 5 bitcoin core + 3 token + 2 document + 2 timestamp
        assert len(tools) == 16
