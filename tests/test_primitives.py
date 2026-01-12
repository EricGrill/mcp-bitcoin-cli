"""Tests for OP_RETURN primitives."""

import pytest
from mcp_bitcoin_cli.primitives import (
    encode_op_return_script,
    decode_op_return_script,
    OP_RETURN,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
)
from mcp_bitcoin_cli.envelope import EnvelopeType, encode_envelope


class TestOpReturnEncoding:
    """Test OP_RETURN script encoding."""

    def test_encode_small_data(self):
        """Encode small data (< 76 bytes) directly."""
        data = b"hello"
        script = encode_op_return_script(data)

        assert script[0] == OP_RETURN
        assert script[1] == len(data)  # Direct push
        assert script[2:] == data

    def test_encode_medium_data(self):
        """Encode medium data (76-255 bytes) with PUSHDATA1."""
        data = b"x" * 100
        script = encode_op_return_script(data)

        assert script[0] == OP_RETURN
        assert script[1] == OP_PUSHDATA1
        assert script[2] == len(data)
        assert script[3:] == data

    def test_encode_large_data(self):
        """Encode large data (256+ bytes) with PUSHDATA2."""
        data = b"x" * 300
        script = encode_op_return_script(data)

        assert script[0] == OP_RETURN
        assert script[1] == OP_PUSHDATA2
        # Little-endian length
        assert int.from_bytes(script[2:4], 'little') == len(data)
        assert script[4:] == data

    def test_encode_with_envelope(self):
        """Encode data wrapped in envelope."""
        data = b"test"
        envelope = encode_envelope(data, EnvelopeType.TEXT)
        script = encode_op_return_script(envelope)

        # Script contains envelope with magic bytes
        assert b"BTCD" in script


class TestOpReturnDecoding:
    """Test OP_RETURN script decoding."""

    def test_decode_small_data(self):
        """Decode small OP_RETURN."""
        data = b"hello"
        script = encode_op_return_script(data)

        decoded = decode_op_return_script(script)
        assert decoded == data

    def test_decode_medium_data(self):
        """Decode medium OP_RETURN with PUSHDATA1."""
        data = b"x" * 100
        script = encode_op_return_script(data)

        decoded = decode_op_return_script(script)
        assert decoded == data

    def test_decode_large_data(self):
        """Decode large OP_RETURN with PUSHDATA2."""
        data = b"x" * 300
        script = encode_op_return_script(data)

        decoded = decode_op_return_script(script)
        assert decoded == data

    def test_decode_invalid_opcode(self):
        """Reject non-OP_RETURN script."""
        script = bytes([0x76, 0x05]) + b"hello"  # OP_DUP instead

        with pytest.raises(ValueError, match="not an OP_RETURN"):
            decode_op_return_script(script)

    def test_roundtrip_max_size(self):
        """Roundtrip near-max OP_RETURN (100KB)."""
        data = b"x" * 99000
        script = encode_op_return_script(data)
        decoded = decode_op_return_script(script)

        assert decoded == data
