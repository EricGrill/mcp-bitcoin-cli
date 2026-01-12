"""Tests for BTCD envelope encoding/decoding."""

import pytest
from mcp_bitcoin_cli.envelope import (
    Envelope,
    EnvelopeType,
    MAGIC_BYTES,
    VERSION,
    encode_envelope,
    decode_envelope,
)


class TestEnvelopeEncoding:
    """Test envelope encoding."""

    def test_encode_raw_data(self):
        """Encode raw bytes into envelope format."""
        data = b"hello world"
        result = encode_envelope(data, EnvelopeType.RAW)

        assert result[:4] == MAGIC_BYTES
        assert result[4] == VERSION
        assert result[5] == EnvelopeType.RAW.value
        assert result[6:] == data

    def test_encode_text_data(self):
        """Encode text into envelope format."""
        text = "Hello, Bitcoin!"
        result = encode_envelope(text.encode(), EnvelopeType.TEXT)

        assert result[:4] == MAGIC_BYTES
        assert result[5] == EnvelopeType.TEXT.value
        assert result[6:] == text.encode()

    def test_encode_from_hex_string(self):
        """Encode data provided as hex string."""
        hex_data = "deadbeef"
        result = encode_envelope(bytes.fromhex(hex_data), EnvelopeType.RAW)

        assert result[6:] == bytes.fromhex(hex_data)


class TestEnvelopeDecoding:
    """Test envelope decoding."""

    def test_decode_valid_envelope(self):
        """Decode a valid envelope."""
        data = b"test payload"
        encoded = encode_envelope(data, EnvelopeType.RAW)

        envelope = decode_envelope(encoded)

        assert envelope.magic == MAGIC_BYTES
        assert envelope.version == VERSION
        assert envelope.type == EnvelopeType.RAW
        assert envelope.payload == data

    def test_decode_invalid_magic(self):
        """Reject envelope with wrong magic bytes."""
        invalid = b"XXXX\x01\x00test"

        with pytest.raises(ValueError, match="Invalid magic bytes"):
            decode_envelope(invalid)

    def test_decode_too_short(self):
        """Reject envelope that's too short."""
        with pytest.raises(ValueError, match="too short"):
            decode_envelope(b"BTC")


class TestEnvelopeTypes:
    """Test all envelope types."""

    @pytest.mark.parametrize("env_type", list(EnvelopeType))
    def test_roundtrip_all_types(self, env_type):
        """All envelope types encode and decode correctly."""
        data = b"test data"
        encoded = encode_envelope(data, env_type)
        decoded = decode_envelope(encoded)

        assert decoded.type == env_type
        assert decoded.payload == data
