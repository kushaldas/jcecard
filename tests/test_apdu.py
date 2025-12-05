"""
Tests for APDU (Application Protocol Data Unit) parsing and building.

Tests cover:
- APDUCommand construction and parsing
- APDUResponse creation and parsing
- APDUParser for various APDU cases
- APDUBuilder for command generation
- Status word interpretation
"""

import pytest
from jcecard.apdu import (
    APDUCommand,
    APDUResponse,
    APDUParser,
    APDUBuilder,
    APDUError,
    SW,
    OpenPGPIns,
    PSOP1P2,
)


class TestAPDUCommand:
    """Tests for APDUCommand dataclass."""
    
    def test_command_creation(self):
        """Test creating an APDU command."""
        cmd = APDUCommand(
            cla=0x00,
            ins=0xA4,
            p1=0x04,
            p2=0x00,
            data=bytes.fromhex("D27600012401"),
            le=0
        )
        assert cmd.cla == 0x00
        assert cmd.ins == 0xA4
        assert cmd.p1 == 0x04
        assert cmd.p2 == 0x00
        assert cmd.data == bytes.fromhex("D27600012401")
    
    def test_command_lc_property(self):
        """Test lc property returns data length."""
        cmd = APDUCommand(cla=0x00, ins=0xDA, p1=0x00, p2=0x5E, data=b"test")
        assert cmd.lc == 4
    
    def test_command_has_data_property(self):
        """Test has_data property."""
        cmd = APDUCommand(cla=0x00, ins=0xC0, p1=0x00, p2=0x00)
        assert not cmd.has_data
        
        cmd = APDUCommand(cla=0x00, ins=0xDA, p1=0x00, p2=0x5E, data=b"test")
        assert cmd.has_data
    
    def test_command_has_le_property(self):
        """Test has_le property."""
        cmd = APDUCommand(cla=0x00, ins=0xC0, p1=0x00, p2=0x00)
        assert not cmd.has_le
        
        cmd = APDUCommand(cla=0x00, ins=0xCA, p1=0x00, p2=0x6E, le=0)
        assert cmd.has_le
    
    def test_command_str(self):
        """Test string representation."""
        cmd = APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00, data=b"aid")
        s = str(cmd)
        assert "INS=A4" in s
        assert "Data=" in s


class TestAPDUResponse:
    """Tests for APDUResponse dataclass."""
    
    def test_response_creation(self):
        """Test creating an APDU response."""
        resp = APDUResponse(sw1=0x90, sw2=0x00, data=b"test")
        assert resp.sw1 == 0x90
        assert resp.sw2 == 0x00
        assert resp.data == b"test"
    
    def test_response_sw_property(self):
        """Test combined status word property."""
        resp = APDUResponse(sw1=0x90, sw2=0x00)
        assert resp.sw == 0x9000
        
        resp = APDUResponse(sw1=0x63, sw2=0xC2)
        assert resp.sw == 0x63C2
    
    def test_response_to_bytes(self):
        """Test encoding response to bytes."""
        resp = APDUResponse(sw1=0x90, sw2=0x00, data=bytes.fromhex("DEADBEEF"))
        data = resp.to_bytes()
        assert data == bytes.fromhex("DEADBEEF9000")
    
    def test_response_to_bytes_no_data(self):
        """Test encoding response with no data."""
        resp = APDUResponse(sw1=0x90, sw2=0x00)
        data = resp.to_bytes()
        assert data == bytes.fromhex("9000")
    
    def test_response_is_success(self):
        """Test success checking."""
        resp = APDUResponse(sw1=0x90, sw2=0x00)
        assert resp.is_success
        
        resp = APDUResponse(sw1=0x63, sw2=0xC2)
        assert not resp.is_success
    
    def test_response_has_more_data(self):
        """Test more data available checking."""
        resp = APDUResponse(sw1=0x61, sw2=0x10)
        assert resp.has_more_data
        assert resp.remaining_bytes == 0x10
        
        resp = APDUResponse(sw1=0x90, sw2=0x00)
        assert not resp.has_more_data


class TestAPDUParser:
    """Tests for APDUParser class."""
    
    def test_parse_select_command(self, sample_apdu_commands):
        """Test parsing SELECT command."""
        cmd = APDUParser.parse(sample_apdu_commands["select"])
        assert cmd.cla == 0x00
        assert cmd.ins == 0xA4
        assert cmd.p1 == 0x04
        assert cmd.p2 == 0x00
        assert cmd.data == bytes.fromhex("D27600012401")
    
    def test_parse_verify_command(self):
        """Test parsing VERIFY command."""
        # VERIFY PW1 mode 81 with PIN "123456"
        raw = bytes.fromhex("00200081") + bytes([6]) + b"123456"
        cmd = APDUParser.parse(raw)
        assert cmd.ins == 0x20
        assert cmd.p2 == 0x81
        assert cmd.data == b"123456"
    
    def test_parse_get_data_command(self, sample_apdu_commands):
        """Test parsing GET DATA command."""
        cmd = APDUParser.parse(sample_apdu_commands["get_data"])
        assert cmd.ins == 0xCA
        assert cmd.p1 == 0x00
        assert cmd.p2 == 0x6E  # Application Related Data tag
    
    def test_parse_case1(self, sample_apdu_commands):
        """Test parsing Case 1 APDU (no data, no Le)."""
        cmd = APDUParser.parse(sample_apdu_commands["case1"])
        assert cmd.ins == 0xC0
        assert cmd.data == b""
    
    def test_parse_too_short(self):
        """Test parsing APDU that's too short."""
        with pytest.raises(APDUError):
            APDUParser.parse(bytes.fromhex("00A4"))
    
    def test_parse_case2_short(self):
        """Test parsing Case 2 short APDU (Le only)."""
        # GET DATA with Le=0 (max)
        raw = bytes.fromhex("00CA006E00")
        cmd = APDUParser.parse(raw)
        assert cmd.ins == 0xCA
        assert cmd.le == 256  # 0x00 means 256 in short form
    
    def test_parse_case3_short(self):
        """Test parsing Case 3 short APDU (data only)."""
        # PUT DATA with 4 bytes
        raw = bytes.fromhex("00DA005E04") + b"test"
        cmd = APDUParser.parse(raw)
        assert cmd.ins == 0xDA
        assert cmd.data == b"test"
        assert cmd.le is None
    
    def test_parse_case4_short(self):
        """Test parsing Case 4 short APDU (data and Le)."""
        # Command with data and Le
        raw = bytes.fromhex("002A9E9A04") + b"hash" + bytes([0x00])
        cmd = APDUParser.parse(raw)
        assert cmd.ins == 0x2A
        assert cmd.data == b"hash"
        assert cmd.le == 256


class TestAPDUBuilder:
    """Tests for APDUBuilder class."""
    
    def test_build_command_basic(self):
        """Test building basic command."""
        raw = APDUBuilder.build_command(0x00, 0xA4, 0x04, 0x00)
        assert raw == bytes.fromhex("00A40400")
    
    def test_build_command_with_data(self):
        """Test building command with data."""
        raw = APDUBuilder.build_command(
            0x00, 0xA4, 0x04, 0x00,
            data=bytes.fromhex("D27600012401")
        )
        assert raw[:4] == bytes.fromhex("00A40400")
        assert raw[4] == 6  # Lc
        assert raw[5:11] == bytes.fromhex("D27600012401")
    
    def test_build_command_with_le(self):
        """Test building command with Le."""
        raw = APDUBuilder.build_command(0x00, 0xCA, 0x00, 0x6E, le=0)
        # Short form: Le=0 means 256
        assert raw == bytes.fromhex("00CA006E00")
    
    def test_build_command_with_data_and_le(self):
        """Test building command with data and Le."""
        raw = APDUBuilder.build_command(
            0x00, 0x2A, 0x9E, 0x9A,
            data=b"hash",
            le=0
        )
        assert raw[:4] == bytes.fromhex("002A9E9A")
        assert raw[4] == 4  # Lc
        assert raw[5:9] == b"hash"
        assert raw[9] == 0  # Le
    
    def test_build_select_command(self):
        """Test building SELECT command for OpenPGP."""
        aid = bytes.fromhex("D27600012401")
        raw = APDUBuilder.build_command(0x00, OpenPGPIns.SELECT, 0x04, 0x00, data=aid)
        assert raw[1] == 0xA4  # SELECT instruction
        assert aid in raw
    
    def test_build_verify_command(self):
        """Test building VERIFY command."""
        pin = b"123456"
        raw = APDUBuilder.build_command(0x00, OpenPGPIns.VERIFY, 0x00, 0x81, data=pin)
        assert raw[1] == 0x20  # VERIFY instruction
        assert raw[3] == 0x81  # PW1 for signing
        assert pin in raw
    
    def test_build_get_data_command(self):
        """Test building GET DATA command."""
        raw = APDUBuilder.build_command(0x00, OpenPGPIns.GET_DATA, 0x00, 0x6E, le=0)
        assert raw[1] == 0xCA  # GET DATA instruction
        assert raw[2] == 0x00
        assert raw[3] == 0x6E  # Application Related Data tag
    
    def test_build_put_data_command(self):
        """Test building PUT DATA command."""
        raw = APDUBuilder.build_command(
            0x00, OpenPGPIns.PUT_DATA, 0x00, 0x5E,
            data=b"test_data"
        )
        assert raw[1] == 0xDA  # PUT DATA instruction
        assert b"test_data" in raw
    
    def test_build_pso_sign_command(self):
        """Test building PSO: COMPUTE DIGITAL SIGNATURE command."""
        hash_data = b"\x00" * 32  # SHA-256 hash
        p1p2 = PSOP1P2.CDS  # 0x9E9A
        raw = APDUBuilder.build_command(
            0x00, OpenPGPIns.PSO,
            (p1p2 >> 8) & 0xFF, p1p2 & 0xFF,
            data=hash_data,
            le=0
        )
        assert raw[1] == 0x2A  # PSO instruction
        assert raw[2] == 0x9E
        assert raw[3] == 0x9A
        assert hash_data in raw
    
    def test_build_pso_decipher_command(self):
        """Test building PSO: DECIPHER command."""
        encrypted_data = b"\x00" * 128
        p1p2 = PSOP1P2.DEC  # 0x8086
        raw = APDUBuilder.build_command(
            0x00, OpenPGPIns.PSO,
            (p1p2 >> 8) & 0xFF, p1p2 & 0xFF,
            data=encrypted_data,
            le=0
        )
        assert raw[1] == 0x2A  # PSO instruction
        assert raw[2] == 0x80
        assert raw[3] == 0x86
    
    def test_build_extended_command(self):
        """Test building extended APDU command."""
        large_data = b"x" * 300
        raw = APDUBuilder.build_command(
            0x00, 0xDA, 0x00, 0x5E,
            data=large_data,
            extended=True
        )
        # Extended format: header + 0x00 + 2-byte Lc
        assert raw[4] == 0x00
        lc = (raw[5] << 8) | raw[6]
        assert lc == 300


class TestSW:
    """Tests for SW (Status Word) enum."""
    
    def test_success_code(self):
        """Test success status word."""
        assert SW.SUCCESS == 0x9000
    
    def test_error_codes(self):
        """Test various error codes."""
        assert SW.WRONG_LENGTH == 0x6700
        assert SW.FILE_NOT_FOUND == 0x6A82
        assert SW.CONDITIONS_NOT_SATISFIED == 0x6985
        assert SW.SECURITY_STATUS_NOT_SATISFIED == 0x6982
    
    def test_wrong_pin_pattern(self):
        """Test wrong PIN status words."""
        # 63 CX where X is retries remaining
        sw = 0x63C2  # 2 retries
        assert (sw & 0xFFF0) == 0x63C0
        assert (sw & 0x000F) == 2


class TestOpenPGPIns:
    """Tests for OpenPGP instruction codes."""
    
    def test_instruction_codes(self):
        """Test instruction byte values."""
        assert OpenPGPIns.SELECT == 0xA4
        assert OpenPGPIns.VERIFY == 0x20
        assert OpenPGPIns.CHANGE_REFERENCE_DATA == 0x24
        assert OpenPGPIns.GET_DATA == 0xCA
        assert OpenPGPIns.PUT_DATA == 0xDA
        assert OpenPGPIns.PSO == 0x2A
        assert OpenPGPIns.GENERATE_ASYMMETRIC_KEY_PAIR == 0x47


class TestAPDUResponseParsing:
    """Tests for APDU response handling."""
    
    def test_response_from_bytes_success(self, sample_apdu_responses):
        """Test creating response from success bytes."""
        raw = sample_apdu_responses["success"]
        # Parse manually since there's no parse_response
        resp = APDUResponse(data=b"", sw1=raw[0], sw2=raw[1])
        assert resp.sw == 0x9000
        assert resp.is_success
    
    def test_response_from_bytes_with_data(self, sample_apdu_responses):
        """Test creating response from bytes with data."""
        raw = sample_apdu_responses["success_with_data"]
        # Data is everything except last 2 bytes
        resp = APDUResponse(data=raw[:-2], sw1=raw[-2], sw2=raw[-1])
        assert resp.sw == 0x9000
        assert resp.is_success
        assert resp.data == bytes.fromhex("DEADBEEF")
    
    def test_response_wrong_pin(self, sample_apdu_responses):
        """Test parsing wrong PIN response."""
        raw = sample_apdu_responses["wrong_pin_2"]
        resp = APDUResponse(sw1=raw[0], sw2=raw[1])
        assert resp.sw == 0x63C2
        assert not resp.is_success
        # Extract retries from SW2
        assert (resp.sw2 & 0x0F) == 2
    
    def test_response_more_data(self, sample_apdu_responses):
        """Test parsing more data available response."""
        raw = sample_apdu_responses["more_data"]
        resp = APDUResponse(sw1=raw[0], sw2=raw[1])
        assert resp.has_more_data
        assert resp.remaining_bytes == 0x10
    
    def test_response_success_factory(self):
        """Test APDUResponse.success factory method."""
        resp = APDUResponse.success(b"test_data")
        assert resp.is_success
        assert resp.data == b"test_data"
    
    def test_response_error_factory(self):
        """Test APDUResponse.error factory method."""
        resp = APDUResponse.error(SW.FILE_NOT_FOUND)
        assert not resp.is_success
        assert resp.sw == SW.FILE_NOT_FOUND
