"""
APDU (Application Protocol Data Unit) Module

Implements ISO 7816-4 APDU command parsing and response building.
Supports both short and extended APDU formats.

APDU Command Structure:
- CLA: Class byte
- INS: Instruction byte
- P1:  Parameter 1
- P2:  Parameter 2
- Lc:  Length of command data (optional)
- Data: Command data (optional)
- Le:  Expected response length (optional)

APDU Response Structure:
- Data: Response data (optional)
- SW1:  Status word 1
- SW2:  Status word 2
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class SW(IntEnum):
    """Common ISO 7816-4 Status Words."""
    # Success
    SUCCESS = 0x9000
    
    # Warnings (62XX, 63XX)
    WARNING_NO_CHANGE = 0x6200
    WARNING_DATA_CORRUPTED = 0x6281
    WARNING_END_OF_FILE = 0x6282
    WARNING_FILE_DEACTIVATED = 0x6283
    WARNING_WRONG_FCI = 0x6284
    WARNING_FILE_TERMINATED = 0x6285
    
    # Counter warnings (63CX - X retries remaining)
    WARNING_COUNTER_0 = 0x63C0
    WARNING_COUNTER_1 = 0x63C1
    WARNING_COUNTER_2 = 0x63C2
    WARNING_COUNTER_3 = 0x63C3
    
    # Execution errors (64XX, 65XX, 66XX)
    EXEC_ERROR = 0x6400
    EXEC_MEMORY_FAILURE = 0x6501
    EXEC_WRONG_LENGTH = 0x6700
    
    # Checking errors (67XX - 6FXX)
    WRONG_LENGTH = 0x6700
    
    # Functions in CLA not supported (68XX)
    CLA_FUNC_NOT_SUPPORTED = 0x6800
    LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881
    SECURE_MESSAGING_NOT_SUPPORTED = 0x6882
    
    # Command not allowed (69XX)
    COMMAND_NOT_ALLOWED = 0x6900
    COMMAND_INCOMPATIBLE = 0x6981
    SECURITY_STATUS_NOT_SATISFIED = 0x6982
    AUTH_METHOD_BLOCKED = 0x6983
    REFERENCE_DATA_NOT_USABLE = 0x6984
    CONDITIONS_NOT_SATISFIED = 0x6985
    COMMAND_NOT_ALLOWED_NO_EF = 0x6986
    EXPECTED_SM_DATA_OBJECTS_MISSING = 0x6987
    INCORRECT_SM_DATA_OBJECTS = 0x6988
    
    # Wrong parameters (6AXX)
    WRONG_PARAMETERS = 0x6A00
    WRONG_DATA = 0x6A80
    FUNC_NOT_SUPPORTED = 0x6A81
    FILE_NOT_FOUND = 0x6A82
    RECORD_NOT_FOUND = 0x6A83
    NOT_ENOUGH_MEMORY = 0x6A84
    WRONG_LC = 0x6A85
    INCORRECT_P1_P2 = 0x6A86
    LC_INCONSISTENT_P1_P2 = 0x6A87
    REFERENCED_DATA_NOT_FOUND = 0x6A88
    FILE_ALREADY_EXISTS = 0x6A89
    DF_NAME_EXISTS = 0x6A8A
    
    # Wrong P1/P2 (6BXX)
    WRONG_P1_P2 = 0x6B00
    
    # Wrong Le (6CXX) - Correct Le in SW2
    WRONG_LE = 0x6C00
    
    # INS not supported (6DXX)
    INS_NOT_SUPPORTED = 0x6D00
    
    # CLA not supported (6EXX)
    CLA_NOT_SUPPORTED = 0x6E00
    
    # No precise diagnosis (6FXX)
    UNKNOWN_ERROR = 0x6F00
    
    @classmethod
    def bytes_remaining(cls, remaining: int) -> int:
        """Generate 61XX status word for remaining bytes."""
        return 0x6100 | (remaining & 0xFF)
    
    @classmethod
    def wrong_le_correct(cls, correct_le: int) -> int:
        """Generate 6CXX status word with correct Le."""
        return 0x6C00 | (correct_le & 0xFF)
    
    @classmethod
    def counter_warning(cls, retries: int) -> int:
        """Generate 63CX status word with retry count."""
        return 0x63C0 | (retries & 0x0F)


@dataclass
class APDUCommand:
    """
    Represents a parsed APDU command.
    
    Attributes:
        cla: Class byte
        ins: Instruction byte
        p1: Parameter 1
        p2: Parameter 2
        data: Command data (may be empty)
        le: Expected response length (None if not specified)
        extended: True if extended APDU format
        chained: True if this is a chained command (CLA bit 4 set)
    """
    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes = b''
    le: Optional[int] = None
    extended: bool = False
    chained: bool = False
    
    @property
    def lc(self) -> int:
        """Length of command data."""
        return len(self.data)
    
    @property
    def has_data(self) -> bool:
        """Whether command has data field."""
        return len(self.data) > 0
    
    @property
    def has_le(self) -> bool:
        """Whether command has Le field."""
        return self.le is not None
    
    def __str__(self) -> str:
        """Human-readable representation."""
        parts = [f"CLA={self.cla:02X}", f"INS={self.ins:02X}",
                 f"P1={self.p1:02X}", f"P2={self.p2:02X}"]
        if self.has_data:
            if len(self.data) <= 16:
                parts.append(f"Data={self.data.hex()}")
            else:
                parts.append(f"Data=({len(self.data)} bytes)")
        if self.has_le:
            parts.append(f"Le={self.le}")
        if self.extended:
            parts.append("(extended)")
        if self.chained:
            parts.append("(chained)")
        return f"APDU[{', '.join(parts)}]"


@dataclass
class APDUResponse:
    """
    Represents an APDU response.
    
    Attributes:
        data: Response data (may be empty)
        sw1: Status word 1
        sw2: Status word 2
    """
    data: bytes = b''
    sw1: int = 0x90
    sw2: int = 0x00
    
    @property
    def sw(self) -> int:
        """Combined status word (SW1 << 8 | SW2)."""
        return (self.sw1 << 8) | self.sw2
    
    @sw.setter
    def sw(self, value: int) -> None:
        """Set status word from combined value."""
        self.sw1 = (value >> 8) & 0xFF
        self.sw2 = value & 0xFF
    
    @property
    def is_success(self) -> bool:
        """Check if response indicates success."""
        return self.sw == SW.SUCCESS
    
    @property
    def has_more_data(self) -> bool:
        """Check if more data is available (61XX)."""
        return self.sw1 == 0x61
    
    @property
    def remaining_bytes(self) -> int:
        """Number of remaining bytes (from 61XX status)."""
        if self.sw1 == 0x61:
            return self.sw2
        return 0
    
    def to_bytes(self) -> bytes:
        """Serialize response to bytes."""
        return self.data + bytes([self.sw1, self.sw2])
    
    @classmethod
    def success(cls, data: bytes = b'') -> 'APDUResponse':
        """Create success response."""
        return cls(data=data, sw1=0x90, sw2=0x00)
    
    @classmethod
    def error(cls, sw: int) -> 'APDUResponse':
        """Create error response with given status word."""
        return cls(sw1=(sw >> 8) & 0xFF, sw2=sw & 0xFF)
    
    @classmethod
    def more_data(cls, data: bytes, remaining: int) -> 'APDUResponse':
        """Create response indicating more data available."""
        sw2 = min(remaining, 0xFF)
        return cls(data=data, sw1=0x61, sw2=sw2)
    
    def __str__(self) -> str:
        """Human-readable representation."""
        if len(self.data) <= 16:
            data_str = self.data.hex() if self.data else "(no data)"
        else:
            data_str = f"({len(self.data)} bytes)"
        return f"Response[{data_str}, SW={self.sw1:02X}{self.sw2:02X}]"


class APDUParser:
    """
    Parser for APDU commands.
    
    Supports ISO 7816-4 short and extended APDU formats.
    """
    
    @staticmethod
    def parse(raw: bytes) -> APDUCommand:
        """
        Parse raw bytes into an APDUCommand.
        
        Args:
            raw: Raw APDU bytes
            
        Returns:
            Parsed APDUCommand
            
        Raises:
            APDUError: If APDU is malformed
        """
        if len(raw) < 4:
            raise APDUError("APDU too short (minimum 4 bytes)")
        
        cla = raw[0]
        ins = raw[1]
        p1 = raw[2]
        p2 = raw[3]
        
        # Check if this is a chained command (CLA bit 4)
        chained = bool(cla & 0x10)
        
        data = b''
        le = None
        extended = False
        
        remaining = raw[4:]
        
        # Case 1: No data, no Le (just header)
        if len(remaining) == 0:
            pass
        
        # Short APDU cases
        elif len(remaining) == 1:
            # Case 2S: No data, Le present (short)
            le_byte = remaining[0]
            le = 256 if le_byte == 0 else le_byte
        
        elif len(remaining) > 1:
            # Check for extended APDU format
            if remaining[0] == 0x00 and len(remaining) >= 3:
                # Could be extended format
                extended = True
                lc_extended = (remaining[1] << 8) | remaining[2]
                
                if len(remaining) == 3:
                    # Case 2E: No data, extended Le
                    le = 65536 if lc_extended == 0 else lc_extended
                    data = b''
                elif len(remaining) == 3 + lc_extended:
                    # Case 3E: Data, no Le
                    data = remaining[3:3 + lc_extended]
                elif len(remaining) == 3 + lc_extended + 2:
                    # Case 4E: Data and extended Le
                    data = remaining[3:3 + lc_extended]
                    le_bytes = remaining[3 + lc_extended:]
                    le_extended = (le_bytes[0] << 8) | le_bytes[1]
                    le = 65536 if le_extended == 0 else le_extended
                else:
                    # Re-parse as short format with 0x00 Lc
                    extended = False
                    data, le = APDUParser._parse_short(remaining)
            
            if not extended:
                # Short APDU format
                data, le = APDUParser._parse_short(remaining)
        
        return APDUCommand(
            cla=cla,
            ins=ins,
            p1=p1,
            p2=p2,
            data=data,
            le=le,
            extended=extended,
            chained=chained
        )
    
    @staticmethod
    def _parse_short(remaining: bytes) -> tuple[bytes, Optional[int]]:
        """
        Parse short APDU format from remaining bytes after header.
        
        This parser is lenient and will accept APDUs with extra trailing bytes,
        which some smart card middleware implementations may send.
        
        Returns:
            Tuple of (data, le)
        """
        data = b''
        le = None
        
        lc = remaining[0]
        
        if len(remaining) == 1:
            # Case 2S: Just Le
            le = 256 if lc == 0 else lc
        elif len(remaining) >= 1 + lc:
            # Case 3S or 4S: Lc and data, optionally with Le
            data = remaining[1:1 + lc]
            if len(remaining) >= 1 + lc + 1:
                # Case 4S: Has Le byte
                le_byte = remaining[1 + lc]
                le = 256 if le_byte == 0 else le_byte
                # Note: Any bytes after Le are silently ignored (lenient parsing)
                if len(remaining) > 1 + lc + 1:
                    import logging
                    logging.getLogger(__name__).debug(
                        f"APDU has {len(remaining) - 1 - lc - 1} extra trailing bytes, ignoring"
                    )
        else:
            raise APDUError(f"Invalid APDU length: Lc={lc} but only {len(remaining) - 1} data bytes available")
        
        return (data, le)


class APDUBuilder:
    """
    Builder for APDU commands and responses.
    """
    
    @staticmethod
    def build_command(
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b'',
        le: Optional[int] = None,
        extended: bool = False
    ) -> bytes:
        """
        Build raw APDU command bytes.
        
        Args:
            cla: Class byte
            ins: Instruction byte
            p1: Parameter 1
            p2: Parameter 2
            data: Command data
            le: Expected response length
            extended: Use extended APDU format
            
        Returns:
            Raw APDU bytes
        """
        result = bytes([cla, ins, p1, p2])
        
        # Determine if we need extended format
        need_extended = extended or len(data) > 255 or (le and le > 256)
        
        if need_extended:
            # Extended APDU format
            if data:
                lc = len(data)
                result += bytes([0x00, (lc >> 8) & 0xFF, lc & 0xFF])
                result += data
            else:
                result += bytes([0x00])
            
            if le is not None:
                if le == 65536:
                    le = 0
                result += bytes([(le >> 8) & 0xFF, le & 0xFF])
        else:
            # Short APDU format
            if data:
                lc = len(data)
                result += bytes([lc])
                result += data
            
            if le is not None:
                if le == 256:
                    le = 0
                result += bytes([le])
        
        return result


class APDUError(Exception):
    """Exception raised for APDU parsing errors."""
    pass


# Common OpenPGP card instructions
class OpenPGPIns(IntEnum):
    """OpenPGP card instruction bytes."""
    SELECT = 0xA4
    GET_DATA = 0xCA
    GET_NEXT_DATA = 0xCC
    VERIFY = 0x20
    CHANGE_REFERENCE_DATA = 0x24
    RESET_RETRY_COUNTER = 0x2C
    PUT_DATA = 0xDA
    PUT_DATA_ODD = 0xDB
    GENERATE_ASYMMETRIC_KEY_PAIR = 0x47
    GET_CHALLENGE = 0x84
    INTERNAL_AUTHENTICATE = 0x88
    PSO = 0x2A  # Perform Security Operation
    GET_RESPONSE = 0xC0
    TERMINATE_DF = 0xE6
    ACTIVATE_FILE = 0x44
    MANAGE_SECURITY_ENVIRONMENT = 0x22


# PSO P1P2 combinations
class PSOP1P2(IntEnum):
    """PSO (Perform Security Operation) P1P2 values."""
    CDS = 0x9E9A      # Compute Digital Signature
    DEC = 0x8086      # Decipher
    ENC = 0x8680      # Encipher (not commonly used)
