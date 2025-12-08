"""
TLV (Tag-Length-Value) Module

Implements BER-TLV encoding and decoding as used in ISO 7816 and OpenPGP cards.

BER-TLV Structure:
- Tag: 1 or more bytes identifying the data object
- Length: 1 or more bytes indicating the length of the value
- Value: The actual data

Tag Format:
- Single byte tag: bits 1-5 != 11111 (0x1F)
- Multi-byte tag: first byte bits 1-5 = 11111, subsequent bytes have bit 8 set
  until the last byte

Length Format:
- Short form (0-127): Single byte with bit 8 = 0
- Long form (128+): First byte = 0x81-0x84, followed by that many length bytes

Tag Classes (bits 7-8 of first byte):
- 00: Universal
- 01: Application
- 10: Context-specific
- 11: Private

Constructed vs Primitive (bit 6 of first byte):
- 0: Primitive (contains data)
- 1: Constructed (contains nested TLV objects)
"""

from dataclasses import dataclass, field
from typing import List, Optional, Iterator
import logging


logger = logging.getLogger(__name__)


@dataclass
class TLV:
    """
    Represents a TLV (Tag-Length-Value) data object.
    
    Attributes:
        tag: The tag value (can be multi-byte)
        value: The value bytes (for primitive) or nested TLVs (for constructed)
        children: List of child TLV objects (for constructed TLVs)
    """
    tag: int
    value: bytes = b''
    children: List['TLV'] = field(default_factory=list)
    
    @property
    def is_constructed(self) -> bool:
        """Check if this is a constructed TLV (contains nested TLVs)."""
        # Bit 6 of the first byte indicates constructed
        first_byte = self._get_first_tag_byte()
        return bool(first_byte & 0x20)
    
    @property
    def tag_class(self) -> int:
        """Get the tag class (0=Universal, 1=Application, 2=Context, 3=Private)."""
        first_byte = self._get_first_tag_byte()
        return (first_byte >> 6) & 0x03
    
    @property
    def length(self) -> int:
        """Get the length of the value."""
        if self.children:
            # For constructed TLV, length is sum of encoded children
            return sum(len(child.to_bytes()) for child in self.children)
        return len(self.value)
    
    def _get_first_tag_byte(self) -> int:
        """Get the first byte of the tag."""
        if self.tag <= 0xFF:
            return self.tag
        elif self.tag <= 0xFFFF:
            return (self.tag >> 8) & 0xFF
        elif self.tag <= 0xFFFFFF:
            return (self.tag >> 16) & 0xFF
        else:
            return (self.tag >> 24) & 0xFF
    
    def find(self, tag: int) -> Optional['TLV']:
        """
        Find a TLV with the specified tag (recursive search).
        
        Args:
            tag: The tag to search for
            
        Returns:
            The found TLV or None
        """
        if self.tag == tag:
            return self
        
        for child in self.children:
            result = child.find(tag)
            if result:
                return result
        
        return None
    
    def find_all(self, tag: int) -> List['TLV']:
        """
        Find all TLVs with the specified tag (recursive search).
        
        Args:
            tag: The tag to search for
            
        Returns:
            List of found TLVs
        """
        results = []
        
        if self.tag == tag:
            results.append(self)
        
        for child in self.children:
            results.extend(child.find_all(tag))
        
        return results
    
    def get_child(self, tag: int) -> Optional['TLV']:
        """
        Get a direct child with the specified tag.
        
        Args:
            tag: The tag to search for
            
        Returns:
            The found TLV or None
        """
        for child in self.children:
            if child.tag == tag:
                return child
        return None
    
    def to_bytes(self) -> bytes:
        """
        Encode this TLV to bytes.
        
        Returns:
            The encoded TLV bytes
        """
        result = TLVEncoder.encode_tag(self.tag)
        
        if self.children:
            # Constructed: encode all children
            value_bytes = b''.join(child.to_bytes() for child in self.children)
        else:
            value_bytes = self.value
        
        result += TLVEncoder.encode_length(len(value_bytes))
        result += value_bytes
        
        return result
    
    def __iter__(self) -> Iterator['TLV']:
        """Iterate over children."""
        return iter(self.children)
    
    def __len__(self) -> int:
        """Return number of children."""
        return len(self.children)
    
    def __str__(self) -> str:
        """Human-readable representation."""
        tag_str = f"{self.tag:04X}" if self.tag > 0xFF else f"{self.tag:02X}"
        if self.children:
            return f"TLV[{tag_str}] (constructed, {len(self.children)} children)"
        elif len(self.value) <= 16:
            return f"TLV[{tag_str}] = {self.value.hex()}"
        else:
            return f"TLV[{tag_str}] ({len(self.value)} bytes)"
    
    def pretty_print(self, indent: int = 0) -> str:
        """
        Pretty print the TLV structure.
        
        Args:
            indent: Current indentation level
            
        Returns:
            Formatted string representation
        """
        prefix = "  " * indent
        tag_str = f"{self.tag:04X}" if self.tag > 0xFF else f"{self.tag:02X}"
        
        if self.children:
            lines = [f"{prefix}[{tag_str}] (constructed)"]
            for child in self.children:
                lines.append(child.pretty_print(indent + 1))
            return "\n".join(lines)
        else:
            if len(self.value) <= 32:
                return f"{prefix}[{tag_str}] = {self.value.hex()}"
            else:
                return f"{prefix}[{tag_str}] = ({len(self.value)} bytes)"


class TLVParser:
    """
    Parser for BER-TLV encoded data.
    """
    
    @staticmethod
    def parse(data: bytes, recursive: bool = True) -> List[TLV]:
        """
        Parse TLV data into a list of TLV objects.
        
        Args:
            data: The raw TLV bytes
            recursive: Whether to parse constructed TLVs recursively
            
        Returns:
            List of parsed TLV objects
        """
        result = []
        offset = 0
        
        while offset < len(data):
            # Skip padding bytes (0x00 or 0xFF)
            if data[offset] in (0x00, 0xFF):
                offset += 1
                continue
            
            try:
                tlv, consumed = TLVParser._parse_one(data[offset:], recursive)
                result.append(tlv)
                offset += consumed
            except TLVError as e:
                logger.warning(f"TLV parse error at offset {offset}: {e}")
                break
        
        return result
    
    @staticmethod
    def parse_one(data: bytes, recursive: bool = True) -> TLV:
        """
        Parse a single TLV from the beginning of data.
        
        Args:
            data: The raw TLV bytes
            recursive: Whether to parse constructed TLVs recursively
            
        Returns:
            The parsed TLV object
            
        Raises:
            TLVError: If parsing fails
        """
        tlv, _ = TLVParser._parse_one(data, recursive)
        return tlv
    
    @staticmethod
    def _parse_one(data: bytes, recursive: bool) -> tuple[TLV, int]:
        """
        Parse one TLV and return it with the number of bytes consumed.
        
        Returns:
            Tuple of (TLV, bytes_consumed)
        """
        if len(data) < 2:
            raise TLVError("Data too short for TLV")
        
        # Parse tag
        tag, tag_len = TLVParser._parse_tag(data)
        
        # Parse length
        length, length_len = TLVParser._parse_length(data[tag_len:])
        
        # Extract value
        value_start = tag_len + length_len
        value_end = value_start + length
        
        if value_end > len(data):
            raise TLVError(f"TLV value extends beyond data (need {value_end}, have {len(data)})")
        
        value = data[value_start:value_end]
        
        # Check if constructed and parse children
        first_byte = data[0]
        is_constructed = bool(first_byte & 0x20)
        
        children = []
        if is_constructed and recursive and len(value) > 0:
            try:
                children = TLVParser.parse(value, recursive=True)
            except TLVError:
                # If recursive parsing fails, treat as primitive
                pass
        
        tlv = TLV(tag=tag, value=value if not children else b'', children=children)
        
        return (tlv, value_end)
    
    @staticmethod
    def _parse_tag(data: bytes) -> tuple[int, int]:
        """
        Parse a tag from the data.
        
        Returns:
            Tuple of (tag_value, bytes_consumed)
        """
        if len(data) < 1:
            raise TLVError("Empty data for tag")
        
        first_byte = data[0]
        
        # Check if multi-byte tag
        if (first_byte & 0x1F) == 0x1F:
            # Multi-byte tag
            tag = first_byte
            offset = 1
            
            while offset < len(data):
                byte = data[offset]
                tag = (tag << 8) | byte
                offset += 1
                
                # Last byte has bit 8 clear
                if not (byte & 0x80):
                    break
            else:
                raise TLVError("Unterminated multi-byte tag")
            
            return (tag, offset)
        else:
            # Single byte tag
            return (first_byte, 1)
    
    @staticmethod
    def _parse_length(data: bytes) -> tuple[int, int]:
        """
        Parse a length field from the data.
        
        Returns:
            Tuple of (length_value, bytes_consumed)
        """
        if len(data) < 1:
            raise TLVError("Empty data for length")
        
        first_byte = data[0]
        
        if first_byte < 0x80:
            # Short form
            return (first_byte, 1)
        
        elif first_byte == 0x80:
            # Indefinite length (not supported in OpenPGP)
            raise TLVError("Indefinite length not supported")
        
        elif first_byte == 0x81:
            # Long form: 1 byte length
            if len(data) < 2:
                raise TLVError("Truncated long form length (81)")
            return (data[1], 2)
        
        elif first_byte == 0x82:
            # Long form: 2 byte length
            if len(data) < 3:
                raise TLVError("Truncated long form length (82)")
            return ((data[1] << 8) | data[2], 3)
        
        elif first_byte == 0x83:
            # Long form: 3 byte length
            if len(data) < 4:
                raise TLVError("Truncated long form length (83)")
            return ((data[1] << 16) | (data[2] << 8) | data[3], 4)
        
        elif first_byte == 0x84:
            # Long form: 4 byte length
            if len(data) < 5:
                raise TLVError("Truncated long form length (84)")
            return ((data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4], 5)
        
        else:
            raise TLVError(f"Invalid length byte: {first_byte:02X}")


class TLVEncoder:
    """
    Encoder for BER-TLV data.
    """
    
    @staticmethod
    def encode_tag(tag: int) -> bytes:
        """
        Encode a tag value to bytes.
        
        Args:
            tag: The tag value
            
        Returns:
            The encoded tag bytes
        """
        if tag <= 0xFF:
            return bytes([tag])
        elif tag <= 0xFFFF:
            return bytes([(tag >> 8) & 0xFF, tag & 0xFF])
        elif tag <= 0xFFFFFF:
            return bytes([(tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])
        else:
            return bytes([(tag >> 24) & 0xFF, (tag >> 16) & 0xFF, 
                          (tag >> 8) & 0xFF, tag & 0xFF])
    
    @staticmethod
    def encode_length(length: int) -> bytes:
        """
        Encode a length value to bytes.
        
        Args:
            length: The length value
            
        Returns:
            The encoded length bytes
        """
        if length < 0x80:
            return bytes([length])
        elif length <= 0xFF:
            return bytes([0x81, length])
        elif length <= 0xFFFF:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        elif length <= 0xFFFFFF:
            return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0x84, (length >> 24) & 0xFF, (length >> 16) & 0xFF,
                          (length >> 8) & 0xFF, length & 0xFF])
    
    @staticmethod
    def encode(tag: int, value: bytes) -> bytes:
        """
        Encode a simple TLV.
        
        Args:
            tag: The tag value
            value: The value bytes
            
        Returns:
            The encoded TLV bytes
        """
        return TLVEncoder.encode_tag(tag) + TLVEncoder.encode_length(len(value)) + value
    
    @staticmethod
    def encode_constructed(tag: int, children: List[TLV]) -> bytes:
        """
        Encode a constructed TLV.
        
        Args:
            tag: The tag value (should have bit 6 set)
            children: List of child TLVs
            
        Returns:
            The encoded TLV bytes
        """
        value = b''.join(child.to_bytes() for child in children)
        return TLVEncoder.encode_tag(tag) + TLVEncoder.encode_length(len(value)) + value


class TLVBuilder:
    """
    Builder for constructing TLV structures.
    """
    
    def __init__(self, tag: int, constructed: bool = False):
        """
        Initialize a TLV builder.
        
        Args:
            tag: The tag for this TLV
            constructed: Whether this is a constructed TLV
        """
        self.tag = tag
        self.value = b''
        self.children: List[TLV] = []
        self.constructed = constructed
    
    def set_value(self, value: bytes) -> 'TLVBuilder':
        """Set the value for a primitive TLV."""
        self.value = value
        return self
    
    def add_child(self, tag: int, value: bytes) -> 'TLVBuilder':
        """Add a child TLV (for constructed TLVs)."""
        self.children.append(TLV(tag=tag, value=value))
        self.constructed = True
        return self
    
    def add_child_tlv(self, tlv: TLV) -> 'TLVBuilder':
        """Add a child TLV object."""
        self.children.append(tlv)
        self.constructed = True
        return self
    
    def build(self) -> TLV:
        """Build the TLV object."""
        if self.constructed:
            return TLV(tag=self.tag, children=self.children)
        else:
            return TLV(tag=self.tag, value=self.value)
    
    def to_bytes(self) -> bytes:
        """Build and encode to bytes."""
        return self.build().to_bytes()


class TLVError(Exception):
    """Exception raised for TLV parsing errors."""
    pass


# Common OpenPGP card tags
class OpenPGPTag:
    """Common OpenPGP card data object tags."""
    # Application related
    AID = 0x4F
    APPLICATION_RELATED_DATA = 0x6E
    LOGIN_DATA = 0x5E
    
    # Cardholder related
    CARDHOLDER_RELATED_DATA = 0x65
    NAME = 0x5B
    LANGUAGE_PREFERENCE = 0x5F2D
    SEX = 0x5F35
    
    # Public key URL
    URL = 0x5F50
    
    # Historical bytes
    HISTORICAL_BYTES = 0x5F52
    
    # Security support template
    SECURITY_SUPPORT_TEMPLATE = 0x7A
    DIGITAL_SIGNATURE_COUNTER = 0x93
    
    # Cardholder certificate
    CARDHOLDER_CERTIFICATE = 0x7F21
    
    # Extended capabilities
    EXTENDED_CAPABILITIES = 0xC0
    
    # Algorithm attributes
    ALGORITHM_ATTRIBUTES_SIG = 0xC1
    ALGORITHM_ATTRIBUTES_DEC = 0xC2
    ALGORITHM_ATTRIBUTES_AUT = 0xC3
    
    # PW Status
    PW_STATUS_BYTES = 0xC4
    
    # Fingerprints
    FINGERPRINTS = 0xC5
    CA_FINGERPRINTS = 0xC6
    
    # Key generation timestamps
    KEY_GENERATION_TIMESTAMPS = 0xCD
    
    # Key information
    KEY_INFORMATION = 0xDE
    
    # UIF (User Interaction Flags)
    UIF_SIG = 0xD6
    UIF_DEC = 0xD7
    UIF_AUT = 0xD8
    
    # Private use DOs
    PRIVATE_DO_1 = 0x0101
    PRIVATE_DO_2 = 0x0102
    PRIVATE_DO_3 = 0x0103
    PRIVATE_DO_4 = 0x0104
    
    # Control Reference Template for key generation
    CRT_SIG = 0xB6
    CRT_DEC = 0xB8
    CRT_AUT = 0xA4
    
    # Public key
    PUBLIC_KEY = 0x7F49
    RSA_MODULUS = 0x81
    RSA_EXPONENT = 0x82
    ECC_PUBLIC_KEY = 0x86
    
    # Algorithm information
    ALGORITHM_INFORMATION = 0xFA
    
    # Extended header list (for key import)
    EXTENDED_HEADER_LIST = 0x4D
    PRIVATE_KEY_TEMPLATE = 0x7F48
