"""
ATR (Answer To Reset) Module

Generates valid ISO 7816-3 ATR for the virtual OpenPGP card.

ATR Structure:
- TS: Initial character (0x3B = direct convention)
- T0: Format character (indicates presence of TA1, TB1, TC1, TD1 and historical bytes)
- TAi, TBi, TCi, TDi: Interface characters
- Historical bytes: Up to 15 bytes of card identification data
- TCK: Check character (XOR of all bytes from T0 onwards)
"""

from typing import Optional


class ATRBuilder:
    """
    Builder for creating ISO 7816-3 compliant ATR.
    
    The ATR identifies the card to the reader and specifies
    communication parameters.
    """
    
    # Initial character values
    TS_DIRECT = 0x3B      # Direct convention
    TS_INVERSE = 0x3F     # Inverse convention
    
    def __init__(self):
        """Initialize ATR builder with defaults."""
        self.ts = self.TS_DIRECT
        self.historical_bytes = b''
        
        # Interface bytes (optional)
        self.ta1: Optional[int] = None  # FI/DI - clock rate conversion
        self.tb1: Optional[int] = None  # Programming voltage (deprecated)
        self.tc1: Optional[int] = None  # Extra guard time
        self.td1: Optional[int] = None  # Protocol and more interface bytes
        
        self.ta2: Optional[int] = None
        self.tb2: Optional[int] = None
        self.tc2: Optional[int] = None
        self.td2: Optional[int] = None
    
    def set_historical_bytes(self, data: bytes) -> 'ATRBuilder':
        """
        Set the historical bytes.
        
        Args:
            data: Up to 15 bytes of historical data
            
        Returns:
            self for chaining
        """
        if len(data) > 15:
            raise ValueError("Historical bytes cannot exceed 15 bytes")
        self.historical_bytes = data
        return self
    
    def set_protocols(self, t0: bool = True, t1: bool = False) -> 'ATRBuilder':
        """
        Set supported protocols.
        
        Args:
            t0: Support T=0 protocol
            t1: Support T=1 protocol
            
        Returns:
            self for chaining
        """
        if t1 and not t0:
            # T=1 only
            self.td1 = 0x81  # T=1, no more interface bytes
        elif t1 and t0:
            # Both T=0 and T=1
            self.td1 = 0x80  # T=0 with more interface bytes
            self.td2 = 0x01  # T=1
        else:
            # T=0 only (default, no TD1 needed)
            self.td1 = None
        return self
    
    def set_clock_rate(self, fi: int = 1, di: int = 1) -> 'ATRBuilder':
        """
        Set clock rate conversion factor (TA1).
        
        Args:
            fi: Clock rate conversion factor index (0-15)
            di: Baud rate divisor index (0-15)
            
        Returns:
            self for chaining
        """
        self.ta1 = ((fi & 0x0F) << 4) | (di & 0x0F)
        return self
    
    def build(self) -> bytes:
        """
        Build the ATR bytes.
        
        Returns:
            The complete ATR including checksum
        """
        result = bytearray([self.ts])
        
        # Build T0
        # High nibble: interface bytes present (TA1=0x10, TB1=0x20, TC1=0x40, TD1=0x80)
        # Low nibble: number of historical bytes
        t0 = len(self.historical_bytes) & 0x0F
        
        if self.ta1 is not None:
            t0 |= 0x10
        if self.tb1 is not None:
            t0 |= 0x20
        if self.tc1 is not None:
            t0 |= 0x40
        if self.td1 is not None:
            t0 |= 0x80
        
        result.append(t0)
        
        # Add interface bytes for first set
        if self.ta1 is not None:
            result.append(self.ta1)
        if self.tb1 is not None:
            result.append(self.tb1)
        if self.tc1 is not None:
            result.append(self.tc1)
        if self.td1 is not None:
            result.append(self.td1)
            
            # Second set if TD1 indicates more
            if self.td1 & 0x80:
                # TD1 indicates more interface bytes
                if self.ta2 is not None:
                    result.append(self.ta2)
                if self.tb2 is not None:
                    result.append(self.tb2)
                if self.tc2 is not None:
                    result.append(self.tc2)
                if self.td2 is not None:
                    result.append(self.td2)
        
        # Add historical bytes
        result.extend(self.historical_bytes)
        
        # Calculate and add TCK (checksum) if T=1 or T=15 is indicated
        # TCK is XOR of all bytes from T0 to the last historical byte
        if self.td1 is not None:
            tck = 0
            for byte in result[1:]:
                tck ^= byte
            result.append(tck)
        
        return bytes(result)


def create_openpgp_atr() -> bytes:
    """
    Create the default ATR for an OpenPGP card.
    
    This ATR is similar to what real OpenPGP cards (like YubiKey) use.
    
    Returns:
        The ATR bytes
    """
    # Historical bytes for OpenPGP card
    # Category indicator: 0x80 (proprietary)
    # Then card-specific data
    historical = bytes([
        0x31,  # Card service data
        0xC0,  # Card capabilities
        0x73,  # Selection methods
        0xC0,  # Data coding
        0x01,  # Maximum logical channels
        0x40,  # Generic
        0x05,  # Card issuer data length
        0x90, 0x00  # Life cycle status
    ])
    
    builder = ATRBuilder()
    builder.set_historical_bytes(historical)
    builder.set_clock_rate(fi=1, di=1)  # Default speed
    builder.set_protocols(t0=True, t1=True)  # Support both T=0 and T=1
    
    return builder.build()


def create_simple_atr() -> bytes:
    """
    Create a simple ATR for basic operation.
    
    This is a minimal ATR that should work with most readers.
    
    Returns:
        The ATR bytes
    """
    # Very simple ATR similar to basic smart cards
    return bytes([
        0x3B,  # TS: Direct convention
        0x9F,  # T0: TA1, TD1 present, 15 historical bytes
        0x95,  # TA1: Fi=9, Di=5 (higher speed)
        0x81,  # TD1: T=1 protocol, no more interface bytes
        0x31,  # Historical byte
        0xFE,  # Historical byte
        0x9F,  # Historical byte
        0x00,  # Historical byte
        0x66,  # Historical byte
        0x46,  # Historical byte
        0x53,  # Historical byte
        0x05,  # Historical byte
        0x10,  # Historical byte
        0x00,  # Historical byte
        0x11,  # Historical byte
        0x71,  # Historical byte
        0xDF,  # Historical byte
        0x00,  # Historical byte
        0x00,  # Historical byte (padding)
    ])


# Default ATR for the virtual OpenPGP card
# This ATR indicates both T=0 and T=1 protocol support for maximum compatibility
# Structure: TS T0 TD1 TD2 [historical bytes] TCK
# 
# Historical bytes match Yubikey format from 5F52 DO: 00 73 00 00 E0 05 90 00
# - 0x00: Category indicator\n# - 0x73: Card service data
# - 0x00 0x00: Card capabilities
# - 0xE0: Status indicator (lifecycle present)
# - 0x05: Life cycle = operational, TERMINATE DF allowed
# - 0x90 0x00: Status word
#
# T0 = 0x88: TD1 present (0x80), 8 historical bytes (0x08)
# TD1 = 0x80: T=0 protocol, TD2 present
# TD2 = 0x01: T=1 protocol
DEFAULT_ATR = bytes([
    0x3B,  # TS: Direct convention
    0x88,  # T0: TD1 present (0x80), 8 historical bytes (0x08)
    0x80,  # TD1: T=0 protocol, TD2 will follow
    0x01,  # TD2: T=1 protocol, no more interface bytes
    # Historical bytes (Yubikey format):
    0x00,  # Category indicator
    0x73,  # Card service data
    0x00,  # Card capabilities byte 1
    0x00,  # Card capabilities byte 2
    0xE0,  # Status indicator (lifecycle present)
    0x05,  # Life cycle: operational, TERMINATE allowed
    0x90,  # Status word high byte
    0x00,  # Status word low byte
    0x0F,  # TCK: Checksum (XOR of all bytes from T0)
])


# Alternative simpler ATR for compatibility
SIMPLE_ATR = bytes([
    0x3B,  # TS: Direct convention  
    0x80,  # T0: No interface bytes, 0 historical bytes
    0x80,  # TD1: T=0
    0x01,  # TCK
])


# YubiKey-like ATR for maximum compatibility
YUBIKEY_LIKE_ATR = bytes([
    0x3B,  # TS
    0xF8,  # T0
    0x13,  # TA1
    0x00,  # TB1
    0x00,  # TC1
    0x81,  # TD1
    0x31,  # TD2
    0xFE,  # TA3
    0x15,  # TB3
    0x59,  # Historical: 'Y'
    0x75,  # Historical: 'u'
    0x62,  # Historical: 'b'
    0x69,  # Historical: 'i'
    0x6B,  # Historical: 'k'
    0x65,  # Historical: 'e'
    0x79,  # Historical: 'y'
    0x34,  # Historical: '4'
])
