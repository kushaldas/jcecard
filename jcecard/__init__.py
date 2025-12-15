"""
jcecard - Virtual OpenPGP Smart Card

A virtual OpenPGP smart card implementation using cryptography
that connects to pcscd via the TCP server on port 9000.
"""

__version__ = "0.1.0"
__author__ = "Kushal Das"

from .apdu import (
    APDUCommand,
    APDUResponse,
    APDUParser,
    APDUBuilder,
    APDUError,
    SW,
    OpenPGPIns,
    PSOP1P2,
)

from .tlv import (
    TLV,
    TLVParser,
    TLVEncoder,
    TLVBuilder,
    TLVError,
    OpenPGPTag,
)

from .atr import (
    ATRBuilder,
    DEFAULT_ATR,
    SIMPLE_ATR,
    create_openpgp_atr,
    create_simple_atr,
)

from .card_data import (
    CardState,
    CardDataStore,
    CardholderData,
    KeySlot,
    PINData,
    AlgorithmAttributes,
)

from .pin_manager import (
    PINManager,
    PINRef,
    PINResult,
    PINVerifyResult,
)

from .security_state import (
    SecurityState,
    AccessCondition,
    OperationAccess,
)

from .crypto_backend import (
    CryptoBackend,
    SimpleCryptoBackend,
    get_crypto_backend,
    KeyType,
    GeneratedKey,
    SignatureResult,
    DecryptionResult,
)

from .main import (
    OpenPGPCard,
    main,
)

from .tcp_server import (
    TCPServer,
    main as tcp_main,
)

# PIV module
from .piv import (
    PIVApplet,
    PIVDataObjects,
    PIVSlot,
    PIVAlgorithm,
)

__all__ = [
    # Version
    "__version__",
    
    # APDU
    "APDUCommand",
    "APDUResponse",
    "APDUParser",
    "APDUBuilder",
    "APDUError",
    "SW",
    "OpenPGPIns",
    "PSOP1P2",
    
    # TLV
    "TLV",
    "TLVParser",
    "TLVEncoder",
    "TLVBuilder",
    "TLVError",
    "OpenPGPTag",
    
    # ATR
    "ATRBuilder",
    "DEFAULT_ATR",
    "SIMPLE_ATR",
    "create_openpgp_atr",
    "create_simple_atr",
    
    # Card Data
    "CardState",
    "CardDataStore",
    "CardholderData",
    "KeySlot",
    "PINData",
    "AlgorithmAttributes",
    
    # PIN Management
    "PINManager",
    "PINRef",
    "PINResult",
    "PINVerifyResult",
    
    # Security State
    "SecurityState",
    "AccessCondition",
    "OperationAccess",
    
    # Crypto Backend
    "CryptoBackend",
    "SimpleCryptoBackend",
    "get_crypto_backend",
    "KeyType",
    "GeneratedKey",
    "SignatureResult",
    "DecryptionResult",
    
    # Main
    "OpenPGPCard",
    "main",
    
    # TCP Server
    "TCPServer",
    "tcp_main",
    
    # PIV
    "PIVApplet",
    "PIVDataObjects",
    "PIVSlot",
    "PIVAlgorithm",
]

