"""
PIV (Personal Identity Verification) Card Implementation

This module implements NIST SP 800-73-4 PIV card functionality for the jcecard
virtual smart card. It provides PIV applet emulation alongside the existing
OpenPGP card support.

Key Features:
- PIV Application ID: A0 00 00 03 08
- Key Slots: 9A (Auth), 9C (Sign), 9D (Key Mgmt), 9E (Card Auth), 82-95 (Retired)
- Algorithms: RSA 2048, ECC P-256, ECC P-384
- Authentication: PIN (80), PUK (81), Management Key (9B)
- Data Objects: CHUID, CCC, X.509 Certificates
"""

from .applet import PIVApplet, PIV_AID
from .data_objects import PIVDataObjects, PIVSlot, PIVAlgorithm

__all__ = [
    "PIVApplet",
    "PIV_AID",
    "PIVDataObjects",
    "PIVSlot",
    "PIVAlgorithm",
]
