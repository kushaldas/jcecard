"""
vpcd Connection Module

Handles TCP socket communication with the vpcd (virtual PC/SC daemon driver).
Implements the vpcd protocol for virtual smart card communication.

Protocol:
- All messages are length-prefixed (2-byte big-endian)
- Control messages have length=1
- APDU messages have length > 1

Control message types:
- VPCD_CTRL_OFF (0): Power off
- VPCD_CTRL_ON (1): Power on
- VPCD_CTRL_RESET (2): Reset
- VPCD_CTRL_ATR (4): Request ATR
"""

import socket
import struct
import logging
from typing import Callable, Optional
from enum import IntEnum


# Configure module logger
logger = logging.getLogger(__name__)


class VPCDControl(IntEnum):
    """vpcd control message types."""
    OFF = 0      # Power off
    ON = 1       # Power on
    RESET = 2    # Reset card
    ATR = 4      # Request ATR


class VPCDConnection:
    """
    Manages the TCP socket connection to vpcd.
    
    The vpcd driver listens on a TCP port (default 35963) and acts as
    a bridge between pcscd and the virtual smart card implementation.
    
    Attributes:
        host: The hostname/IP to connect to (default: localhost)
        port: The TCP port number (default: 35963)
        sock: The TCP socket connection
        connected: Whether currently connected to vpcd
    """
    
    DEFAULT_HOST = 'localhost'
    DEFAULT_PORT = 35963
    RECV_BUFFER_SIZE = 65536  # Support extended APDUs
    LENGTH_PREFIX_SIZE = 2
    CTRL_MSG_LENGTH = 1
    
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        """
        Initialize the vpcd connection.
        
        Args:
            host: The hostname/IP to connect to
            port: The TCP port number
        """
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.connected = False
        
        # Callbacks for handling events
        self._on_power_on: Optional[Callable[[], None]] = None
        self._on_power_off: Optional[Callable[[], None]] = None
        self._on_reset: Optional[Callable[[], bytes]] = None
        self._on_atr_request: Optional[Callable[[], bytes]] = None
        self._on_apdu: Optional[Callable[[bytes], bytes]] = None
    
    def set_callbacks(
        self,
        on_power_on: Optional[Callable[[], None]] = None,
        on_power_off: Optional[Callable[[], None]] = None,
        on_reset: Optional[Callable[[], bytes]] = None,
        on_atr_request: Optional[Callable[[], bytes]] = None,
        on_apdu: Optional[Callable[[bytes], bytes]] = None
    ) -> None:
        """
        Set callback functions for handling vpcd events.
        
        Args:
            on_power_on: Called when card is powered on
            on_power_off: Called when card is powered off
            on_reset: Called on card reset, should return ATR
            on_atr_request: Called when ATR is requested, should return ATR
            on_apdu: Called with APDU command bytes, should return response bytes
        """
        if on_power_on:
            self._on_power_on = on_power_on
        if on_power_off:
            self._on_power_off = on_power_off
        if on_reset:
            self._on_reset = on_reset
        if on_atr_request:
            self._on_atr_request = on_atr_request
        if on_apdu:
            self._on_apdu = on_apdu
    
    def connect(self) -> bool:
        """
        Establish connection to vpcd.
        
        Returns:
            True if connection successful, False otherwise
        """
        if self.connected:
            logger.warning("Already connected to vpcd")
            return True
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock.connect((self.host, self.port))
            self.connected = True
            logger.info(f"Connected to vpcd at {self.host}:{self.port}")
            return True
        except socket.error as e:
            logger.error(f"Failed to connect to vpcd: {e}")
            self.sock = None
            self.connected = False
            return False
    
    def disconnect(self) -> None:
        """Close the connection to vpcd."""
        if self.sock:
            try:
                self.sock.close()
            except socket.error as e:
                logger.warning(f"Error closing socket: {e}")
            finally:
                self.sock = None
                self.connected = False
                logger.info("Disconnected from vpcd")
    
    def reconnect(self) -> bool:
        """
        Reconnect to vpcd.
        
        Returns:
            True if reconnection successful, False otherwise
        """
        self.disconnect()
        return self.connect()
    
    def _recv_exact(self, num_bytes: int) -> bytes:
        """
        Receive exact number of bytes from socket.
        
        Args:
            num_bytes: Number of bytes to receive
            
        Returns:
            The received bytes
            
        Raises:
            ConnectionError: If connection is lost
        """
        if self.sock is None:
            raise ConnectionError("Not connected to vpcd")
        data = b''
        while len(data) < num_bytes:
            chunk = self.sock.recv(num_bytes - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by vpcd")
            data += chunk
        return data
    
    def _send_message(self, data: bytes) -> None:
        """
        Send a length-prefixed message to vpcd.
        
        Args:
            data: The message payload to send
        """
        if self.sock is None:
            raise ConnectionError("Not connected to vpcd")
        # Prepend 2-byte big-endian length
        length = struct.pack('>H', len(data))
        self.sock.sendall(length + data)
        logger.debug(f"Sent {len(data)} bytes: {data.hex()}")
    
    def _recv_message(self) -> tuple[int, bytes]:
        """
        Receive a length-prefixed message from vpcd.
        
        Returns:
            Tuple of (length, payload)
            
        Raises:
            ConnectionError: If connection is lost
        """
        # Read 2-byte big-endian length
        length_data = self._recv_exact(self.LENGTH_PREFIX_SIZE)
        length = struct.unpack('>H', length_data)[0]
        
        if length == 0:
            return (0, b'')
        
        # Read payload
        payload = self._recv_exact(length)
        logger.debug(f"Received {length} bytes: {payload.hex()}")
        return (length, payload)
    
    def send_atr(self, atr: bytes) -> None:
        """
        Send ATR (Answer To Reset) to vpcd.
        
        Args:
            atr: The ATR bytes to send
        """
        self._send_message(atr)
        logger.info(f"Sent ATR: {atr.hex()}")
    
    def send_response(self, response: bytes) -> None:
        """
        Send APDU response to vpcd.
        
        Args:
            response: The response bytes (data + status word)
        """
        self._send_message(response)
        logger.debug(f"Sent response: {response.hex()}")
    
    def _handle_control_message(self, ctrl: int) -> Optional[bytes]:
        """
        Handle a control message from vpcd.
        
        Args:
            ctrl: The control message type
            
        Returns:
            ATR bytes if ATR should be sent, None otherwise
        """
        try:
            ctrl_type = VPCDControl(ctrl)
        except ValueError:
            logger.warning(f"Unknown control message: {ctrl}")
            return None
        
        logger.info(f"Control message: {ctrl_type.name}")
        
        if ctrl_type == VPCDControl.OFF:
            if self._on_power_off:
                self._on_power_off()
            return None
        
        elif ctrl_type == VPCDControl.ON:
            if self._on_power_on:
                self._on_power_on()
            return None
        
        elif ctrl_type == VPCDControl.RESET:
            if self._on_reset:
                return self._on_reset()
            return None
        
        elif ctrl_type == VPCDControl.ATR:
            if self._on_atr_request:
                return self._on_atr_request()
            return None
        
        return None
    
    def process_one_message(self) -> bool:
        """
        Process a single message from vpcd.
        
        This method blocks until a message is received, processes it,
        and sends any response.
        
        Returns:
            True if message was processed, False if connection lost
        """
        try:
            length, payload = self._recv_message()
            
            # Control message (length == 1)
            if length == self.CTRL_MSG_LENGTH:
                ctrl = payload[0]
                atr = self._handle_control_message(ctrl)
                if atr:
                    self.send_atr(atr)
            
            # APDU command (length > 1)
            elif length > self.CTRL_MSG_LENGTH:
                if self._on_apdu:
                    response = self._on_apdu(payload)
                    self.send_response(response)
                else:
                    # No handler, return generic error
                    logger.warning("No APDU handler registered")
                    self.send_response(bytes([0x6F, 0x00]))  # No precise diagnosis
            
            return True
            
        except ConnectionError as e:
            logger.error(f"Connection error: {e}")
            self.connected = False
            return False
        except Exception as e:
            logger.exception(f"Error processing message: {e}")
            return False
    
    def run(self) -> None:
        """
        Main event loop - process messages until disconnected.
        
        This method will block and continuously process messages
        from vpcd until the connection is closed.
        """
        if not self.connected:
            if not self.connect():
                raise ConnectionError("Failed to connect to vpcd")
        
        logger.info("Starting vpcd message loop")
        
        while self.connected:
            if not self.process_one_message():
                break
        
        logger.info("vpcd message loop ended")
        self.disconnect()


class VPCDConnectionError(Exception):
    """Exception raised for vpcd connection errors."""
    pass
