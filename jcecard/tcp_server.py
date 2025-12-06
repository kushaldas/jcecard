"""
TCP Server for jcecard Virtual Smart Card

This module provides a TCP server that bridges between the IFD handler
(Rust library loaded by pcscd) and the jcecard OpenPGP card implementation.

Protocol:
- All messages are length-prefixed: 4 bytes big-endian length + data
- First byte of data is message type:
  - 0x01: APDU command/response
  - 0x02: POWER_ON
  - 0x03: POWER_OFF
  - 0x04: RESET
  - 0x05: GET_ATR
  - 0x06: PRESENCE check
"""

import argparse
import logging
import os
import signal
import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Optional

from .atr import DEFAULT_ATR
from .main import OpenPGPCard

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Message types
MSG_APDU = 0x01
MSG_POWER_ON = 0x02
MSG_POWER_OFF = 0x03
MSG_RESET = 0x04
MSG_GET_ATR = 0x05
MSG_PRESENCE = 0x06

# Response status
STATUS_OK = 0x00
STATUS_ERROR = 0x01
STATUS_NO_CARD = 0x02


class TCPServer:
    """TCP server for jcecard virtual smart card."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 9999, 
                 storage_path: Optional[Path] = None):
        """
        Initialize the TCP server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            storage_path: Path for persistent card data storage
        """
        self.host = host
        self.port = port
        self.storage_path = storage_path
        self.card: Optional[OpenPGPCard] = None
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.lock = threading.Lock()
        
        # Create the card instance
        self._create_card()
    
    def _create_card(self) -> None:
        """Create the OpenPGP card instance."""
        atr = DEFAULT_ATR
        self.card = OpenPGPCard(atr=atr, storage_path=self.storage_path)
        logger.info("OpenPGP card created")
    
    def _recv_message(self, conn: socket.socket) -> Optional[bytes]:
        """
        Receive a length-prefixed message.
        
        Args:
            conn: The client connection
            
        Returns:
            The message data or None if connection closed
        """
        # Read length (4 bytes, big-endian)
        length_data = b''
        while len(length_data) < 4:
            chunk = conn.recv(4 - len(length_data))
            if not chunk:
                return None
            length_data += chunk
        
        length = struct.unpack(">I", length_data)[0]
        
        if length == 0:
            return b''
        
        if length > 65536:
            logger.error(f"Message too large: {length}")
            return None
        
        # Read message
        data = b''
        while len(data) < length:
            chunk = conn.recv(min(length - len(data), 4096))
            if not chunk:
                return None
            data += chunk
        
        return data
    
    def _send_message(self, conn: socket.socket, data: bytes) -> bool:
        """
        Send a length-prefixed message.
        
        Args:
            conn: The client connection
            data: The data to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            length = struct.pack(">I", len(data))
            conn.sendall(length + data)
            return True
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False
    
    def _handle_message(self, data: bytes) -> bytes:
        """
        Handle an incoming message.
        
        Args:
            data: The message data
            
        Returns:
            The response data
        """
        if not data:
            return bytes([STATUS_ERROR])
        
        msg_type = data[0]
        payload = data[1:] if len(data) > 1 else b''
        
        logger.debug(f"Message type: 0x{msg_type:02X}, payload: {payload.hex()}")
        
        with self.lock:
            if msg_type == MSG_APDU:
                return self._handle_apdu(payload)
            elif msg_type == MSG_POWER_ON:
                return self._handle_power_on()
            elif msg_type == MSG_POWER_OFF:
                return self._handle_power_off()
            elif msg_type == MSG_RESET:
                return self._handle_reset()
            elif msg_type == MSG_GET_ATR:
                return self._handle_get_atr()
            elif msg_type == MSG_PRESENCE:
                return self._handle_presence()
            else:
                logger.warning(f"Unknown message type: 0x{msg_type:02X}")
                return bytes([STATUS_ERROR])
    
    def _handle_apdu(self, apdu: bytes) -> bytes:
        """Handle APDU command."""
        if not self.card:
            return bytes([STATUS_NO_CARD])
        
        logger.info(f"APDU command: {apdu.hex()}")
        
        try:
            response = self.card.process_apdu(apdu)
            logger.info(f"APDU response: {response.hex()}")
            return bytes([STATUS_OK]) + response
        except Exception as e:
            logger.exception(f"Error processing APDU: {e}")
            return bytes([STATUS_ERROR])
    
    def _handle_power_on(self) -> bytes:
        """Handle power on."""
        if not self.card:
            return bytes([STATUS_NO_CARD])
        
        logger.info("Power ON")
        self.card.power_on()
        atr = self.card.get_atr()
        return bytes([STATUS_OK]) + atr
    
    def _handle_power_off(self) -> bytes:
        """Handle power off."""
        if not self.card:
            return bytes([STATUS_NO_CARD])
        
        logger.info("Power OFF")
        self.card.power_off()
        return bytes([STATUS_OK])
    
    def _handle_reset(self) -> bytes:
        """Handle card reset."""
        if not self.card:
            return bytes([STATUS_NO_CARD])
        
        logger.info("Card RESET")
        atr = self.card.reset()
        return bytes([STATUS_OK]) + atr
    
    def _handle_get_atr(self) -> bytes:
        """Handle ATR request."""
        if not self.card:
            return bytes([STATUS_NO_CARD])
        
        atr = self.card.get_atr()
        return bytes([STATUS_OK]) + atr
    
    def _handle_presence(self) -> bytes:
        """Handle presence check."""
        if self.card:
            return bytes([STATUS_OK])
        else:
            return bytes([STATUS_NO_CARD])
    
    def _handle_client(self, conn: socket.socket, addr: tuple) -> None:
        """
        Handle a client connection.
        
        Args:
            conn: The client socket
            addr: The client address
        """
        logger.info(f"Client connected from {addr}")
        
        try:
            while self.running:
                data = self._recv_message(conn)
                if data is None:
                    break
                
                response = self._handle_message(data)
                if not self._send_message(conn, response):
                    break
        except Exception as e:
            logger.exception(f"Error handling client: {e}")
        finally:
            conn.close()
            logger.info(f"Client disconnected: {addr}")
    
    def start(self) -> None:
        """Start the TCP server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        
        self.running = True
        logger.info(f"TCP server listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                # Handle client in a thread
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.exception(f"Error accepting connection: {e}")
    
    def stop(self) -> None:
        """Stop the TCP server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.card:
            self.card.save_state()
        logger.info("TCP server stopped")


def main() -> None:
    """Main entry point for the TCP server."""
    parser = argparse.ArgumentParser(
        description="jcecard TCP Server - Virtual OpenPGP Smart Card"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9999,
        help="Port to listen on (default: 9999)"
    )
    parser.add_argument(
        "--storage",
        type=str,
        default=os.path.expanduser("~/.jcecard"),
        help="Path for persistent card state storage directory"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    storage_path = Path(args.storage) if args.storage else None
    
    server = TCPServer(
        host=args.host,
        port=args.port,
        storage_path=storage_path
    )
    
    def signal_handler(sig, frame):
        logger.info("Received signal, shutting down...")
        server.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
