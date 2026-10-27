"""
Protocol and framing module for the Secrecy secure messaging system.

Author: Rishabh Srivastava
Roll No.: 44285
Project: Secrecy

This module provides length-prefixed framing over TCP sockets and JSON message
serialization, schema validation, and error handling.

Framing format:
    [4-byte big-endian unsigned length] + [UTF-8 encoded JSON payload]
"""

import json
import socket
import struct
from typing import Any, Dict, Optional, Tuple

# Protocol limits and defaults
MAX_FRAME_SIZE: int = 65536  # 64 KiB
MAX_PLAINTEXT_BYTES: int = 30000  # Enforces safe payload size comfortably within frame limits
DEFAULT_SOCKET_TIMEOUT: float = 10.0  # Seconds

# Message Types
MSG_KEY_REQUEST = "KEY_REQUEST"
MSG_KEY_RESPONSE = "KEY_RESPONSE"
MSG_SECURE_MESSAGE = "SECURE_MESSAGE"
MSG_STATUS_RESPONSE = "STATUS_RESPONSE"


class ProtocolError(Exception):
    """Base exception for all protocol and framing errors."""
    pass


class ConnectionClosedError(ProtocolError):
    """Raised when the remote socket closes unexpectedly."""
    pass


class FrameTooLargeError(ProtocolError):
    """Raised when an incoming frame exceeds MAX_FRAME_SIZE."""
    pass


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Read exactly `num_bytes` from the socket stream.

    Args:
        sock: Connected TCP socket.
        num_bytes: Number of bytes to read.

    Returns:
        Exact bytes buffer.

    Raises:
        ConnectionClosedError: If socket EOF is reached before receiving all bytes.
        socket.timeout: If socket timeout triggers.
        OSError: On network error.
    """
    chunks = []
    received = 0
    while received < num_bytes:
        chunk = sock.recv(num_bytes - received)
        if not chunk:
            if received == 0:
                raise ConnectionClosedError("Remote connection closed by peer.")
            raise ConnectionClosedError(
                f"Connection closed prematurely (received {received}/{num_bytes} bytes)."
            )
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def send_frame(sock: socket.socket, payload: Dict[str, Any]) -> None:
    """
    Serialize a dictionary to UTF-8 JSON, prefix with a 4-byte big-endian length header,
    and send all bytes over the socket.

    Args:
        sock: Connected TCP socket.
        payload: Python dictionary to serialize.

    Raises:
        FrameTooLargeError: If serialized frame exceeds MAX_FRAME_SIZE.
        ProtocolError: On serialization error.
    """
    if not isinstance(payload, dict):
        raise ProtocolError(f"Payload must be a dictionary, got {type(payload).__name__}.")

    try:
        raw_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except Exception as e:
        raise ProtocolError(f"Failed to serialize payload to JSON: {e}") from e

    frame_length = len(raw_json)
    if frame_length > MAX_FRAME_SIZE:
        raise FrameTooLargeError(
            f"Outgoing frame size ({frame_length} bytes) exceeds maximum ({MAX_FRAME_SIZE} bytes)."
        )

    header = struct.pack(">I", frame_length)
    sock.sendall(header + raw_json)


def recv_frame(sock: socket.socket) -> Dict[str, Any]:
    """
    Receive a length-prefixed JSON frame from the socket and deserialize it.

    Args:
        sock: Connected TCP socket.

    Returns:
        Deserialized dictionary.

    Raises:
        ConnectionClosedError: If remote end disconnected.
        FrameTooLargeError: If frame length header exceeds MAX_FRAME_SIZE.
        ProtocolError: On malformed header, non-UTF8 payload, or invalid JSON.
    """
    header_bytes = _recv_exact(sock, 4)
    (frame_length,) = struct.unpack(">I", header_bytes)

    if frame_length > MAX_FRAME_SIZE:
        raise FrameTooLargeError(
            f"Incoming frame size ({frame_length} bytes) exceeds maximum ({MAX_FRAME_SIZE} bytes)."
        )
    if frame_length == 0:
        raise ProtocolError("Incoming frame length cannot be zero.")

    body_bytes = _recv_exact(sock, frame_length)
    try:
        body_text = body_bytes.decode("utf-8")
        parsed = json.loads(body_text)
    except UnicodeDecodeError as e:
        raise ProtocolError(f"Frame body is not valid UTF-8: {e}") from e
    except json.JSONDecodeError as e:
        raise ProtocolError(f"Frame body is not valid JSON: {e}") from e

    if not isinstance(parsed, dict):
        raise ProtocolError(f"Root JSON element must be an object/dict, got {type(parsed).__name__}.")

    return parsed


# ---------------------------------------------------------------------------
# Message Builders and Validators
# ---------------------------------------------------------------------------

def build_key_request() -> Dict[str, Any]:
    """Build a KEY_REQUEST message."""
    return {
        "type": MSG_KEY_REQUEST,
        "client_name": "SecrecyClient",
        "client_version": "1.0"
    }


def validate_key_request(msg: Dict[str, Any]) -> None:
    """Validate a KEY_REQUEST message."""
    if not isinstance(msg, dict):
        raise ProtocolError("Message must be a dictionary.")
    if msg.get("type") != MSG_KEY_REQUEST:
        raise ProtocolError(f"Expected message type {MSG_KEY_REQUEST}, got {msg.get('type')}.")


def build_key_response(p: int, g: int, server_pub: int) -> Dict[str, Any]:
    """Build a KEY_RESPONSE message containing ElGamal domain parameters and server public key."""
    return {
        "type": MSG_KEY_RESPONSE,
        "status": "OK",
        "p": str(p),
        "g": str(g),
        "server_pub": str(server_pub)
    }


def validate_key_response(msg: Dict[str, Any]) -> Tuple[int, int, int]:
    """
    Validate a KEY_RESPONSE message and return (p, g, server_pub) as integers.
    """
    if not isinstance(msg, dict):
        raise ProtocolError("Message must be a dictionary.")
    if msg.get("type") != MSG_KEY_RESPONSE:
        raise ProtocolError(f"Expected message type {MSG_KEY_RESPONSE}, got {msg.get('type')}.")
    if msg.get("status") != "OK":
        raise ProtocolError(f"Server returned error status: {msg.get('status')}")

    try:
        p = int(msg["p"])
        g = int(msg["g"])
        server_pub = int(msg["server_pub"])
    except (KeyError, ValueError, TypeError) as e:
        raise ProtocolError(f"Malformed or missing numerical fields in KEY_RESPONSE: {e}") from e

    return p, g, server_pub


def build_secure_message(
    c1: int,
    c2: int,
    iv: int,
    ciphertext_bytes: bytes,
    hash_code_hex: str,
    sig_r: int,
    sig_s: int,
    client_pub: int
) -> Dict[str, Any]:
    """
    Build a SECURE_MESSAGE containing all cryptographic artifacts required by the assignment.
    """
    if not (isinstance(iv, int) and 0 <= iv <= 0xFFFF):
        raise ProtocolError(f"Invalid IV value: {iv}")
    if not isinstance(ciphertext_bytes, (bytes, bytearray)):
        raise ProtocolError("Ciphertext must be bytes.")
    if not (isinstance(hash_code_hex, str) and len(hash_code_hex) == 128):
        raise ProtocolError("Hash code must be a 128-character hex string.")

    return {
        "type": MSG_SECURE_MESSAGE,
        "encrypted_key": {
            "c1": str(c1),
            "c2": str(c2)
        },
        "iv": iv,
        "ciphertext": ciphertext_bytes.hex(),
        "hash_code": hash_code_hex.lower(),
        "signature": {
            "r": str(sig_r),
            "s": str(sig_s)
        },
        "client_pub": str(client_pub)
    }


def validate_secure_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and extract parsed cryptographic components from a SECURE_MESSAGE.

    Returns a dict with:
        c1: int
        c2: int
        iv: int
        ciphertext: bytes
        hash_code: str (lowercase hex)
        sig_r: int
        sig_s: int
        client_pub: int
    """
    if not isinstance(msg, dict):
        raise ProtocolError("Message must be a dictionary.")
    if msg.get("type") != MSG_SECURE_MESSAGE:
        raise ProtocolError(f"Expected message type {MSG_SECURE_MESSAGE}, got {msg.get('type')}.")

    try:
        enc_key = msg["encrypted_key"]
        c1 = int(enc_key["c1"])
        c2 = int(enc_key["c2"])
        iv = int(msg["iv"])
        ciphertext_hex = str(msg["ciphertext"])
        ciphertext = bytes.fromhex(ciphertext_hex)
        hash_code = str(msg["hash_code"]).lower()
        sig = msg["signature"]
        sig_r = int(sig["r"])
        sig_s = int(sig["s"])
        client_pub = int(msg["client_pub"])
    except (KeyError, ValueError, TypeError) as e:
        raise ProtocolError(f"Malformed or missing field in SECURE_MESSAGE: {e}") from e

    if not (0 <= iv <= 0xFFFF):
        raise ProtocolError(f"IV out of 16-bit range: {iv}")
    if len(ciphertext) == 0 or len(ciphertext) % 2 != 0:
        raise ProtocolError(f"Ciphertext length must be a positive multiple of 2 bytes, got {len(ciphertext)}.")
    if len(hash_code) != 128:
        raise ProtocolError(f"Whirlpool hash code must be exactly 128 hex chars, got {len(hash_code)}.")

    return {
        "c1": c1,
        "c2": c2,
        "iv": iv,
        "ciphertext": ciphertext,
        "hash_code": hash_code,
        "sig_r": sig_r,
        "sig_s": sig_s,
        "client_pub": client_pub
    }


def build_status_response(
    status: str,
    detail: str,
    signature_valid: bool,
    hash_matched: bool
) -> Dict[str, Any]:
    """Build a STATUS_RESPONSE message."""
    return {
        "type": MSG_STATUS_RESPONSE,
        "status": status,
        "detail": detail,
        "signature_valid": bool(signature_valid),
        "hash_matched": bool(hash_matched)
    }


def validate_status_response(msg: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and extract fields from a STATUS_RESPONSE."""
    if not isinstance(msg, dict):
        raise ProtocolError("Message must be a dictionary.")
    if msg.get("type") != MSG_STATUS_RESPONSE:
        raise ProtocolError(f"Expected message type {MSG_STATUS_RESPONSE}, got {msg.get('type')}.")

    status = msg.get("status")
    if status not in ("ACCEPTED", "REJECTED"):
        raise ProtocolError(f"Invalid status value: {status}")

    return {
        "status": status,
        "detail": str(msg.get("detail", "")),
        "signature_valid": bool(msg.get("signature_valid", False)),
        "hash_matched": bool(msg.get("hash_matched", False))
    }
