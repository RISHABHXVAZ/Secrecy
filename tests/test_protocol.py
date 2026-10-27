"""
Comprehensive unit tests for the Secrecy network protocol and framing.

Author: Rishabh Srivastava
Roll No.: 44285
Project: Secrecy
"""

import socket
import struct
import unittest

from secrecy.protocol import (
    DEFAULT_SOCKET_TIMEOUT,
    MAX_FRAME_SIZE,
    MAX_PLAINTEXT_BYTES,
    MSG_KEY_REQUEST,
    MSG_KEY_RESPONSE,
    MSG_SECURE_MESSAGE,
    MSG_STATUS_RESPONSE,
    ConnectionClosedError,
    FrameTooLargeError,
    ProtocolError,
    build_key_request,
    build_key_response,
    build_secure_message,
    build_status_response,
    recv_frame,
    send_frame,
    validate_key_request,
    validate_key_response,
    validate_secure_message,
    validate_status_response,
)


class TestProtocolFraming(unittest.TestCase):
    """Test socket framing, length prefixes, and error handling."""

    def setUp(self):
        self.sock_client, self.sock_server = socket.socketpair()
        self.sock_client.settimeout(2.0)
        self.sock_server.settimeout(2.0)

    def tearDown(self):
        self.sock_client.close()
        self.sock_server.close()

    def test_roundtrip_frame(self):
        """Verify sending and receiving valid JSON frames through connected sockets."""
        payload = {"type": "TEST", "data": "Hello, Secrecy!", "number": 44285}
        send_frame(self.sock_client, payload)
        received = recv_frame(self.sock_server)
        self.assertEqual(received, payload)

    def test_frame_too_large_outgoing(self):
        """Verify that outgoing frames exceeding MAX_FRAME_SIZE raise FrameTooLargeError."""
        oversized = {"big": "X" * (MAX_FRAME_SIZE + 10)}
        with self.assertRaises(FrameTooLargeError):
            send_frame(self.sock_client, oversized)

    def test_frame_too_large_incoming(self):
        """Verify that incoming frames declaring length > MAX_FRAME_SIZE are rejected."""
        fake_header = struct.pack(">I", MAX_FRAME_SIZE + 100)
        self.sock_client.sendall(fake_header)
        with self.assertRaises(FrameTooLargeError):
            recv_frame(self.sock_server)

    def test_zero_length_frame_rejected(self):
        """Verify that incoming frame declaring 0 bytes length is rejected."""
        zero_header = struct.pack(">I", 0)
        self.sock_client.sendall(zero_header)
        with self.assertRaises(ProtocolError):
            recv_frame(self.sock_server)

    def test_connection_closed_on_header(self):
        """Verify that socket closing before header is complete raises ConnectionClosedError."""
        self.sock_client.close()
        with self.assertRaises(ConnectionClosedError):
            recv_frame(self.sock_server)

    def test_connection_closed_mid_payload(self):
        """Verify that socket closing mid-payload raises ConnectionClosedError."""
        header = struct.pack(">I", 50)
        partial_data = b'{"half":'
        self.sock_client.sendall(header + partial_data)
        self.sock_client.close()
        with self.assertRaises(ConnectionClosedError):
            recv_frame(self.sock_server)

    def test_invalid_json_payload_rejected(self):
        """Verify that invalid JSON payload raises ProtocolError."""
        bad_json = b"{invalid_json_content"
        header = struct.pack(">I", len(bad_json))
        self.sock_client.sendall(header + bad_json)
        with self.assertRaises(ProtocolError):
            recv_frame(self.sock_server)


class TestMessageSchemas(unittest.TestCase):
    """Test builders and strict validators for all protocol message types."""

    def test_key_request_lifecycle(self):
        """Verify KEY_REQUEST creation and validation."""
        req = build_key_request()
        self.assertEqual(req["type"], MSG_KEY_REQUEST)
        validate_key_request(req)

        # Invalid type
        with self.assertRaises(ProtocolError):
            validate_key_request({"type": "WRONG"})

    def test_key_response_lifecycle(self):
        """Verify KEY_RESPONSE creation and validation."""
        p = 23
        g = 5
        server_pub = 8
        resp = build_key_response(p, g, server_pub)
        parsed_p, parsed_g, parsed_pub = validate_key_response(resp)
        self.assertEqual((parsed_p, parsed_g, parsed_pub), (p, g, server_pub))

        # Missing field
        bad_resp = {"type": MSG_KEY_RESPONSE, "status": "OK", "p": "23"}
        with self.assertRaises(ProtocolError):
            validate_key_response(bad_resp)

        # Error status
        err_resp = {"type": MSG_KEY_RESPONSE, "status": "ERROR"}
        with self.assertRaises(ProtocolError):
            validate_key_response(err_resp)

    def test_secure_message_lifecycle(self):
        """Verify SECURE_MESSAGE creation and validation."""
        c1 = 12345
        c2 = 67890
        iv = 0x1234
        ciphertext = b"\x01\x02\x03\x04"
        hash_code = "a" * 128
        sig_r = 11111
        sig_s = 22222
        client_pub = 33333

        msg = build_secure_message(
            c1=c1,
            c2=c2,
            iv=iv,
            ciphertext_bytes=ciphertext,
            hash_code_hex=hash_code,
            sig_r=sig_r,
            sig_s=sig_s,
            client_pub=client_pub
        )
        self.assertEqual(msg["type"], MSG_SECURE_MESSAGE)

        parsed = validate_secure_message(msg)
        self.assertEqual(parsed["c1"], c1)
        self.assertEqual(parsed["c2"], c2)
        self.assertEqual(parsed["iv"], iv)
        self.assertEqual(parsed["ciphertext"], ciphertext)
        self.assertEqual(parsed["hash_code"], hash_code)
        self.assertEqual(parsed["sig_r"], sig_r)
        self.assertEqual(parsed["sig_s"], sig_s)
        self.assertEqual(parsed["client_pub"], client_pub)

    def test_secure_message_validation_failures(self):
        """Verify that malformed SECURE_MESSAGE contents are rejected."""
        # Invalid IV out of range
        with self.assertRaises(ProtocolError):
            build_secure_message(1, 2, 0x10000, b"\x01\x02", "a" * 128, 3, 4, 5)

        # Invalid hash length
        with self.assertRaises(ProtocolError):
            build_secure_message(1, 2, 0x1234, b"\x01\x02", "short_hash", 3, 4, 5)

        # Non-bytes ciphertext in builder
        with self.assertRaises(ProtocolError):
            build_secure_message(1, 2, 0x1234, "not_bytes", "a" * 128, 3, 4, 5)

    def test_status_response_lifecycle(self):
        """Verify STATUS_RESPONSE creation and validation."""
        resp = build_status_response("ACCEPTED", "Signature valid and hash matches.", True, True)
        parsed = validate_status_response(resp)
        self.assertEqual(parsed["status"], "ACCEPTED")
        self.assertTrue(parsed["signature_valid"])
        self.assertTrue(parsed["hash_matched"])

        # Invalid status string
        with self.assertRaises(ProtocolError):
            validate_status_response({"type": MSG_STATUS_RESPONSE, "status": "UNKNOWN"})


if __name__ == "__main__":
    unittest.main()
