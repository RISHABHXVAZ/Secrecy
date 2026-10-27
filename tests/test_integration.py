"""
Comprehensive end-to-end integration tests for Secrecy client-server exchange.

Author: Rishabh Srivastava
Roll No.: 44285
Project: Secrecy

Tests:
1. Normal end-to-end secure transmission (ACCEPTED, signature valid, hash matches).
2. Ciphertext tampering attack rejection (REJECTED).
3. Session key tampering attack rejection (REJECTED).
4. Digital signature tampering attack rejection (REJECTED).
5. Unicode strings and emoji payloads.
"""

import socket
import threading
import time
import unittest

from secrecy.client import send_secure_message
from secrecy.elgamal import elgamal_generate_keypair
from secrecy.params import (
    RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G,
    RFC3526_MODP_2048_P,
)
from secrecy.server import process_secure_session


class TestEndToEndIntegration(unittest.TestCase):
    """Integration test suite executing full client-server exchange over loopback sockets."""

    @classmethod
    def setUpClass(cls):
        cls.p = RFC3526_MODP_2048_P
        cls.g = RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G
        cls.server_pub, cls.server_priv = elgamal_generate_keypair(cls.p, cls.g)

    def _run_server_once(self, server_sock: socket.socket, result_holder: list):
        try:
            conn, _ = server_sock.accept()
            with conn:
                accepted = process_secure_session(
                    conn=conn,
                    p=self.p,
                    g=self.g,
                    server_priv=self.server_priv,
                    server_pub=self.server_pub,
                    verbose=False
                )
                result_holder.append(accepted)
        except Exception as e:
            result_holder.append(e)

    def _execute_session(
        self,
        message: str,
        idea_key: int | None = None,
        tamper_cipher: bool = False,
        tamper_key: bool = False,
        tamper_sig: bool = False
    ) -> tuple[bool, bool]:
        """
        Start single-shot server listener on dynamic ephemeral port, run client,
        and return (server_accepted, client_accepted).
        """
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        server_result: list = []
        srv_thread = threading.Thread(
            target=self._run_server_once,
            args=(server_sock, server_result),
            daemon=True
        )
        srv_thread.start()

        # Give the server thread a moment to enter accept()
        time.sleep(0.05)

        client_success = False
        try:
            client_success = send_secure_message(
                host="127.0.0.1",
                port=port,
                message=message,
                idea_key_32bit=idea_key,
                tamper_cipher=tamper_cipher,
                tamper_key=tamper_key,
                tamper_sig=tamper_sig,
                verbose=False
            )
        finally:
            srv_thread.join(timeout=5.0)
            server_sock.close()

        server_success = server_result[0] if server_result else False
        return server_success, client_success

    def test_e2e_successful_transmission(self):
        """Verify normal secure transmission where signature is VALID and message is ACCEPTED."""
        msg = "Confidential Report: Assignment 1 - Rishabh Srivastava (44285)"
        key = 0xDC6F3F59
        srv_ok, cl_ok = self._execute_session(msg, idea_key=key)
        self.assertTrue(srv_ok, "Server should have accepted the message.")
        self.assertTrue(cl_ok, "Client should have received ACCEPTED status.")

    def test_e2e_ciphertext_tampering_rejected(self):
        """Verify that altering ciphertext in transit causes rejection due to padding error or hash mismatch."""
        msg = "Financial Wire: Transfer $1,000,000 to Account #44285"
        srv_ok, cl_ok = self._execute_session(msg, tamper_cipher=True)
        self.assertFalse(srv_ok, "Server must reject tampered ciphertext.")
        self.assertFalse(cl_ok, "Client must receive REJECTED status.")

    def test_e2e_key_tampering_rejected(self):
        """Verify that tampering with the ElGamal-encrypted session key causes decryption/hash rejection."""
        msg = "Strategic Briefing: Classified Material"
        srv_ok, cl_ok = self._execute_session(msg, tamper_key=True)
        self.assertFalse(srv_ok, "Server must reject session with corrupted key.")
        self.assertFalse(cl_ok, "Client must receive REJECTED status.")

    def test_e2e_signature_tampering_rejected(self):
        """Verify that altering the digital signature value causes rejection."""
        msg = "Authorization Token: Rishabh Srivastava"
        srv_ok, cl_ok = self._execute_session(msg, tamper_sig=True)
        self.assertFalse(srv_ok, "Server must reject invalid digital signature.")
        self.assertFalse(cl_ok, "Client must receive REJECTED status.")

    def test_e2e_unicode_and_emojis(self):
        """Verify transmission of multi-byte UTF-8 text and symbols."""
        msg = "Secrecy Cryptosystem 🔐: 44285 — नमस्ते दुनिया 🌍"
        srv_ok, cl_ok = self._execute_session(msg)
        self.assertTrue(srv_ok)
        self.assertTrue(cl_ok)


if __name__ == "__main__":
    unittest.main()
