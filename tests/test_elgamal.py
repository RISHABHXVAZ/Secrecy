# Author: Rishabh Srivastava
# Roll Number: 44285
# Project: Secrecy

"""
Automated unit tests for ElGamal key exchange, digital signatures, and mathematical verification.
Author: Rishabh Srivastava (Roll No. 44285)
"""

import math
import unittest
from secrecy.params import (
    RFC3526_MODP_2048_P,
    RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G,
    TEST_P,
    TEST_G,
)
from secrecy.elgamal import (
    generate_keypair,
    elgamal_encrypt_key,
    elgamal_decrypt_key,
    elgamal_sign,
    elgamal_verify,
    _elgamal_sign_with_k_TESTING_ONLY,
)
from secrecy.whirlpool import whirlpool_bytes


class TestElGamal(unittest.TestCase):
    """Test suite for ElGamal asymmetric cryptosystem operations."""

    def setUp(self):
        self.prod_p = RFC3526_MODP_2048_P
        self.prod_g = RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G
        self.test_p = TEST_P
        self.test_g = TEST_G

    def test_keypair_generation_consistency(self):
        """Verify keypair generation bounds and mathematical consistency: y = g^x mod p."""
        # Test on production group
        pub_y, priv_x = generate_keypair(self.prod_p, self.prod_g)
        self.assertTrue(2 <= priv_x <= self.prod_p - 2, "Private exponent out of range")
        self.assertTrue(2 <= pub_y <= self.prod_p - 2, "Public key out of range")
        self.assertEqual(pow(self.prod_g, priv_x, self.prod_p), pub_y)

        # Test on small group
        pub_y_test, priv_x_test = generate_keypair(self.test_p, self.test_g)
        self.assertTrue(2 <= priv_x_test <= self.test_p - 2)
        self.assertTrue(2 <= pub_y_test <= self.test_p - 2)
        self.assertEqual(pow(self.test_g, priv_x_test, self.test_p), pub_y_test)

    def test_key_exchange_roundtrips(self):
        """
        Verify successful encryption and decryption of 32-bit Simplified IDEA keys:
        0, 1, interior representative values, and 0xFFFFFFFF.
        """
        pub_y, priv_x = generate_keypair(self.prod_p, self.prod_g)

        keys_to_test = [
            0x00000000,  # Extreme lower bound (M = 1)
            0x00000001,
            44285,       # Author roll number
            0xDC6F3F59,  # Hoffman paper key
            0x12345678,
            0xFFFFFFFF,  # Extreme upper bound (M = 2^32)
        ]

        for key in keys_to_test:
            c1, c2 = elgamal_encrypt_key(key, self.prod_p, self.prod_g, pub_y)
            self.assertTrue(1 <= c1 <= self.prod_p - 1)
            self.assertTrue(1 <= c2 <= self.prod_p - 1)

            recovered_key = elgamal_decrypt_key(c1, c2, self.prod_p, priv_x)
            self.assertEqual(
                recovered_key,
                key,
                f"Key exchange failed to recover 32-bit key 0x{key:08X}",
            )

    def test_key_encryption_input_validations(self):
        """Verify rejection of invalid IDEA key types and out-of-range values."""
        pub_y, priv_x = generate_keypair(self.prod_p, self.prod_g)

        # Out-of-range key values
        with self.assertRaises(ValueError):
            elgamal_encrypt_key(-1, self.prod_p, self.prod_g, pub_y)
        with self.assertRaises(ValueError):
            elgamal_encrypt_key(0x100000000, self.prod_p, self.prod_g, pub_y)

        # Boolean masquerading as int
        with self.assertRaises(ValueError):
            elgamal_encrypt_key(True, self.prod_p, self.prod_g, pub_y)

        # Non-integer types
        with self.assertRaises(ValueError):
            elgamal_encrypt_key("0x1234", self.prod_p, self.prod_g, pub_y)  # type: ignore[arg-type]

        # Invalid public key
        with self.assertRaises(ValueError):
            elgamal_encrypt_key(100, self.prod_p, self.prod_g, 1)  # y < 2
        with self.assertRaises(ValueError):
            elgamal_encrypt_key(100, self.prod_p, self.prod_g, self.prod_p)  # y >= p

    def test_ciphertext_validation_and_tampering(self):
        """Verify rejection of malformed ciphertext elements and tampered values."""
        pub_y, priv_x = generate_keypair(self.prod_p, self.prod_g)
        c1, c2 = elgamal_encrypt_key(0x12345678, self.prod_p, self.prod_g, pub_y)

        # Malformed ciphertext bounds
        with self.assertRaises(ValueError):
            elgamal_decrypt_key(0, c2, self.prod_p, priv_x)
        with self.assertRaises(ValueError):
            elgamal_decrypt_key(self.prod_p, c2, self.prod_p, priv_x)
        with self.assertRaises(ValueError):
            elgamal_decrypt_key(c1, 0, self.prod_p, priv_x)

        # Tampered c2 element: multiplying c2 produces a value M out of range [1, 2^32]
        # Since p is 2048 bits and valid M is <= 2^32, almost all elements in Z_p^* lie outside [1, 2^32]
        tampered_c2 = (c2 * 9999999999999999) % self.prod_p
        with self.assertRaises(ValueError):
            elgamal_decrypt_key(c1, tampered_c2, self.prod_p, priv_x)

    def test_digital_signature_production_group(self):
        """Verify digital signing and verification using the 2048-bit production group."""
        pub_y, priv_x = generate_keypair(self.prod_p, self.prod_g)
        digest = whirlpool_bytes(b"Secrecy: Rishabh Srivastava Roll No 44285")

        r, s = elgamal_sign(digest, self.prod_p, self.prod_g, priv_x)
        self.assertTrue(1 <= r <= self.prod_p - 1)
        self.assertTrue(1 <= s <= self.prod_p - 2)

        is_valid, v1, v2 = elgamal_verify(digest, r, s, self.prod_p, self.prod_g, pub_y)
        self.assertTrue(is_valid, "Valid signature must verify successfully")
        self.assertEqual(v1, v2, "Verification equation must hold: v1 == v2")

        # Independent mathematical verification check
        m = int.from_bytes(digest, "big") % (self.prod_p - 1)
        expected_v1 = pow(self.prod_g, m, self.prod_p)
        expected_v2 = (pow(pub_y, r, self.prod_p) * pow(r, s, self.prod_p)) % self.prod_p
        self.assertEqual(v1, expected_v1)
        self.assertEqual(v2, expected_v2)

    def test_digital_signature_test_group(self):
        """Verify digital signing and verification using the isolated small test group (p=467, g=2)."""
        pub_y, priv_x = generate_keypair(self.test_p, self.test_g)
        digest = whirlpool_bytes(b"Test message")

        r, s = elgamal_sign(digest, self.test_p, self.test_g, priv_x)
        self.assertTrue(1 <= r <= self.test_p - 1)
        self.assertTrue(1 <= s <= self.test_p - 2)

        is_valid, v1, v2 = elgamal_verify(digest, r, s, self.test_p, self.test_g, pub_y)
        self.assertTrue(is_valid)
        self.assertEqual(v1, v2)

    def test_signature_tampered_digest_rejected(self):
        """Verify that any modification to the message digest causes signature verification to fail."""
        pub_y, priv_x = generate_keypair(self.prod_p, self.prod_g)
        digest = whirlpool_bytes(b"Original message")

        r, s = elgamal_sign(digest, self.prod_p, self.prod_g, priv_x)

        # Alter 1 byte of the 64-byte digest
        tampered_digest = bytearray(digest)
        tampered_digest[0] ^= 0x01
        tampered_digest = bytes(tampered_digest)

        is_valid, v1, v2 = elgamal_verify(tampered_digest, r, s, self.prod_p, self.prod_g, pub_y)
        self.assertFalse(is_valid, "Tampered digest must be rejected")
        self.assertNotEqual(v1, v2)

    def test_signature_tampered_components_rejected(self):
        """Verify that altering r or s causes signature verification to fail."""
        pub_y, priv_x = generate_keypair(self.prod_p, self.prod_g)
        digest = whirlpool_bytes(b"Test authentic payload")
        r, s = elgamal_sign(digest, self.prod_p, self.prod_g, priv_x)

        # Tampered r
        tampered_r = (r + 1) if (r + 1) < self.prod_p else (r - 1)
        is_valid_r, _, _ = elgamal_verify(digest, tampered_r, s, self.prod_p, self.prod_g, pub_y)
        self.assertFalse(is_valid_r, "Tampered signature component r must fail")

        # Tampered s
        tampered_s = (s + 1) if (s + 1) < (self.prod_p - 1) else (s - 1)
        is_valid_s, _, _ = elgamal_verify(digest, r, tampered_s, self.prod_p, self.prod_g, pub_y)
        self.assertFalse(is_valid_s, "Tampered signature component s must fail")

        # Out-of-bounds signature components
        self.assertFalse(elgamal_verify(digest, 0, s, self.prod_p, self.prod_g, pub_y)[0])
        self.assertFalse(elgamal_verify(digest, self.prod_p, s, self.prod_p, self.prod_g, pub_y)[0])
        self.assertFalse(elgamal_verify(digest, r, 0, self.prod_p, self.prod_g, pub_y)[0])
        self.assertFalse(elgamal_verify(digest, r, self.prod_p - 1, self.prod_p, self.prod_g, pub_y)[0])

    def test_digest_length_and_type_validation(self):
        """Verify that elgamal_sign and elgamal_verify reject invalid digest lengths and types."""
        pub_y, priv_x = generate_keypair(self.prod_p, self.prod_g)

        # Wrong digest byte lengths (!= 64)
        for invalid_len in [0, 32, 63, 65, 128]:
            bad_bytes = b"X" * invalid_len
            with self.assertRaises(ValueError):
                elgamal_sign(bad_bytes, self.prod_p, self.prod_g, priv_x)
            with self.assertRaises(ValueError):
                elgamal_verify(bad_bytes, 10, 10, self.prod_p, self.prod_g, pub_y)

        # Non-bytes input types
        with self.assertRaises(TypeError):
            elgamal_sign("123" * 21, self.prod_p, self.prod_g, priv_x)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            elgamal_verify("123" * 21, 10, 10, self.prod_p, self.prod_g, pub_y)  # type: ignore[arg-type]

    def test_deterministic_signing_test_helper(self):
        """
        Verify the test-only isolated deterministic nonce signing helper.
        Tests independent arithmetic on small safe prime p = 467, g = 2.
        """
        p = self.test_p
        g = self.test_g
        x = 105
        y = pow(g, x, p)

        digest = whirlpool_bytes(b"KAT signature test")
        m = int.from_bytes(digest, "big") % (p - 1)

        # Choose k with gcd(k, p - 1) == 1
        k = 31
        self.assertEqual(math.gcd(k, p - 1), 1)

        r, s = _elgamal_sign_with_k_TESTING_ONLY(digest, k, p, g, x)
        self.assertEqual(r, pow(g, k, p))
        self.assertEqual(s, ((m - x * r) * pow(k, -1, p - 1)) % (p - 1))

        is_valid, v1, v2 = elgamal_verify(digest, r, s, p, g, y)
        self.assertTrue(is_valid)
        self.assertEqual(v1, v2)

        # Nonce having gcd(k, p - 1) != 1 must be rejected
        with self.assertRaises(ValueError):
            _elgamal_sign_with_k_TESTING_ONLY(digest, 2, p, g, x)  # gcd(2, 466) == 2


if __name__ == "__main__":
    unittest.main()
