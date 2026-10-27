# Author: Rishabh Srivastava
# Roll Number: 44285
# Project: Secrecy

"""
Unit tests for Simplified IDEA implementation.
Author: Rishabh Srivastava (Roll No. 44285)

Tests include:
1. Authoritative Known-Answer Test (KAT) from Nick Hoffman's paper.
2. Verification of exact 28 encryption subkeys from Hoffman's paper table.
3. Verification of exact 28 decryption subkeys from Hoffman's paper table.
4. Modular arithmetic primitives (addition mod 16, multiplication mod 17, inverses).
5. All-zero and all-one blocks and keys.
6. PKCS#7 2-byte padding correctness and error detection.
7. CBC-mode encryption/decryption round-trips for empty, odd, even, and UTF-8 inputs.
8. Error handling on invalid keys, blocks, IVs, and malformed ciphertext.
"""

import unittest
from secrecy.simplified_idea import (
    rol32,
    add16,
    inv_add16,
    mul17,
    inv_mul17,
    generate_subkeys,
    generate_decryption_keys,
    idea_encrypt_block,
    idea_decrypt_block,
    pad_pkcs7_2byte,
    unpad_pkcs7_2byte,
    idea_cbc_encrypt,
    idea_cbc_decrypt,
)


class TestSimplifiedIDEA(unittest.TestCase):
    """Test suite for Simplified IDEA cipher, arithmetic primitives, and CBC mode."""

    def test_modular_arithmetic_inverses(self):
        """Verify that every 4-bit nibble has correct additive and multiplicative inverses."""
        for x in range(16):
            # Additive inverse test: (x + -x) mod 16 == 0
            inv_a = inv_add16(x)
            self.assertEqual(add16(x, inv_a), 0, f"Additive inverse failed for {x}")

            # Multiplicative inverse test: (x * x^-1) mod 17 == 1
            inv_m = inv_mul17(x)
            self.assertEqual(mul17(x, inv_m), 1, f"Multiplicative inverse failed for {x}")

    def test_hoffman_paper_key_schedule(self):
        """
        Verify the exact 28 subkeys generated from the 32-bit key in Hoffman's paper:
        Key: 1101 1100 0110 1111 0011 1111 0101 1001 (0xDC6F3F59)
        """
        key = 0xDC6F3F59
        subkeys = generate_subkeys(key)
        self.assertEqual(len(subkeys), 28)

        expected_encryption_subkeys = [
            # Round 1 (Z1 .. Z6)
            13, 12, 6, 15, 3, 15,
            # Round 2 (Z1 .. Z6)
            5, 9, 1, 11, 12, 15,
            # Round 3 (Z1 .. Z6)
            13, 6, 7, 7, 15, 3,
            # Round 4 (Z1 .. Z6)
            15, 5, 9, 13, 12, 6,
            # Round 5 (Z1 .. Z4)
            15, 13, 6, 7,
        ]
        self.assertEqual(subkeys, expected_encryption_subkeys)

    def test_hoffman_paper_decryption_key_schedule(self):
        """
        Verify the exact 28 decryption subkeys generated from Hoffman's paper table (Page 5).
        """
        key = 0xDC6F3F59
        enc_subkeys = generate_subkeys(key)
        dec_subkeys = generate_decryption_keys(enc_subkeys)
        self.assertEqual(len(dec_subkeys), 28)

        expected_decryption_subkeys = [
            # Round 1: K1 .. K6
            8, 3, 10, 5, 12, 6,
            # Round 2: K1 .. K6
            8, 11, 7, 4, 15, 3,
            # Round 3: K1 .. K6
            4, 10, 9, 5, 12, 15,
            # Round 4: K1 .. K6
            7, 7, 15, 14, 3, 15,
            # Round 5: K1 .. K4
            4, 4, 10, 8,
        ]
        self.assertEqual(dec_subkeys, expected_decryption_subkeys)

    def test_hoffman_paper_reference_vector(self):
        """
        Authoritative Known-Answer Test (KAT):
        Plaintext:  1001110010101100 (0x9CAC)
        Key:        11011100011011110011111101011001 (0xDC6F3F59)
        Ciphertext: 1011101101001011 (0xBB4B)
        """
        pt = 0x9CAC
        key = 0xDC6F3F59
        subkeys = generate_subkeys(key)

        ct, logs = idea_encrypt_block(pt, subkeys, log_steps=True)
        self.assertEqual(ct, 0xBB4B, f"KAT failed: expected 0xBB4B, got 0x{ct:04X}")
        self.assertTrue(len(logs) > 0, "Expected intermediate step logs")

        # Verify block decryption with decryption subkeys
        dec_subkeys = generate_decryption_keys(subkeys)
        recovered_pt, dec_logs = idea_decrypt_block(ct, dec_subkeys, log_steps=True)
        self.assertEqual(recovered_pt, pt, f"Decryption failed: expected 0x{pt:04X}, got 0x{recovered_pt:04X}")

    def test_zero_and_all_one_extremes(self):
        """Test boundary cases with all-zero and all-one blocks and keys."""
        test_cases = [
            (0x0000, 0x00000000),
            (0xFFFF, 0xFFFFFFFF),
            (0x0000, 0xFFFFFFFF),
            (0xFFFF, 0x00000000),
            (0xAAAA, 0x55555555),
        ]
        for pt, key in test_cases:
            enc_keys = generate_subkeys(key)
            dec_keys = generate_decryption_keys(enc_keys)

            ct, _ = idea_encrypt_block(pt, enc_keys)
            recovered, _ = idea_decrypt_block(ct, dec_keys)
            self.assertEqual(recovered, pt, f"Round-trip failed for pt=0x{pt:04X}, key=0x{key:08X}")

    def test_exhaustive_block_roundtrips(self):
        """
        Exhaustive test for all 65,536 16-bit blocks (0x0000 through 0xFFFF)
        across keys 0x00000000, 0xFFFFFFFF, and 0xDC6F3F59.
        Total checks: 3 * 65,536 = 196,608 block encryptions and decryptions.
        """
        keys_to_test = [0x00000000, 0xFFFFFFFF, 0xDC6F3F59]
        for key in keys_to_test:
            enc_subkeys = generate_subkeys(key)
            dec_subkeys = generate_decryption_keys(enc_subkeys)
            for block in range(65536):
                ct, _ = idea_encrypt_block(block, enc_subkeys)
                recovered, _ = idea_decrypt_block(ct, dec_subkeys)
                self.assertEqual(
                    recovered,
                    block,
                    f"Exhaustive roundtrip failed for key 0x{key:08X} at block 0x{block:04X}",
                )

    def test_pkcs7_2byte_padding(self):
        """Test PKCS#7 2-byte block padding and unpadding edge cases."""
        # Empty data: pad_len = 2 -> b"\x02\x02"
        self.assertEqual(pad_pkcs7_2byte(b""), b"\x02\x02")
        self.assertEqual(unpad_pkcs7_2byte(b"\x02\x02"), b"")

        # Odd length (1 byte): pad_len = 1 -> b"\x01"
        self.assertEqual(pad_pkcs7_2byte(b"A"), b"A\x01")
        self.assertEqual(unpad_pkcs7_2byte(b"A\x01"), b"A")

        # Even length (2 bytes): pad_len = 2 -> b"\x02\x02"
        self.assertEqual(pad_pkcs7_2byte(b"AB"), b"AB\x02\x02")
        self.assertEqual(unpad_pkcs7_2byte(b"AB\x02\x02"), b"AB")

        # Odd length (3 bytes)
        self.assertEqual(pad_pkcs7_2byte(b"XYZ"), b"XYZ\x01")
        self.assertEqual(unpad_pkcs7_2byte(b"XYZ\x01"), b"XYZ")

    def test_pkcs7_2byte_padding_rejections(self):
        """Test that malformed padding bytes are rejected with ValueError."""
        invalid_paddings = [
            b"",                  # Empty
            b"\x01",              # Odd length
            b"\x03\x03\x03",      # Pad byte > 2
            b"\x00\x00",          # Pad byte 0
            b"A\x02",             # Pad byte 2 but only 1 pad byte present
            b"A\x03",             # Pad byte 3
            b"AB\x01\x02",        # Corrupted second pad byte
        ]
        for invalid in invalid_paddings:
            with self.assertRaises(ValueError, msg=f"Failed to reject invalid padding: {invalid!r}"):
                unpad_pkcs7_2byte(invalid)

    def test_cbc_mode_roundtrips(self):
        """Verify CBC encryption and decryption round-trips across various message structures."""
        key = 0x12345678
        messages = [
            b"",
            b"A",
            b"AB",
            b"ABC",
            b"ABCD",
            b"Cryptographic Engineering",
            "Roll 44285 / Rishabh Srivastava / 密码学 / חֲשָׁאִיּוּת".encode("utf-8"),
            bytes(range(256)),  # All byte values 0x00 .. 0xFF
        ]

        for msg in messages:
            ct, enc_logs = idea_cbc_encrypt(msg, key)
            self.assertTrue(len(ct) >= 4)
            self.assertEqual(len(ct) % 2, 0)

            pt, dec_logs = idea_cbc_decrypt(ct, key)
            self.assertEqual(pt, msg, f"CBC round-trip failed for message length {len(msg)}")

    def test_cbc_mode_deterministic_iv(self):
        """Verify CBC mode behaves correctly with explicit fixed IV."""
        key = 0xDC6F3F59
        iv = b"\x12\x34"
        msg = b"TEST"
        ct1, _ = idea_cbc_encrypt(msg, key, iv=iv)
        ct2, _ = idea_cbc_encrypt(msg, key, iv=iv)
        self.assertEqual(ct1, ct2, "CBC with same IV should produce identical ciphertext")

        # Different IV should produce different ciphertext
        ct3, _ = idea_cbc_encrypt(msg, key, iv=b"\x56\x78")
        self.assertNotEqual(ct1, ct3)

    def test_invalid_parameters_raise(self):
        """Verify error handling on out-of-range keys, blocks, IVs, and ciphertext."""
        subkeys = generate_subkeys(0x12345678)

        # Block out of 16-bit range
        with self.assertRaises(ValueError):
            idea_encrypt_block(-1, subkeys)
        with self.assertRaises(ValueError):
            idea_encrypt_block(0x10000, subkeys)

        # Key out of 32-bit range
        with self.assertRaises(ValueError):
            generate_subkeys(-1)
        with self.assertRaises(ValueError):
            generate_subkeys(0x100000000)

        # Invalid subkey list length
        with self.assertRaises(ValueError):
            idea_encrypt_block(0x1234, [0] * 27)
        with self.assertRaises(ValueError):
            generate_decryption_keys([0] * 20)

        # Invalid IV length
        with self.assertRaises(ValueError):
            idea_cbc_encrypt(b"Hi", 0x12345678, iv=b"\x01")
        with self.assertRaises(ValueError):
            idea_cbc_encrypt(b"Hi", 0x12345678, iv=b"\x01\x02\x03")

        # Invalid ciphertext length for CBC decrypt
        with self.assertRaises(ValueError):
            idea_cbc_decrypt(b"\x01\x02", 0x12345678)  # < 4 bytes
        with self.assertRaises(ValueError):
            idea_cbc_decrypt(b"\x01\x02\x03\x04\x05", 0x12345678)  # odd length


if __name__ == "__main__":
    unittest.main()
