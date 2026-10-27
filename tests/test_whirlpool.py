# Author: Rishabh Srivastava
# Roll Number: 44285
# Project: Secrecy

"""
Automated unit test suite for Whirlpool hash function implementation.
Author: Rishabh Srivastava (Roll No. 44285)

Authoritative Reference Vector Sources:
1. ISO/IEC 10118-3:2004 Information technology -- Security techniques -- Hash-functions --
   Part 3: Dedicated hash-functions (Whirlpool revision 2003).
2. NESSIE (New European Schemes for Signatures, Integrity, and Encryption) portfolio test suite
   (Linux Kernel crypto/tcrypt.h and crypto/testmgr.h wp512 test vectors by Vincent Rijmen and Paulo Barreto).
3. Open-source cryptographic benchmark suites (Botan / RHash / Crypto++).
"""

import unittest
from secrecy.whirlpool import (
    whirlpool,
    whirlpool_bytes,
    WHIRLPOOL_SBOX,
    _pad_whirlpool,
)


class TestWhirlpool(unittest.TestCase):
    """Test suite for pure-Python Whirlpool hash implementation."""

    def test_digest_length_and_format(self):
        """Verify digest length: exactly 64 raw bytes and 128 lowercase hex characters."""
        sample_inputs = [b"", b"a", b"abc", b"test data", b"X" * 128]
        for data in sample_inputs:
            raw_digest = whirlpool_bytes(data)
            hex_digest = whirlpool(data)

            self.assertIsInstance(raw_digest, bytes)
            self.assertEqual(len(raw_digest), 64, f"Raw digest must be 64 bytes, got {len(raw_digest)}")

            self.assertIsInstance(hex_digest, str)
            self.assertEqual(len(hex_digest), 128, f"Hex digest must be 128 chars, got {len(hex_digest)}")
            self.assertEqual(hex_digest, hex_digest.lower(), "Hex digest must be lowercase")
            self.assertEqual(raw_digest.hex(), hex_digest, "Raw bytes hex representation must match hex digest")

    def test_iso_kat_empty_string(self):
        """
        Authoritative Test Vector 1: Empty input (0 bits).
        Source: ISO/IEC 10118-3:2004 / NESSIE portfolio.
        """
        expected = (
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7"
            "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
        )
        self.assertEqual(whirlpool(b""), expected)

    def test_iso_kat_single_byte_a(self):
        """
        Authoritative Test Vector 2: Single ASCII character 'a' (8 bits).
        Source: ISO/IEC 10118-3:2004 / NESSIE portfolio (wp512 testvec 1).
        """
        expected = (
            "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42"
            "d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a"
        )
        self.assertEqual(whirlpool(b"a"), expected)

    def test_iso_kat_abc(self):
        """
        Authoritative Test Vector 3: String 'abc' (24 bits).
        Source: ISO/IEC 10118-3:2004 / NESSIE portfolio (wp512 testvec 2).
        """
        expected = (
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c"
            "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"
        )
        self.assertEqual(whirlpool(b"abc"), expected)

    def test_iso_kat_fox_pangram(self):
        """
        Authoritative Test Vector 4: Pangram 'The quick brown fox jumps over the lazy dog'.
        Source: Standard cryptographic reference suites (Wikipedia / Botan / Crypto++).
        """
        msg = b"The quick brown fox jumps over the lazy dog"
        expected = (
            "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725f"
            "d2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35"
        )
        self.assertEqual(whirlpool(msg), expected)

    def test_iso_kat_one_thousand_a_bytes(self):
        """
        Authoritative Test Vector 5: One thousand ASCII 'a' bytes (8000 bits).
        Source: Standard ISO/IEC 10118-3 long vector test.
        """
        msg = b"a" * 1000
        expected = (
            "fe24b173807796fdac15ebcaf5769f661695601ffeb64490ec0eecd30bd5b2c3"
            "773b36d4edaf3175378b8df114e9496c833ef13606e7ab3d455681e98ecc818f"
        )
        self.assertEqual(whirlpool(msg), expected)

    def test_block_boundary_lengths(self):
        """
        Test block boundaries around 32-byte length-field boundary and 64-byte cipher block size:
        31, 32, 63, 64, 65, 127, 128 bytes.
        Verifies padding expansion and multi-block chaining.
        """
        boundary_lengths = [31, 32, 63, 64, 65, 127, 128]
        seen_digests = set()
        for length in boundary_lengths:
            data = bytes([i % 256 for i in range(length)])
            digest = whirlpool(data)
            self.assertEqual(len(digest), 128)
            # Each distinct boundary length must produce a distinct digest
            self.assertNotIn(digest, seen_digests)
            seen_digests.add(digest)

            # Validate internal padding structure
            padded = _pad_whirlpool(data)
            self.assertEqual(len(padded) % 64, 0, f"Padded data for length {length} must be a multiple of 64")
            self.assertEqual(padded[length], 0x80, "Padding must begin with 0x80 byte")

    def test_utf8_unicode_inputs(self):
        """Verify handling of multi-byte UTF-8 Unicode strings."""
        unicode_texts = [
            "Rishabh Srivastava (Roll No. 44285)",
            "Simplified IDEA + ElGamal + Whirlpool 密码学",
            "חֲשָׁאִיּוּת / אָבְטָחָה / Secrecy",
            "🔒🔑🛡️ Standard Cryptography 2026",
        ]
        for text in unicode_texts:
            data = text.encode("utf-8")
            digest = whirlpool(data)
            self.assertEqual(len(digest), 128)

    def test_type_validation(self):
        """Verify that passing non-bytes raises TypeError."""
        invalid_inputs = ["string input", 12345, None, [1, 2, 3], {"data": b"abc"}]
        for invalid in invalid_inputs:
            with self.assertRaises(TypeError):
                whirlpool(invalid)  # type: ignore[arg-type]
            with self.assertRaises(TypeError):
                whirlpool_bytes(invalid)  # type: ignore[arg-type]

    def test_sbox_bijective_and_bounds(self):
        """Verify that the Whirlpool S-box is a bijective permutation over 0..255."""
        self.assertEqual(len(WHIRLPOOL_SBOX), 256)
        self.assertEqual(len(set(WHIRLPOOL_SBOX)), 256, "S-box must be a permutation (all 256 unique)")
        self.assertEqual(set(WHIRLPOOL_SBOX), set(range(256)))
        # Verify known fixed S-box values from ISO/IEC 10118-3:2004
        self.assertEqual(WHIRLPOOL_SBOX[0], 0x18)
        self.assertEqual(WHIRLPOOL_SBOX[1], 0x23)
        self.assertEqual(WHIRLPOOL_SBOX[255], 0x86)


if __name__ == "__main__":
    unittest.main()
