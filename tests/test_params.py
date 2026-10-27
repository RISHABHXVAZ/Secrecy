# Author: Rishabh Srivastava
# Roll Number: 44285
# Project: Secrecy

"""
Automated unit tests for ElGamal domain parameters and validation logic.
Author: Rishabh Srivastava (Roll No. 44285)
"""

import unittest
from secrecy.params import (
    RFC3526_MODP_2048_P,
    RFC3526_MODP_2048_Q,
    RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G,
    TEST_P,
    TEST_Q,
    TEST_G,
    is_strict_int,
    is_valid_integer_in_range,
    check_generator_full_order,
    validate_production_group,
    validate_public_key,
    validate_private_key,
)


class TestDomainParameters(unittest.TestCase):
    """Test suite for domain constants, generator full-order proofs, and validators."""

    def test_production_modulus_properties(self):
        """Verify RFC 3526 Group 14 2048-bit modulus size and safe-prime relation."""
        self.assertEqual(RFC3526_MODP_2048_P.bit_length(), 2048)
        self.assertEqual(RFC3526_MODP_2048_Q, (RFC3526_MODP_2048_P - 1) // 2)
        # Verify custom full-order generator constant
        self.assertEqual(RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G, 11)

    def test_production_generator_full_order(self):
        """
        Verify that g = 11 has full multiplicative group order p - 1 over RFC 3526 modulus.
        Also verify that standard RFC generator g = 2 generates the order-q subgroup.
        """
        p = RFC3526_MODP_2048_P
        q = RFC3526_MODP_2048_Q
        g_custom = RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G

        # Standard RFC generator 2 has subgroup order q
        self.assertEqual(pow(2, q, p), 1, "RFC generator 2 must have order q")

        # Custom generator 11 has full order 2q = p - 1
        self.assertTrue(
            check_generator_full_order(p, q, g_custom),
            "Custom generator 11 must be confirmed as full-order primitive root",
        )

    def test_test_only_parameters_full_order(self):
        """Verify safe-prime properties and full order of isolated test parameters (p=467, g=2)."""
        self.assertEqual(TEST_P, 467)
        self.assertEqual(TEST_Q, 233)
        self.assertEqual(TEST_G, 2)
        self.assertTrue(
            check_generator_full_order(TEST_P, TEST_Q, TEST_G),
            "Test generator 2 must have full order 466 modulo 467",
        )

    def test_strict_int_helper(self):
        """Verify is_strict_int rejects booleans and non-integers."""
        self.assertTrue(is_strict_int(0))
        self.assertTrue(is_strict_int(12345))
        self.assertTrue(is_strict_int(-99))

        # Must reject booleans (since in Python isinstance(True, int) is True)
        self.assertFalse(is_strict_int(True))
        self.assertFalse(is_strict_int(False))

        # Must reject non-integers
        self.assertFalse(is_strict_int("123"))
        self.assertFalse(is_strict_int(12.34))
        self.assertFalse(is_strict_int(None))
        self.assertFalse(is_strict_int([1, 2]))

    def test_valid_integer_in_range(self):
        """Test strict range validation."""
        self.assertTrue(is_valid_integer_in_range(5, 1, 10))
        self.assertTrue(is_valid_integer_in_range(1, 1, 10))
        self.assertTrue(is_valid_integer_in_range(10, 1, 10))

        self.assertFalse(is_valid_integer_in_range(0, 1, 10))
        self.assertFalse(is_valid_integer_in_range(11, 1, 10))
        self.assertFalse(is_valid_integer_in_range(True, 0, 1))

    def test_validate_production_group(self):
        """Test validation of the project's production group parameters."""
        self.assertTrue(
            validate_production_group(
                RFC3526_MODP_2048_P, RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G
            )
        )

        # Mismatched generator
        self.assertFalse(validate_production_group(RFC3526_MODP_2048_P, 2))
        self.assertFalse(validate_production_group(RFC3526_MODP_2048_P, 3))

        # Mismatched modulus
        self.assertFalse(validate_production_group(TEST_P, RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G))

        # Invalid types / booleans
        self.assertFalse(validate_production_group(True, 11))
        self.assertFalse(validate_production_group("2048_P", 11))
        self.assertFalse(validate_production_group(None, 11))

    def test_validate_public_and_private_keys(self):
        """Test public and private key range validation [2, p - 2]."""
        p = RFC3526_MODP_2048_P

        # Valid interior keys
        for key in [2, 3, 0x12345678, p - 2]:
            self.assertTrue(validate_public_key(key, p))
            self.assertTrue(validate_private_key(key, p))

        # Invalid boundary keys (0, 1, p - 1, p, p + 1)
        for invalid_key in [-1, 0, 1, p - 1, p, p + 1]:
            self.assertFalse(validate_public_key(invalid_key, p))
            self.assertFalse(validate_private_key(invalid_key, p))

        # Reject booleans masquerading as integers
        self.assertFalse(validate_public_key(True, p))
        self.assertFalse(validate_public_key(False, p))
        self.assertFalse(validate_private_key(True, p))

        # Reject non-integers
        self.assertFalse(validate_public_key("pubkey", p))
        self.assertFalse(validate_private_key(None, p))


if __name__ == "__main__":
    unittest.main()
