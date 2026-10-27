# Author: Rishabh Srivastava
# Roll Number: 44285
# Project: Secrecy

"""
Cryptographic domain parameters and validation functions for ElGamal operations.
Author: Rishabh Srivastava (Roll No. 44285)

Domain Specifications:
1. Production/Demonstration Group:
   - Modulus (p): RFC 3526 Group 14 2048-bit MODP safe prime.
   - Subgroup order prime (q): (p - 1) // 2.
   - Generator (g): RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G = 11.

   IMPORTANT DISTINCTION:
   - RFC 3526 officially specifies generator g = 2 for Diffie-Hellman Key Exchange.
     In RFC 3526, g = 2 generates the quadratic residues subgroup of prime order q,
     satisfying 2^q = 1 mod p.
   - For classical ElGamal digital signatures, the signature equation
     s = (m - x * r) * k^(-1) mod (p - 1)
     operates modulo (p - 1). This classical construction requires a generator of
     the FULL multiplicative group Z_p^* having order p - 1.
   - Therefore, this project specifies a custom full-order generator: g = 11.
   - Generator 11 is NOT the standard generator defined in RFC 3526; it is a custom
     full-order primitive root selected specifically for classical ElGamal equations
     over the RFC 3526 Group 14 modulus.
   - This is an educational implementation and must not be used as a production-grade
     cryptographic library.

Mathematical Order Proof:
   For any safe prime p = 2q + 1 where q is prime:
   - The divisors of p - 1 = 2q are {1, 2, q, 2q}.
   - The order of any element g in Z_p^* must divide 2q.
   - If pow(g, q, p) == p - 1 == -1 mod p, then ord(g) cannot divide q.
   - If pow(g, 2, p) != 1 mod p, then ord(g) cannot be 1 or 2.
   - Consequently, ord(g) must be exactly 2q = p - 1, establishing that g is a
     primitive root generating the entire multiplicative group Z_p^*.

2. Test-Only Group:
   - Modulus: TEST_P = 467 (safe prime with q = 233).
   - Generator: TEST_G = 2 (full order 466 = TEST_P - 1).
   - FOR DETERMINISTIC UNIT TESTS ONLY. NEVER USE IN DEMONSTRATION OR PRODUCTION.
"""

from __future__ import annotations
from typing import Any


# RFC 3526 Group 14 2048-bit MODP Prime Modulus
_RFC3526_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

RFC3526_MODP_2048_P: int = int(_RFC3526_P_HEX, 16)
RFC3526_MODP_2048_Q: int = (RFC3526_MODP_2048_P - 1) // 2

# Custom full-order generator (ord(11) = p - 1) over RFC 3526 Group 14 modulus
RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G: int = 11

# Isolated small test-only safe prime parameters (p = 2*233 + 1 = 467)
# WARNING: TEST-ONLY PARAMETERS — NEVER USE IN DEMONSTRATION OR PRODUCTION.
TEST_P: int = 467
TEST_Q: int = (TEST_P - 1) // 2  # 233
TEST_G: int = 2


def is_strict_int(val: Any) -> bool:
    """Return True if val is an integer and NOT a boolean."""
    return isinstance(val, int) and not isinstance(val, bool)


def is_valid_integer_in_range(val: Any, min_val: int, max_val: int) -> bool:
    """
    Validate that val is a strict integer (not bool) and satisfies min_val <= val <= max_val.
    """
    if not is_strict_int(val):
        return False
    return min_val <= val <= max_val


def check_generator_full_order(p: int, q: int, g: int) -> bool:
    """
    Verify that generator g has full multiplicative group order p - 1 over safe prime p = 2q + 1.
    Criteria:
      1. pow(g, q, p) == p - 1  (order does not divide q)
      2. pow(g, 2, p) != 1      (order does not divide 2)
    """
    if not (is_strict_int(p) and is_strict_int(q) and is_strict_int(g)):
        return False
    if p <= 3 or q != (p - 1) // 2 or g < 2 or g >= p:
        return False
    return pow(g, q, p) == p - 1 and pow(g, 2, p) != 1


def validate_production_group(p: Any, g: Any) -> bool:
    """
    Validate that received parameters match the project's production/demonstration group.
    """
    if not (is_strict_int(p) and is_strict_int(g)):
        return False
    return p == RFC3526_MODP_2048_P and g == RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G


def validate_public_key(y: Any, p: Any) -> bool:
    """
    Validate that a public key y belongs to the accepted range [2, p - 2] for modulus p.
    Rejects booleans, non-integers, and values outside the boundary.
    """
    if not (is_strict_int(y) and is_strict_int(p)):
        return False
    if p <= 3:
        return False
    return 2 <= y <= p - 2


def validate_private_key(x: Any, p: Any) -> bool:
    """
    Validate that a private key x belongs to the accepted range [2, p - 2] for modulus p.
    """
    if not (is_strict_int(x) and is_strict_int(p)):
        return False
    if p <= 3:
        return False
    return 2 <= x <= p - 2
