# Author: Rishabh Srivastava
# Roll Number: 44285
# Project: Secrecy

"""
Classical ElGamal asymmetric cryptosystem implementation for key exchange and digital signatures.
Author: Rishabh Srivastava (Roll No. 44285)

This module implements:
1. Asymmetric key-pair generation using cryptographically secure randomness (secrets).
2. ElGamal encryption and decryption of a 32-bit Simplified IDEA symmetric key.
   - Nonzero reversible mapping: M = K + 1, where K in [0, 2^32 - 1] -> M in [1, 2^32].
3. Classical ElGamal digital signatures over 512-bit Whirlpool digests.
   - Digest integer representation: m = int.from_bytes(digest_bytes, "big") % (p - 1).
   - Under the 2048-bit production modulus (p > 2^2047 >> 2^512), m < p - 1 holds
     naturally, so the modulo operation preserves the full 512-bit digest value.
   - For small test groups (such as p = 467), the modulo reduction ensures mathematically
     sound exponentiation within the group order.
"""

from __future__ import annotations
import math
import secrets
from typing import Tuple

from secrecy.params import (
    is_strict_int,
    is_valid_integer_in_range,
    validate_public_key,
    validate_private_key,
)


def generate_keypair(p: int, g: int) -> Tuple[int, int]:
    """
    Generate an ElGamal keypair (public_y, private_x) for domain parameters (p, g).

    Returns:
        tuple[int, int]: (public_y, private_x) where
          - private_x in [2, p - 2]
          - public_y = pow(g, private_x, p) in [2, p - 2]
    """
    if not (is_strict_int(p) and is_strict_int(g)):
        raise TypeError("Modulus p and generator g must be strict integers")
    if p <= 3 or g < 2 or g >= p:
        raise ValueError(f"Invalid domain parameters: p={p}, g={g}")

    # Maximum generation attempts to prevent theoretical infinite loop
    for _ in range(1000):
        # Generate private exponent x in [2, p - 2]
        private_x = secrets.randbelow(p - 3) + 2
        public_y = pow(g, private_x, p)

        # Retry if generated public key violates accepted range [2, p - 2]
        if validate_public_key(public_y, p):
            return public_y, private_x

    raise RuntimeError("Failed to generate a valid keypair within retry threshold")


# Alias for explicit namespace naming
elgamal_generate_keypair = generate_keypair


def elgamal_encrypt_key(
    key_32bit: int, p: int, g: int, public_y: int
) -> Tuple[int, int]:
    """
    Encrypt an unsigned 32-bit Simplified IDEA key using ElGamal with server public key public_y.

    Encoding:
      Reversible nonzero mapping: M = key_32bit + 1 (M in [1, 2^32]).
      Requires p > 2^32 to guarantee uniqueness.

    Returns:
        tuple[int, int]: (c1, c2)
    """
    if not is_valid_integer_in_range(key_32bit, 0, 0xFFFFFFFF):
        raise ValueError(f"key_32bit must be an unsigned 32-bit integer (0 <= K <= 0xFFFFFFFF), got {key_32bit!r}")
    if not validate_public_key(public_y, p):
        raise ValueError(f"Invalid public key public_y={public_y!r} for modulus p")
    if not (is_strict_int(g) and 2 <= g < p):
        raise ValueError(f"Invalid generator g={g!r}")
    if p <= (1 << 32):
        raise ValueError(f"Modulus p must be greater than 2^32 for 32-bit key encoding, got p={p}")

    M = key_32bit + 1

    # Sample random ephemeral exponent k in [2, p - 2]
    # No gcd(k, p - 1) == 1 required for ElGamal encryption
    k = secrets.randbelow(p - 3) + 2
    c1 = pow(g, k, p)
    c2 = (M * pow(public_y, k, p)) % p

    return c1, c2


def elgamal_decrypt_key(c1: int, c2: int, p: int, private_x: int) -> int:
    """
    Decrypt an ElGamal ciphertext (c1, c2) to recover the 32-bit Simplified IDEA key.

    Returns:
        int: Unsigned 32-bit integer key K in [0, 0xFFFFFFFF].
    """
    if not (is_valid_integer_in_range(c1, 1, p - 1) and is_valid_integer_in_range(c2, 1, p - 1)):
        raise ValueError("Ciphertext elements c1 and c2 must be integers in [1, p - 1]")
    if not validate_private_key(private_x, p):
        raise ValueError(f"Invalid private key private_x for modulus p")

    # Recover shared secret: shared = c1^x mod p
    shared = pow(c1, private_x, p)
    shared_inv = pow(shared, -1, p)
    M = (c2 * shared_inv) % p

    # Verify that decrypted M lies in the valid 32-bit encoding range [1, 2^32]
    if not (1 <= M <= (1 << 32)):
        raise ValueError(
            f"Decrypted value M={M} is outside the valid 32-bit encoding range [1, 2^32]"
        )

    return M - 1


def elgamal_sign(
    digest_bytes: bytes, p: int, g: int, private_x: int
) -> Tuple[int, int]:
    """
    Compute a classical ElGamal digital signature over a 64-byte Whirlpool digest.

    Digest representation:
      m = int.from_bytes(digest_bytes, "big") % (p - 1)

    Signing nonce rules:
      - k sampled randomly from [2, p - 2]
      - gcd(k, p - 1) == 1
      - resampled if s == 0

    Returns:
        tuple[int, int]: (r, s) where 1 <= r <= p - 1 and 1 <= s <= p - 2
    """
    if not isinstance(digest_bytes, (bytes, bytearray)):
        raise TypeError(f"digest_bytes must be bytes or bytearray, got {type(digest_bytes).__name__}")
    if len(digest_bytes) != 64:
        raise ValueError(f"Expected 64 digest bytes (Whirlpool 512-bit), got {len(digest_bytes)}")
    if not validate_private_key(private_x, p):
        raise ValueError("Invalid private key private_x for modulus p")
    if not (is_strict_int(g) and 2 <= g < p):
        raise ValueError(f"Invalid generator g={g!r}")

    m = int.from_bytes(digest_bytes, "big") % (p - 1)

    for _ in range(5000):
        # Sample nonce k in [2, p - 2] with gcd(k, p - 1) == 1
        k = secrets.randbelow(p - 3) + 2
        if math.gcd(k, p - 1) != 1:
            continue

        r = pow(g, k, p)
        k_inv = pow(k, -1, p - 1)
        s = ((m - private_x * r) * k_inv) % (p - 1)

        # Discard and regenerate nonce if s == 0
        if s != 0:
            return r, s

    raise RuntimeError("Failed to generate a valid non-zero signature within retry threshold")


def elgamal_verify(
    digest_bytes: bytes, r: int, s: int, p: int, g: int, public_y: int
) -> Tuple[bool, int, int]:
    """
    Verify a classical ElGamal digital signature (r, s) over a 64-byte Whirlpool digest.

    Equations:
      v1 = pow(g, m, p)
      v2 = (pow(public_y, r, p) * pow(r, s, p)) % p

    Returns:
        tuple[bool, int, int]: (is_valid, v1, v2)
    """
    if not isinstance(digest_bytes, (bytes, bytearray)):
        raise TypeError(f"digest_bytes must be bytes or bytearray, got {type(digest_bytes).__name__}")
    if len(digest_bytes) != 64:
        raise ValueError(f"Expected 64 digest bytes (Whirlpool 512-bit), got {len(digest_bytes)}")
    if not validate_public_key(public_y, p):
        raise ValueError("Invalid public key public_y for modulus p")
    if not (is_strict_int(g) and 2 <= g < p):
        raise ValueError(f"Invalid generator g={g!r}")

    # Validate signature ranges: 1 <= r <= p - 1 and 1 <= s <= p - 2
    if not (is_valid_integer_in_range(r, 1, p - 1) and is_valid_integer_in_range(s, 1, p - 2)):
        return False, 0, 0

    m = int.from_bytes(digest_bytes, "big") % (p - 1)

    v1 = pow(g, m, p)
    v2 = (pow(public_y, r, p) * pow(r, s, p)) % p

    return v1 == v2, v1, v2


def _elgamal_sign_with_k_TESTING_ONLY(
    digest_bytes: bytes, k: int, p: int, g: int, private_x: int
) -> Tuple[int, int]:
    """
    TEST-ONLY HELPER: Deterministic ElGamal signature generation with fixed nonce k.
    WARNING: NEVER EXPOSE TO NORMAL CLIENT/SERVER APIS OR RUNTIME FLOWS.
    """
    if len(digest_bytes) != 64:
        raise ValueError("Expected 64 digest bytes")
    if not (2 <= k <= p - 2 and math.gcd(k, p - 1) == 1):
        raise ValueError(f"Invalid test nonce k={k}")

    m = int.from_bytes(digest_bytes, "big") % (p - 1)
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = ((m - private_x * r) * k_inv) % (p - 1)
    if s == 0:
        raise ValueError("Test nonce produced s = 0")
    return r, s
