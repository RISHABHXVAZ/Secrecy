# Author: Rishabh Srivastava
# Roll Number: 44285
# Project: Secrecy

"""
Pure Python implementation of the Whirlpool cryptographic hash function (ISO/IEC 10118-3:2004).
Author: Rishabh Srivastava (Roll No. 44285)

This module implements the standard Whirlpool 512-bit hash function entirely from scratch
using only Python's standard library. No third-party or native hashing libraries are used.

Whirlpool Overview:
- Output: 512-bit digest (64 bytes / 128 lowercase hexadecimal characters)
- Internal structure: Dedicated 512-bit block cipher W in Miyaguchi-Preneel compression mode
- Rounds: 10 identical rounds per 512-bit (64-byte) message block
- Operations per round:
    * SubBytes (gamma): 8x8 non-linear S-box substitution derived from 4x4 mini-boxes E and R
    * ShiftColumns (pi): Cyclical rotation of byte columns in the 8x8 state
    * MixRows (theta): Linear diffusion using an 8x8 circulant MDS matrix over GF(2^8) (modulus 0x11D)
    * AddRoundKey (sigma): Bitwise XOR with round subkey and round constant rc[r]
"""

from __future__ import annotations
from typing import List, Tuple


# 4-bit mini-boxes E and R used to generate the 8x8 Whirlpool S-box (ISO/IEC 10118-3:2004)
_E = [0x1, 0xB, 0x9, 0xC, 0xD, 0x6, 0xF, 0x3, 0xE, 0x8, 0x7, 0x4, 0xA, 0x2, 0x5, 0x0]
_R = [0x7, 0xC, 0xB, 0xD, 0xE, 0x4, 0x9, 0xF, 0x6, 0x3, 0x8, 0xA, 0x2, 0x5, 0x1, 0x0]

_E_INV = [0] * 16
for _i, _v in enumerate(_E):
    _E_INV[_v] = _i

# Synthesize the complete 256-byte S-box
WHIRLPOOL_SBOX: List[int] = [0] * 256
for _u in range(16):
    for _v in range(16):
        _u_prime = _E[_u]
        _v_prime = _E_INV[_v]
        _x = _u_prime ^ _v_prime
        _x_prime = _R[_x]
        _u_dprime = _E[_u_prime ^ _x_prime]
        _v_dprime = _E_INV[_v_prime ^ _x_prime]
        WHIRLPOOL_SBOX[(_u << 4) | _v] = (_u_dprime << 4) | _v_dprime


def _gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(2^8) modulo the reduction polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1D
        b >>= 1
    return res


# First row of the circulant MDS diffusion matrix C: (1, 1, 4, 1, 8, 5, 2, 9)
_C_ROW = [1, 1, 4, 1, 8, 5, 2, 9]

# Precompute the eight 64-bit lookup tables T[0..7][256] combining S-box substitution and MixRows diffusion
_T: List[List[int]] = [[0] * 256 for _ in range(8)]
for _x in range(256):
    _s = WHIRLPOOL_SBOX[_x]
    _col = [_gf_mul(_s, _c) for _c in _C_ROW]
    _w = 0
    for _byte in _col:
        _w = (_w << 8) | _byte
    _T[0][_x] = _w
    for _t in range(1, 8):
        # Rotate 64-bit word right by 8 bits
        _w = ((_w >> 8) | ((_w & 0xFF) << 56)) & 0xFFFFFFFFFFFFFFFF
        _T[_t][_x] = _w

# The 10 64-bit round constants for r = 0 .. 9 (ISO/IEC 10118-3:2004)
_RC: List[int] = [
    0x1823C6E887B8014F,
    0x36A6D2F5796F9152,
    0x60BC9B8EA30C7B35,
    0x1DE0D7C22E4BFE57,
    0x157737E59FF04ADA,
    0x58C9290AB1A06B85,
    0xBD5D10F4CB3E0567,
    0xE427418BA77D95D8,
    0xFBEE7C66DD17479E,
    0xCA2DBF07AD5A8333,
]


def _whirlpool_op(src: List[int], shift: int) -> int:
    """
    Combined SubBytes, ShiftColumns, and MixRows round operation on an 8-word 64-bit array.
    Uses precomputed diffusion lookup tables T[0..7].
    """
    return (
        _T[0][(src[shift & 7] >> 56) & 0xFF]
        ^ _T[1][(src[(shift + 7) & 7] >> 48) & 0xFF]
        ^ _T[2][(src[(shift + 6) & 7] >> 40) & 0xFF]
        ^ _T[3][(src[(shift + 5) & 7] >> 32) & 0xFF]
        ^ _T[4][(src[(shift + 4) & 7] >> 24) & 0xFF]
        ^ _T[5][(src[(shift + 3) & 7] >> 16) & 0xFF]
        ^ _T[6][(src[(shift + 2) & 7] >> 8) & 0xFF]
        ^ _T[7][src[(shift + 1) & 7] & 0xFF]
    )


def _pad_whirlpool(message: bytes) -> bytes:
    """
    Apply standard Whirlpool padding (ISO/IEC 10118-3:2004):
    1. Append bit '1' (byte 0x80).
    2. Append '0' bits until total bit length = 256 mod 512 (byte length = 32 mod 64).
    3. Append original message length in bits as a 256-bit (32-byte) big-endian unsigned integer.
    """
    bit_len = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) % 64 != 32:
        padded.append(0x00)
    padded.extend(bit_len.to_bytes(32, "big"))
    return bytes(padded)


def whirlpool_bytes(data: bytes) -> bytes:
    """
    Compute the standard 512-bit Whirlpool hash of data.

    Returns:
        Exactly 64 raw digest bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Input data must be bytes or bytearray, got {type(data).__name__}")

    padded = _pad_whirlpool(data)
    hash_words = [0] * 8

    # Process each 64-byte (512-bit) block
    for blk_offset in range(0, len(padded), 64):
        block = padded[blk_offset : blk_offset + 64]
        p_block = [
            int.from_bytes(block[i * 8 : (i + 1) * 8], "big") for i in range(8)
        ]

        # Working key K and state initialized from previous hash and current block
        K = [[0] * 8, [0] * 8]
        state = [[0] * 8, [0] * 8]
        for i in range(8):
            K[0][i] = hash_words[i]
            state[0][i] = p_block[i] ^ hash_words[i]

        m = 0
        for r in range(10):
            next_m = m ^ 1
            for i in range(8):
                K[next_m][i] = _whirlpool_op(K[m], i)
                if i == 0:
                    K[next_m][0] ^= _RC[r]
                state[next_m][i] = _whirlpool_op(state[m], i) ^ K[next_m][i]
            m = next_m

        # Miyaguchi-Preneel hashing update: H_i = W(H_{i-1}, M_i) ^ H_{i-1} ^ M_i
        for i in range(8):
            hash_words[i] ^= state[m][i] ^ p_block[i]

    digest = bytearray()
    for w in hash_words:
        digest.extend(w.to_bytes(8, "big"))
    return bytes(digest)


def whirlpool(data: bytes) -> str:
    """
    Compute the standard 512-bit Whirlpool hash of data as a hexadecimal string.

    Returns:
        Exactly 128 lowercase hexadecimal characters.
    """
    return whirlpool_bytes(data).hex()


# Alias for explicit typing/naming clarity
whirlpool_hex = whirlpool
