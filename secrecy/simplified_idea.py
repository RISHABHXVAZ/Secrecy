# Author: Rishabh Srivastava
# Roll Number: 44285
# Project: Secrecy

"""
Simplified IDEA (International Data Encryption Algorithm) Implementation.
Author: Rishabh Srivastava (Roll No. 44285)

This module implements the Simplified IDEA block cipher based on the specification
by Nick Hoffman (Department of Mathematics, Northern Kentucky University).

Specifications:
- Plaintext block size: 16 bits (four 4-bit nibbles: X1, X2, X3, X4)
- Ciphertext block size: 16 bits
- Key size: 32 bits (eight 4-bit nibbles initially: Z1 .. Z8)
- Rounds: 4 identical complete rounds + 1 final half-round transformation
- Subkeys: 28 4-bit subkeys generated via successive 6-bit cyclic left shifts
- Operations:
    * Bitwise XOR on 4-bit nibbles
    * Addition modulo 2^4 = 16
    * Multiplication modulo 2^4 + 1 = 17, where 0000_2 represents 16 (= -1 mod 17)

Note on Erratum in Nick Hoffman's Paper:
On page 4 of the reference paper, the example key in the prose text is printed as:
    110111000110111100111111 (24 bits)
However, on page 3 and in the encryption key schedule table, the actual 32-bit key
is explicitly defined as:
    11011100011011110011111101011001 (0xDC6F3F59)
This 32-bit key correctly produces the reference ciphertext:
    Plaintext:  1001110010101100 (0x9CAC)
    Ciphertext: 1011101101001011 (0xBB4B)
"""

from __future__ import annotations
import secrets
from typing import List, Tuple


def rol32(val: int, r: int) -> int:
    """Cyclically rotate a 32-bit integer left by r bit positions."""
    r = r % 32
    return ((val << r) | (val >> (32 - r))) & 0xFFFFFFFF


def add16(a: int, b: int) -> int:
    """Addition modulo 16 on 4-bit nibbles."""
    return (a + b) & 0xF


def inv_add16(a: int) -> int:
    """Additive inverse modulo 16 on 4-bit nibbles."""
    return (-a) & 0xF


def mul17(a: int, b: int) -> int:
    """
    Multiplication modulo 17 on 4-bit nibbles.
    0000_2 (0) represents integer 16 (= -1 mod 17).
    Results congruent to 16 mod 17 are represented as 0000_2 (0).
    """
    x = 16 if a == 0 else a
    y = 16 if b == 0 else b
    p = (x * y) % 17
    return 0 if p == 16 else p


def inv_mul17(a: int) -> int:
    """
    Multiplicative inverse modulo 17 on 4-bit nibbles.
    0000_2 (16) is its own inverse under multiplication mod 17 (16 * 16 = 256 = 1 mod 17).
    """
    val = 16 if a == 0 else a
    for inv in range(1, 17):
        if (val * inv) % 17 == 1:
            return 0 if inv == 16 else inv
    raise ValueError(f"No multiplicative inverse mod 17 for nibble {a}")


def generate_subkeys(key_32bit: int) -> List[int]:
    """
    Generate the 28 4-bit subkeys required for Simplified IDEA encryption.

    Key schedule according to Nick Hoffman:
    - 32-bit key is split into eight nibbles (Z1 .. Z8).
    - Round 1 takes Z1 .. Z6.
    - Round 2 takes Z7, Z8, then cyclically shifts the 32-bit key left by 6 bits.
    - Round 2 completes with first 4 nibbles of the shifted key.
    - Round 3 takes the remaining 4 nibbles of that shifted key, then shifts left by 6 bits.
    - Round 3 completes with first 2 nibbles of the newly shifted key.
    - Round 4 takes the next 6 nibbles, then shifts left by 6 bits.
    - Round 5 (final transformation) takes the first 4 nibbles.
    """
    if not (0 <= key_32bit <= 0xFFFFFFFF):
        raise ValueError(f"Key must be an unsigned 32-bit integer (0 <= key <= 0xFFFFFFFF), got {key_32bit}")

    subkeys: List[int] = []
    curr_key = key_32bit
    while len(subkeys) < 28:
        for i in range(8):
            nibble = (curr_key >> (28 - 4 * i)) & 0xF
            subkeys.append(nibble)
            if len(subkeys) == 28:
                break
        curr_key = rol32(curr_key, 6)

    return subkeys


def generate_decryption_keys(subkeys: List[int]) -> List[int]:
    """
    Generate the 28 4-bit decryption subkeys from encryption subkeys.

    Let Z_j^i denote the j-th encryption subkey of round i (i in 1..5).
    Let K_j^i denote the j-th decryption subkey of round i (i in 1..5).

    Decryption schedule:
    Round 1:
        K_1^1 = (Z_1^5)^(-1) mod 17
        K_2^1 = -Z_2^5 mod 16
        K_3^1 = -Z_3^5 mod 16
        K_4^1 = (Z_4^5)^(-1) mod 17
        K_5^1 = Z_5^4
        K_6^1 = Z_6^4
    Rounds r in [2, 3, 4] with enc_r = 6 - r:
        K_1^r = (Z_1^enc_r)^(-1) mod 17
        K_2^r = -Z_2^enc_r mod 16
        K_3^r = -Z_3^enc_r mod 16
        K_4^r = (Z_4^enc_r)^(-1) mod 17
        K_5^r = Z_5^(enc_r - 1)
        K_6^r = Z_6^(enc_r - 1)
    Round 5 (half-round):
        K_1^5 = (Z_1^1)^(-1) mod 17
        K_2^5 = -Z_2^1 mod 16
        K_3^5 = -Z_3^1 mod 16
        K_4^5 = (Z_4^1)^(-1) mod 17
    """
    if len(subkeys) != 28:
        raise ValueError(f"Expected 28 subkeys, got {len(subkeys)}")

    # Group encryption subkeys by round
    Z: dict[int, list[int]] = {
        1: subkeys[0:6],
        2: subkeys[6:12],
        3: subkeys[12:18],
        4: subkeys[18:24],
        5: subkeys[24:28],
    }

    K: dict[int, list[int]] = {}
    # Round 1
    K[1] = [
        inv_mul17(Z[5][0]),
        inv_add16(Z[5][1]),
        inv_add16(Z[5][2]),
        inv_mul17(Z[5][3]),
        Z[4][4],
        Z[4][5],
    ]

    # Rounds 2, 3, 4
    for r in range(2, 5):
        enc_r = 6 - r
        K[r] = [
            inv_mul17(Z[enc_r][0]),
            inv_add16(Z[enc_r][1]),
            inv_add16(Z[enc_r][2]),
            inv_mul17(Z[enc_r][3]),
            Z[enc_r - 1][4],
            Z[enc_r - 1][5],
        ]

    # Round 5
    K[5] = [
        inv_mul17(Z[1][0]),
        inv_add16(Z[1][1]),
        inv_add16(Z[1][2]),
        inv_mul17(Z[1][3]),
    ]

    dec_keys: List[int] = []
    for r in range(1, 5):
        dec_keys.extend(K[r])
    dec_keys.extend(K[5])
    return dec_keys


def idea_encrypt_block(
    block_16bit: int, subkeys: List[int], log_steps: bool = False
) -> Tuple[int, List[str]]:
    """
    Encrypt a single 16-bit block using Simplified IDEA with 28 subkeys.

    Returns:
        (ciphertext_16bit, intermediate_log_strings)
    """
    if not (0 <= block_16bit <= 0xFFFF):
        raise ValueError(f"Block must be an unsigned 16-bit integer (0 <= block <= 0xFFFF), got {block_16bit}")
    if len(subkeys) != 28:
        raise ValueError(f"Expected 28 subkeys, got {len(subkeys)}")

    logs: List[str] = []
    X1 = (block_16bit >> 12) & 0xF
    X2 = (block_16bit >> 8) & 0xF
    X3 = (block_16bit >> 4) & 0xF
    X4 = block_16bit & 0xF

    if log_steps:
        logs.append(f"Initial block nibbles: X1={X1:X}, X2={X2:X}, X3={X3:X}, X4={X4:X}")

    sk_idx = 0
    for r in range(1, 5):
        z1, z2, z3, z4, z5, z6 = subkeys[sk_idx : sk_idx + 6]
        sk_idx += 6

        s1 = mul17(X1, z1)
        s2 = add16(X2, z2)
        s3 = add16(X3, z3)
        s4 = mul17(X4, z4)
        s5 = s1 ^ s3
        s6 = s2 ^ s4
        s7 = mul17(s5, z5)
        s8 = add16(s6, s7)
        s9 = mul17(s8, z6)
        s10 = add16(s7, s9)
        s11 = s1 ^ s9
        s12 = s3 ^ s9
        s13 = s2 ^ s10
        s14 = s4 ^ s10

        if log_steps:
            logs.append(
                f"Round {r} Subkeys: Z1={z1:X}, Z2={z2:X}, Z3={z3:X}, Z4={z4:X}, Z5={z5:X}, Z6={z6:X}"
            )
            logs.append(
                f"Round {r} Steps: s1={s1:X}, s2={s2:X}, s3={s3:X}, s4={s4:X}, "
                f"s7={s7:X}, s8={s8:X}, s9={s9:X}, s10={s10:X}"
            )
            logs.append(
                f"Round {r} Output (swapped): X1={s11:X}, X2={s13:X}, X3={s12:X}, X4={s14:X}"
            )

        # Swapped nibbles for input to the next round
        X1, X2, X3, X4 = s11, s13, s12, s14

    # Round 5: Final transformation (half round)
    z1, z2, z3, z4 = subkeys[sk_idx : sk_idx + 4]
    y1 = mul17(X1, z1)
    y2 = add16(X2, z2)
    y3 = add16(X3, z3)
    y4 = mul17(X4, z4)

    if log_steps:
        logs.append(f"Round 5 (Final Transformation) Subkeys: Z1={z1:X}, Z2={z2:X}, Z3={z3:X}, Z4={z4:X}")
        logs.append(f"Final Nibbles: Y1={y1:X}, Y2={y2:X}, Y3={y3:X}, Y4={y4:X}")

    out_block = (y1 << 12) | (y2 << 8) | (y3 << 4) | y4
    return out_block, logs


def idea_decrypt_block(
    block_16bit: int, dec_subkeys: List[int], log_steps: bool = False
) -> Tuple[int, List[str]]:
    """
    Decrypt a single 16-bit block using Simplified IDEA with 28 decryption subkeys.
    Uses the exact same transformation function as encryption, parameterised by dec_subkeys.
    """
    return idea_encrypt_block(block_16bit, dec_subkeys, log_steps=log_steps)


def pad_pkcs7_2byte(data: bytes) -> bytes:
    """
    Apply PKCS#7 padding for 2-byte (16-bit) blocks.
    - If length is odd, appends 1 byte with value 0x01.
    - If length is even, appends 2 bytes with value 0x02, 0x02.
    """
    pad_len = 2 - (len(data) % 2)
    if pad_len == 0:
        pad_len = 2
    return data + bytes([pad_len] * pad_len)


def unpad_pkcs7_2byte(padded_data: bytes) -> bytes:
    """
    Validate and remove PKCS#7 padding for 2-byte (16-bit) blocks.
    Raises ValueError if padding is malformed or invalid.
    """
    if len(padded_data) < 2 or len(padded_data) % 2 != 0:
        raise ValueError(
            f"Invalid padded data length: must be non-empty even number of bytes, got {len(padded_data)}"
        )

    pad_len = padded_data[-1]
    if pad_len not in (1, 2):
        raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len} (expected 1 or 2)")

    if padded_data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError(
            f"Corrupted PKCS#7 padding bytes: expected {bytes([pad_len] * pad_len)!r}, got {padded_data[-pad_len:]!r}"
        )

    return padded_data[:-pad_len]


def idea_cbc_encrypt(
    plaintext: bytes, key_32bit: int, iv: bytes | None = None
) -> Tuple[bytes, List[str]]:
    """
    Encrypt arbitrary bytes in Cipher Block Chaining (CBC) mode using Simplified IDEA.

    Padding: PKCS#7 2-byte block padding.
    IV: 16-bit (2-byte) initialization vector. If not supplied, sampled via `secrets`.
    Ciphertext format: IV (2 bytes) || Ciphertext blocks (2 * N bytes).

    Returns:
        (ciphertext_bytes, intermediate_logs)
    """
    if iv is None:
        iv = secrets.token_bytes(2)
    elif len(iv) != 2:
        raise ValueError(f"IV must be exactly 2 bytes (16 bits), got {len(iv)} bytes")

    subkeys = generate_subkeys(key_32bit)
    padded = pad_pkcs7_2byte(plaintext)

    logs: List[str] = [
        f"CBC Encryption initialized with 32-bit Key: 0x{key_32bit:08X}",
        f"Random 16-bit IV: 0x{int.from_bytes(iv, 'big'):04X}",
        f"Plaintext length: {len(plaintext)} bytes -> Padded length: {len(padded)} bytes",
    ]

    ciphertext_blocks: List[bytes] = [iv]
    prev_ct = int.from_bytes(iv, "big")

    num_blocks = len(padded) // 2
    for b_idx in range(num_blocks):
        pt_block = int.from_bytes(padded[b_idx * 2 : (b_idx + 1) * 2], "big")
        cbc_input = pt_block ^ prev_ct
        ct_block, block_logs = idea_encrypt_block(cbc_input, subkeys, log_steps=False)
        prev_ct = ct_block
        ciphertext_blocks.append(ct_block.to_bytes(2, "big"))

    logs.append(f"Encrypted {num_blocks} 16-bit blocks in CBC mode.")
    return b"".join(ciphertext_blocks), logs


def idea_cbc_decrypt(ciphertext: bytes, key_32bit: int) -> Tuple[bytes, List[str]]:
    """
    Decrypt CBC-mode ciphertext using Simplified IDEA.

    Validates:
    - Minimum length 4 bytes (2 bytes IV + at least 1 2-byte block).
    - Length must be even.
    - PKCS#7 2-byte padding validation.

    Returns:
        (decrypted_plaintext_bytes, intermediate_logs)
    """
    if len(ciphertext) < 4 or len(ciphertext) % 2 != 0:
        raise ValueError(
            f"Invalid CBC ciphertext length: expected even length >= 4 bytes, got {len(ciphertext)}"
        )

    iv = ciphertext[:2]
    prev_ct = int.from_bytes(iv, "big")

    enc_subkeys = generate_subkeys(key_32bit)
    dec_subkeys = generate_decryption_keys(enc_subkeys)

    logs: List[str] = [
        f"CBC Decryption initialized with 32-bit Key: 0x{key_32bit:08X}",
        f"Extracted 16-bit IV: 0x{prev_ct:04X}",
    ]

    decrypted_blocks: List[bytes] = []
    num_blocks = (len(ciphertext) - 2) // 2

    for b_idx in range(num_blocks):
        ct_bytes = ciphertext[2 + b_idx * 2 : 2 + (b_idx + 1) * 2]
        ct_block = int.from_bytes(ct_bytes, "big")
        dec_block, _ = idea_decrypt_block(ct_block, dec_subkeys, log_steps=False)
        pt_block = dec_block ^ prev_ct
        prev_ct = ct_block
        decrypted_blocks.append(pt_block.to_bytes(2, "big"))

    raw_padded = b"".join(decrypted_blocks)
    plaintext = unpad_pkcs7_2byte(raw_padded)
    logs.append(f"Decrypted {num_blocks} blocks and successfully validated PKCS#7 padding.")
    return plaintext, logs
