"""
Cryptographic intermediate execution tracer and display formatting for Secrecy.

Author: Rishabh Srivastava
Roll Number: 44285
Project: Secrecy

Provides block-by-block and round-by-round tracing for Simplified IDEA
encryption and decryption in CBC mode, as well as formatted terminal display
helpers matching the assignment requirements.
"""

from typing import List, Tuple
from secrecy.simplified_idea import (
    generate_subkeys,
    generate_decryption_keys,
    pad_pkcs7_2byte,
    unpad_pkcs7_2byte,
    idea_encrypt_block,
    idea_decrypt_block,
)


def cbc_encrypt_with_trace(
    plaintext: bytes,
    key_32bit: int,
    iv_16bit: int
) -> Tuple[bytes, List[str]]:
    """
    Encrypt plaintext in CBC mode with Simplified IDEA, collecting full
    round-by-round trace logs for every block.

    Args:
        plaintext: Raw plaintext bytes.
        key_32bit: 32-bit Simplified IDEA key.
        iv_16bit: 16-bit Initialization Vector.

    Returns:
        (ciphertext_blocks_bytes, trace_lines)
    """
    subkeys = generate_subkeys(key_32bit)
    padded = pad_pkcs7_2byte(plaintext)
    trace: List[str] = []

    trace.append(f"32-bit Session Key: 0x{key_32bit:08X} ({key_32bit})")
    trace.append(f"16-bit IV:          0x{iv_16bit:04X} ({iv_16bit})")
    trace.append(f"Plaintext Length:   {len(plaintext)} bytes (Padded: {len(padded)} bytes)")
    num_blocks = len(padded) // 2
    trace.append(f"Total Blocks:       {num_blocks}")

    prev_ct = iv_16bit
    ct_blocks = []

    for idx in range(num_blocks):
        pt_bytes = padded[idx * 2 : (idx + 1) * 2]
        pt_block = int.from_bytes(pt_bytes, "big")
        cbc_in = pt_block ^ prev_ct

        trace.append(f"\n--- Block {idx + 1}/{num_blocks} ---")
        trace.append(f"  Plaintext block: 0x{pt_block:04X} (bytes: {pt_bytes!r})")
        trace.append(f"  CBC XOR input:   0x{pt_block:04X} ^ 0x{prev_ct:04X} = 0x{cbc_in:04X}")

        ct_block, block_logs = idea_encrypt_block(cbc_in, subkeys, log_steps=True)
        for log_line in block_logs:
            trace.append(f"  {log_line}")

        trace.append(f"  Resulting Ciphertext Block: 0x{ct_block:04X}")
        prev_ct = ct_block
        ct_blocks.append(ct_block.to_bytes(2, "big"))

    return b"".join(ct_blocks), trace


def cbc_decrypt_with_trace(
    ciphertext_blocks_bytes: bytes,
    iv_16bit: int,
    key_32bit: int
) -> Tuple[bytes, List[str]]:
    """
    Decrypt ciphertext blocks in CBC mode with Simplified IDEA, collecting full
    round-by-round trace logs for every block.

    Args:
        ciphertext_blocks_bytes: Raw ciphertext blocks (without IV prefix).
        iv_16bit: 16-bit Initialization Vector.
        key_32bit: 32-bit Simplified IDEA key.

    Returns:
        (unpadded_plaintext_bytes, trace_lines)
    """
    if len(ciphertext_blocks_bytes) == 0 or len(ciphertext_blocks_bytes) % 2 != 0:
        raise ValueError(f"Invalid ciphertext block bytes length: {len(ciphertext_blocks_bytes)}")

    enc_subkeys = generate_subkeys(key_32bit)
    dec_subkeys = generate_decryption_keys(enc_subkeys)
    trace: List[str] = []

    num_blocks = len(ciphertext_blocks_bytes) // 2
    trace.append(f"32-bit Session Key: 0x{key_32bit:08X} ({key_32bit})")
    trace.append(f"16-bit IV:          0x{iv_16bit:04X} ({iv_16bit})")
    trace.append(f"Total Blocks:       {num_blocks}")

    prev_ct = iv_16bit
    pt_blocks = []

    for idx in range(num_blocks):
        ct_bytes = ciphertext_blocks_bytes[idx * 2 : (idx + 1) * 2]
        ct_block = int.from_bytes(ct_bytes, "big")

        trace.append(f"\n--- Block {idx + 1}/{num_blocks} ---")
        trace.append(f"  Ciphertext block: 0x{ct_block:04X}")

        dec_out, block_logs = idea_decrypt_block(ct_block, dec_subkeys, log_steps=True)
        for log_line in block_logs:
            trace.append(f"  {log_line}")

        pt_block = dec_out ^ prev_ct
        trace.append(f"  CBC XOR output:  0x{dec_out:04X} ^ 0x{prev_ct:04X} = 0x{pt_block:04X}")
        prev_ct = ct_block
        pt_blocks.append(pt_block.to_bytes(2, "big"))

    raw_padded = b"".join(pt_blocks)
    plaintext = unpad_pkcs7_2byte(raw_padded)
    trace.append(f"\nPadding validated and removed: {len(raw_padded)} -> {len(plaintext)} bytes.")
    return plaintext, trace
