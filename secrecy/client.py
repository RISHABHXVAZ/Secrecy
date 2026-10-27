"""
Client application for the Secrecy secure messaging system.

Author: Rishabh Srivastava
Roll Number: 44285
Project: Secrecy

Features:
- Connects to Secrecy server via TCP.
- Obtains server's ElGamal public key and verifies domain parameters.
- Generates client ElGamal signing key pair.
- Accepts message interactively or via CLI.
- Generates or accepts 32-bit Simplified IDEA key.
- Computes 512-bit Whirlpool hash from scratch.
- Generates ElGamal digital signature on the digest.
- Encrypts 32-bit IDEA key using server's ElGamal public key.
- Encrypts message using Simplified IDEA in CBC mode with 16-bit IV, tracing round transformations.
- Displays complete cryptographic details matching assignment layout.
- Sends SECURE_MESSAGE and displays server's verification STATUS_RESPONSE.
"""

import argparse
import secrets
import socket
import sys
from typing import Optional, Tuple

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

from secrecy.elgamal import (
    elgamal_encrypt_key,
    elgamal_generate_keypair,
    elgamal_sign,
)
from secrecy.params import (
    validate_production_group,
    validate_public_key,
)
from secrecy.protocol import (
    DEFAULT_SOCKET_TIMEOUT,
    MAX_PLAINTEXT_BYTES,
    build_key_request,
    build_secure_message,
    recv_frame,
    send_frame,
    validate_key_response,
    validate_status_response,
)
from secrecy.tracer import cbc_encrypt_with_trace
from secrecy.whirlpool import whirlpool_bytes, whirlpool_hex


def format_large_int(val: int, preview_len: int = 16) -> str:
    """Format large integers with hex preview and bit-length for clean display."""
    hex_str = f"{val:X}"
    if len(hex_str) > preview_len * 2:
        return f"0x{hex_str[:preview_len]}...{hex_str[-preview_len:]} ({val.bit_length()} bits)"
    return f"0x{hex_str} ({val.bit_length()} bits)"


def send_secure_message(
    host: str,
    port: int,
    message: str,
    idea_key_32bit: Optional[int] = None,
    tamper_cipher: bool = False,
    tamper_key: bool = False,
    tamper_sig: bool = False,
    verbose: bool = True
) -> bool:
    """
    Execute the client secure message exchange with the server.

    Returns:
        True if server returns ACCEPTED, False if REJECTED or failed.
    """
    message_bytes = message.encode("utf-8")
    if len(message_bytes) > MAX_PLAINTEXT_BYTES:
        raise ValueError(
            f"Message size ({len(message_bytes)} bytes) exceeds maximum permitted ({MAX_PLAINTEXT_BYTES} bytes)."
        )

    # Simplified IDEA 32-bit session key
    if idea_key_32bit is None:
        idea_key_32bit = secrets.randbelow(0x100000000)
    elif not (0 <= idea_key_32bit <= 0xFFFFFFFF):
        raise ValueError(f"IDEA key must be in range [0, 0xFFFFFFFF], got {idea_key_32bit}")

    # Generate 16-bit random IV
    iv_16bit = secrets.randbelow(0x10000)

    print("\n" + "=" * 80)
    print("                     SECRECY CLIENT - SECURE SENDER")
    print("=" * 80)
    print(f"Author: Rishabh Srivastava | Roll No.: 44285")
    print("-" * 80)
    print(f"Input Message:                {message!r}")
    print(f"Message Size:                 {len(message_bytes)} bytes")
    print(f"Secret Key (Simplified IDEA): 0x{idea_key_32bit:08X} ({idea_key_32bit})")

    # Connect to server
    print(f"Connecting to Secrecy server at {host}:{port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(DEFAULT_SOCKET_TIMEOUT)
        sock.connect((host, port))

        # Step 1: Send KEY_REQUEST
        send_frame(sock, build_key_request())

        # Step 2: Receive KEY_RESPONSE
        key_resp = recv_frame(sock)
        p, g, server_pub = validate_key_response(key_resp)
        validate_production_group(p, g)
        validate_public_key(server_pub, p)

        print("-" * 80)
        print(f"ElGamal Parameters:")
        print(f"  Prime Modulus (p):          {format_large_int(p)}")
        print(f"  Custom Generator (g):       {g}")
        print(f"  Server Public Key:          {format_large_int(server_pub)}")
        print("-" * 80)

        # Step 3: Client generates its ElGamal key pair for digital signature
        client_pub, client_priv = elgamal_generate_keypair(p, g)
        print(f"Client Public Key:            {format_large_int(client_pub)}")

        # Step 4: Encrypt 32-bit IDEA session key using server's ElGamal public key
        c1, c2 = elgamal_encrypt_key(idea_key_32bit, p, g, server_pub)
        if tamper_key:
            print("[SIMULATED ATTACK] Tampering with ElGamal encrypted key ciphertext (c2)...")
            c2 = (c2 ^ 0xFF) % p

        print("-" * 80)
        print(f"Encrypted Secret Key (ElGamal):")
        print(f"  c1 = {format_large_int(c1)}")
        print(f"  c2 = {format_large_int(c2)}")

        # Step 5: Encrypt message using Simplified IDEA in CBC mode with trace
        print("\n" + "-" * 80)
        print("             INTERMEDIATE SIMPLIFIED IDEA ENCRYPTION PROCESS")
        print("-" * 80)
        ciphertext_blocks, trace_lines = cbc_encrypt_with_trace(
            plaintext=message_bytes,
            key_32bit=idea_key_32bit,
            iv_16bit=iv_16bit
        )
        if verbose:
            for line in trace_lines:
                print(line)
        else:
            print(f"Encrypted {len(ciphertext_blocks) // 2} blocks in CBC mode.")

        if tamper_cipher:
            print("\n[SIMULATED ATTACK] Tampering with ciphertext bytes...")
            raw_ct = bytearray(ciphertext_blocks)
            raw_ct[0] ^= 0x5A
            ciphertext_blocks = bytes(raw_ct)

        print("-" * 80)
        print(f"Cipher Text (hex):            {ciphertext_blocks.hex()}")

        # Step 6: Compute Whirlpool Hash from scratch
        digest_bytes = whirlpool_bytes(message_bytes)
        hash_code_hex = whirlpool_hex(message_bytes)
        print("-" * 80)
        print(f"Hash Code (Whirlpool 512-bit): {hash_code_hex}")

        # Step 7: Compute ElGamal Digital Signature on the digest
        sig_r, sig_s = elgamal_sign(digest_bytes, p, g, client_priv)
        if tamper_sig:
            print("[SIMULATED ATTACK] Tampering with signature value s...")
            sig_s = (sig_s + 1) % (p - 1)
            if sig_s == 0:
                sig_s = 1

        print("-" * 80)
        print(f"Digital Signature (r, s):")
        print(f"  r = {format_large_int(sig_r)}")
        print(f"  s = {format_large_int(sig_s)}")

        # Step 8: Build and transmit SECURE_MESSAGE
        sec_msg = build_secure_message(
            c1=c1,
            c2=c2,
            iv=iv_16bit,
            ciphertext_bytes=ciphertext_blocks,
            hash_code_hex=hash_code_hex,
            sig_r=sig_r,
            sig_s=sig_s,
            client_pub=client_pub
        )
        print("-" * 80)
        print("Transmitting SECURE_MESSAGE to server...")
        send_frame(sock, sec_msg)

        # Step 9: Receive and validate STATUS_RESPONSE
        status_frame = recv_frame(sock)
        status_info = validate_status_response(status_frame)

        print("\n" + "=" * 80)
        print("                     SERVER VERIFICATION RESPONSE")
        print("=" * 80)
        print(f"Server Status:                <{status_info['status']}>")
        print(f"Signature Valid:              {status_info['signature_valid']}")
        print(f"Hash Code Matched:            {status_info['hash_matched']}")
        print(f"Server Detail:                {status_info['detail']}")
        print("=" * 80 + "\n")

        return status_info["status"] == "ACCEPTED"


def main():
    parser = argparse.ArgumentParser(
        description="Secrecy Secure Client — Author: Rishabh Srivastava (Roll No. 44285)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Server port (default: 9999)")
    parser.add_argument("--message", "-m", help="Message to send (prompts if omitted)")
    parser.add_argument("--key", "-k", help="32-bit IDEA key in hex (e.g. 0xDC6F3F59) or decimal")
    parser.add_argument("--quiet", action="store_true", help="Suppress block-level round details")
    parser.add_argument("--tamper-cipher", action="store_true", help="Attack simulation: tamper with ciphertext")
    parser.add_argument("--tamper-key", action="store_true", help="Attack simulation: tamper with encrypted key")
    parser.add_argument("--tamper-sig", action="store_true", help="Attack simulation: tamper with digital signature")
    args = parser.parse_args()

    message = args.message
    if not message:
        try:
            message = input("Enter message to encrypt and send: ")
        except (EOFError, KeyboardInterrupt):
            print("\nAborted by user.")
            sys.exit(1)

    key_val = None
    if args.key:
        try:
            if args.key.lower().startswith("0x"):
                key_val = int(args.key, 16)
            else:
                key_val = int(args.key)
        except ValueError:
            print(f"Invalid key specification: {args.key}")
            sys.exit(1)

    try:
        success = send_secure_message(
            host=args.host,
            port=args.port,
            message=message,
            idea_key_32bit=key_val,
            tamper_cipher=args.tamper_cipher,
            tamper_key=args.tamper_key,
            tamper_sig=args.tamper_sig,
            verbose=not args.quiet
        )
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[CLIENT ERROR] {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
