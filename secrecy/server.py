"""
Server application for the Secrecy secure messaging system.

Author: Rishabh Srivastava
Roll Number: 44285
Project: Secrecy

Features:
- Listens for client connections over TCP using length-prefixed JSON protocol.
- Generates ElGamal key pair over RFC 3526 2048-bit safe prime group with custom full-order generator g=11.
- Provides public key upon KEY_REQUEST.
- Receives SECURE_MESSAGE, decrypts 32-bit Simplified IDEA key via ElGamal.
- Decrypts message in CBC mode with Simplified IDEA, tracing block transformations.
- Recomputes Whirlpool digest on recovered plaintext.
- Verifies ElGamal digital signature (computing and displaying LHS and RHS).
- Displays formatted terminal output matching assignment requirements.
- Returns STATUS_RESPONSE to client.
"""

import argparse
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

from secrecy.elgamal import elgamal_decrypt_key, elgamal_generate_keypair, elgamal_verify
from secrecy.params import (
    RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G,
    RFC3526_MODP_2048_P,
    validate_production_group,
    validate_public_key,
)
from secrecy.protocol import (
    DEFAULT_SOCKET_TIMEOUT,
    ConnectionClosedError,
    ProtocolError,
    build_key_response,
    build_status_response,
    recv_frame,
    send_frame,
    validate_key_request,
    validate_secure_message,
)
from secrecy.tracer import cbc_decrypt_with_trace
from secrecy.whirlpool import whirlpool_bytes, whirlpool_hex


def format_large_int(val: int, preview_len: int = 16) -> str:
    """Format large integers with hex preview and bit-length for clean display."""
    hex_str = f"{val:X}"
    if len(hex_str) > preview_len * 2:
        return f"0x{hex_str[:preview_len]}...{hex_str[-preview_len:]} ({val.bit_length()} bits)"
    return f"0x{hex_str} ({val.bit_length()} bits)"


def process_secure_session(
    conn: socket.socket,
    p: int,
    g: int,
    server_priv: int,
    server_pub: int,
    verbose: bool = True
) -> bool:
    """
    Handle a single client connection session.

    Returns:
        True if message was accepted with valid signature and hash, False otherwise.
    """
    conn.settimeout(DEFAULT_SOCKET_TIMEOUT)

    # Step 1: Receive and handle KEY_REQUEST
    req_frame = recv_frame(conn)
    validate_key_request(req_frame)

    # Step 2: Send KEY_RESPONSE
    resp_frame = build_key_response(p=p, g=g, server_pub=server_pub)
    send_frame(conn, resp_frame)

    # Step 3: Receive SECURE_MESSAGE
    sec_frame = recv_frame(conn)
    fields = validate_secure_message(sec_frame)

    c1 = fields["c1"]
    c2 = fields["c2"]
    iv = fields["iv"]
    ciphertext = fields["ciphertext"]
    received_hash_hex = fields["hash_code"]
    sig_r = fields["sig_r"]
    sig_s = fields["sig_s"]
    client_pub = fields["client_pub"]

    print("\n" + "=" * 80)
    print("                     SECRECY SERVER - MESSAGE RECEIVED")
    print("=" * 80)
    print(f"Author: Rishabh Srivastava | Roll No.: 44285")
    print("-" * 80)
    print(f"ElGamal Prime Modulus (p):    {format_large_int(p)}")
    print(f"ElGamal Custom Generator (g): {g}")
    print(f"Server Public Key:            {format_large_int(server_pub)}")
    print(f"Client Public Key:            {format_large_int(client_pub)}")
    print("-" * 80)

    # Validate client's public key
    validate_public_key(client_pub, p)

    # Step 4: Decrypt 32-bit Simplified IDEA Secret Key
    try:
        decrypted_key_32bit = elgamal_decrypt_key(c1, c2, p, server_priv)
        print(f"Decrypted Secret Key:         0x{decrypted_key_32bit:08X} ({decrypted_key_32bit})")
    except Exception as e:
        print(f"[ERROR] Failed to decrypt ElGamal secret key: {e}")
        status_resp = build_status_response("REJECTED", f"Key decryption failed: {e}", False, False)
        send_frame(conn, status_resp)
        return False

    # Step 5: Decrypt Ciphertext using Simplified IDEA with intermediate trace
    print("\n" + "-" * 80)
    print("             INTERMEDIATE SIMPLIFIED IDEA DECRYPTION PROCESS")
    print("-" * 80)
    try:
        decrypted_bytes, trace_lines = cbc_decrypt_with_trace(
            ciphertext_blocks_bytes=ciphertext,
            iv_16bit=iv,
            key_32bit=decrypted_key_32bit
        )
        if verbose:
            for line in trace_lines:
                print(line)
        else:
            print(f"Decrypted {len(ciphertext) // 2} blocks successfully.")
    except Exception as e:
        print(f"[ERROR] IDEA Decryption error: {e}")
        status_resp = build_status_response("REJECTED", f"IDEA decryption failed: {e}", False, False)
        send_frame(conn, status_resp)
        return False

    # Decode plaintext
    try:
        decrypted_text = decrypted_bytes.decode("utf-8")
        print("-" * 80)
        print(f"Decrypted Message:            {decrypted_text!r}")
    except UnicodeDecodeError:
        print("-" * 80)
        print(f"Decrypted Message (raw bytes): {decrypted_bytes!r} (non-UTF8)")

    # Step 6: Whirlpool Hashing
    recomputed_digest_bytes = whirlpool_bytes(decrypted_bytes)
    recomputed_hash_hex = whirlpool_hex(decrypted_bytes)

    print("\n" + "-" * 80)
    print("                         HASH CODE VERIFICATION")
    print("-" * 80)
    print(f"Received Hash Code:           {received_hash_hex}")
    print(f"Recomputed Hash Code:         {recomputed_hash_hex}")

    hash_matched = (received_hash_hex.lower() == recomputed_hash_hex.lower())
    print(f"Hash Match Result:            {'MATCHED (Integrity Preserved)' if hash_matched else 'MISMATCH (Tampered)'}")

    # Step 7: Digital Signature Verification
    print("\n" + "-" * 80)
    print("                     DIGITAL SIGNATURE VERIFICATION")
    print("-" * 80)
    m = int.from_bytes(recomputed_digest_bytes, "big") % (p - 1)
    lhs = (pow(client_pub, sig_r, p) * pow(sig_r, sig_s, p)) % p
    rhs = pow(g, m, p)

    print(f"Signature Components (r, s):")
    print(f"  r = {format_large_int(sig_r)}")
    print(f"  s = {format_large_int(sig_s)}")
    print(f"Verification Formula: (y^r * r^s) mod p == (g^m) mod p")
    print(f"  LHS = {format_large_int(lhs)}")
    print(f"  RHS = {format_large_int(rhs)}")

    sig_valid = (lhs == rhs and 1 <= sig_r <= p - 1)
    print(f"Digital Signature:            {'VALID' if sig_valid else 'INVALID'}")

    # Final Decision
    print("-" * 80)
    if sig_valid and hash_matched:
        print("Final Status:                 MESSAGE <ACCEPTED>")
        status_resp = build_status_response(
            status="ACCEPTED",
            detail="Signature is VALID and message digest MATCHES.",
            signature_valid=True,
            hash_matched=True
        )
        send_frame(conn, status_resp)
        print("=" * 80 + "\n")
        return True
    else:
        print("Final Status:                 MESSAGE <REJECTED>")
        reasons = []
        if not sig_valid:
            reasons.append("Invalid digital signature")
        if not hash_matched:
            reasons.append("Hash code mismatch")
        status_resp = build_status_response(
            status="REJECTED",
            detail="; ".join(reasons),
            signature_valid=sig_valid,
            hash_matched=hash_matched
        )
        send_frame(conn, status_resp)
        print("=" * 80 + "\n")
        return False


def run_server(
    host: str = "127.0.0.1",
    port: int = 9999,
    once: bool = False,
    verbose: bool = True
) -> None:
    """Run the Secrecy server listener."""
    p = RFC3526_MODP_2048_P
    g = RFC3526_MODP_2048_CUSTOM_FULL_ORDER_G
    validate_production_group(p, g)

    print("Generating ElGamal server keypair (2048-bit)...")
    server_pub, server_priv = elgamal_generate_keypair(p, g)
    print(f"Server ready. Public key: {format_large_int(server_pub)}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print(f"[SECRECY SERVER] Listening on {host}:{port} (once={once})...\n")

        while True:
            try:
                conn, addr = s.accept()
                print(f"[SECRECY SERVER] Incoming connection from {addr[0]}:{addr[1]}")
                with conn:
                    process_secure_session(
                        conn=conn,
                        p=p,
                        g=g,
                        server_priv=server_priv,
                        server_pub=server_pub,
                        verbose=verbose
                    )
            except KeyboardInterrupt:
                print("\n[SECRECY SERVER] Shutting down on user interrupt.")
                break
            except Exception as e:
                print(f"[SECRECY SERVER] Session error: {e}")

            if once:
                print("[SECRECY SERVER] Single-session complete (--once). Exiting.")
                break


def main():
    parser = argparse.ArgumentParser(
        description="Secrecy Secure Server — Author: Rishabh Srivastava (Roll No. 44285)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Port to bind (default: 9999)")
    parser.add_argument("--once", action="store_true", help="Handle one message and exit")
    parser.add_argument("--quiet", action="store_true", help="Suppress block-level round details")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, once=args.once, verbose=not args.quiet)


if __name__ == "__main__":
    main()
