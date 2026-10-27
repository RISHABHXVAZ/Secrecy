"""
Interactive end-to-end demonstration script for Secrecy.

Author: Rishabh Srivastava
Roll Number: 44285
Project: Secrecy

Runs a live local demonstration showing:
1. Normal secure transmission (Simplified IDEA CBC + ElGamal Key Exchange + ElGamal Signature + Whirlpool).
2. Tampering attack detection (Ciphertext alteration detected and rejected).
"""

import os
import subprocess
import sys
import time


def print_banner(title: str):
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80 + "\n")


def run_demo():
    print_banner("SECRECY LIVE DEMONSTRATION — Author: Rishabh Srivastava (Roll No: 44285)")
    print("Project: Secure Client-Server Message Exchange")
    print("Algorithms: Simplified IDEA, ElGamal Key Exchange, ElGamal Digital Signatures, Whirlpool")
    print("-" * 80)

    demo_port = 9888
    demo_msg = "Confidential Assignment: Cryptosystem Implementation — Rishabh Srivastava (44285)"
    demo_key = "0xDC6F3F59"

    print("\n[SCENARIO 1] Executing Normal Secure Message Exchange (Authentic & Valid)...")
    time.sleep(1.0)

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    # Start server in single-shot mode
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "secrecy.server", "--port", str(demo_port), "--once"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        env=env
    )
    time.sleep(0.8)

    # Run client
    client_res = subprocess.run(
        [
            sys.executable, "-m", "secrecy.client",
            "--port", str(demo_port),
            "--message", demo_msg,
            "--key", demo_key
        ],
        text=True,
        encoding="utf-8",
        env=env
    )

    server_stdout, _ = server_proc.communicate(timeout=10.0)

    print("\n--- SERVER TERMINAL LOGS ---")
    print(server_stdout)

    print_banner("[SCENARIO 2] Attack Simulation: Tampering with Ciphertext in Transit...")
    time.sleep(1.0)

    attack_port = 9889
    server_attack_proc = subprocess.Popen(
        [sys.executable, "-m", "secrecy.server", "--port", str(attack_port), "--once"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        env=env
    )
    time.sleep(0.8)

    client_attack_res = subprocess.run(
        [
            sys.executable, "-m", "secrecy.client",
            "--port", str(attack_port),
            "--message", demo_msg,
            "--key", demo_key,
            "--tamper-cipher"
        ],
        text=True,
        encoding="utf-8",
        env=env
    )

    server_attack_stdout, _ = server_attack_proc.communicate(timeout=10.0)

    print("\n--- SERVER TERMINAL LOGS (ATTACK REJECTION) ---")
    print(server_attack_stdout)

    print_banner("DEMONSTRATION COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    run_demo()
