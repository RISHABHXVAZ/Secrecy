"""
Script to capture authentic client-server execution outputs and generate
high-resolution terminal screenshots.

Author: Rishabh Srivastava
Roll Number: 44285
Project: Secrecy
"""

import io
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PIL import Image, ImageDraw, ImageFont

from secrecy.client import send_secure_message
from secrecy.server import run_server


def capture_execution(
    message: str,
    idea_key: int,
    port: int,
    tamper_cipher: bool = False,
    tamper_sig: bool = False,
    verbose: bool = True
) -> tuple[str, str]:
    """
    Run server and client as independent subprocesses, capturing their
    isolated, authentic standard outputs.
    """
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    # Start server process
    server_cmd = [
        sys.executable,
        "-m", "secrecy.server",
        "--port", str(port),
        "--once"
    ]
    if not verbose:
        server_cmd.append("--quiet")

    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        env=env
    )

    # Wait for server to initialize and bind
    time.sleep(1.0)

    # Run client process
    client_cmd = [
        sys.executable,
        "-m", "secrecy.client",
        "--port", str(port),
        "--message", message,
        "--key", f"0x{idea_key:08X}"
    ]
    if not verbose:
        client_cmd.append("--quiet")
    if tamper_cipher:
        client_cmd.append("--tamper-cipher")
    if tamper_sig:
        client_cmd.append("--tamper-sig")

    client_res = subprocess.run(
        client_cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        env=env
    )

    server_stdout, _ = server_proc.communicate(timeout=10.0)
    client_stdout = client_res.stdout + (f"\n[STDERR]: {client_res.stderr}" if client_res.stderr else "")

    return client_stdout, server_stdout


def render_terminal_screenshot(
    text: str,
    title: str,
    output_png_path: str,
    max_lines: int = 65
) -> None:
    """
    Render genuine terminal output text into a crisp, high-resolution PNG image
    styled like a modern developer terminal window (Windows Terminal / VS Code dark).
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_png_path)), exist_ok=True)

    lines = text.strip().split("\n")
    if len(lines) > max_lines:
        # Keep head and tail with a break marker
        half = max_lines // 2
        lines = lines[:half] + ["", "  ... [Intermediate blocks omitted for visual brevity] ...", ""] + lines[-half:]

    # Try to load high quality monospace fonts
    font = None
    font_size = 14
    for font_name in [
        "consola.ttf", "consolas.ttf", "cour.ttf", "courier.ttf", "arial.ttf"
    ]:
        try:
            font = ImageFont.truetype(font_name, font_size)
            break
        except Exception:
            pass

    if font is None:
        font = ImageFont.load_default()

    # Calculate dimensions
    char_width = 8.5
    char_height = 20
    max_col = max(len(l) for l in lines) if lines else 80
    max_col = max(max_col, 80)

    padding_x = 24
    padding_top = 44  # For terminal window header
    padding_bottom = 24

    img_width = int(max_col * char_width) + padding_x * 2
    img_height = int(len(lines) * char_height) + padding_top + padding_bottom

    # Colors (Dark terminal theme)
    bg_color = (18, 22, 28)
    header_color = (28, 33, 40)
    border_color = (48, 54, 61)
    text_color = (220, 225, 230)
    accent_green = (86, 211, 100)
    accent_cyan = (100, 210, 255)
    accent_yellow = (240, 200, 80)
    accent_red = (255, 100, 100)

    img = Image.new("RGB", (img_width, img_height), bg_color)
    draw = ImageDraw.Draw(img)

    # Header bar
    draw.rectangle([(0, 0), (img_width, padding_top - 6)], fill=header_color)
    draw.line([(0, padding_top - 6), (img_width, padding_top - 6)], fill=border_color, width=1)

    # Terminal buttons (Close, Minimize, Maximize)
    draw.ellipse([(16, 12), (28, 24)], fill=(255, 95, 86))
    draw.ellipse([(36, 12), (48, 24)], fill=(255, 189, 46))
    draw.ellipse([(56, 12), (68, 24)], fill=(39, 201, 63))

    # Title text
    draw.text((85, 10), title, fill=(160, 170, 180), font=font)

    # Render lines
    y = padding_top
    for line in lines:
        color = text_color
        if "====" in line or "----" in line:
            color = (80, 90, 105)
        elif "SECRECY" in line or "Author:" in line:
            color = accent_cyan
        elif "<ACCEPTED>" in line or "VALID" in line or "MATCHED" in line:
            color = accent_green
        elif "<REJECTED>" in line or "INVALID" in line or "MISMATCH" in line or "ATTACK" in line:
            color = accent_red
        elif "Round" in line or "Block" in line:
            color = accent_yellow

        draw.text((padding_x, y), line, fill=color, font=font)
        y += char_height

    img.save(output_png_path, "PNG", optimize=True)
    print(f"[SCREENSHOT] Generated: {output_png_path} ({img_width}x{img_height})")


def main():
    print("=== Generating Authentic Terminal Outputs & Screenshots ===")
    os.makedirs("docs", exist_ok=True)
    os.makedirs("docs/screenshots", exist_ok=True)
    test_msg = "Confidential Assignment: Cryptosystem Implementation — Rishabh Srivastava (44285)"
    test_key = 0xDC6F3F59

    # 1. Normal Authentic Run
    client_out, server_out = capture_execution(
        message=test_msg,
        idea_key=test_key,
        port=9991,
        verbose=True
    )

    # Save raw authentic text logs
    with open("docs/demo_client_output.txt", "w", encoding="utf-8") as f:
        f.write(client_out)
    with open("docs/demo_server_output.txt", "w", encoding="utf-8") as f:
        f.write(server_out)

    render_terminal_screenshot(
        text=client_out,
        title="Secrecy Client — Secure Sender Terminal (Author: Rishabh Srivastava | Roll No: 44285)",
        output_png_path="docs/screenshots/client_execution.png",
        max_lines=60
    )

    render_terminal_screenshot(
        text=server_out,
        title="Secrecy Server — Verification Receiver Terminal (Author: Rishabh Srivastava | Roll No: 44285)",
        output_png_path="docs/screenshots/server_execution.png",
        max_lines=60
    )

    # 2. Attack Simulation Run (Tampered Ciphertext)
    attack_client_out, attack_server_out = capture_execution(
        message=test_msg,
        idea_key=test_key,
        port=9992,
        tamper_cipher=True,
        verbose=False
    )

    attack_combined = f"--- CLIENT PERSPECTIVE ---\n{attack_client_out}\n\n--- SERVER PERSPECTIVE ---\n{attack_server_out}"
    render_terminal_screenshot(
        text=attack_combined,
        title="Secrecy Attack Simulation — Ciphertext Tampering & Cryptographic Rejection",
        output_png_path="docs/screenshots/attack_rejection.png",
        max_lines=50
    )

    print("\nAll terminal screenshots successfully created in docs/screenshots/")


if __name__ == "__main__":
    main()
