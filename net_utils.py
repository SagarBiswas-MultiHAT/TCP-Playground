import argparse
import base64
import getpass
import hashlib
import json
import ipaddress
import os
import socket
from typing import Dict, Optional, Tuple


def parse_port(value: str) -> Optional[int]:
    try:
        port = int(value.strip())
        if 1 <= port <= 65535:
            return port
    except Exception:
        pass
    return None


def resolve_host(value: str) -> Optional[str]:
    host = value.strip()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            socket.getaddrinfo(host, None)
            return host
        except Exception:
            return None


def prompt_for_port(prompt: str) -> int:
    port_str = input(prompt)
    port = parse_port(port_str)
    if port is None:
        raise ValueError("Invalid port number. Please enter a number between 1 and 65535.")
    return port


def prompt_for_host(prompt: str) -> str:
    host = input(prompt).strip()
    resolved = resolve_host(host)
    if resolved is None:
        raise ValueError("Invalid host or IP address.")
    return resolved


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--port",
        type=int,
        help="TCP port (1-65535). If omitted, prompts interactively.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.0,
        help="Socket timeout in seconds (0 = blocking).",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Enable TLS. Requires --cert and --key.",
    )
    parser.add_argument("--cert", type=str, help="Path to TLS certificate (PEM).")
    parser.add_argument("--key", type=str, help="Path to TLS private key (PEM).")
    parser.add_argument(
        "--tls-insecure",
        action="store_true",
        help="Disable TLS certificate verification (use only for local testing).",
    )


def validate_port_arg(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if 1 <= value <= 65535:
        return value
    raise ValueError("Invalid port number. Please enter a number between 1 and 65535.")


def validate_timeout(value: float) -> float:
    if value < 0:
        raise ValueError("Timeout must be >= 0.")
    return value


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    raw = input(f"{prompt} {suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def prompt_password(prompt: str) -> str:
    password = getpass.getpass(prompt)
    if not password:
        raise ValueError("Password cannot be empty.")
    return password


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _derive_keys(password: str, salt: bytes = b"network-communication-scripts-v1") -> Tuple[bytes, bytes]:
    key_material = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=64)
    return key_material[:32], key_material[32:]


def encrypt_text(plain_text: str, password: str) -> str:
    plain = plain_text.encode("utf-8")
    nonce = os.urandom(16)
    enc_key, mac_key = _derive_keys(password)
    stream = _keystream(enc_key, nonce, len(plain))
    cipher = bytes(a ^ b for a, b in zip(plain, stream))
    tag = hashlib.sha256(mac_key + nonce + cipher).digest()[:16]
    payload = nonce + tag + cipher
    return base64.b64encode(payload).decode("ascii")


def decrypt_text(encoded_payload: str, password: str) -> str:
    try:
        payload = base64.b64decode(encoded_payload.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("Invalid encrypted payload.") from exc

    if len(payload) < 32:
        raise ValueError("Encrypted payload too short.")

    nonce = payload[:16]
    tag = payload[16:32]
    cipher = payload[32:]
    enc_key, mac_key = _derive_keys(password)
    expected_tag = hashlib.sha256(mac_key + nonce + cipher).digest()[:16]
    if tag != expected_tag:
        raise ValueError("Failed to decrypt message. Check password.")

    stream = _keystream(enc_key, nonce, len(cipher))
    plain = bytes(a ^ b for a, b in zip(cipher, stream))

    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Failed to decrypt message. Check password.") from exc


def send_packet(sock: socket.socket, packet: Dict[str, object]) -> None:
    data = (json.dumps(packet, separators=(",", ":")) + "\n").encode("utf-8")
    sock.sendall(data)


def recv_packet(sock: socket.socket, buffer: bytearray, max_packet_size: int = 1_000_000) -> Optional[Dict[str, object]]:
    while True:
        nl = buffer.find(b"\n")
        if nl != -1:
            line = bytes(buffer[:nl])
            del buffer[: nl + 1]
            if not line.strip():
                continue
            try:
                packet = json.loads(line.decode("utf-8"))
            except Exception:
                raise ValueError("Invalid protocol packet.")
            if not isinstance(packet, dict):
                raise ValueError("Protocol packet must be an object.")
            return packet

        chunk = sock.recv(4096)
        if not chunk:
            return None
        buffer.extend(chunk)
        if len(buffer) > max_packet_size:
            raise ValueError("Protocol buffer exceeded limit.")
