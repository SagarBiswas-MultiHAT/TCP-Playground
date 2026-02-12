import argparse
import socket
import ssl
import threading
from typing import Dict, Optional, Tuple

from net_utils import (
    add_common_args,
    decrypt_text,
    encrypt_text,
    prompt_for_host,
    prompt_password,
    prompt_for_port,
    recv_packet,
    resolve_host,
    send_packet,
    validate_port_arg,
    validate_timeout,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP client.")
    parser.add_argument(
        "--host",
        type=str,
        help="Server IP/hostname. If omitted, prompts interactively.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password for secure mode. If omitted and required, prompts interactively.",
    )
    add_common_args(parser)
    return parser.parse_args()


def wrap_tls_client(sock: socket.socket, host: str, insecure: bool) -> ssl.SSLSocket:
    if insecure:
        context = ssl._create_unverified_context()
        return context.wrap_socket(sock, server_hostname=host)
    context = ssl.create_default_context()
    return context.wrap_socket(sock, server_hostname=host)


def connect_socket(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if timeout > 0:
        sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def connect_and_handshake(
    host: str,
    port: int,
    timeout: float,
    force_tls: bool,
    tls_insecure: bool,
) -> Tuple[socket.socket, Dict[str, object], bool, bytearray]:
    attempts = [True] if force_tls else [False, True]
    last_error: Optional[Exception] = None

    for use_tls in attempts:
        sock: Optional[socket.socket] = None
        try:
            sock = connect_socket(host, port, timeout)
            if use_tls:
                sock = wrap_tls_client(sock, host, tls_insecure)
            buffer = bytearray()
            hello = recv_packet(sock, buffer)
            if hello is None or hello.get("type") != "hello":
                raise ValueError("Server did not send a valid handshake packet.")
            return sock, hello, use_tls, buffer
        except Exception as exc:
            last_error = exc
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    raise RuntimeError(f"Could not connect to {host}:{port} — {last_error}")


def main() -> int:
    args = parse_args()
    try:
        port = validate_port_arg(args.port)
        timeout = validate_timeout(args.timeout)
    except ValueError as exc:
        print(str(exc))
        return 1

    host = None
    if args.host:
        host = resolve_host(args.host)
        if host is None:
            print("Invalid host or IP address.")
            return 1
    else:
        try:
            host = prompt_for_host("Enter the IP address of the server: ")
        except ValueError as exc:
            print(str(exc))
            return 1

    if port is None:
        try:
            port = prompt_for_port("Enter the port you want to connect to: ")
        except ValueError as exc:
            print(str(exc))
            return 1

    try:
        sock, hello_packet, using_tls, buffer = connect_and_handshake(
            host=host,
            port=port,
            timeout=timeout,
            force_tls=args.tls,
            tls_insecure=args.tls_insecure,
        )
    except Exception as exc:
        print(str(exc))
        return 1

    secure_mode = bool(hello_packet.get("secure", False))
    session_password: Optional[str] = None

    if secure_mode:
        if not using_tls:
            print("Server requires secure mode over TLS, but TLS is not active.")
            sock.close()
            return 1
        session_password = args.password
        if not session_password:
            try:
                session_password = prompt_password("Enter password: ")
            except ValueError as exc:
                print(str(exc))
                sock.close()
                return 1
        send_packet(sock, {"type": "auth", "password": session_password})
        auth_packet = recv_packet(sock, buffer)
        if auth_packet is None or auth_packet.get("type") != "auth_result":
            print("Authentication failed: no valid server response.")
            sock.close()
            return 1
        if not bool(auth_packet.get("ok", False)):
            print(f"Authentication failed: {auth_packet.get('reason', 'Unknown error.')}")
            sock.close()
            return 1
        client_name = str(auth_packet.get("client_name", "unknown"))
        print(f"Authenticated as {client_name}")
    else:
        auth_packet = recv_packet(sock, buffer)
        if auth_packet is None or auth_packet.get("type") != "auth_result" or not bool(auth_packet.get("ok", False)):
            print("Connection rejected by server.")
            sock.close()
            return 1
        client_name = str(auth_packet.get("client_name", "unknown"))

    print(f"Connected to {host}:{port}")

    stop_event = threading.Event()

    def decode_packet_text(packet: Dict[str, object]) -> str:
        is_encrypted = bool(packet.get("encrypted", False))
        if not is_encrypted:
            return str(packet.get("text", ""))
        payload = packet.get("payload")
        if not isinstance(payload, str):
            return "[Invalid encrypted payload]"
        if not session_password:
            return "[Encrypted message received but no password is available]"
        try:
            return decrypt_text(payload, session_password)
        except ValueError:
            return "[Could not decrypt message]"

    def recv_loop() -> None:
        try:
            while not stop_event.is_set():
                packet = recv_packet(sock, buffer)
                if packet is None:
                    print("\nConnection closed by remote host.")
                    stop_event.set()
                    break

                packet_type = str(packet.get("type", ""))
                if packet_type == "count":
                    print(f"+ Total connected clints: [{packet.get('total', '?')}]")
                    continue

                if packet_type == "chat":
                    sender = str(packet.get("from", "unknown"))
                    text = decode_packet_text(packet)
                    print(f"{sender}: {text}")
                    continue

                if packet_type == "system":
                    text = decode_packet_text(packet)
                    print(text)
                    continue
        except Exception as exc:
            if not stop_event.is_set():
                print(f"\nReceive error: {exc}")
                stop_event.set()

    def send_loop() -> None:
        try:
            while not stop_event.is_set():
                line = input()
                if not line:
                    continue
                packet: Dict[str, object] = {"type": "chat", "encrypted": secure_mode}
                if secure_mode:
                    packet["payload"] = encrypt_text(line, session_password or "")
                else:
                    packet["text"] = line
                send_packet(sock, packet)
        except Exception as exc:
            if not stop_event.is_set():
                print(f"\nSend error: {exc}")
                stop_event.set()

    recv_thread = threading.Thread(target=recv_loop, daemon=True)
    send_thread = threading.Thread(target=send_loop, daemon=True)
    recv_thread.start()
    send_thread.start()
    try:
        while recv_thread.is_alive() or send_thread.is_alive():
            recv_thread.join(timeout=0.5)
            send_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nInterrupted, shutting down.\n")
        stop_event.set()
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
