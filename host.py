import argparse
import hmac
import socket
import ssl
import sys
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional

from net_utils import (
    add_common_args,
    decrypt_text,
    encrypt_text,
    validate_client_name,
    prompt_for_port,
    prompt_password,
    prompt_yes_no,
    recv_packet,
    send_packet,
    validate_port_arg,
    validate_timeout,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP server.")
    parser.add_argument(
        "--bind",
        type=str,
        default="",
        help="Bind address (default: all interfaces).",
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Enable password-protected encrypted chat mode.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password for secure mode (if omitted, prompt interactively).",
    )
    add_common_args(parser)
    return parser.parse_args()


def wrap_tls_server(conn: socket.socket, cert: str, key: str) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context.wrap_socket(conn, server_side=True)


@dataclass
class ClientSession:
    conn: socket.socket
    addr: tuple
    name: str
    buffer: bytearray = field(default_factory=bytearray)
    send_lock: threading.Lock = field(default_factory=threading.Lock)


def main() -> int:
    args = parse_args()
    try:
        port = validate_port_arg(args.port)
        timeout = validate_timeout(args.timeout)
    except ValueError as exc:
        print(str(exc))
        return 1

    if port is None:
        try:
            port = prompt_for_port("Enter the port you want to listen on: ")
        except ValueError as exc:
            print(str(exc))
            return 1

    secure_mode = args.secure
    if not args.secure:
        secure_mode = prompt_yes_no("Encrypt the communication?", default=False)

    secure_password: Optional[str] = None
    if secure_mode:
        secure_password = args.password
        if not secure_password:
            try:
                secure_password = prompt_password("Set password: ")
            except ValueError as exc:
                print(str(exc))
                return 1
        args.tls = True

    if args.tls and (not args.cert or not args.key):
        print("TLS enabled but --cert/--key not provided.")
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if timeout > 0:
        sock.settimeout(timeout)
    sock.bind((args.bind, port))
    sock.listen(128)
    sock.settimeout(0.5)
    print(f"\nListening on {args.bind or '127.0.0.1'}:{port}... (Ctrl-C to stop)")
    print(f"Security mode: {'ENCRYPTED' if secure_mode else 'PLAINTEXT'}")
    stop_event = threading.Event()
    clients: Dict[str, ClientSession] = {}
    clients_lock = threading.Lock()

    def send_threadsafe(client: ClientSession, packet: Dict[str, object]) -> None:
        with client.send_lock:
            send_packet(client.conn, packet)

    def build_text_payload(
        message_type: str,
        text: str,
        sender: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Dict[str, object]:
        packet: Dict[str, object] = {"type": message_type, "encrypted": secure_mode}
        if sender is not None:
            packet["from"] = sender
        if port is not None:
            packet["port"] = port
        if secure_mode:
            packet["payload"] = encrypt_text(text, secure_password or "")
        else:
            packet["text"] = text
        return packet

    def remove_client(name: str) -> Optional[ClientSession]:
        with clients_lock:
            return clients.pop(name, None)

    def snapshot_clients() -> Dict[str, ClientSession]:
        with clients_lock:
            return dict(clients)

    def broadcast(packet: Dict[str, object]) -> None:
        stale = []
        for name, client in snapshot_clients().items():
            try:
                send_threadsafe(client, packet)
            except Exception:
                stale.append(name)
        for name in stale:
            removed = remove_client(name)
            if removed is not None:
                try:
                    removed.conn.close()
                except Exception:
                    pass

    def publish_count() -> None:
        with clients_lock:
            total = len(clients)
        print(f"+ Total connected clints: [{total}]\n")
        broadcast({"type": "count", "total": total})

    def announce_system(message: str) -> None:
        print(message)
        broadcast(build_text_payload("system", message))

    def handle_client(client: ClientSession) -> None:
        try:
            while not stop_event.is_set():
                packet = recv_packet(client.conn, client.buffer)
                if packet is None:
                    break
                if packet.get("type") != "chat":
                    continue

                try:
                    if secure_mode:
                        encrypted_payload = packet.get("payload")
                        if not isinstance(encrypted_payload, str):
                            raise ValueError("Missing encrypted payload.")
                        text = decrypt_text(encrypted_payload, secure_password or "")
                    else:
                        text = str(packet.get("text", ""))
                except ValueError:
                    send_threadsafe(client, build_text_payload("system", "Could not decrypt your message."))
                    continue

                if not text.strip():
                    continue

                message = text.rstrip("\r\n")
                print(f"..:: {client.name}[{client.addr[1]}]: {message}")
                broadcast(
                    build_text_payload("chat", message, sender=client.name, port=client.addr[1])
                )
        except Exception as exc:
            if not stop_event.is_set():
                print(f"\nReceive error from {client.name}: {exc}")
        finally:
            removed = remove_client(client.name)
            if removed is not None:
                try:
                    removed.conn.close()
                except Exception:
                    pass
                announce_system(f"\n{client.name} disconnected.\n")
                publish_count()

    def accept_loop() -> None:
        while not stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as exc:
                if not stop_event.is_set():
                    print(f"Accept error: {exc}")
                continue

            print(f"\nConnection from {addr[0]}:{addr[1]}")

            if args.tls:
                try:
                    conn = wrap_tls_server(conn, args.cert, args.key)
                except Exception as exc:
                    print(f"TLS handshake failed: {exc}")
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue

            buffer = bytearray()
            try:
                send_packet(conn, {"type": "hello", "secure": secure_mode})

                if secure_mode:
                    auth_packet = recv_packet(conn, buffer)
                    if auth_packet is None:
                        conn.close()
                        continue
                    if auth_packet.get("type") != "auth":
                        send_packet(conn, {"type": "auth_result", "ok": False, "reason": "Authentication required."})
                        conn.close()
                        continue
                    client_password = str(auth_packet.get("password", ""))
                    if not hmac.compare_digest(client_password, secure_password or ""):
                        send_packet(conn, {"type": "auth_result", "ok": False, "reason": "Wrong password."})
                        conn.close()
                        continue
                else:
                    auth_packet = recv_packet(conn, buffer)
                    if auth_packet is None:
                        conn.close()
                        continue
                    if auth_packet.get("type") != "auth":
                        send_packet(conn, {"type": "auth_result", "ok": False, "reason": "Authentication required."})
                        conn.close()
                        continue

                try:
                    requested_name = validate_client_name(str(auth_packet.get("name", "")))
                except ValueError:
                    send_packet(conn, {"type": "auth_result", "ok": False, "reason": "Invalid name."})
                    conn.close()
                    continue

                with clients_lock:
                    existing = set(clients.keys())
                    if requested_name not in existing:
                        client_name = requested_name
                    else:
                        suffix = 2
                        while True:
                            candidate = f"{requested_name}-{suffix}"
                            if candidate not in existing:
                                client_name = candidate
                                break
                            suffix += 1
                    client = ClientSession(conn=conn, addr=addr, name=client_name, buffer=buffer)
                    clients[client_name] = client

                send_threadsafe(client, {"type": "auth_result", "ok": True, "client_name": client_name})
                announce_system(f"\n{client_name} joined from {addr[0]}:{addr[1]}")
                publish_count()
                threading.Thread(target=handle_client, args=(client,), daemon=True).start()
            except Exception as exc:
                print(f"Handshake failed: {exc}")
                try:
                    conn.close()
                except Exception:
                    pass

    def send_loop() -> None:
        try:
            while not stop_event.is_set():
                line = sys.stdin.readline()
                if not line:
                    stop_event.set()
                    break
                message = line.rstrip("\r\n")
                if not message:
                    continue
                print(f"..:: server: {message}")
                broadcast(build_text_payload("chat", message, sender="server"))
        except Exception as exc:
            if not stop_event.is_set():
                print(f"Send error: {exc}")
                stop_event.set()

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    send_thread = threading.Thread(target=send_loop, daemon=True)
    accept_thread.start()
    send_thread.start()

    try:
        while accept_thread.is_alive() or send_thread.is_alive():
            accept_thread.join(timeout=0.5)
            send_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nInterrupted, shutting down.\n")
        stop_event.set()
    finally:
        for client in snapshot_clients().values():
            try:
                client.conn.close()
            except Exception:
                pass
        try:
            sock.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
