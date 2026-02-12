import argparse
import socket
import ssl
import sys
import threading

from net_utils import (
    add_common_args,
    prompt_for_port,
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
    add_common_args(parser)
    return parser.parse_args()


def wrap_tls_server(conn: socket.socket, cert: str, key: str) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context.wrap_socket(conn, server_side=True)


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

    if args.tls and (not args.cert or not args.key):
        print("TLS enabled but --cert/--key not provided.")
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if timeout > 0:
        sock.settimeout(timeout)
    sock.bind((args.bind, port))
    sock.listen(1)
    print(f"Listening on {args.bind or '127.0.0.1'}:{port}... (Ctrl-C to stop)")

    try:
        conn, addr = sock.accept()
    except socket.timeout:
        print("No incoming connection before timeout.")
        sock.close()
        return 1
    except KeyboardInterrupt:
        print("\nServer stopped.")
        sock.close()
        return 0

    print(f"Connection from {addr[0]}:{addr[1]}")

    if args.tls:
        try:
            conn = wrap_tls_server(conn, args.cert, args.key)
        except Exception as exc:
            print(f"TLS handshake failed: {exc}")
            conn.close()
            sock.close()
            return 1

    stop_event = threading.Event()

    def recv_loop() -> None:
        try:
            while not stop_event.is_set():
                data = conn.recv(4096)
                if not data:
                    print("\nConnection closed by remote host.")
                    stop_event.set()
                    break
                sys.stdout.write(data.decode(errors="replace"))
                sys.stdout.flush()
        except Exception as exc:
            if not stop_event.is_set():
                print(f"\nReceive error: {exc}")
                stop_event.set()

    def send_loop() -> None:
        try:
            while not stop_event.is_set():
                line = sys.stdin.readline()
                if not line:
                    stop_event.set()
                    break
                conn.sendall(line.encode())
        except Exception as exc:
            if not stop_event.is_set():
                print(f"\nSend error: {exc}")
                stop_event.set()

    recv_thread = threading.Thread(target=recv_loop, daemon=True)
    send_thread = threading.Thread(target=send_loop, daemon=True)
    recv_thread.start()
    send_thread.start()
    try:
        # Join in a loop with timeout so KeyboardInterrupt can be processed
        while recv_thread.is_alive() or send_thread.is_alive():
            recv_thread.join(timeout=0.5)
            send_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nInterrupted, shutting down.\n")
        stop_event.set()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
