import socket

import pytest

from net_utils import (
    decrypt_text,
    encrypt_text,
    parse_port,
    recv_packet,
    resolve_host,
    send_packet,
    validate_client_name,
    validate_port_arg,
    validate_timeout,
)


def test_parse_port_valid():
    assert parse_port("1") == 1
    assert parse_port("65535") == 65535
    assert parse_port(" 8080 ") == 8080


def test_parse_port_invalid():
    assert parse_port("0") is None
    assert parse_port("65536") is None
    assert parse_port("abc") is None


def test_resolve_host_valid_local():
    assert resolve_host("127.0.0.1") == "127.0.0.1"
    assert resolve_host("localhost") == "localhost"


def test_resolve_host_invalid():
    assert resolve_host("") is None
    assert resolve_host("invalid_host_###") is None


def test_validate_port_arg():
    assert validate_port_arg(80) == 80
    with pytest.raises(ValueError):
        validate_port_arg(0)


def test_validate_timeout():
    assert validate_timeout(0.0) == 0.0
    assert validate_timeout(2.5) == 2.5
    with pytest.raises(ValueError):
        validate_timeout(-1)


def test_validate_client_name_valid():
    assert validate_client_name("Sagar") == "Sagar"
    assert validate_client_name("  Alice  ") == "Alice"


def test_validate_client_name_invalid():
    with pytest.raises(ValueError):
        validate_client_name("")
    with pytest.raises(ValueError):
        validate_client_name(" " * 5)
    with pytest.raises(ValueError):
        validate_client_name("x" * 25)


def test_encrypt_decrypt_roundtrip():
    plain = "hello secure world"
    password = "super-secret"
    encrypted = encrypt_text(plain, password)
    assert encrypted != plain
    assert decrypt_text(encrypted, password) == plain


def test_decrypt_with_wrong_password_fails():
    encrypted = encrypt_text("message", "good-password")
    with pytest.raises(ValueError):
        decrypt_text(encrypted, "bad-password")


def test_send_and_receive_packet():
    server, client = socket.socketpair()
    try:
        send_packet(server, {"type": "hello", "secure": False})
        packet = recv_packet(client, bytearray())
        assert packet == {"type": "hello", "secure": False}
    finally:
        server.close()
        client.close()


def test_recv_packet_rejects_invalid_json():
    server, client = socket.socketpair()
    try:
        server.sendall(b"not-json\n")
        with pytest.raises(ValueError):
            recv_packet(client, bytearray())
    finally:
        server.close()
        client.close()
