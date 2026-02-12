# Network Communication Scripts

A practical TCP chat playground in pure Python with:

- multi-client support
- optional secure mode (TLS + password-based message encryption)
- interactive CLI prompts for quick local testing
- lightweight unit tests and GitHub Actions CI

The client filename is intentionally `clint.py`.

---

## What this project does

This repository contains two runnable scripts:

- `host.py` — starts the chat server and accepts multiple clients.
- `clint.py` — connects a client to the server and joins the chat.

It is designed for learning, demos, and LAN experiments. The code is intentionally straightforward so you can understand and extend it quickly.

---

## Feature overview

- **Multiple clients** can connect to one host at the same time.
- **Broadcast chat**: each message is delivered to all connected clients.
- **Join/leave events** are announced in real time.
- **Live connected count** is shown as clients join/leave.
- **Secure mode** (optional):
  - TLS transport
  - password authentication at connect time
  - password-based message encryption on top of TLS
- **Smart client prompt**: client asks for password only when server says secure mode is enabled.

---

## Requirements

- Python 3.9+
- `pip`

Runtime dependencies are from the standard library. Test dependency is listed in `requirements.txt`.

Install test tools:

```powershell
pip install -r requirements.txt
```

---

## Quick start (interactive)

Open one terminal for host and one or more terminals for clients.

### 1) Start host

```powershell
python -u host.py
```

Example:

```text
Enter the port you want to listen on: 12345
Encrypt the communication? [y/N]: y
Set password:
Listening on 127.0.0.1:12345... (Ctrl-C to stop)
Security mode: ENCRYPTED
```

### 2) Start first client

```powershell
python -u clint.py
```

Example:

```text
Enter the IP address of the server: 127.0.0.1
Enter the port you want to connect to: 12345
Enter password:
Authenticated as clint1
Connected to 127.0.0.1:12345
```

### 3) Start more clients

Run `python -u clint.py` again in additional terminals. Each one gets a unique name (`clint2`, `clint3`, ...), receives join/leave updates, and participates in the same room.

---

## Command-line usage

### Host

```powershell
python -u host.py --bind 0.0.0.0 --port 12345 --timeout 0
```

Common host options:

- `--bind` bind address (default empty = all interfaces)
- `--port` port number
- `--timeout` socket timeout in seconds (0 = blocking)
- `--secure` force secure mode without prompt
- `--password` secure mode password (if omitted, host prompts)
- `--tls --cert --key` explicit TLS config

> Note: if secure mode is enabled, host enforces TLS.

### Client

```powershell
python -u clint.py --host 127.0.0.1 --port 12345
```

Common client options:

- `--host` server host/IP
- `--port` server port
- `--timeout` socket timeout
- `--password` pre-supply secure password (optional)
- `--tls` force TLS connection attempt first
- `--tls-insecure` disable certificate verification for local/self-signed testing

---

## Security model

When secure mode is ON:

1. Server uses TLS for transport.
2. Client receives handshake metadata and knows secure mode is required.
3. Client prompts for password only in this case.
4. Server validates password before admitting the client.
5. Chat messages are additionally encrypted at the application layer.

When secure mode is OFF:

- no password prompt
- plaintext application messages
- regular TCP transport unless you explicitly use TLS flags

### Generate a self-signed certificate (local testing)

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365
```

Then run host with:

```powershell
python -u host.py --port 12345 --secure --password mypass --tls --cert cert.pem --key key.pem
```

And run client with:

```powershell
python -u clint.py --host 127.0.0.1 --port 12345 --tls --tls-insecure
```

---

## Typical terminal experience

Host side (example):

```text
Connection from 127.0.0.1:49207
clint1 joined from 127.0.0.1:49207
+ Total connected clints: [1]
Connection from 127.0.0.1:49222
clint2 joined from 127.0.0.1:49222
+ Total connected clints: [2]
clint1: hello everyone
clint2: hi!
```

Client side (example):

```text
Connected to 127.0.0.1:12345
clint1 joined from 127.0.0.1:49207
+ Total connected clints: [1]
clint2 joined from 127.0.0.1:49222
+ Total connected clints: [2]
clint1: hello everyone
```

---

## Tests

Run all tests:

```powershell
pytest -q
```

Current tests focus on utility and protocol helpers in `net_utils.py`:

- input validation (port/timeout/host)
- encryption/decryption behavior
- protocol packet framing and parsing

---

## GitHub Actions CI

Workflow file: `.github/workflows/python-ci.yml`

It runs on push and pull request across Python `3.9`, `3.10`, `3.11`, and `3.12`, then executes `pytest -q`.

If CI fails, start with:

```powershell
pip install -r requirements.txt
pytest -q
```

---

## Project structure

```text
host.py          # Multi-client server
clint.py         # Interactive client
net_utils.py     # Shared validation, protocol, encryption helpers
tests/           # Unit tests
```

---

## Troubleshooting

- **Connection refused**: host is not running, wrong host/port, or firewall blocked.
- **TLS handshake failed**: certificate/key mismatch or client verification settings.
- **Authentication failed**: wrong secure-mode password.
- **No password prompt on client**: server is in plaintext mode.
- **Password prompt appears unexpectedly**: server is running secure mode on that port.

---

## Notes for contributors

- Keep changes small and testable.
- Prefer extending `net_utils.py` for shared protocol logic.
- Add/adjust tests for behavior changes before merging.

Contributions and improvements are welcome.
