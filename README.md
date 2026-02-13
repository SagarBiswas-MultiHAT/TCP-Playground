# Network Communication Scripts

<div align="right">

![CI](https://github.com/SagarBiswas-MultiHAT/TCP-Playground/actions/workflows/python-ci.yml/badge.svg) 
&nbsp;
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
&nbsp; 
![License](https://img.shields.io/badge/license-MIT-green) 
&nbsp;
![Last commit](https://img.shields.io/github/last-commit/SagarBiswas-MultiHAT/TCP-Playground) 
&nbsp;
![Issues](https://img.shields.io/github/issues/SagarBiswas-MultiHAT/TCP-Playground)

</div>

A simple multi-client TCP chat app in Python, built for learning and practical local/LAN testing.


![ckecking](pics/image.png)

This project gives you:
- a server (`host.py`)
- a client (`clint.py`)
- optional secure mode (TLS + password-protected encrypted messages)
- real user names (clients now choose their own names)
- unit tests + GitHub Actions CI

> Note: the client file is intentionally named `clint.py`.

---

## Table of contents

- [What this project does](#what-this-project-does)
- [Features](#features)
- [How secure mode works](#how-secure-mode-works)
- [Quick start (interactive)](#quick-start-interactive)
- [TLS with self-signed certificate (recommended local flow)](#tls-with-self-signed-certificate-recommended-local-flow)
- [Command-line reference](#command-line-reference)
- [Example terminal output](#example-terminal-output)
- [Tests](#tests)
- [GitHub Actions (green tick guide)](#github-actions-green-tick-guide)
- [Project structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## What this project does

- `host.py` starts a chat server.
- `clint.py` connects clients to that server.
- Every connected client can send messages to everyone.
- You can run in:
  - **PLAINTEXT mode** (simple TCP)
  - **ENCRYPTED mode** (TLS transport + password-authenticated encrypted payloads)

---

## Features

- Multi-client chat room
- Broadcast messaging
- Join/leave system announcements
- Live connected-client counter
- Optional TLS transport
- Optional password-protected message encryption
- Interactive prompts for host, port, password, and **user name**
- Client certificate controls:
  - strict verify (default)
  - trust custom cert via `--cert`
  - bypass verify via `--tls-insecure` (local testing only)

---

## How secure mode works

When secure mode is ON:
1. Server enforces TLS.
2. Client performs TLS handshake.
3. Client sends chosen user name + password.
4. Server validates password.
5. Messages are encrypted at the application layer before being broadcast.

When secure mode is OFF:
- no password is required
- messages are plain text at app layer
- connection is normal TCP unless TLS is explicitly used

---

## Quick start (Without TLS with self-signed certificate)

Open one terminal for server and one or more for clients.

### 1) Start server

```powershell
python -u host.py
```

### 2) Start client

```powershell
python -u clint.py
```

The client will prompt for:
- server IP/host
- server port
- **user name**
- password (only if server is in secure mode)

### 3) Start more clients

Run `python -u clint.py` again in additional terminals and use different names.

---

## TLS with self-signed certificate (recommended local flow)

Generate cert (OpenSSL with addext; recent OpenSSL versions):

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 `
  -subj "/C=BD/ST=Dhaka/L=Dhaka/O=MultiHAT/OU=RedHAT/CN=localhost" `
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Start the host:

```powershell
python -u host.py --port 12345 --secure --password mypass --tls --cert cert.pem --key key.pem
```

Connect the client (trust the cert):

```powershell
python -u clint.py --host 127.0.0.1 --port 12345 --tls --cert cert.pem
```

If you only want quick local testing and do not want certificate verification:

```powershell
python -u clint.py --host 127.0.0.1 --port 12345 --tls --tls-insecure
```

---

## Command-line reference

### Server (`host.py`)

```powershell
python -u host.py --bind 0.0.0.0 --port 12345 --timeout 0
```

Options:
- `--bind` bind address (default: all interfaces)
- `--port` TCP port
- `--timeout` socket timeout in seconds (`0` = blocking)
- `--secure` enable secure mode without prompt
- `--password` set secure password non-interactively
- `--tls` enable TLS
- `--cert` certificate PEM file
- `--key` private key PEM file

### Client (`clint.py`)

```powershell
python -u clint.py --host 127.0.0.1 --port 12345
```

Options:
- `--host` server host/IP
- `--port` server port
- `--timeout` socket timeout
- `--name` client display name (if omitted, prompt asks)
- `--password` secure-mode password (if omitted, prompt asks)
- `--tls` force TLS first
- `--cert` certificate/CA PEM to trust during TLS verification
- `--tls-insecure` disable certificate verification (testing only)

---

## Example terminal output

Server:

```text
Listening on 127.0.0.1:12345... (Ctrl-C to stop)
Security mode: ENCRYPTED
Connection from 127.0.0.1:56582
Alice joined from 127.0.0.1:56582
+ Total connected clints: [1]
..:: Alice[56582]: Hello everyone
```

Client:

```text
--> Enter the IP address of the server: 127.0.0.1
--> Enter the port you want to connect to: 12345
--> Enter your user name: Alice
--> Enter password:
Authenticated as Alice
Connected to 127.0.0.1:12345
```

---

## Tests

Install test dependency:

```powershell
pip install -r requirements.txt
```

Run tests:

```powershell
pytest -q
```

Current tests cover shared utilities in `net_utils.py`:
- host/port validation
- timeout validation
- name validation
- encryption/decryption behavior
- packet framing and JSON parsing

---

## GitHub Actions (green tick guide)

Workflow file:
- `.github/workflows/python-ci.yml`

It runs on push and pull request against Python:
- `3.9`
- `3.10`
- `3.11`
- `3.12`

To maximize chance of green tick in **Get started with GitHub Actions**:
1. Run tests locally first (`pytest -q`).
2. Keep `.github/workflows/python-ci.yml` in place.
3. Push your commit.
4. Confirm all matrix jobs pass in the Actions tab.

---

## Project structure

```text
host.py
clint.py
net_utils.py
tests/
.github/workflows/python-ci.yml
```

---

## Troubleshooting

- **`TLS certificate verification failed` on client**
  - Use `--cert cert.pem`, or for local tests only use `--tls-insecure`.
- **`tlsv1 alert unknown ca` / `bad certificate` on server logs**
  - Usually means client rejected the cert or hostname/SAN does not match.
- **Authentication failed**
  - Password mismatch in secure mode.
- **Connection refused**
  - Host not running, wrong host/port, or firewall issue.

---

## Notes

This project is intentionally lightweight and easy to read. If you want, the next natural improvements are:
- private/direct messages
- persisted chat history
- richer client commands (`/help`, `/users`, `/rename`)
- stronger cryptography primitives and formal protocol versioning
