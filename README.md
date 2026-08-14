# ZTREA — Zero-Trust Remote Execution Agent

A Python toolkit that combines **file notarization** (sign & verify files offline) with a **Zero-Trust Remote Execution Agent** — a FastAPI-based server that only runs commands from cryptographically signed, timestamped, nonce-protected requests.

---

## Features

- **RSA Key Generation** — 2048-bit RSA key pairs saved as PEM files
- **File Signing & Verification** — sign any file; detect any byte-level tampering
- **Zero-Trust Command Execution** — server only executes commands from authenticated clients
- **Replay Attack Protection** — every request carries a timestamp (30 s window) and a one-time UUID nonce
- **Signed Execution Receipts** — server signs and returns proof of execution back to the client
- **Shell Injection Prevention** — `shlex.split` + `shell=False` subprocess execution
- **Legacy Socket Demo** — original raw TCP client/server pair for learning purposes

---

## Project Structure

```
Secure File Notary CLI/
│
├── crypto_engine.py      # Core: key generation, signing, verification, nonce cache
│
├── server_agent.py       # FastAPI ZTREA server — verifies requests, runs commands, returns receipts
├── client_cli.py         # CLI client — signs commands, dispatches to server, validates receipts
│
├── notary.py             # Offline CLI: keygen / sign file / verify file
│
├── client.py             # Legacy raw TCP client (replay attack demo)
├── server.py             # Legacy raw TCP server (replay attack demo)
│
├── requirements.txt      # Python dependencies
├── contract.txt          # Example file for notary demo
├── contract.txt.sig      # Example signature for notary demo
│
├── client_public.pem     # Client public key  (generated via setup)
├── server_public.pem     # Server public key  (generated via setup)
│
└── .gitignore
```

> `client_private.pem`, `server_private.pem`, and `private.pem` are excluded from version control.

---

## Requirements

- Python 3.8+

Install all dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt` includes: `cryptography`, `fastapi`, `uvicorn`, `pydantic`, `requests`

---

## Usage

### Part 1 — File Notary (Offline)

#### Generate Keys

```bash
python notary.py keygen
```

Creates `private.pem` and `public.pem`. Refuses to overwrite existing keys.

#### Sign a File

```bash
python notary.py sign contract.txt
```

Produces `contract.txt.sig` next to the file. Use `--key` to specify a custom private key path.

#### Verify a File

```bash
python notary.py verify contract.txt contract.txt.sig
```

```
[+] VERIFIED: The file is authentic and unaltered.
[-] FAILED: The signature is invalid. The file has been tampered with or the wrong key was used.
```

---

### Part 2 — Zero-Trust Remote Execution Agent

#### Step 1 — Generate Keypairs

```bash
python client_cli.py setup
```

Generates `client_private.pem`, `client_public.pem`, `server_private.pem`, `server_public.pem`.

#### Step 2 — Start the Server

```bash
uvicorn server_agent:app --host 127.0.0.1 --port 8000 --reload
```

The server loads `client_public.pem` (to verify incoming requests) and `server_private.pem` (to sign receipts).

#### Step 3 — Run a Command

```bash
python client_cli.py run "whoami"
python client_cli.py run "ls -la"
```

Example output:

```
[*] Signing command: 'whoami'
[*] Dispatching to http://127.0.0.1:8000/api/v1/execute (Nonce: a3f1c...)
[*] Receipt received. Verifying server signature...

[+] --- SECURE EXECUTION RECEIPT VALIDATED ---
Target Process Exit Code: 0

[STDOUT]:
desktop\user
```

---

### Part 3 — Legacy TCP Demo (Replay Attack Simulation)

Start the raw TCP server:

```bash
python server.py
```

Send a normal signed message:

```bash
python client.py
```

Simulate a replay attack (timestamps the message 60 seconds in the past):

```bash
python client.py --replay
```

```
[-] BLOCKED: Message is 60 seconds old. Replay attack detected.
```

---

## How It Works

### `crypto_engine.py` — Shared Security Core

All cryptographic operations go through `CryptoEngine`:

| Method | Purpose |
|---|---|
| `generate_keypair()` | Creates a 2048-bit RSA key pair |
| `create_signed_payload()` | Wraps a command with a timestamp + UUID nonce, signs the whole envelope with RSA-PSS + SHA-256 |
| `verify_and_extract()` | Verifies signature → checks timestamp age → checks nonce hasn't been seen before |

The nonce cache auto-expires entries older than `max_time_drift` to prevent memory leaks.

### `server_agent.py` — FastAPI Execution Agent

On every `POST /api/v1/execute`:

1. **Cryptographic check** — verifies the client's RSA-PSS signature
2. **Temporal check** — rejects messages older than 30 seconds
3. **Replay check** — rejects any nonce seen before in the current window
4. **Safe execution** — runs the command via `subprocess.run` with `shell=False` and `shlex.split`, with a 15-second hard timeout
5. **Signed receipt** — signs and returns the stdout/stderr/exit code so the client can verify the response wasn't tampered with

### `client_cli.py` — Admin CLI

1. Signs the command payload with `client_private.pem`
2. POSTs to the server and receives a signed receipt
3. Verifies the receipt using `server_public.pem`
4. Validates the `original_nonce` in the receipt matches the request — detects MITM/replay on the response side

---

## Security Notes

- Private keys (`*_private.pem`) are stored unencrypted. In production, protect them with a passphrase or a secrets manager and restrict OS file permissions (`chmod 400`).
- The replay window defaults to **30 seconds** — client and server clocks must be roughly in sync (NTP recommended for production).
- `shell=False` in subprocess execution prevents shell injection. Do not change this.
- This project is a security learning tool and local demonstration. It is not a production-grade PKI or remote execution system.
