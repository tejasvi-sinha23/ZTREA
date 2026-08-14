# ZTREA: Zero-Trust Remote Execution Agent

A cryptographically secure, API-driven daemon for executing infrastructure commands remotely. 

ZTREA replaces traditional, trust-based SSH access with a mathematically verifiable execution pipeline. It ensures that a server only executes commands dispatched by an authenticated administrator and provides the client with a cryptographic receipt proving the execution results.

## Security Architecture

ZTREA operates on a strict Zero-Trust model. Every request is treated as hostile until it passes a multi-stage verification pipeline:

1. **RSA-PSS Signatures:** Commands are wrapped in a JSON envelope and signed using a 2048-bit RSA Private Key. The server rejects any payload where the signature fails verification against the authorized Public Key.
2. **Strict Time-Bounding:** Every payload contains a UNIX timestamp. The server drops any request older than 30 seconds, mitigating delayed-execution attacks.
3. **Nonce Caching (Replay Defense):** To prevent an attacker from replaying a captured packet within the 30-second window, the client generates a unique UUID (Nonce) for every request. The server maintains a self-cleaning, in-memory cache of seen nonces and strictly rejects duplicates.
4. **Shell Injection Prevention:** Commands are parsed using `shlex.split` and executed via Python's `subprocess` with `shell=False`. This completely bypasses the host OS shell, neutralizing command chaining (e.g., `; rm -rf /`) and injection attempts.
5. **Mutual Non-Repudiation:** Upon execution, the server bundles the `stdout`, `stderr`, and original Nonce, signs it with its own Private Key, and returns it. The client verifies this receipt, ensuring the response was not spoofed by a Man-in-the-Middle (MITM).

---

## System Components

| Component | Purpose |
|---|---|
| `crypto_engine.py` | The cryptographic core. Handles key generation, payload signing, RSA-PSS verification, and the self-cleaning hybrid Nonce/Timestamp cache. |
| `server_agent.py` | The FastAPI daemon. Listens for requests, executes the verification pipeline, safely runs the command, and generates the signed execution receipt. |
| `client_cli.py` | The Administrator CLI. Signs payloads, dispatches them to the target server, and cryptographically verifies the server's receipt before displaying output. |

---

## Quickstart

### 1. Requirements
* Python 3.10+
* `pip install -r requirements.txt` *(includes cryptography, fastapi, uvicorn, pydantic, requests)*

### 2. Provision Infrastructure Keys
Generate the required RSA key pairs for both the Client and the Server:
```bash
python client_cli.py setup