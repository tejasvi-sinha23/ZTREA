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
| `crypto_game.py` | The interactive GUI simulator. Run this to visually explore and attempt the attacks described in the Attacker's Playbook. |

---

## Quickstart

### 1. Requirements
* Python 3.10+
* `pip install -r requirements.txt` *(includes cryptography, fastapi, uvicorn, pydantic, requests)*

### 2. Provision Infrastructure Keys
Generate the required RSA key pairs for both the Client and the Server:
```bash
python client_cli.py setup
```

### 3. Start the Server

```bash
uvicorn server_agent:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Run a Signed Command

```bash
python client_cli.py run "whoami"
```

---

## The Attacker's Playbook (Interactive Lab)

> **Want to try this hands-on?** Launch the interactive GUI simulator first:
> ```bash
> python crypto_game.py
> ```
> The simulator gives you a visual interface to intercept payloads, tamper with data, and watch the defenses fire in real time. The levels below map directly to what you'll see in the game.

To truly understand a security system, you must attempt to break it. Use the simulator's GUI to execute the following attacks and observe how the mathematical defenses react.

---

### Level 1: The Integrity Attack (Data Tampering)

**The Goal:** Alter the financial payload to steal funds without possessing the private key.

1. Click **"1. Intercept Valid Transaction"** to generate a signed payload.
2. In the JSON text box, manually change `"amount": 500` to `"amount": 1000000`.
3. Do **not** change the Base64 signature.
4. Click **"2. Submit to Target Node"**.

**Result:** `SECURITY ALERT: Integrity Attack`

**The Concept:** Because you changed the JSON payload, the SHA-256 hash of the text completely changed. When the server decrypts the provided signature using the Public Key, the resulting hash no longer matches the payload's hash. Tampering is mathematically impossible to hide.

---

### Level 2: The Replay Attack (Context Tampering)

**The Goal:** Force the server to process the same valid transaction multiple times.

1. Click **"Clear Node Memory"** to start fresh.
2. Click **"1. Intercept Valid Transaction"**.
3. Do **not** change anything — the JSON and signature are perfectly valid.
4. Click **"2. Submit to Target Node"**. The system will accept the $500 transfer.
5. Immediately click **"2. Submit to Target Node"** a second time.

**Result:** `SECURITY ALERT: Replay Attack`

**The Concept:** The cryptography is perfect, but the server remembers the nonce (Number Used Once). Signatures prove *who* sent a message and *what* it says, but they do not prove *when* it was sent. Caching nonces prevents attackers from sniffing valid packets and spamming them at the server.

---

### Level 3: The Temporal Attack (Time-Drift)

**The Goal:** Attempt to bypass the nonce cache by waiting for the server to clear its memory, then sending an old transaction.

1. Click **"Clear Node Memory"**.
2. Click **"1. Intercept Valid Transaction"**.
3. Wait exactly **31 seconds** — do not click submit yet.
4. After 31 seconds pass, click **"2. Submit to Target Node"**.

**Result:** `SECURITY ALERT: Expired`

**The Concept:** If a server stored every nonce forever, it would eventually run out of RAM and crash (a memory leak). To fix this, servers only store nonces for a short window (e.g., 30 seconds). But if the cache clears, an attacker could replay the message on second 31. To prevent this, the payload also includes a timestamp — once the payload is older than 30 seconds, the server drops it immediately, allowing it to safely evict the nonce from memory.

---

## Security Notes

- Private keys (`*_private.pem`) are stored unencrypted. In production, protect them with a passphrase or a secrets manager and restrict OS file permissions (`chmod 400`).
- The replay window defaults to **30 seconds** — client and server clocks must be roughly in sync (NTP recommended for production).
- `shell=False` in subprocess execution prevents shell injection. Do not change this.
- This project is a security learning tool and local demonstration. It is not a production-grade PKI or remote execution system.