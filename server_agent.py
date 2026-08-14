import os
import shlex
import json
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from crypto_engine import CryptoEngine

app = FastAPI(title="ZTREA - Zero-Trust Remote Execution Agent")
engine = CryptoEngine(max_time_drift=30)

# In production, these must be absolute paths protected by strict OS file permissions (chmod 400).
CLIENT_PUB_KEY_PATH = "client_public.pem"
SERVER_PRIV_KEY_PATH = "server_private.pem"

class ExecutionRequest(BaseModel):
    payload: str
    signature: str

def load_key(path, is_private=False):
    if not os.path.exists(path):
        raise FileNotFoundError(f"CRITICAL: Key file missing at {path}")
    
    with open(path, "rb") as f:
        key_data = f.read()
        if is_private:
            return serialization.load_pem_private_key(key_data, password=None)
        else:
            return serialization.load_pem_public_key(key_data)

@app.post("/api/v1/execute")
async def execute_command(req: ExecutionRequest):
    try:
        client_pub = load_key(CLIENT_PUB_KEY_PATH, is_private=False)
        server_priv = load_key(SERVER_PRIV_KEY_PATH, is_private=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # 1. Cryptographic and Temporal Verification
    try:
        request_data = {"payload": req.payload, "signature": req.signature}
        verified_data = engine.verify_and_extract(client_pub, request_data)
    except ValueError as e:
        # Returning a 403 Forbidden with the exact crypto failure reason
        raise HTTPException(status_code=403, detail=str(e))

    command_str = verified_data.get("command")
    original_nonce = verified_data.get("nonce")

    # 2. Safe Command Execution
    # shlex.split ensures 'echo "hello; ls"' is treated as one command, 
    # preventing shell injection attacks.
    safe_command = shlex.split(command_str)
    
    try:
        result = subprocess.run(
            safe_command,
            capture_output=True,
            text=True,
            timeout=15, # Hard kill after 15s to prevent hanging the API
            shell=False 
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        return_code = result.returncode
    except Exception as e:
        stdout = ""
        stderr = str(e)
        return_code = -1

    # 3. Generate Cryptographic Receipt
    receipt_data = {
        "original_nonce": original_nonce,
        "stdout": stdout,
        "stderr": stderr,
        "return_code": return_code
    }
    
    # We serialize the receipt into the command field of our engine to sign it.
    receipt_signed = engine.create_signed_payload(
        server_priv, 
        command=json.dumps(receipt_data),
        target_env="client-audit-log"
    )

    return {
        "status": "success" if return_code == 0 else "failed",
        "receipt": receipt_signed
    }
#uvicorn server_agent:app --host 127.0.0.1 --port 8000 --reload