import argparse
import requests
import json
import base64
import os
import sys
from cryptography.hazmat.primitives import serialization
from crypto_engine import CryptoEngine

API_URL = "http://127.0.0.1:8000/api/v1/execute"
CLIENT_PRIV_KEY_PATH = "client_private.pem"
CLIENT_PUB_KEY_PATH = "client_public.pem"
SERVER_PRIV_KEY_PATH = "server_private.pem"
SERVER_PUB_KEY_PATH = "server_public.pem"

engine = CryptoEngine(max_time_drift=30)

def setup_keys():
    """Generates both Client and Server keypairs for the local simulation."""
    def save_pair(priv_path, pub_path):
        if os.path.exists(priv_path) or os.path.exists(pub_path):
            print(f"[-] Keys {priv_path}/{pub_path} already exist. Skipping.")
            return
            
        priv, pub = engine.generate_keypair()
        with open(priv_path, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(pub_path, "wb") as f:
            f.write(pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[+] Generated {priv_path} and {pub_path}")

    print("[*] Provisioning Infrastructure Keys...")
    save_pair(CLIENT_PRIV_KEY_PATH, CLIENT_PUB_KEY_PATH)
    save_pair(SERVER_PRIV_KEY_PATH, SERVER_PUB_KEY_PATH)

def load_key(path, is_private=False):
    if not os.path.exists(path):
        print(f"[-] CRITICAL: Missing key file: {path}. Run 'python client_cli.py setup' first.")
        sys.exit(1)
    with open(path, "rb") as f:
        key_data = f.read()
        if is_private:
            return serialization.load_pem_private_key(key_data, password=None)
        else:
            return serialization.load_pem_public_key(key_data)

def run_command(command_str):
    client_priv = load_key(CLIENT_PRIV_KEY_PATH, is_private=True)
    server_pub = load_key(SERVER_PUB_KEY_PATH, is_private=False)

    print(f"[*] Signing command: '{command_str}'")
    req_data = engine.create_signed_payload(client_priv, command_str, target_env="prod-server-01")
    
    # Extract the nonce we just generated so we can verify the receipt matches it
    payload_decoded = json.loads(base64.b64decode(req_data["payload"]).decode('utf-8'))
    original_nonce = payload_decoded["nonce"]
    
    print(f"[*] Dispatching to {API_URL} (Nonce: {original_nonce})...")
    
    try:
        response = requests.post(API_URL, json=req_data, timeout=20)
    except requests.exceptions.RequestException as e:
        print(f"[-] Network Error: {e}")
        sys.exit(1)

    if response.status_code != 200:
        print(f"[-] Server rejected request (HTTP {response.status_code}): {response.text}")
        sys.exit(1)

    res_json = response.json()
    if "receipt" not in res_json:
        print("[-] FATAL: Server returned a 200 OK but provided no cryptographic receipt. Assuming compromise.")
        sys.exit(1)

    print("[*] Receipt received. Verifying server signature...")
    
    try:
        # Verify the server's receipt using the server's public key
        verified_receipt = engine.verify_and_extract(server_pub, res_json["receipt"])
    except ValueError as e:
        print(f"[-] FATAL: Receipt cryptographic verification failed: {e}")
        sys.exit(1)

    # The server packs the actual output inside the "command" field of its engine payload
    receipt_data = json.loads(verified_receipt["command"])
    
    if receipt_data["original_nonce"] != original_nonce:
        print("[-] FATAL: Nonce mismatch. This receipt is for a different command. Possible replay or MITM attack.")
        sys.exit(1)

    print("\n[+] --- SECURE EXECUTION RECEIPT VALIDATED ---")
    print(f"Target Process Exit Code: {receipt_data['return_code']}")
    
    if receipt_data['stdout']:
        print("\n[STDOUT]:")
        print(receipt_data['stdout'])
        
    if receipt_data['stderr']:
        print("\n[STDERR]:")
        print(receipt_data['stderr'])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZTREA Admin CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("setup", help="Generate Client and Server Keypairs")
    
    run_parser = subparsers.add_parser("run", help="Execute a command securely on the remote server")
    run_parser.add_argument("cmd", help="The bash command to execute (e.g. 'ls -la')")

    args = parser.parse_args()

    if args.command == "setup":
        setup_keys()
    elif args.command == "run":
        run_command(args.cmd)