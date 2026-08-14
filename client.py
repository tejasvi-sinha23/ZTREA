import socket
import json
import base64
import time
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = '127.0.0.1'
PORT = 65432
PRIVATE_KEY_PATH = "private.pem"

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def sign_message(private_key, payload_bytes):
    return private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def send_message(message_text, simulate_replay=False):
    private_key = load_private_key()
    
    # Generate timestamp. If simulating an attack, artificially age it by 60 seconds.
    current_time = int(time.time())
    if simulate_replay:
        current_time -= 60
        print("[!] Simulating Replay Attack: Injecting old timestamp...")

    # The payload is now a JSON structure containing BOTH message and time
    payload_data = {
        "message": message_text,
        "timestamp": current_time
    }
    
    payload_bytes = json.dumps(payload_data).encode('utf-8')
    
    # Sign the ENTIRE payload, preventing timestamp tampering
    signature_bytes = sign_message(private_key, payload_bytes)
    
    # Package for transmission
    envelope = {
        "payload": base64.b64encode(payload_bytes).decode('utf-8'),
        "signature": base64.b64encode(signature_bytes).decode('utf-8')
    }
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(json.dumps(envelope).encode('utf-8'))
        response = s.recv(1024)
        
    print(f"Server Response: {response.decode('utf-8')}")

if __name__ == "__main__":
    replay_mode = "--replay" in sys.argv
    msg = "AUTHORIZE TRANSFER: $500 to Account A"
    
    print(f"[*] Dispatching: '{msg}'")
    send_message(msg, simulate_replay=replay_mode)