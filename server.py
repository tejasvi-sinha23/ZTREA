import socket
import json
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

HOST = '127.0.0.1'
PORT = 65432
PUBLIC_KEY_PATH = "public.pem"
MAX_TIME_DRIFT = 30  # Seconds. Any message older than this is rejected.

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def verify_message(public_key, payload_bytes, signature_bytes):
    try:
        public_key.verify(
            signature_bytes,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def start_server():
    public_key = load_public_key()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Server listening on {HOST}:{PORT}...")
        
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(4096)
                if not data:
                    break
                
                envelope = json.loads(data.decode('utf-8'))
                payload_bytes = base64.b64decode(envelope['payload'])
                signature_bytes = base64.b64decode(envelope['signature'])
                
                # 1. Cryptographic Verification
                if not verify_message(public_key, payload_bytes, signature_bytes):
                    print("[-] FAILED: Invalid signature. Dropping connection.\n")
                    conn.sendall(b"403 Forbidden: Invalid Signature")
                    continue
                
                # 2. Temporal Verification (Replay Protection)
                payload_data = json.loads(payload_bytes.decode('utf-8'))
                msg_time = payload_data.get('timestamp', 0)
                current_time = int(time.time())
                
                # Calculate the age of the message
                age = abs(current_time - msg_time)
                
                if age > MAX_TIME_DRIFT:
                    print(f"[-] BLOCKED: Message is {age} seconds old. Replay attack detected.\n")
                    conn.sendall(b"403 Forbidden: Expired Message (Replay Detected)")
                else:
                    print(f"[+] VERIFIED: '{payload_data['message']}' (Age: {age}s)\n")
                    conn.sendall(b"200 OK: Transaction Processed")

if __name__ == "__main__":
    start_server()