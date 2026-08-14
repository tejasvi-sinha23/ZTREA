import time
import uuid
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

class CryptoEngine:
    def __init__(self, max_time_drift=30):
        self.max_time_drift = max_time_drift
        self.seen_nonces = {}  # Format: {nonce: timestamp}

    def clean_nonce_cache(self, current_time):
        """Prevents memory leaks by removing expired nonces."""
        expired = [
            n for n, ts in self.seen_nonces.items() 
            if abs(current_time - ts) > self.max_time_drift
        ]
        for n in expired:
            del self.seen_nonces[n]

    @staticmethod
    def generate_keypair():
        """Utility to generate keys for testing."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def create_signed_payload(self, private_key, command, target_env):
        """Constructs and signs the command envelope."""
        payload_data = {
            "command": command,
            "target_env": target_env,
            "timestamp": int(time.time()),
            "nonce": str(uuid.uuid4())
        }
        
        payload_bytes = json.dumps(payload_data, sort_keys=True).encode('utf-8')
        
        signature = private_key.sign(
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return {
            "payload": base64.b64encode(payload_bytes).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8')
        }

    def verify_and_extract(self, public_key, request_data):
        """
        Validates the signature, timestamp, and nonce.
        Returns the command data if valid, raises ValueError if hacked.
        """
        try:
            payload_bytes = base64.b64decode(request_data['payload'])
            signature_bytes = base64.b64decode(request_data['signature'])
        except KeyError:
            raise ValueError("Malformed request: Missing payload or signature.")

        # 1. Cryptographic Verification
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
        except InvalidSignature:
            raise ValueError("Cryptographic verification failed. Payload altered or invalid key.")

        # 2. Extract Data
        payload_data = json.loads(payload_bytes.decode('utf-8'))
        msg_time = payload_data.get('timestamp', 0)
        nonce = payload_data.get('nonce', '')
        current_time = int(time.time())

        # 3. Temporal Verification (Timestamp)
        age = abs(current_time - msg_time)
        if age > self.max_time_drift:
            raise ValueError(f"Temporal validation failed. Message is {age}s old (Max: {self.max_time_drift}s).")

        # 4. Replay Verification (Nonce)
        self.clean_nonce_cache(current_time)
        if nonce in self.seen_nonces:
            raise ValueError(f"Replay attack detected. Nonce '{nonce}' has already been used.")
        
        # Cache the nonce
        self.seen_nonces[nonce] = msg_time

        return payload_data