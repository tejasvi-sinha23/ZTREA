import argparse
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

def generate_keys(private_out='private.pem', public_out='public.pem'):
    """Task 1: Generate RSA Keys and save them to disk."""
    if os.path.exists(private_out) or os.path.exists(public_out):
        print("[-] Keys already exist. Refusing to overwrite.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Save Private Key
    with open(private_out, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Save Public Key
    public_key = private_key.public_key()
    with open(public_out, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"[+] Keys generated successfully: {private_out}, {public_out}")

def sign_file(filepath, private_key_path):
    """Task 2: Sign a message (file payload)."""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    with open(filepath, "rb") as f:
        payload = f.read()

    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Encode in base64 to make it human-readable/transportable
    sig_b64 = base64.b64encode(signature)
    sig_path = f"{filepath}.sig"
    
    with open(sig_path, "wb") as f:
        f.write(sig_b64)
        
    print(f"[+] File signed successfully. Signature saved to: {sig_path}")

def verify_file(filepath, sig_path, public_key_path):
    """Task 3: Verify the signature of a file."""
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    with open(filepath, "rb") as f:
        payload = f.read()

    with open(sig_path, "rb") as f:
        signature = base64.b64decode(f.read())

    try:
        public_key.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[+] VERIFIED: The file is authentic and unaltered.")
        return True
    except InvalidSignature:
        print("[-] FAILED: The signature is invalid. The file has been tampered with or the wrong key was used.")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure File Notary - Digital Signature Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Keygen command
    subparsers.add_parser("keygen", help="Generate RSA private and public keys")

    # Sign command
    parser_sign = subparsers.add_parser("sign", help="Sign a file")
    parser_sign.add_argument("file", help="File to sign")
    parser_sign.add_argument("--key", default="private.pem", help="Path to private key")

    # Verify command
    parser_verify = subparsers.add_parser("verify", help="Verify a file's signature")
    parser_verify.add_argument("file", help="File to verify")
    parser_verify.add_argument("signature", help="Signature file (.sig)")
    parser_verify.add_argument("--key", default="public.pem", help="Path to public key")

    args = parser.parse_args()

    if args.command == "keygen":
        generate_keys()
    elif args.command == "sign":
        sign_file(args.file, args.key)
    elif args.command == "verify":
        verify_file(args.file, args.signature, args.key)