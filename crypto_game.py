import json
import base64
import time
import uuid
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

class ZenithCryptoSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Zenith Interstellar - Crypto Heist Simulator")
        self.root.geometry("800x650")
        
        # System State
        self.private_key, self.public_key = self.generate_keys()
        self.seen_nonces = set()
        self.current_signature = b""

        self.setup_ui()

    def generate_keys(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        return priv, pub

    def setup_ui(self):
        # Header
        tk.Label(self.root, text="Target: Zenith Interstellar Financial Node", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Payload Area (Editable by the "Attacker")
        tk.Label(self.root, text="Intercepted Payload (JSON) - YOU CAN EDIT THIS:", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        self.payload_text = scrolledtext.ScrolledText(self.root, height=8, width=90)
        self.payload_text.pack(padx=20, pady=5)

        # Signature Area (Read-only representation)
        tk.Label(self.root, text="Intercepted Cryptographic Signature (Base64):", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        self.signature_text = scrolledtext.ScrolledText(self.root, height=4, width=90, bg="#f0f0f0")
        self.signature_text.pack(padx=20, pady=5)

        # Controls
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="1. Intercept Valid Transaction", command=self.generate_transaction, bg="#d9edf7", width=25).grid(row=0, column=0, padx=10, pady=5)
        tk.Button(btn_frame, text="2. Submit to Target Node", command=self.submit_to_node, bg="#dff0d8", width=25).grid(row=0, column=1, padx=10, pady=5)
        
        tk.Label(self.root, text="Attacker Shortcuts:", font=("Arial", 10, "bold")).pack(pady=10)
        tk.Button(self.root, text="Tamper: Change Amount to $1,000,000", command=self.tamper_payload, bg="#f2dede", width=35).pack(pady=2)
        tk.Button(self.root, text="Clear Node Memory (Reset)", command=self.reset_system, width=35).pack(pady=2)

        self.generate_transaction()

    def generate_transaction(self):
        """Generates a valid, signed transaction from the admin."""
        payload_data = {
            "from": "Admin",
            "to": "Account_A",
            "amount": 500,
            "timestamp": int(time.time()),
            "nonce": str(uuid.uuid4())
        }
        
        payload_bytes = json.dumps(payload_data, indent=2).encode('utf-8')
        
        self.current_signature = self.private_key.sign(
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        self.payload_text.delete(1.0, tk.END)
        self.payload_text.insert(tk.END, payload_bytes.decode('utf-8'))
        
        self.signature_text.delete(1.0, tk.END)
        self.signature_text.insert(tk.END, base64.b64encode(self.current_signature).decode('utf-8'))

    def tamper_payload(self):
        """Simulates an attacker changing the data without recalculating the signature."""
        try:
            current_data = json.loads(self.payload_text.get(1.0, tk.END))
            current_data["amount"] = 1000000
            self.payload_text.delete(1.0, tk.END)
            self.payload_text.insert(tk.END, json.dumps(current_data, indent=2))
            messagebox.showinfo("Tampered", "Payload amount changed to $1,000,000. \nNotice the signature did not change. Now try submitting it.")
        except Exception:
            messagebox.showerror("Error", "Invalid JSON format in payload.")

    def submit_to_node(self):
        """The simulated server verification process."""
        try:
            raw_payload = self.payload_text.get(1.0, tk.END).strip().encode('utf-8')
            payload_data = json.loads(raw_payload)
            
            # 1. Cryptographic Verification
            try:
                self.public_key.verify(
                    self.current_signature,
                    raw_payload,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except InvalidSignature:
                messagebox.showerror("SECURITY ALERT: Integrity Attack", "Signature Verification FAILED.\n\nThe payload was altered after it was signed. The math does not match.")
                return

            # 2. Replay Verification
            nonce = payload_data.get("nonce")
            if nonce in self.seen_nonces:
                messagebox.showerror("SECURITY ALERT: Replay Attack", f"Duplicate Nonce detected: {nonce}\n\nThis exact transaction was already processed. Replay attack blocked.")
                return
            
            # 3. Temporal Verification
            msg_time = payload_data.get("timestamp", 0)
            if abs(int(time.time()) - msg_time) > 30:
                messagebox.showerror("SECURITY ALERT: Expired", "Transaction timestamp is too old (> 30 seconds). Blocked.")
                return

            # Success
            self.seen_nonces.add(nonce)
            messagebox.showinfo("SUCCESS", f"Transaction Verified & Processed!\n\nTransferred ${payload_data['amount']} to {payload_data['to']}.")

        except json.JSONDecodeError:
            messagebox.showerror("System Error", "The payload is not valid JSON.")
        except Exception as e:
            messagebox.showerror("System Error", str(e))

    def reset_system(self):
        self.seen_nonces.clear()
        self.generate_transaction()
        messagebox.showinfo("Reset", "Node memory cleared. New transaction generated.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ZenithCryptoSimulator(root)
    root.mainloop()