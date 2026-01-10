import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class SecurityLayer:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """Generates a private and public key pair (2048-bit RSA)."""
        print("[SecurityLayer] Generating RSA 2048-bit Key Pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        print("[SecurityLayer] Keys Generated Successfully.")
        return self.private_key, self.public_key

    def calculate_md5(self, message):
        """Calculates MD5 hash of the message."""
        md5_hash = hashlib.md5(message.encode('utf-8')).hexdigest()
        return md5_hash

    def encrypt_packet(self, message):
        """
        Creates a secure packet:
        1. Calculate MD5 hash for integrity.
        2. Combine Message + Delimiter + Hash.
        3. Encrypt the combined data using Public Key.
        """
        if not self.public_key:
            raise Exception("Public key not loaded.")

        # 1. Integrity Check (MD5)
        msg_hash = self.calculate_md5(message)
        
        # 2. Payload Construction
        # Format: MESSAGE || ::HASH:: || MD5_HASH
        payload = f"{message}::HASH::{msg_hash}"
        
        print(f"[Sender] MD5 Hash of original message: {msg_hash}")
        
        # 3. Encryption
        ciphertext = self.public_key.encrypt(
            payload.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt_packet(self, ciphertext_b64):
        """
        Decrypts and verifies the packet:
        1. Decrypt using Private Key.
        2. Split into Message and Hash.
        3. Verify MD5 matches.
        """
        if not self.private_key:
            raise Exception("Private key not loaded.")

        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext_bytes = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_payload = plaintext_bytes.decode('utf-8')
            
            # Split Message and Hash
            if "::HASH::" in decrypted_payload:
                message, received_hash = decrypted_payload.rsplit("::HASH::", 1)
                
                # Verify Integrity
                calculated_hash = self.calculate_md5(message)
                
                print(f"[Receiver] Calculated Hash: {calculated_hash}")
                print(f"[Receiver] Received Hash:   {received_hash}")
                
                if calculated_hash == received_hash:
                    print("[Receiver] INTEGRITY CHECK PASSED (MD5 Matches)")
                    return message
                else:
                    return "ERROR: INTEGRITY CHECK FAILED! Message may have been tampered with."
            else:
                return "ERROR: Invalid packet format."
                
        except Exception as e:
            return f"Decryption Failed: {str(e)}"

def main():
    print("="*60)
    print("      SECURE MESSAGING SYSTEM (ASSIGNMENT DEMO)")
    print("      Security: RSA-2048 (Encryption) + MD5 (Integrity)")
    print("="*60)
    
    # Initialize Security Layer
    sec_layer = SecurityLayer()
    
    # 1. Setup Keys
    print("\n[+] SYSTEM INITIALIZATION")
    sec_layer.generate_keys()

    # 2. User Input
    original_message = "Confidential Assignment Data"
    print("\n" + "-"*60)
    print(f" 1. SENDER INPUT")
    print("-"*60)
    print(f" Message:      '{original_message}'")

    # 3. Simulate Network Transmission (Encryption)
    print("\n" + "-"*60)
    print(f" 2. SECURE TRANSMISSION (Network Layer)")
    print("-"*60)
    encrypted_packet = sec_layer.encrypt_packet(original_message)
    print(f" [!] Encrypted Packet (Base64 Encoded for Transmission):")
    print(f" {encrypted_packet}") 

    # 4. Simulate Receiver (Decryption)
    print("\n" + "-"*60)
    print(f" 3. RECEIVER OUTPUT")
    print("-"*60)
    decrypted_message = sec_layer.decrypt_packet(encrypted_packet)
    print(f" Decrypted Msg: '{decrypted_message}'")
    print("="*60)

if __name__ == "__main__":
    main()
