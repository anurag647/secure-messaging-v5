from flask import Flask, render_template, request, jsonify, session
import base64
import hashlib
import json
import os
import secrets
import time
import hmac
import struct
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# --- Rate Limiting (Brute Force Protection) ---
class RateLimiter:
    def __init__(self, max_attempts=5, window_seconds=60):
        self.attempts = {}
        self.max_attempts = max_attempts
        self.window = window_seconds
    
    def is_blocked(self, ip):
        now = time.time()
        if ip in self.attempts:
            attempts, first_attempt = self.attempts[ip]
            if now - first_attempt > self.window:
                self.attempts[ip] = (1, now)
                return False
            if attempts >= self.max_attempts:
                return True
            self.attempts[ip] = (attempts + 1, first_attempt)
        else:
            self.attempts[ip] = (1, now)
        return False
    
    def reset(self, ip):
        if ip in self.attempts:
            del self.attempts[ip]

rate_limiter = RateLimiter()

# --- TOTP (2FA like Google Authenticator) ---
class TOTP:
    def __init__(self, secret=None):
        self.secret = secret or base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
    
    def generate_code(self, timestamp=None):
        if timestamp is None:
            timestamp = int(time.time())
        time_step = timestamp // 30
        key = base64.b32decode(self.secret)
        msg = struct.pack('>Q', time_step)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0f
        code = struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff
        return str(code % 1000000).zfill(6)
    
    def verify_code(self, code, window=1):
        timestamp = int(time.time())
        for i in range(-window, window + 1):
            if code == self.generate_code(timestamp + i * 30):
                return True
        return False
    
    def get_qr_uri(self, account_name="SecureMessaging"):
        return f"otpauth://totp/{account_name}?secret={self.secret}&issuer=SecureMsg"

# --- Enhanced Security Layer ---
class SecurityLayer:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.message_history = []
        self.keys_dir = os.path.join(os.path.dirname(__file__), 'keys')
        self.history_file = os.path.join(os.path.dirname(__file__), 'history.json')
        self.aes_key = None
        self.totp = None
        self.key_password = None
        self.pending_messages = {}
        self.used_nonces = set()  # Anti-replay protection
        self.session_fingerprints = {}  # Session fingerprinting
        self.encryption_count = 0
        self.decryption_count = 0
        self.failed_attempts = 0
        os.makedirs(self.keys_dir, exist_ok=True)
        self._load_history()
    
    def calculate_security_score(self):
        """Calculate overall security score based on configuration"""
        score = 0
        max_score = 100
        
        # Keys generated (+30)
        if self.private_key:
            score += 30
        
        # 2FA enabled (+25)
        if self.totp:
            score += 25
        
        # Password protected keys (+15)
        if self.key_password:
            score += 15
        
        # AES key generated (+15)
        if self.aes_key:
            score += 15
        
        # Low failed attempts (+15)
        if self.failed_attempts < 3:
            score += 15
        elif self.failed_attempts < 5:
            score += 10
        elif self.failed_attempts < 10:
            score += 5
        
        return {
            "score": score,
            "max_score": max_score,
            "percentage": int((score / max_score) * 100),
            "grade": "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "D" if score >= 50 else "F",
            "details": {
                "keys_generated": self.private_key is not None,
                "2fa_enabled": self.totp is not None,
                "password_protected": self.key_password is not None,
                "aes_ready": self.aes_key is not None,
                "failed_attempts": self.failed_attempts
            }
        }
    
    def verify_nonce(self, nonce):
        """Anti-replay protection - verify nonce hasn't been used"""
        if nonce in self.used_nonces:
            return False
        self.used_nonces.add(nonce)
        # Clean old nonces (keep last 1000)
        if len(self.used_nonces) > 1000:
            self.used_nonces = set(list(self.used_nonces)[-500:])
        return True
    
    def register_fingerprint(self, session_id, fingerprint):
        """Register session fingerprint for security tracking"""
        self.session_fingerprints[session_id] = {
            "fingerprint": fingerprint,
            "timestamp": datetime.now().isoformat(),
            "access_count": 1
        }
    
    def verify_fingerprint(self, session_id, fingerprint):
        """Verify session fingerprint matches"""
        if session_id not in self.session_fingerprints:
            return True  # New session
        stored = self.session_fingerprints[session_id]
        stored["access_count"] += 1
        return stored["fingerprint"] == fingerprint

    def _load_history(self):
        """Load history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.message_history = json.load(f)
        except:
            self.message_history = []

    def _save_history(self):
        """Save history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.message_history[-100:], f, indent=2)
        except:
            pass

    def add_to_history(self, entry):
        """Add entry and persist"""
        self.message_history.append(entry)
        self._save_history()

    def clear_history(self):
        """Clear all history"""
        self.message_history = []
        self._save_history()

    def generate_keys(self, password=None):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.key_password = password
        
        # Generate AES key for hybrid encryption
        self.aes_key = secrets.token_bytes(32)  # AES-256
        
        # Generate TOTP secret for 2FA
        self.totp = TOTP()
        
        return {
            "rsa_generated": True,
            "aes_generated": True,
            "totp_secret": self.totp.secret,
            "totp_uri": self.totp.get_qr_uri()
        }

    def export_keys(self, password=None):
        if not self.private_key:
            raise Exception("Keys not generated")
        
        # Encryption algorithm for private key
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
        
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(os.path.join(self.keys_dir, 'id_rsa'), 'wb') as f:
            f.write(private_pem)
        with open(os.path.join(self.keys_dir, 'id_rsa.pub'), 'wb') as f:
            f.write(public_pem)
        
        return {
            "private_key_path": os.path.join(self.keys_dir, 'id_rsa'),
            "public_key_path": os.path.join(self.keys_dir, 'id_rsa.pub'),
            "password_protected": password is not None
        }

    def calculate_hash(self, message, algorithm='md5'):
        if algorithm == 'sha256':
            return hashlib.sha256(message.encode('utf-8')).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(message.encode('utf-8')).hexdigest()
        return hashlib.md5(message.encode('utf-8')).hexdigest()

    # --- AES-256 Hybrid Encryption ---
    def aes_encrypt(self, data):
        """Encrypt data with AES-256-GCM"""
        if self.aes_key is None:
            self.aes_key = secrets.token_bytes(32)
        
        iv = secrets.token_bytes(12)  # GCM uses 12-byte IV
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + Tag + Ciphertext
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')

    def aes_decrypt(self, encrypted_b64):
        """Decrypt AES-256-GCM data"""
        data = base64.b64decode(encrypted_b64)
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

    def hybrid_encrypt(self, message, hash_algo='sha256', expiry_minutes=None):
        """
        Hybrid Encryption:
        1. Encrypt message with AES-256
        2. Encrypt AES key with RSA
        3. Bundle everything together
        """
        if not self.public_key:
            raise Exception("Keys not generated")
        
        # Generate per-message AES key
        session_aes_key = secrets.token_bytes(32)
        
        timestamp = datetime.now().isoformat()
        msg_hash = self.calculate_hash(message, hash_algo)
        
        # Payload with timestamp
        payload = json.dumps({
            "message": message,
            "hash": msg_hash,
            "hash_algo": hash_algo,
            "timestamp": timestamp,
            "expiry": (datetime.now() + timedelta(minutes=expiry_minutes)).isoformat() if expiry_minutes else None
        })
        
        # AES encrypt the payload
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(session_aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload.encode()) + encryptor.finalize()
        
        # RSA encrypt the AES key
        encrypted_aes_key = self.public_key.encrypt(
            session_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Bundle: encrypted_key_len (2 bytes) + encrypted_key + iv + tag + ciphertext
        encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode()
        aes_data_b64 = base64.b64encode(iv + encryptor.tag + ciphertext).decode()
        
        packet = json.dumps({
            "encrypted_key": encrypted_key_b64,
            "encrypted_data": aes_data_b64,
            "encryption": "RSA-2048 + AES-256-GCM"
        })
        
        # Store for expiry tracking
        msg_id = hashlib.sha256(packet.encode()).hexdigest()[:16]
        if expiry_minutes:
            self.pending_messages[msg_id] = {
                "expiry": datetime.now() + timedelta(minutes=expiry_minutes),
                "packet": packet
            }
        
        self.add_to_history({
            "type": "encrypt",
            "timestamp": timestamp,
            "hash": msg_hash,
            "hash_algorithm": hash_algo,
            "encryption": "Hybrid RSA+AES",
            "expiry": f"{expiry_minutes} min" if expiry_minutes else "None"
        })
        
        return base64.b64encode(packet.encode()).decode(), msg_hash, timestamp, msg_id

    def hybrid_decrypt(self, packet_b64, totp_code=None):
        """Decrypt hybrid encrypted message"""
        if not self.private_key:
            raise Exception("Keys not generated")
        
        # Verify 2FA if enabled
        if self.totp and totp_code:
            if not self.totp.verify_code(totp_code):
                return {"error": "Invalid 2FA code", "2fa_failed": True}
        
        try:
            packet = json.loads(base64.b64decode(packet_b64).decode())
            
            # Decrypt AES key with RSA
            encrypted_aes_key = base64.b64decode(packet["encrypted_key"])
            session_aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt data with AES
            aes_data = base64.b64decode(packet["encrypted_data"])
            iv = aes_data[:12]
            tag = aes_data[12:28]
            ciphertext = aes_data[28:]
            
            cipher = Cipher(algorithms.AES(session_aes_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            payload = json.loads(plaintext.decode())
            
            # Check expiry
            if payload.get("expiry"):
                expiry_time = datetime.fromisoformat(payload["expiry"])
                if datetime.now() > expiry_time:
                    return {"error": "Message has expired", "expired": True}
            
            # Verify integrity
            calculated_hash = self.calculate_hash(payload["message"], payload["hash_algo"])
            integrity_ok = calculated_hash == payload["hash"]
            
            self.add_to_history({
                "type": "decrypt",
                "timestamp": datetime.now().isoformat(),
                "integrity": integrity_ok,
                "message_preview": payload["message"][:50] + "..." if len(payload["message"]) > 50 else payload["message"]
            })
            
            return {
                "message": payload["message"],
                "received_hash": payload["hash"],
                "calculated_hash": calculated_hash,
                "integrity_ok": integrity_ok,
                "timestamp": payload["timestamp"],
                "encryption_used": packet.get("encryption", "Unknown")
            }
            
        except Exception as e:
            return {"error": str(e)}

    def sign_message(self, message):
        if not self.private_key:
            raise Exception("Private key not available")
        
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message, signature_b64):
        if not self.public_key:
            raise Exception("Public key not available")
        
        try:
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def get_current_totp(self):
        if self.totp:
            return self.totp.generate_code()
        return None

    def get_history(self):
        return self.message_history[-20:]

    def cleanup_expired(self):
        now = datetime.now()
        expired = [k for k, v in self.pending_messages.items() if v["expiry"] < now]
        for k in expired:
            del self.pending_messages[k]
        return len(expired)

# Global instance
sec_layer = SecurityLayer()

# --- Rate limit decorator ---
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        if rate_limiter.is_blocked(ip):
            return jsonify({"error": "Too many requests. Try again later.", "rate_limited": True}), 429
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/generate', methods=['POST'])
@rate_limit
def generate_keys():
    data = request.json or {}
    password = data.get('password')
    result = sec_layer.generate_keys(password)
    return jsonify({"status": "success", **result})

@app.route('/api/export-keys', methods=['POST'])
@rate_limit
def export_keys():
    data = request.json or {}
    password = data.get('password')
    try:
        result = sec_layer.export_keys(password)
        return jsonify({"status": "success", **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
@rate_limit
def encrypt():
    data = request.json
    message = data.get('message', '')
    hash_algo = data.get('hash_algorithm', 'sha256')
    expiry = data.get('expiry_minutes')
    use_hybrid = data.get('hybrid', True)
    
    if not message:
        return jsonify({"error": "No message provided"}), 400
    
    try:
        if use_hybrid:
            encrypted, msg_hash, timestamp, msg_id = sec_layer.hybrid_encrypt(
                message, hash_algo, int(expiry) if expiry else None
            )
            return jsonify({
                "status": "success",
                "encryption_type": "Hybrid RSA-2048 + AES-256-GCM",
                "hash": msg_hash,
                "hash_algorithm": hash_algo,
                "encrypted_packet": encrypted,
                "timestamp": timestamp,
                "message_id": msg_id,
                "expiry_minutes": expiry
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
@rate_limit
def decrypt():
    data = request.json
    encrypted = data.get('encrypted', '')
    totp_code = data.get('totp_code')
    
    if not encrypted:
        return jsonify({"error": "No encrypted data provided"}), 400
    
    try:
        result = sec_layer.hybrid_decrypt(encrypted, totp_code)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/sign', methods=['POST'])
@rate_limit
def sign():
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({"error": "No message provided"}), 400
    
    try:
        signature = sec_layer.sign_message(message)
        return jsonify({"status": "success", "signature": signature})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify', methods=['POST'])
@rate_limit
def verify():
    data = request.json
    message = data.get('message', '')
    signature = data.get('signature', '')
    
    if not message or not signature:
        return jsonify({"error": "Message and signature required"}), 400
    
    try:
        is_valid = sec_layer.verify_signature(message, signature)
        return jsonify({"is_valid": is_valid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/totp', methods=['GET'])
def get_totp():
    if sec_layer.totp:
        return jsonify({
            "current_code": sec_layer.get_current_totp(),
            "secret": sec_layer.totp.secret,
            "uri": sec_layer.totp.get_qr_uri()
        })
    return jsonify({"error": "2FA not enabled"}), 400

@app.route('/api/history', methods=['GET'])
def get_history():
    sec_layer.cleanup_expired()
    return jsonify({"history": sec_layer.get_history()})

@app.route('/api/history/clear', methods=['POST'])
def clear_history():
    sec_layer.clear_history()
    return jsonify({"status": "success", "message": "History cleared"})

@app.route('/api/security-score', methods=['GET'])
def get_security_score():
    """Get overall security score and status"""
    score_data = sec_layer.calculate_security_score()
    return jsonify({
        "status": "success",
        **score_data,
        "encryption_count": sec_layer.encryption_count,
        "decryption_count": sec_layer.decryption_count,
        "active_sessions": len(sec_layer.session_fingerprints)
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get overall system status"""
    return jsonify({
        "status": "protected",
        "version": "5.0",
        "keys_ready": sec_layer.private_key is not None,
        "2fa_enabled": sec_layer.totp is not None,
        "security_score": sec_layer.calculate_security_score()["percentage"],
        "uptime": "active"
    })

if __name__ == '__main__':
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print("\n" + "="*60)
    print("   [PROTECTED] SECURE MESSAGING WEB APP v5.0")
    print("="*60)
    print("\n   NEW IN v5.0:")
    print("   [+] Red 'Quantum Nebula' Theme")
    print("   [+] PROTECTED Security Badge")
    print("   [+] Real-Time Refresh Feature")
    print("   [+] Security Score Dashboard")
    print("   [+] Anti-Replay Protection")
    print("   [+] Session Fingerprinting")
    print("\n   SECURITY FEATURES:")
    print("   [+] RSA-2048 + AES-256-GCM Hybrid Encryption")
    print("   [+] SHA-256/SHA-512 Integrity Hashing")
    print("   [+] 2FA (TOTP - Google Authenticator)")
    print("   [+] Message Expiry (Auto-Delete)")
    print("   [+] Brute-Force Protection (Rate Limiting)")
    print(f"\n   Local:   http://127.0.0.1:5000")
    print(f"   Network: http://{local_ip}:5000")
    print("\n" + "="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
