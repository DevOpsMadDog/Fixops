"""
Enterprise cryptographic utilities and secure token generation
"""

import secrets
import string
import hashlib
import hmac
from typing import Optional, Dict, Any
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure random token
    Suitable for session tokens, API keys, etc.
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_secure_password(length: int = 16) -> str:
    """
    Generate cryptographically secure password with mixed character types
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")
    
    # Ensure at least one character from each category
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Start with one character from each category
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the rest with random characters from all categories
    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)


def generate_api_key(prefix: str = "fxo", length: int = 32) -> str:
    """
    Generate API key with prefix for identification
    Format: prefix_randompart
    """
    random_part = generate_secure_token(length)
    return f"{prefix}_{random_part}"


def hash_sensitive_data(data: str, salt: Optional[str] = None) -> Dict[str, str]:
    """
    Hash sensitive data with salt for secure storage
    Returns dict with hash and salt
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Use PBKDF2 for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,  # High iteration count for security
    )
    
    key = kdf.derive(data.encode())
    hash_hex = key.hex()
    
    return {
        "hash": hash_hex,
        "salt": salt
    }


def verify_sensitive_data(data: str, stored_hash: str, salt: str) -> bool:
    """
    Verify sensitive data against stored hash
    """
    try:
        # Recreate hash with same salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
        )
        
        key = kdf.derive(data.encode())
        computed_hash = key.hex()
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, computed_hash)
        
    except Exception:
        return False


def generate_encryption_key() -> bytes:
    """
    Generate encryption key for Fernet symmetric encryption
    """
    return Fernet.generate_key()


def encrypt_data(data: str, key: bytes) -> str:
    """
    Encrypt data using Fernet symmetric encryption
    """
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return base64.urlsafe_b64encode(encrypted_data).decode()


def decrypt_data(encrypted_data: str, key: bytes) -> str:
    """
    Decrypt data using Fernet symmetric encryption
    """
    f = Fernet(key)
    decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
    decrypted_data = f.decrypt(decoded_data)
    return decrypted_data.decode()


def generate_checksum(data: str) -> str:
    """
    Generate SHA-256 checksum for data integrity verification
    """
    return hashlib.sha256(data.encode()).hexdigest()


def verify_checksum(data: str, expected_checksum: str) -> bool:
    """
    Verify data integrity using checksum
    """
    computed_checksum = generate_checksum(data)
    return hmac.compare_digest(expected_checksum, computed_checksum)


def generate_hmac_signature(data: str, secret_key: str) -> str:
    """
    Generate HMAC signature for message authentication
    """
    signature = hmac.new(
        secret_key.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature


def verify_hmac_signature(data: str, signature: str, secret_key: str) -> bool:
    """
    Verify HMAC signature for message authentication
    """
    expected_signature = generate_hmac_signature(data, secret_key)
    return hmac.compare_digest(expected_signature, signature)


class SecureTokenManager:
    """
    Manager for secure token operations with enterprise features
    """
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
    
    def generate_signed_token(self, payload: Dict[str, Any], expiry_minutes: int = 60) -> str:
        """
        Generate signed token with payload and expiry
        """
        import json
        import time
        
        # Add timestamp and expiry
        payload_with_meta = {
            **payload,
            "iat": int(time.time()),
            "exp": int(time.time() + (expiry_minutes * 60))
        }
        
        # Serialize payload
        payload_json = json.dumps(payload_with_meta, sort_keys=True)
        
        # Encode payload
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()
        
        # Generate signature
        signature = self.generate_hmac_signature(payload_b64, self.secret_key)
        
        # Combine payload and signature
        return f"{payload_b64}.{signature}"
    
    def verify_signed_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify signed token and return payload if valid
        """
        import json
        import time
        
        try:
            # Split token
            parts = token.split(".")
            if len(parts) != 2:
                return None
            
            payload_b64, signature = parts
            
            # Verify signature
            if not self.verify_hmac_signature(payload_b64, signature, self.secret_key):
                return None
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
            payload = json.loads(payload_json)
            
            # Check expiry
            if "exp" in payload and payload["exp"] < int(time.time()):
                return None
            
            return payload
            
        except Exception:
            return None
    
    def generate_hmac_signature(self, data: str, secret_key: str) -> str:
        """Generate HMAC signature"""
        return generate_hmac_signature(data, secret_key)
    
    def verify_hmac_signature(self, data: str, signature: str, secret_key: str) -> bool:
        """Verify HMAC signature"""
        return verify_hmac_signature(data, signature, secret_key)


# Utility functions for common crypto operations
def secure_compare(a: str, b: str) -> bool:
    """
    Timing-safe string comparison to prevent timing attacks
    """
    return hmac.compare_digest(a, b)


def generate_nonce(length: int = 16) -> str:
    """
    Generate cryptographic nonce for one-time use
    """
    return secrets.token_hex(length)


def generate_salt(length: int = 16) -> str:
    """
    Generate cryptographic salt for password hashing
    """
    return secrets.token_hex(length)