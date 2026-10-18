import hashlib
import hmac
import secrets
import base64
import time
from typing import Optional, Tuple
from backend.app.config import settings

PBKDF2_ITERATIONS = 100_000
SALT_BYTES = 16

def generate_salt() -> str:
    """Generate a cryptographically secure 16-byte random salt as hex."""
    return secrets.token_hex(SALT_BYTES)

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Returns (hashed_password_hex, salt_hex).
    Architecture-neutral, portable to IBM LinuxONE (s390x) and x86.
    """
    if not salt:
        salt = generate_salt()
    
    salt_bytes = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        PBKDF2_ITERATIONS
    )
    return dk.hex(), salt

def verify_password(plain_password: str, hashed_password: str, salt: str) -> bool:
    """
    Verifies a plain password against the stored hash and salt using constant-time comparison.
    """
    try:
        salt_bytes = bytes.fromhex(salt)
        expected_dk = bytes.fromhex(hashed_password)
        actual_dk = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt_bytes,
            PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(actual_dk, expected_dk)
    except Exception:
        return False

# In-memory token store for prototype session management (mapped to user_id, expires_at)
# In high-volume production on IBM LinuxONE, this can be backed by Redis or Db2 session store.
_SESSION_STORE = {}

def create_access_token(user_id: int, role: str) -> str:
    """
    Generates an opaque cryptographic bearer token and records active session.
    """
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + (settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    _SESSION_STORE[token] = {
        "user_id": user_id,
        "role": role,
        "expires_at": expires_at
    }
    return token

def validate_token(token: str) -> Optional[dict]:
    """
    Validates a bearer token. Returns payload dict if valid, else None.
    Prunes expired tokens.
    """
    session = _SESSION_STORE.get(token)
    if not session:
        return None
    if time.time() > session["expires_at"]:
        _SESSION_STORE.pop(token, None)
        return None
    return session

def revoke_token(token: str) -> bool:
    """Revokes an active session token."""
    return _SESSION_STORE.pop(token, None) is not None
