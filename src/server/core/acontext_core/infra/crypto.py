"""
Envelope encryption module compatible with the Go API implementation.

Uses HKDF-SHA256 for key derivation and AES-256-GCM for encryption.
All wrapped DEK and ciphertext formats are: nonce (12 bytes) + ciphertext.

User KEK only — the admin KEK has been removed. Encryption is driven by
the caller passing a user KEK derived from the raw API key + pepper.
"""

import os
import base64
from typing import Optional, Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # AES-GCM nonce

# Must match Go constants in internal/infra/crypto/service.go
_USER_KEK_SALT = b"acontext-user-kek"
_USER_KEK_INFO = b"acontext envelope encryption user KEK"


def derive_kek(secret: bytes, salt: bytes, info: bytes) -> bytes:
    """Derive a KEK using HKDF-SHA256 (compatible with Go's golang.org/x/crypto/hkdf)."""
    if not secret:
        raise ValueError("secret is empty")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=info,
    )
    return hkdf.derive(secret)


def derive_user_kek(api_key_raw: str, pepper: str) -> bytes:
    """Derive the user KEK from the raw API key and pepper.

    Mirrors the Go implementation: HKDF-SHA256 over (apiKeyRaw + pepper)
    with userKEKSalt and userKEKInfo.
    """
    secret = (api_key_raw + pepper).encode()
    return derive_kek(secret, _USER_KEK_SALT, _USER_KEK_INFO)


def generate_dek() -> bytes:
    """Generate a random 256-bit DEK."""
    return os.urandom(KEY_SIZE)


def wrap_dek(kek: bytes, dek: bytes) -> bytes:
    """Wrap (encrypt) a DEK with a KEK using AES-256-GCM. Returns nonce + ciphertext."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(kek)
    ct = aesgcm.encrypt(nonce, dek, None)
    return nonce + ct


def unwrap_dek(kek: bytes, wrapped_dek: bytes) -> bytes:
    """Unwrap (decrypt) a DEK. Expects nonce + ciphertext."""
    if len(wrapped_dek) < NONCE_SIZE:
        raise ValueError("wrapped DEK too short")
    nonce = wrapped_dek[:NONCE_SIZE]
    ct = wrapped_dek[NONCE_SIZE:]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ct, None)


def encrypt(dek: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM. Returns nonce + ciphertext."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(dek)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt(dek: bytes, ciphertext_with_nonce: bytes) -> bytes:
    """Decrypt ciphertext. Expects nonce + ciphertext."""
    if len(ciphertext_with_nonce) < NONCE_SIZE:
        raise ValueError("ciphertext too short")
    nonce = ciphertext_with_nonce[:NONCE_SIZE]
    ct = ciphertext_with_nonce[NONCE_SIZE:]
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ct, None)


def encrypt_data(user_kek: bytes, plaintext: bytes) -> Tuple[bytes, Dict[str, str]]:
    """Encrypt data using envelope encryption with the user KEK.

    Returns (ciphertext, metadata_dict) where metadata_dict contains
    "enc-algo" and "enc-dek-user".
    """
    dek = generate_dek()
    ciphertext = encrypt(dek, plaintext)
    user_wrapped = wrap_dek(user_kek, dek)
    meta = {
        "enc-algo": "AES-256-GCM",
        "enc-dek-user": base64.b64encode(user_wrapped).decode(),
    }
    return ciphertext, meta


def decrypt_data(user_kek: bytes, ciphertext: bytes, enc_meta: Dict[str, str]) -> bytes:
    """Decrypt data using envelope encryption with the user KEK.

    Unwraps the DEK from enc_meta["enc-dek-user"], then decrypts.
    """
    wrapped_b64 = enc_meta.get("enc-dek-user", "")
    if not wrapped_b64:
        raise ValueError("enc-dek-user missing from encryption metadata")
    wrapped = base64.b64decode(wrapped_b64)
    dek = unwrap_dek(user_kek, wrapped)
    return decrypt(dek, ciphertext)


def metadata_from_map(metadata: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Extract encryption metadata from S3 object metadata.
    Returns None if the object is not encrypted (no "enc-algo" key)."""
    algo = metadata.get("enc-algo", "")
    if not algo:
        return None
    return {
        "enc-algo": algo,
        "enc-dek-user": metadata.get("enc-dek-user", ""),
    }
