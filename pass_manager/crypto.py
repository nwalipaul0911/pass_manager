from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
KDF_ITERATIONS = 600_000


def default_vault_path() -> Path:
    override = os.environ.get("PASS_MANAGER_VAULT")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "share" / "pass_manager" / "vault.enc"


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_data(data: dict, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    fernet = Fernet(derive_key(password, salt))
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    token = fernet.encrypt(payload)
    return salt + token


def decrypt_data(blob: bytes, password: str) -> dict:
    if len(blob) < SALT_SIZE + 1:
        raise ValueError("Vault file is corrupted or empty.")
    salt, token = blob[:SALT_SIZE], blob[SALT_SIZE:]
    fernet = Fernet(derive_key(password, salt))
    try:
        payload = fernet.decrypt(token)
    except InvalidToken:
        raise ValueError("Invalid master password.") from None
    return json.loads(payload.decode("utf-8"))
