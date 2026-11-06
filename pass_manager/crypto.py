"""Key derivation and encryption helpers for the on-disk vault format."""

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
    """Choose the vault path configured by the user or the default location.

    Returns:
        The expanded path from ``PASS_MANAGER_VAULT`` when set; otherwise,
        ``~/.local/share/pass_manager/vault.enc`` under the current home
        directory.
    """
    override = os.environ.get("PASS_MANAGER_VAULT")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "share" / "pass_manager" / "vault.enc"


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key using PBKDF2-HMAC-SHA256.

    Args:
        password: Master password encoded as UTF-8 before derivation.
        salt: Per-vault random salt used as the KDF salt.

    Returns:
        A URL-safe base64-encoded 32-byte key accepted by Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_data(data: dict, password: str) -> bytes:
    """Serialize data as compact JSON and encrypt it with a derived key.

    Args:
        data: JSON-serializable dictionary to protect.
        password: Master password used to derive the encryption key.

    Returns:
        Bytes containing a new random salt followed by the Fernet token.

    Raises:
        TypeError: If ``data`` cannot be serialized as JSON.
    """
    salt = os.urandom(SALT_SIZE)
    fernet = Fernet(derive_key(password, salt))
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    token = fernet.encrypt(payload)
    return salt + token


def decrypt_data(blob: bytes, password: str) -> dict:
    """Decrypt a salted vault blob and parse its JSON payload.

    Args:
        blob: Bytes containing the salt prefix and encrypted Fernet token.
        password: Master password used to derive the decryption key.

    Returns:
        The decrypted JSON object as a dictionary.

    Raises:
        ValueError: If the blob is too short or authentication fails, including
            when the password is incorrect.
        UnicodeDecodeError: If the decrypted bytes are not valid UTF-8.
        json.JSONDecodeError: If the decrypted text is not valid JSON.
    """
    if len(blob) < SALT_SIZE + 1:
        raise ValueError("Vault file is corrupted or empty.")
    salt, token = blob[:SALT_SIZE], blob[SALT_SIZE:]
    fernet = Fernet(derive_key(password, salt))
    try:
        payload = fernet.decrypt(token)
    except InvalidToken:
        raise ValueError("Invalid master password.") from None
    return json.loads(payload.decode("utf-8"))
