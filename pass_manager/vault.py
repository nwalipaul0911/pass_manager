from __future__ import annotations

import secrets
import string
from pathlib import Path

from pass_manager.crypto import decrypt_data, default_vault_path, encrypt_data
from pass_manager.models import SECRET_TYPES, SecretEntry


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_vault_path()
        self._entries: dict[str, SecretEntry] = {}
        self._unlocked = False

    @property
    def exists(self) -> bool:
        return self.path.is_file()

    @property
    def is_unlocked(self) -> bool:
        return self._unlocked

    def create(self, master_password: str) -> None:
        if self.exists:
            raise VaultError(f"Vault already exists at {self.path}")
        self._entries = {}
        self._save(master_password)
        self._unlocked = True

    def unlock(self, master_password: str) -> None:
        if not self.exists:
            raise VaultError(
                f"No vault found at {self.path}. Run 'pass-manager init' first."
            )
        data = decrypt_data(self.path.read_bytes(), master_password)
        self._entries = {
            entry["id"]: SecretEntry.from_dict(entry)
            for entry in data.get("entries", [])
        }
        self._unlocked = True

    def lock(self) -> None:
        self._entries = {}
        self._unlocked = False

    def _save(self, master_password: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"version": 1, "entries": [e.to_dict() for e in self._entries.values()]}
        self.path.write_bytes(encrypt_data(data, master_password))
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def save(self, master_password: str) -> None:
        if not self._unlocked:
            raise VaultError("Vault is locked.")
        self._save(master_password)

    def add(self, entry: SecretEntry, master_password: str) -> SecretEntry:
        self._require_unlocked()
        if entry.secret_type not in SECRET_TYPES:
            raise VaultError(
                f"Invalid type '{entry.secret_type}'. "
                f"Choose from: {', '.join(SECRET_TYPES)}"
            )
        if self._find_by_name(entry.name):
            raise VaultError(f"A secret named '{entry.name}' already exists.")
        self._entries[entry.id] = entry
        self._save(master_password)
        return entry

    def get(self, name: str) -> SecretEntry:
        self._require_unlocked()
        entry = self._find_by_name(name)
        if not entry:
            raise VaultError(f"No secret named '{name}'.")
        return entry

    def list_entries(
        self, secret_type: str | None = None, query: str | None = None
    ) -> list[SecretEntry]:
        self._require_unlocked()
        entries = sorted(self._entries.values(), key=lambda e: e.name.lower())
        if secret_type:
            entries = [e for e in entries if e.secret_type == secret_type]
        if query:
            q = query.lower()
            entries = [
                e
                for e in entries
                if q in e.name.lower()
                or q in e.username.lower()
                or q in e.url.lower()
                or q in e.notes.lower()
                or any(q in tag.lower() for tag in e.tags)
            ]
        return entries

    def update(self, name: str, master_password: str, **fields) -> SecretEntry:
        self._require_unlocked()
        entry = self.get(name)
        allowed = {"name", "secret_type", "secret", "username", "url", "notes", "tags"}
        for key, value in fields.items():
            if key not in allowed or value is None:
                continue
            if key == "secret_type" and value not in SECRET_TYPES:
                raise VaultError(
                    f"Invalid type '{value}'. Choose from: {', '.join(SECRET_TYPES)}"
                )
            setattr(entry, key, value)
        if "name" in fields and fields["name"] and fields["name"] != name:
            conflict = self._find_by_name(fields["name"])
            if conflict and conflict.id != entry.id:
                raise VaultError(f"A secret named '{fields['name']}' already exists.")
        entry.touch()
        self._save(master_password)
        return entry

    def delete(self, name: str, master_password: str) -> None:
        self._require_unlocked()
        entry = self.get(name)
        del self._entries[entry.id]
        self._save(master_password)

    def _find_by_name(self, name: str) -> SecretEntry | None:
        name_lower = name.lower()
        for entry in self._entries.values():
            if entry.name.lower() == name_lower:
                return entry
        return None

    def _require_unlocked(self) -> None:
        if not self._unlocked:
            raise VaultError("Vault is locked. Unlock with your master password first.")


def generate_password(
    length: int = 20,
    symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> str:
    if length < 8:
        raise ValueError("Password length must be at least 8.")
    chars = string.ascii_letters + string.digits
    if symbols:
        chars += "!@#$%^&*()-_=+[]{}"
    if exclude_ambiguous:
        for ch in "0O1lI|`'\"\\;:":
            chars = chars.replace(ch, "")
    return "".join(secrets.choice(chars) for _ in range(length))
