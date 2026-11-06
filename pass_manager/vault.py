"""Vault storage operations and secure password generation."""

from __future__ import annotations

import secrets
import string
from pathlib import Path

from pass_manager.crypto import decrypt_data, default_vault_path, encrypt_data
from pass_manager.models import SECRET_TYPES, SecretEntry


class VaultError(Exception):
    """Signal an expected error while creating or using a vault.

    Args:
        *args: Optional exception message and values, forwarded to
            :class:`Exception`.

    Returns:
        A :class:`VaultError` instance whose string form is the supplied
        message, when provided.
    """

    pass


class Vault:
    """Manage the in-memory entries and encrypted file for one vault.

    Attributes:
        path: Filesystem path used to read and write the encrypted vault.
        exists: Whether a regular file currently exists at ``path``.
        is_unlocked: Whether decrypted entries are currently held in memory.

    The vault starts locked. Call :meth:`create` or :meth:`unlock` before
    methods that read or change entries.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Set up a locked vault instance without reading its file.

        Args:
            path: Optional vault file location. If omitted or ``None``, use
                :func:`pass_manager.crypto.default_vault_path`.

        Returns:
            ``None``. Initializes an empty in-memory entry map and locked state.
        """
        self.path = path or default_vault_path()
        self._entries: dict[str, SecretEntry] = {}
        self._unlocked = False

    @property
    def exists(self) -> bool:
        """Check whether the configured path currently names a regular file.

        Returns:
            ``True`` if the vault file exists; otherwise ``False``.
        """
        return self.path.is_file()

    @property
    def is_unlocked(self) -> bool:
        """Report whether this instance currently holds decrypted entries.

        Returns:
            ``True`` after a successful :meth:`create` or :meth:`unlock`,
            until :meth:`lock` is called; otherwise ``False``.
        """
        return self._unlocked

    def create(self, master_password: str) -> None:
        """Write a new empty encrypted vault and leave it unlocked.

        Args:
            master_password: Password used to derive the vault encryption key.

        Returns:
            ``None``. Creates parent directories as needed and writes the new
            encrypted file.

        Raises:
            VaultError: If a file already exists at the configured path.
            OSError: If the vault file cannot be written.
        """
        if self.exists:
            raise VaultError(f"Vault already exists at {self.path}")
        self._entries = {}
        self._save(master_password)
        self._unlocked = True

    def unlock(self, master_password: str) -> None:
        """Decrypt the configured file and load its entries into memory.

        Args:
            master_password: Password used to derive the decryption key.

        Returns:
            ``None``. On success, sets the instance's unlocked state to true.

        Raises:
            VaultError: If no vault file exists at the configured path.
            ValueError: If the file is malformed or the password is incorrect.
            OSError: If the file cannot be read.
        """
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
        """Clear this instance's decrypted entries and mark it locked.

        Returns:
            ``None``. The encrypted file on disk is not changed.
        """
        self._entries = {}
        self._unlocked = False

    def _save(self, master_password: str) -> None:
        """Serialize, encrypt, and write the current entries to disk.

        Args:
            master_password: Password used to derive the encryption key.

        Returns:
            ``None``. Creates parent directories and attempts to set file
            permissions to ``0600`` where supported.

        Raises:
            OSError: If the vault file cannot be written. Failure to change
                permissions alone is ignored.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"version": 1, "entries": [e.to_dict() for e in self._entries.values()]}
        self.path.write_bytes(encrypt_data(data, master_password))
        try:
            # Restrictive permissions are best-effort on platforms that support chmod.
            self.path.chmod(0o600)
        except OSError:
            pass

    def save(self, master_password: str) -> None:
        """Encrypt and persist the current entries if the vault is unlocked.

        Args:
            master_password: Password used to encrypt the saved vault.

        Returns:
            ``None`` after the encrypted file is written.

        Raises:
            VaultError: If this instance is locked.
            OSError: If the encrypted file cannot be written.
        """
        if not self._unlocked:
            raise VaultError("Vault is locked.")
        self._save(master_password)

    def add(self, entry: SecretEntry, master_password: str) -> SecretEntry:
        """Validate, add, and persist a new entry.

        Args:
            entry: Entry to add. Its type must be in :data:`SECRET_TYPES` and
                its name must be unique without regard to letter case.
            master_password: Password used to encrypt the updated vault.

        Returns:
            The same :class:`SecretEntry` object after it has been added.

        Raises:
            VaultError: If the vault is locked, the type is invalid, or another
                entry already has the same name.
            OSError: If the updated vault cannot be written.
        """
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
        """Find and return an entry by its case-insensitive name.

        Args:
            name: Name to look up.

        Returns:
            The matching :class:`SecretEntry`.

        Raises:
            VaultError: If the vault is locked or no entry has that name.
        """
        self._require_unlocked()
        entry = self._find_by_name(name)
        if not entry:
            raise VaultError(f"No secret named '{name}'.")
        return entry

    def list_entries(
        self, secret_type: str | None = None, query: str | None = None
    ) -> list[SecretEntry]:
        """List entries in name order with optional type and text filters.

        Args:
            secret_type: Optional exact type to include, such as ``"password"``
                or ``"api_key"``.
            query: Optional case-insensitive substring searched across names,
                usernames, URLs, notes, and tags.

        Returns:
            A new list of matching entries sorted by name, case-insensitively.

        Raises:
            VaultError: If the vault is locked.
        """
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
        """Change supported fields on an entry and persist the vault.

        Args:
            name: Current entry name used for lookup.
            master_password: Password used to encrypt the updated vault.
            **fields: Optional replacements for ``name``, ``secret_type``,
                ``secret``, ``username``, ``url``, ``notes``, and ``tags``.
                Unknown fields and values of ``None`` are ignored.

        Returns:
            The updated :class:`SecretEntry`, with its ``updated_at`` value
            refreshed.

        Raises:
            VaultError: If the vault is locked, the entry is missing, the new
                type is invalid, or the new name conflicts with another entry.
            OSError: If the updated vault cannot be written.
        """
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
        """Remove an entry by name and persist the updated vault.

        Args:
            name: Case-insensitive name of the entry to remove.
            master_password: Password used to encrypt the updated vault.

        Returns:
            ``None`` after the entry is removed and the vault is saved.

        Raises:
            VaultError: If the vault is locked or the entry does not exist.
            OSError: If the updated vault cannot be written.
        """
        self._require_unlocked()
        entry = self.get(name)
        del self._entries[entry.id]
        self._save(master_password)

    def _find_by_name(self, name: str) -> SecretEntry | None:
        """Search the current in-memory entries by case-insensitive name.

        Args:
            name: Name to compare with the entries currently in memory.

        Returns:
            The matching entry, or ``None`` if there is no match. This helper
            does not check whether the vault is unlocked.
        """
        name_lower = name.lower()
        for entry in self._entries.values():
            if entry.name.lower() == name_lower:
                return entry
        return None

    def _require_unlocked(self) -> None:
        """Ensure entry operations are performed on an unlocked vault.

        Returns:
            ``None`` if unlocked.

        Raises:
            VaultError: If the vault is locked.
        """
        if not self._unlocked:
            raise VaultError("Vault is locked. Unlock with your master password first.")


def generate_password(
    length: int = 20,
    symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> str:
    """Generate a cryptographically random password.

    Args:
        length: Number of characters to generate; must be at least 8.
        symbols: If true, include characters from the configured symbol set.
        exclude_ambiguous: If true, remove characters that are easy to confuse,
            such as ``0``, ``O``, ``1``, and ``l``.

    Returns:
        A randomly selected string of exactly ``length`` characters.

    Raises:
        ValueError: If ``length`` is less than 8.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8.")
    chars = string.ascii_letters + string.digits
    if symbols:
        chars += "!@#$%^&*()-_=+[]{}"
    if exclude_ambiguous:
        for ch in "0O1lI|`'\"\\;:":
            chars = chars.replace(ch, "")
    return "".join(secrets.choice(chars) for _ in range(length))
