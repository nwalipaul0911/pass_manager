"""Data model for secret entries stored in a vault."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


SECRET_TYPES = ("password", "api_key", "note", "other")


def _utc_now() -> str:
    """Get the current UTC timestamp.

    Returns:
        The current time as an ISO 8601 string with timezone information.
    """
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SecretEntry:
    """Represent a vault item and its descriptive metadata.

    Args:
        name: Human-readable, unique entry name.
        secret_type: Entry category, normally one of :data:`SECRET_TYPES`.
        secret: The protected value, such as a password or API key.
        username: Optional associated username or email address.
        url: Optional related website or service URL.
        notes: Optional free-form text.
        tags: Optional list of labels for organizing or searching entries.
        id: Stable UUID string, generated when omitted.
        created_at: Creation timestamp; defaults to the current UTC time.
        updated_at: Last-modified timestamp; defaults to the current UTC time.

    Returns:
        A :class:`SecretEntry` instance containing the supplied values and
        defaults for omitted optional fields.
    """

    name: str
    secret_type: str
    secret: str
    username: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Convert all entry fields to a dictionary.

        Returns:
            A new dictionary containing every dataclass field, including the
            secret value, timestamps, ID, and metadata.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecretEntry:
        """Build an entry from a dictionary, applying defaults to optional keys.

        Args:
            data: Stored field values. ``name`` and ``secret`` are required;
                missing optional fields receive the model defaults.

        Returns:
            A new entry. Missing ``id`` values receive a new UUID; missing
            timestamps default to the current UTC time.

        Raises:
            KeyError: If ``name`` or ``secret`` is missing from ``data``.
        """
        return cls(
            id=data.get("id", str(uuid4())),
            name=data["name"],
            secret_type=data.get("secret_type", "password"),
            secret=data["secret"],
            username=data.get("username", ""),
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
            created_at=data.get("created_at", _utc_now()),
            updated_at=data.get("updated_at", _utc_now()),
        )

    def touch(self) -> None:
        """Refresh the entry's last-modified timestamp.

        Returns:
            ``None``. Updates ``updated_at`` to the current UTC time in ISO
            8601 format.
        """
        self.updated_at = _utc_now()
