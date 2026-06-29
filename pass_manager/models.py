from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


SECRET_TYPES = ("password", "api_key", "note", "other")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SecretEntry:
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
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecretEntry:
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
        self.updated_at = _utc_now()
