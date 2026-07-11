from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Evidence(Base):
    __tablename__ = "evidences"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )

    incident_id: Mapped[int] = mapped_column(
        Integer,
        index=True,
        nullable=False
    )

    username: Mapped[str] = mapped_column(
        String(100),
        index=True,
        nullable=False
    )

    evidence_type: Mapped[str] = mapped_column(
        String(50),
        default="INCIDENT_SNAPSHOT",
        nullable=False
    )

    snapshot_json: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    sha256_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )