from datetime import datetime
from app.models.normalized_windows_event import (
    NormalizedWindowsEvent
)
from sqlalchemy import (
    Integer,
    String,
    Text,
    DateTime,
    JSON,
)

from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from sqlalchemy.sql import func

from app.db.base import Base


class NormalizedWindowsEvent(Base):

    __tablename__ = "normalized_windows_events"


    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )


    raw_event_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True
    )


    event_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True
    )


    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )


    source_ip: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )


    computer: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )


    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )


    severity: Mapped[str] = mapped_column(
        String(50),
        default="LOW"
    )


    details: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now()
    )