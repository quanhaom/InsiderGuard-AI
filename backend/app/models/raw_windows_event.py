from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Integer,
    String,
    Text
)

from sqlalchemy.orm import (
    Mapped,
    mapped_column
)

from sqlalchemy.sql import func

from app.db.base import Base



class RawWindowsEvent(Base):

    __tablename__ = "raw_windows_events"


    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )


    record_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        index=True
    )


    event_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True
    )


    computer: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )


    provider: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )


    source_ip: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )


    xml: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )


    parsed_status: Mapped[str] = mapped_column(
        String(50),
        default="RAW",
        nullable=False
    )


    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )