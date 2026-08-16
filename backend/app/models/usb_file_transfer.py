from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Integer,
    String,
)

from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from sqlalchemy.sql import func

from app.db.base import Base


class UsbFileTransfer(Base):
    __tablename__ = "usb_file_transfers"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    computer: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    device_id: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    drive_letter: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    file_path: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    file_name: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    extension: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    file_size: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
    )

    sha256_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="LOW",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )