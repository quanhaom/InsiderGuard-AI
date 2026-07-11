from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class BlockchainBlock(Base):
    __tablename__ = "blockchain_blocks"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )

    block_index: Mapped[int] = mapped_column(
        Integer,
        unique=True,
        index=True,
        nullable=False
    )

    evidence_id: Mapped[int] = mapped_column(
        Integer,
        unique=True,
        index=True,
        nullable=False
    )

    evidence_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )

    previous_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )

    block_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False
    )

    nonce: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )