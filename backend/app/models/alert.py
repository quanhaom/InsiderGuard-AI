from datetime import datetime

from sqlalchemy import (
    Integer,
    String,
    DateTime,
    Text
)

from sqlalchemy.orm import (
    Mapped,
    mapped_column
)

from app.db.base import Base


class Alert(Base):

    __tablename__ = "alerts"


    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )


    username: Mapped[str] = mapped_column(
        String,
        index=True
    )


    alert_type: Mapped[str] = mapped_column(
        String
    )


    severity: Mapped[str] = mapped_column(
        String
    )


    risk_score: Mapped[int] = mapped_column(
        Integer
    )


    reason: Mapped[str] = mapped_column(
        Text,
        nullable=True
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )