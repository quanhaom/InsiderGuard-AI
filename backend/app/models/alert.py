from datetime import datetime

from sqlalchemy import String, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Alert(Base):

    __tablename__ = "alerts"


    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )


    alert_type: Mapped[str] = mapped_column(
        String,
        nullable=False
    )


    severity: Mapped[str] = mapped_column(
        String,
        nullable=False
    )


    username: Mapped[str] = mapped_column(
        String,
        nullable=True
    )


    source_ip: Mapped[str] = mapped_column(
        String,
        nullable=True
    )


    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )