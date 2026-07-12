from datetime import datetime

from sqlalchemy import String, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class FailedLoginEvent(Base):

    __tablename__ = "failed_login_events"


    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )


    username: Mapped[str] = mapped_column(
        String,
        nullable=False
    )


    source_ip: Mapped[str] = mapped_column(
        String,
        nullable=False
    )


    failure_reason: Mapped[str] = mapped_column(
        String,
        nullable=True
    )


    status: Mapped[str] = mapped_column(
        String,
        nullable=True
    )


    sub_status: Mapped[str] = mapped_column(
        String,
        nullable=True
    )


    failed_time: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )