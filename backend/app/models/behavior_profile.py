from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class BehaviorProfile(Base):
    __tablename__ = "behavior_profiles"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )

    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True
    )

    avg_login_hour: Mapped[float] = mapped_column(
        Float,
        default=0.0
    )

    total_logins: Mapped[int] = mapped_column(
        Integer,
        default=0
    )

    common_source_ip: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    first_login_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )

    last_updated: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )