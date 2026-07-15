from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    Integer,
    JSON,
    String,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from app.db.base import Base


class BehaviorProfile(Base):

    __tablename__ = "behavior_profiles"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True
    )

    # Existing

    login_count: Mapped[int] = mapped_column(
        Integer,
        default=0
    )

    common_ip: Mapped[str] = mapped_column(
        String(100),
        default=""
    )

    common_host: Mapped[str] = mapped_column(
        String(100),
        default=""
    )

    # New UEBA features

    avg_login_hour: Mapped[float] = mapped_column(
        Float,
        default=0
    )

    avg_failed_logins_per_day: Mapped[
        float
    ] = mapped_column(
        Float,
        default=0
    )

    known_ips: Mapped[list] = mapped_column(
        JSON,
        default=list
    )

    known_devices: Mapped[list] = mapped_column(
        JSON,
        default=list
    )

    risk_baseline: Mapped[float] = mapped_column(
        Float,
        default=0
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )

    last_login: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )