from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class BehaviorProfile(Base):

    __tablename__ = "behavior_profiles"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    username: Mapped[str] = mapped_column(
        String,
        unique=True,
        index=True
    )

    login_count: Mapped[int] = mapped_column(
        Integer,
        default=0
    )

    common_ip: Mapped[str] = mapped_column(
        String,
        default=""
    )

    common_host: Mapped[str] = mapped_column(
        String,
        default=""
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