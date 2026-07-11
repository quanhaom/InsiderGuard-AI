from datetime import datetime

from sqlalchemy import String
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey

from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from app.db.base import Base


class LoginEvent(Base):

    __tablename__ = "login_events"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )

    username: Mapped[str] = mapped_column(
        String(100)
    )

    source_ip: Mapped[str] = mapped_column(
        String(100)
    )

    login_time: Mapped[datetime] = mapped_column(
        DateTime
    )