from datetime import datetime

from sqlalchemy import Integer, String, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RiskAssessment(Base):

    __tablename__ = "risk_assessments"


    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )


    username: Mapped[str] = mapped_column(
        String,
        index=True
    )


    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0
    )


    reason: Mapped[str] = mapped_column(
        Text,
        nullable=True
    )


    severity: Mapped[str] = mapped_column(
        String,
        default="LOW"
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )