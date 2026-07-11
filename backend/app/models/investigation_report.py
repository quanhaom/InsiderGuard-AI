from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class InvestigationReport(Base):
    __tablename__ = "investigation_reports"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )

    incident_id: Mapped[int] = mapped_column(
        Integer,
        unique=True,
        index=True,
        nullable=False
    )

    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    analysis: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    recommendations: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    mitre_techniques: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]"
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False
    )

    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    prompt_snapshot: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )