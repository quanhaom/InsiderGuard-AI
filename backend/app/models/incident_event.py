from datetime import datetime

from sqlalchemy import (
    Integer,
    String,
    DateTime,
    ForeignKey,
    Text,
    JSON,
)

from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from app.db.base import Base



class IncidentEvent(Base):

    __tablename__ = "incident_events"


    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )


    incident_id: Mapped[int] = mapped_column(
        ForeignKey(
            "incidents.id"
        ),
        nullable=False
    )


    event_type: Mapped[str] = mapped_column(
        String(100)
    )


    actor_type: Mapped[str] = mapped_column(
        String(50),
        default="SYSTEM"
    )


    actor_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )


    description: Mapped[str] = mapped_column(
        Text
    )


    old_status: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )


    new_status: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )


    event_metadata: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )