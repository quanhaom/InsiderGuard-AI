from fastapi import (
    APIRouter,
    Depends,
)

from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.models.incident import Incident


router = APIRouter(
    prefix="/dashboard",
    tags=[
        "Dashboard"
    ]
)


@router.get(
    "/incident-summary"
)
def incident_summary(
    db: Session = Depends(get_db),
):

    total = (
        db.query(Incident)
        .count()
    )


    open_count = (
        db.query(Incident)
        .filter(
            Incident.status == "OPEN"
        )
        .count()
    )


    investigating = (
        db.query(Incident)
        .filter(
            Incident.status
            == "INVESTIGATING"
        )
        .count()
    )


    resolved = (
        db.query(Incident)
        .filter(
            Incident.status
            == "RESOLVED"
        )
        .count()
    )


    closed = (
        db.query(Incident)
        .filter(
            Incident.status
            == "CLOSED"
        )
        .count()
    )


    return {

        "total": total,

        "open": open_count,

        "investigating": investigating,

        "resolved": resolved,

        "closed": closed,

    }



@router.get(
    "/recent-incidents"
)
def recent_incidents(
    db: Session = Depends(get_db),
):

    incidents = (
        db.query(Incident)

        .order_by(
            Incident.created_at.desc()
        )

        .limit(10)

        .all()
    )


    return incidents