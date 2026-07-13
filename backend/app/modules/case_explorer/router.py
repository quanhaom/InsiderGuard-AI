from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.case_explorer.service import (
    CaseExplorerService,
)

from datetime import datetime
from app.models.incident import Incident

from pydantic import BaseModel


class IncidentStatusUpdate(BaseModel):
    status: str

router = APIRouter(
    prefix="/case-explorer",
    tags=["Case Explorer"],
)


@router.get("/incidents")
def list_incidents(
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    status_filter: str | None = Query(
        default=None,
        alias="status",
    ),
    severity: str | None = Query(
        default=None
    ),
    username: str | None = Query(
        default=None
    ),
    db: Session = Depends(get_db),
):
    return CaseExplorerService.list_incidents(
        db=db,
        page=page,
        page_size=page_size,
        status=status_filter,
        severity=severity,
        username=username,
    )


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = (
        CaseExplorerService.get_incident(
            db=db,
            incident_id=incident_id,
        )
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return incident


@router.get("/evidences")
def list_evidences(
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    incident_id: int | None = Query(
        default=None
    ),
    username: str | None = Query(
        default=None
    ),
    evidence_type: str | None = Query(
        default=None
    ),
    db: Session = Depends(get_db),
):
    return CaseExplorerService.list_evidences(
        db=db,
        page=page,
        page_size=page_size,
        incident_id=incident_id,
        username=username,
        evidence_type=evidence_type,
    )


@router.get("/evidences/{evidence_id}")
def get_evidence(
    evidence_id: int,
    db: Session = Depends(get_db),
):
    evidence = (
        CaseExplorerService.get_evidence(
            db=db,
            evidence_id=evidence_id,
        )
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )



    return evidence


@router.patch("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
):
    allowed_statuses = {
        "OPEN",
        "IN_PROGRESS",
        "CONTAINED",
        "RESOLVED",
        "FALSE_POSITIVE",
    }

    new_status = payload.status.upper()

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid incident status",
        )

    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    incident.status = new_status

    if new_status in {
        "RESOLVED",
        "FALSE_POSITIVE",
    }:
        incident.closed_at = datetime.utcnow()
    else:
        incident.closed_at = None

    db.commit()
    db.refresh(incident)

    return {
        "id": incident.id,
        "status": incident.status,
        "closed_at": incident.closed_at,
    }

@router.get("/incidents/unresolved-count")
def get_unresolved_incident_count(
    db: Session = Depends(get_db),
):
    unresolved_statuses = [
        "OPEN",
        "IN_PROGRESS",
        "CONTAINED",
    ]

    count = (
        db.query(Incident)
        .filter(
            Incident.status.in_(
                unresolved_statuses
            )
        )
        .count()
    )

    return {
        "count": count
    }