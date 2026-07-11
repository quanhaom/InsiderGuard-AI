from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.incidents.service import IncidentService
from app.schemas.incident import (
    IncidentResponse,
    IncidentStatusUpdate,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"]
)


@router.get(
    "",
    response_model=list[IncidentResponse]
)
def get_all_incidents(
    db: Session = Depends(get_db)
):
    return IncidentService.get_all_incidents(db=db)


@router.get(
    "/user/{username}",
    response_model=list[IncidentResponse]
)
def get_user_incidents(
    username: str,
    db: Session = Depends(get_db)
):
    return IncidentService.get_user_incidents(
        db=db,
        username=username
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse
)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    incident = IncidentService.get_incident(
        db=db,
        incident_id=incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )

    return incident


@router.patch(
    "/{incident_id}/status",
    response_model=IncidentResponse
)
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db)
):
    incident = IncidentService.get_incident(
        db=db,
        incident_id=incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )

    try:
        return IncidentService.update_status(
            db=db,
            incident=incident,
            new_status=payload.status
        )

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error)
        ) from error