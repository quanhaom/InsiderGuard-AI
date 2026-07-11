import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.investigator.service import InvestigatorService
from app.schemas.investigation import InvestigationReportResponse


router = APIRouter(
    prefix="/investigator",
    tags=["AI Investigator"]
)


def serialize_report(report) -> dict:
    try:
        recommendations = json.loads(report.recommendations)
    except (json.JSONDecodeError, TypeError):
        recommendations = []

    try:
        mitre_techniques = json.loads(report.mitre_techniques)
    except (json.JSONDecodeError, TypeError):
        mitre_techniques = []

    return {
        "id": report.id,
        "incident_id": report.incident_id,
        "summary": report.summary,
        "analysis": report.analysis,
        "recommendations": recommendations,
        "mitre_techniques": mitre_techniques,
        "confidence": report.confidence,
        "model_name": report.model_name,
        "created_at": report.created_at
    }


@router.post(
    "/incident/{incident_id}/generate",
    response_model=InvestigationReportResponse,
    status_code=status.HTTP_201_CREATED
)
def generate_investigation_report(
    incident_id: int,
    db: Session = Depends(get_db)
):
    try:
        report = InvestigatorService.generate_report(
            db=db,
            incident_id=incident_id
        )

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error)
        ) from error

    return serialize_report(report)


@router.post(
    "/incident/{incident_id}/regenerate",
    response_model=InvestigationReportResponse
)
def regenerate_investigation_report(
    incident_id: int,
    db: Session = Depends(get_db)
):
    try:
        report = InvestigatorService.regenerate_report(
            db=db,
            incident_id=incident_id
        )

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error)
        ) from error

    return serialize_report(report)


@router.get(
    "/reports/{report_id}",
    response_model=InvestigationReportResponse
)
def get_report(
    report_id: int,
    db: Session = Depends(get_db)
):
    report = InvestigatorService.get_report(
        db=db,
        report_id=report_id
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation report not found"
        )

    return serialize_report(report)


@router.get(
    "/incident/{incident_id}",
    response_model=InvestigationReportResponse
)
def get_incident_report(
    incident_id: int,
    db: Session = Depends(get_db)
):
    report = InvestigatorService.get_incident_report(
        db=db,
        incident_id=incident_id
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation report not found"
        )

    return serialize_report(report)