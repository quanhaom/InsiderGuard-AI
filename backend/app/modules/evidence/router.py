import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.evidence.service import EvidenceService
from app.modules.incidents.service import IncidentService
from app.schemas.evidence import (
    EvidenceResponse,
    EvidenceVerificationResponse,
)


router = APIRouter(
    prefix="/evidence",
    tags=["Evidence"]
)


def serialize_evidence(evidence) -> dict:
    return {
        "id": evidence.id,
        "incident_id": evidence.incident_id,
        "username": evidence.username,
        "evidence_type": evidence.evidence_type,
        "snapshot": json.loads(evidence.snapshot_json),
        "sha256_hash": evidence.sha256_hash,
        "created_at": evidence.created_at
    }


@router.post(
    "/incident/{incident_id}",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED
)
def create_incident_evidence(
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

    evidence = EvidenceService.create_from_incident(
        db=db,
        incident=incident
    )

    return serialize_evidence(evidence)


@router.get(
    "/{evidence_id}",
    response_model=EvidenceResponse
)
def get_evidence(
    evidence_id: int,
    db: Session = Depends(get_db)
):
    evidence = EvidenceService.get_evidence(
        db=db,
        evidence_id=evidence_id
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )

    return serialize_evidence(evidence)


@router.get(
    "/incident/{incident_id}/all",
    response_model=list[EvidenceResponse]
)
def get_incident_evidence(
    incident_id: int,
    db: Session = Depends(get_db)
):
    evidences = EvidenceService.get_incident_evidence(
        db=db,
        incident_id=incident_id
    )

    return [
        serialize_evidence(evidence)
        for evidence in evidences
    ]


@router.get(
    "/{evidence_id}/verify",
    response_model=EvidenceVerificationResponse
)
def verify_evidence(
    evidence_id: int,
    db: Session = Depends(get_db)
):
    evidence = EvidenceService.get_evidence(
        db=db,
        evidence_id=evidence_id
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )

    calculated_hash, is_valid = (
        EvidenceService.verify_evidence(evidence)
    )

    return {
        "evidence_id": evidence.id,
        "stored_hash": evidence.sha256_hash,
        "calculated_hash": calculated_hash,
        "is_valid": is_valid
    }