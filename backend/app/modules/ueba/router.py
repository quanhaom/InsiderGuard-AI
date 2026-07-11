import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.ueba.service import UebaService
from app.schemas.risk import (
    LoginRiskEvaluationRequest,
    RiskAssessmentResponse,
)


router = APIRouter(
    prefix="/ueba",
    tags=["UEBA"]
)


def serialize_assessment(assessment) -> dict:
    try:
        reasons = json.loads(assessment.reasons)
    except (json.JSONDecodeError, TypeError):
        reasons = []

    return {
        "id": assessment.id,
        "username": assessment.username,
        "risk_score": assessment.risk_score,
        "risk_level": assessment.risk_level,
        "reasons": reasons,
        "created_at": assessment.created_at
    }


@router.post(
    "/evaluate/{username}",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_201_CREATED
)
def evaluate_login_risk(
    username: str,
    payload: LoginRiskEvaluationRequest,
    db: Session = Depends(get_db)
):
    try:
        assessment = UebaService.evaluate_login(
            db=db,
            username=username,
            payload=payload
        )

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error)
        ) from error

    return serialize_assessment(assessment)


@router.get(
    "/latest/{username}",
    response_model=RiskAssessmentResponse
)
def get_latest_risk(
    username: str,
    db: Session = Depends(get_db)
):
    assessment = UebaService.get_latest(
        db=db,
        username=username
    )

    if assessment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No risk assessment found for '{username}'"
            )
        )

    return serialize_assessment(assessment)


@router.get(
    "/history/{username}",
    response_model=list[RiskAssessmentResponse]
)
def get_risk_history(
    username: str,
    db: Session = Depends(get_db)
):
    assessments = UebaService.get_history(
        db=db,
        username=username
    )

    return [
        serialize_assessment(item)
        for item in assessments
    ]