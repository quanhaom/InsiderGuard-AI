from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert
from app.models.evidence import Evidence
from app.models.failed_login_event import FailedLoginEvent
from app.models.incident import Incident
from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


@router.get("/overview")
def get_overview(
    db: Session = Depends(get_db),
) -> dict:
    login_events = (
        db.query(func.count(LoginEvent.id))
        .scalar()
        or 0
    )

    failed_logins = (
        db.query(func.count(FailedLoginEvent.id))
        .scalar()
        or 0
    )

    alerts = (
        db.query(func.count(Alert.id))
        .scalar()
        or 0
    )

    open_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.status == "OPEN")
        .scalar()
        or 0
    )

    high_risk_users = (
        db.query(func.count(func.distinct(
            RiskAssessment.username
        )))
        .filter(RiskAssessment.risk_score >= 80)
        .scalar()
        or 0
    )

    evidence_count = (
        db.query(func.count(Evidence.id))
        .scalar()
        or 0
    )

    return {
        "login_events": login_events,
        "failed_logins": failed_logins,
        "alerts": alerts,
        "open_incidents": open_incidents,
        "high_risk_users": high_risk_users,
        "evidence_count": evidence_count,
    }


@router.get("/recent-alerts")
def get_recent_alerts(
    limit: int = 10,
    db: Session = Depends(get_db),
) -> list[dict]:
    alerts = (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": alert.id,
            "username": alert.username,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "reason": alert.reason,
            "created_at": alert.created_at,
        }
        for alert in alerts
    ]


@router.get("/open-incidents")
def get_open_incidents(
    limit: int = 10,
    db: Session = Depends(get_db),
) -> list[dict]:
    incidents = (
        db.query(Incident)
        .filter(Incident.status == "OPEN")
        .order_by(Incident.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": incident.id,
            "alert_id": incident.alert_id,
            "username": incident.username,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "description": incident.description,
            "created_at": incident.created_at,
        }
        for incident in incidents
    ]


@router.get("/risk-timeline")
def get_risk_timeline(
    limit: int = 20,
    db: Session = Depends(get_db),
) -> list[dict]:
    assessments = (
        db.query(RiskAssessment)
        .order_by(RiskAssessment.created_at.desc())
        .limit(limit)
        .all()
    )

    assessments.reverse()

    return [
        {
            "id": assessment.id,
            "username": assessment.username,
            "risk_score": assessment.risk_score,
            "severity": assessment.severity,
            "reason": assessment.reason,
            "created_at": assessment.created_at,
        }
        for assessment in assessments
    ]


@router.get("/evidence-status")
def get_evidence_status(
    db: Session = Depends(get_db),
) -> dict:
    total = (
        db.query(func.count(Evidence.id))
        .scalar()
        or 0
    )

    hashed = (
        db.query(func.count(Evidence.id))
        .filter(Evidence.sha256_hash.isnot(None))
        .scalar()
        or 0
    )

    return {
        "total_evidence": total,
        "hashed_evidence": hashed,
        "integrity_status": (
            "VERIFIED"
            if total == hashed
            else "CHECK_REQUIRED"
        ),
    }