import json
from typing import Any

from sqlalchemy.orm import Session

from app.models.evidence import Evidence
from app.models.incident import Incident
from app.models.risk_assessment import RiskAssessment
from app.modules.evidence.hash_service import EvidenceHashService
from app.repositories.behavior_profile_repository import (
    BehaviorProfileRepository,
)
from app.repositories.evidence_repository import EvidenceRepository
from app.repositories.risk_repository import RiskRepository


class EvidenceService:

    DEFAULT_EVIDENCE_TYPE = "INCIDENT_SNAPSHOT"

    @classmethod
    def create_from_incident(
        cls,
        db: Session,
        incident: Incident
    ) -> Evidence:
        already_exists = EvidenceRepository.exists_for_incident(
            db=db,
            incident_id=incident.id,
            evidence_type=cls.DEFAULT_EVIDENCE_TYPE
        )

        if already_exists:
            existing = EvidenceRepository.get_by_incident_id(
                db=db,
                incident_id=incident.id
            )

            return existing[0]

        assessment = (
            db.query(RiskAssessment)
            .filter(
                RiskAssessment.id
                == incident.risk_assessment_id
            )
            .first()
        )

        profile = BehaviorProfileRepository.get_by_username(
            db=db,
            username=incident.username
        )

        snapshot = cls._build_snapshot(
            incident=incident,
            assessment=assessment,
            profile=profile
        )

        snapshot_json = EvidenceHashService.normalize_snapshot(
            snapshot
        )

        sha256_hash = EvidenceHashService.generate_hash(
            snapshot
        )

        evidence = Evidence(
            incident_id=incident.id,
            username=incident.username,
            evidence_type=cls.DEFAULT_EVIDENCE_TYPE,
            snapshot_json=snapshot_json,
            sha256_hash=sha256_hash
        )

        return EvidenceRepository.create(
            db=db,
            evidence=evidence
        )

    @staticmethod
    def _build_snapshot(
        incident: Incident,
        assessment: RiskAssessment | None,
        profile: Any
    ) -> dict[str, Any]:
        reasons: list[str] = []

        if assessment is not None:
            try:
                reasons = json.loads(assessment.reasons)
            except (json.JSONDecodeError, TypeError):
                reasons = []

        snapshot: dict[str, Any] = {
            "incident": {
                "id": incident.id,
                "username": incident.username,
                "risk_assessment_id": (
                    incident.risk_assessment_id
                ),
                "title": incident.title,
                "severity": incident.severity,
                "description": incident.description,
                "status": incident.status,
                "detected_at": incident.detected_at
            },
            "risk_assessment": None,
            "behavior_profile": None,
            "indicators": reasons
        }

        if assessment is not None:
            snapshot["risk_assessment"] = {
                "id": assessment.id,
                "username": assessment.username,
                "risk_score": assessment.risk_score,
                "risk_level": assessment.risk_level,
                "reasons": reasons,
                "created_at": assessment.created_at
            }

        if profile is not None:
            snapshot["behavior_profile"] = {
                "id": profile.id,
                "username": profile.username,
                "avg_login_hour": profile.avg_login_hour,
                "total_logins": profile.total_logins,
                "common_source_ip": (
                    profile.common_source_ip
                ),
                "first_login_at": profile.first_login_at,
                "last_login_at": profile.last_login_at,
                "last_updated": profile.last_updated
            }

        return snapshot

    @staticmethod
    def get_evidence(
        db: Session,
        evidence_id: int
    ) -> Evidence | None:
        return EvidenceRepository.get_by_id(
            db=db,
            evidence_id=evidence_id
        )

    @staticmethod
    def get_incident_evidence(
        db: Session,
        incident_id: int
    ) -> list[Evidence]:
        return EvidenceRepository.get_by_incident_id(
            db=db,
            incident_id=incident_id
        )

    @staticmethod
    def verify_evidence(
        evidence: Evidence
    ) -> tuple[str, bool]:
        snapshot = json.loads(evidence.snapshot_json)

        calculated_hash = EvidenceHashService.generate_hash(
            snapshot
        )

        return (
            calculated_hash,
            calculated_hash == evidence.sha256_hash
        )