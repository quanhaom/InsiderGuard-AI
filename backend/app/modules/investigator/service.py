import json
from typing import Any

from sqlalchemy.orm import Session

from app.models.investigation_report import InvestigationReport
from app.modules.blockchain.service import BlockchainService
from app.modules.investigator.llm import (
    LLMProvider,
    MockInvestigationLLM,
)
from app.modules.investigator.prompt_builder import (
    InvestigationPromptBuilder,
)
from app.repositories.evidence_repository import EvidenceRepository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.investigation_repository import (
    InvestigationRepository,
)


class InvestigatorService:

    @staticmethod
    def _serialize_incident(incident) -> dict[str, Any]:
        return {
            "id": incident.id,
            "username": incident.username,
            "risk_assessment_id": incident.risk_assessment_id,
            "title": incident.title,
            "severity": incident.severity,
            "description": incident.description,
            "status": incident.status,
            "detected_at": incident.detected_at,
            "resolved_at": incident.resolved_at
        }

    @staticmethod
    def _serialize_evidence(evidence) -> dict[str, Any]:
        return {
            "id": evidence.id,
            "incident_id": evidence.incident_id,
            "username": evidence.username,
            "evidence_type": evidence.evidence_type,
            "snapshot": json.loads(evidence.snapshot_json),
            "sha256_hash": evidence.sha256_hash,
            "created_at": evidence.created_at
        }

    @classmethod
    def generate_report(
        cls,
        db: Session,
        incident_id: int,
        llm: LLMProvider | None = None
    ) -> InvestigationReport:
        existing = InvestigationRepository.get_by_incident_id(
            db=db,
            incident_id=incident_id
        )

        if existing is not None:
            return existing

        incident = IncidentRepository.get_by_id(
            db=db,
            incident_id=incident_id
        )

        if incident is None:
            raise ValueError("Incident not found")

        evidences = EvidenceRepository.get_by_incident_id(
            db=db,
            incident_id=incident_id
        )

        if not evidences:
            raise ValueError(
                "No evidence found for this incident"
            )

        evidence = evidences[0]

        chain_verification = BlockchainService.verify_chain(db=db)

        incident_data = cls._serialize_incident(incident)
        evidence_data = cls._serialize_evidence(evidence)

        prompt = InvestigationPromptBuilder.build(
            incident=incident_data,
            evidence=evidence_data,
            blockchain_verification=chain_verification
        )

        provider = llm or MockInvestigationLLM()

        generated = provider.generate_report(
            {
                "incident": incident_data,
                "evidence": evidence_data,
                "blockchain_verification": chain_verification,
                "prompt": prompt
            }
        )

        report = InvestigationReport(
            incident_id=incident_id,
            summary=generated["summary"],
            analysis=generated["analysis"],
            recommendations=json.dumps(
                generated["recommendations"],
                ensure_ascii=False
            ),
            mitre_techniques=json.dumps(
                generated["mitre_techniques"],
                ensure_ascii=False
            ),
            confidence=float(generated["confidence"]),
            model_name=provider.model_name,
            prompt_snapshot=prompt
        )

        return InvestigationRepository.create(
            db=db,
            report=report
        )

    @staticmethod
    def get_report(
        db: Session,
        report_id: int
    ) -> InvestigationReport | None:
        return InvestigationRepository.get_by_id(
            db=db,
            report_id=report_id
        )

    @staticmethod
    def get_incident_report(
        db: Session,
        incident_id: int
    ) -> InvestigationReport | None:
        return InvestigationRepository.get_by_incident_id(
            db=db,
            incident_id=incident_id
        )

    @classmethod
    def regenerate_report(
        cls,
        db: Session,
        incident_id: int
    ) -> InvestigationReport:
        existing = InvestigationRepository.get_by_incident_id(
            db=db,
            incident_id=incident_id
        )

        if existing is not None:
            InvestigationRepository.delete(
                db=db,
                report=existing
            )

        return cls.generate_report(
            db=db,
            incident_id=incident_id
        )