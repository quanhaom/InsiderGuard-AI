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
from app.repositories.evidence_repository import (
    EvidenceRepository,
)
from app.repositories.incident_repository import (
    IncidentRepository,
)
from app.repositories.investigation_repository import (
    InvestigationRepository,
)


class InvestigatorService:

    @staticmethod
    def _serialize_incident(
        incident
    ) -> dict[str, Any]:
        return {
            "id": incident.id,
            "alert_id": incident.alert_id,
            "username": incident.username,
            "title": incident.title,
            "severity": incident.severity,
            "description": incident.description,
            "status": incident.status,
            "detected_at": incident.created_at,
            "resolved_at": incident.closed_at,
        }

    @staticmethod
    def _serialize_evidence(
        evidence
    ) -> dict[str, Any]:
        try:
            snapshot = json.loads(
                evidence.snapshot_json
            )
        except (
            json.JSONDecodeError,
            TypeError,
        ):
            snapshot = {
                "raw_snapshot": (
                    evidence.snapshot_json
                )
            }

        return {
            "id": evidence.id,
            "incident_id": evidence.incident_id,
            "username": evidence.username,
            "evidence_type": evidence.evidence_type,
            "snapshot": snapshot,
            "sha256_hash": evidence.sha256_hash,
            "created_at": evidence.created_at,
        }

    @staticmethod
    def _normalize_chain_verification(
        result: dict[str, Any]
    ) -> dict[str, Any]:
        is_valid = bool(
            result.get(
                "is_valid",
                result.get("verified", False),
            )
        )

        return {
            **result,
            "is_valid": is_valid,
            "verified": is_valid,
        }

    @classmethod
    def generate_report(
        cls,
        db: Session,
        incident_id: int,
        llm: LLMProvider | None = None,
    ) -> InvestigationReport:
        # Mỗi incident chỉ có một report.
        existing_report = (
            InvestigationRepository
            .get_by_incident_id(
                db=db,
                incident_id=incident_id,
            )
        )

        if existing_report is not None:
            return existing_report

        incident = IncidentRepository.get_by_id(
            db=db,
            incident_id=incident_id,
        )

        if incident is None:
            raise ValueError(
                "Incident not found"
            )

        evidences = (
            EvidenceRepository
            .get_by_incident_id(
                db=db,
                incident_id=incident_id,
            )
        )

        if not evidences:
            raise ValueError(
                "No evidence found for this incident"
            )

        # Hiện tại dùng evidence đầu tiên.
        evidence = evidences[0]

        chain_result = (
            BlockchainService.verify_chain(
                db=db
            )
        )

        chain_verification = (
            cls._normalize_chain_verification(
                chain_result
            )
        )

        incident_data = (
            cls._serialize_incident(
                incident
            )
        )

        evidence_data = (
            cls._serialize_evidence(
                evidence
            )
        )

        prompt = (
            InvestigationPromptBuilder.build(
                incident=incident_data,
                evidence=evidence_data,
                blockchain_verification=(
                    chain_verification
                ),
            )
        )

        provider = (
            llm
            or MockInvestigationLLM()
        )

        generated = provider.generate_report(
            {
                "incident": incident_data,
                "evidence": evidence_data,
                "blockchain_verification": (
                    chain_verification
                ),
                "prompt": prompt,
            }
        )

        recommendations = generated.get(
            "recommendations",
            [],
        )

        mitre_techniques = generated.get(
            "mitre_techniques",
            [],
        )

        report = InvestigationReport(
            incident_id=incident_id,
            summary=generated.get(
                "summary",
                "No summary generated.",
            ),
            analysis=generated.get(
                "analysis",
                "No analysis generated.",
            ),
            recommendations=json.dumps(
                recommendations,
                ensure_ascii=False,
            ),
            mitre_techniques=json.dumps(
                mitre_techniques,
                ensure_ascii=False,
            ),
            confidence=float(
                generated.get(
                    "confidence",
                    0.0,
                )
            ),
            model_name=provider.model_name,
            prompt_snapshot=prompt,
        )

        try:
            return (
                InvestigationRepository.create(
                    db=db,
                    report=report,
                )
            )

        except Exception:
            db.rollback()
            raise

    @staticmethod
    def get_report(
        db: Session,
        report_id: int,
    ) -> InvestigationReport | None:
        return InvestigationRepository.get_by_id(
            db=db,
            report_id=report_id,
        )

    @staticmethod
    def get_incident_report(
        db: Session,
        incident_id: int,
    ) -> InvestigationReport | None:
        return (
            InvestigationRepository
            .get_by_incident_id(
                db=db,
                incident_id=incident_id,
            )
        )

    @classmethod
    def regenerate_report(
        cls,
        db: Session,
        incident_id: int,
        llm: LLMProvider | None = None,
    ) -> InvestigationReport:
        existing_report = (
            InvestigationRepository
            .get_by_incident_id(
                db=db,
                incident_id=incident_id,
            )
        )

        if existing_report is not None:
            InvestigationRepository.delete(
                db=db,
                report=existing_report,
            )

        return cls.generate_report(
            db=db,
            incident_id=incident_id,
            llm=llm,
        )